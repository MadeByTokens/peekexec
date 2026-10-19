//! Showing the dialog and turning the human's answer into a [`Decision`].

use std::io::BufReader;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use peekexec_proto::ui::{FromUi, ToUi};
use peekexec_proto::view::PromptView;
use peekexec_proto::wire::{read_msg, write_msg};

use crate::platform::{Authenticator, ProcessInfo, PromptOutcome, SystemPrompt};
use crate::session::Display;
use crate::spawn::{self, Creds, Spec};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Approved,
    Cancelled,
    Denied(String),
    AuthFailed,
    TimedOut,
    /// Nobody could be asked; the message says why and what to do.
    Failed(String),
}

pub const ATTEMPTS: u8 = 3;

pub struct Dialog {
    pub program: PathBuf,
    /// uid/gid to run the dialog as (the human's own, in root mode).
    pub run_as: Option<(u32, u32)>,
}

/// Show `view`, collect the answer, verify the password. Blocks until the
/// human answers, the deadline passes, or `cancel` is set.
/// How an Approve click is confirmed.
pub enum Approver<'a> {
    /// The password typed into the dialog, checked by PAM.
    Password {
        auth: &'a dyn Authenticator,
        user: &'a str,
    },
    /// The desktop's own prompt, showing `message`, about `subject`.
    System {
        prompt: &'a dyn SystemPrompt,
        subject: &'a ProcessInfo,
        uid: u32,
        message: String,
    },
}

pub fn ask(
    dialog: &Dialog,
    display: &Display,
    view: &PromptView,
    approver: &Approver,
    cancel: &AtomicBool,
) -> Result<Decision, String> {
    // A socket, not pipes: until the dialog makes itself non-dumpable, other
    // programs of the user may open /proc/<pid>/fd/N, and a pipe opened that
    // way can be read from later (the password goes through it). A socket
    // cannot be opened through /proc.
    let (mut conn, theirs) =
        UnixStream::pair().map_err(|e| format!("cannot create the dialog socket: {e}"))?;
    let theirs_out = theirs
        .try_clone()
        .map_err(|e| format!("cannot create the dialog socket: {e}"))?;
    let mut env = display.vars.clone();
    env.push(("LANG".into(), "C.UTF-8".into()));
    let mut cmd = spawn::command(Spec {
        program: &dialog.program,
        args: &[],
        env: &env,
        stdin: Stdio::from(OwnedFd::from(theirs)),
        stdout: Stdio::from(OwnedFd::from(theirs_out)),
        // Not the daemon's own stderr: under systemd that is the journal,
        // where the dialog's lines would pass for the daemon's (audit) ones.
        stderr: Stdio::piped(),
        // The human's own uid and gid, and no supplementary groups: root's
        // group 0 must not leak.
        creds: dialog.run_as.map(|(uid, gid)| Creds {
            uid,
            gid,
            groups: Vec::new(),
        }),
        no_new_privs: true,
    });
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("cannot start dialog {}: {e}", dialog.program.display()))?;
    // The child holds its own copies now.
    drop(cmd);
    let stderr = child.stderr.take().expect("piped");
    std::thread::spawn(move || {
        use std::io::BufRead;
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            let line: String = line.chars().take(500).collect();
            eprintln!("peekexecd: dialog stderr: {line:?}");
        }
    });
    let reader = conn
        .try_clone()
        .map_err(|e| format!("cannot read from the dialog: {e}"))?;

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut r = BufReader::new(reader);
        while let Ok(Some(msg)) = read_msg::<_, FromUi>(&mut r) {
            if tx.send(msg).is_err() {
                break;
            }
        }
    });

    let show = ToUi::Show {
        view: Box::new(view.clone()),
    };
    let answer = write_msg(&mut conn, &show)
        .map(|()| wait_for_answer(&rx, &mut conn, view, approver, cancel))
        .map_err(|e| format!("dialog did not accept the request: {e}"));
    // The dialog exits when its stdin reaches end of file.
    let _ = conn.shutdown(std::net::Shutdown::Write);
    let _ = child.kill();
    let status = child.wait();
    match answer? {
        Some(decision) => Ok(decision),
        // The dialog went away by itself: closed by the human if it exited
        // cleanly, otherwise it crashed or could not open the display.
        None => match status {
            Ok(s) if s.success() => Ok(Decision::Cancelled),
            Ok(s) => Err(format!("the dialog failed ({s}); see the daemon log")),
            Err(e) => Err(format!("the dialog failed: {e}")),
        },
    }
}

/// `None` if the dialog disconnected without answering.
fn wait_for_answer(
    rx: &mpsc::Receiver<FromUi>,
    stdin: &mut UnixStream,
    view: &PromptView,
    approver: &Approver,
    cancel: &AtomicBool,
) -> Option<Decision> {
    let deadline = Instant::now() + Duration::from_secs(view.timeout_secs.into());
    let mut attempts = ATTEMPTS;
    loop {
        if cancel.load(Ordering::SeqCst) {
            return Some(Decision::Cancelled);
        }
        let now = Instant::now();
        if now >= deadline {
            return Some(Decision::TimedOut);
        }
        let tick = (deadline - now).min(Duration::from_millis(200));
        match rx.recv_timeout(tick) {
            Ok(FromUi::Approve { .. }) if matches!(approver, Approver::System { .. }) => {
                let Approver::System {
                    prompt,
                    subject,
                    uid,
                    message,
                } = approver
                else {
                    unreachable!()
                };
                let _ = write_msg(stdin, &ToUi::SystemPromptOpen);
                return Some(
                    match prompt.approve(subject, *uid, message, deadline, cancel) {
                        Ok(PromptOutcome::Authorized) => Decision::Approved,
                        Ok(PromptOutcome::Dismissed) => Decision::Cancelled,
                        Ok(PromptOutcome::TimedOut) => Decision::TimedOut,
                        Ok(PromptOutcome::NotAuthorized) => Decision::AuthFailed,
                        Ok(PromptOutcome::NoAgent) => Decision::Failed(
                            "no polkit authentication agent answered for the requester's \
                             session: run the request from a program inside your desktop \
                             session (e.g. a terminal there), not over ssh"
                                .into(),
                        ),
                        Err(e) => Decision::Failed(format!("system prompt: {e}")),
                    },
                );
            }
            Ok(FromUi::Approve { password }) => match approver.verify(password.as_deref()) {
                Ok(true) => return Some(Decision::Approved),
                Ok(false) => {
                    attempts -= 1;
                    if attempts == 0 {
                        return Some(Decision::AuthFailed);
                    }
                    let _ = write_msg(
                        stdin,
                        &ToUi::WrongPassword {
                            attempts_left: attempts,
                        },
                    );
                }
                Err(e) => {
                    eprintln!("peekexecd: authentication error: {e}");
                    return Some(Decision::AuthFailed);
                }
            },
            Ok(FromUi::Cancel) => return Some(Decision::Cancelled),
            Ok(FromUi::Deny { reason }) => return Some(Decision::Denied(reason)),
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => return None,
        }
    }
}

impl Approver<'_> {
    fn verify(&self, password: Option<&str>) -> Result<bool, crate::platform::PlatformError> {
        match self {
            Approver::Password { auth, user } => auth.verify(user, password),
            Approver::System { .. } => Ok(false),
        }
    }
}

/// Stands in for the dialog and PAM in automated tests. Compiled only with
/// the `test-approver` feature, which release builds never enable, and
/// refuses to work as root.
#[cfg(feature = "test-approver")]
pub mod test_approver {
    use super::*;

    pub const ENV: &str = "PEEKEXEC_TEST_APPROVER";

    /// `approve`, `cancel`, `deny:<reason>`, `authfail`, `timeout`,
    /// `delay:<ms>` (approve after a pause), or `hold` (wait until cancelled
    /// or the request's timeout passes).
    pub fn decide(answer: &str, view: &PromptView, cancel: &AtomicBool) -> Decision {
        assert!(
            !nix::unistd::geteuid().is_root(),
            "the test approver must never run as root"
        );
        match answer {
            "approve" => Decision::Approved,
            "cancel" => Decision::Cancelled,
            "authfail" => Decision::AuthFailed,
            "timeout" => Decision::TimedOut,
            "hold" => {
                let deadline = Instant::now() + Duration::from_secs(view.timeout_secs.into());
                while Instant::now() < deadline {
                    if cancel.load(Ordering::SeqCst) {
                        return Decision::Cancelled;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Decision::TimedOut
            }
            other => {
                if let Some(reason) = other.strip_prefix("deny:") {
                    Decision::Denied(reason.to_string())
                } else if let Some(ms) = other.strip_prefix("delay:") {
                    let ms = ms
                        .parse()
                        .unwrap_or_else(|_| panic!("bad {ENV} value {other:?}"));
                    std::thread::sleep(Duration::from_millis(ms));
                    Decision::Approved
                } else {
                    panic!("unknown {ENV} value {other:?}")
                }
            }
        }
    }
}
