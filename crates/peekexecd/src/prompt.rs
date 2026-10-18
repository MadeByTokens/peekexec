//! Showing the dialog and turning the human's answer into a [`Decision`].

use std::io::BufReader;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use peekexec_proto::ui::{FromUi, ToUi};
use peekexec_proto::view::PromptView;
use peekexec_proto::wire::{read_msg, write_msg};

use crate::platform::Authenticator;
use crate::session::Display;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Approved,
    Cancelled,
    Denied(String),
    AuthFailed,
    TimedOut,
}

pub const ATTEMPTS: u8 = 3;

pub struct Dialog {
    pub program: PathBuf,
    /// uid/gid to run the dialog as (the human's own, in root mode).
    pub run_as: Option<(u32, u32)>,
}

/// Show `view`, collect the answer, verify the password. Blocks until the
/// human answers, the deadline passes, or `cancel` is set.
pub fn ask(
    dialog: &Dialog,
    display: &Display,
    view: &PromptView,
    auth: &dyn Authenticator,
    user: &str,
    cancel: &AtomicBool,
) -> Result<Decision, String> {
    let mut cmd = Command::new(&dialog.program);
    cmd.env_clear()
        .envs(display.vars.iter().map(|(k, v)| (k, v)))
        .env("LANG", "C.UTF-8")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    if let Some((uid, gid)) = dialog.run_as {
        cmd.uid(uid).gid(gid);
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("cannot start dialog {}: {e}", dialog.program.display()))?;
    let mut stdin = child.stdin.take().expect("piped");
    let stdout = child.stdout.take().expect("piped");

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut r = BufReader::new(stdout);
        while let Ok(Some(msg)) = read_msg::<_, FromUi>(&mut r) {
            if tx.send(msg).is_err() {
                break;
            }
        }
    });

    let show = ToUi::Show {
        view: Box::new(view.clone()),
    };
    let answer = write_msg(&mut stdin, &show)
        .map(|()| wait_for_answer(&rx, &mut stdin, view, auth, user, cancel))
        .map_err(|e| format!("dialog did not accept the request: {e}"));
    drop(stdin); // the dialog exits when its stdin closes
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
    stdin: &mut std::process::ChildStdin,
    view: &PromptView,
    auth: &dyn Authenticator,
    user: &str,
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
            Ok(FromUi::Approve { password }) => match auth.verify(user, password.as_deref()) {
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
