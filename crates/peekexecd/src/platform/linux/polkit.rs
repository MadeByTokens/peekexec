//! Approval through the desktop's own polkit authentication agent, for
//! displays the daemon cannot verify (Wayland). The session's agent was
//! registered with polkitd when the user logged in. Only GNOME Shell's is
//! used: there the shell, which is the compositor, draws the prompt, and
//! another program cannot read or drive it. On other desktops the agent is
//! an ordinary program of the user's, which a requester can end and replace
//! with its own (polkit then asks that one), so the path is refused there.
//!
//! polkit prefers an agent registered for the *subject process* over the
//! session's, and any process may register one for a process of its own
//! user, so a requester could otherwise receive (and fake) the prompt itself.
//! Before asking, the daemon therefore registers a *fallback* agent of its own
//! for the subject: only one agent may exist per subject, so this blocks the
//! requester from registering one, while `fallback` makes polkit still use
//! the session's agent. If the slot is already taken, peekexec refuses. The
//! guard agent itself never authenticates anyone.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use zbus::zvariant::Value;

use crate::platform::{PlatformError, ProcessInfo, PromptOutcome, SystemPrompt};

pub const ACTION: &str = "org.peekexec.approve";
const POLICY: &str = "/usr/share/polkit-1/actions/org.peekexec.approve.policy";
const DEST: &str = "org.freedesktop.PolicyKit1";
const PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
const IFACE: &str = "org.freedesktop.PolicyKit1.Authority";
const ALLOW_USER_INTERACTION: u32 = 1;

pub struct Polkit;

/// The guard: a fallback agent that only declines, and records that it was
/// asked (meaning the session has no agent of its own).
struct Guard(std::sync::Arc<AtomicBool>);

#[zbus::interface(name = "org.freedesktop.PolicyKit1.AuthenticationAgent")]
impl Guard {
    fn begin_authentication(
        &self,
        _action_id: &str,
        _message: &str,
        _icon_name: &str,
        _details: HashMap<String, String>,
        _cookie: &str,
        _identities: Vec<(String, HashMap<String, zbus::zvariant::OwnedValue>)>,
    ) -> zbus::fdo::Result<()> {
        self.0.store(true, Ordering::SeqCst);
        Err(zbus::fdo::Error::Failed(
            "peekexec guard agent: no desktop authentication agent to ask".into(),
        ))
    }

    fn cancel_authentication(&self, _cookie: &str) {}
}

fn subject_details(pid: u32, start_time: u64, uid: u32) -> HashMap<&'static str, Value<'static>> {
    // A `unix-process` subject (pid + start time + uid): never `unix-session`,
    // which makes polkitd abort (see docs/notes).
    HashMap::from([
        ("pid", Value::from(pid)),
        ("start-time", Value::from(start_time)),
        ("uid", Value::from(uid as i32)),
    ])
}

type Reply = zbus::Result<(bool, bool, HashMap<String, String>)>;

/// polkit expands `$(name)` inside messages, and an unterminated `$(`
/// would swallow the rest. Passing the text as a detail and the message as
/// a single reference makes polkit insert it verbatim, unparsed.
fn details(message: &str) -> HashMap<&'static str, &str> {
    HashMap::from([
        ("polkit.message", "$(peekexec.message)"),
        ("peekexec.message", message),
    ])
}

/// How soon after the session's leader GNOME Shell must have started to
/// count as the one that came up with the session.
const SHELL_START: Duration = Duration::from_secs(120);

impl SystemPrompt for Polkit {
    fn usable_for(&self, subject: &ProcessInfo, uid: u32) -> Result<(), String> {
        if !Path::new(POLICY).exists() {
            return Err(format!("the polkit action {ACTION} is not installed"));
        }
        // polkit asks the agent of the subject's login session, or, for a
        // process in none (apps under `user@.service`), the user's display
        // session. A session the human is not sitting at (ssh, ssh
        // localhost, an inactive console) may have an agent of the
        // requester's choosing.
        let cgroup = std::fs::read_to_string(format!("/proc/{}/cgroup", subject.pid))
            .map_err(|e| format!("requester cgroup: {e}"))?;
        let id = match session_of(&cgroup) {
            Some(id) => id,
            None => display_session(uid)?,
        };
        let record =
            std::fs::read_to_string(format!("/run/systemd/sessions/{id}")).unwrap_or_default();
        if !active_local_session(&record, uid) {
            return Err(format!(
                "the requester runs in login session {id}, which is not your active local \
                 session (e.g. ssh or another console); send the request from your desktop \
                 session"
            ));
        }
        desktop_shell(&record, uid)
    }

    fn approve(
        &self,
        subject: &ProcessInfo,
        uid: u32,
        message: &str,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<PromptOutcome, PlatformError> {
        let start_time = subject
            .start_time
            .ok_or_else(|| PlatformError::Other("requester start time unknown".into()))?;
        // Again, now: the human may have switched sessions since the
        // request was shown, or the shell may have gone.
        self.usable_for(subject, uid)
            .map_err(|e| PlatformError::Other(format!("refusing: {e}")))?;
        let conn = zbus::blocking::Connection::system()
            .map_err(|e| PlatformError::Other(format!("system bus: {e}")))?;
        // The Continue click that leads here may come from a display the
        // requester runs itself, so polkit must be what involves the human:
        // if it would grant with no one asked (a local rule, a remembered
        // authorization), refuse.
        match self.decide_silently(&conn, subject.pid, start_time, uid, message)? {
            (true, _) => {
                return Err(PlatformError::Other(
                    "refusing: polkit would allow this without asking anyone (a local rule or \
                     a remembered authorization for org.peekexec.approve), so no human would \
                     confirm it"
                        .into(),
                ))
            }
            (false, false) => return Ok(PromptOutcome::NotAuthorized),
            (false, true) => {}
        }
        let cancellation_id = format!("peekexec-{}-{}", subject.pid, start_time);

        // Hold the subject's agent slot before asking (see the module docs).
        let guard_path = format!("/org/peekexec/Guard/p{}_{}", subject.pid, start_time);
        let guard_asked = std::sync::Arc::new(AtomicBool::new(false));
        conn.object_server()
            .at(guard_path.as_str(), Guard(guard_asked.clone()))
            .map_err(|e| PlatformError::Other(format!("guard agent: {e}")))?;
        let options: HashMap<&str, Value> = HashMap::from([("fallback", Value::from(true))]);
        let registered = conn.call_method(
            Some(DEST),
            PATH,
            Some(IFACE),
            "RegisterAuthenticationAgentWithOptions",
            &(
                (
                    "unix-process",
                    subject_details(subject.pid, start_time, uid),
                ),
                "C.UTF-8",
                guard_path.as_str(),
                options,
            ),
        );
        if let Err(e) = registered {
            let _ = conn.object_server().remove::<Guard, _>(guard_path.as_str());
            return Err(PlatformError::Other(format!(
                "refusing: could not reserve the requester's polkit agent slot ({e}); another \
                 program may have registered its own agent for it"
            )));
        }
        let result = self.ask(
            &conn,
            subject,
            start_time,
            uid,
            message,
            &cancellation_id,
            deadline,
            cancel,
        );
        let _ = conn.call_method(
            Some(DEST),
            PATH,
            Some(IFACE),
            "UnregisterAuthenticationAgent",
            &(
                (
                    "unix-process",
                    subject_details(subject.pid, start_time, uid),
                ),
                guard_path.as_str(),
            ),
        );
        let _ = conn.object_server().remove::<Guard, _>(guard_path.as_str());
        if guard_asked.load(Ordering::SeqCst) {
            return Ok(PromptOutcome::NoAgent);
        }
        result
    }
}

impl Polkit {
    /// polkit's answer without user interaction: (authorized, challenge).
    fn decide_silently(
        &self,
        conn: &zbus::blocking::Connection,
        pid: u32,
        start_time: u64,
        uid: u32,
        message: &str,
    ) -> Result<(bool, bool), PlatformError> {
        // The same details as the real check: a rule may look at them.
        let details = details(message);
        let reply: Reply = conn
            .call_method(
                Some(DEST),
                PATH,
                Some(IFACE),
                "CheckAuthorization",
                &(
                    ("unix-process", subject_details(pid, start_time, uid)),
                    ACTION,
                    details,
                    0u32,
                    "",
                ),
            )
            .and_then(|m| m.body().deserialize());
        let (authorized, challenge, _) =
            reply.map_err(|e| PlatformError::Other(format!("polkit: {e}")))?;
        Ok((authorized, challenge))
    }

    #[allow(clippy::too_many_arguments)]
    fn ask(
        &self,
        conn: &zbus::blocking::Connection,
        subject: &ProcessInfo,
        start_time: u64,
        uid: u32,
        message: &str,
        cancellation_id: &str,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<PromptOutcome, PlatformError> {
        let cancellation_id = cancellation_id.to_string();

        let (tx, rx) = mpsc::channel::<Reply>();
        let worker = conn.clone();
        let (pid, id, text) = (subject.pid, cancellation_id.clone(), message.to_string());
        std::thread::spawn(move || {
            let subject_details = subject_details(pid, start_time, uid);
            let details = details(&text);
            let reply = worker
                .call_method(
                    Some(DEST),
                    PATH,
                    Some(IFACE),
                    "CheckAuthorization",
                    &(
                        ("unix-process", subject_details),
                        ACTION,
                        details,
                        ALLOW_USER_INTERACTION,
                        id.as_str(),
                    ),
                )
                .and_then(|m| m.body().deserialize());
            let _ = tx.send(reply);
        });

        let mut withdrawn: Option<PromptOutcome> = None;
        loop {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(reply) => {
                    if let Some(outcome) = withdrawn {
                        return Ok(outcome);
                    }
                    return outcome(reply);
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(PlatformError::Other(
                        "polkit query ended unexpectedly".into(),
                    ))
                }
                Err(RecvTimeoutError::Timeout) => {}
            }
            if withdrawn.is_none() {
                let reason = if cancel.load(Ordering::SeqCst) {
                    Some(PromptOutcome::Dismissed)
                } else if Instant::now() >= deadline {
                    Some(PromptOutcome::TimedOut)
                } else {
                    None
                };
                if let Some(r) = reason {
                    // Closes the desktop's prompt; the pending call then returns.
                    let _ = conn.call_method(
                        Some(DEST),
                        PATH,
                        Some(IFACE),
                        "CancelCheckAuthorization",
                        &(cancellation_id.as_str(),),
                    );
                    withdrawn = Some(r);
                }
            }
        }
    }
}

/// The logind session whose scope (`session-<id>.scope`) holds the
/// process, if any. Scopes are root-owned: a process cannot move into one.
/// Apps under `user@.service` belong to none; polkit then uses the user's
/// display session.
fn session_of(cgroup: &str) -> Option<String> {
    cgroup
        .lines()
        .filter_map(|l| l.rsplit(':').next())
        .flat_map(|path| path.split('/'))
        .find_map(|part| part.strip_prefix("session-")?.strip_suffix(".scope"))
        .filter(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric()))
        .map(str::to_string)
}

/// A logind session record of `uid`'s that the human is sitting at: it has
/// a seat and is that seat's active session. Positive evidence only:
/// logind counts every session without a seat as "active", and pam_systemd
/// does not mark `ssh localhost` as remote, so "active and not remote"
/// would let such a session through.
fn active_local_session(record: &str, uid: u32) -> bool {
    let get = |key: &str| {
        record
            .lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
    };
    get("UID") == Some(uid.to_string().as_str())
        && get("SEAT").is_some_and(|s| !s.is_empty())
        && get("ACTIVE") == Some("1")
        && get("STATE") == Some("active")
        && get("CLASS") == Some("user")
        && get("REMOTE") != Some("1")
}

/// The session logind uses as `uid`'s graphical one (`DISPLAY=` in the
/// user record logind writes).
fn display_session(uid: u32) -> Result<String, String> {
    let record = std::fs::read_to_string(format!("/run/systemd/users/{uid}"))
        .map_err(|e| format!("no logind record for your user: {e}"))?;
    record
        .lines()
        .find_map(|l| l.strip_prefix("DISPLAY="))
        .filter(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric()))
        .map(str::to_string)
        .ok_or_else(|| "logind names no graphical session for your user".to_string())
}

/// Positive evidence that GNOME Shell holds the session's polkit agent: a
/// `gnome-shell` of the user's, from a binary root controls, that started
/// within [`SHELL_START`] of the session's leader (kernel start times,
/// one clock). A requester can start a shell or an agent of its own, but
/// not one that started before it did; and a shell that was restarted
/// (only possible on X11) no longer counts.
fn desktop_shell(record: &str, uid: u32) -> Result<(), String> {
    let refused = |why: &str| {
        Err(format!(
            "the desktop's password dialog cannot be shown to be GNOME Shell's ({why}); on \
             other desktops it is an ordinary program, which another program of yours could \
             replace"
        ))
    };
    let Some(leader) = record
        .lines()
        .find_map(|l| l.strip_prefix("LEADER="))
        .and_then(|p| p.parse::<u32>().ok())
    else {
        return refused("logind names no session leader");
    };
    let Some(leader_start) = super::peer::start_time_of(leader) else {
        return refused("the session leader is gone");
    };
    let hz = nix::unistd::sysconf(nix::unistd::SysconfVar::CLK_TCK)
        .ok()
        .flatten()
        .filter(|&t| t > 0)
        .unwrap_or(100) as u64;
    let owners = crate::trust::trusted_owners();
    let Ok(procs) = std::fs::read_dir("/proc") else {
        return refused("cannot list processes");
    };
    let found = procs.filter_map(Result::ok).any(|entry| {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            return false;
        };
        let owned = std::fs::read_to_string(format!("/proc/{pid}/status"))
            .is_ok_and(|s| status_uids(&s) == Some([uid; 4]));
        // The very file at this path (`exe_of` marks any other), which
        // only root can change.
        let shell = || {
            super::peer::exe_of(pid).is_some_and(|exe| {
                exe.rsplit('/').next() == Some("gnome-shell")
                    && crate::trust::check(Path::new(&exe), &owners).is_ok()
            })
        };
        let with_session = || {
            super::peer::start_time_of(pid)
                .is_some_and(|t| started_with(leader_start, t, hz, SHELL_START))
        };
        owned && shell() && with_session()
    });
    if found {
        Ok(())
    } else {
        refused("no GNOME Shell that started with your session")
    }
}

/// The real, effective, saved and filesystem uids of a `/proc/<pid>/status`.
fn status_uids(status: &str) -> Option<[u32; 4]> {
    let ids: Vec<u32> = status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))?
        .split_whitespace()
        .map(|n| n.parse().ok())
        .collect::<Option<_>>()?;
    ids.try_into().ok()
}

/// Whether a process that started at `t` (clock ticks since boot) started
/// within `window` after the session's leader did.
fn started_with(leader: u64, t: u64, hz: u64, window: Duration) -> bool {
    t >= leader && t - leader <= window.as_secs() * hz
}

fn outcome(reply: Reply) -> Result<PromptOutcome, PlatformError> {
    match reply {
        Ok((true, _, _)) => Ok(PromptOutcome::Authorized),
        Ok((false, _, details))
            if details.get("polkit.dismissed").map(String::as_str) == Some("true") =>
        {
            Ok(PromptOutcome::Dismissed)
        }
        // A challenge that nobody answered: no authentication agent for the
        // requester's session.
        Ok((false, true, _)) => Ok(PromptOutcome::NoAgent),
        Ok((false, false, _)) => Ok(PromptOutcome::NotAuthorized),
        Err(zbus::Error::MethodError(name, _, _)) if name.as_str().ends_with(".Cancelled") => {
            Ok(PromptOutcome::Dismissed)
        }
        Err(e) => Err(PlatformError::Other(format!("polkit: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_session_scope() {
        let cg = "0::/user.slice/user-1000.slice/session-2.scope\n";
        assert_eq!(session_of(cg).as_deref(), Some("2"));
        let app = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-x.scope\n";
        assert_eq!(session_of(app), None);
        assert_eq!(
            session_of("0::/user.slice/user-1000.slice/session-c1.scope\n").as_deref(),
            Some("c1")
        );
        assert_eq!(session_of("0::/x/session-../y.scope\n"), None);
    }

    #[test]
    fn the_shell_must_have_started_with_the_session() {
        let w = Duration::from_secs(120);
        assert!(started_with(1000, 1000, 100, w));
        assert!(started_with(1000, 1000 + 120 * 100, 100, w));
        assert!(!started_with(1000, 1000 + 120 * 100 + 1, 100, w));
        // Older than the leader: some other process with a reused pid.
        assert!(!started_with(1000, 999, 100, w));
    }

    #[test]
    fn reads_all_four_uids() {
        let st = "Name:\tgnome-shell\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\n";
        assert_eq!(status_uids(st), Some([1000; 4]));
        assert_eq!(
            status_uids("Uid:\t1000\t0\t1000\t1000\n"),
            Some([1000, 0, 1000, 1000])
        );
        assert_eq!(status_uids("Uid:\t1000\n"), None);
        assert_eq!(status_uids(""), None);
    }

    #[test]
    fn only_the_active_local_session_counts() {
        let rec =
            "UID=1000\nACTIVE=1\nSTATE=active\nREMOTE=0\nTYPE=wayland\nCLASS=user\nSEAT=seat0\n";
        assert!(active_local_session(rec, 1000));
        // `ssh localhost`: no seat, so "active", and not marked remote.
        assert!(!active_local_session(
            &rec.replace("SEAT=seat0\n", ""),
            1000
        ));
        assert!(!active_local_session(
            &rec.replace("SEAT=seat0", "SEAT="),
            1000
        ));
        assert!(!active_local_session(
            &rec.replace("STATE=active", "STATE=online"),
            1000
        ));
        assert!(!active_local_session(
            &rec.replace("CLASS=user", "CLASS=greeter"),
            1000
        ));
        assert!(!active_local_session(rec, 1001));
        assert!(!active_local_session(
            &rec.replace("REMOTE=0", "REMOTE=1"),
            1000
        ));
        assert!(!active_local_session(
            &rec.replace("ACTIVE=1", "ACTIVE=0"),
            1000
        ));
        assert!(!active_local_session("", 1000));
    }
}
