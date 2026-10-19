//! Approval through the desktop's own polkit authentication agent, for
//! displays the daemon cannot verify (Wayland). The session's agent was
//! registered with polkitd when the user logged in (on GNOME it is drawn by
//! the shell itself).
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

impl SystemPrompt for Polkit {
    fn available(&self) -> bool {
        Path::new(POLICY).exists()
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
        // polkit asks the agent of the subject's login session. A session
        // the human is not sitting at (ssh, an inactive console) may have an
        // agent of the requester's choosing.
        let cgroup = std::fs::read_to_string(format!("/proc/{}/cgroup", subject.pid))
            .map_err(|e| PlatformError::Other(format!("requester cgroup: {e}")))?;
        if let Some(id) = session_of(&cgroup) {
            let record =
                std::fs::read_to_string(format!("/run/systemd/sessions/{id}")).unwrap_or_default();
            if !active_local_session(&record, uid) {
                return Err(PlatformError::Other(format!(
                    "refusing: the requester runs in login session {id}, which is not your \
                     active local session (e.g. ssh or another console). Send the request from \
                     your desktop session"
                )));
            }
        }
        let conn = zbus::blocking::Connection::system()
            .map_err(|e| PlatformError::Other(format!("system bus: {e}")))?;
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
            // polkit expands `$(name)` inside messages, and an unterminated
            // `$(` would swallow the rest. Passing the text as a detail and
            // the message as a single reference makes polkit insert it
            // verbatim, unparsed.
            let details: HashMap<&str, &str> = HashMap::from([
                ("polkit.message", "$(peekexec.message)"),
                ("peekexec.message", text.as_str()),
            ]);
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

/// A logind session record of `uid`'s, active and not remote.
fn active_local_session(record: &str, uid: u32) -> bool {
    let get = |key: &str| {
        record
            .lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
    };
    get("UID") == Some(uid.to_string().as_str())
        && get("ACTIVE") == Some("1")
        && get("REMOTE") != Some("1")
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
    fn only_the_active_local_session_counts() {
        let rec = "UID=1000\nACTIVE=1\nREMOTE=0\nTYPE=wayland\n";
        assert!(active_local_session(rec, 1000));
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
