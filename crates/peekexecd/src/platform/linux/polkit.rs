//! Approval through the desktop's own polkit authentication agent, for
//! displays the daemon cannot verify (Wayland). The agent was registered with
//! polkitd when the user logged in (on GNOME it is drawn by the shell itself),
//! so a requester cannot route the password prompt through a display server
//! of its own.

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
        let conn = zbus::blocking::Connection::system()
            .map_err(|e| PlatformError::Other(format!("system bus: {e}")))?;
        let cancellation_id = format!("peekexec-{}-{}", subject.pid, start_time);

        let (tx, rx) = mpsc::channel::<Reply>();
        let worker = conn.clone();
        let (pid, id, text) = (subject.pid, cancellation_id.clone(), message.to_string());
        std::thread::spawn(move || {
            // A `unix-process` subject (pid + start time + uid): never
            // `unix-session`, which makes polkitd abort (see docs/notes).
            let subject_details: HashMap<&str, Value> = HashMap::from([
                ("pid", Value::from(pid)),
                ("start-time", Value::from(start_time)),
                ("uid", Value::from(uid as i32)),
            ]);
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
