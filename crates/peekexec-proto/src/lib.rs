//! Wire types shared by the client, the daemon and the dialog.
//!
//! [`Status`], [`Level`] and [`Response`] are the public contract with
//! automated callers: `peekexec help schema` and the exit-code table are
//! generated from them, and tests check that `peekexec help agents` names
//! every status and level, so changing them changes the documented
//! interface.

use peekexec_core::Request;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub mod ui;
pub mod view;
pub mod wire;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// The human approved and the command ran. `exit_code` is its own exit code.
    Approved,
    /// The request is waiting for the human (from `submit`, or `wait --timeout`
    /// expired), or, with `running`, approved and running.
    Pending,
    /// The human pressed Cancel / Esc / closed the dialog, or the caller withdrew it.
    Cancelled,
    /// The human denied it and wrote `deny_reason` for you.
    Denied,
    /// Three wrong passwords.
    AuthFailed,
    /// The human did not respond in time.
    Timeout,
    /// Refused, invalid, or the daemon could not be reached: what was asked
    /// did not start. See `error`.
    Error,
    /// What became of the request cannot be said: it went out and no valid
    /// answer came back, it started and was lost, or the daemon no longer
    /// knows the id. It may have run. Do not resend it; see `error`.
    Unknown,
}

impl Status {
    pub const ALL: [Status; 8] = [
        Status::Approved,
        Status::Pending,
        Status::Cancelled,
        Status::Denied,
        Status::AuthFailed,
        Status::Timeout,
        Status::Error,
        Status::Unknown,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Status::Approved => "approved",
            Status::Pending => "pending",
            Status::Cancelled => "cancelled",
            Status::Denied => "denied",
            Status::AuthFailed => "auth_failed",
            Status::Timeout => "timeout",
            Status::Error => "error",
            Status::Unknown => "unknown",
        }
    }

    /// peekexec's own process exit code. `None` for [`Status::Approved`],
    /// where the command's exit code is passed through instead.
    pub fn exit_code(self) -> Option<u8> {
        match self {
            Status::Approved => None,
            Status::Cancelled => Some(130),
            Status::Denied => Some(131),
            Status::AuthFailed => Some(132),
            Status::Timeout => Some(133),
            Status::Error => Some(134),
            Status::Pending => Some(135),
            Status::Unknown => Some(136),
        }
    }

    pub fn meaning(self) -> &'static str {
        match self {
            Status::Approved => "approved; the command's own exit code",
            Status::Pending => "still waiting for the human (wait --timeout expired)",
            Status::Cancelled => "cancelled by the human, or withdrawn by you: stop, don't retry",
            Status::Denied => "denied with a reason: read deny_reason, change your approach",
            Status::AuthFailed => "authentication failed (3 wrong passwords)",
            Status::Timeout => "timed out, no response from the human",
            Status::Error => "refused, invalid, or daemon unavailable; it did not start: see error",
            Status::Unknown => "what became of it cannot be said: it may have run, do not resend",
        }
    }
}

/// How a limit on the command was applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    /// Enforced by the kernel; the command cannot exceed it.
    Kernel,
    /// Applied, but not containment: a root process can undo it (e.g. rejoin
    /// the host network namespace, or ask a system service to act for it).
    BestEffort,
    /// Requested and shown to the human, but this platform cannot enforce it.
    DeclaredOnly,
    /// No limit was requested.
    NotRequested,
    /// No command ran: peekexec performed the action itself (e.g. `install`
    /// writes only the one destination file).
    Builtin,
}

/// How far the dialog itself can be trusted on this display (THREAT_MODEL.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DisplayTier {
    /// Other programs of the same user can see and drive the dialog.
    X11,
    /// The compositor isolates the dialog from other programs.
    Wayland,
}

/// What was actually enforced for this run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Enforced {
    /// Paths the command could write. `None`: writes were not restricted.
    pub write: Option<Vec<String>>,
    pub write_level: Level,
    /// Whether the command had network access.
    pub network: bool,
    pub network_level: Level,
}

/// The single JSON object printed by `--json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Response {
    pub status: Status,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// SHA-256 of exactly what was (or would have been) executed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Command output, decoded as UTF-8 with invalid bytes replaced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdout: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stderr: Option<String>,
    /// True when part of `stdout` or `stderr` was dropped. The text in those
    /// fields that says so comes from the same stream as the command's own
    /// output, so it proves nothing; this field does.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub output_truncated: bool,
    /// With status `pending`: the human has approved and the command is
    /// running, so it can no longer be cancelled.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub running: bool,
    /// Something about what ran that is worth reading: it may have left
    /// something running as root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
    /// The human's message to you, delivered by the root daemon (unless
    /// `dev_mode` is true). As trustworthy as the dialog it was typed into:
    /// see `display_verified`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforced: Option<Enforced>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_tier: Option<DisplayTier>,
    /// False when the display could not be verified: a program of the
    /// user's could have been relaying the dialog.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_verified: Option<bool>,
    /// True when the daemon that answered does not run as root (development
    /// mode, or a program posing as peekexecd on a socket named by
    /// PEEKEXEC_SOCKET; the client checks the daemon's uid): nothing ran as
    /// root, and the status and `deny_reason` are not the human's.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub dev_mode: bool,
    /// The agent session id (register).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Response {
    pub fn error(message: impl Into<String>) -> Self {
        Response {
            error: Some(message.into()),
            ..Response::new(Status::Error)
        }
    }

    pub fn new(status: Status) -> Self {
        Response {
            status,
            request_id: None,
            sha256: None,
            exit_code: None,
            stdout: None,
            stderr: None,
            output_truncated: false,
            running: false,
            warning: None,
            deny_reason: None,
            enforced: None,
            display_tier: None,
            display_verified: None,
            dev_mode: false,
            session: None,
            error: None,
        }
    }
}

/// Client → daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ClientMsg {
    /// Submit and block until the human answers and the command finishes.
    Run {
        request: Request,
    },
    /// Submit and return a `pending` response with a request id at once.
    Submit {
        request: Request,
    },
    Wait {
        id: String,
        timeout_secs: Option<u32>,
    },
    Cancel {
        id: String,
    },
    /// Build the exact view the human would get, without prompting.
    Preview {
        request: Request,
    },
    /// Ask the human to register an agent process (default: the caller's
    /// nearest non-shell ancestor), so its later requests are labelled.
    Register {
        name: String,
        agent_pid: Option<u32>,
        why: Option<String>,
        timeout_secs: u32,
    },
    /// End the registrations of the caller's agent ancestors.
    Unregister,
}

/// Daemon → client reply to [`ClientMsg::Preview`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum PreviewReply {
    Ok { view: Box<view::PromptView> },
    Error { error: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_are_unique_and_outside_command_range() {
        let mut codes: Vec<u8> = Status::ALL.iter().filter_map(|s| s.exit_code()).collect();
        assert!(codes.iter().all(|&c| c > 125));
        codes.sort();
        codes.dedup();
        assert_eq!(codes.len(), Status::ALL.len() - 1);
    }

    #[test]
    fn as_str_matches_serde() {
        for s in Status::ALL {
            let json = serde_json::to_string(&s).unwrap();
            assert_eq!(json, format!("\"{}\"", s.as_str()));
        }
    }
}
