//! The OS boundary. Everything platform-specific the daemon needs goes
//! through one of these traits.

use std::collections::BTreeMap;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::Child;

use peekexec_proto::{Enforced, Level};

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;

#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    #[error("{0} is not supported on this platform yet")]
    Unsupported(&'static str),
    #[error("{what}: {source}")]
    Io {
        what: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{0}")]
    Other(String),
}

/// One process in the requester's chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub exe: Option<String>,
    pub cmdline: Vec<String>,
}

/// Who is asking, as established by the kernel, not by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub uid: u32,
    pub gid: u32,
    pub process: ProcessInfo,
    pub cwd: Option<String>,
    /// Parent, grandparent, ... up to (not including) pid 1.
    pub ancestry: Vec<ProcessInfo>,
}

pub trait PeerInfo {
    fn identify(&self, conn: &UnixStream) -> Result<Peer, PlatformError>;
}

/// What the dialog answered when asked for a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    Secret(String),
    Cancelled,
    Denied(String),
}

/// The dialog, as seen by an authenticator. Backends with their own UI
/// (Touch ID) may never call it.
pub trait Challenger {
    fn ask(&mut self, attempts_left: u8) -> Answer;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthOutcome {
    Authenticated,
    Failed,
    Cancelled,
    Denied(String),
}

pub trait Authenticator {
    fn authenticate(
        &self,
        user: &str,
        ui: &mut dyn Challenger,
    ) -> Result<AuthOutcome, PlatformError>;
}

/// Everything needed to start the approved command, taken from the snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecPlan {
    pub argv: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: String,
    pub write: Option<Vec<String>>,
    pub no_net: bool,
}

pub trait Sandbox {
    /// What [`Sandbox::spawn`] would enforce for this plan. Shown in the
    /// dialog before approval and returned to the caller afterwards, so it
    /// must never overstate.
    fn enforcement(&self, plan: &ExecPlan) -> Enforced;
    fn spawn(&self, plan: &ExecPlan) -> Result<Child, PlatformError>;
}

/// The honest answer for a backend that enforces nothing: every requested
/// limit is reported as declared only.
pub fn declared_only(plan: &ExecPlan) -> Enforced {
    let level = |requested: bool| {
        if requested {
            Level::DeclaredOnly
        } else {
            Level::NotRequested
        }
    };
    Enforced {
        write: plan.write.clone(),
        write_level: level(plan.write.is_some()),
        network: !plan.no_net,
        network_level: level(plan.no_net),
    }
}

/// Obtains the daemon's listening socket (systemd/launchd activation or bind).
pub trait Listener {
    fn listen(&self) -> Result<UnixListener, PlatformError>;
}

pub struct Platform {
    pub peer: Box<dyn PeerInfo>,
    pub auth: Box<dyn Authenticator>,
    pub sandbox: Box<dyn Sandbox>,
    pub listener: Box<dyn Listener>,
}

#[cfg(target_os = "linux")]
pub fn current() -> Platform {
    linux::platform()
}

#[cfg(target_os = "macos")]
pub fn current() -> Platform {
    macos::platform()
}
