//! The OS boundary. Everything platform-specific the daemon needs goes
//! through one of these traits.

use std::collections::BTreeMap;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
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

impl PlatformError {
    pub fn io(what: impl Into<String>, source: std::io::Error) -> Self {
        PlatformError::Io {
            what: what.into(),
            source,
        }
    }
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
    /// Whether the process was pinned (pidfd) while being described, so a
    /// reused pid cannot have been described instead.
    pub pinned: bool,
}

/// An X server verified to belong to the user's active local session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XServer {
    /// `:N`
    pub display: String,
    pub xauthority: Option<String>,
}

pub trait PeerInfo: Send + Sync {
    fn identify(&self, conn: &UnixStream) -> Result<Peer, PlatformError>;
    /// Environment of a process the daemon may read (to find the user's
    /// display). `None` if it is gone or unreadable.
    fn environ(&self, pid: u32) -> Option<Vec<(String, String)>>;
    /// Processes owned by `uid` (fallback when looking for a display).
    fn processes_of(&self, uid: u32) -> Vec<u32>;
    /// The X server of `uid`'s active local graphical session, identified
    /// from sources the requester cannot control. `None` if it cannot be
    /// verified (the dialog then says so).
    fn verified_x_server(&self, uid: u32) -> Option<XServer>;
}

/// Checks the human's credentials. The approval itself (the Approve click)
/// is collected by the dialog before this is called, so a PAM stack that
/// succeeds without a password still cannot skip the human.
pub trait Authenticator: Send + Sync {
    /// Whether the dialog should ask for a password (false for Touch ID).
    fn wants_password(&self) -> bool;
    fn verify(&self, user: &str, password: Option<&str>) -> Result<bool, PlatformError>;
}

/// Everything needed to start the approved command, taken from the snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecPlan {
    /// Absolute, resolved path of the program to execute.
    pub program: String,
    /// argv, including argv[0] as the human saw it.
    pub argv: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: String,
    pub write: Option<Vec<String>>,
    pub no_net: bool,
}

pub trait Sandbox: Send + Sync {
    /// What [`Sandbox::spawn`] will enforce for this plan. Shown in the
    /// dialog before approval and returned to the caller afterwards, so it
    /// must never overstate.
    fn enforcement(&self, plan: &ExecPlan) -> Enforced;
    /// Start the plan with stdin closed and stdout/stderr piped.
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

/// Obtains the daemon's listening socket: inherited from the service
/// manager (systemd/launchd) if it passed one, else bound at `path`.
pub trait Listener: Send + Sync {
    /// `world`: let every local user connect (root mode); else owner only.
    fn listen(&self, path: &Path, world: bool) -> Result<UnixListener, PlatformError>;
}

pub struct Platform {
    pub peer: Box<dyn PeerInfo>,
    pub auth: Box<dyn Authenticator>,
    pub sandbox: Box<dyn Sandbox>,
    pub listener: Box<dyn Listener>,
}

#[cfg(target_os = "linux")]
pub fn current(pam_service: &str) -> Platform {
    linux::platform(pam_service)
}

#[cfg(target_os = "macos")]
pub fn current(_pam_service: &str) -> Platform {
    macos::platform()
}
