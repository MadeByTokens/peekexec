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
    /// Kernel start time (clock ticks since boot): with the pid, identifies
    /// the process even after the pid is reused.
    pub start_time: Option<u64>,
}

/// A process held so that its pid cannot silently come to mean another one.
#[derive(Debug)]
pub struct Pinned {
    pub pid: u32,
    pub start_time: u64,
    /// Kept open to hold the process; read by the Linux backend.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) handle: Option<std::os::fd::OwnedFd>,
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
    /// Environment of a process owned by `uid` (to find the user's
    /// display). `None` if it is gone, unreadable, or someone else's: before
    /// approval the daemon reads only the requester's own processes
    /// (design rule 1).
    fn environ(&self, pid: u32, uid: u32) -> Option<Vec<(String, String)>>;
    /// Processes owned by `uid` (fallback when looking for a display).
    fn processes_of(&self, uid: u32) -> Vec<u32>;
    /// The X server of `uid`'s active local graphical session, identified
    /// from sources the requester cannot control. `None` if it cannot be
    /// verified (the dialog then says so).
    fn verified_x_server(&self, uid: u32) -> Option<XServer>;
    /// Hold `pid` if it is still the process that started at `start_time`.
    fn pin(&self, pid: u32, start_time: u64) -> Option<Pinned>;
    /// Whether a pinned process is still running.
    fn alive(&self, p: &Pinned) -> bool;
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
#[derive(Debug, Clone)]
pub struct ExecPlan {
    /// Absolute, resolved path of the program to execute.
    pub program: String,
    /// argv, including argv[0] as the human saw it.
    pub argv: Vec<String>,
    pub env: BTreeMap<String, String>,
    /// The working directory as shown to the human...
    pub cwd: String,
    /// ...and opened when it was shown; the command starts in this one.
    pub cwd_fd: Option<std::sync::Arc<std::os::fd::OwnedFd>>,
    pub write: Option<Vec<String>>,
    pub no_net: bool,
    /// The requesting user, recorded as the command's audit login uid.
    pub audit_uid: Option<u32>,
}

pub trait Sandbox: Send + Sync {
    /// What [`Sandbox::spawn`] will enforce for this plan. Shown in the
    /// dialog before approval and returned to the caller afterwards, so it
    /// must never overstate.
    fn enforcement(&self, plan: &ExecPlan) -> Enforced;
    /// Start the plan with stdin closed and stdout/stderr piped.
    fn spawn(&self, plan: &ExecPlan) -> Result<Started, PlatformError>;
}

/// A started command.
pub struct Started {
    pub child: Child,
    /// Every process the command starts, wherever it moves: ended once the
    /// command exits. `None` where the platform cannot hold them; then
    /// only the command's process group is ended.
    pub group: Option<Box<dyn Group>>,
}

/// The processes of one approved command.
pub trait Group: Send {
    /// Kill every process still in the group, and remove it.
    fn end(self: Box<Self>) -> Result<(), String>;
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

/// How a system-drawn approval prompt ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptOutcome {
    Authorized,
    /// Closed or cancelled by the human, or withdrawn because the request was.
    Dismissed,
    /// The human failed to authenticate.
    NotAuthorized,
    /// Nobody could be asked: no authentication agent for the requester.
    NoAgent,
    TimedOut,
}

/// The desktop's own approval prompt (polkit agent on Linux). Used when the
/// daemon cannot verify the display its own dialog would appear on.
pub trait SystemPrompt: Send + Sync {
    /// Whether the human can be asked about `subject` this way, with a
    /// prompt no other program of theirs can stand in for; `Err` says why
    /// not.
    fn usable_for(&self, subject: &ProcessInfo, uid: u32) -> Result<(), String>;
    /// Ask about `subject` (the requesting process) with `message` shown in
    /// the prompt; blocks until answered, `deadline`, or `cancel`.
    fn approve(
        &self,
        subject: &ProcessInfo,
        uid: u32,
        message: &str,
        deadline: std::time::Instant,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<PromptOutcome, PlatformError>;
}

/// Obtains the daemon's listening socket: inherited from the service
/// manager (systemd/launchd) if it passed one, else bound at `path`.
pub trait Listener: Send + Sync {
    /// `group`: also let members of this group connect (the administrators,
    /// in root mode); `None`: the owner only.
    fn listen(&self, path: &Path, group: Option<u32>) -> Result<UnixListener, PlatformError>;
}

pub struct Platform {
    pub peer: Box<dyn PeerInfo>,
    pub auth: Box<dyn Authenticator>,
    pub sandbox: Box<dyn Sandbox>,
    pub listener: Box<dyn Listener>,
    pub system_prompt: Option<Box<dyn SystemPrompt>>,
}

#[cfg(target_os = "linux")]
pub fn current(pam_service: &str) -> Platform {
    linux::platform(pam_service)
}

#[cfg(target_os = "macos")]
pub fn current(_pam_service: &str) -> Platform {
    macos::platform()
}
