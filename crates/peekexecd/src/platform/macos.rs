//! macOS backends (M4): getpeereid + LOCAL_PEERPID, LocalAuthentication
//! (Touch ID / password), sandbox-exec (best effort, reported as
//! declared_only where it cannot guarantee), launchd socket.

use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::Child;

use peekexec_proto::Enforced;

use super::{
    declared_only, Authenticator, ExecPlan, Listener, Peer, PeerInfo, Pinned, Platform,
    PlatformError, Sandbox, XServer,
};

pub fn platform() -> Platform {
    Platform {
        peer: Box::new(Unported),
        auth: Box::new(Unported),
        sandbox: Box::new(Unported),
        listener: Box::new(Unported),
        system_prompt: None,
    }
}

pub struct Unported;

impl PeerInfo for Unported {
    fn identify(&self, _conn: &UnixStream) -> Result<Peer, PlatformError> {
        Err(PlatformError::Unsupported(
            "peer identification on macOS (M4)",
        ))
    }

    fn environ(&self, _pid: u32) -> Option<Vec<(String, String)>> {
        None
    }

    fn processes_of(&self, _uid: u32) -> Vec<u32> {
        Vec::new()
    }

    fn verified_x_server(&self, _uid: u32) -> Option<XServer> {
        None
    }

    fn pin(&self, _pid: u32, _start_time: u64) -> Option<Pinned> {
        None
    }

    fn alive(&self, _p: &Pinned) -> bool {
        false
    }
}

impl Authenticator for Unported {
    fn wants_password(&self) -> bool {
        false
    }

    fn verify(&self, _user: &str, _password: Option<&str>) -> Result<bool, PlatformError> {
        Err(PlatformError::Unsupported("authentication on macOS (M4)"))
    }
}

impl Sandbox for Unported {
    fn enforcement(&self, plan: &ExecPlan) -> Enforced {
        // Nothing is enforced yet.
        declared_only(plan)
    }

    fn spawn(&self, _plan: &ExecPlan) -> Result<Child, PlatformError> {
        Err(PlatformError::Unsupported("execution on macOS (M4)"))
    }
}

impl Listener for Unported {
    fn listen(&self, _path: &Path, _group: Option<u32>) -> Result<UnixListener, PlatformError> {
        Err(PlatformError::Unsupported("launchd socket (M4)"))
    }
}
