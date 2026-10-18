//! macOS backends (M4): getpeereid + LOCAL_PEERPID, LocalAuthentication
//! (Touch ID / password), sandbox-exec (best effort, reported as
//! declared_only where it cannot guarantee), launchd socket.

use std::os::unix::net::{UnixListener, UnixStream};
use std::process::Child;

use peekexec_proto::Enforced;

use super::{
    declared_only, AuthOutcome, Authenticator, Challenger, ExecPlan, Listener, Peer, PeerInfo,
    Platform, PlatformError, Sandbox,
};

pub fn platform() -> Platform {
    Platform {
        peer: Box::new(Unported),
        auth: Box::new(Unported),
        sandbox: Box::new(Unported),
        listener: Box::new(Unported),
    }
}

pub struct Unported;

impl PeerInfo for Unported {
    fn identify(&self, _conn: &UnixStream) -> Result<Peer, PlatformError> {
        Err(PlatformError::Unsupported(
            "peer identification on macOS (M4)",
        ))
    }
}

impl Authenticator for Unported {
    fn authenticate(
        &self,
        _user: &str,
        _ui: &mut dyn Challenger,
    ) -> Result<AuthOutcome, PlatformError> {
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
    fn listen(&self) -> Result<UnixListener, PlatformError> {
        Err(PlatformError::Unsupported("launchd socket (M4)"))
    }
}
