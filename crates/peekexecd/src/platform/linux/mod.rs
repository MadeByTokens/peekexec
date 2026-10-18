//! Linux backends: kernel peer credentials + /proc, PAM, network namespace
//! for `--no-net`, systemd socket activation. Landlock write limits: M2.

mod display;
mod pam;
mod peer;
mod sandbox;

use std::os::fd::FromRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::Path;

use super::{Listener, Platform, PlatformError};

pub use pam::Pam;
pub use peer::ProcPeerInfo;
pub use sandbox::Namespaces;

pub fn platform(pam_service: &str) -> Platform {
    Platform {
        peer: Box::new(ProcPeerInfo),
        auth: Box::new(Pam::new(pam_service)),
        sandbox: Box::new(Namespaces),
        listener: Box::new(SystemdSocket),
    }
}

/// Uses the socket systemd passed (`LISTEN_FDS`), else binds one.
pub struct SystemdSocket;

const SD_LISTEN_FDS_START: i32 = 3;

impl Listener for SystemdSocket {
    fn listen(&self, path: &Path, world: bool) -> Result<UnixListener, PlatformError> {
        let ours = std::env::var("LISTEN_PID")
            .ok()
            .and_then(|p| p.parse::<u32>().ok())
            == Some(std::process::id());
        let fds: u32 = std::env::var("LISTEN_FDS")
            .ok()
            .and_then(|n| n.parse().ok())
            .unwrap_or(0);
        if ours && fds >= 1 {
            // SAFETY: systemd guarantees fd 3 is an open listening socket
            // passed to this pid; nothing else in this process owns it.
            // Not inherited by the dialog or by approved commands.
            // SAFETY: fcntl on an fd we own; failure is reported.
            if unsafe { libc::fcntl(SD_LISTEN_FDS_START, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
                return Err(PlatformError::io(
                    "set FD_CLOEXEC on the systemd socket",
                    std::io::Error::last_os_error(),
                ));
            }
            return Ok(unsafe { UnixListener::from_raw_fd(SD_LISTEN_FDS_START) });
        }

        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| PlatformError::io(format!("create {}", dir.display()), e))?;
        }
        match std::fs::symlink_metadata(path) {
            Ok(m) if std::os::unix::fs::FileTypeExt::is_socket(&m.file_type()) => {
                std::fs::remove_file(path).map_err(|e| {
                    PlatformError::io(format!("remove stale {}", path.display()), e)
                })?;
            }
            Ok(_) => {
                return Err(PlatformError::Other(format!(
                    "{} exists and is not a socket; refusing to replace it",
                    path.display()
                )))
            }
            Err(_) => {}
        }
        let listener = UnixListener::bind(path)
            .map_err(|e| PlatformError::io(format!("bind {}", path.display()), e))?;
        let mode = if world { 0o666 } else { 0o600 };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .map_err(|e| PlatformError::io(format!("chmod {}", path.display()), e))?;
        Ok(listener)
    }
}
