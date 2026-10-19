use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Stdio};

use peekexec_proto::{Enforced, Level};

use crate::platform::{declared_only, ExecPlan, PlatformError, Sandbox};
use crate::spawn::{self, Spec};

/// `--no-net` via a fresh network namespace (root only). That stops a
/// well-behaved program from using the network, but it is not containment:
/// a root process can rejoin the host namespace or ask a system service to
/// act for it, so it is reported as best effort. Write limits are declared
/// only. Real containment (approved commands as transient systemd units
/// with a capability bounding set and `ReadWritePaths=`, see PLAN.md) is
/// planned.
pub struct Namespaces;

fn is_root() -> bool {
    nix::unistd::geteuid().is_root()
}

impl Sandbox for Namespaces {
    fn enforcement(&self, plan: &ExecPlan) -> Enforced {
        let mut e = declared_only(plan);
        if plan.no_net && is_root() {
            e.network_level = Level::BestEffort;
        }
        e
    }

    fn spawn(&self, plan: &ExecPlan) -> Result<Child, PlatformError> {
        let env: Vec<(String, String)> = plan
            .env
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let mut cmd = spawn::command(Spec {
            program: Path::new(&plan.program),
            args: plan.argv.get(1..).unwrap_or_default(),
            env: &env,
            stdin: Stdio::null(),
            stdout: Stdio::piped(),
            stderr: Stdio::piped(),
            // The approved command runs as root, and may run setuid tools.
            creds: None,
            no_new_privs: false,
        });
        if let Some(arg0) = plan.argv.first() {
            cmd.arg0(arg0);
        }
        cmd.process_group(0);
        let dir_fd = plan.cwd_fd.as_ref().map(|fd| fd.as_raw_fd());
        if dir_fd.is_none() {
            cmd.current_dir(&plan.cwd);
        }
        let no_net = plan.no_net && is_root();
        // Attribute the command to the requesting user in the audit log
        // (auid), as sudo and pkexec do. Formatted here, written in the child.
        let loginuid = plan
            .audit_uid
            .filter(|_| is_root())
            .map(|uid| std::ffi::CString::new(uid.to_string()).expect("digits"));
        // SAFETY: only async-signal-safe libc calls; no allocation or locks.
        unsafe {
            cmd.pre_exec(move || {
                // The directory that was shown, not whatever its path names now.
                if let Some(fd) = dir_fd {
                    if libc::fchdir(fd) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                libc::umask(0o022);
                if let Some(uid) = &loginuid {
                    let fd = libc::open(c"/proc/self/loginuid".as_ptr(), libc::O_WRONLY);
                    if fd >= 0 {
                        // Best effort: fails if a login uid is already set.
                        libc::write(fd, uid.as_ptr().cast(), uid.count_bytes());
                        libc::close(fd);
                    }
                }
                if no_net && libc::unshare(libc::CLONE_NEWNET) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        cmd.spawn()
            .map_err(|e| PlatformError::io(format!("start {}", plan.program), e))
    }
}
