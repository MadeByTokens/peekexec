use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};

use peekexec_proto::{Enforced, Level};

use crate::platform::{declared_only, ExecPlan, PlatformError, Sandbox};

/// `--no-net` via a fresh network namespace (root only). Write limits come
/// with Landlock in M2 and are reported as declared only until then.
pub struct Namespaces;

fn is_root() -> bool {
    nix::unistd::geteuid().is_root()
}

impl Sandbox for Namespaces {
    fn enforcement(&self, plan: &ExecPlan) -> Enforced {
        let mut e = declared_only(plan);
        if plan.no_net && is_root() {
            e.network_level = Level::Kernel;
        }
        e
    }

    fn spawn(&self, plan: &ExecPlan) -> Result<Child, PlatformError> {
        let mut cmd = Command::new(&plan.program);
        if let Some(arg0) = plan.argv.first() {
            cmd.arg0(arg0);
        }
        cmd.args(plan.argv.iter().skip(1))
            .env_clear()
            .envs(&plan.env)
            .current_dir(&plan.cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        if plan.no_net && is_root() {
            // SAFETY: unshare is async-signal-safe; the closure touches no
            // allocator or locks.
            unsafe {
                cmd.pre_exec(|| {
                    if libc::unshare(libc::CLONE_NEWNET) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        cmd.spawn()
            .map_err(|e| PlatformError::io(format!("start {}", plan.program), e))
    }
}
