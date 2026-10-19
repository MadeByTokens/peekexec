//! Starting processes (design rule 5): every process the daemon starts gets
//! an explicit environment, explicit stdio, no other descriptors, and, when
//! it runs as someone else, credentials dropped for good. Callers add their
//! own `pre_exec` steps after these.

use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};

/// The user a process is started as.
#[derive(Debug, Clone)]
pub struct Creds {
    pub uid: u32,
    pub gid: u32,
    /// Supplementary groups; empty for none.
    pub groups: Vec<u32>,
}

/// Everything about a process that is not left to inheritance.
pub struct Spec<'a> {
    pub program: &'a Path,
    pub args: &'a [String],
    /// The whole environment: nothing is inherited.
    pub env: &'a [(String, String)],
    pub stdin: Stdio,
    pub stdout: Stdio,
    pub stderr: Stdio,
    /// Run as this user (from root), or unchanged.
    pub creds: Option<Creds>,
    /// `no_new_privs`: exec can never grant more privilege. For everything
    /// but the approved command, which may legitimately run setuid tools.
    pub no_new_privs: bool,
}

/// close_range(2) flag: mark the range close-on-exec instead of closing it,
/// so std's own exec-error pipe keeps working.
#[cfg(target_os = "linux")]
const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;

/// A [`Command`] set up from `spec`.
pub fn command(spec: Spec) -> Command {
    let mut cmd = Command::new(spec.program);
    cmd.args(spec.args)
        .env_clear()
        .envs(spec.env.iter().map(|(k, v)| (k, v)))
        .stdin(spec.stdin)
        .stdout(spec.stdout)
        .stderr(spec.stderr);
    let creds = spec.creds.map(|c| {
        let groups: Vec<libc::gid_t> = c.groups.clone();
        (c.uid as libc::uid_t, c.gid as libc::gid_t, groups)
    });
    // Only Linux has no_new_privs.
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
    let no_new_privs = spec.no_new_privs;
    // SAFETY: only async-signal-safe libc calls on data prepared before the
    // fork; no allocation.
    unsafe {
        cmd.pre_exec(move || {
            // Nothing but stdio reaches the program, whatever another
            // thread had open without O_CLOEXEC. Before Linux 5.11 there is
            // no CLOSE_RANGE_CLOEXEC: mark each descriptor instead. If
            // neither works, the process is not started (design rule 5).
            #[cfg(target_os = "linux")]
            if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, CLOSE_RANGE_CLOEXEC) != 0 {
                let mut limit = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let max = limit.rlim_cur.min(libc::c_int::MAX as libc::rlim_t) as libc::c_int;
                for fd in 3..max {
                    let flags = libc::fcntl(fd, libc::F_GETFD);
                    if flags >= 0 && libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
            }
            if let Some((uid, gid, groups)) = &creds {
                // Groups first (root's group 0 must not leak), then gid,
                // then uid; then make sure none of it can be undone.
                if libc::setgroups(groups.len() as _, groups.as_ptr()) != 0
                    || libc::setgid(*gid) != 0
                    || libc::setuid(*uid) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getegid() != *gid || (*uid != 0 && libc::setuid(0) == 0) {
                    return Err(std::io::Error::from_raw_os_error(libc::EPERM));
                }
                // After setuid the kernel makes the process dumpable again
                // (per fs.suid_dumpable), so until exec the user could
                // attach to it: a copy of the daemon's memory, holding all
                // of its descriptors. exec of a 0711 binary keeps it so.
                #[cfg(target_os = "linux")]
                if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            #[cfg(target_os = "linux")]
            if no_new_privs && libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd
}
