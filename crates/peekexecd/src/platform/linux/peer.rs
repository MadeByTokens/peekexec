use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

use crate::platform::{Peer, PeerInfo, Pinned, PlatformError, ProcessInfo, XServer};

/// SO_PEERCRED for the identity, /proc for the description, and a pidfd
/// (SO_PEERPIDFD, Linux 6.5+) to prove the description is of that process.
pub struct ProcPeerInfo;

impl PeerInfo for ProcPeerInfo {
    fn identify(&self, conn: &UnixStream) -> Result<Peer, PlatformError> {
        let cred = getsockopt(conn, PeerCredentials)
            .map_err(|e| PlatformError::Other(format!("SO_PEERCRED: {e}")))?;
        let pid = cred.pid() as u32;
        let pidfd = peer_pidfd(conn);

        let process = process_info(pid);
        let cwd = readlink(pid, "cwd");
        let mut ancestry = Vec::new();
        let mut next = parent_pid(pid);
        while let Some(ppid) = next.filter(|&p| p > 1) {
            ancestry.push(process_info(ppid));
            next = parent_pid(ppid);
        }
        // Still alive after we read /proc, so the pid was not reused meanwhile.
        let pinned = pidfd.as_ref().is_some_and(|fd| pidfd_alive(fd, pid));
        Ok(Peer {
            uid: cred.uid(),
            gid: cred.gid(),
            process,
            cwd,
            ancestry,
            pinned,
        })
    }

    fn environ(&self, pid: u32) -> Option<Vec<(String, String)>> {
        let raw = std::fs::read(format!("/proc/{pid}/environ")).ok()?;
        Some(
            raw.split(|&b| b == 0)
                .filter_map(|kv| std::str::from_utf8(kv).ok()?.split_once('='))
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
    }

    fn verified_x_server(&self, uid: u32) -> Option<XServer> {
        super::display::verified_x_server(uid)
    }

    fn pin(&self, pid: u32, start_time: u64) -> Option<Pinned> {
        // SAFETY: pidfd_open returns a new fd we own, or -1.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
        if fd < 0 {
            return None;
        }
        // SAFETY: fd is a fresh, valid descriptor owned by nobody else.
        let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
        // Opened after looking: confirm it is still the same process.
        (start_time_of(pid) == Some(start_time) && pidfd_alive(&fd, pid)).then_some(Pinned {
            pid,
            start_time,
            handle: Some(fd),
        })
    }

    fn alive(&self, p: &Pinned) -> bool {
        p.handle.as_ref().is_some_and(|fd| pidfd_alive(fd, p.pid))
    }

    fn processes_of(&self, uid: u32) -> Vec<u32> {
        let Ok(dir) = std::fs::read_dir("/proc") else {
            return Vec::new();
        };
        dir.filter_map(Result::ok)
            .filter_map(|e| {
                let pid: u32 = e.file_name().to_str()?.parse().ok()?;
                (e.metadata().ok()?.uid() == uid).then_some(pid)
            })
            .collect()
    }
}

/// SO_PEERPIDFD from asm-generic/socket.h (x86_64, aarch64, riscv, ...).
#[cfg(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64"
))]
const SO_PEERPIDFD: libc::c_int = 77;

#[cfg(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64"
))]
fn peer_pidfd(conn: &UnixStream) -> Option<OwnedFd> {
    let mut fd: libc::c_int = -1;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: fd/len point to valid, correctly sized locals.
    let rc = unsafe {
        libc::getsockopt(
            conn.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_PEERPIDFD,
            (&mut fd as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    // SAFETY: on success the kernel returned a new fd that we now own.
    (rc == 0 && fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64"
)))]
fn peer_pidfd(_conn: &UnixStream) -> Option<OwnedFd> {
    None
}

/// The pidfd still names a live process, and it is `pid`.
fn pidfd_alive(fd: &OwnedFd, pid: u32) -> bool {
    // SAFETY: signal 0 only checks existence; null siginfo is allowed.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            0,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if rc != 0 {
        return false;
    }
    let fdinfo = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd()));
    fdinfo.ok().is_some_and(|info| {
        info.lines()
            .find_map(|l| l.strip_prefix("Pid:"))
            .and_then(|p| p.trim().parse::<u32>().ok())
            == Some(pid)
    })
}

fn readlink(pid: u32, what: &str) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/{what}"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// Appended to an executable path that names some other file here.
pub const NOT_THIS_FILE: &str = " (not the file at this path)";

/// The executable of `pid`, as a path in the daemon's own view of the
/// filesystem. The kernel prints the path as the process sees it: in another
/// mount namespace a bind mount can put any file at `/usr/bin/bash`. So the
/// path is accepted only if it names the very file the process runs (same
/// device and inode); otherwise it is marked, and no trust check passes.
pub fn exe_of(pid: u32) -> Option<String> {
    let path = readlink(pid, "exe")?;
    let running = std::fs::metadata(format!("/proc/{pid}/exe")).ok();
    let here = std::fs::metadata(&path).ok();
    let same =
        matches!((running, here), (Some(a), Some(b)) if a.dev() == b.dev() && a.ino() == b.ino());
    Some(if same {
        path
    } else {
        format!("{path}{NOT_THIS_FILE}")
    })
}

fn process_info(pid: u32) -> ProcessInfo {
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline"))
        .map(|raw| {
            raw.split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect()
        })
        .unwrap_or_default();
    ProcessInfo {
        pid,
        exe: exe_of(pid),
        cmdline,
        start_time: start_time_of(pid),
    }
}

fn start_time_of(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_start_time(&stat)
}

/// Field 22 of /proc/<pid>/stat; fields are counted after the `(comm)`.
fn parse_start_time(stat: &str) -> Option<u64> {
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(19)?.parse().ok()
}

fn parent_pid(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_ppid(&stat)
}

/// The comm field (in parentheses) may itself contain spaces and ')', so
/// parse from the last ')': "<pid> (<comm>) <state> <ppid> ...".
fn parse_ppid(stat: &str) -> Option<u32> {
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(1)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_self_over_socketpair() {
        let (a, _b) = UnixStream::pair().unwrap();
        let peer = ProcPeerInfo.identify(&a).unwrap();
        assert_eq!(peer.process.pid, std::process::id());
        assert_eq!(peer.uid, nix::unistd::getuid().as_raw());
        assert!(peer.process.exe.is_some());
        assert!(!peer.ancestry.is_empty());
    }

    #[test]
    fn pins_with_pidfd_on_new_kernels() {
        let (a, _b) = UnixStream::pair().unwrap();
        let has_pidfd = peer_pidfd(&a).is_some();
        assert_eq!(ProcPeerInfo.identify(&a).unwrap().pinned, has_pidfd);
    }

    #[test]
    fn ppid_survives_hostile_comm() {
        assert_eq!(parse_ppid("42 (evil) 1 2 ) S 777 42 42"), Some(777));
        assert_eq!(parse_ppid("42 (bash) S 100 42 42"), Some(100));
        assert_eq!(parse_ppid("garbage"), None);
    }

    #[test]
    fn pins_self_and_rejects_wrong_start_time() {
        let me = std::process::id();
        let st = start_time_of(me).unwrap();
        let pinned = ProcPeerInfo.pin(me, st).expect("pin self");
        assert!(ProcPeerInfo.alive(&pinned));
        assert!(ProcPeerInfo.pin(me, st + 1).is_none());
    }

    #[test]
    fn reads_own_environ() {
        let env = ProcPeerInfo.environ(std::process::id()).unwrap();
        assert!(env.iter().any(|(k, _)| k == "PATH"));
    }

    #[test]
    fn exe_path_must_name_the_running_file() {
        let me = exe_of(std::process::id()).unwrap();
        assert!(!me.ends_with(NOT_THIS_FILE), "{me}");

        // In its own mount namespace a process can put another file at a
        // system path; the kernel then reports that path as its executable.
        let dir = std::env::temp_dir().join(format!("pe-exe-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let copy = dir.join("sleep");
        std::fs::copy("/bin/sleep", &copy).unwrap();
        let script = format!(
            "mount --bind {} /bin/sleep && exec /bin/sleep 5",
            copy.display()
        );
        let mut child = std::process::Command::new("unshare")
            .args(["-Urm", "sh", "-c", &script])
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300));
        let exe = exe_of(child.id());
        let _ = child.kill();
        let _ = child.wait();
        std::fs::remove_dir_all(&dir).unwrap();
        match exe {
            Some(e) if e.starts_with("/bin/sleep") || e.starts_with("/usr/bin/sleep") => {
                assert!(e.ends_with(NOT_THIS_FILE), "{e}");
            }
            // No unprivileged user namespaces here (e.g. AppArmor-restricted).
            other => eprintln!("skipped: no namespace sandbox ({other:?})"),
        }
    }
}
