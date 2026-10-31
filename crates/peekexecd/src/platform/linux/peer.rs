use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

use crate::platform::{Peer, PeerInfo, Pinned, PlatformError, ProcessInfo, XServer};

/// Ancestors read for a request, at most (a process can nest itself
/// arbitrarily deep).
const MAX_ANCESTRY: usize = 64;

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
        let ancestry = walk((pid, process.start_time), stat_of, process_info);
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

    fn environ(&self, pid: u32, uid: u32) -> Option<Vec<(String, String)>> {
        // The owner of the opened file, not of a path looked up again: the
        // kernel gives /proc/<pid>/environ the process's uid.
        let mut f = std::fs::File::open(format!("/proc/{pid}/environ")).ok()?;
        if f.metadata().ok()?.uid() != uid {
            return None;
        }
        let mut raw = Vec::new();
        std::io::Read::read_to_end(&mut f, &mut raw).ok()?;
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
            exe: exe_id(pid),
            handle: Some(fd),
        })
    }

    fn alive(&self, p: &Pinned) -> bool {
        // Exec keeps the pid and start time: the file is what tells.
        p.handle.as_ref().is_some_and(|fd| pidfd_alive(fd, p.pid)) && exe_id(p.pid) == p.exe
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
    Some(stat_of(pid)?.1)
}

/// Field 22 of /proc/<pid>/stat; fields are counted after the `(comm)`.
fn parse_start_time(stat: &str) -> Option<u64> {
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(19)?.parse().ok()
}

/// The file a process is running, by device and inode.
fn exe_id(pid: u32) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let exe = std::fs::metadata(format!("/proc/{pid}/exe")).ok()?;
    Some((exe.dev(), exe.ino()))
}

/// The ancestors of `start` (a pid and the start time it was described
/// with), nearest first. At each step the pid must still be the process that
/// was accepted (same start time, in the one read that gives its parent),
/// and the parent must have started no later than it, and still be its
/// parent when read again. A pid reused anywhere ends the walk: the request
/// then counts as from fewer ancestors, never from someone else's.
fn walk(
    start: (u32, Option<u64>),
    stat: impl Fn(u32) -> Option<(u32, u64)>,
    info: impl Fn(u32) -> ProcessInfo,
) -> Vec<ProcessInfo> {
    let mut ancestry = Vec::new();
    let mut child = start;
    while ancestry.len() < MAX_ANCESTRY {
        // Past the limit, cut, not followed: an agent session beyond it is
        // not found, so the request counts as unregistered.
        let Some(link) = stat(child.0) else {
            break;
        };
        let (ppid, started) = link;
        if child.1 != Some(started) || ppid <= 1 {
            break;
        }
        let parent = info(ppid);
        if !parent.start_time.is_some_and(|p| p <= started) || stat(child.0) != Some(link) {
            break;
        }
        child = (ppid, parent.start_time);
        ancestry.push(parent);
    }
    ancestry
}

/// Parent pid and start time from one read of `/proc/<pid>/stat`. As bytes:
/// a process may name itself with anything, and must not end the walk.
fn stat_of(pid: u32) -> Option<(u32, u64)> {
    let stat = std::fs::read(format!("/proc/{pid}/stat")).ok()?;
    let stat = String::from_utf8_lossy(&stat);
    Some((parse_ppid(&stat)?, parse_start_time(&stat)?))
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

    fn process(pid: u32, start: u64) -> ProcessInfo {
        ProcessInfo {
            pid,
            exe: None,
            cmdline: vec![],
            start_time: Some(start),
        }
    }

    #[test]
    fn the_walk_follows_a_chain_of_older_parents() {
        let stat = |p| match p {
            300 => Some((200, 30)),
            200 => Some((100, 20)),
            100 => Some((1, 10)),
            _ => None,
        };
        let start = |p: u32| u64::from(p) / 10;
        let chain = walk((300, Some(30)), stat, |p| process(p, start(p)));
        let pids: Vec<u32> = chain.iter().map(|p| p.pid).collect();
        assert_eq!(pids, [200, 100]);
    }

    /// The race 648e2ab named: pid 200 is accepted, exits, and its number
    /// goes to a child of the agent (100). The new process's parent would
    /// join the chain to the agent's session.
    #[test]
    fn a_pid_reused_after_it_was_accepted_ends_the_walk() {
        use std::cell::Cell;
        let reused = Cell::new(false);
        let reads = Cell::new(0);
        let stat = |p| match p {
            300 => {
                reads.set(reads.get() + 1);
                if reads.get() == 2 {
                    reused.set(true);
                }
                Some((200, 30))
            }
            200 if reused.get() => Some((100, 90)),
            200 => Some((50, 20)),
            _ => None,
        };
        let chain = walk((300, Some(30)), stat, |p| process(p, 20));
        let pids: Vec<u32> = chain.iter().map(|p| p.pid).collect();
        assert_eq!(pids, [200], "joined someone else's chain: {pids:?}");
    }

    #[test]
    fn a_parent_younger_than_its_child_ends_the_walk() {
        let stat = |_| Some((200, 30));
        assert!(walk((300, Some(30)), stat, |p| process(p, 31)).is_empty());
    }

    #[test]
    fn a_parent_that_changes_while_described_ends_the_walk() {
        use std::cell::Cell;
        let n = Cell::new(0);
        let stat = |_| {
            n.set(n.get() + 1);
            Some((if n.get() == 1 { 200 } else { 201 }, 30))
        };
        assert!(walk((300, Some(30)), stat, |p| process(p, 20)).is_empty());
    }

    #[test]
    fn a_process_name_that_is_not_utf8_does_not_end_the_walk() {
        let raw = b"300 (\xff\xfe) S 200 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 12345 0 0";
        let stat = String::from_utf8_lossy(raw);
        assert_eq!(parse_ppid(&stat), Some(200));
        assert_eq!(parse_start_time(&stat), Some(12345));
    }

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
        let me = nix::unistd::geteuid().as_raw();
        let env = ProcPeerInfo.environ(std::process::id(), me).unwrap();
        assert!(env.iter().any(|(k, _)| k == "PATH"));
        // Not as anyone else's.
        assert!(ProcPeerInfo
            .environ(std::process::id(), me.wrapping_add(1))
            .is_none());
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

    /// `exec` keeps pid and start time; a registration names a program.
    #[test]
    fn a_process_that_execs_another_program_is_not_the_one_pinned() {
        let me = std::process::id();
        let info = ProcPeerInfo;
        let started = start_time_of(me).unwrap();
        let mut pinned = info.pin(me, started).expect("pidfd_open needs Linux 5.3");
        assert!(info.alive(&pinned));
        pinned.exe = Some((0, 0));
        assert!(!info.alive(&pinned));
    }
}
