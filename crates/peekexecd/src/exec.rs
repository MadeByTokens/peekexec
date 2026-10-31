//! Running an approved [`Execution`].

use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::platform::{ExecPlan, Sandbox, Started};

/// Output kept per stream; the rest is drained and dropped.
pub const OUTPUT_CAP: u64 = 16 * 1024 * 1024;

pub struct Outcome {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
}

/// How long output is still read after the command exits. A background
/// process it moved out of its process group (so not killed with it) may
/// hold stdout open; without a limit the request would wait for it.
pub const LINGER: Duration = Duration::from_secs(2);

/// Why there is no [`Outcome`]. The requester must be told which: a command
/// that started may have done its work.
#[derive(Debug)]
pub enum Failure {
    NotStarted(String),
    Started(String),
}

pub fn run(sandbox: &dyn Sandbox, plan: &ExecPlan) -> Result<Outcome, Failure> {
    let Started { mut child, group } = sandbox
        .spawn(plan)
        .map_err(|e| Failure::NotStarted(e.to_string()))?;
    let out = child.stdout.take().expect("piped");
    let err = child.stderr.take().expect("piped");
    let deadline = Arc::new(Mutex::new(None));
    let reader = {
        let deadline = Arc::clone(&deadline);
        std::thread::Builder::new()
            .spawn(move || capture([Box::new(out), Box::new(err)], &deadline))
    };
    // When the command exits, end everything it left behind: its process
    // group, and its cgroup, which holds even the processes that left the
    // group (see THREAT_MODEL.md, boundary 5). Waiting with WNOWAIT keeps
    // the exited child's pid, and so its group id, from being reused
    // before the kill. If no thread could be started to read its output,
    // it is ended at once instead (without a reader it would block on a
    // full pipe).
    if reader.is_ok() {
        wait_exited(child.id());
    }
    // SAFETY: plain signal to the command's own process group.
    unsafe { libc::killpg(child.id() as libc::pid_t, libc::SIGKILL) };
    let ended = group.map(|g| g.end());
    let status = child
        .wait()
        .map_err(|e| Failure::Started(format!("wait: {e}")))?;
    let reader = reader.map_err(|e| {
        Failure::Started(format!(
            "cannot read the command's output ({e}); it was killed"
        ))
    })?;
    if let Some(Err(e)) = ended {
        eprintln!("peekexecd: {e}");
    }
    let exit_code = status
        .code()
        .or_else(|| status.signal().map(|s| 128 + s))
        .unwrap_or(1);
    *deadline.lock().unwrap() = Some(Instant::now() + LINGER);
    let [(stdout, out_cut), (stderr, err_cut)] = reader.join().unwrap_or_default();
    Ok(Outcome {
        exit_code,
        stdout,
        stderr,
        truncated: out_cut || err_cut,
    })
}

/// Block until `pid` has exited, without reaping it.
fn wait_exited(pid: u32) {
    loop {
        // SAFETY: zeroed siginfo is a valid out-parameter for waitid.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        if rc == 0 || io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return;
        }
    }
}

trait Stream: Read + AsRawFd + Send {}
impl<T: Read + AsRawFd + Send> Stream for T {}

/// Read both streams until each reaches end of file or, once `deadline` is
/// set (the command has exited), until it passes. Up to [`OUTPUT_CAP`]
/// bytes per stream are kept.
fn capture(
    mut streams: [Box<dyn Stream>; 2],
    deadline: &Mutex<Option<Instant>>,
) -> [(String, bool); 2] {
    let mut bufs = [Vec::new(), Vec::new()];
    let mut dropped = [0usize; 2];
    let mut open = [true, true];
    let mut chunk = vec![0u8; 64 * 1024];
    let mut lingered = false;
    while open.iter().any(|&o| o) {
        if deadline
            .lock()
            .unwrap()
            .is_some_and(|d| Instant::now() >= d)
        {
            lingered = true;
            break;
        }
        let mut fds: Vec<libc::pollfd> = (0..2)
            .filter(|&i| open[i])
            .map(|i| libc::pollfd {
                fd: streams[i].as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        // SAFETY: `fds` is a valid array of `fds.len()` pollfd structs.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 100) };
        if rc < 0 {
            if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }
        for p in fds.iter().filter(|p| p.revents != 0) {
            let i = (0..2)
                .find(|&i| streams[i].as_raw_fd() == p.fd)
                .expect("polled");
            // Readable or hung up: a read does not block.
            match streams[i].read(&mut chunk) {
                Ok(0) => open[i] = false,
                Ok(n) => {
                    let keep = n.min(OUTPUT_CAP as usize - bufs[i].len());
                    bufs[i].extend_from_slice(&chunk[..keep]);
                    dropped[i] += n - keep;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => open[i] = false,
            }
        }
    }
    std::array::from_fn(|i| {
        let mut s = String::from_utf8_lossy(&bufs[i]).into_owned();
        // A reply must fit a message once encoded (see OUTPUT_BUDGET).
        let cut = peekexec_proto::wire::fit_output(&mut s).unwrap_or(0);
        let truncated = dropped[i] > 0 || cut > 0;
        if truncated {
            s.push_str(&format!(
                "\n[peekexec: {} more bytes dropped]\n",
                dropped[i] + cut
            ));
        }
        if lingered && open[i] {
            s.push_str(
                "\n[peekexec: stopped reading: a background process the command started \
                 still holds this output open]\n",
            );
        }
        (s, truncated || (lingered && open[i]))
    })
}

/// Atomically replace (or create) `dest` with `content`: write a temporary
/// file next to it, fsync, rename. An existing file keeps its mode.
pub fn install(dest: &Path, content: &[u8], id: &str) -> Result<Outcome, String> {
    let dir = dest.parent().ok_or("destination has no parent")?;
    let existing = std::fs::metadata(dest).ok();
    // Setuid, setgid and sticky bits are never carried over to new content.
    let mode = existing
        .as_ref()
        .map(|m| m.permissions().mode() & 0o777)
        .unwrap_or_else(|| new_file_mode(content));
    let tmp = dir.join(format!(".peekexec-{id}.tmp"));
    let err = |what: &str, e: io::Error| format!("{what} {}: {e}", tmp.display());
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| err("create", e))?;
    // A replaced file keeps its owner, group, ACL and SELinux label: a
    // root:shadow file that came back root:root would lock out every
    // program that reads it through its group. chown before chmod, since
    // chown clears setuid bits (none are set anyway).
    let written = f
        .write_all(content)
        .and_then(|()| match &existing {
            Some(m) => std::os::unix::fs::fchown(&f, Some(m.uid()), Some(m.gid())),
            None => Ok(()),
        })
        .and_then(|()| f.set_permissions(std::fs::Permissions::from_mode(mode)))
        .and_then(|()| match &existing {
            Some(_) => copy_xattrs(dest, &f),
            None => Ok(()),
        })
        .and_then(|()| f.sync_all());
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(err("write", e));
    }
    if let Err(e) = std::fs::rename(&tmp, dest) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("rename into {}: {e}", dest.display()));
    }
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(Outcome {
        exit_code: 0,
        stdout: format!("installed {} ({} bytes)\n", dest.display(), content.len()),
        stderr: String::new(),
        truncated: false,
    })
}

/// Mode of a newly created file: executable if it is a program (ELF or
/// `#!`), since that is what a file installed into a bin directory needs.
pub fn new_file_mode(content: &[u8]) -> u32 {
    if content.starts_with(b"\x7fELF") || content.starts_with(b"#!") {
        0o755
    } else {
        0o644
    }
}

/// Security attributes that describe who may use a file, carried over from
/// the file being replaced. An attribute the old file lacks is skipped.
#[cfg(target_os = "linux")]
fn copy_xattrs(from: &Path, to: &std::fs::File) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    let from = std::ffi::CString::new(from.as_os_str().as_bytes()).map_err(io::Error::other)?;
    for name in [c"security.selinux", c"system.posix_acl_access"] {
        let mut buf = vec![0u8; 4096];
        // SAFETY: valid C strings and a buffer of the stated length.
        let n = unsafe {
            libc::getxattr(
                from.as_ptr(),
                name.as_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::ENODATA | libc::ENOTSUP) => continue,
                _ => return Err(e),
            }
        }
        // SAFETY: as above; `n` bytes of `buf` were written by getxattr.
        let rc = unsafe {
            libc::fsetxattr(
                to.as_raw_fd(),
                name.as_ptr(),
                buf.as_ptr().cast(),
                n as usize,
                0,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn copy_xattrs(_from: &Path, _to: &std::fs::File) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    fn install_keeps_the_group() {
        let primary = nix::unistd::getgid().as_raw();
        let Some(other) = nix::unistd::getgroups()
            .unwrap_or_default()
            .into_iter()
            .map(|g| g.as_raw())
            .find(|&g| g != primary)
        else {
            eprintln!("skipped: needs a second group");
            return;
        };
        let dir = std::env::temp_dir().join(format!("pe-group-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("x.conf");
        std::fs::write(&dest, "old\n").unwrap();
        std::os::unix::fs::chown(&dest, None, Some(other)).unwrap();
        install(&dest, b"new\n", "g").unwrap();
        assert_eq!(std::fs::metadata(&dest).unwrap().gid(), other);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn new_programs_are_executable() {
        let dir = std::env::temp_dir().join(format!("pe-newmode-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for (name, content, want) in [
            ("tool", &b"#!/bin/sh\necho hi\n"[..], 0o755),
            ("bin", b"\x7fELF\x02rest", 0o755),
            ("x.conf", b"key=value\n", 0o644),
        ] {
            let dest = dir.join(name);
            install(&dest, content, name).unwrap();
            let mode = std::fs::metadata(&dest).unwrap().permissions().mode() & 0o7777;
            assert_eq!(mode, want, "{name}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn install_replaces_atomically_and_keeps_mode() {
        let dir = std::env::temp_dir().join(format!("pe-install-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("x.conf");
        install(&dest, b"one\n", "a").unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"one\n");
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o640)).unwrap();
        install(&dest, b"two\n", "b").unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"two\n");
        let mode = std::fs::metadata(&dest).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o640);
        assert_eq!(
            std::fs::read_dir(&dir).unwrap().count(),
            1,
            "temp file left behind"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Run where this process's cgroup can be written (a delegated user
    /// unit); skipped elsewhere.
    #[test]
    #[cfg(target_os = "linux")]
    fn processes_that_leave_the_group_are_ended() {
        use crate::platform::{linux::Namespaces, Group};
        match crate::platform::linux::CommandGroup::create() {
            Ok(g) => Box::new(g).end().unwrap(),
            Err(e) => {
                eprintln!("skipped: {e}");
                return;
            }
        }
        // A process in a session of its own, which reports its own pid
        // (`setsid` may fork, so `$!` would name the wrong one).
        let f = std::env::temp_dir().join(format!("pe-setsid-{}", std::process::id()));
        let f = f.to_str().unwrap();
        let script = format!(
            "setsid sh -c 'echo $$ > {f}; exec sleep 300' </dev/null >/dev/null 2>&1 & \
             while [ ! -s {f} ]; do sleep 0.01; done; cat {f}; rm {f}"
        );
        let plan = ExecPlan {
            program: "/bin/sh".into(),
            argv: vec!["sh".into(), "-c".into(), script],
            env: Default::default(),
            cwd: "/".into(),
            cwd_fd: None,
            write: None,
            no_net: false,
            audit_uid: None,
        };
        let out = run(&Namespaces, &plan).unwrap();
        let pid: u32 = out.stdout.trim().parse().expect(&out.stdout);
        // Gone, or a zombie waiting for whoever reaps orphans.
        let deadline = Instant::now() + Duration::from_secs(2);
        let running = || {
            std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .is_ok_and(|st| !st.rsplit(')').next().unwrap_or("").starts_with(" Z"))
        };
        while running() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!running(), "setsid child {pid} outlived the command");
    }
}
