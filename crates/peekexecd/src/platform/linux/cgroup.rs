//! A cgroup of its own for each approved command, so that when it exits
//! everything it started is ended, including processes that left its
//! process group (`setsid`, `nohup ... &` with job control, double forks).
//! A process cannot leave a cgroup by itself unless it may write the cgroup
//! tree: the tree is the daemon's (the service has `Delegate=yes`), and the
//! approved command, being root, could move its processes out on purpose,
//! as it could do anything else; this bounds what it starts by accident or
//! by habit (`&`, `nohup`, `setsid`), not what it is written to escape.
//! Processes handed to systemd (`systemd-run`, `systemctl start`) become
//! units of systemd's own and are not ended; daemons the command starts
//! itself (a FUSE mount, `dhclient`) are.
//!
//! The command enters its group itself, before `exec` (see
//! [`CommandGroup::procs`]), so nothing it runs is ever outside it.

use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::platform::Group;

const ROOT: &str = "/sys/fs/cgroup";

/// How long the processes of a group may take to go once killed.
const END_TIMEOUT: Duration = Duration::from_secs(5);

pub struct CommandGroup {
    dir: PathBuf,
}

impl CommandGroup {
    /// A new, empty cgroup under this process's own. `Err` where there is
    /// no cgroup v2 hierarchy or it cannot be written (not root and not
    /// delegated, or a service without `Delegate=yes`); the caller then
    /// ends only the process group.
    pub fn create() -> Result<CommandGroup, String> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        if !Path::new(ROOT).join("cgroup.controllers").exists() {
            return Err("no cgroup v2 hierarchy at /sys/fs/cgroup".into());
        }
        let own = std::fs::read_to_string("/proc/self/cgroup")
            .map_err(|e| format!("/proc/self/cgroup: {e}"))?;
        let own = own_path(&own).ok_or("not in a cgroup v2 hierarchy")?;
        let parent = Path::new(ROOT).join(own.trim_start_matches('/'));
        // A group of the same name may be left from an earlier run whose
        // pid this one reuses (its processes still in it): take the next.
        let mut last = None;
        for _ in 0..16 {
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let dir = parent.join(format!("peekexec-cmd-{}-{n}", std::process::id()));
            match std::fs::create_dir(&dir) {
                Ok(()) => return Ok(CommandGroup { dir }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => last = Some(e),
                Err(e) => return Err(format!("create {}: {e}", dir.display())),
            }
        }
        Err(format!(
            "no free group name under {}: {last:?}",
            parent.display()
        ))
    }

    /// The file a process writes `0` to, to move itself into the group.
    pub fn procs(&self) -> CString {
        let p = self.dir.join("cgroup.procs");
        CString::new(p.into_os_string().into_encoded_bytes()).expect("no NUL in a cgroup path")
    }

    fn file(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn events(&self, key: &str) -> Option<bool> {
        let events = std::fs::read_to_string(self.file("cgroup.events")).ok()?;
        events_flag(&events, key)
    }

    /// Kill every process in the group: `cgroup.kill` (Linux 5.14+), or
    /// else freeze it, so nothing forks or exits meanwhile, and kill each
    /// member. A frozen process is still alive, so its pid still names it.
    fn kill_all(&self) -> Result<(), String> {
        if std::fs::write(self.file("cgroup.kill"), "1").is_ok() {
            return Ok(());
        }
        std::fs::write(self.file("cgroup.freeze"), "1")
            .map_err(|e| format!("cannot freeze {}: {e}", self.dir.display()))?;
        let deadline = Instant::now() + END_TIMEOUT;
        while self.events("frozen") != Some(true) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        // Freezing covers the groups below, which the command may have
        // made: their members are killed too.
        for pid in members(&self.dir) {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
        Ok(())
    }
}

impl Group for CommandGroup {
    fn end(self: Box<Self>) -> Result<(), String> {
        let killed = self.kill_all();
        let deadline = Instant::now() + END_TIMEOUT;
        while self.events("populated") != Some(false) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        std::fs::remove_dir(&self.dir).map_err(|e| {
            format!(
                "processes the command left behind may still run in {}: {e}",
                self.dir.display()
            )
        })?;
        killed
    }
}

/// Groups left by an earlier run of the daemon that ended abruptly:
/// removed once empty (systemd kills their processes when it stops the
/// service).
pub fn remove_stale() {
    let Ok(own) = std::fs::read_to_string("/proc/self/cgroup") else {
        return;
    };
    let Some(own) = own_path(&own) else {
        return;
    };
    let Ok(entries) = std::fs::read_dir(Path::new(ROOT).join(own.trim_start_matches('/'))) else {
        return;
    };
    for e in entries.filter_map(Result::ok) {
        if e.file_name().to_string_lossy().starts_with("peekexec-cmd-") {
            let _ = std::fs::remove_dir(e.path());
        }
    }
}

/// The processes in `dir` and in every group below it.
fn members(dir: &Path) -> Vec<i32> {
    let mut out: Vec<i32> = std::fs::read_to_string(dir.join("cgroup.procs"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.trim().parse().ok())
        .collect();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.filter_map(Result::ok) {
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                out.extend(members(&e.path()));
            }
        }
    }
    out
}

/// The cgroup v2 path in a `/proc/<pid>/cgroup` (its `0::` line).
fn own_path(cgroup: &str) -> Option<&str> {
    cgroup
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .filter(|p| p.starts_with('/') && !p.split('/').any(|c| c == ".."))
}

/// A `key 0|1` line of `cgroup.events`.
fn events_flag(events: &str, key: &str) -> Option<bool> {
    events.lines().find_map(|l| {
        let (k, v) = l.split_once(' ')?;
        (k == key).then_some(v.trim() == "1")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cgroup_files() {
        assert_eq!(
            own_path("0::/system.slice/peekexecd.service\n"),
            Some("/system.slice/peekexecd.service")
        );
        assert_eq!(own_path("12:pids:/x\n"), None);
        assert_eq!(own_path("0::/a/../b\n"), None);
        let ev = "populated 1\nfrozen 0\n";
        assert_eq!(events_flag(ev, "populated"), Some(true));
        assert_eq!(events_flag(ev, "frozen"), Some(false));
        assert_eq!(events_flag(ev, "x"), None);
    }
}
