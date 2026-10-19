//! Which files root may run or write into without breaking the binding
//! between what the human saw and what executes.
//!
//! A program the requester can modify could be swapped after approval, so
//! programs (and install destinations) must be owned by a trusted uid all the
//! way up the directory chain, and not writable by anyone else.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Programs are looked up here, never in the requester's PATH.
pub const SAFE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

const S_ISVTX: u32 = 0o1000;

/// Owners whose files are trusted: root, plus the daemon's own uid (which
/// is root in production; the developer in `--dev` mode).
pub fn trusted_owners() -> Vec<u32> {
    let me = nix::unistd::geteuid().as_raw();
    if me == 0 {
        vec![0]
    } else {
        vec![0, me]
    }
}

/// Canonicalize `path` and check it and every ancestor. Returns the
/// canonical path.
pub fn check(path: &Path, owners: &[u32]) -> Result<PathBuf, String> {
    check_with(path, owners, false)
}

/// Whether the user could change what `path` names, as the program will
/// look it up after approval: every existing prefix of the path *as
/// written* must be root-controlled, so a symlink, a missing file or a
/// directory under the user's control counts too. Kernel filesystems
/// (/proc, /sys, /dev) are nosuid but their owners are real.
pub fn check_named(path: &Path, owners: &[u32]) -> Result<(), String> {
    use std::os::unix::fs::FileTypeExt;
    for p in path.ancestors() {
        // A device node's mode says who may use the device (/dev/null is
        // 0666), not who may change what the name refers to: its directory
        // decides that, and is checked next.
        let device = |m: &std::fs::Metadata| {
            let t = m.file_type();
            t.is_char_device() || t.is_block_device()
        };
        match std::fs::symlink_metadata(p) {
            Ok(m) if device(&m) => continue,
            Ok(_) => {
                check_with(p, owners, true)?;
            }
            Err(_) => {}
        }
    }
    Ok(())
}

fn check_with(path: &Path, owners: &[u32], kernel_fs_ok: bool) -> Result<PathBuf, String> {
    let canon = path
        .canonicalize()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let mut leaf = true;
    for p in canon.ancestors() {
        let m = std::fs::metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
        if !owners.contains(&m.uid()) {
            return Err(format!(
                "{} is owned by uid {}, which is not trusted: it could change after approval",
                p.display(),
                m.uid()
            ));
        }
        if on_nosuid_mount(p) && !(kernel_fs_ok && on_kernel_fs(p)) {
            return Err(format!(
                "{} is on a filesystem mounted nosuid (removable media, a disk image or FUSE \
                 mounted for a user): whoever mounted it controls its files, whatever owner \
                 they show",
                p.display()
            ));
        }
        let mode = m.permissions().mode();
        let sticky_dir = !leaf && m.is_dir() && mode & S_ISVTX != 0;
        if mode & 0o022 != 0 && !sticky_dir {
            return Err(format!(
                "{} is writable by other users: it could change after approval",
                p.display()
            ));
        }
        leaf = false;
    }
    Ok(canon)
}

/// Resolve argv[0] the way the human will be shown it: relative to `cwd` if
/// it contains a slash, else in [`SAFE_PATH`]. The result is canonical and
/// trusted.
pub fn resolve_program(name: &str, cwd: &str, owners: &[u32]) -> Result<PathBuf, String> {
    let candidate = if name.contains('/') {
        Path::new(cwd).join(name)
    } else {
        SAFE_PATH
            .split(':')
            .map(|dir| Path::new(dir).join(name))
            .find(|p| is_executable_file(p))
            .ok_or_else(|| format!("{name}: not found in {SAFE_PATH}"))?
    };
    if !is_executable_file(&candidate) {
        return Err(format!("{}: not an executable file", candidate.display()));
    }
    check(&candidate, owners).map_err(|e| {
        format!("{e}. To run a file you own, use `peekexec script`, which snapshots it")
    })
}

/// Mounts made for users (udisks for removable media and disk images,
/// FUSE) are always nosuid, and the kernel itself refuses to trust setuid
/// files there. Their files may claim any owner, so ownership proves
/// nothing. Unknown (statvfs failed) counts as nosuid.
fn on_nosuid_mount(p: &Path) -> bool {
    use nix::sys::statvfs::{statvfs, FsFlags};
    statvfs(p).map_or(true, |s| s.flags().contains(FsFlags::ST_NOSUID))
}

/// proc, sysfs, tmpfs (and devtmpfs), devpts, cgroup2: files the kernel
/// owns, whose owners cannot be claimed by whoever mounted them.
// f_type is i64 here but differs by architecture.
#[allow(clippy::unnecessary_cast)]
fn on_kernel_fs(p: &Path) -> bool {
    const KERNEL: [i64; 5] = [0x9fa0, 0x6265_6572, 0x0102_1994, 0x1cd1, 0x6367_7270];
    nix::sys::statfs::statfs(p).is_ok_and(|s| KERNEL.contains(&(s.filesystem_type().0 as i64)))
}

fn is_executable_file(p: &Path) -> bool {
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_binaries_are_trusted() {
        let p = resolve_program("sh", "/", &[0]).unwrap();
        assert!(p.is_absolute());
    }

    #[test]
    fn user_files_are_not_trusted_by_root() {
        let dir = std::env::temp_dir().join(format!("pe-trust-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Independent of the umask (Ubuntu's 002 makes new dirs group-writable).
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let f = dir.join("tool");
        std::fs::write(&f, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
        let me = nix::unistd::geteuid().as_raw();
        if me != 0 {
            let err = check(&f, &[0]).unwrap_err();
            assert!(err.contains("not trusted"), "{err}");
        }
        // /tmp is world-writable but sticky: fine as an ancestor.
        assert!(check(&f, &[0, me]).is_ok());
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(check(&f, &[0, me])
            .unwrap_err()
            .contains("writable by other"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_programs_are_reported() {
        let err = resolve_program("no-such-tool-zz", "/", &[0]).unwrap_err();
        assert!(err.contains("not found"));
    }

    #[test]
    fn nosuid_mounts_are_not_trusted() {
        // /run is a nosuid tmpfs on systemd systems; files on such mounts
        // (removable media, disk images, FUSE) may claim any owner.
        let run = Path::new("/run");
        if !on_nosuid_mount(run) {
            eprintln!("skipped: /run is not mounted nosuid here");
            return;
        }
        let err = check(run, &[0]).unwrap_err();
        assert!(err.contains("nosuid"), "{err}");
        assert!(!on_nosuid_mount(Path::new("/usr/bin")));
    }
}
