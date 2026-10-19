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
        if on_nosuid_mount(p) {
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

/// Whether `uid` (with `groups`) could read `path` itself, judged from the
/// mode bits. Conservative: with a POSIX ACL the group bits are only a mask,
/// so such a file counts as readable only if everyone may read it.
pub fn readable_by(path: &Path, uid: u32, groups: &[u32]) -> bool {
    let Ok(m) = std::fs::metadata(path) else {
        return false;
    };
    let mode = m.permissions().mode();
    if uid == 0 || mode & 0o004 != 0 {
        return true;
    }
    if has_acl(path) {
        return false;
    }
    if m.uid() == uid {
        mode & 0o400 != 0
    } else {
        groups.contains(&m.gid()) && mode & 0o040 != 0
    }
}

#[cfg(target_os = "linux")]
fn has_acl(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(p) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return true;
    };
    // SAFETY: valid C strings; a null buffer of size 0 only asks for the size.
    let n = unsafe {
        libc::getxattr(
            p.as_ptr(),
            c"system.posix_acl_access".as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };
    // No such attribute, or a filesystem without them: no ACL. Anything
    // else (e.g. EACCES): assume there is one.
    n >= 0
        || !matches!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ENODATA | libc::ENOTSUP)
        )
}

#[cfg(not(target_os = "linux"))]
fn has_acl(_path: &Path) -> bool {
    true
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

    #[test]
    fn readability_follows_mode_bits() {
        let dir = std::env::temp_dir().join(format!("pe-read-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("f");
        std::fs::write(&f, "x").unwrap();
        let me = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        let set = |m| std::fs::set_permissions(&f, std::fs::Permissions::from_mode(m)).unwrap();
        set(0o600);
        assert!(readable_by(&f, me, &[gid]));
        assert!(!readable_by(&f, me + 1, &[gid]));
        set(0o640);
        assert!(readable_by(&f, me + 1, &[gid]));
        assert!(!readable_by(&f, me + 1, &[gid + 1]));
        set(0o604);
        assert!(readable_by(&f, me + 1, &[gid + 1]));
        set(0o000);
        assert!(!readable_by(&f, me, &[gid]));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
