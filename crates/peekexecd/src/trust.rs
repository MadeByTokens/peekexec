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

/// A program that handles secrets or the user's files (the dialog, the
/// inspection helper) must not be readable by others: the kernel makes a
/// process that execs a file it cannot read non-dumpable from the start,
/// so the user cannot attach to it before it hardens itself.
pub fn not_readable_by_others(path: &Path) -> Result<(), String> {
    let mode = std::fs::metadata(path)
        .map_err(|e| format!("{}: {e}", path.display()))?
        .permissions()
        .mode();
    if mode & 0o044 != 0 {
        return Err(format!(
            "{} is readable by others (mode {:o}); install it 0711, as install.sh does",
            path.display(),
            mode & 0o7777
        ));
    }
    Ok(())
}

/// Canonicalize `path` and check it and every ancestor. Returns the
/// canonical path.
pub fn check(path: &Path, owners: &[u32]) -> Result<PathBuf, String> {
    check_with(path, owners, false)
}

/// Like [`check`], for a directory already open: it walks up from the
/// object held, never by name, so moving or re-pointing a path meanwhile
/// changes nothing. `shown` names it in the errors.
pub fn check_dir(dir: &std::fs::File, shown: &str, owners: &[u32]) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let err = |e: std::io::Error| format!("{shown}: {e}");
    let mut cur = dir.try_clone().map_err(err)?;
    let mut leaf = true;
    // Deeper than PATH_MAX allows: something is wrong.
    for _ in 0..2048 {
        let m = cur.metadata().map_err(err)?;
        let what = if leaf {
            shown.to_string()
        } else {
            format!("a directory above {shown}")
        };
        if !owners.contains(&m.uid()) {
            return Err(format!(
                "{what} is owned by uid {}, which is not trusted: it could change after approval",
                m.uid()
            ));
        }
        let nosuid = nix::sys::statvfs::fstatvfs(&cur).map_or(true, |s| {
            s.flags().contains(nix::sys::statvfs::FsFlags::ST_NOSUID)
        });
        if nosuid {
            return Err(format!(
                "{what} is on a filesystem mounted nosuid: whoever mounted it controls its files"
            ));
        }
        let mode = m.permissions().mode();
        // Not even sticky (/tmp): a root-owned directory in one can be
        // removed by a root job (tmp cleaning) and the name taken by the
        // user before the request runs.
        if mode & 0o022 != 0 {
            return Err(format!(
                "{what} is writable by other users: it could change after approval"
            ));
        }
        // `..` of the object itself, through its descriptor.
        let parent = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(format!("/proc/self/fd/{}/..", cur.as_raw_fd()))
            .map_err(err)?;
        let p = parent.metadata().map_err(err)?;
        if (p.dev(), p.ino()) == (m.dev(), m.ino()) {
            return Ok(());
        }
        cur = parent;
        leaf = false;
    }
    Err(format!("{shown}: too many directories above it"))
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
        // Not even a sticky directory (/tmp) above it: what root owns
        // there can be removed by a root job (tmp cleaning) and the name
        // taken by the user between approval and use.
        if m.permissions().mode() & 0o022 != 0 {
            return Err(format!(
                "{} is writable by other users: it could change after approval",
                p.display()
            ));
        }
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
#[cfg(target_os = "linux")]
#[allow(clippy::unnecessary_cast)]
fn on_kernel_fs(p: &Path) -> bool {
    const KERNEL: [i64; 5] = [0x9fa0, 0x6265_6572, 0x0102_1994, 0x1cd1, 0x6367_7270];
    nix::sys::statfs::statfs(p).is_ok_and(|s| KERNEL.contains(&(s.filesystem_type().0 as i64)))
}

#[cfg(not(target_os = "linux"))]
fn on_kernel_fs(_: &Path) -> bool {
    false
}

fn is_executable_file(p: &Path) -> bool {
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// For tests: a new directory (mode 0755) that this process's owner rule
/// trusts, outside `/tmp` (which no chain may pass through): under
/// `$XDG_RUNTIME_DIR` or `$HOME`, whichever the check accepts. `None` if
/// neither does; the test then skips.
#[cfg(test)]
pub fn test_dir(tag: &str) -> Option<PathBuf> {
    let owners = trusted_owners();
    let base = ["XDG_RUNTIME_DIR", "HOME"]
        .iter()
        .filter_map(std::env::var_os)
        .map(PathBuf::from)
        .find(|b| check(b, &owners).is_ok())?;
    let dir = base.join(format!(".pe-test-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).ok()?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).ok()?;
    Some(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readable_programs_are_refused() {
        let dir = std::env::temp_dir().join(format!("pe-mode-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("prog");
        std::fs::write(&f, b"x").unwrap();
        for (mode, ok) in [(0o711, true), (0o700, true), (0o755, false), (0o751, false)] {
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(not_readable_by_others(&f).is_ok(), ok, "{mode:o}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn system_binaries_are_trusted() {
        let p = resolve_program("sh", "/", &[0]).unwrap();
        assert!(p.is_absolute());
    }

    #[test]
    fn user_files_are_not_trusted_by_root() {
        let Some(dir) = test_dir("trust") else {
            eprintln!("skipped: no trusted scratch directory");
            return;
        };
        let f = dir.join("tool");
        std::fs::write(&f, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
        let me = nix::unistd::geteuid().as_raw();
        if me != 0 {
            let err = check(&f, &[0]).unwrap_err();
            assert!(err.contains("not trusted"), "{err}");
        }
        assert!(check(&f, &[0, me]).is_ok());
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(check(&f, &[0, me])
            .unwrap_err()
            .contains("writable by other"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn open_directories_are_checked_by_object() {
        let open = |p: &str| std::fs::File::open(p).unwrap();
        // Not /usr/share: GitHub's ubuntu-24.04 runner makes it writable by
        // everyone, and then it is rightly not trusted.
        let r = check_dir(&open("/etc"), "/etc", &[0]);
        assert!(r.is_ok(), "{r:?}");
        // Sticky and world-writable: not as it, and not above it either.
        let err = check_dir(&open("/tmp"), "/tmp", &[0]).unwrap_err();
        assert!(err.contains("writable by other"), "{err}");
        let in_tmp = std::fs::read_dir("/tmp").ok().and_then(|d| {
            d.filter_map(Result::ok).map(|e| e.path()).find(|p| {
                std::fs::symlink_metadata(p).is_ok_and(|m| {
                    m.is_dir() && m.uid() == 0 && m.permissions().mode() & 0o022 == 0
                })
            })
        });
        match in_tmp {
            Some(p) => {
                let err = check(&p, &[0]).unwrap_err();
                assert!(err.contains("/tmp is writable by other"), "{err}");
            }
            None => eprintln!("skipped: no root-owned directory in /tmp"),
        }
        if !nix::unistd::geteuid().is_root() {
            let home = std::env::var("HOME").unwrap();
            let err = check_dir(&open(&home), &home, &[0]).unwrap_err();
            assert!(err.contains("not trusted"), "{err}");
        }
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
