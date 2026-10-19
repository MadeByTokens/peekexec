//! Looking at the filesystem for a request before the human approves it.
//!
//! Design rule 1: before approval the daemon acts with the requesting
//! user's authority, not root's. What root could learn about files the user
//! cannot access would reach the requester in a preview, an error, or the
//! dialog (which runs as the user). So every path the request names is
//! resolved, checked and read here, in a helper process with the user's
//! credentials and `no_new_privs`, and the kernel decides what may be looked
//! at. The helper returns the facts and the opened working directory
//! (`SCM_RIGHTS`); the daemon never resolves a requester-named path as root
//! before approval.
//!
//! In development mode the daemon already runs as the user, and
//! [`inspect`] is called directly.

use std::io::{BufReader, IoSlice, IoSliceMut, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use peekexec_core::{Action, Request};
use peekexec_proto::wire::{read_msg, write_msg};
use serde::{Deserialize, Serialize};

use crate::prepare::display_line;
use crate::spawn::{self, Spec};
use crate::trust;

/// argv[1] that makes `peekexecd` act as the inspection helper.
pub const HELPER_ARG: &str = "--inspect-helper";

/// A path on a filesystem that never answers (the user's own FUSE mount,
/// say) must not hold the request forever.
pub const HELPER_TIMEOUT: Duration = Duration::from_secs(10);

/// Largest existing file whose content is read to show a diff.
const DIFF_MAX: u64 = 4 * 1024 * 1024;

/// What the daemon needs to know about the filesystem to show and run a
/// request, as seen with the requesting user's authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inspection {
    /// The working directory, canonical.
    pub cwd: String,
    pub cwd_warning: Option<String>,
    pub facts: Facts,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Facts {
    Run {
        /// argv[0], resolved, canonical and trusted.
        program: String,
        file_args_note: Option<String>,
    },
    Script {
        interpreter: String,
        interpreter_arg: Option<String>,
    },
    Install {
        /// Final destination, canonical parent.
        dest: String,
        existing: Option<Existing>,
    },
}

/// The file an install would replace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Existing {
    pub len: u64,
    pub mode: u32,
    pub owner: String,
    /// Its content, or why it is not shown, worded to follow "whose
    /// current content".
    pub content: Result<Vec<u8>, String>,
}

pub use crate::spawn::Creds;

/// Inspect `req` with this process's own authority. `owners` are the uids
/// whose files count as root-controlled (the daemon's, not this process's).
pub fn inspect(req: &Request, owners: &[u32]) -> Result<(Inspection, OwnedFd), String> {
    inspect_unexplained(req, owners).map_err(explain_denied)
}

fn inspect_unexplained(req: &Request, owners: &[u32]) -> Result<(Inspection, OwnedFd), String> {
    let (cwd, fd, cwd_warning) = open_workdir(&req.cwd, owners)?;
    let facts = match &req.action {
        Action::Run { argv } => {
            let program = trust::resolve_program(&argv[0], &cwd, owners)?;
            Facts::Run {
                program: path_str(&program)?,
                file_args_note: untrusted_file_args(&argv[1..], &cwd, owners),
            }
        }
        Action::Script { content, .. } => {
            let (interpreter, interpreter_arg) = interpreter(content, owners)?;
            Facts::Script {
                interpreter,
                interpreter_arg,
            }
        }
        Action::Install { src, dest, .. } => {
            let dest = install_target(dest, src, owners)?;
            Facts::Install {
                existing: existing(&dest),
                dest: path_str(&dest)?,
            }
        }
    };
    Ok((
        Inspection {
            cwd,
            cwd_warning,
            facts,
        },
        fd,
    ))
}

/// A refusal because the user cannot look at a path says how to do the
/// step anyway: in a script, which the human reads in full.
fn explain_denied(e: String) -> String {
    if e.contains("Permission denied") {
        format!(
            "{e}. You cannot access this yourself, so peekexec does not look at it before \
             approval. Do that step inside `peekexec script`, where the human reads exactly \
             what happens"
        )
    } else {
        e
    }
}

/// Run [`inspect`] in a helper process: `helper` is this daemon's own
/// binary, started with [`HELPER_ARG`], with `creds` (or unchanged, in
/// tests), `no_new_privs`, an environment of only `LANG=C.UTF-8`, and only
/// its stdio.
pub fn inspect_as(
    helper: &Path,
    creds: Option<&Creds>,
    req: &Request,
    owners: &[u32],
) -> Result<(Inspection, OwnedFd), String> {
    let fail = |e: std::io::Error| format!("cannot start the inspection helper: {e}");
    let (mut conn, theirs) = UnixStream::pair().map_err(fail)?;
    let theirs_out = theirs.try_clone().map_err(fail)?;
    let mut cmd = spawn::command(Spec {
        program: helper,
        args: &[HELPER_ARG.into()],
        env: &[("LANG".into(), "C.UTF-8".into())],
        stdin: Stdio::from(OwnedFd::from(theirs)),
        stdout: Stdio::from(OwnedFd::from(theirs_out)),
        stderr: Stdio::null(),
        creds: creds.cloned(),
        no_new_privs: true,
    });
    let mut child = cmd.spawn().map_err(fail)?;
    // The child holds its own copies of its ends now.
    drop(cmd);
    let result = exchange(&mut conn, req, owners);
    let _ = child.kill();
    let _ = child.wait();
    let (inspection, fd) = result?;
    // The helper runs as the user, so its answer is input like any other.
    // Facts root relies on are checked again here. Failures say nothing
    // specific: a forged answer must not become a way to probe as root.
    match verify(req, &inspection, &fd, owners) {
        Ok(cwd_warning) => Ok((
            Inspection {
                cwd_warning,
                ..inspection
            },
            fd,
        )),
        Err(why) => {
            eprintln!("peekexecd: inspection helper answer rejected: {why}");
            Err("the inspection helper's answer did not verify; see the daemon log".into())
        }
    }
}

/// Check what the daemon relies on in a helper's answer, as root. What can
/// be derived from the request is derived again and compared: the program
/// argv[0] resolves to, the interpreter and `#!` flag the content names,
/// the install destination. The rest is checked: the install directory is
/// root-controlled, the descriptor is the directory shown. Root only looks
/// again at paths the helper, as the user, already reached, and the
/// results are only compared, never reported, so this reveals nothing
/// (design rule 1). Returns the working-directory warning, recomputed.
pub fn verify(
    req: &Request,
    inspection: &Inspection,
    cwd_fd: &OwnedFd,
    owners: &[u32],
) -> Result<Option<String>, String> {
    let trusted = |p: &str| {
        Path::new(p).is_absolute()
            && trust::check(Path::new(p), owners).is_ok_and(|c| c == Path::new(p))
    };
    match (&req.action, &inspection.facts) {
        (Action::Run { argv }, Facts::Run { program, .. }) => {
            let expected = trust::resolve_program(&argv[0], &inspection.cwd, owners)
                .ok()
                .and_then(|p| p.to_str().map(str::to_string));
            if !trusted(program) || expected.as_deref() != Some(program.as_str()) {
                return Err(format!(
                    "program {program:?} is not what {:?} resolves to",
                    argv[0]
                ));
            }
        }
        (
            Action::Script { content, .. },
            Facts::Script {
                interpreter: got,
                interpreter_arg: got_arg,
            },
        ) => {
            // The same parse and flag allowlist, on the request's own bytes.
            let expected = interpreter(content, owners).ok();
            if !trusted(got) || expected != Some((got.clone(), got_arg.clone())) {
                return Err(format!(
                    "interpreter {got:?} {got_arg:?} is not what the #! line names"
                ));
            }
        }
        (Action::Install { src, dest, .. }, Facts::Install { dest: got, .. }) => {
            // Derived here, independently, and required to match exactly.
            // Only compared, never reported: it reveals nothing.
            let got = Path::new(got);
            let expected = expected_install_target(dest, src);
            let parent_ok = got.parent().is_some_and(|p| trusted(&p.to_string_lossy()));
            if expected.as_deref() != Some(got) || !parent_ok {
                return Err(format!(
                    "install destination {got:?} does not match {dest:?}"
                ));
            }
        }
        _ => return Err("facts do not match the request".into()),
    }
    let held = nix::sys::stat::fstat(cwd_fd.as_raw_fd()).map_err(|e| format!("fstat: {e}"))?;
    let shown = std::fs::metadata(&inspection.cwd).map_err(|e| format!("cwd: {e}"))?;
    let is_dir = held.st_mode & libc::S_IFMT == libc::S_IFDIR;
    if !is_dir || (held.st_dev as u64, held.st_ino as u64) != (shown.dev(), shown.ino()) {
        return Err(format!(
            "the directory descriptor is not {:?}",
            inspection.cwd
        ));
    }
    Ok(trust::check(Path::new(&inspection.cwd), owners)
        .err()
        .map(|why| {
            format!(
                "Runs inside {}, which root does not control ({why}). Programs may load \
             code or settings from it (git, python, make, npm...).",
                inspection.cwd
            )
        }))
}

#[derive(Serialize, Deserialize)]
struct Job {
    request: Request,
    owners: Vec<u32>,
}

type Reply = Result<Inspection, String>;

fn exchange(
    conn: &mut UnixStream,
    req: &Request,
    owners: &[u32],
) -> Result<(Inspection, OwnedFd), String> {
    let timeout = |e: std::io::Error| match e.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => format!(
            "inspecting the request took longer than {} s: a path it names may be on a \
             filesystem that does not answer",
            HELPER_TIMEOUT.as_secs()
        ),
        _ => format!("inspection helper: {e}"),
    };
    conn.set_read_timeout(Some(HELPER_TIMEOUT))
        .map_err(timeout)?;
    write_msg(
        conn,
        &Job {
            request: req.clone(),
            owners: owners.to_vec(),
        },
    )
    .map_err(timeout)?;
    let fd = recv_marker(conn).map_err(timeout)?;
    let reply: Reply = read_msg(&mut BufReader::new(&*conn))
        .map_err(timeout)?
        .ok_or("the inspection helper exited without answering")?;
    match (reply, fd) {
        (Ok(inspection), Some(fd)) => Ok((inspection, fd)),
        (Ok(_), None) => Err("the inspection helper sent no directory descriptor".into()),
        (Err(e), _) => Err(e),
    }
}

/// One marker byte, carrying the working directory's descriptor when the
/// inspection succeeded.
fn recv_marker(conn: &UnixStream) -> std::io::Result<Option<OwnedFd>> {
    use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags};
    let mut byte = [0u8; 1];
    let mut iov = [IoSliceMut::new(&mut byte)];
    let mut space = nix::cmsg_space!(RawFd);
    #[cfg(target_os = "linux")]
    let flags = MsgFlags::MSG_CMSG_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let flags = MsgFlags::empty();
    let msg = recvmsg::<()>(conn.as_raw_fd(), &mut iov, Some(&mut space), flags)?;
    if msg.bytes == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "the inspection helper exited without answering",
        ));
    }
    let mut fd = None;
    for c in msg.cmsgs()? {
        if let ControlMessageOwned::ScmRights(fds) = c {
            for raw in fds {
                // SAFETY: the kernel just installed this descriptor for us.
                let owned = unsafe { OwnedFd::from_raw_fd(raw) };
                fd.get_or_insert(owned);
            }
        }
    }
    Ok(fd)
}

/// The helper's main: one job on stdin (a socket), the marker byte (with
/// the directory descriptor) and the reply on stdout (the same socket).
pub fn helper_main() -> ! {
    // Other programs of the user must not be able to drive this process.
    // Installed mode 0711 (not readable by users), it is non-dumpable from
    // exec on; this covers other installs.
    // SAFETY: plain prctl call with constant arguments.
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0)
    };
    // SAFETY: fd 0 is the socket the daemon passed; nothing else owns it.
    let conn = unsafe { UnixStream::from_raw_fd(0) };
    let job: Job = match read_msg(&mut BufReader::new(&conn)) {
        Ok(Some(job)) => job,
        _ => std::process::exit(2),
    };
    let (fd, reply): (Option<OwnedFd>, Reply) = match inspect(&job.request, &job.owners) {
        Ok((inspection, fd)) => (Some(fd), Ok(inspection)),
        Err(e) => (None, Err(e)),
    };
    let sent = send_marker(&conn, fd.as_ref());
    if sent.is_err() || write_msg(&mut &conn, &reply).is_err() {
        std::process::exit(3);
    }
    std::process::exit(0)
}

fn send_marker(conn: &UnixStream, fd: Option<&OwnedFd>) -> std::io::Result<()> {
    use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags, UnixAddr};
    let raw: Vec<RawFd> = fd.iter().map(|f| f.as_raw_fd()).collect();
    let cmsgs: Vec<ControlMessage> = if raw.is_empty() {
        Vec::new()
    } else {
        vec![ControlMessage::ScmRights(&raw)]
    };
    sendmsg::<UnixAddr>(
        conn.as_raw_fd(),
        &[IoSlice::new(b"F")],
        &cmsgs,
        MsgFlags::empty(),
        None,
    )?;
    Ok(())
}

fn path_str(p: &Path) -> Result<String, String> {
    p.to_str()
        .map(str::to_string)
        .ok_or_else(|| format!("path is not valid UTF-8: {}", p.display()))
}

fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// A directory descriptor usable with fchdir (O_PATH is Linux-only).
#[cfg(target_os = "linux")]
const DIR_FLAGS: i32 = libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC;
#[cfg(not(target_os = "linux"))]
const DIR_FLAGS: i32 = libc::O_DIRECTORY | libc::O_CLOEXEC;

/// The directory the command runs in, opened once: the process changes into
/// this very directory (by descriptor), not whatever the path names later.
fn open_workdir(
    requested: &str,
    owners: &[u32],
) -> Result<(String, OwnedFd, Option<String>), String> {
    let canon = Path::new(requested)
        .canonicalize()
        .map_err(|e| format!("working directory {requested}: {e}"))?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(DIR_FLAGS)
        .open(&canon)
        .map_err(|e| format!("working directory {}: {e}", canon.display()))?;
    let path = path_str(&canon)?;
    // Programs load code and settings from the directory they run in
    // (git hooks and config, Python modules, Makefiles, ...).
    let warning = trust::check(&canon, owners).err().map(|why| {
        format!(
            "Runs inside {path}, which root does not control ({why}). Programs may load \
             code or settings from it (git, python, make, npm...)."
        )
    });
    Ok((path, OwnedFd::from(file), warning))
}

/// The interpreter for a script: its `#!` line (resolved and trusted;
/// `/usr/bin/env NAME` is looked up in SAFE_PATH), else /bin/sh.
pub fn interpreter(content: &[u8], owners: &[u32]) -> Result<(String, Option<String>), String> {
    let first = content.split(|&b| b == b'\n').next().unwrap_or_default();
    let Some(shebang) = first.strip_prefix(b"#!") else {
        let sh = trust::resolve_program("sh", "/", owners)?;
        return Ok((path_str(&sh)?, None));
    };
    let line = std::str::from_utf8(shebang)
        .map_err(|_| "the #! line is not valid UTF-8".to_string())?
        .trim();
    let (prog, arg) = match line.split_once(char::is_whitespace) {
        Some((p, a)) => (p, Some(a.trim().to_string()).filter(|a| !a.is_empty())),
        None => (line, None),
    };
    if !prog.starts_with('/') {
        return Err(format!(
            "the #! interpreter must be an absolute path, got {prog:?}"
        ));
    }
    if basename(prog) == "env" {
        let name = arg.ok_or("`#!/usr/bin/env` needs a program name")?;
        if name.contains(char::is_whitespace) || name.starts_with('-') {
            return Err(format!("unsupported #!/usr/bin/env arguments: {name:?}"));
        }
        let resolved = trust::resolve_program(&name, "/", owners)?;
        return Ok((path_str(&resolved)?, None));
    }
    let resolved = trust::resolve_program(prog, "/", owners)?;
    let resolved = path_str(&resolved)?;
    if let Some(a) = &arg {
        if !shebang_flag_ok(basename(&resolved), a) {
            return Err(format!(
                "the #! line passes {a:?} to {resolved}. Allowed: simple shell flags \
                 (-e, -eu, -x...), python -I/-s/-E..., perl -w/-T, and -f for awk, sed and \
                 make. Other flags can make an interpreter run code the human never sees"
            ));
        }
    }
    Ok((resolved, arg))
}

/// `#!` arguments go to the interpreter before the script, so they must not
/// name files, modules or code, and their meaning depends on the
/// interpreter (`-e` is "exit on error" to sh, "run this code" to perl or
/// awk). So each family has its own set; `interp` is the resolved binary's
/// name (`dash`, `python3.10`, `gawk`).
fn shebang_flag_ok(interp: &str, arg: &str) -> bool {
    let Some(flags) = arg.strip_prefix('-') else {
        return false;
    };
    let family = interp.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    let allowed = match family {
        "sh" | "bash" | "dash" | "zsh" | "ksh" | "mksh" | "ash" => "aeEfuvxBCTl",
        "python" => "IsSEBuO",
        "perl" => "wWXTt",
        // `-f FILE`: read the program from the script itself, as the kernel
        // would for `#!/usr/bin/awk -f`.
        "awk" | "gawk" | "mawk" | "nawk" | "sed" | "make" | "gmake" => return flags == "f",
        _ => return false,
    };
    !flags.is_empty() && flags.len() <= 6 && flags.chars().all(|c| allowed.contains(c))
}

/// Arguments naming an existing file that root does not control
/// (`sh ~/x.sh`, `cp /tmp/f /etc/`, `--config=/home/u/c`): the program may
/// read or run it, but its content is not shown and can change after
/// approval. One note for all of them.
fn untrusted_file_args(args: &[String], cwd: &str, owners: &[u32]) -> Option<String> {
    let mut hits = Vec::new();
    for a in args {
        let value = a.split_once('=').map_or(a.as_str(), |(_, v)| v);
        if !value.contains('/') {
            continue;
        }
        let path = Path::new(cwd).join(value);
        if !std::fs::metadata(&path).is_ok_and(|m| m.is_file()) {
            continue;
        }
        if trust::check(&path, owners).is_err() && !hits.contains(&value) {
            hits.push(value);
        }
    }
    (!hits.is_empty()).then(|| {
        let shown: Vec<String> = hits
            .iter()
            .take(3)
            .map(|h| display_line(h, 100).into_string())
            .collect();
        let more = hits.len().saturating_sub(3);
        format!(
            "Names {}{}, which root does not control: if the program reads or runs it, that \
             content is not shown here and can change after approval. To run your own script \
             use `peekexec script`; to put a file in place, `peekexec install`.",
            shown.join(", "),
            if more > 0 {
                format!(" and {more} more")
            } else {
                String::new()
            }
        )
    })
}

/// Final destination of an install: `dest`, or `dest/basename(src)` if
/// `dest` is a directory. Its directory must be trusted; an existing target
/// must be a regular file.
fn install_target(dest: &str, src: &str, owners: &[u32]) -> Result<PathBuf, String> {
    let mut target = PathBuf::from(dest);
    if target.is_dir() {
        let name = Path::new(src)
            .file_name()
            .ok_or_else(|| format!("cannot take a file name from {src}"))?;
        target.push(name);
    }
    let parent = target
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", target.display()))?;
    let parent = trust::check(parent, owners)
        .map_err(|e| format!("install destination not allowed: {e}"))?;
    let target = parent.join(target.file_name().ok_or("destination has no file name")?);
    match std::fs::symlink_metadata(&target) {
        Ok(m) if !m.file_type().is_file() => Err(format!(
            "{} exists and is not a regular file (directory, symlink or device)",
            target.display()
        )),
        Ok(m) if m.nlink() > 1 => Err(format!("{} has other hard links", target.display())),
        Ok(_) => Ok(target),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(target),
        Err(e) => Err(format!("{}: {e}", target.display())),
    }
}

/// Where an install of `src` to `dest` lands, by the same rule as
/// [`install_target`] (a directory gets `basename(src)`), with the parent
/// canonical. `None` if it cannot be worked out.
fn expected_install_target(dest: &str, src: &str) -> Option<PathBuf> {
    let mut target = PathBuf::from(dest);
    if target.is_dir() {
        target.push(Path::new(src).file_name()?);
    }
    let parent = target.parent()?.canonicalize().ok()?;
    Some(parent.join(target.file_name()?))
}

/// The file an install would replace, read as far as this process may.
fn existing(target: &Path) -> Option<Existing> {
    let m = std::fs::metadata(target).ok()?;
    let content = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(target)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::PermissionDenied => {
                "cannot be read without root, so it is not shown".to_string()
            }
            _ => format!("cannot be read: {e}"),
        })
        .and_then(|f| {
            let mut buf = Vec::new();
            f.take(DIFF_MAX + 1)
                .read_to_end(&mut buf)
                .map_err(|e| format!("cannot be read: {e}"))?;
            if buf.len() as u64 > DIFF_MAX {
                return Err(format!(
                    "is larger than {} MiB, so it is not compared",
                    DIFF_MAX >> 20
                ));
            }
            Ok(buf)
        });
    Some(Existing {
        len: m.len(),
        mode: m.permissions().mode() & 0o777,
        owner: owner_name(m.uid(), m.gid()),
        content,
    })
}

/// `user:group`, by name where the user database has one.
fn owner_name(uid: u32, gid: u32) -> String {
    use nix::unistd::{Gid, Group, Uid, User};
    let user = User::from_uid(Uid::from_raw(uid))
        .ok()
        .flatten()
        .map_or_else(|| uid.to_string(), |u| u.name);
    let group = Group::from_gid(Gid::from_raw(gid))
        .ok()
        .flatten()
        .map_or_else(|| gid.to_string(), |g| g.name);
    format!("{user}:{group}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shebang_flags_are_allowlisted() {
        for (interp, ok) in [
            ("dash", "-e"),
            ("bash", "-eu"),
            ("bash", "-eux"),
            ("python3.10", "-I"),
            ("python3", "-Is"),
            ("perl", "-w"),
            ("gawk", "-f"),
            ("sed", "-f"),
        ] {
            assert!(shebang_flag_ok(interp, ok), "{interp} {ok}");
        }
        for bad in [
            "-mfoo",
            "-c",
            "-r/home/u/x",
            "--rcfile",
            "-e /tmp/x",
            "x",
            "-",
            "-Mstrict",
        ] {
            assert!(!shebang_flag_ok("bash", bad), "{bad}");
        }
        // `-e`/`-E` means "the next argument is code" to these.
        for (interp, bad) in [
            ("gawk", "-e"),
            ("mawk", "-e"),
            ("perl", "-e"),
            ("perl", "-E"),
            ("ruby", "-e"),
            ("node", "-e"),
            ("php", "-B"),
            ("busybox", "-e"),
            ("gawk", "-fe"),
        ] {
            assert!(!shebang_flag_ok(interp, bad), "{interp} {bad}");
        }
        let owners = trust::trusted_owners();
        assert!(interpreter(b"#!/bin/sh -c\n", &owners).is_err());
    }

    #[test]
    fn interpreter_from_shebang() {
        let owners = trust::trusted_owners();
        let (sh, arg) = interpreter(b"echo hi\n", &owners).unwrap();
        assert!(sh.starts_with('/') && arg.is_none());
        let (bash, _) = interpreter(b"#!/usr/bin/env bash\necho\n", &owners).unwrap();
        assert!(bash.ends_with("bash"));
        let (_, arg) = interpreter(b"#!/bin/sh -e\n", &owners).unwrap();
        assert_eq!(arg.as_deref(), Some("-e"));
        assert!(interpreter(b"#!relative\n", &owners).is_err());
        assert!(interpreter(b"#!/usr/bin/env -S bash -x\n", &owners).is_err());
    }

    #[test]
    fn arguments_naming_user_files_are_flagged() {
        if nix::unistd::geteuid().is_root() {
            return;
        }
        let dir = std::env::temp_dir().join(format!("pe-argfile-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("job.sh");
        std::fs::write(&script, "echo hi\n").unwrap();
        let s = script.to_str().unwrap();
        // Trusted owners are root only, as in production.
        let note = untrusted_file_args(&[s.into()], "/", &[0]).unwrap();
        assert!(note.contains("job.sh"), "{note}");
        let opt = format!("--config={s}");
        assert!(untrusted_file_args(&[opt], "/", &[0]).is_some());
        // System files and plain words are not flagged.
        assert!(untrusted_file_args(&["/etc/hostname".into(), "-y".into()], "/", &[0]).is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn req(action: Action, cwd: &str) -> Request {
        Request {
            action,
            why: None,
            write: None,
            no_net: false,
            env: Default::default(),
            cwd: cwd.into(),
            timeout_secs: 30,
        }
    }

    fn dir_fd(p: &str) -> OwnedFd {
        OwnedFd::from(
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(DIR_FLAGS)
                .open(p)
                .unwrap(),
        )
    }

    #[test]
    fn helper_answers_are_verified() {
        let owners = [0];
        let run = req(
            Action::Run {
                argv: vec!["true".into()],
            },
            "/",
        );
        let program = path_str(&trust::resolve_program("true", "/", &owners).unwrap()).unwrap();
        let honest = Inspection {
            cwd: "/".into(),
            cwd_warning: None,
            facts: Facts::Run {
                program,
                file_args_note: None,
            },
        };
        assert!(verify(&run, &honest, &dir_fd("/"), &owners).is_ok());

        // A forged program: a file the user controls.
        let dir = std::env::temp_dir().join(format!("pe-verify-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fake = dir.join("true");
        std::fs::write(&fake, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let forged = Inspection {
            facts: Facts::Run {
                program: fake.to_str().unwrap().into(),
                file_args_note: None,
            },
            ..honest.clone()
        };
        if !nix::unistd::geteuid().is_root() {
            assert!(verify(&run, &forged, &dir_fd("/"), &owners).is_err());
        }
        std::fs::remove_dir_all(&dir).unwrap();

        // The descriptor must be the directory shown.
        let moved = Inspection {
            cwd: "/usr".into(),
            ..honest.clone()
        };
        assert!(verify(&run, &moved, &dir_fd("/"), &owners).is_err());

        // Another trusted program than argv[0] names.
        let other = Inspection {
            facts: Facts::Run {
                program: path_str(&trust::resolve_program("false", "/", &owners).unwrap()).unwrap(),
                file_args_note: None,
            },
            ..honest.clone()
        };
        assert!(verify(&run, &other, &dir_fd("/"), &owners).is_err());

        // A script's interpreter and flag must be what its #! line names.
        let script = req(
            Action::Script {
                path: "x.sh".into(),
                content: b"#!/bin/sh -e\ntrue\n".to_vec(),
                args: vec![],
            },
            "/",
        );
        let (interp, arg) = interpreter(b"#!/bin/sh -e\n", &owners).unwrap();
        let facts = |interpreter: &str, interpreter_arg: Option<&str>| Inspection {
            facts: Facts::Script {
                interpreter: interpreter.into(),
                interpreter_arg: interpreter_arg.map(String::from),
            },
            ..honest.clone()
        };
        assert!(verify(
            &script,
            &facts(&interp, arg.as_deref()),
            &dir_fd("/"),
            &owners
        )
        .is_ok());
        // A flag the allowlist would refuse, or none at all.
        assert!(verify(&script, &facts(&interp, Some("-c")), &dir_fd("/"), &owners).is_err());
        assert!(verify(&script, &facts(&interp, None), &dir_fd("/"), &owners).is_err());
        // Another trusted interpreter.
        let other = path_str(&trust::resolve_program("true", "/", &owners).unwrap()).unwrap();
        assert!(verify(&script, &facts(&other, Some("-e")), &dir_fd("/"), &owners).is_err());

        // An install must land where it was asked to.
        let install = req(
            Action::Install {
                src: "a.conf".into(),
                content: vec![],
                dest: "/etc/a.conf".into(),
            },
            "/",
        );
        let elsewhere = Inspection {
            facts: Facts::Install {
                dest: "/etc/sudoers.d/zz".into(),
                existing: None,
            },
            ..honest.clone()
        };
        assert!(verify(&install, &elsewhere, &dir_fd("/"), &owners).is_err());
        // Same file name, another trusted directory: still not the request.
        let same_name = Inspection {
            facts: Facts::Install {
                dest: "/etc/sudoers.d/a.conf".into(),
                existing: None,
            },
            ..honest.clone()
        };
        assert!(verify(&install, &same_name, &dir_fd("/"), &owners).is_err());
        // A directory as the destination gets the source's name, and only that.
        let into_dir = req(
            Action::Install {
                src: "/home/u/a.conf".into(),
                content: vec![],
                dest: "/etc".into(),
            },
            "/",
        );
        let named = |d: &str| Inspection {
            facts: Facts::Install {
                dest: d.into(),
                existing: None,
            },
            ..honest.clone()
        };
        assert!(verify(&into_dir, &named("/etc/a.conf"), &dir_fd("/"), &owners).is_ok());
        assert!(verify(&into_dir, &named("/etc/b.conf"), &dir_fd("/"), &owners).is_err());
        let right = Inspection {
            facts: Facts::Install {
                dest: "/etc/a.conf".into(),
                existing: None,
            },
            ..honest
        };
        assert!(verify(&install, &right, &dir_fd("/"), &owners).is_ok());
    }

    #[test]
    fn unreadable_existing_files_are_not_read() {
        if nix::unistd::geteuid().is_root() {
            return;
        }
        let dir = std::env::temp_dir().join(format!("pe-existing-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("secret.conf");
        std::fs::write(&f, "secret-line\n").unwrap();
        assert_eq!(existing(&f).unwrap().content.unwrap(), b"secret-line\n");
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o000)).unwrap();
        let e = existing(&f).unwrap();
        assert!(e
            .content
            .unwrap_err()
            .contains("cannot be read without root"));
        assert_eq!(e.len, 12, "what stat shows anyone who can reach it");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
