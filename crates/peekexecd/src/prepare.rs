//! Turns a client [`Request`] into (a) the exact [`PromptView`] the human
//! sees and (b) the exact [`Execution`] that runs if they approve. Both come
//! from the same resolved values, in one place, so they cannot disagree.

use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use peekexec_core::display::shell_join;
use peekexec_core::format::{format_shell, verbatim};
use peekexec_core::{Action, Request};
use peekexec_proto::view::{ProcLine, PromptView, Section, Syntax};
use peekexec_proto::{DisplayTier, Enforced, Level};

use crate::platform::{ExecPlan, Peer, ProcessInfo, Sandbox};
use crate::trust::{self, SAFE_PATH};

pub enum Execution {
    Command(ExecPlan),
    /// Written by the daemon itself; no program runs.
    Install {
        dest: PathBuf,
        content: Vec<u8>,
    },
}

pub struct Prepared {
    pub view: PromptView,
    pub exec: Execution,
    pub enforced: Enforced,
    /// Root-owned copy of a script, removed after the request ends.
    pub snapshot_dir: Option<PathBuf>,
}

pub struct Ctx<'a> {
    pub sandbox: &'a dyn Sandbox,
    pub wants_password: bool,
    pub dev: bool,
    pub snapshot_root: &'a Path,
}

/// Longest dialog timeout a request may ask for.
pub const MAX_TIMEOUT_SECS: u32 = 600;

const SHELLS: &[&str] = &["sh", "bash", "dash", "zsh", "ksh", "mksh", "ash", "busybox"];

/// The only variables a request may set. An allowlist, because the list of
/// variables that make *some* program load code from an unshown place
/// (LD_*, PATH, BASH_ENV, PYTHONPATH, GIT_CONFIG_*, PAGER, JAVA_TOOL_OPTIONS,
/// ...) is open-ended.
pub const ENV_ALLOW: &[&str] = &[
    "DEBIAN_FRONTEND",
    "DEBCONF_NONINTERACTIVE_SEEN",
    "APT_LISTCHANGES_FRONTEND",
    "NEEDRESTART_MODE",
    "NEEDRESTART_SUSPEND",
    "LANG",
    "LANGUAGE",
    "TZ",
    "TERM",
    "NO_COLOR",
    "COLUMNS",
    "LINES",
];
pub const ENV_ALLOW_PREFIX: &[&str] = &["LC_"];

/// Values are restricted too: no `/`, so none of them can name a file
/// (`TZ=:/home/u/x`, `LANG=/home/u/locale`).
fn env_value_ok(v: &str) -> bool {
    v.len() <= 256
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.@:+,-".contains(c))
}

pub fn prepare(
    ctx: &Ctx,
    peer: &Peer,
    user: &User,
    req: &Request,
    id: &str,
    tier: DisplayTier,
    materialize: bool,
) -> Result<Prepared, String> {
    validate(req)?;
    let owners = trust::trusted_owners();
    let env = command_env(user, &req.env, ctx.dev);
    let mut snapshot_dir = None;

    let (sections, exec, enforced) = match &req.action {
        Action::Run { argv } => {
            let program = trust::resolve_program(&argv[0], &req.cwd, &owners)?;
            let program = path_str(&program)?;
            let plan = ExecPlan {
                program: program.clone(),
                argv: argv.clone(),
                env,
                cwd: req.cwd.clone(),
                write: req.write.clone(),
                no_net: req.no_net,
            };
            let enforced = ctx.sandbox.enforcement(&plan);
            (
                vec![run_section(argv, &program)],
                Execution::Command(plan),
                enforced,
            )
        }
        Action::Script {
            path,
            content,
            args,
        } => {
            let name = Path::new(path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("script")
                .to_string();
            let dir = ctx.snapshot_root.join(id);
            let copy = dir.join(&name);
            let (interp, interp_arg) = interpreter(content, &owners)?;
            if materialize {
                write_snapshot(&dir, &copy, content)?;
                snapshot_dir = Some(dir);
            }
            let copy = path_str(&copy)?;
            let mut argv = vec![interp.clone()];
            argv.extend(interp_arg.clone());
            argv.push(copy.clone());
            argv.extend(args.iter().cloned());
            let plan = ExecPlan {
                program: interp.clone(),
                argv: argv.clone(),
                env,
                cwd: req.cwd.clone(),
                write: req.write.clone(),
                no_net: req.no_net,
            };
            let text = String::from_utf8_lossy(content).into_owned();
            let is_shell = SHELLS.contains(&basename(&interp));
            let section = Section {
                title: name,
                header: Some(format!("snapshot of {path}, run as: {}", shell_join(&argv))),
                syntax: if is_shell {
                    Syntax::Shell
                } else {
                    Syntax::Plain
                },
                formatted: verbatim(&text),
                raw: text,
            };
            let enforced = ctx.sandbox.enforcement(&plan);
            (vec![section], Execution::Command(plan), enforced)
        }
        Action::Install { src, content, dest } => {
            let dest = install_target(dest, src, &owners)?;
            let dest_s = path_str(&dest)?;
            let header = match std::fs::metadata(&dest) {
                Ok(m) => format!(
                    "replaces existing file ({} bytes, mode {:o}) with {} bytes from {src}",
                    m.len(),
                    m.permissions().mode() & 0o7777,
                    content.len()
                ),
                Err(_) => format!("new file, mode 644, {} bytes from {src}", content.len()),
            };
            let text = String::from_utf8_lossy(content).into_owned();
            let section = Section {
                title: format!("→ {dest_s}"),
                header: Some(header),
                syntax: Syntax::Plain,
                formatted: verbatim(&text),
                raw: text,
            };
            let enforced = Enforced {
                write: Some(vec![dest_s]),
                write_level: Level::Builtin,
                network: false,
                network_level: Level::Builtin,
            };
            let exec = Execution::Install {
                dest,
                content: content.clone(),
            };
            (vec![section], exec, enforced)
        }
    };

    let mut notes = Vec::new();
    if ctx.dev {
        notes.push(format!(
            "DEVELOPMENT MODE: this runs as {}, not as root.",
            user.name
        ));
    }
    if !peer.pinned {
        notes.push("Requester identity could not be pinned (needs Linux 6.5+): the process details below are best effort.".into());
    }
    if std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope").is_ok_and(|s| s.trim() == "0")
    {
        notes.push(
            "ptrace_scope is 0: other programs of yours may be able to read this dialog.".into(),
        );
    }

    let requester = std::iter::once(&peer.process)
        .chain(&peer.ancestry)
        .map(proc_line)
        .collect();
    let view = PromptView {
        request_id: id.to_string(),
        sha256: req.digest(),
        requester,
        requester_user: user.name.clone(),
        pinned: peer.pinned,
        cwd: req.cwd.clone(),
        run_as: if ctx.dev {
            format!("{} (development mode, NOT root)", user.name)
        } else {
            "root".into()
        },
        dev_mode: ctx.dev,
        why: req.why.clone(),
        enforced: enforced.clone(),
        display_tier: tier,
        env: req
            .env
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        sections,
        notes,
        timeout_secs: req.timeout_secs.clamp(5, MAX_TIMEOUT_SECS),
        wants_password: ctx.wants_password,
    };
    Ok(Prepared {
        view,
        exec,
        enforced,
        snapshot_dir,
    })
}

pub struct User {
    pub name: String,
    pub home: String,
}

fn validate(req: &Request) -> Result<(), String> {
    if !req.cwd.starts_with('/') {
        return Err("cwd must be absolute".into());
    }
    if let Action::Run { argv } = &req.action {
        if argv.is_empty() || argv[0].is_empty() {
            return Err("empty command".into());
        }
    }
    let strings: Vec<&str> = match &req.action {
        Action::Run { argv } => argv.iter().map(String::as_str).collect(),
        Action::Script { path, args, .. } => std::iter::once(path.as_str())
            .chain(args.iter().map(String::as_str))
            .collect(),
        Action::Install { src, dest, .. } => vec![src, dest],
    };
    if strings.iter().any(|s| s.contains('\0')) {
        return Err("arguments may not contain NUL bytes".into());
    }
    for path in req.write.iter().flatten() {
        if !path.starts_with('/') {
            return Err(format!("--write path must be absolute: {path}"));
        }
    }
    for (k, v) in &req.env {
        let allowed =
            ENV_ALLOW.contains(&k.as_str()) || ENV_ALLOW_PREFIX.iter().any(|p| k.starts_with(p));
        if !allowed {
            return Err(format!(
                "--env {k} is not allowed. Allowed: {}, {}*. Other variables can make root \
                 load code that the dialog cannot show",
                ENV_ALLOW.join(", "),
                ENV_ALLOW_PREFIX.join("*, ")
            ));
        }
        if !env_value_ok(v) {
            return Err(format!(
                "--env {k}: value may only contain letters, digits and _.@:+,- (no paths)"
            ));
        }
    }
    Ok(())
}

fn command_env(
    user: &User,
    extra: &BTreeMap<String, String>,
    dev: bool,
) -> BTreeMap<String, String> {
    let (name, home) = if dev {
        (user.name.as_str(), user.home.as_str())
    } else {
        ("root", "/root")
    };
    let mut env: BTreeMap<String, String> = [
        ("PATH", SAFE_PATH),
        ("HOME", home),
        ("USER", name),
        ("LOGNAME", name),
        ("SHELL", "/bin/sh"),
        ("LANG", "C.UTF-8"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    env.extend(extra.iter().map(|(k, v)| (k.clone(), v.clone())));
    env
}

fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

fn path_str(p: &Path) -> Result<String, String> {
    p.to_str()
        .map(str::to_string)
        .ok_or_else(|| format!("path is not valid UTF-8: {}", p.display()))
}

fn run_section(argv: &[String], program: &str) -> Section {
    let raw: String = argv
        .iter()
        .enumerate()
        .map(|(i, a)| format!("argv[{i}] {a}\n"))
        .collect();
    let resolved = if basename(program) == basename(&argv[0]) && argv[0].starts_with('/') {
        String::new()
    } else {
        format!("{} → {program}", argv[0])
    };
    let is_shell = SHELLS.contains(&basename(&argv[0])) || SHELLS.contains(&basename(program));
    if is_shell && argv.len() >= 3 && argv[1] == "-c" {
        let mut invocation = vec![program.to_string(), "-c".into(), "‹script below›".into()];
        invocation.extend(argv[3..].iter().cloned());
        let mut header = invocation.join(" ");
        if !resolved.is_empty() {
            header = format!("{header}   ({resolved})");
        }
        return Section {
            title: "shell script".into(),
            header: Some(header),
            syntax: Syntax::Shell,
            raw: argv[2].clone(),
            formatted: format_shell(&argv[2]),
        };
    }
    Section {
        title: "command".into(),
        header: (!resolved.is_empty()).then_some(resolved),
        syntax: Syntax::Shell,
        raw,
        formatted: verbatim(&shell_join(argv)),
    }
}

/// The interpreter for a script: its `#!` line (resolved and trusted;
/// `/usr/bin/env NAME` is looked up in SAFE_PATH), else /bin/sh.
fn interpreter(content: &[u8], owners: &[u32]) -> Result<(String, Option<String>), String> {
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
    Ok((path_str(&resolved)?, arg))
}

fn write_snapshot(dir: &Path, file: &Path, content: &[u8]) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let err = |e: std::io::Error| format!("snapshot {}: {e}", file.display());
    if let Some(root) = dir.parent() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(root)
            .map_err(err)?;
    }
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(dir)
        .map_err(err)?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o500)
        .open(file)
        .map_err(err)?;
    std::io::Write::write_all(&mut f, content).map_err(err)
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
    if let Ok(m) = std::fs::symlink_metadata(&target) {
        if !m.file_type().is_file() {
            return Err(format!(
                "{} exists and is not a regular file (directory, symlink or device)",
                target.display()
            ));
        }
        if m.nlink() > 1 {
            return Err(format!("{} has other hard links", target.display()));
        }
    }
    Ok(target)
}

fn proc_line(p: &ProcessInfo) -> ProcLine {
    ProcLine {
        pid: p.pid,
        exe: p.exe.clone(),
        cmdline: p.cmdline.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(action: Action) -> Request {
        Request {
            action,
            why: None,
            write: None,
            no_net: false,
            env: BTreeMap::new(),
            cwd: "/".into(),
            timeout_secs: 120,
        }
    }

    #[test]
    fn env_is_an_allowlist() {
        let with = |k: &str, v: &str| {
            let mut r = req(Action::Run {
                argv: vec!["true".into()],
            });
            r.env.insert(k.into(), v.into());
            validate(&r)
        };
        for k in [
            "LD_PRELOAD",
            "PATH",
            "BASH_ENV",
            "PYTHONPATH",
            "GIT_CONFIG_GLOBAL",
            "PAGER",
            "JAVA_TOOL_OPTIONS",
            "BASH_FUNC_x%%",
        ] {
            assert!(with(k, "x").is_err(), "{k} accepted");
        }
        assert!(with("DEBIAN_FRONTEND", "noninteractive").is_ok());
        assert!(with("LC_ALL", "C.UTF-8").is_ok());
        assert!(
            with("TZ", ":/home/u/zone").is_err(),
            "path in value accepted"
        );
        assert!(with("LANG", "/home/u/locale").is_err());
    }

    #[test]
    fn shell_c_gets_formatted_section() {
        let argv: Vec<String> = ["sh", "-c", "a && b"].map(String::from).to_vec();
        let s = run_section(&argv, "/usr/bin/dash");
        assert_eq!(s.raw, "a && b");
        assert_eq!(s.formatted.len(), 2);
        assert!(s.header.unwrap().contains("sh → /usr/bin/dash"));
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
}
