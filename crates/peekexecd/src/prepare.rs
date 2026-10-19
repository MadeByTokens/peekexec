//! Turns a client [`Request`] into (a) the exact [`PromptView`] the human
//! sees and (b) the exact [`Execution`] that runs if they approve. Both come
//! from the same resolved values, in one place, so they cannot disagree.

use std::collections::BTreeMap;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use peekexec_core::display::shell_join;
use peekexec_core::format::{format_shell, verbatim};
use peekexec_core::textcheck::{classify, scan, FindingKind};
use peekexec_core::{Action, Request};
use peekexec_proto::view::{Approval, ProcLine, PromptView, Provenance, Section, Syntax, ViewKind};
use peekexec_proto::{Enforced, Level};

use crate::inspect::{Facts, Inspection};
use crate::platform::{ExecPlan, Peer, ProcessInfo, Sandbox};
use crate::session::Display;
use crate::trust::{self, SAFE_PATH};

pub enum Execution {
    Command(ExecPlan),
    /// Nothing runs (agent registration).
    Nothing,
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

/// Looks at the filesystem for a request with the requesting user's
/// authority (see [`crate::inspect`]).
pub type Inspector = dyn Fn(&Request, &[u32]) -> Result<(Inspection, OwnedFd), String> + Sync;

pub struct Ctx<'a> {
    pub sandbox: &'a dyn Sandbox,
    pub inspect: &'a Inspector,
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
    display: &Display,
    materialize: bool,
) -> Result<Prepared, String> {
    validate(req)?;
    let owners = trust::trusted_owners();
    let env = command_env(user, &req.env, ctx.dev);
    let mut snapshot_dir = None;
    let mut notes = Vec::new();
    // Everything known about the filesystem comes from here: nothing below
    // looks at a requester-named path itself.
    let (inspection, cwd_fd) = (ctx.inspect)(req, &owners)?;
    let workdir = WorkDir {
        path: inspection.cwd.clone(),
        fd: Arc::new(cwd_fd),
    };
    notes.extend(inspection.cwd_warning.clone());
    let mismatch = || "internal error: inspection does not match the request".to_string();

    let (sections, exec, enforced) = match (&req.action, inspection.facts) {
        (
            Action::Run { argv },
            Facts::Run {
                program,
                file_args_note,
            },
        ) => {
            let plan = ExecPlan {
                program: program.clone(),
                argv: argv.clone(),
                env,
                cwd: workdir.path.clone(),
                cwd_fd: Some(Arc::clone(&workdir.fd)),
                write: req.write.clone(),
                no_net: req.no_net,
                audit_uid: Some(peer.uid),
            };
            let enforced = ctx.sandbox.enforcement(&plan);
            notes.extend(file_args_note);
            (
                vec![run_section(argv, &program)],
                Execution::Command(plan),
                enforced,
            )
        }
        (
            Action::Script {
                path,
                content,
                args,
            },
            Facts::Script {
                interpreter: interp,
                interpreter_arg: interp_arg,
            },
        ) => {
            let name = Path::new(path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("script")
                .to_string();
            let dir = ctx.snapshot_root.join(id);
            // The interpreter receives the snapshot's path as an argument,
            // so none of it may come from the requester.
            let copy = dir.join(snapshot_name(&name));
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
                cwd: workdir.path.clone(),
                cwd_fd: Some(Arc::clone(&workdir.fd)),
                write: req.write.clone(),
                no_net: req.no_net,
                audit_uid: Some(peer.uid),
            };
            let text = String::from_utf8_lossy(content).into_owned();
            let is_shell = SHELLS.contains(&basename(&interp));
            let section = Section {
                title: display_line(&name, 80),
                header: Some(display_line(
                    &format!(
                        "snapshot of the file the requester calls {path}; runs as: {}",
                        shell_join(&argv)
                    ),
                    400,
                )),
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
        (Action::Install { src, content, .. }, Facts::Install { dest, existing }) => {
            let dest_s = dest;
            let dest = PathBuf::from(&dest_s);
            let header = match &existing {
                Some(e) => format!(
                    "replaces an existing file ({} bytes) with {} bytes the requester calls {src}; \
                     owner stays {}, mode stays {:o} (setuid/setgid/sticky bits are always \
                     cleared)",
                    e.len,
                    content.len(),
                    e.owner,
                    e.mode
                ),
                None => format!(
                    "new file, owner root, mode {:o}, {} bytes the requester calls {src}",
                    crate::exec::new_file_mode(content),
                    content.len()
                ),
            };
            let mut sections = vec![install_section(&dest_s, &header, content, &mut notes)];
            match existing.map(|e| e.content) {
                Some(Ok(old)) => {
                    if let Some(diff) = install_diff(&old, content) {
                        sections.insert(0, diff);
                    }
                }
                Some(Err(why)) => notes.push(format!(
                    "Replaces {dest_s}, whose current content {why}; it is lost."
                )),
                None => {}
            }
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
            (sections, exec, enforced)
        }
        _ => return Err(mismatch()),
    };

    notes.extend(sensitive_targets(&sections, &enforced));
    if ctx.dev {
        notes.push(format!(
            "DEVELOPMENT MODE: this runs as {}, not as root.",
            user.name
        ));
    }
    if !display.verified {
        notes.push("Could not verify which display server shows this dialog: a program of yours could be relaying it and reading what you type. Approve only a request you expected.".into());
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
    // Some notes quote requester-chosen paths.
    let notes: Vec<String> = notes.iter().map(|n| display_line(n, 1000)).collect();

    let requester = std::iter::once(&peer.process)
        .chain(&peer.ancestry)
        .map(proc_line)
        .collect();
    let view = PromptView {
        kind: ViewKind::Root,
        approval: Approval::Password,
        provenance: Provenance::Unregistered,
        request_id: id.to_string(),
        sha256: req.digest(),
        requester,
        requester_user: user.name.clone(),
        pinned: peer.pinned,
        cwd: display_line(&workdir.path, 300),
        run_as: if ctx.dev {
            format!("{} (development mode, NOT root)", user.name)
        } else {
            "root".into()
        },
        dev_mode: ctx.dev,
        why: req.why.as_deref().map(|w| display_line(w, 300)),
        enforced: enforced.clone(),
        display_tier: display.tier,
        display_verified: display.verified,
        env: req
            .env
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        sections,
        notes,
        timeout_secs: req.timeout_secs.clamp(5, MAX_TIMEOUT_SECS),
        wants_password: ctx.wants_password,
        input_guard_ms: 400,
        enter_approves: false,
        approve_delay_ms: 0,
    };
    let findings: usize = view.sections.iter().map(|s| scan(&s.raw).len()).sum();
    let mut view = view;
    view.enter_approves = view.notes.is_empty() && findings == 0;
    Ok(Prepared {
        view,
        exec,
        enforced,
        snapshot_dir,
    })
}

/// Text for a single dialog line: characters that could fake extra lines or
/// hide text become visible `⟨U+XXXX⟩` tokens, and long text is cut.
pub fn display_line(s: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i == max_chars {
            out.push('…');
            break;
        }
        // Unlike code, a one-line field must not contain newlines or tabs.
        let hidden = c.is_control() || !matches!(classify(c), None | Some(FindingKind::NonAscii));
        if hidden {
            out.push_str(&format!("⟨U+{:04X}⟩", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// Control characters as visible `⟨U+XXXX⟩` tokens, everything else as is
/// (the dialog marks other hidden characters itself). The tokens are not
/// ASCII, so they also count as findings and Enter does not approve.
fn escape_controls(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() || matches!(c, '\u{2028}' | '\u{2029}') {
                format!("⟨U+{:04X}⟩", c as u32)
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// Prefix of the note added when the display cannot be verified.
pub const UNVERIFIED_NOTE: &str = "Could not verify which display server shows this dialog";
const SYSTEM_PROMPT_NOTE: &str = "You will confirm in your desktop's own password dialog";

/// Switch a view to approval through the desktop's own prompt.
pub fn use_system_prompt(view: &mut PromptView) {
    view.approval = Approval::SystemPrompt;
    view.wants_password = false;
    view.notes.retain(|n| !n.starts_with(UNVERIFIED_NOTE));
    view.notes.insert(
        0,
        format!(
            "{SYSTEM_PROMPT_NOTE} next; it repeats the key facts. This window cannot be \
             verified: if the two disagree, cancel."
        ),
    );
}

/// The text the desktop's prompt shows: the decisive facts on their own,
/// since a decoy window could sit next to it.
pub fn system_prompt_message(view: &PromptView) -> String {
    // Lines per section, and characters per line (longer ones wrap, they
    // are never cut): the prompt is the only trustworthy view, so what it
    // leaves out it says it leaves out.
    const LINES: usize = 12;
    const WIDTH: usize = 120;
    let mut body = String::new();
    let mut omitted = 0;
    for s in &view.sections {
        let lines: Vec<String> = s
            .formatted
            .iter()
            .map(|l| display_line(l.text.trim(), usize::MAX))
            .filter(|l| !l.is_empty())
            .flat_map(|l| wrap(&l, WIDTH))
            .collect();
        body.push_str(&format!("\n{}:\n", display_line(&s.title, 80)));
        for l in lines.iter().take(LINES) {
            body.push_str(&format!("    {l}\n"));
        }
        if lines.len() > LINES {
            omitted += lines.len() - LINES;
            body.push_str(&format!(
                "    … {} more lines NOT shown here\n",
                lines.len() - LINES
            ));
        }
    }
    let mut m = String::new();
    m.push_str(match view.kind {
        ViewKind::Root => "peekexec: run this as root?\n",
        ViewKind::Register => "peekexec: register an agent session?\n",
    });
    if omitted > 0 {
        m.push_str(&format!(
            "⚠ INCOMPLETE: {omitted} lines are not shown here. They appear only in the \
             peekexec window, which cannot be verified. Approve only if you expected exactly \
             this request.\n"
        ));
    }
    m.push_str(&body);
    // Every value below is already escaped where the view is built; escaping
    // again here keeps the prompt safe even if that ever changes.
    let from = match &view.provenance {
        Provenance::InSession { agent, since, .. } => {
            format!("{}'s session (registered {since})", display_line(agent, 60))
        }
        Provenance::Unregistered => view
            .requester
            .first()
            .map(|p| {
                format!(
                    "{} (pid {}), not a registered agent",
                    display_line(&p.name(), 40),
                    p.pid
                )
            })
            .unwrap_or_default(),
    };
    m.push_str(&format!(
        "\nfrom: {from}\nin: {}\n",
        display_line(&view.cwd, 120)
    ));
    if view.kind == ViewKind::Root {
        let facts: Vec<String> = view
            .summary(0)
            .into_iter()
            .map(|(_, t)| display_line(&t, 160))
            .collect();
        m.push_str(&format!("{}\n", facts.join(" · ")));
    }
    if let Provenance::InSession { others, .. } = &view.provenance {
        if !others.is_empty() {
            let others: Vec<String> = others.iter().map(|o| display_line(o, 40)).collect();
            m.push_str(&format!(
                "⚠ a script or program it started may be asking: {}\n",
                others.join(", ")
            ));
        }
    }
    let warnings = view
        .notes
        .iter()
        .filter(|n| !n.starts_with(SYSTEM_PROMPT_NOTE));
    // All of them: each kind of note appears at most once.
    for n in warnings {
        m.push_str(&format!("⚠ {}\n", display_line(n, 300)));
    }
    m.push_str(&format!(
        "request sha256 {}…",
        &view.sha256[..12.min(view.sha256.len())]
    ));
    m
}

/// `s` in pieces of at most `width` characters.
fn wrap(s: &str, width: usize) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    chars
        .chunks(width.max(1))
        .map(|c| c.iter().collect())
        .collect()
}

pub struct User {
    pub name: String,
    pub home: String,
    pub uid: u32,
    /// Primary group, from the user database.
    pub gid: u32,
    /// Primary and supplementary groups, from the user database.
    pub groups: Vec<u32>,
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
        // Shown in the one-line summary: a line break would fake its lines.
        if path.chars().any(char::is_control) {
            return Err(format!(
                "--write path may not contain control characters: {path:?}"
            ));
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
    // One argument per line: line breaks and other control characters
    // inside an argument become visible tokens, or one argument could pass
    // for several.
    let raw: String = argv
        .iter()
        .enumerate()
        .map(|(i, a)| format!("argv[{i}] {}\n", escape_controls(a)))
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

/// The snapshot's file name: fixed, keeping a short alphanumeric extension
/// (`deploy.py` → `script.py`) for interpreters that care.
fn snapshot_name(requested: &str) -> String {
    match Path::new(requested).extension().and_then(|e| e.to_str()) {
        Some(ext)
            if (1..=8).contains(&ext.len()) && ext.bytes().all(|b| b.is_ascii_alphanumeric()) =>
        {
            format!("script.{ext}")
        }
        _ => "script".into(),
    }
}

/// The working directory as inspected, and its descriptor.
struct WorkDir {
    path: String,
    fd: Arc<OwnedFd>,
}

/// Places where a file makes root run commands later, or controls logins.
const SENSITIVE: &[&str] = &[
    "/etc/sudoers",
    "/etc/sudo.conf",
    "/etc/cron",
    "/etc/anacrontab",
    "/etc/init.d",
    "/etc/rc.local",
    "/etc/modprobe.d",
    "/etc/modules-load.d",
    "/etc/logrotate",
    "/etc/xdg/autostart",
    "/etc/X11/Xsession",
    "/etc/update-motd.d",
    "/etc/NetworkManager/dispatcher.d",
    "/etc/kernel",
    "/etc/default/grub",
    "/boot",
    "/usr/share/polkit-1",
    // Before /usr/bin in root's PATH: a program here shadows the system one.
    "/usr/local/bin",
    "/usr/local/sbin",
    "/var/spool/cron",
    "/etc/systemd",
    "/lib/systemd",
    "/usr/lib/systemd",
    "/etc/udev",
    "/lib/udev",
    "/etc/profile",
    "/etc/bash.bashrc",
    "/etc/environment",
    "/etc/ld.so.preload",
    "/etc/ld.so.conf",
    "/etc/pam.d",
    "/etc/security",
    "/etc/ssh",
    "/root/.ssh",
    "/etc/polkit-1",
    "/etc/apt/sources.list",
    "/etc/apt/apt.conf",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
];

/// One note for all hits, so naming many paths cannot push other warnings
/// out of the desktop prompt's summary.
fn sensitive_targets(sections: &[Section], enforced: &Enforced) -> Option<String> {
    let mut hits: Vec<&str> = Vec::new();
    let texts = sections
        .iter()
        .map(|s| s.raw.as_str())
        .chain(enforced.write.iter().flatten().map(String::as_str));
    for text in texts {
        // `/etc//cron.d` and `/etc/./cron.d` name /etc/cron.d too.
        let mut text = text.to_string();
        while text.contains("//") || text.contains("/./") {
            text = text.replace("//", "/").replace("/./", "/");
        }
        for &p in SENSITIVE {
            if text.contains(p) && !hits.contains(&p) {
                hits.push(p);
            }
        }
    }
    (!hits.is_empty()).then(|| {
        let paths: Vec<String> = hits.iter().map(|p| format!("{p}*")).collect();
        format!(
            "Touches {}: files there can run commands as root later or control logins.",
            paths.join(", ")
        )
    })
}

fn install_section(dest: &str, header: &str, content: &[u8], notes: &mut Vec<String>) -> Section {
    let binary = content.contains(&0) || std::str::from_utf8(content).is_err();
    let (raw, syntax) = if binary {
        let kind = if content.starts_with(b"\x7fELF") {
            notes.push(format!("Installs an executable program into {dest}."));
            "an executable program (ELF)"
        } else {
            "binary data"
        };
        (
            format!(
                "Not text: {kind}, {} bytes, sha256 {}.\nIts content cannot be shown here.\n",
                content.len(),
                peekexec_core::request::sha256_hex(content)
            ),
            Syntax::Plain,
        )
    } else {
        (String::from_utf8_lossy(content).into_owned(), Syntax::Plain)
    };
    Section {
        title: display_line(&format!("new {dest}"), 120),
        header: Some(display_line(header, 400)),
        syntax,
        formatted: verbatim(&raw),
        raw,
    }
}

/// What changes in an existing text file, as a unified diff.
fn install_diff(old: &[u8], content: &[u8]) -> Option<Section> {
    let (old, new) = (
        std::str::from_utf8(old).ok()?,
        std::str::from_utf8(content).ok()?,
    );
    let diff = similar::TextDiff::from_lines(old, new)
        .unified_diff()
        .context_radius(3)
        .header("current", "new")
        .to_string();
    let raw = if diff.is_empty() {
        "No changes: the new content is identical to the current file.\n".to_string()
    } else {
        diff
    };
    Some(Section {
        title: "changes".into(),
        header: Some("unified diff: lines starting with - are removed, + are added".into()),
        syntax: Syntax::Diff,
        formatted: verbatim(&raw),
        raw,
    })
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

/// Process details are under the control of whoever runs the process, so
/// they are escaped, and `trusted` says whether the executable is a
/// root-owned file that only root could have put there.
pub fn proc_line(p: &ProcessInfo) -> ProcLine {
    let trusted = p
        .exe
        .as_deref()
        .is_some_and(|e| trust::check(Path::new(e), &[0]).is_ok());
    ProcLine {
        pid: p.pid,
        exe: p.exe.as_deref().map(|e| display_line(e, 200)),
        cmdline: p.cmdline.iter().map(|a| display_line(a, 200)).collect(),
        trusted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

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
    fn why_cannot_fake_lines() {
        assert_eq!(
            display_line("ok\nRuns as: nobody", 300),
            "ok⟨U+000A⟩Runs as: nobody"
        );
        assert_eq!(display_line("abcdef", 3), "abc…");
        assert_eq!(display_line("café", 300), "café");
    }

    #[test]
    fn an_argument_cannot_pass_for_several() {
        let r = req(Action::Run {
            argv: ["chmod", "0755", "/usr/local/bin\nargv[3] /tmp/harmless"]
                .map(String::from)
                .to_vec(),
        });
        let p = prepare_for_tests(&r);
        let s = &p.view.sections[0];
        assert_eq!(s.raw.lines().count(), 3, "{}", s.raw);
        assert!(s.raw.contains("⟨U+000A⟩"), "{}", s.raw);
        assert_eq!(s.formatted.len(), 1);
        assert!(!p.view.enter_approves);

        let mut r = req(Action::Run {
            argv: vec!["true".into()],
        });
        r.write = Some(vec!["/etc/motd\nnetwork: blocked".into()]);
        assert!(validate(&r).unwrap_err().contains("control characters"));
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
    fn snapshot_name_ignores_the_requested_name() {
        assert_eq!(snapshot_name("x;BEGIN{system(\"id\")}"), "script");
        assert_eq!(snapshot_name("deploy.py"), "script.py");
        assert_eq!(snapshot_name("a.b;c"), "script");
        assert_eq!(snapshot_name("noext"), "script");
        assert_eq!(snapshot_name(".hidden"), "script");
    }

    #[test]
    fn script_runs_from_a_daemon_named_snapshot() {
        let r = req(Action::Script {
            path: "/home/u/x;whatever".into(),
            content: b"#!/bin/sh -e\necho hi\n".to_vec(),
            args: vec![],
        });
        let p = prepare_for_tests(&r);
        let Execution::Command(plan) = p.exec else {
            panic!("not a command")
        };
        assert!(
            plan.argv.last().unwrap().ends_with("/r-test/script"),
            "{:?}",
            plan.argv
        );
    }

    #[test]
    fn install_never_shows_what_the_user_cannot_read() {
        if nix::unistd::geteuid().is_root() {
            return;
        }
        let dir = std::env::temp_dir().join(format!("pe-unread-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let dest = dir.join("secret.conf");
        std::fs::write(&dest, "secret-line\n").unwrap();
        let install = req(Action::Install {
            src: "new.conf".into(),
            content: b"new\n".to_vec(),
            dest: dest.to_str().unwrap().into(),
        });
        // Readable by the requester: the diff is shown.
        let shown = prepare_for_tests(&install);
        assert!(shown
            .view
            .sections
            .iter()
            .any(|s| s.raw.contains("secret-line")));
        // Not readable by the requester (this test process, whose authority
        // inspection uses): nothing of it is shown.
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o000)).unwrap();
        let hidden = prepare_for_tests(&install);
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o600)).unwrap();
        let text = serde_json::to_string(&hidden.view).unwrap();
        assert!(!text.contains("secret-line"), "{text}");
        assert!(!text.contains("No changes"), "{text}");
        assert!(hidden.view.notes.iter().any(|n| n.contains("cannot read")));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn prepare_for_tests(r: &Request) -> Prepared {
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        let sandbox = crate::platform::linux::Namespaces;
        let ctx = Ctx {
            sandbox: &sandbox,
            inspect: &crate::inspect::inspect,
            wants_password: true,
            dev: true,
            snapshot_root: Path::new("/nonexistent/peekexec-tests"),
        };
        let peer = Peer {
            uid,
            gid,
            process: ProcessInfo {
                pid: 1,
                exe: None,
                cmdline: vec![],
                start_time: None,
            },
            cwd: None,
            ancestry: vec![],
            pinned: true,
        };
        let user = User {
            name: "u".into(),
            home: "/home/u".into(),
            uid,
            gid,
            groups: vec![gid],
        };
        let display = Display {
            vars: vec![],
            tier: peekexec_proto::DisplayTier::X11,
            verified: true,
        };
        prepare(&ctx, &peer, &user, r, "r-test", &display, false).unwrap()
    }

    #[test]
    fn system_prompt_message_carries_the_facts() {
        let mut v = PromptView {
            kind: ViewKind::Root,
            approval: Approval::Password,
            provenance: Provenance::Unregistered,
            request_id: "r-1".into(),
            sha256: "3f9a1c0000000000000000000000000000000000000000000000000000c21e".into(),
            requester: vec![],
            requester_user: "u".into(),
            pinned: true,
            cwd: "/".into(),
            run_as: "root".into(),
            dev_mode: false,
            why: Some("ignored: only daemon facts go in".into()),
            enforced: Enforced {
                write: Some(vec!["/etc/udev/rules.d".into()]),
                write_level: Level::DeclaredOnly,
                network: false,
                network_level: Level::BestEffort,
            },
            display_tier: peekexec_proto::DisplayTier::Wayland,
            display_verified: false,
            env: vec![],
            sections: vec![run_section(
                &["sh", "-c", "a && b; c; d; e; f $("].map(String::from),
                "/usr/bin/dash",
            )],
            notes: vec![
                format!("{UNVERIFIED_NOTE}: x"),
                "Touches /etc/sudoers*".into(),
            ],
            timeout_secs: 60,
            wants_password: true,
            input_guard_ms: 400,
            enter_approves: false,
            approve_delay_ms: 0,
        };
        use_system_prompt(&mut v);
        assert_eq!(v.approval, Approval::SystemPrompt);
        assert!(!v.wants_password);
        let m = system_prompt_message(&v);
        assert!(m.starts_with("peekexec: run this as root?"));
        assert!(m.contains("    a &&"), "{m}");
        assert!(m.contains("    f $("), "all six lines fit: {m}");
        assert!(!m.contains("INCOMPLETE"), "{m}");
        assert!(m.contains("writes /etc/udev/rules.d"), "{m}");
        assert!(m.contains("⚠ Touches /etc/sudoers*"), "{m}");
        assert!(!m.contains(UNVERIFIED_NOTE), "{m}");
        assert!(!m.contains("ignored"), "why must not be in the prompt: {m}");
        assert!(m.ends_with("request sha256 3f9a1c000000…"), "{m}");

        // Too long for the prompt: it says so, before the content.
        let script: String = (0..30).map(|i| format!("step{i}\n")).collect();
        v.sections = vec![run_section(
            &["sh".into(), "-c".into(), script],
            "/usr/bin/dash",
        )];
        let m = system_prompt_message(&v);
        let warn = m.find("INCOMPLETE: 18 lines").expect(&m);
        assert!(warn < m.find("step0").unwrap(), "{m}");
        assert!(!m.contains("step12"), "{m}");

        // A long line wraps; nothing is cut off.
        let long = format!("apt-get install -y {}evil-tail", "pkg ".repeat(60));
        v.sections = vec![run_section(
            &["sh".into(), "-c".into(), long],
            "/usr/bin/dash",
        )];
        let m = system_prompt_message(&v);
        assert!(m.contains("evil-tail"), "{m}");

        // Every warning is listed.
        v.notes = (0..6).map(|i| format!("warning {i}")).collect();
        let m = system_prompt_message(&v);
        assert!(m.contains("⚠ warning 5"), "{m}");
    }

    #[test]
    fn flags_sensitive_targets() {
        let e = Enforced {
            write: Some(vec!["/etc/sudoers.d/x".into()]),
            write_level: Level::Builtin,
            network: false,
            network_level: Level::Builtin,
        };
        let note = sensitive_targets(&[], &e).unwrap();
        assert!(note.contains("/etc/sudoers"));
        // Many hits are still one note.
        let e = Enforced {
            write: Some(vec!["/etc/sudoers.d/x".into(), "/etc/cron.d/y".into()]),
            ..e
        };
        let note = sensitive_targets(&[], &e).unwrap();
        assert!(note.contains("/etc/sudoers*, /etc/cron*"), "{note}");
        // Redundant slashes and dots do not hide a path.
        for p in ["/etc//cron.d/x", "/etc/./cron.d/x", "/usr/local/bin/apt"] {
            let e = Enforced {
                write: Some(vec![p.into()]),
                ..e.clone()
            };
            assert!(sensitive_targets(&[], &e).is_some(), "{p}");
        }
    }

    #[test]
    fn binary_install_is_described_not_shown() {
        let mut notes = Vec::new();
        let s = install_section(
            "/usr/local/bin/x",
            "h",
            b"\x7fELF\x02\x01\x00junk",
            &mut notes,
        );
        assert!(s.raw.starts_with("Not text: an executable program"));
        assert_eq!(notes.len(), 1);
    }
}
