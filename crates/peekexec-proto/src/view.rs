//! The prompt as data. The daemon builds one [`PromptView`] per request;
//! the dialog renders it, and `peekexec preview` prints [`PromptView::to_text`]
//! of the very same value, so what an agent previews is what the human gets.

use peekexec_core::format::Line;
use peekexec_core::textcheck::{classify, scan, FindingKind};
use serde::{Deserialize, Serialize};

use crate::{DisplayTier, Enforced, Level};

/// Text that is safe on one line of the dialog (design rule 3). It can only
/// be made by escaping ([`Shown::line`]: characters that could fake extra
/// lines or hide text become visible `⟨U+XXXX⟩` tokens, long text is cut)
/// or from a constant the daemon wrote ([`Shown::fixed`]). There is no
/// `From<String>`, so requester text cannot reach a one-line field without
/// being escaped: forgetting is a compile error.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Shown(String);

impl Shown {
    /// `s` escaped for one line, cut after `max_chars` characters.
    pub fn line(s: &str, max_chars: usize) -> Shown {
        let mut out = String::new();
        for (i, c) in s.chars().enumerate() {
            if i == max_chars {
                out.push('…');
                break;
            }
            // Unlike code, a one-line field must not contain newlines or tabs.
            // The token brackets themselves are escaped, so a token cannot
            // be forged.
            let hidden = c.is_control()
                || matches!(c, '⟨' | '⟩')
                || !matches!(classify(c), None | Some(FindingKind::NonAscii));
            if hidden {
                out.push_str(&format!("⟨U+{:04X}⟩", c as u32));
            } else {
                out.push(c);
            }
        }
        Shown(out)
    }

    /// Text the daemon itself wrote, as a literal.
    pub fn fixed(s: &'static str) -> Shown {
        Shown(s.to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl std::ops::Deref for Shown {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

/// One-line pieces joined with `sep`: still one line.
pub fn join(items: &[Shown], sep: &str) -> String {
    items
        .iter()
        .map(Shown::as_str)
        .collect::<Vec<_>>()
        .join(sep)
}

impl std::fmt::Display for Shown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcLine {
    pub pid: u32,
    pub exe: Option<Shown>,
    pub cmdline: Vec<Shown>,
    /// The executable is root-owned and only root could have placed it.
    /// Names of untrusted processes may be chosen by whoever runs them.
    pub trusted: bool,
}

impl ProcLine {
    /// Short display name: the executable's file name, else argv[0].
    pub fn name(&self) -> String {
        self.exe
            .as_deref()
            .or(self.cmdline.first().map(Shown::as_str))
            .map(|p| p.rsplit('/').next().unwrap_or(p).to_string())
            .unwrap_or_else(|| "?".into())
    }
}

/// Where the human proves they approve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Approval {
    /// Password typed into this dialog (verified display).
    Password,
    /// "Continue" here, then the desktop's own prompt (polkit agent), which
    /// repeats the key facts; for displays the daemon cannot verify.
    SystemPrompt,
}

/// What the human is asked to approve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewKind {
    /// Running something as root.
    Root,
    /// Registering an agent process; nothing runs.
    Register,
}

/// Where a request came from, relative to registered agent sessions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Provenance {
    Unregistered,
    /// From inside a registered agent's process tree. This does not prove
    /// the agent itself decided to ask: a program it started could have.
    InSession {
        agent: Shown,
        since: Shown,
        /// Short labels from the agent's child down to the client.
        path: Vec<Shown>,
        /// Scripts and programs in `path` other than shells and peekexec.
        others: Vec<Shown>,
        /// The command of the agent's shell, if it ran one.
        command: Option<Shown>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Syntax {
    Shell,
    Plain,
    Diff,
}

/// One tab in the dialog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Section {
    pub title: Shown,
    /// How the content runs, one fact per line: each argument root passes
    /// (`argv[i] ...`, escaped, never cut), the resolved program, the
    /// target's owner and mode. Shown in full with the content, and counted
    /// in the desktop's prompt like it (design rule 4): nothing that
    /// executes lives only in a line that can be cut or left out.
    pub invocation: Vec<Shown>,
    pub syntax: Syntax,
    /// Ground truth: exactly what executes, unformatted.
    pub raw: String,
    /// Display layout of the same content (see `peekexec_core::format`).
    pub formatted: Vec<Line>,
    /// Not what runs: the changes since the request the human saw before,
    /// for comparison. Left out of the desktop prompt (a note there says
    /// it exists) and of the findings (its text is counted where it runs).
    #[serde(default)]
    pub comparison: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromptView {
    pub kind: ViewKind,
    pub approval: Approval,
    pub provenance: Provenance,
    pub request_id: String,
    pub sha256: String,
    /// The requesting process first, then its parent, grandparent, ...
    pub requester: Vec<ProcLine>,
    pub requester_user: Shown,
    /// Whether the requester's identity was pinned (pidfd) while it was read.
    pub pinned: bool,
    pub cwd: Shown,
    pub run_as: Shown,
    pub dev_mode: bool,
    /// The requester's own explanation. Unverified.
    pub why: Option<Shown>,
    pub enforced: Enforced,
    pub display_tier: DisplayTier,
    /// Whether the display was found from sources the requester cannot
    /// control (see THREAT_MODEL.md).
    pub display_verified: bool,
    /// Allowlisted names, values limited to `[A-Za-z0-9_.@:+,-]`; escaped
    /// all the same, like every other one-line field.
    pub env: Vec<(Shown, Shown)>,
    pub sections: Vec<Section>,
    /// Warnings the human should see (unpinned identity, dev mode, ...).
    pub notes: Vec<Shown>,
    pub timeout_secs: u32,
    /// False when the platform authenticates without a password (Touch ID).
    pub wants_password: bool,
    /// Keystrokes are ignored this long after the dialog appears (longer
    /// when it follows another request closely).
    pub input_guard_ms: u32,
    /// Whether Enter may approve. False whenever there is anything to warn
    /// about (notes, suspicious characters): then only a click approves.
    pub enter_approves: bool,
    /// Approve stays disabled this long after the dialog appears (set when a
    /// script or program may be asking instead of the agent).
    pub approve_delay_ms: u32,
}

impl PromptView {
    /// Suspicious characters in what executes: the content and the
    /// invocation (where escaped characters are `⟨U+XXXX⟩` tokens, which
    /// count too). The dialog and the daemon count the same way.
    pub fn findings(&self) -> usize {
        self.sections
            .iter()
            .filter(|s| !s.comparison)
            .map(|s| scan(&s.raw).len() + s.invocation.iter().map(|l| scan(l).len()).sum::<usize>())
            .sum()
    }

    /// One-line requester chain, e.g. `claude (pid 4121) ← bash ← kitty`,
    /// showing at most `max` processes.
    pub fn requester_chain(&self, sep: &str, max: usize) -> String {
        let mut parts: Vec<String> = self
            .requester
            .iter()
            .take(max)
            .enumerate()
            .map(|(i, p)| {
                if i == 0 {
                    format!("{} (pid {})", p.name(), p.pid)
                } else {
                    p.name()
                }
            })
            .collect();
        if self.requester.len() > max {
            parts.push("…".into());
        }
        parts.join(sep)
    }

    /// The summary line: writes, network, where the output goes, findings.
    pub fn summary(&self, findings: usize) -> Vec<(bool, String)> {
        let e = &self.enforced;
        let mut out = Vec::new();
        let how = |l: Level| match l {
            Level::Kernel => "",
            Level::BestEffort => " (best effort)",
            Level::DeclaredOnly => " (declared, not enforced)",
            Level::NotRequested => "",
            Level::Builtin => "",
        };
        match &e.write {
            Some(paths) => {
                // Checked by the daemon already; escaped here all the same.
                let paths: Vec<Shown> = paths.iter().map(|p| Shown::line(p, 300)).collect();
                out.push((
                    e.write_level != Level::Kernel && e.write_level != Level::Builtin,
                    format!("writes {}{}", join(&paths, ", "), how(e.write_level)),
                ))
            }
            None => out.push((true, "writes ANYWHERE".into())),
        }
        if e.network {
            out.push((false, "network allowed".into()));
        } else {
            out.push((
                e.network_level != Level::Kernel,
                format!("no network{}", how(e.network_level)),
            ));
        }
        // A command's stdout and stderr go to whoever asked: approving
        // `cat /etc/shadow` hands the file to the requester. Not for an
        // install, which runs nothing.
        if e.write_level != Level::Builtin {
            out.push((true, "its output goes back to the requester".into()));
        }
        if findings > 0 {
            out.push((true, format!("{findings} suspicious character(s)")));
        }
        out
    }

    /// Plain-text rendering used by `peekexec preview`.
    pub fn to_text(&self, findings: usize) -> String {
        let mut t = String::new();
        let mut line = |s: String| {
            t.push_str(&s);
            t.push('\n');
        };
        line(match self.kind {
            ViewKind::Root => "Root access requested".into(),
            ViewKind::Register => "Register an agent session".into(),
        });
        line(format!(
            "  origin  : {}",
            match &self.provenance {
                Provenance::Unregistered => "not from a registered agent session".to_string(),
                Provenance::InSession {
                    agent, since, path, ..
                } => format!(
                    "{agent}'s session (registered {since}): {agent} → {}",
                    join(path, " → ")
                ),
            }
        ));
        if let Provenance::InSession { agent, others, .. } = &self.provenance {
            if !others.is_empty() {
                line(format!(
                    "  WARNING : a script or program that {agent} started may be asking: {}",
                    join(others, ", ")
                ));
            }
        }
        line(format!(
            "  from    : {}  [user {}]",
            self.requester_chain(" ← ", 6),
            self.requester_user
        ));
        line(format!("  in      : {}", self.cwd));
        line(format!("  run as  : {}", self.run_as));
        if let Some(why) = &self.why {
            line(format!("  says    : “{why}”  (unverified)"));
        }
        let summary: Vec<String> = self
            .summary(findings)
            .into_iter()
            .map(|(warn, s)| format!("{}{s}", if warn { "⚠ " } else { "✓ " }))
            .collect();
        line(format!("  summary : {}", summary.join("   ")));
        for (k, v) in &self.env {
            line(format!("  env     : {k}={v}"));
        }
        for n in &self.notes {
            line(format!("  note    : {n}"));
        }
        for s in &self.sections {
            line(String::new());
            let what = if s.comparison {
                " (for comparison: not what runs)"
            } else {
                ""
            };
            line(format!("── {}{what} ──", s.title));
            for l in &s.invocation {
                line(format!("     {l}"));
            }
            for (i, l) in s.formatted.iter().enumerate() {
                let mark = if l.continued { '↳' } else { ' ' };
                // As the dialog does: only lines the formatter split are
                // re-indented; others keep their own indentation.
                let (indent, text) = l.shown();
                // Printed to a terminal: escape sequences must not act.
                let text = Shown::line(text, usize::MAX);
                line(format!("{:>4}{mark} {}{text}", i + 1, "  ".repeat(indent)));
            }
        }
        line(String::new());
        line(format!("sha256 {}", self.sha256));
        t
    }
}
