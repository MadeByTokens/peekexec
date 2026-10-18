//! The prompt as data. The daemon builds one [`PromptView`] per request;
//! the dialog renders it, and `peekexec preview` prints [`PromptView::to_text`]
//! of the very same value, so what an agent previews is what the human gets.

use peekexec_core::format::Line;
use serde::{Deserialize, Serialize};

use crate::{DisplayTier, Enforced, Level};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcLine {
    pub pid: u32,
    pub exe: Option<String>,
    pub cmdline: Vec<String>,
}

impl ProcLine {
    /// Short display name: the executable's file name, else argv[0].
    pub fn name(&self) -> String {
        self.exe
            .as_deref()
            .or(self.cmdline.first().map(String::as_str))
            .map(|p| p.rsplit('/').next().unwrap_or(p).to_string())
            .unwrap_or_else(|| "?".into())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Syntax {
    Shell,
    Plain,
}

/// One tab in the dialog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Section {
    pub title: String,
    /// How the content is invoked (interpreter, resolved program, target).
    pub header: Option<String>,
    pub syntax: Syntax,
    /// Ground truth: exactly what executes, unformatted.
    pub raw: String,
    /// Display layout of the same content (see `peekexec_core::format`).
    pub formatted: Vec<Line>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromptView {
    pub request_id: String,
    pub sha256: String,
    /// The requesting process first, then its parent, grandparent, ...
    pub requester: Vec<ProcLine>,
    pub requester_user: String,
    /// Whether the requester's identity was pinned (pidfd) while it was read.
    pub pinned: bool,
    pub cwd: String,
    pub run_as: String,
    pub dev_mode: bool,
    /// The requester's own explanation. Unverified.
    pub why: Option<String>,
    pub enforced: Enforced,
    pub display_tier: DisplayTier,
    pub env: Vec<(String, String)>,
    pub sections: Vec<Section>,
    /// Warnings the human should see (unpinned identity, dev mode, ...).
    pub notes: Vec<String>,
    pub timeout_secs: u32,
    /// False when the platform authenticates without a password (Touch ID).
    pub wants_password: bool,
}

impl PromptView {
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

    /// The summary line: writes, network, findings.
    pub fn summary(&self, findings: usize) -> Vec<(bool, String)> {
        let e = &self.enforced;
        let mut out = Vec::new();
        let how = |l: Level| match l {
            Level::Kernel => "",
            Level::DeclaredOnly => " (declared, not enforced)",
            Level::NotRequested => "",
            Level::Builtin => "",
        };
        match &e.write {
            Some(paths) => out.push((
                e.write_level != Level::Kernel && e.write_level != Level::Builtin,
                format!("writes {}{}", paths.join(", "), how(e.write_level)),
            )),
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
        line("Root access requested".into());
        line(format!(
            "  from    : {}  [user {}]",
            self.requester_chain(" ← ", 6),
            self.requester_user
        ));
        line(format!("  in      : {}", self.cwd));
        line(format!("  run as  : {}", self.run_as));
        if let Some(why) = &self.why {
            line(format!("  says    : {why:?}  (unverified)"));
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
            line(format!("── {} ──", s.title));
            if let Some(h) = &s.header {
                line(format!("     {h}"));
            }
            for (i, l) in s.formatted.iter().enumerate() {
                let mark = if l.continued { '↳' } else { ' ' };
                let text = l.text.trim_end_matches('\n').trim_start();
                line(format!(
                    "{:>4}{mark} {}{text}",
                    i + 1,
                    "  ".repeat(l.indent)
                ));
            }
        }
        line(String::new());
        line(format!("sha256 {}", self.sha256));
        t
    }
}
