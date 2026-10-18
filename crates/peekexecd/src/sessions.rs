//! Registered agent sessions: is a request coming from inside the agent
//! process tree the human registered?
//!
//! The uid of a request is certain (kernel). Process names are not: any
//! program of the user can call itself "claude". A registration, approved
//! once by the human, pins one specific process (pidfd + start time); later
//! requests are matched against the kernel's process ancestry. A process
//! cannot make a registered agent its ancestor, so "from inside this agent's
//! session" is something unrelated programs cannot fake.
//!
//! What ancestry cannot tell is whether the agent itself, or a program it
//! started, decided to ask: a program keeps its pid across `exec`, so it can
//! turn itself into a `bash -c '…'` that looks like the agent's own shell.
//! Programs other than shells in the chain are therefore *flagged* (they
//! show a script or tool is involved), but their absence proves nothing.

use std::time::SystemTime;

use crate::platform::{Pinned, ProcessInfo};

/// Shells that sit between an agent and the commands it runs.
pub const SHELLS: &[&str] = &["sh", "bash", "dash", "zsh", "ksh", "mksh", "ash", "fish"];

pub struct AgentSession {
    pub id: String,
    pub name: String,
    pub uid: u32,
    pub pinned: Pinned,
    pub registered_at: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Provenance {
    /// No registered agent among the requester's ancestors.
    Unregistered,
    /// Inside a registered agent's process tree.
    InSession {
        session: String,
        /// Short labels from the agent's child down to the client.
        path: Vec<String>,
        /// The entries of `path` that are neither the installed peekexec
        /// client nor a shell running a `-c` command: scripts and programs.
        others: Vec<String>,
        /// The `-c` command of the shell right below the agent, if any.
        command: Option<String>,
    },
}

fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// A short-option cluster containing `c` (`-c`, `-lc`), never a long option
/// such as `--rcfile`.
fn is_c_flag(a: &str) -> bool {
    a.len() > 1
        && a.starts_with('-')
        && !a.starts_with("--")
        && a[1..].chars().all(|c| c.is_ascii_alphabetic())
        && a.contains('c')
}

/// For a trusted shell started with `-c`, the command string.
fn shell_command(p: &ProcessInfo, trusted: &dyn Fn(&str) -> bool) -> Option<Option<String>> {
    let exe = p.exe.as_deref()?;
    if !SHELLS.contains(&basename(exe)) || !trusted(exe) {
        return None;
    }
    let mut args = p.cmdline.iter().skip(1);
    for a in args.by_ref() {
        if !a.starts_with('-') {
            return None; // a script file
        }
        if is_c_flag(a) {
            return Some(args.find(|a| !a.starts_with('-')).cloned());
        }
    }
    None
}

/// A short, readable label: `bash -c`, `sh build.sh`, `make install`.
fn label(p: &ProcessInfo, trusted: &dyn Fn(&str) -> bool) -> String {
    let name = basename(p.exe.as_deref().unwrap_or("?")).to_string();
    if shell_command(p, trusted).is_some() {
        return format!("{name} -c");
    }
    let first = p.cmdline.iter().skip(1).find(|a| !a.starts_with('-'));
    let mut l = match first {
        Some(arg) => format!("{name} {}", basename(arg)),
        None => name,
    };
    if l.chars().count() > 40 {
        l = l.chars().take(39).collect::<String>() + "…";
    }
    l
}

/// Where a request came from, given its process chain (the connecting
/// process first, then its parent, ...).
///
/// `is_live(session, process)` must confirm the session is still pinned to
/// that very process; `trusted(exe)` whether an executable is one only a
/// trusted owner could have placed.
pub fn classify(
    chain: &[ProcessInfo],
    sessions: &[&AgentSession],
    is_live: &dyn Fn(&AgentSession, &ProcessInfo) -> bool,
    trusted: &dyn Fn(&str) -> bool,
) -> Provenance {
    let found = chain
        .iter()
        .enumerate()
        .find_map(|(k, p)| sessions.iter().find(|s| is_live(s, p)).map(|s| (k, *s)));
    let Some((k, session)) = found else {
        return Provenance::Unregistered;
    };
    let below = &chain[..k]; // client first
    let is_client = |i: usize, p: &ProcessInfo| {
        i == 0
            && p.exe
                .as_deref()
                .is_some_and(|e| basename(e) == "peekexec" && trusted(e))
    };
    let others = below
        .iter()
        .enumerate()
        .rev()
        .filter(|&(i, p)| !is_client(i, p) && shell_command(p, trusted).is_none())
        .map(|(_, p)| label(p, trusted))
        .collect();
    Provenance::InSession {
        session: session.name.clone(),
        path: below.iter().rev().map(|p| label(p, trusted)).collect(),
        others,
        command: below
            .last()
            .and_then(|p| shell_command(p, trusted))
            .flatten(),
    }
}

/// The process to register when the caller does not name one: the nearest
/// ancestor that is neither the peekexec client nor a shell.
pub fn default_agent(chain: &[ProcessInfo]) -> Option<&ProcessInfo> {
    chain.iter().skip(1).find(|p| {
        let name = p.exe.as_deref().map(basename).unwrap_or("");
        name != "peekexec" && !SHELLS.contains(&name)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(pid: u32, exe: &str, args: &[&str]) -> ProcessInfo {
        ProcessInfo {
            pid,
            exe: Some(exe.into()),
            cmdline: std::iter::once(exe)
                .chain(args.iter().copied())
                .map(String::from)
                .collect(),
            start_time: Some(pid as u64 * 10),
        }
    }

    fn session(pid: u32) -> AgentSession {
        AgentSession {
            id: "s-1".into(),
            name: "Claude Code".into(),
            uid: 1000,
            pinned: Pinned {
                pid,
                start_time: pid as u64 * 10,
                handle: None,
            },
            registered_at: SystemTime::now(),
        }
    }

    fn live(s: &AgentSession, p: &ProcessInfo) -> bool {
        p.pid == s.pinned.pid && p.start_time == Some(s.pinned.start_time)
    }

    fn trusted(exe: &str) -> bool {
        exe.starts_with("/usr/")
    }

    fn run(chain: &[ProcessInfo]) -> Provenance {
        let s = session(100);
        classify(chain, &[&s], &live, &trusted)
    }

    fn others(chain: &[ProcessInfo]) -> Vec<String> {
        match run(chain) {
            Provenance::InSession { others, .. } => others,
            p => panic!("{p:?}"),
        }
    }

    const CLI: &str = "/usr/local/bin/peekexec";
    const AGENT: &str = "/home/u/.local/bin/claude";

    #[test]
    fn agent_shell_only() {
        let chain = [
            proc(300, CLI, &["run", "--", "id"]),
            proc(200, "/usr/bin/bash", &["-c", "-l", "peekexec run -- id"]),
            proc(100, AGENT, &[]),
        ];
        assert_eq!(
            run(&chain),
            Provenance::InSession {
                session: "Claude Code".into(),
                path: vec!["bash -c".into(), "peekexec run".into()],
                others: vec![],
                command: Some("peekexec run -- id".into()),
            }
        );
    }

    #[test]
    fn scripts_and_programs_in_between_are_listed() {
        let chain = [
            proc(400, CLI, &["run", "--", "id"]),
            proc(350, "/usr/bin/make", &["install"]),
            proc(300, "/usr/bin/dash", &["/tmp/x/build.sh"]),
            proc(200, "/usr/bin/bash", &["-c", "sh /tmp/x/build.sh"]),
            proc(100, AGENT, &[]),
        ];
        assert_eq!(others(&chain), ["dash build.sh", "make install"]);
    }

    #[test]
    fn a_client_that_is_not_the_installed_cli_is_listed() {
        let chain = [
            proc(300, "/home/u/fake-peekexec", &[]),
            proc(200, "/usr/bin/bash", &["-c", "x"]),
            proc(100, AGENT, &[]),
        ];
        assert_eq!(others(&chain), ["fake-peekexec"]);
    }

    #[test]
    fn untrusted_shells_and_long_options_are_not_agent_shells() {
        let chain = [
            proc(300, CLI, &[]),
            proc(250, "/home/u/bin/bash", &["-c", "x"]),
            proc(200, "/usr/bin/bash", &["--rcfile", "/home/u/rc"]),
            proc(100, AGENT, &[]),
        ];
        assert_eq!(others(&chain), ["bash rc", "bash x"]);
        assert!(!is_c_flag("--rcfile") && is_c_flag("-lc") && !is_c_flag("-1c"));
    }

    #[test]
    fn reused_pid_or_no_agent_is_unregistered() {
        let mut agent = proc(100, AGENT, &[]);
        agent.start_time = Some(1); // same pid, different process
        let chain = [
            proc(300, CLI, &[]),
            proc(200, "/usr/bin/bash", &["-c", "x"]),
            agent,
        ];
        assert_eq!(run(&chain), Provenance::Unregistered);
        assert_eq!(run(&[proc(300, CLI, &[])]), Provenance::Unregistered);
    }

    #[test]
    fn default_agent_skips_shells() {
        let chain = [
            proc(300, CLI, &[]),
            proc(200, "/usr/bin/bash", &["-c", "x"]),
            proc(100, AGENT, &[]),
            proc(50, "/usr/bin/gnome-terminal-server", &[]),
        ];
        assert_eq!(default_agent(&chain).unwrap().pid, 100);
    }
}
