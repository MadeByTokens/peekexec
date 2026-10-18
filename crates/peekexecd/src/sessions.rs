//! Registered agent sessions: which process is "the agent", and whether a
//! request came from the agent's own command or from something it started.
//!
//! The uid of a request is certain (kernel). Process names are not: any
//! program of the user can call itself "claude". A registration, approved
//! once by the human, pins one specific process (pidfd + start time); later
//! requests are matched against the kernel's process ancestry, which a
//! process cannot fake to *gain* a registered agent as its ancestor.

use std::path::Path;
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
    /// The installed peekexec, called from the agent's own shell command
    /// (`sh -c '...'`), or by the agent process itself.
    Direct {
        session: String,
        command: Option<String>,
    },
    /// A program the agent started made the request.
    Indirect { session: String, via: Vec<String> },
}

fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// A shell started with a command string (`-c`), not running a script file.
fn shell_command(p: &ProcessInfo, trusted: &dyn Fn(&str) -> bool) -> Option<Option<String>> {
    let exe = p.exe.as_deref()?;
    if !SHELLS.contains(&basename(exe)) || !trusted(exe) {
        return None;
    }
    let mut args = p.cmdline.iter().skip(1);
    for a in args.by_ref() {
        if !a.starts_with('-') {
            return None; // a script file: not the agent's own command
        }
        if a.contains('c') {
            return Some(args.find(|a| !a.starts_with('-')).cloned());
        }
    }
    None
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
    let name = session.name.clone();
    if k == 0 {
        return Provenance::Direct {
            session: name,
            command: None,
        };
    }
    let client = &chain[0];
    let client_ok = client
        .exe
        .as_deref()
        .is_some_and(|e| basename(e) == "peekexec" && trusted(e));
    let middle = &chain[1..k];
    let commands: Vec<Option<Option<String>>> =
        middle.iter().map(|p| shell_command(p, trusted)).collect();
    if client_ok && !middle.is_empty() && commands.iter().all(Option::is_some) {
        return Provenance::Direct {
            session: name,
            command: commands.last().cloned().flatten().flatten(),
        };
    }
    let via = chain[..k]
        .iter()
        .rev()
        .map(|p| {
            let exe = p.exe.as_deref().unwrap_or("?");
            let label = Path::new(exe)
                .file_name()
                .map_or(exe.to_string(), |n| n.to_string_lossy().into_owned());
            if p.cmdline.len() > 1 && SHELLS.contains(&label.as_str()) {
                format!("{label} {}", p.cmdline[1..].join(" "))
            } else {
                label
            }
        })
        .collect();
    Provenance::Indirect { session: name, via }
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

    const CLI: &str = "/usr/local/bin/peekexec";
    const AGENT: &str = "/home/u/.local/bin/claude";

    #[test]
    fn agent_tool_call_is_direct() {
        let chain = [
            proc(300, CLI, &["run", "--", "id"]),
            proc(200, "/usr/bin/bash", &["-c", "-l", "peekexec run -- id"]),
            proc(100, AGENT, &[]),
        ];
        assert_eq!(
            run(&chain),
            Provenance::Direct {
                session: "Claude Code".into(),
                command: Some("peekexec run -- id".into())
            }
        );
    }

    #[test]
    fn script_started_by_the_agent_is_indirect() {
        // The agent ran ./build.sh, whose interpreter is bash (no -c).
        let chain = [
            proc(400, CLI, &["run", "--", "id"]),
            proc(300, "/usr/bin/bash", &["./build.sh"]),
            proc(200, "/usr/bin/bash", &["-c", "./build.sh"]),
            proc(100, AGENT, &[]),
        ];
        let Provenance::Indirect { via, .. } = run(&chain) else {
            panic!()
        };
        assert_eq!(via, ["bash -c ./build.sh", "bash ./build.sh", "peekexec"]);
    }

    #[test]
    fn other_programs_in_between_are_indirect() {
        let chain = [
            proc(400, CLI, &[]),
            proc(300, "/usr/bin/make", &["install"]),
            proc(200, "/usr/bin/bash", &["-c", "make install"]),
            proc(100, AGENT, &[]),
        ];
        assert!(matches!(run(&chain), Provenance::Indirect { .. }));
    }

    #[test]
    fn a_client_that_is_not_the_installed_cli_is_indirect() {
        let chain = [
            proc(300, "/home/u/fake-peekexec", &[]),
            proc(200, "/usr/bin/bash", &["-c", "x"]),
            proc(100, AGENT, &[]),
        ];
        assert!(matches!(run(&chain), Provenance::Indirect { .. }));
    }

    #[test]
    fn untrusted_shell_binary_is_indirect() {
        let chain = [
            proc(300, CLI, &[]),
            proc(200, "/home/u/bin/bash", &["-c", "x"]),
            proc(100, AGENT, &[]),
        ];
        assert!(matches!(run(&chain), Provenance::Indirect { .. }));
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
