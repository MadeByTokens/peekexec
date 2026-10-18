//! Linux backends. Auth (PAM), Sandbox (Landlock + netns) and Listener
//! (systemd socket activation) arrive in M1/M2.

use std::os::unix::net::{UnixListener, UnixStream};
use std::process::Child;

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use peekexec_proto::Enforced;

use super::{
    declared_only, AuthOutcome, Authenticator, Challenger, ExecPlan, Listener, Peer, PeerInfo,
    Platform, PlatformError, ProcessInfo, Sandbox,
};

pub fn platform() -> Platform {
    Platform {
        peer: Box::new(ProcPeerInfo),
        auth: Box::new(Pam),
        sandbox: Box::new(Landlock),
        listener: Box::new(SystemdSocket),
    }
}

/// SO_PEERCRED for the identity, /proc for the description.
///
/// TODO(M1): pin the process with a pidfd (SO_PEERPIDFD, Linux 6.5+) so a
/// reused pid cannot be described in place of the real requester.
pub struct ProcPeerInfo;

impl PeerInfo for ProcPeerInfo {
    fn identify(&self, conn: &UnixStream) -> Result<Peer, PlatformError> {
        let cred = getsockopt(conn, PeerCredentials)
            .map_err(|e| PlatformError::Other(format!("SO_PEERCRED: {e}")))?;
        let pid = cred.pid() as u32;
        let mut ancestry = Vec::new();
        let mut next = parent_pid(pid);
        while let Some(ppid) = next.filter(|&p| p > 1) {
            ancestry.push(process_info(ppid));
            next = parent_pid(ppid);
        }
        Ok(Peer {
            uid: cred.uid(),
            gid: cred.gid(),
            process: process_info(pid),
            cwd: readlink(pid, "cwd"),
            ancestry,
        })
    }
}

fn readlink(pid: u32, what: &str) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/{what}"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

fn process_info(pid: u32) -> ProcessInfo {
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline"))
        .map(|raw| {
            raw.split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect()
        })
        .unwrap_or_default();
    ProcessInfo {
        pid,
        exe: readlink(pid, "exe"),
        cmdline,
    }
}

fn parent_pid(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_ppid(&stat)
}

/// The comm field (in parentheses) may itself contain spaces and ')', so
/// parse from the last ')': "<pid> (<comm>) <state> <ppid> ...".
fn parse_ppid(stat: &str) -> Option<u32> {
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(1)?.parse().ok()
}

pub struct Pam;

impl Authenticator for Pam {
    fn authenticate(
        &self,
        _user: &str,
        _ui: &mut dyn Challenger,
    ) -> Result<AuthOutcome, PlatformError> {
        Err(PlatformError::Unsupported("PAM authentication (M1)"))
    }
}

pub struct Landlock;

impl Sandbox for Landlock {
    fn enforcement(&self, plan: &ExecPlan) -> Enforced {
        // Nothing is enforced yet.
        declared_only(plan)
    }

    fn spawn(&self, _plan: &ExecPlan) -> Result<Child, PlatformError> {
        Err(PlatformError::Unsupported("sandboxed execution (M1)"))
    }
}

pub struct SystemdSocket;

impl Listener for SystemdSocket {
    fn listen(&self) -> Result<UnixListener, PlatformError> {
        Err(PlatformError::Unsupported("socket activation (M1)"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use peekexec_proto::Level;

    #[test]
    fn identifies_self_over_socketpair() {
        let (a, _b) = UnixStream::pair().unwrap();
        let peer = ProcPeerInfo.identify(&a).unwrap();
        assert_eq!(peer.process.pid, std::process::id());
        assert_eq!(peer.uid, nix::unistd::getuid().as_raw());
        assert!(peer.process.exe.is_some());
        assert!(!peer.ancestry.is_empty());
    }

    #[test]
    fn ppid_survives_hostile_comm() {
        assert_eq!(parse_ppid("42 (evil) 1 2 ) S 777 42 42"), Some(777));
        assert_eq!(parse_ppid("42 (bash) S 100 42 42"), Some(100));
        assert_eq!(parse_ppid("garbage"), None);
    }

    #[test]
    fn never_claims_unimplemented_enforcement() {
        let plan = ExecPlan {
            argv: vec!["true".into()],
            env: Default::default(),
            cwd: "/".into(),
            write: Some(vec!["/etc/x".into()]),
            no_net: true,
        };
        let e = Landlock.enforcement(&plan);
        assert_eq!(e.write_level, Level::DeclaredOnly);
        assert_eq!(e.network_level, Level::DeclaredOnly);
    }
}
