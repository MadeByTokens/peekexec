//! Finding the human's real X server from sources the requester cannot
//! control, so a requester cannot route the dialog through a display server
//! of its own (e.g. a nested Xephyr shown on the real screen) and read the
//! password as it is typed.
//!
//! The X server must be, all at once:
//! - inside the cgroup scope of the user's X11 logind session that has a
//!   seat and a VT and is that seat's active session (scopes are root-owned;
//!   processes cannot move into them),
//! - a descendant of that session's leader process (as logind records it),
//! - a root-owned `Xorg` binary started for the session's VT (`vtN`; a second
//!   Xorg cannot take a VT that is in use),
//! - the only process meeting all of the above.
//!
//! The display number is read from the abstract socket that very process
//! listens on (clients try it first; the filesystem socket sits in a
//! world-writable directory and may be the user's),
//! the cookie path from its own `-auth` argument. Anything less returns
//! `None`, and the dialog reports the display as unverified. Wayland
//! sessions are never verified here: there the compositor is the display
//! server, and checking Xwayland would verify the wrong thing.

use std::collections::HashSet;
use std::path::Path;

use crate::platform::XServer;
use crate::trust;

const SESSIONS: &str = "/run/systemd/sessions";

#[derive(Debug, PartialEq, Eq)]
struct Session {
    scope: String,
    leader: u32,
    vt: u32,
}

pub fn verified_x_server(uid: u32) -> Option<XServer> {
    let sessions = active_x11_sessions(uid);
    if sessions.is_empty() {
        return None;
    }
    let mut found = Vec::new();
    for entry in std::fs::read_dir("/proc").ok()?.filter_map(Result::ok) {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(cgroup) = std::fs::read_to_string(format!("/proc/{pid}/cgroup")) else {
            continue;
        };
        let Some(session) = sessions.iter().find(|s| in_scope(&cgroup, &s.scope)) else {
            continue;
        };
        let Some(exe) = super::peer::exe_of(pid).map(std::path::PathBuf::from) else {
            continue;
        };
        if exe.file_name().and_then(|n| n.to_str()) != Some("Xorg")
            || trust::check(&exe, &[0]).is_err()
        {
            continue;
        }
        let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
        if !has_arg(&cmdline, &format!("vt{}", session.vt)) {
            continue;
        }
        if !descends_from(pid, session.leader) {
            continue;
        }
        let Some(display) = listening_display(pid) else {
            continue;
        };
        found.push(XServer {
            display: format!(":{display}"),
            xauthority: auth_arg(&cmdline),
        });
    }
    // Ambiguity is not verification.
    if found.len() == 1 {
        found.pop()
    } else {
        None
    }
}

/// The user's active, local X11 sessions.
fn active_x11_sessions(uid: u32) -> Vec<Session> {
    let Ok(dir) = std::fs::read_dir(SESSIONS) else {
        return Vec::new();
    };
    dir.filter_map(Result::ok)
        .filter(|e| !e.file_name().to_string_lossy().contains('.'))
        .filter_map(|e| std::fs::read_to_string(e.path()).ok())
        .filter_map(|text| parse_session(&text, uid))
        .collect()
}

/// A logind session record, if it is this user's X11 session that the
/// human is sitting at, with a known scope, leader and VT. Positive
/// evidence only, as for polkit: logind counts every seatless session as
/// active.
fn parse_session(record: &str, uid: u32) -> Option<Session> {
    let get = |key: &str| {
        record
            .lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
    };
    let ok = get("UID") == Some(uid.to_string().as_str())
        && get("SEAT").is_some_and(|s| !s.is_empty())
        && get("ACTIVE") == Some("1")
        && get("STATE") == Some("active")
        && get("CLASS") == Some("user")
        && get("REMOTE") != Some("1")
        && get("TYPE") == Some("x11");
    if !ok {
        return None;
    }
    Some(Session {
        scope: get("SCOPE")?.to_string(),
        leader: get("LEADER")?.parse().ok()?,
        vt: get("VTNR")?.parse().ok()?,
    })
}

fn descends_from(mut pid: u32, ancestor: u32) -> bool {
    for _ in 0..64 {
        if pid == ancestor {
            return true;
        }
        if pid <= 1 {
            return false;
        }
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            return false;
        };
        let Some(ppid) = stat
            .rfind(')')
            .and_then(|i| stat[i + 1..].split_whitespace().nth(1))
            .and_then(|p| p.parse().ok())
        else {
            return false;
        };
        pid = ppid;
    }
    false
}

fn has_arg(cmdline: &[u8], want: &str) -> bool {
    cmdline.split(|&b| b == 0).any(|a| a == want.as_bytes())
}

/// Whole path: below `user@.service`, delegated to the user, a process can
/// make a group of any name.
fn in_scope(cgroup: &str, scope: &str) -> bool {
    cgroup.lines().any(|l| {
        l.rsplit(':').next().is_some_and(|path| {
            path.strip_prefix("/user.slice/user-")
                .and_then(|rest| rest.split_once('/'))
                .is_some_and(|(user, rest)| user.ends_with(".slice") && rest == scope)
        })
    })
}

/// Display number of the abstract X socket (`@/tmp/.X11-unix/X1`) that
/// `pid` holds in listening state. Not the filesystem one: an abstract name
/// held by Xorg cannot be taken by anyone else, and clients try it first.
fn listening_display(pid: u32) -> Option<u32> {
    let inodes: HashSet<u64> = std::fs::read_dir(format!("/proc/{pid}/fd"))
        .ok()?
        .filter_map(Result::ok)
        .filter_map(|fd| std::fs::read_link(fd.path()).ok())
        .filter_map(|link| {
            let s = link.to_str()?.strip_prefix("socket:[")?.strip_suffix(']')?;
            s.parse().ok()
        })
        .collect();
    let table = std::fs::read_to_string("/proc/net/unix").ok()?;
    table
        .lines()
        .skip(1)
        .filter_map(parse_unix_line)
        .find(|(inode, _)| inodes.contains(inode))
        .map(|(_, display)| display)
}

const SO_ACCEPTCON: u32 = 0x10000;

/// `(inode, display)` for a listening X11 socket line of /proc/net/unix:
/// `Num RefCount Protocol Flags Type St Inode Path`.
fn parse_unix_line(line: &str) -> Option<(u64, u32)> {
    let f: Vec<&str> = line.split_whitespace().collect();
    let flags = u32::from_str_radix(f.get(3)?, 16).ok()?;
    if flags & SO_ACCEPTCON == 0 {
        return None;
    }
    let inode = f.get(6)?.parse().ok()?;
    let path = f.get(7)?;
    let num = path.strip_prefix("@/tmp/.X11-unix/X")?.parse().ok()?;
    Some((inode, num))
}

fn auth_arg(cmdline: &[u8]) -> Option<String> {
    let args: Vec<&[u8]> = cmdline.split(|&b| b == 0).collect();
    let i = args.iter().position(|a| *a == b"-auth")?;
    let path = std::str::from_utf8(args.get(i + 1)?).ok()?;
    Path::new(path).is_absolute().then(|| path.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_active_local_x11_session() {
        let rec = "UID=1000\nUSER=u\nACTIVE=1\nSTATE=active\nREMOTE=0\nTYPE=x11\nCLASS=user\nSEAT=seat0\nSCOPE=session-2.scope\nLEADER=3795\nVTNR=2\n";
        assert_eq!(
            parse_session(rec, 1000),
            Some(Session {
                scope: "session-2.scope".into(),
                leader: 3795,
                vt: 2
            })
        );
        // Positive evidence: a seat, a VT, the seat's active user session.
        for (from, to) in [
            ("SEAT=seat0\n", ""),
            ("SEAT=seat0", "SEAT="),
            ("VTNR=2\n", ""),
            ("STATE=active", "STATE=online"),
            ("CLASS=user", "CLASS=greeter"),
        ] {
            assert_eq!(parse_session(&rec.replace(from, to), 1000), None, "{from}");
        }
        assert_eq!(parse_session(rec, 1001), None);
        assert_eq!(
            parse_session(&rec.replace("ACTIVE=1", "ACTIVE=0"), 1000),
            None
        );
        assert_eq!(
            parse_session(&rec.replace("REMOTE=0", "REMOTE=1"), 1000),
            None
        );
        assert_eq!(
            parse_session(&rec.replace("TYPE=x11", "TYPE=wayland"), 1000),
            None
        );
        assert_eq!(parse_session(&rec.replace("LEADER=3795\n", ""), 1000), None);
        // UID=10000 must not match uid 1000 by prefix.
        assert_eq!(
            parse_session(&rec.replace("UID=1000", "UID=10000"), 1000),
            None
        );
    }

    #[test]
    fn ancestry_and_args() {
        let me = std::process::id();
        assert!(descends_from(me, me));
        assert!(!descends_from(1, me));
        assert!(has_arg(b"Xorg\0vt2\0-auth\0x\0", "vt2"));
        assert!(!has_arg(b"Xorg\0vt22\0", "vt2"));
    }

    #[test]
    fn scope_match_is_exact() {
        let cg = "0::/user.slice/user-1000.slice/session-2.scope\n";
        assert!(in_scope(cg, "session-2.scope"));
        assert!(!in_scope(cg, "session-12.scope"));
        assert!(!in_scope(
            "0::/user.slice/user-1000.slice/user@1000.service/session-2.scope\n",
            "session-2.scope"
        ));
        assert!(!in_scope(
            "0::/user.slice/user-1000.slice/session-12.scope\n",
            "session-2.scope"
        ));
    }

    #[test]
    fn parses_listening_x_sockets_only() {
        let listen =
            "0000000000000000: 00000002 00000000 00010000 0001 01 25177 @/tmp/.X11-unix/X1";
        let conn = "0000000000000000: 00000003 00000000 00000000 0001 03 28477 @/tmp/.X11-unix/X1";
        let other = "0000000000000000: 00000002 00000000 00010000 0001 01 99 /run/foo.sock";
        let file = "0000000000000000: 00000002 00000000 00010000 0001 01 25176 /tmp/.X11-unix/X1";
        assert_eq!(
            parse_unix_line(file),
            None,
            "the filesystem socket may be the user's"
        );
        assert_eq!(parse_unix_line(listen), Some((25177, 1)));
        assert_eq!(parse_unix_line(conn), None);
        assert_eq!(parse_unix_line(other), None);
    }

    #[test]
    fn reads_auth_argument() {
        let cmd =
            b"/usr/lib/xorg/Xorg\0vt2\0-displayfd\x003\0-auth\0/run/user/1000/gdm/Xauthority\0";
        assert_eq!(
            auth_arg(cmd).as_deref(),
            Some("/run/user/1000/gdm/Xauthority")
        );
        assert_eq!(auth_arg(b"Xorg\0-auth\0relative\0"), None);
    }
}
