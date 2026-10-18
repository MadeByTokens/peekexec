//! Finding the human's real X server from sources the requester cannot
//! control, so a requester cannot route the dialog through a display server
//! of its own (e.g. a nested Xephyr shown on the real screen) and read the
//! password as it is typed.
//!
//! The X server must be: inside the cgroup scope of the user's active local
//! graphical logind session (scopes are root-owned; user processes cannot
//! move into them), running a root-owned `Xorg`/`Xwayland` binary, and the
//! display number is read from the socket that very process listens on. The
//! cookie path comes from its own `-auth` argument.

use std::collections::HashSet;
use std::path::Path;

use crate::platform::XServer;
use crate::trust;

const SESSIONS: &str = "/run/systemd/sessions";

pub fn verified_x_server(uid: u32) -> Option<XServer> {
    let scopes = active_graphical_scopes(uid);
    if scopes.is_empty() {
        return None;
    }
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
        if !scopes.iter().any(|s| in_scope(&cgroup, s)) {
            continue;
        }
        let Ok(exe) = std::fs::read_link(format!("/proc/{pid}/exe")) else {
            continue;
        };
        let name = exe.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !matches!(name, "Xorg" | "Xwayland") || trust::check(&exe, &[0]).is_err() {
            continue;
        }
        let Some(display) = listening_display(pid) else {
            continue;
        };
        let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
        return Some(XServer {
            display: format!(":{display}"),
            xauthority: auth_arg(&cmdline),
        });
    }
    None
}

/// Scopes of the user's active, local, graphical sessions.
fn active_graphical_scopes(uid: u32) -> Vec<String> {
    let Ok(dir) = std::fs::read_dir(SESSIONS) else {
        return Vec::new();
    };
    dir.filter_map(Result::ok)
        .filter(|e| !e.file_name().to_string_lossy().contains('.'))
        .filter_map(|e| std::fs::read_to_string(e.path()).ok())
        .filter_map(|text| graphical_scope(&text, uid))
        .collect()
}

/// The SCOPE of a logind session record, if it is this user's active,
/// local, graphical session.
fn graphical_scope(record: &str, uid: u32) -> Option<String> {
    let get = |key: &str| {
        record
            .lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
    };
    let ok = get("UID") == Some(uid.to_string().as_str())
        && get("ACTIVE") == Some("1")
        && get("REMOTE") != Some("1")
        && matches!(get("TYPE"), Some("x11" | "wayland"));
    ok.then(|| get("SCOPE").map(str::to_string)).flatten()
}

fn in_scope(cgroup: &str, scope: &str) -> bool {
    cgroup.lines().any(|l| {
        l.rsplit(':')
            .next()
            .is_some_and(|path| path.ends_with(&format!("/{scope}")))
    })
}

/// Display number of an X socket (`@/tmp/.X11-unix/X1` or the filesystem
/// one) that `pid` holds in listening state.
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
    let num = path
        .trim_start_matches('@')
        .strip_prefix("/tmp/.X11-unix/X")?
        .parse()
        .ok()?;
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
    fn picks_active_local_graphical_session() {
        let rec =
            "UID=1000\nUSER=u\nACTIVE=1\nSTATE=active\nREMOTE=0\nTYPE=x11\nSCOPE=session-2.scope\n";
        assert_eq!(
            graphical_scope(rec, 1000).as_deref(),
            Some("session-2.scope")
        );
        assert_eq!(graphical_scope(rec, 1001), None);
        assert_eq!(
            graphical_scope(&rec.replace("ACTIVE=1", "ACTIVE=0"), 1000),
            None
        );
        assert_eq!(
            graphical_scope(&rec.replace("REMOTE=0", "REMOTE=1"), 1000),
            None
        );
        assert_eq!(
            graphical_scope(&rec.replace("TYPE=x11", "TYPE=tty"), 1000),
            None
        );
        // UID=10000 must not match uid 1000 by prefix.
        assert_eq!(
            graphical_scope(&rec.replace("UID=1000", "UID=10000"), 1000),
            None
        );
    }

    #[test]
    fn scope_match_is_exact() {
        let cg = "0::/user.slice/user-1000.slice/session-2.scope\n";
        assert!(in_scope(cg, "session-2.scope"));
        assert!(!in_scope(cg, "session-12.scope"));
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
