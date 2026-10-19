//! Choosing the display the dialog appears on.
//!
//! Whoever controls the display server sees every key typed into the dialog.
//! A requester that could pick the display (DISPLAY / WAYLAND_DISPLAY in its
//! own environment) could run a nested server (Xephyr, nested weston) shown
//! on the real screen and capture the password. So the display comes from
//! the platform's verified lookup (logind session + the X server process in
//! it) whenever possible. Only when that fails do we fall back to the
//! environment of the user's processes, and then the dialog and the response
//! say the display is unverified. Remote displays are refused outright.

use peekexec_proto::DisplayTier;

use crate::platform::{Peer, PeerInfo};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Display {
    pub vars: Vec<(String, String)>,
    pub tier: DisplayTier,
    /// Found from sources the requester cannot control.
    pub verified: bool,
}

pub fn find(info: &dyn PeerInfo, peer: &Peer) -> Option<Display> {
    if let Some(x) = info.verified_x_server(peer.uid) {
        let mut vars = vec![("DISPLAY".to_string(), x.display)];
        vars.extend(x.xauthority.map(|a| ("XAUTHORITY".to_string(), a)));
        return Some(Display {
            vars,
            tier: DisplayTier::X11,
            verified: true,
        });
    }
    let chain = std::iter::once(peer.process.pid).chain(peer.ancestry.iter().map(|p| p.pid));
    let rest = info.processes_of(peer.uid);
    chain
        .chain(rest)
        .filter_map(|pid| info.environ(pid, peer.uid))
        .find_map(|env| from_environ(&env, peer.uid))
}

fn get<'a>(env: &'a [(String, String)], key: &str) -> Option<&'a str> {
    env.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

pub fn from_environ(env: &[(String, String)], uid: u32) -> Option<Display> {
    let runtime = get(env, "XDG_RUNTIME_DIR").filter(|d| *d == format!("/run/user/{uid}"));
    if let (Some(wl), Some(rt)) = (get(env, "WAYLAND_DISPLAY"), runtime) {
        if !wl.is_empty() && !wl.contains('/') {
            return Some(Display {
                vars: vec![
                    ("WAYLAND_DISPLAY".into(), wl.into()),
                    ("XDG_RUNTIME_DIR".into(), rt.into()),
                ],
                tier: DisplayTier::Wayland,
                verified: false,
            });
        }
    }
    let display = get(env, "DISPLAY").filter(|d| is_local_display(d))?;
    let mut vars = vec![("DISPLAY".to_string(), display.to_string())];
    if let Some(xa) = get(env, "XAUTHORITY").filter(|p| p.starts_with('/')) {
        vars.push(("XAUTHORITY".into(), xa.into()));
    }
    if let Some(rt) = runtime {
        vars.push(("XDG_RUNTIME_DIR".into(), rt.into()));
    }
    Some(Display {
        vars,
        tier: DisplayTier::X11,
        verified: false,
    })
}

/// `:N` or `:N.S` only: no host part, so never a remote X server.
fn is_local_display(d: &str) -> bool {
    let Some(rest) = d.strip_prefix(':') else {
        return false;
    };
    let mut parts = rest.splitn(2, '.');
    let num_ok =
        |s: Option<&str>| s.is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()));
    num_ok(parts.next()) && parts.next().map_or(true, |s| num_ok(Some(s)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn prefers_wayland() {
        let d = from_environ(
            &env(&[
                ("DISPLAY", ":0"),
                ("WAYLAND_DISPLAY", "wayland-0"),
                ("XDG_RUNTIME_DIR", "/run/user/1000"),
            ]),
            1000,
        )
        .unwrap();
        assert_eq!(d.tier, DisplayTier::Wayland);
    }

    #[test]
    fn x11_with_cookie() {
        let d = from_environ(
            &env(&[
                ("DISPLAY", ":1"),
                ("XAUTHORITY", "/run/user/1000/gdm/Xauthority"),
            ]),
            1000,
        )
        .unwrap();
        assert_eq!(d.tier, DisplayTier::X11);
        assert_eq!(d.vars.len(), 2);
    }

    #[test]
    fn refuses_remote_and_foreign_displays() {
        assert!(from_environ(&env(&[("DISPLAY", "evil.example:0")]), 1000).is_none());
        assert!(from_environ(&env(&[("DISPLAY", ":0x")]), 1000).is_none());
        // Wayland socket in another user's runtime dir: ignored, no X fallback here.
        assert!(from_environ(
            &env(&[
                ("WAYLAND_DISPLAY", "wayland-0"),
                ("XDG_RUNTIME_DIR", "/run/user/0")
            ]),
            1000
        )
        .is_none());
        assert!(is_local_display(":1.0"));
    }
}
