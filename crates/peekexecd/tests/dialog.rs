//! The daemon ⇄ dialog channel, with a stand-in dialog script: the view
//! arrives, the answer comes back, and the dialog gets nothing but stdio,
//! on descriptors that cannot be reopened through /proc.

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::AtomicBool;

use peekexec_core::{Action, Request};
use peekexec_proto::DisplayTier;
use peekexecd::platform::{Authenticator, Peer, PlatformError, ProcessInfo};
use peekexecd::prepare::{self, Ctx, User};
use peekexecd::prompt::{self, Approver, Decision, Dialog};
use peekexecd::session::Display;

struct NoAuth;

impl Authenticator for NoAuth {
    fn wants_password(&self) -> bool {
        true
    }
    fn verify(&self, _user: &str, _password: Option<&str>) -> Result<bool, PlatformError> {
        Ok(false)
    }
}

/// Reads the Show message, reports what it can see in its deny reason,
/// then waits for the daemon to hang up.
const FAKE_DIALOG: &str = r#"#!/bin/sh
read -r line
case "$line" in *'"msg":"show"'*) show=yes ;; *) show=no ;; esac
if ( : < /proc/self/fd/0 ) 2>/dev/null; then reopen=yes; else reopen=no; fi
fds=$(ls /proc/self/fd | tr '\n' ' ')
echo "a line for the log" >&2
printf '{"msg":"deny","reason":"show=%s reopen=%s fds=%s"}\n' "$show" "$reopen" "$fds"
cat > /dev/null
"#;

#[test]
fn dialog_channel_is_a_socket_with_only_stdio() {
    let dir = std::env::temp_dir().join(format!("pe-dialog-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let program = dir.join("fake-dialog");
    std::fs::write(&program, FAKE_DIALOG).unwrap();
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();

    let sandbox = peekexecd::platform::linux::Namespaces;
    let ctx = Ctx {
        sandbox: &sandbox,
        inspect: &peekexecd::inspect::inspect,
        wants_password: true,
        dev: true,
        snapshot_root: std::path::Path::new("/nonexistent/peekexec-dialog"),
    };
    let peer = Peer {
        uid: 1000,
        gid: 1000,
        process: ProcessInfo {
            pid: 1,
            exe: None,
            cmdline: vec![],
            start_time: None,
        },
        cwd: None,
        ancestry: vec![],
        pinned: false,
    };
    let user = User {
        name: "u".into(),
        home: "/home/u".into(),
        uid: 1000,
        gid: 1000,
        groups: vec![1000],
    };
    let display = Display {
        vars: vec![],
        tier: DisplayTier::X11,
        verified: true,
    };
    let req = Request {
        action: Action::Run {
            argv: vec!["true".into()],
        },
        why: None,
        write: None,
        no_net: false,
        env: BTreeMap::new(),
        cwd: "/".into(),
        timeout_secs: 30,
    };
    let prepared = prepare::prepare(&ctx, &peer, &user, &req, "r-dialog", &display, false).unwrap();

    let dialog = Dialog {
        program: program.clone(),
        run_as: None,
    };
    let approver = Approver::Password {
        auth: &NoAuth,
        user: "u",
    };
    let decision = prompt::ask(
        &dialog,
        &display,
        &prepared.view,
        &approver,
        &AtomicBool::new(false),
    )
    .unwrap();
    std::fs::remove_dir_all(&dir).unwrap();

    let Decision::Denied(reason) = decision else {
        panic!("{decision:?}")
    };
    assert!(reason.contains("show=yes"), "{reason}");
    assert!(
        reason.contains("reopen=no"),
        "stdin reopened via /proc: {reason}"
    );
    // 0-2 are stdio; 3 is the directory `ls` itself opened.
    let fds: Vec<&str> = reason
        .split("fds=")
        .nth(1)
        .unwrap()
        .split_whitespace()
        .collect();
    assert_eq!(fds, ["0", "1", "2", "3"], "{reason}");
}
