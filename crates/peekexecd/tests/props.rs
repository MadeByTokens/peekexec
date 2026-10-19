//! Property tests for the daemon: requester-controlled input must never
//! crash it, and text shown on one line must never be able to fake lines or
//! hide characters.

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;

use peekexec_core::textcheck::{classify, FindingKind};
use peekexec_core::{Action, Request};
use peekexec_proto::DisplayTier;
use peekexecd::platform::{Peer, ProcessInfo};
use peekexecd::prepare::{self, display_line, Ctx, User};
use peekexecd::session::Display;
use peekexecd::sessions::{self, AgentSession};
use proptest::prelude::*;

fn process(pid: u32, exe: String, args: Vec<String>) -> ProcessInfo {
    ProcessInfo {
        pid,
        exe: Some(exe),
        cmdline: args,
        start_time: Some(pid as u64),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3000))]

    #[test]
    fn one_line_text_cannot_fake_lines_or_hide_characters(s in any::<String>(), max in 1usize..400) {
        let out = display_line(&s, max);
        for c in out.chars() {
            prop_assert!(!c.is_control(), "control {:?} in {:?}", c, out);
            prop_assert!(
                matches!(classify(c), None | Some(FindingKind::NonAscii)),
                "hidden {:?} in {:?}", c, out
            );
        }
        // Each escaped character becomes one ⟨U+XXXXXX⟩ token at most.
        prop_assert!(s.chars().take(max).count() <= max);
        prop_assert!(out.chars().count() <= max * 10 + 1);
    }

    #[test]
    fn prepare_never_panics(
        argv in proptest::collection::vec(any::<String>(), 0..5),
        env in proptest::collection::btree_map("[A-Z_]{0,12}", any::<String>(), 0..3),
        cwd in any::<String>(),
        write in proptest::option::of(proptest::collection::vec(any::<String>(), 0..3)),
        why in proptest::option::of(any::<String>()),
    ) {
        let sandbox = peekexecd::platform::linux::Namespaces;
        let ctx = Ctx {
            sandbox: &sandbox,
            wants_password: true,
            dev: true,
            snapshot_root: std::path::Path::new("/nonexistent/peekexec-props"),
        };
        let peer = Peer {
            uid: 1000,
            gid: 1000,
            process: process(1, "/usr/bin/true".into(), vec![]),
            cwd: None,
            ancestry: vec![],
            pinned: false,
        };
        let user = User { name: "u".into(), home: "/home/u".into(), uid: 1000, groups: vec![1000] };
        let display = Display { vars: vec![], tier: DisplayTier::X11, verified: false };
        let req = Request {
            action: Action::Run { argv },
            why,
            write,
            no_net: false,
            env: env.into_iter().collect::<BTreeMap<_, _>>(),
            cwd,
            timeout_secs: 60,
        };
        let _ = prepare::prepare(&ctx, &peer, &user, &req, "r-props", &display, false);
    }

    #[test]
    fn classify_never_panics(
        chain in proptest::collection::vec(
            (1u32..50, "(/usr/bin/|/home/u/)?[a-z]{1,8}", proptest::collection::vec("-?[a-z/.]{0,6}", 0..4)),
            0..8,
        ),
        agent_pid in 1u32..50,
    ) {
        let chain: Vec<ProcessInfo> = chain
            .into_iter()
            .map(|(pid, exe, args)| process(pid, exe, args))
            .collect();
        let session = AgentSession::for_tests("agent", agent_pid);
        let live = |s: &AgentSession, p: &ProcessInfo| p.pid == s.pinned.pid;
        let trusted = |e: &str| e.starts_with("/usr/");
        let _ = sessions::classify(&chain, &[&session], &live, &trusted);
    }
}
