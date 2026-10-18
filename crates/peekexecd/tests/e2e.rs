//! End-to-end: the real daemon binary in `--dev` mode, driven over its
//! socket, with the test approver standing in for the human.
//!
//!   cargo test -p peekexecd --features test-approver

#![cfg(feature = "test-approver")]

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use peekexec_core::{Action, Request};
use peekexec_proto::view::Syntax;
use peekexec_proto::wire::call;
use peekexec_proto::{ClientMsg, Level, PreviewReply, Response, Status};

struct Daemon {
    child: Child,
    socket: PathBuf,
    dir: PathBuf,
}

impl Daemon {
    fn start(answer: &str) -> Daemon {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "pe-e2e-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let socket = dir.join("d.sock");
        let child = Command::new(env!("CARGO_BIN_EXE_peekexecd"))
            .args(["--dev", "--socket"])
            .arg(&socket)
            .env("XDG_RUNTIME_DIR", &dir)
            .env("PEEKEXEC_TEST_APPROVER", answer)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !socket.exists() {
            assert!(Instant::now() < deadline, "daemon did not start");
            std::thread::sleep(Duration::from_millis(20));
        }
        Daemon { child, socket, dir }
    }

    fn send(&self, msg: &ClientMsg) -> Response {
        call(&self.socket, msg).unwrap()
    }

    fn run(&self, request: Request) -> Response {
        self.send(&ClientMsg::Run { request })
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn request(action: Action) -> Request {
    Request {
        action,
        why: Some("e2e test".into()),
        write: None,
        no_net: false,
        env: BTreeMap::new(),
        cwd: "/".into(),
        timeout_secs: 30,
    }
}

fn sh(script: &str) -> Request {
    request(Action::Run {
        argv: vec!["sh".into(), "-c".into(), script.into()],
    })
}

#[test]
fn approved_command_runs_and_reports() {
    let d = Daemon::start("approve");
    let r = d.run(sh("echo hi; echo oops >&2; exit 3"));
    assert_eq!(r.status, Status::Approved, "{r:?}");
    assert_eq!(r.exit_code, Some(3));
    assert_eq!(r.stdout.as_deref(), Some("hi\n"));
    assert_eq!(r.stderr.as_deref(), Some("oops\n"));
    assert!(r.dev_mode);
    assert_eq!(
        r.sha256.as_deref(),
        Some(sh("echo hi; echo oops >&2; exit 3").digest().as_str())
    );
    let e = r.enforced.unwrap();
    assert_eq!(e.write_level, Level::NotRequested);
}

#[test]
fn environment_is_clean() {
    // The daemon inherits SECRET; the command must not.
    std::env::set_var("SECRET", "leaked");
    let d = Daemon::start("approve");
    let mut req = sh("echo \"$PATH|${SECRET:-unset}|$TZ\"");
    req.env.insert("TZ".into(), "UTC".into());
    let r = d.run(req);
    assert_eq!(
        r.stdout.as_deref(),
        Some("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin|unset|UTC\n")
    );
}

#[test]
fn denial_reaches_the_agent_and_blocks_identical_resend() {
    let d = Daemon::start("deny:use the vendor rules file");
    let r = d.run(sh("chmod 777 /dev/ttyACM0"));
    assert_eq!(r.status, Status::Denied);
    assert_eq!(r.deny_reason.as_deref(), Some("use the vendor rules file"));

    // Same command, reworded explanation: still the same request.
    let mut again = sh("chmod 777 /dev/ttyACM0");
    again.why = Some("please, it is really needed".into());
    let r = d.run(again);
    assert_eq!(r.status, Status::Error);
    let err = r.error.unwrap();
    assert!(
        err.contains("refused") && err.contains("use the vendor rules file"),
        "{err}"
    );

    // A changed request is asked again.
    let r = d.run(sh("cp 49-stlink.rules /etc/udev/rules.d/"));
    assert_eq!(r.status, Status::Denied);
}

#[test]
fn cancel_and_auth_failure_statuses() {
    assert_eq!(
        Daemon::start("cancel").run(sh("true")).status,
        Status::Cancelled
    );
    assert_eq!(
        Daemon::start("authfail").run(sh("true")).status,
        Status::AuthFailed
    );
    assert_eq!(
        Daemon::start("timeout").run(sh("true")).status,
        Status::Timeout
    );
}

#[test]
fn submit_wait_cancel() {
    let d = Daemon::start("hold");
    let r = d.send(&ClientMsg::Submit {
        request: sh("true"),
    });
    assert_eq!(r.status, Status::Pending);
    let id = r.request_id.unwrap();

    let r = d.send(&ClientMsg::Wait {
        id: id.clone(),
        timeout_secs: Some(1),
    });
    assert_eq!(r.status, Status::Pending);

    let r = d.send(&ClientMsg::Cancel { id: id.clone() });
    assert_eq!(r.status, Status::Cancelled);

    let r = d.send(&ClientMsg::Wait {
        id,
        timeout_secs: Some(1),
    });
    assert_eq!(r.status, Status::Cancelled, "result stays available");

    let r = d.send(&ClientMsg::Wait {
        id: "r-nope".into(),
        timeout_secs: Some(1),
    });
    assert_eq!(r.status, Status::Error);
}

#[test]
fn script_runs_from_snapshot_not_from_disk() {
    let d = Daemon::start("delay:500");
    let script = d.dir.join("job.sh");
    std::fs::write(&script, "#!/bin/sh\necho original \"$1\"\n").unwrap();
    let content = std::fs::read(&script).unwrap();
    let r = d.send(&ClientMsg::Submit {
        request: request(Action::Script {
            path: script.to_str().unwrap().into(),
            content,
            args: vec!["arg".into()],
        }),
    });
    let id = r.request_id.unwrap();
    // Swap the file while the "human" is still looking at the dialog.
    std::fs::write(&script, "#!/bin/sh\necho EVIL\n").unwrap();
    let r = d.send(&ClientMsg::Wait {
        id,
        timeout_secs: Some(10),
    });
    assert_eq!(r.status, Status::Approved, "{r:?}");
    assert_eq!(r.stdout.as_deref(), Some("original arg\n"));
    let snaps = d.dir.join("peekexec-dev/snap");
    let left = std::fs::read_dir(&snaps).map(|it| it.count()).unwrap_or(0);
    assert_eq!(left, 0, "snapshot not cleaned up");
}

#[test]
fn untrusted_programs_and_env_are_rejected() {
    let d = Daemon::start("approve");
    let tool = d.dir.join("tool");
    std::fs::write(&tool, "#!/bin/sh\necho hi\n").unwrap();
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o777)).unwrap();
    let r = d.run(request(Action::Run {
        argv: vec![tool.to_str().unwrap().into()],
    }));
    assert_eq!(r.status, Status::Error);
    assert!(r.error.unwrap().contains("peekexec script"));

    let mut req = sh("true");
    req.env.insert("LD_PRELOAD".into(), "/tmp/x.so".into());
    let r = d.run(req);
    assert!(r.error.unwrap().contains("LD_PRELOAD"));
}

#[test]
fn install_writes_exactly_one_file() {
    let d = Daemon::start("approve");
    let target_dir = d.dir.join("etc");
    std::fs::create_dir(&target_dir).unwrap();
    std::fs::set_permissions(&target_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let r = d.run(request(Action::Install {
        src: "/src/49-stlink.rules".into(),
        content: b"SUBSYSTEM==\"usb\"\n".to_vec(),
        dest: target_dir.to_str().unwrap().into(),
    }));
    assert_eq!(r.status, Status::Approved, "{r:?}");
    let written = target_dir.join("49-stlink.rules");
    assert_eq!(std::fs::read(&written).unwrap(), b"SUBSYSTEM==\"usb\"\n");
    let e = r.enforced.unwrap();
    assert_eq!(e.write_level, Level::Builtin);
    assert_eq!(e.write.unwrap(), [written.to_str().unwrap()]);
}

#[test]
fn preview_matches_what_would_be_shown() {
    let d = Daemon::start("approve");
    let reply: PreviewReply = call(
        &d.socket,
        &ClientMsg::Preview {
            request: sh("cp a /etc/x/ && udevadm trigger"),
        },
    )
    .unwrap();
    let PreviewReply::Ok { view } = reply else {
        panic!("{reply:?}")
    };
    assert_eq!(view.sections.len(), 1);
    let s = &view.sections[0];
    assert_eq!(s.syntax, Syntax::Shell);
    assert_eq!(s.raw, "cp a /etc/x/ && udevadm trigger");
    assert_eq!(s.formatted.len(), 2);
    assert!(view.run_as.contains("NOT root"));
    assert!(view.notes.iter().any(|n| n.contains("DEVELOPMENT MODE")));
    assert_eq!(view.requester[0].pid, std::process::id());
}

#[test]
fn runs_in_root_by_default_and_pins_an_explicit_cwd() {
    let d = Daemon::start("delay:500");
    let r = d.run(sh("pwd -P"));
    assert_eq!(r.stdout.as_deref(), Some("/\n"));

    // Ask to run in `work`, then swap `work` for a symlink while the
    // "human" is still looking: the command must still start in the
    // directory that was shown.
    let work = d.dir.join("work");
    let other = d.dir.join("other");
    std::fs::create_dir(&work).unwrap();
    std::fs::create_dir(&other).unwrap();
    let mut req = sh("pwd -P");
    req.cwd = work.to_str().unwrap().into();
    let id = d
        .send(&ClientMsg::Submit { request: req })
        .request_id
        .unwrap();
    std::thread::sleep(Duration::from_millis(100));
    let moved = d.dir.join("work-moved");
    std::fs::rename(&work, &moved).unwrap();
    std::os::unix::fs::symlink(&other, &work).unwrap();
    let r = d.send(&ClientMsg::Wait {
        id,
        timeout_secs: Some(10),
    });
    assert_eq!(r.status, Status::Approved, "{r:?}");
    assert_eq!(r.stdout.as_deref().map(str::trim), moved.to_str());
}

#[test]
fn writable_cwd_is_flagged_and_disables_enter() {
    let d = Daemon::start("approve");
    let open_dir = d.dir.join("open");
    std::fs::create_dir(&open_dir).unwrap();
    std::fs::set_permissions(&open_dir, std::fs::Permissions::from_mode(0o777)).unwrap();
    let mut req = sh("true");
    req.cwd = open_dir.to_str().unwrap().into();
    let reply: PreviewReply = call(&d.socket, &ClientMsg::Preview { request: req }).unwrap();
    let PreviewReply::Ok { view } = reply else {
        panic!("{reply:?}")
    };
    assert!(
        view.notes.iter().any(|n| n.contains("Runs inside")),
        "{:?}",
        view.notes
    );
    assert!(!view.enter_approves);
}

#[test]
fn shebang_arguments_are_restricted() {
    let d = Daemon::start("approve");
    let r = d.run(request(Action::Script {
        path: "/x/job.pl".into(),
        content: b"#!/usr/bin/perl -Mevil\nprint 1\n".to_vec(),
        args: vec![],
    }));
    assert_eq!(r.status, Status::Error);
    assert!(r.error.unwrap().contains("Only simple flags"));
}

#[test]
fn leftover_processes_are_killed() {
    let d = Daemon::start("approve");
    let started = Instant::now();
    let r = d.run(sh("sleep 30 & echo started"));
    assert_eq!(r.stdout.as_deref(), Some("started\n"));
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "waited for the background job"
    );
}

#[test]
fn too_many_pending_requests_are_refused() {
    let d = Daemon::start("hold");
    let ids: Vec<_> = (0..3)
        .map(|i| {
            d.send(&ClientMsg::Submit {
                request: sh(&format!("echo {i}")),
            })
        })
        .collect();
    assert!(ids.iter().all(|r| r.status == Status::Pending));
    let r = d.send(&ClientMsg::Submit {
        request: sh("echo 4"),
    });
    let r = if r.status == Status::Pending {
        d.send(&ClientMsg::Wait {
            id: r.request_id.unwrap(),
            timeout_secs: Some(2),
        })
    } else {
        r
    };
    assert_eq!(r.status, Status::Error);
    assert!(r.error.unwrap().contains("already waiting"));
}

#[test]
fn install_clears_setuid_bits() {
    let d = Daemon::start("approve");
    let target_dir = d.dir.join("bin");
    std::fs::create_dir(&target_dir).unwrap();
    std::fs::set_permissions(&target_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let target = target_dir.join("tool");
    std::fs::write(&target, b"old\n").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o4755)).unwrap();
    let r = d.run(request(Action::Install {
        src: "/src/tool".into(),
        content: b"new\n".to_vec(),
        dest: target.to_str().unwrap().into(),
    }));
    assert_eq!(r.status, Status::Approved, "{r:?}");
    let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode, 0o755);
}

fn preview_view(d: &Daemon, request: Request) -> peekexec_proto::view::PromptView {
    let reply: PreviewReply = call(&d.socket, &ClientMsg::Preview { request }).unwrap();
    match reply {
        PreviewReply::Ok { view } => *view,
        other => panic!("{other:?}"),
    }
}

fn register(d: &Daemon, pid: u32) -> Response {
    d.send(&ClientMsg::Register {
        name: "Test Agent".into(),
        agent_pid: Some(pid),
        why: Some("e2e".into()),
        timeout_secs: 30,
    })
}

#[test]
fn registered_agent_requests_are_labelled() {
    use peekexec_proto::view::Provenance;
    let d = Daemon::start("approve");
    let me = std::process::id();

    assert_eq!(
        preview_view(&d, sh("true")).provenance,
        Provenance::Unregistered
    );

    let r = register(&d, me);
    assert_eq!(r.status, Status::Approved, "{r:?}");
    let session = r.session.unwrap();
    assert!(session.starts_with("s-"));
    assert_eq!(
        register(&d, me).session.as_deref(),
        Some(session.as_str()),
        "idempotent"
    );

    // The agent process itself asks: in its session, nothing in between.
    let v = preview_view(&d, sh("true"));
    assert!(
        matches!(&v.provenance, Provenance::InSession { agent, others, .. }
            if agent == "Test Agent" && others.is_empty()),
        "{:?}",
        v.provenance
    );
    assert_eq!(v.approve_delay_ms, 0);

    // A program the agent started asks (not the peekexec CLI): flagged.
    let script = format!(
        "import json,socket;s=socket.socket(socket.AF_UNIX);s.connect({:?});\
         s.sendall((json.dumps({{'op':'preview','request':json.loads({:?})}})+'\\n').encode());\
         print(s.makefile().readline())",
        d.socket.to_str().unwrap(),
        serde_json::to_string(&sh("true")).unwrap()
    );
    let out = Command::new("sh")
        .args(["-c", "python3 -c \"$0\"", &script])
        .output()
        .unwrap();
    let reply: PreviewReply =
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {out:?}"));
    let PreviewReply::Ok { view } = reply else {
        panic!("{reply:?}")
    };
    let Provenance::InSession { others, .. } = &view.provenance else {
        panic!("{:?}", view.provenance)
    };
    assert!(
        others.iter().any(|p| p.starts_with("python3")),
        "{others:?}"
    );
    assert_eq!(view.approve_delay_ms, 2000);
    assert!(!view.enter_approves);

    let r = d.send(&ClientMsg::Unregister);
    assert_eq!(r.stdout.as_deref(), Some("removed 1 agent session(s)\n"));
    assert_eq!(
        preview_view(&d, sh("true")).provenance,
        Provenance::Unregistered
    );
}

#[test]
fn denied_registration_creates_no_session() {
    let d = Daemon::start("deny:not now");
    let r = register(&d, std::process::id());
    assert_eq!(r.status, Status::Denied);
    assert!(r.session.is_none());
    let r = d.send(&ClientMsg::Register {
        name: "x".into(),
        agent_pid: Some(1),
        why: None,
        timeout_secs: 30,
    });
    assert!(
        r.error.unwrap().contains("ancestors"),
        "neither the caller nor one of its ancestors"
    );
}
