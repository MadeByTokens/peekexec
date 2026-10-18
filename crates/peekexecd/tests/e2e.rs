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
