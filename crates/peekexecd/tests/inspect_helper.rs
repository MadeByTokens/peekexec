//! The inspection helper as a real process: the answer and the working
//! directory's descriptor come back over its socket, errors come back as
//! errors, and it runs with `no_new_privs`.

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use peekexec_core::{Action, Request};
use peekexecd::inspect::{inspect_as, Facts};

const HELPER: &str = env!("CARGO_BIN_EXE_peekexecd");

fn request(cwd: &str) -> Request {
    Request {
        action: Action::Run {
            argv: vec!["true".into()],
        },
        why: None,
        write: None,
        no_net: false,
        env: BTreeMap::new(),
        cwd: cwd.into(),
        timeout_secs: 30,
    }
}

fn owners() -> Vec<u32> {
    vec![0, nix::unistd::geteuid().as_raw()]
}

#[test]
fn helper_returns_facts_and_the_directory_descriptor() {
    let (inspection, fd) =
        inspect_as(Path::new(HELPER), None, &request("/usr"), &owners()).unwrap();
    assert_eq!(inspection.cwd, "/usr");
    let Facts::Run { program, .. } = inspection.facts else {
        panic!("{:?}", inspection.facts)
    };
    assert!(program.ends_with("/true"), "{program}");
    // The descriptor is that very directory.
    let held = std::fs::metadata(format!("/proc/self/fd/{}", fd.as_raw_fd())).unwrap();
    let usr = std::fs::metadata("/usr").unwrap();
    assert_eq!((held.dev(), held.ino()), (usr.dev(), usr.ino()));
}

#[test]
fn helper_errors_come_back_as_errors() {
    let err = inspect_as(
        Path::new(HELPER),
        None,
        &request("/no/such/directory"),
        &owners(),
    )
    .unwrap_err();
    assert!(err.contains("/no/such/directory"), "{err}");
}

#[test]
fn helper_runs_with_no_new_privs() {
    let dir = std::env::temp_dir().join(format!("pe-nnp-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let report = dir.join("status");
    let wrapper = dir.join("helper");
    std::fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\ngrep NoNewPrivs /proc/self/status > {}\nexec {HELPER} \"$@\"\n",
            report.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
    inspect_as(&wrapper, None, &request("/"), &owners()).unwrap();
    let status = std::fs::read_to_string(&report).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(status.split_whitespace().last(), Some("1"), "{status}");
}
