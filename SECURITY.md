# Security

peekexec is pre-alpha, and no independent expert has audited it. The
[README](README.md#what-it-wont-protect-you-from) lists what it won't protect you
from in plain words, and [THREAT_MODEL.md](THREAT_MODEL.md) goes through it in
detail.

## Reporting a vulnerability

Please report privately through GitHub's "Report a vulnerability" (private
security advisories) on the repository, not in a public issue. Include the
version or commit, your distribution and desktop, and steps to reproduce.
You should get a reply within a week. Only the latest commit on `main` is
supported until the first release.

## Scope

In scope: anything that lets a request run as root without the human having
been shown what runs, lets a non-administrator get root, lets anyone other
than the human answer the dialog where the threat model says they cannot, or
makes the dialog misrepresent a request.

Known and documented, not vulnerabilities by themselves: the X11 limits
(any program of the same user can see and drive windows), unverified Wayland
displays, `--write` being declared only, `--no-net` being best effort, files
read at runtime not being shown.

## What the installer puts on your system

`packaging/install.sh` first copies the built binaries into a root-only staging
directory, checks them there, and refuses a test build. It then installs:

- `/usr/local/bin/peekexec`, the client;
- `/usr/libexec/peekexec/peekexecd` and `peekexec-ui`, mode 0711: executable but
  not readable by users, so the copies that run as you can't be attached to;
- `peekexecd.socket` and `peekexecd.service` in `/etc/systemd/system`, with a
  drop-in that sets the socket's group to `--admin-group`;
- `/usr/share/polkit-1/actions/org.peekexec.approve.policy`, which the Wayland
  path needs (skipped if polkit is not installed);
- `/etc/pam.d/peekexec`, unless it exists already.

The daemon runs as root and starts on first use, through the socket. Only members
of the admin group can connect.

## `unsafe` inventory

The daemon and dialog are written in Rust. `unsafe` is limited to calls into C
interfaces, each with a `SAFETY:` comment:

| File | Count | What |
|---|---|---|
| `crates/peekexecd/src/platform/linux/pam.rs` | 16 | Linux-PAM FFI: `pam_start/authenticate/acct_mgmt/get_item/end/strerror`, the conversation callback (calloc/strdup contract with libpam) |
| `crates/peekexecd/src/platform/linux/peer.rs` | 5 | `SO_PEERPIDFD`, `pidfd_open`, pidfd liveness check |
| `crates/peekexecd/src/exec.rs` | 7 | `waitid(WNOWAIT)`, `killpg`, `poll` (output reader), `getxattr`/`fsetxattr`/`fremovexattr` (an installed file keeps its SELinux label and ACL) |
| `crates/peekexec-ui/src/main.rs` | 2 | `prctl(PR_SET_DUMPABLE)`, euid/egid check |
| `crates/peekexecd/src/platform/linux/mod.rs` | 2 | adopting the systemd socket (fd 3), `FD_CLOEXEC` |
| `crates/peekexecd/src/platform/linux/sandbox.rs` | 1 | `pre_exec` for approved commands: entering its cgroup, `fchdir`, `umask`, `loginuid`, `unshare(CLONE_NEWNET)` |
| `crates/peekexecd/src/spawn.rs` | 1 | `pre_exec` for every process the daemon starts: `close_range` (or `fcntl(FD_CLOEXEC)` on each descriptor before Linux 5.11), `setgroups`/`setgid`/`setuid` and the check they cannot be undone, `PR_SET_DUMPABLE` after the drop, `PR_SET_NO_NEW_PRIVS` |
| `crates/peekexecd/src/main.rs` | 1 | `prctl(PR_SET_DUMPABLE)` (no core files) |
| `crates/peekexecd/src/server.rs` | 2 | `localtime_r` (time shown on agent sessions) |
| `crates/peekexecd/src/inspect.rs` | 3 | adopting the descriptor received with `SCM_RIGHTS`; the helper adopting its socket (fd 0) and making itself non-dumpable |

## Release integrity

In place: CI runs `cargo deny check` (known vulnerabilities, yanked crates,
licences, sources; policy in `deny.toml`, including the acknowledged
"unmaintained" notices and why) and `cargo audit`.

CI builds with `--locked`, actions are pinned to commits and their tool
versions to exact releases, the workflow token is read-only, and checkouts
do not keep it.

Planned, not yet in place: reproducible builds, signed releases, an SBOM.
