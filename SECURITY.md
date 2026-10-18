# Security

peekexec is pre-alpha and has not been audited. Read
[THREAT_MODEL.md](THREAT_MODEL.md) for what it is meant to hold against.

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

## `unsafe` inventory

The daemon and dialog are written in Rust. `unsafe` is limited to calls into C
interfaces, each with a `SAFETY:` comment:

| File | Count | What |
|---|---|---|
| `crates/peekexecd/src/platform/linux/pam.rs` | 14 | Linux-PAM FFI: `pam_start/authenticate/acct_mgmt/end`, the conversation callback (calloc/strdup contract with libpam) |
| `crates/peekexecd/src/platform/linux/peer.rs` | 3 | `SO_PEERPIDFD`, pidfd liveness check |
| `crates/peekexecd/src/exec.rs` | 3 | `waitid(WNOWAIT)`, `killpg` |
| `crates/peekexec-ui/src/main.rs` | 3 | `prctl(PR_SET_DUMPABLE)`, euid/egid check, zeroing the password buffer |
| `crates/peekexecd/src/platform/linux/mod.rs` | 2 | adopting the systemd socket (fd 3), `FD_CLOEXEC` |
| `crates/peekexecd/src/platform/linux/sandbox.rs` | 1 | `pre_exec`: `fchdir`, `umask`, `loginuid`, `unshare(CLONE_NEWNET)` |
| `crates/peekexecd/src/prompt.rs` | 1 | `pre_exec` for the dialog: `setgroups`, `setgid`, `setuid` |

## Release integrity

In place: CI runs `cargo deny check` (known vulnerabilities, yanked crates,
licences, sources; policy in `deny.toml`, including the acknowledged
"unmaintained" notices and why) and `cargo audit`.

Planned, not yet in place: reproducible builds, signed releases, an SBOM,
pinned CI actions.
