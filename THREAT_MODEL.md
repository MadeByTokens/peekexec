# peekexec — threat model

## Scope

A single-seat Linux desktop where the person at the keyboard is an
administrator, and the requester is usually an AI coding agent (or a script)
running as that same user. Not designed for multi-user servers, SSH sessions,
or policy-based delegation; use sudo, doas or polkit rules there.

## What peekexec promises

**Informed consent, bound to what runs.** If the human approves, root runs the
argv, script bytes, environment, install content and target, and working
directory that were shown, with the limits reported in `enforced`.

It does not promise:

- that the approved command is safe (the human decides; flags help);
- anything about files and directories the command reads while running;
- containment: `--write` is declared only, `--no-net` is best effort;
- protection from a malicious program running as the same user on X11.

## Actors

| Actor | Trust |
|---|---|
| Human approver | Trusted. An administrator (member of `sudo`, `wheel` or `admin`) typing **their own** password; usually the same account as the requester, as with sudo. |
| Requester (agent, script) | **Untrusted.** Controls argv, file contents, env (within an allowlist), working directory, `--why`, and its own process names. May be buggy, overeager or prompt-injected; on X11 a malicious one is out of reach (see tiers). |
| Other local users | Untrusted. Turned away before their request is read. |
| `peekexecd` (root) | Trusted computing base. |
| `peekexec-ui` (the dialog) | Started by the daemon from a root-owned path with a clean environment, as the approving user with no supplementary groups; non-dumpable. Trusted to render honestly, but it runs as the user, so on X11 other programs of that user can drive it. |
| Kernel, PAM, display server | Trusted, with the display caveats below. |

## Boundaries and how each is held

1. **Who is asking.** Authorization uses only the uid from `SO_PEERCRED`,
   captured when the connection is made. Non-administrators get an error
   before the daemon reads their request. The process description in the
   dialog comes from `/proc`: the executable path is reported by the kernel,
   while names and command lines are set by the process itself and can be
   anything. The connecting process is pinned with a pidfd (Linux 6.5+), which
   proves the pid was not reused, not that the process did not exec something
   else. Ancestors are best effort. Processes whose executable is not
   root-owned are marked.
2. **Shown ↔ executed.**
   - Script and install contents travel inside the request. Scripts run from a
     root-only snapshot; the caller's file is never re-read.
   - `run` resolves argv[0] in a fixed system PATH and requires the program and
     every directory above it to be root-owned and not writable by others. A
     script's `#!` interpreter is held to the same rule, and may receive only
     simple flags (`-e`, `-eu`, `-x`...).
   - The environment is rebuilt from scratch; requests may add only allowlisted
     variables (`DEBIAN_FRONTEND`, `LANG`, `LC_*`, `TZ`...) with path-free values.
   - The working directory is `/` unless the request names one. A named
     directory is opened when the request is prepared and entered by descriptor
     (`fchdir`), so moving or replacing the path afterwards has no effect. A
     directory root does not control is flagged, because programs load code and
     settings from it (git, Python, make...).
   - Install destinations must sit in a root-owned directory chain. The file is
     written atomically (temp file and rename). Symlinks, directories and
     hard-linked targets are refused, and setuid, setgid and sticky bits are
     never carried over.
3. **Daemon → dialog.** The approval and `deny_reason` travel over pipes the
   requester cannot write to directly. An Approve click is always required
   before PAM runs, so a PAM stack that succeeds without a password still
   cannot skip the human. PAM prompts the dialog cannot answer (a username, an
   OTP code) fail closed.
4. **Dialog ↔ human (the display).** Whoever runs the display server sees every
   key typed into the dialog. So the display is never taken from the
   requester's environment when it can be verified. On X11, the daemon accepts
   only an X server that is inside the cgroup scope of the user's active local
   logind session, descends from that session's leader, runs a root-owned
   `Xorg` started for the session's VT, and is the only process meeting all
   that. Otherwise (Wayland today, or no logind) the dialog falls back to the
   user's environment and says, in the dialog and as `display_verified: false`,
   that the display is unverified.
5. **Executed command → system.** It runs as full root. The process group is
   killed when the command exits, the umask is 022, and the audit login uid is
   set to the requester. Programs that detach into their own session can
   outlive it. `enforced` reports `kernel`, `best_effort`, `builtin` (no command
   ran: peekexec wrote the file), `declared_only` or `not_requested` per limit.

## Display tiers

| Tier | Setup | Holds against |
|---|---|---|
| 1 | X11, verified X server | Buggy, overeager or prompt-injected requesters. **Not** a malicious same-user program: X11 lets any client draw fake windows, read keys, and synthesize input (including clicking Approve after reading a typed password, or forging a Deny reason). sudo and pkexec share this limit. |
| 1- | Unverified display (Wayland today) | As tier 1, and the dialog may be relayed through another display server. Flagged on every request. |
| 2 | Wayland with the password entered in the desktop's own polkit dialog | Planned (M2): the compositor-drawn prompt carries the decisive facts. |
| 3 | Dedicated VT and/or FIDO2 touch | Planned: the prompt is outside the user session; presence cannot be faked in software. |

## Things a hurried human might assume

- **The working directory's contents are not shown.** Running in a directory
  the user owns is flagged for this reason.
- **A write scope is not containment.** A udev rule, systemd unit, cron entry,
  sudoers fragment or profile script can run commands as root later; targets
  under such paths are flagged.
- **Formatted is a rendering.** Its line texts are exact slices of the
  original, but indentation and colours are hints and can mislead; Raw is the
  ground truth.
- **`--why` is the requester's claim**, shown below everything the daemon
  checked and labelled unverified.
- **Enter-to-approve** works only when there is nothing to warn about; with any
  note or marked character, approving needs a click. A dialog arriving right
  after another gets a longer input guard.
- **The one-hour refusal of a denied request** is a courtesy for well-behaved
  agents (any change makes a new request), not a control.

## Denial of service

Accepted for a single-seat desktop: an administrator's own processes can
queue requests (at most 3 pending, 16 connections) and occupy the single
dialog. Other users are rejected before sending a request. Any local user can
crash polkitd on affected versions (a polkit bug, Launchpad #1562721; see
[docs/notes/polkit-unix-session-crash.md](docs/notes/polkit-unix-session-crash.md)); this
does not affect peekexec's X11 path.

## Audit

Each request is logged to the journal with the requester's uid and pid, the
command (argv, or script/install content hash), working directory, stated
reason, outcome, exit code and any deny reason. The command's audit login uid
is the requester's.

## Out of scope

- A malicious root, kernel, or display server.
- Physical attacks on an unlocked machine.
- Judging whether an approved command is a good idea.
- Windows (UAC already provides an elevation prompt; out of scope).

## Release integrity

Planned: reproducible builds, signed releases, SBOM. The test-only approver is
a cargo feature excluded from release builds; it refuses to run as root, and
`packaging/install.sh` refuses a daemon binary that contains it.
