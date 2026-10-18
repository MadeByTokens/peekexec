# peekexec — threat model

## What peekexec promises

**Informed consent, bound to execution.** If the human approves, root runs
exactly the bytes and settings that were shown, nothing else, and within the
limits reported in `enforced`.

It does **not** promise the approved command is safe. A human can approve
something harmful; peekexec makes sure they could see it first.

## Actors

| Actor | Trust |
|---|---|
| Human approver | Trusted. An administrator (member of `sudo`, `wheel` or `admin`) who knows their password. |
| Requester (agent, script, user) | **Untrusted.** Controls argv, files, env, `--why`. May be buggy or overeager; in higher tiers, may be malicious. |
| Other processes of the same user | Untrusted. On X11 they can see and drive any window. |
| `peekexecd` (root) | Trusted computing base. |
| `peekexec-ui` (the dialog) | Trusted to render and report honestly. Started by the daemon (never by the requester) from a root-owned path, with a clean environment, as the approving user; it marks itself non-dumpable, so other processes of that user cannot ptrace it or read its memory. A dedicated system user is planned. |
| Kernel, PAM, display server | Trusted, with the X11 caveat below. |

## Trust boundaries and how each is held

1. **Requester → daemon (Unix socket).** Identity comes from the kernel
   (`SO_PEERCRED`), never from the message. The process description comes from
   `/proc`, and the process is pinned with a pidfd (`SO_PEERPIDFD`, Linux 6.5+)
   so a reused pid cannot be described instead. On older kernels the dialog
   says the identity is not pinned. Ancestors (parent, grandparent) are
   described best-effort.
2. **Shown ↔ executed (TOCTOU).** Everything that executes is fixed before it
   is shown:
   - Script and install contents travel inside the request; the daemon writes
     scripts to a root-only snapshot directory and runs that copy. The caller's
     files are never re-read.
   - `run` resolves argv[0] in a fixed system PATH (never the caller's) and
     requires the program and every directory above it to be root-owned and not
     writable by others, so it cannot be swapped after approval. A script's
     `#!` interpreter is held to the same rule.
   - The environment is rebuilt from scratch. Requests may only add variables
     from a short allowlist (`DEBIAN_FRONTEND`, `LANG`, `LC_*`, `TZ`, `TERM`,
     ...) with path-free values, because the set of variables that make some
     program load unseen code (`LD_*`, `PATH`, `PYTHONPATH`, `GIT_CONFIG_*`,
     `PAGER`, ...) is open-ended.
   - Install destinations must sit in a root-owned directory chain; the file is
     written atomically (temp file + rename) and an existing symlink, directory
     or hard-linked target is refused.
3. **Daemon → dialog.** The approval and the `deny_reason` travel
   dialog → daemon → requester over pipes the requester cannot reach. An Approve
   click is always required before PAM runs, so a PAM stack that succeeds
   without a password still cannot skip the human.
4. **Dialog ↔ human (the display).** Whoever runs the display server sees
   every key typed into the dialog. A requester that could choose the display
   could run a nested server (Xephyr, nested weston) on the real screen, show
   the genuine dialog inside it, and capture the password. So the display is
   never taken from the requester's environment when it can be verified: on
   Linux the daemon picks the X server running inside the cgroup scope of the
   user's active local logind session (root-owned; user processes cannot move
   into it), requires a root-owned `Xorg`/`Xwayland` binary, reads the display
   number from the socket that process listens on, and the cookie path from
   its own `-auth` argument. When that is impossible (Wayland compositors,
   systems without logind), the dialog falls back to the user's environment
   and says, in the dialog and as `display_verified: false`, that the display
   is unverified. See also the tiers below.
5. **Executed command → system.** Limited by the `Sandbox` backend and reported
   per run. Only `kernel` (and `builtin` for installs) count as guarantees.

## Display tiers

| Tier | Setup | Holds against |
|---|---|---|
| 1 | X11 dialog + keyboard grab | Buggy or overeager requesters. **Not** a malicious same-user process: X11 lets any client draw fake windows, poll the keyboard state and synthesize input. The keyboard grab stops ordinary key snooping only. sudo and pkexec share this limit. |
| 2 | Wayland, compositor verified | Adds isolation: other clients cannot read the dialog's input or inject events. Compositor verification is not implemented yet, so Wayland is currently reported as unverified. |
| 3 | Dedicated VT and/or FIDO2 touch (`pam_u2f`) | A compromised user session: the prompt is outside it, and physical presence cannot be faked in software. (planned) |

The dialog and `--json` output (`display_tier`, `display_verified`) always
state the tier in effect.

## Things the human might assume that are not true

- **Files read while the command runs are not shown.** `sh -c 'cp ./x /etc/'`
  shows the command, not the contents of `./x`, which the requester can change
  after approval. `peekexec install` exists for this; agents are told so in
  `peekexec help agents`. (A risk flag for it is planned.)
- **A write scope is not containment.** `--write /etc/udev/rules.d` stops writes
  elsewhere, but a udev rule can itself run commands later. Same for
  systemd units, cron, sudoers.d, profile scripts. (Risk flags planned.)
- **Formatted view is a rendering.** Its lines are exact slices of the original
  (checked in code; it falls back to one line per original line otherwise),
  but only Raw is the ground truth.
- **`--why` is the requester's claim.** It is labelled unverified.
- **`declared_only` is not a limit.** In M1, `--write` is declared only (Landlock
  arrives in M2); `--no-net` is kernel-enforced when running as root.

## Platform notes

| | Peer identity | Auth | Write limit | Network limit | Keyboard |
|---|---|---|---|---|---|
| Linux ≥ 6.5 | SO_PEERCRED + pidfd | PAM | declared_only (Landlock: M2) | netns (kernel) | X11 grab / Wayland |
| Linux < 6.5 | SO_PEERCRED, not pinned | PAM | same | netns (kernel) | same |
| macOS (M4) | getpeereid + LOCAL_PEERPID | LocalAuthentication | sandbox-exec, best effort | sandbox-exec, best effort | SecureEventInput |

## Development mode

`peekexecd --dev` runs the whole flow as the current user: nothing runs as root,
and files owned by that user are trusted in addition to root's. The dialog,
`preview` and every response say so (`dev_mode: true`).

## Out of scope

- A malicious root, kernel, or display server.
- Physical attacks on an unlocked machine.
- Judging whether an approved command is a good idea (risk flags help; the
  human decides).
- Windows.

## Release integrity

Reproducible builds, minisign signatures, SBOM. The test-only approver is a
cargo feature excluded from release builds; it refuses to run as root, and
`packaging/install.sh` refuses a daemon binary that contains it.
