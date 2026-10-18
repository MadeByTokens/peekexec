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
| Human approver | Trusted. Knows the password / holds the key. |
| Requester (agent, script, user) | **Untrusted.** Controls argv, files, env, `--why`. May be buggy or overeager; in higher tiers, may be malicious. |
| Other processes of the same user | Untrusted. On X11 they can see and drive any window. |
| `peekexecd` (root) | Trusted computing base. |
| `peekexec-ui` (runs as `_peekexec`) | Trusted to render and report honestly; isolated from the requester's uid. |
| Kernel, PAM, display server | Trusted, with the X11 caveat below. |

## Trust boundaries and how each is held

1. **Requester → daemon (Unix socket).** Identity comes from the kernel
   (`SO_PEERCRED`), never from the message. The process description comes from
   `/proc`. *Gap:* pid reuse between the connection and reading `/proc`;
   M1 pins the process with a pidfd (`SO_PEERPIDFD`, Linux 6.5+), and older
   kernels show a "process identity not pinned" note.
2. **Shown ↔ executed (TOCTOU).** Files are read once by the client and carried
   inline; the daemon writes the snapshot to a root-owned directory, hashes it,
   shows that, and executes that. The caller's files are never re-read.
3. **Daemon → dialog.** The dialog runs under its own uid, so the requester
   cannot ptrace it (and `ptrace_scope ≥ 1` adds a second barrier). The
   `deny_reason` and the approval travel dialog → daemon → requester; the
   requester cannot inject either.
4. **Dialog ↔ human (the display).** See tiers.
5. **Executed command → system.** Limited by the `Sandbox` backend and reported
   per run. Only `kernel` level counts as a guarantee.

## Display tiers

| Tier | Setup | Holds against |
|---|---|---|
| 1 | X11 dialog + keyboard grab | Buggy or overeager requesters. **Not** a malicious same-user process: X11 lets any client draw fake windows, read keys, and synthesize input. sudo and pkexec share this. |
| 2 | Wayland | Adds isolation: other clients cannot read the dialog's input or inject events. |
| 3 | Dedicated VT and/or FIDO2 touch (`pam_u2f`) | A compromised user session: the prompt is outside it, and physical presence cannot be faked in software. |

The dialog and `--json` output always state the tier in effect.

## Things the human might assume that are not true

- **A write scope is not containment.** `--write /etc/udev/rules.d` stops writes
  elsewhere, but a udev rule can itself run commands later. Same for
  systemd units, cron, sudoers.d, profile scripts. Risk flags call these out.
- **Formatted view is a rendering.** It is re-parsed and compared to the
  original; on mismatch the dialog falls back to Raw. Raw is the ground truth.
- **`--why` is the requester's claim.** It is labelled unverified.
- **`declared_only` is not a limit.** It means the platform could not enforce it.

## Platform notes

| | Peer identity | Auth | Write limit | Network limit | Keyboard |
|---|---|---|---|---|---|
| Linux ≥ 5.13 | SO_PEERCRED (+pidfd ≥ 6.5) | PAM | Landlock (kernel) | netns (kernel) | X11 grab / Wayland |
| Linux < 5.13 | same | PAM | declared_only | netns (kernel) | same |
| macOS | getpeereid + LOCAL_PEERPID | LocalAuthentication | sandbox-exec, best effort | sandbox-exec, best effort | SecureEventInput |

## Out of scope

- A malicious root, kernel, or display server.
- Physical attacks on an unlocked machine.
- Judging whether an approved command is a good idea (risk flags help; the
  human decides).
- Windows.

## Release integrity

Reproducible builds, minisign signatures, SBOM. The test-only approver is a
cargo feature excluded from release builds; CI verifies the release binary
does not contain it.
