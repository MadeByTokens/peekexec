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
| Other local users | Untrusted. Cannot connect: the socket is mode 0660, group-owned by the administrator group (`sudo`, `wheel` or `admin`). The daemon checks membership again. |
| `peekexecd` (root) | Trusted computing base. |
| `peekexec-ui` (the dialog) | Started by the daemon from a root-owned path with a clean environment, as the approving user with no supplementary groups; non-dumpable. Trusted to render honestly, but it runs as the user, so on X11 other programs of that user can drive it. |
| Kernel, PAM, display server | Trusted, with the display caveats below. |

## Boundaries and how each is held

1. **Who is asking.** Only members of the administrator group can open the
   socket at all. Authorization uses only the uid from `SO_PEERCRED`,
   captured when the connection is made; non-administrators (should one get
   through, e.g. via a stale group membership) get an error before the
   daemon reads their request. The process description in the
   dialog comes from `/proc`: the executable path is reported by the kernel,
   while names and command lines are set by the process itself and can be
   anything. The connecting process is pinned with a pidfd (Linux 6.5+), which
   proves the pid was not reused, not that the process did not exec something
   else. Ancestors are best effort. Processes whose executable is not
   root-owned are marked. The executable path the kernel reports is the one
   the process sees, which in another mount namespace can name any file, so
   it counts only if it is the very file (device and inode) at that path in
   the daemon's view; otherwise it is marked "not the file at this path".

   **Registered agent sessions** make "is this from my agent?" checkable. The
   human approves a registration once (password, like any request); it pins
   one process (pidfd plus kernel start time, so a reused pid does not inherit
   it) and ends when that process exits. Each later request is matched
   against the kernel's ancestry of the connecting process, and the dialog
   says either "from <agent>'s session" with the chain in between, or "not
   from a registered agent session".

   *What it proves:* the request came from inside that agent's process tree.
   A process cannot make a registered agent its ancestor, so unrelated
   programs (another terminal, a background job, another agent) cannot claim
   to be it.

   *What it does not prove:* that the agent itself decided to ask. A program
   the agent started keeps its pid when it `exec`s, so it can turn itself into
   a `bash -c '…'` that looks exactly like the agent's own shell. Scripts and
   programs visible in the chain (`sh build.sh`, `make`, `python3`) are
   flagged and disable Enter, but their absence is no proof. Telling the
   agent's own requests apart needs a channel only the agent holds (the
   planned MCP transport). Nor does it prove the agent was not compromised;
   its `--why` remains a claim.
2. **Shown ↔ executed.**
   - Script and install contents travel inside the request. Scripts run from a
     root-only snapshot whose name the daemon picks (`script`, keeping a short
     alphanumeric extension), so no part of the interpreter's arguments comes
     from the requester; the caller's file is never re-read.
   - `run` resolves argv[0] in a fixed system PATH and requires the program and
     every directory above it to be root-owned and not writable by others, and
     not on a nosuid mount: removable media, disk images and FUSE mounted for
     a user are nosuid, and their files may claim any owner. A
     script's `#!` interpreter is held to the same rule, and may receive only
     flags allowlisted for that interpreter (`-e` is harmless to sh but means
     "run this code" to perl or awk).
   - What the view shows, it shows to the requester (preview) and to a dialog
     running as the user. So the current content of a file being replaced is
     shown (as a diff) only if the user could read it without root; otherwise
     the dialog says it is withheld.
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
3. **Daemon → dialog.** The approval and `deny_reason` travel over a socket
   pair the requester cannot write to directly; not pipes, because until the
   dialog makes itself non-dumpable other programs of the user may open
   `/proc/<pid>/fd/N`, and a pipe opened that way can be read later. The
   dialog inherits no other descriptors, and its stderr reaches the log
   labelled as the dialog's. An Approve click is always required
   before PAM runs, so a PAM stack that succeeds without a password still
   cannot skip the human. PAM prompts the dialog cannot answer (a username, an
   OTP code) fail closed.
4. **Dialog ↔ human (the display).** Whoever runs the display server sees every
   key typed into the dialog. So the display is never taken from the
   requester's environment when it can be verified. On X11, the daemon accepts
   only an X server that is inside the cgroup scope of the user's active local
   logind session, descends from that session's leader, runs a root-owned
   `Xorg` started for the session's VT, and is the only process meeting all
   that. Otherwise (Wayland, or no logind) peekexec's window is found through
   the user's environment and cannot be trusted (`display_verified: false`),
   so it becomes read-only: the human clicks Continue there, and the password
   goes into the desktop's own polkit prompt for the `org.peekexec.approve`
   action (admin authentication, never remembered). That prompt is drawn by
   the authentication agent registered at login (GNOME Shell itself), which a
   requester cannot reroute, and it shows a summary written by the daemon: the
   command (up to 12 lines per section, long lines wrapped rather than cut,
   and a warning at the top whenever anything is left out), where it came
   from, the working directory, the limits and every warning. The summary is
   passed so that polkit inserts it verbatim (no `$(...)` expansion). The
   subject is the requesting process (`unix-process`: pid, start time, uid).
   polkit would prefer an agent registered for that very process over the
   session's, and a process may register one for any process of its own user,
   so a requester could otherwise receive and fake the prompt itself. The
   daemon therefore first registers a *fallback* agent of its own for the
   subject: polkit allows one agent per subject, so this blocks the requester
   from registering one, while `fallback` keeps the session's agent in use.
   If the slot is already taken, peekexec refuses (tested with `pkttyagent
   --process`). A requester with no agent in its session (e.g. over ssh)
   gets an error. Residual risk: if the session's agent is not running (e.g.
   while GNOME Shell restarts), a process in that session could register a
   session agent of its own.
   Without the polkit action installed, the password falls back to the
   unverified window, flagged on every request.
5. **Executed command → system.** It runs as full root. The process group is
   killed when the command exits, the umask is 022, and the audit login uid is
   set to the requester. Programs that detach into their own session can
   outlive it. `enforced` reports `kernel`, `best_effort`, `builtin` (no command
   ran: peekexec wrote the file), `declared_only` or `not_requested` per limit.

## Display tiers

| Tier | Setup | Holds against |
|---|---|---|
| 1 | X11, verified X server | Buggy, overeager or prompt-injected requesters. **Not** a malicious same-user program: X11 lets any client draw fake windows, read keys, and synthesize input (including clicking Approve after reading a typed password, or forging a Deny reason). sudo and pkexec share this limit. |
| 1- | Unverified display, polkit action not installed | As tier 1, and the dialog may be relayed through another display server. Flagged on every request. |
| 2 | Wayland: password in the desktop's own polkit prompt | The password goes only to the compositor-drawn prompt, which other clients cannot read or drive, and which carries the decisive facts on its own. Remaining risk: a decoy window next to it showing different details; the prompt's summary is what counts, and for content longer than it can show (it says so) only the unverifiable window has the rest. |
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
dialog. Other users cannot connect. Any local user can
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
