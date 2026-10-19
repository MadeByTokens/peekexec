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

**Nothing without a human.** What the daemon answers without a human
(previews, refusals, errors) tells the requester nothing it could not find
out without root: no file content the user cannot read, nothing about paths
the user cannot reach. This holds by construction: before approval, every
path a request names is resolved, checked and read by a helper process with
the requesting user's credentials and `no_new_privs`, so the kernel decides
(`crates/peekexecd/src/inspect.rs`). Because the helper runs as the user,
its answer is input too: what root relies on (program, interpreter, install
directory, the directory descriptor) is checked again as root, with generic
errors, and the helper cannot be driven by other programs of the user (its
binary is not readable by them, so it is non-dumpable from exec). A request
naming a path the user cannot
reach is refused before approval; such steps go inside `peekexec script`,
where the human reads them.

It does not promise:

- that the approved command is safe (the human decides; flags help);
- anything about files and directories the command reads while running;
- containment: `--write` is declared only, `--no-net` is best effort;
- protection from a malicious program running as the same user on X11.

## Design rules

Every change is held to these. They are the classic principles of Saltzer
and Schroeder (*The Protection of Information in Computer Systems*, 1975),
stated for peekexec, with the kernel interfaces made for them. Reviews go
through [docs/review-checklist.md](docs/review-checklist.md): every input
the requester controls, against every place the daemon uses it.

1. **Before approval, the requester's authority, not root's** (least
   privilege; the confused deputy). Whatever the daemon looks at before a
   human approves, it looks at with the requesting user's credentials, in a
   helper with `no_new_privs`, so the kernel decides what may be learned.
   That includes other users' processes: the daemon reads only the
   requester's own. What the helper answers is input too: whatever root
   can recompute from the request (the program, the `#!` interpreter and
   its flag, the install target) it recomputes and compares; the rest it
   checks, with generic errors.
2. **Objects, not names** (complete mediation). Hold what was checked (a
   descriptor, an inode, a pidfd) and use that, never a path or pid looked
   up again later. Authority comes from the account, not from what the
   process carries: administrator membership and the dialog's credentials
   come from the user database, never from the caller's egid or
   environment.
3. **Requester bytes are data, never structure.** They go into one argv
   slot or one file verbatim, or are shown through one escaping function;
   they never become part of a path, a command line or a line of the
   dialog. This covers every part of an input: an environment variable's
   *name* is requester text as much as its value, and so is an install
   destination. Each part is held to a grammar (an allowlist of
   characters, not a list of bad ones), and every field of the view that
   holds requester text has a type that can only be made by escaping
   (`Shown`), so forgetting is a compile error.
4. **What is shown is complete, or says what it leaves out**, in every
   view a human may rely on: the dialog *and* the desktop's prompt.
   Everything root executes or writes (each argument, each variable, the
   target) is in a counted line, never only in a header that is cut or
   left out. Nothing the requester sends can push another fact out of
   view: line breaks are escaped, runs of blank lines, spaces or tabs are
   collapsed into a visible marker, and lists are bounded.
5. **Every process started gets an explicit allowlist** of descriptors,
   environment and credentials, and cannot gain privilege by exec
   (`no_new_privs`) unless it is the approved command. Descriptors are
   marked close-on-exec with `close_range`, or one by one up to the
   descriptor limit on a kernel without it; if that fails, the process is
   not started.
6. **Do what a careful administrator would do**: keep owners, modes and
   labels, finish, and report.
7. **Economy of mechanism.** Every feature that runs as root before
   approval must earn its place; fewer is safer.

Allowlists decide (environment, `#!` flags); denylists only warn (sensitive
paths). When a check cannot be made, the answer is no (fail-safe defaults).
A check that the human is present needs positive evidence ("this session
has a seat and is its active one"), never the absence of a warning sign
("not marked remote").

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
   - `run` looks a bare argv[0] up in a fixed system PATH (a path is used as
     given, relative to the working directory) and requires the program and
     every directory above it to be root-owned and not writable by others
     (a root-owned sticky directory such as `/tmp` may sit above it, not be
     it), and not on a nosuid mount: removable media, disk images and FUSE
     mounted for a user are nosuid, and their files may claim any owner. A
     script's `#!` interpreter is held to the same rule, and may receive only
     flags allowlisted for that interpreter (`-e` is harmless to sh but means
     "run this code" to perl or awk). An interpreter must also read the text
     as shown: a Python script or installed Python file may declare no
     source encoding but UTF-8 or ASCII (`# coding: utf-7` turns a comment
     into code) and may not contain a zip archive (which Python runs
     instead of the text).
   - What the view shows, it shows to the requester (preview) and to a dialog
     running as the user. So the current content of a file being replaced is
     shown (as a diff) only if the user could read it without root; otherwise
     the dialog says it is withheld.
   - The environment is rebuilt from scratch; requests may add only allowlisted
     variables by exact name (`DEBIAN_FRONTEND`, `LANG`, the `LC_*` locale
     categories, `TZ`...) with path-free values.
   - The working directory is `/` unless the request names one. A named
     directory is opened when the request is prepared and entered by descriptor
     (`fchdir`), so moving or replacing the path afterwards has no effect. A
     directory root does not control is flagged, because programs load code and
     settings from it (git, Python, make...).
   - Install destinations must sit in a root-owned directory chain, and their
     names may not contain control or hidden characters (nor may the
     source's name, which a file installed into a directory takes). The
     full destination is a counted line of the dialog and the desktop
     prompt, never only the cut title. The file is
     written atomically (temp file and rename). Symlinks, directories and
     hard-linked targets are refused, and setuid, setgid and sticky bits are
     never carried over.
3. **Daemon → dialog.** The approval and `deny_reason` travel over a socket
   pair the requester cannot write to directly; not pipes, because until the
   dialog makes itself non-dumpable other programs of the user may open
   `/proc/<pid>/fd/N`, and a pipe opened that way can be read later. The
   dialog inherits no other descriptors, and its stderr reaches the log
   labelled as the dialog's. An Approve click is always required
   before PAM runs, so on a verified display a PAM stack that succeeds
   without a password still cannot skip the human. On an unverified display
   the requester may be the one clicking (its own display server), so there
   the human's involvement must come from elsewhere: polkit's own prompt
   (boundary 4), which the daemon first checks would actually ask. PAM
   prompts the dialog cannot answer (a username, an OTP code) fail closed.
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
   action (the user's own password, `auth_self`, never remembered; only
   the active local session may be asked at all: `allow_any` and
   `allow_inactive` are `no`). Since the Continue click may come from a
   display the requester runs, the daemon first asks polkit without user
   interaction and refuses if it would allow with no one asked (a local
   rule granting the action, a remembered authorization). That prompt is drawn by
   the authentication agent registered at login (GNOME Shell itself), which a
   requester cannot reroute, and it shows a summary written by the daemon: the
   command (up to 12 lines per section, long lines wrapped rather than cut,
   and a warning at the top whenever anything is left out; the prompt has no
   colour or markers, so every character outside printable ASCII is written
   as `⟨U+XXXX⟩`, runs of spaces collapse into a count, and the number of
   suspicious characters comes first), where it came
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
   --process`). Because polkit asks the agent of the requester's login
   session, the requester must be in a session of the user's that has a
   seat and is that seat's active session, or in none (apps under
   `user@.service`, where polkit uses the display session). Any other
   session (ssh, `ssh localhost`, which logind counts as active and does
   not mark remote, an inactive console), whose agent the requester could
   have chosen, is refused before polkit is asked. A requester with no
   agent in its session gets an error. Residual risk: if the session's
   agent is not running (e.g. while GNOME Shell restarts), a process in
   that session could register a session agent of its own.
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
- Lying to the agent about what happened. Whatever sets the agent's
  environment or PATH (a `.envrc`, a Makefile, a prompt injection) can put
  another `peekexec` first in PATH, or name another socket in
  `PEEKEXEC_SOCKET`, and forge any answer, a `deny_reason` included. The
  second is caught: the client checks that the daemon runs as root and
  otherwise reports `dev_mode: true`. The first is not. Neither gets root:
  that still takes the human.
- Physical attacks on an unlocked machine.
- Judging whether an approved command is a good idea.
- Windows (UAC already provides an elevation prompt; out of scope).

## Release integrity

Planned: reproducible builds, signed releases, SBOM. The test-only approver is
a cargo feature excluded from release builds; it refuses to run as root, and
`packaging/install.sh` refuses a daemon binary that contains it.
