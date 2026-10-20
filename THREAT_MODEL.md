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
naming a path the user cannot reach is refused before approval; such steps go inside `peekexec script`,
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
| Human approver | Trusted. An administrator (member of the first of `sudo`, `wheel`, `admin` that exists) typing **their own** password; usually the same account as the requester, as with sudo. |
| Requester (agent, script) | **Untrusted.** Controls argv, file contents, env (within an allowlist), working directory, `--why`, and its own process names. May be buggy, overeager or prompt-injected; on X11, one that runs programs of its own (any agent with a shell can) is out of reach: it can read the password as it is typed (see tiers). |
| Other local users | Untrusted. Cannot connect: the socket is mode 0660, group-owned by the administrator group (the first of `sudo`, `wheel`, `admin` that exists). The daemon checks membership again. |
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
     as shown: no script or installed file may declare a source encoding but
     UTF-8 or ASCII in its first two lines (`# coding: utf-7` turns a
     comment into code for Python, and a shell script can hand itself to
     Python), read from the raw bytes as Python does; no script, and no
     installed file that looks like Python, may contain a zip archive
     (which Python runs instead of the text).
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
     names may contain only printable ASCII (nor may the
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
   the authentication agent registered at login. On GNOME that is the shell
   itself, the compositor, which a requester cannot reroute; on other
   desktops it is an ordinary program of the user's, which a requester could
   end and replace with its own. So the path is used only with positive
   evidence that GNOME Shell holds it: the session's controller, as logind
   records it (the one process that took control of the session's devices,
   the compositor on Wayland), resolved to a pid by the bus daemon, is a
   `gnome-shell` of the user's from a binary root controls. A requester can
   start a shell or an agent of its own, but not take the session from the
   compositor, which cannot be replaced without ending the session. X11
   sessions have no controller, so they never take this path. The prompt
   shows a summary written by the daemon.
   The daemon's facts come first: the limits, where the request came from,
   the working directory and every warning. Then the command in full: every
   argument and every line of content, indentation kept (as a count: GNOME
   centres the text), then the environment. Nothing is cut. The prompt does
   not scroll, so the daemon lays the message out as GNOME draws it
   (measured in the VM: about 45 `x` widths per line, wrapped at spaces,
   `-` and `/`, each character counted at its widest in the Ubuntu and
   Cantarell fonts, a word wider than a line broken and marked `⟨+⟩` so it
   is not clipped) and counts every screen line. The whole message must fit
   in 22 of them, which keeps the password field on a screen 768 pixels
   tall (root can raise it with `--prompt-lines` for larger screens). A
   request that does not fit is refused on this path rather than approved
   with part of it below the screen's edge or visible only in the window
   that cannot be verified. That leaves room for a few short lines of
   script; longer work is split into steps. The prompt has
   no colour or markers, so every character outside printable ASCII is
   written as `⟨U+XXXX⟩`, runs of spaces collapse into a count, and the
   number of suspicious characters comes first. The summary is
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
   agent in its session gets an error. Residual risk: another agent that
   registered before GNOME Shell did at login (one started from the
   session's autostart) would go unnoticed (GNOME Shell then reports that
   it could not register its own), and with `ptrace_scope` 0
   (noted in the dialog) a program of the user's could take over the
   shell itself.
   Where there is no prompt that can be trusted (the polkit action is not
   installed, or the desktop is not GNOME), the request is refused before
   anything is shown: typing the password into the unverified window would
   hand it to whoever runs that display. An administrator can allow that
   anyway by starting the daemon with `--allow-unverified-display`; every
   such dialog then says the display could not be verified.
5. **Executed command → system.** It runs as full root, in a cgroup of its
   own that it enters before `exec`. When it exits, everything in that
   cgroup is killed (`cgroup.kill`, or freeze and kill on kernels before
   5.14), so processes that left its process group (`setsid`, a background
   job of a shell with job control, a double fork) end with it too, and so
   do daemons it starts itself (a FUSE mount, `dhclient`). Work handed to
   systemd (`systemd-run`, `systemctl start`) becomes a unit of systemd's
   own and is not ended. This bounds what a command leaves running by habit
   or by accident; being root, a command written to escape can move itself
   out of its group. Without a writable cgroup v2 hierarchy only the
   process group is killed, and the journal says so. Its output goes to the
   daemon, so stopping the daemon ends running commands too: `install.sh`
   waits for them before it restarts peekexecd, and a daemon that crashes
   takes them with it. The umask is 022, and the audit login uid is set to
   the requester. `enforced`
   reports `kernel`, `best_effort`, `builtin` (no command ran: peekexec
   wrote the file), `declared_only` or `not_requested` per limit.

## Display tiers

| Tier | Setup | Holds against |
|---|---|---|
| 1 | X11, verified X server | Requesters that only *ask* for the wrong thing: buggy, overeager, or talked into a bad request. **Not** a requester that runs programs of its own, and a prompt-injected agent with a shell can do exactly that: X11 lets any client draw fake windows, read keys, and synthesize input, so it can read the password as it is typed and later type it and click Approve itself (or forge a Deny reason). sudo and pkexec share this limit. |
| 1- | Unverified display and no prompt that can be trusted (no polkit action, or not GNOME) | Refused, unless root starts the daemon with `--allow-unverified-display`; then as tier 1, and the dialog may be relayed through a display server the requester runs. Flagged on every request. |
| 2 | GNOME on Wayland: password in GNOME Shell's polkit prompt | The password goes only to the compositor-drawn prompt, which other clients cannot read or drive, and which carries the decisive facts on its own. Remaining risk: a decoy window next to it showing different details; the prompt's summary is what counts, and it holds the whole request (one that does not fit is refused). |
| 3 | Dedicated VT and/or FIDO2 touch | Planned: the prompt is outside the user session; presence cannot be faked in software. |

## Things a hurried human might assume

- **The working directory's contents are not shown.** Running in a directory
  the user owns is flagged for this reason.
- **A write scope is not containment.** A udev rule, systemd unit, cron entry,
  sudoers fragment or profile script can run commands as root later, and so
  can a file put in `/usr/bin`, `/usr/lib` or `/root`; targets under such
  paths are flagged (a denylist: it warns, it does not decide).
- **Formatted is a rendering.** Its line texts are exact slices of the
  original, but indentation and colours are hints and can mislead; Raw is the
  ground truth.
- **`--why` is the requester's claim**, shown below everything the daemon
  checked and labelled unverified.
- **Enter-to-approve** works only for a plain `run` (no word of it names a
  shell, an interpreter or a program that runs another, such as `timeout`
  or `xargs`, and no argument holds spaces or shell syntax), only when there
  is nothing to warn about, and only when no
  key was pressed while the window was opening (the human was typing into
  something else, perhaps a password); otherwise approving needs a pointer
  click, which the keyboard (Tab, then Space) cannot stand in for. Scripts,
  installs and code for an interpreter (`sh -c`, `python3 -c`) always take a
  click: the warnings are a list of known dangers, and a requester can
  preview a request until nothing on the list is flagged. A dialog
  arriving right after another gets a longer input guard, and the daemon
  refuses an Approve that comes sooner than the dialog allows one.
- **The one-hour refusal of a denied request** is a courtesy for well-behaved
  agents (any change makes a new request), not a control.

## Denial of service

Accepted for a single-seat desktop: an administrator's own processes can
queue requests (at most 3 pending and 1 registration, 16 connections) and
occupy the single dialog. On an unverified display the requester may answer
the dialog itself, so its wrong passwords (3 per request) can count toward a
lockout such as pam_faillock; it could do the same with `su`. Other users
cannot connect. Any local user can crash polkitd on affected versions (a polkit bug, Launchpad #1562721; see
[docs/notes/polkit-unix-session-crash.md](docs/notes/polkit-unix-session-crash.md)); this
does not affect peekexec's X11 path.

## Audit

Each request is logged to the journal with the requester's uid and pid, the
command (argv, or script/install content hash), working directory, stated
reason, outcome, exit code and any deny reason. An approved one is logged
twice: before the command starts (so a command that ends the daemon or the
machine is still on record) and when it ends. Requester strings are quoted
in plain ASCII and each is cut at 512 bytes (32 arguments at most; the
request's sha256 identifies the rest), so no line reaches journald's
`LineMax` and is split into records that begin with requester text, and
the unit has no log rate limit, so a flood of refused requests cannot
crowd out the record of an approved one. The command's audit
login uid is the requester's.

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
