# How peekexec works

A short tour, from the idea down to the code, for anyone (person or agent)
who wants to know what makes peekexec tick: what happens to a request, why
each step is there, and what was knowingly left open. It explains and points;
the details live in the documents and code it links, so you can check every
claim and go further. Code is named by file and function, never by line.

## The idea in one paragraph

An AI agent sometimes needs root for a step: reload udev rules, flash a
board, fix a disk. sudo asks for the password in a terminal, which an
agent's tool calls usually do not have, and pkexec's prompt tells you
little: before polkit 123 it names only the
program ("run /bin/sh as the super user"), and since then a command line cut
in the middle past about 80 characters
([pkexec, read against peekexec](notes/pkexec-comparison.md), with links
to polkit's source). peekexec puts a root daemon between the agent and root.
The agent sends a request; a human sees exactly what would run, who asked,
and why, and approves with their own password, cancels, or denies with a
reason the agent gets back. Its one promise: **what is shown is what runs,
and nothing runs without a human**
([What peekexec promises](../THREAT_MODEL.md#what-peekexec-promises)).
It does not promise that the command is a good idea; that is the human's
call.

## The pieces, and who each runs as

```
agent ─▶ peekexec (CLI, as the user)
           │  Unix socket /run/peekexec/peekexec.sock (0660, admin group)
           ▼
         peekexecd (daemon, root, started by systemd on first connection)
           ├─ inspection helper   peekexecd --inspect-helper, as the user, no_new_privs
           ├─ dialog              peekexec-ui, as the user, non-dumpable; where the display
           │                      is unverified (Wayland) it only shows, and the password
           │                      goes to GNOME Shell's prompt, or the request is refused
           ├─ PAM / polkit        checks the human's own password
           └─ the command         as root, in a cgroup of its own; output back to the agent
```

- **Requester:** whatever calls [`peekexec`](../crates/peekexec/src/main.rs),
  usually an agent. Untrusted: it may be buggy, overeager or
  prompt-injected, and it may lie in `--why`
  ([Actors](../THREAT_MODEL.md#actors)).
- **Daemon:** [`peekexecd`](../crates/peekexecd/src/server.rs), the only
  part that is root before approval, started through
  [its socket unit](../packaging/systemd/peekexecd.socket). Everything it
  shows and runs is built in one place from the same values.
- **Inspection helper:** the daemon's own binary
  ([`inspect.rs`](../crates/peekexecd/src/inspect.rs)), run as the
  requesting user with
  [`no_new_privs`](https://man7.org/linux/man-pages/man2/PR_SET_NO_NEW_PRIVS.2const.html),
  so before approval the kernel decides what may be learned about the
  filesystem.
- **Dialog:** [`peekexec-ui`](../crates/peekexec-ui/src/main.rs), a normal
  window (no keyboard grab) that renders what the daemon sends; it decides
  nothing.

## The life of one request

The code is `Daemon::process` in
[`server.rs`](../crates/peekexecd/src/server.rs) and the functions it calls;
the file's own summary is identify → prepare → ask → execute → report.

1. **Identify.** The client connects. The daemon takes the uid from the
   kernel ([`SO_PEERCRED`](https://man7.org/linux/man-pages/man7/unix.7.html))
   and pins the process with a
   [pidfd](https://man7.org/linux/man-pages/man2/pidfd_open.2.html), taken
   from the socket (`SO_PEERPIDFD`) on Linux 6.5 and later
   ([`peer.rs`](../crates/peekexecd/src/platform/linux/peer.rs)). Only
   members of the administrator group chosen at install may connect, and
   membership is checked again from the user database. The process chain
   shown later is read from `/proc`; the names in it are claims.
   Details: [Boundaries, 1](../THREAT_MODEL.md#boundaries-and-how-each-is-held).
2. **Queue.** Each request gets an id and a worker (`Daemon::start`); a
   user may have only a few waiting at once. A request identical to one
   denied in the last hour gets the denial again, only if it comes from the
   same requester, a courtesy to agents and not a control. The request's sha256 covers everything that determines
   what runs, but not `--why` or the timeout (`Request::digest` in
   [`request.rs`](../crates/peekexec-core/src/request.rs)).
3. **Find the display.** The daemon looks for the X server of the user's
   active local session from sources the requester cannot set
   ([`session.rs`](../crates/peekexecd/src/session.rs),
   [`display.rs`](../crates/peekexecd/src/platform/linux/display.rs)).
   Anything it cannot verify counts as unverified.
   Details: [X11: verified, then the dialog takes the password](../THREAT_MODEL.md#x11-verified-then-the-dialog-takes-the-password).
4. **Look, as the user.** `prepare` in
   [`prepare.rs`](../crates/peekexecd/src/prepare.rs) asks the inspection
   helper (`inspect_as`) to resolve the program, the script's interpreter,
   the working directory and the install target, and to look at the paths
   the request names (every word of the arguments; in script text, absolute,
   `./` and `../` paths; up to a bound, past which a note says so; a glob or
   a name computed in a script is not seen), using the kernel's
   [`access`](https://man7.org/linux/man-pages/man2/access.2.html) as the
   user. The helper's answer is input too, so root checks it (`verify`):
   what root can recompute, it recomputes and compares. What the helper
   finds becomes notes: a path programs of the user's could change after
   approval ([`trust.rs`](../crates/peekexecd/src/trust.rs)), a file the
   user cannot read (its content would come back to the agent), a disk and
   what is on it ([`blockdev.rs`](../crates/peekexecd/src/blockdev.rs)).
   Details: [Things a hurried human might assume](../THREAT_MODEL.md#things-a-hurried-human-might-assume).
5. **Build the view and the execution together.** From the same resolved
   values, `prepare` builds the `PromptView` the human sees
   ([`view.rs`](../crates/peekexec-proto/src/view.rs)) and the `Execution`
   that runs, so the two cannot disagree. A script is copied into a
   root-only snapshot whose name the daemon picks; the caller's file is
   never read again. Details: [Boundaries, 2](../THREAT_MODEL.md#boundaries-and-how-each-is-held).
6. **Choose how the human approves** (`Daemon::choose_approval`). On a
   verified X server, the password goes into peekexec's dialog. Otherwise
   (Wayland, or an X server it cannot verify), only GNOME Shell's own polkit
   prompt can be trusted with it: the daemon checks that the polkit action
   is installed, that the request comes from the active local session (or
   from no session, as apps started under `user@.service` do, where polkit
   uses the display session), and that the prompt is drawn by a
   root-controlled GNOME Shell
   ([`polkit.rs`](../crates/peekexecd/src/platform/linux/polkit.rs)), and
   that its summary of the whole request fits on screen. With no prompt
   that can be trusted, the request is refused before anything is shown.
   Details: [Anything else: the window is read-only](../THREAT_MODEL.md#anything-else-the-window-is-read-only),
   [What the prompt says](../THREAT_MODEL.md#what-the-prompt-says).

   `peekexec preview` runs steps 1 and 3 to 6 (no queue, no snapshot
   written) and prints the resulting view. The notes of step 7 are added only when a
   dialog really opens, and can still turn Enter off.
7. **Ask, one dialog at a time.** A lock keeps one dialog on screen. Just
   before it opens, the daemon adds what only it knows: the request arrived
   right after another, others are waiting, or it is a near-copy of one just
   seen (with the differences). On a verified display it checks again that
   the display did not change while the request waited. Then `ask` in
   [`prompt.rs`](../crates/peekexecd/src/prompt.rs) starts the dialog as the
   user and talks to it over a socket pair. On the password path the human
   types their own password and
   [`pam.rs`](../crates/peekexecd/src/platform/linux/pam.rs) checks it. On
   the GNOME path, after the human clicks Continue, the daemon first asks
   polkit without user interaction and refuses if polkit would allow it
   with no one asked; otherwise GNOME's prompt asks for the password.
   Details: [Boundaries, 3](../THREAT_MODEL.md#boundaries-and-how-each-is-held),
   [Keeping the prompt on the right agent](../THREAT_MODEL.md#keeping-the-prompt-on-the-right-agent).
8. **Run.** An audit line is written before the command starts. Just before
   running, root checks again that the program (or install directory) is
   root-controlled and that every disk name still leads to the disk that was
   shown (`ready_to_run` in [`server.rs`](../crates/peekexecd/src/server.rs)).
   The command runs as root with an environment rebuilt from an allowlist
   (`command_env` in [`prepare.rs`](../crates/peekexecd/src/prepare.rs)),
   inherited descriptors closed on exec
   ([`close_range`](https://man7.org/linux/man-pages/man2/close_range.2.html),
   [`spawn.rs`](../crates/peekexecd/src/spawn.rs)), umask 022, the working
   directory entered by the descriptor held since step 4
   ([`fchdir`](https://man7.org/linux/man-pages/man2/fchdir.2.html)), and,
   where the daemon can make one, a cgroup of its own entered before exec
   ([`sandbox.rs`](../crates/peekexecd/src/platform/linux/sandbox.rs),
   [`cgroup.rs`](../crates/peekexecd/src/platform/linux/cgroup.rs)).
   Whether it can make one is found before approval, by making one and
   removing it; where it cannot, the dialog said so, and where the dialog
   did not say so and none can be made when the command starts, the command
   does not run. An install writes the file
   itself, atomically, with no command at all
   ([`exec.rs`](../crates/peekexecd/src/exec.rs)).
   Details: [Boundaries, 5](../THREAT_MODEL.md#boundaries-and-how-each-is-held).
9. **Report.** When the command ends, its process group is killed, and
   everything left in its cgroup too, where it has one
   ([`cgroup.kill`](https://docs.kernel.org/admin-guide/cgroup-v2.html)). Its exit code, stdout and
   stderr go back to the agent with what was enforced. The snapshot is
   removed, and a second audit line records the outcome.
   Details: [Audit](../THREAT_MODEL.md#audit).

## Decisions, and what each costs

| Decision | Why | Cost | Details |
|---|---|---|---|
| A root daemon, not a setuid program | A setuid program starts inside a process the caller prepared (its arguments, environment, limits); pkexec's worst bug came from there | A service to install and keep running; stopping it ends running commands | [pkexec comparison](notes/pkexec-comparison.md#step-by-step) |
| Look before approval as the user, not as root | Root would answer questions about files the agent cannot read; the helper lets the kernel decide | A helper process per request, and its answer has to be checked | [Rule 1](../THREAT_MODEL.md#design-rules), [`inspect.rs`](../crates/peekexecd/src/inspect.rs) |
| View and execution from the same values | Two code paths can drift; one cannot | All of a request's logic lives in one large module | [`prepare.rs`](../crates/peekexecd/src/prepare.rs) |
| Hold objects, not names | A path checked and later used again can point elsewhere by then | Descriptors and re-checks: the working directory is a descriptor; programs and disks are checked again just before running | [Rule 2](../THREAT_MODEL.md#design-rules) |
| Run only root-controlled programs (a bare name is looked up only in a fixed PATH); scripts from a snapshot | A file the user can change could be swapped after approval | Your own tools go through `peekexec script` or `install`, not `run` | [Boundaries, 2](../THREAT_MODEL.md#boundaries-and-how-each-is-held), [`trust.rs`](../crates/peekexecd/src/trust.rs) |
| Allowlists decide, denylists only warn | No list of dangerous things is complete | Some harmless variables, flags and programs are refused or take a click | [Design rules](../THREAT_MODEL.md#design-rules) |
| Enter approves only simple reads and a few everyday reloads, from an allowlist | Typing aimed at another window must not approve anything more | Most requests need a click | [Enter-to-approve](../THREAT_MODEL.md#things-a-hurried-human-might-assume) |
| No keyboard grab | A grab trapped the human: after an Alt-Tab, a dialog behind other windows could hold the whole keyboard; on X11 it only stopped ordinary key snooping anyway | The dialog is a normal window others can cover | [The commit that removed it](https://github.com/MadeByTokens/peekexec/commit/1ab7be07f12bd6c1b94d0a058e11934450d3db0f) |
| Password in peekexec's dialog only on a verified X server; otherwise GNOME's prompt, or refuse | Whoever runs the display reads every key typed into it | Unverified displays without GNOME's prompt (other Wayland desktops, an unverified X server) are refused unless an administrator allows the unverified window | [The display in detail](../THREAT_MODEL.md#the-display-in-detail) |
| Approval never remembered | Each request is a decision about that request | A password for every request | Password path: PAM asked in each dialog (`Approver::verify` in [`prompt.rs`](../crates/peekexecd/src/prompt.rs)); GNOME path: [the polkit action](../packaging/polkit/org.peekexec.approve.policy) is `auth_self`, and [a remembered authorization is refused](../THREAT_MODEL.md#anything-else-the-window-is-read-only) |
| Output goes back to the agent | The agent needs it to do its job | Reading what you could not read yourself hands it to the agent, so such reads need a click | [Hurried human](../THREAT_MODEL.md#things-a-hurried-human-might-assume) |
| Disks described, bound, and re-checked | The classic hardware mistake is the right command on the wrong disk | Naming any disk takes a click | [`blockdev.rs`](../crates/peekexecd/src/blockdev.rs) |
| A cgroup per command, killed at the end | Commands should not leave things running as root by habit | Work handed to systemd (`systemd-run`, `systemctl start`) is not ended; where the daemon cannot make a cgroup, only the process group is, and the dialog says so | [Boundaries, 5](../THREAT_MODEL.md#boundaries-and-how-each-is-held) |
| Economy of mechanism | Every feature that runs as root before approval is attack surface | Some conveniences were left out on purpose | [Rule 7](../THREAT_MODEL.md#design-rules) |

The design rules are the classic principles of Saltzer and Schroeder,
[*The Protection of Information in Computer Systems*](https://www.cs.virginia.edu/~evans/cs551/saltzer/)
(1975), stated for peekexec in [THREAT_MODEL.md](../THREAT_MODEL.md#design-rules).
Reviews hold every requester input against every use, in
[review-checklist.md](review-checklist.md).

## What the human sees, and when Enter works

The dialog shows the daemon's own facts (limits, where the request came
from, the working directory, every warning), the command or content with
hidden characters made visible
([`textcheck.rs`](../crates/peekexec-core/src/textcheck.rs)), and the
agent's reason, shown below everything the daemon checked and marked
unverified. Requester text can never push the daemon's facts out of view
(design rule 4). Every one-line field that holds requester text has a type
that can only be made by escaping it (`Shown` in
[`view.rs`](../crates/peekexec-proto/src/view.rs), design rule 3); script
and file content is shown as it is, with hidden characters marked.

Enter approves only a single `run` of a read-only program or one of a few
everyday reloads (`udevadm control --reload-rules`, `systemctl
daemon-reload`...), short and plain, with nothing to warn about, no walk
below what it names, and only if nobody was typing as the window opened.
The exact rule is in `man peekexec` ("ENTER OR CLICK", from
[`manual.md`](../crates/peekexec/src/manual.md)), in
[THREAT_MODEL.md](../THREAT_MODEL.md#things-a-hurried-human-might-assume),
and in the code (`plain_run` in
[`prepare.rs`](../crates/peekexecd/src/prepare.rs)). `preview` says whether
Enter applies as prepared; the notes added when the dialog opens can still
turn it off.

## What we accepted

Some limits come with the idea itself, some wait on planned work, and some
were judged not worth the mechanism. The full list is in
[Known limits](../THREAT_MODEL.md#known-limits).

**With the idea itself:**

- **A same-user program on X11.** Any X11 client can read keys and click
  for you, so an agent that runs programs of its own can read the password
  as it is typed. sudo and pkexec share this. GNOME's prompt on Wayland is
  not exposed that way, unless something was planted in `$HOME` before the
  login (a GNOME Shell extension runs inside the process that draws it)
  ([Display tiers](../THREAT_MODEL.md#display-tiers),
  [What that evidence does not prove](../THREAT_MODEL.md#what-that-evidence-does-not-prove)).
- **The account's own groups.** `docker`, `lxd`, `incus-admin`, `libvirt`
  and `disk` give root without peekexec; `input` reads the password. What to
  check, with sources, is in the README, under
  [Your account's groups](../README.md#your-accounts-groups).
- **What the agent is told.** Whatever sets the agent's PATH can put a fake
  `peekexec` first and forge any answer. It cannot get root that way
  ([Out of scope](../THREAT_MODEL.md#out-of-scope)).
- **The command itself.** peekexec makes sure you see what runs, not that
  it is wise. An approved command is full root.

**Waiting on planned work** ([PLAN.md](../PLAN.md)):

- **Containment.** `--write` is declared, not enforced, and `--no-net` is
  best effort, until commands run as transient systemd units.
- **A prompt outside the user's session** (a console or a FIDO2 touch), the
  real answer to the display problem.

**Left as they are, for now** (details in
[the follow-ups](notes/sixth-review-followups.md#known-limits-left-as-they-are)):

- Descriptions and notes come from the helper and are not re-checked by
  root; root re-checks only what it acts on.
- A disk named by a computation in a script, or by a glob, is not
  described; "in use" cannot see a VM's open disk or a ZFS member.
- Your own processes can fill the queue
  ([Denial of service](../THREAT_MODEL.md#denial-of-service)).
- Nobody outside the project has reviewed it yet.

## The code, by crate

| Crate / module | What it does |
|---|---|
| [`peekexec-core`](../crates/peekexec-core/src/lib.rs) | What a request is, its hash ([`request.rs`](../crates/peekexec-core/src/request.rs)), text checks for hidden characters ([`textcheck.rs`](../crates/peekexec-core/src/textcheck.rs)), display-only formatting ([`format.rs`](../crates/peekexec-core/src/format.rs)). No OS code |
| [`peekexec-proto`](../crates/peekexec-proto/src/lib.rs) | Messages between client, daemon and dialog; `PromptView`, the prompt as data ([`view.rs`](../crates/peekexec-proto/src/view.rs)) |
| [`peekexec`](../crates/peekexec/src/main.rs) | The CLI, `peekexec help agents` ([`help.rs`](../crates/peekexec/src/help.rs)), the man page source ([`manual.md`](../crates/peekexec/src/manual.md)) |
| [`peekexec-ui`](../crates/peekexec-ui/src/main.rs) | The dialog (egui) |
| [`server.rs`](../crates/peekexecd/src/server.rs) | Connections, the request table, the life of a request |
| [`inspect.rs`](../crates/peekexecd/src/inspect.rs) | The inspection helper and root's `verify` |
| [`prepare.rs`](../crates/peekexecd/src/prepare.rs) | Request → view + execution; notes; the Enter rule; the command's environment |
| [`trust.rs`](../crates/peekexecd/src/trust.rs) | Which files root may run or write into |
| [`blockdev.rs`](../crates/peekexecd/src/blockdev.rs) | Describing and binding disks |
| [`prompt.rs`](../crates/peekexecd/src/prompt.rs) | Showing the dialog and turning the answer into a decision |
| [`session.rs`](../crates/peekexecd/src/session.rs), [`sessions.rs`](../crates/peekexecd/src/sessions.rs) | Choosing the display; registered agent sessions |
| [`exec.rs`](../crates/peekexecd/src/exec.rs), [`spawn.rs`](../crates/peekexecd/src/spawn.rs) | Running an approved execution; starting any process with an explicit allowlist |
| [`platform/linux/`](../crates/peekexecd/src/platform/linux/mod.rs) | Peer credentials ([`peer.rs`](../crates/peekexecd/src/platform/linux/peer.rs)), PAM ([`pam.rs`](../crates/peekexecd/src/platform/linux/pam.rs)), polkit ([`polkit.rs`](../crates/peekexecd/src/platform/linux/polkit.rs)), the X server check ([`display.rs`](../crates/peekexecd/src/platform/linux/display.rs)), the command's sandbox: working directory, umask, cgroup, `--no-net` ([`sandbox.rs`](../crates/peekexecd/src/platform/linux/sandbox.rs), [`cgroup.rs`](../crates/peekexecd/src/platform/linux/cgroup.rs)) |

## References

Outside sources for the mechanisms this tour relies on:

- Linux man pages: [`unix(7)`](https://man7.org/linux/man-pages/man7/unix.7.html)
  (`SO_PEERCRED`), [`pidfd_open(2)`](https://man7.org/linux/man-pages/man2/pidfd_open.2.html),
  [`PR_SET_NO_NEW_PRIVS`](https://man7.org/linux/man-pages/man2/PR_SET_NO_NEW_PRIVS.2const.html),
  [`access(2)`](https://man7.org/linux/man-pages/man2/access.2.html),
  [`close_range(2)`](https://man7.org/linux/man-pages/man2/close_range.2.html),
  [`fchdir(2)`](https://man7.org/linux/man-pages/man2/fchdir.2.html).
- The kernel's [cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)
  (`cgroup.kill`).
- [polkit(8)](https://www.freedesktop.org/software/polkit/docs/latest/polkit.8.html),
  and polkit's source, read in [the pkexec comparison](notes/pkexec-comparison.md).
- Saltzer and Schroeder, [*The Protection of Information in Computer Systems*](https://www.cs.virginia.edu/~evans/cs551/saltzer/), 1975.
- The sources for what each group grants are quoted in the README, under
  [Your account's groups](../README.md#your-accounts-groups).

## Where to go next

| If you want | Read |
|---|---|
| To use it | [README](../README.md), then `man peekexec` |
| To call it from an agent | `peekexec help agents` ([source](../crates/peekexec/src/help.rs)) |
| Every option and the JSON | [cli.md](cli.md) |
| What holds against whom, in detail | [THREAT_MODEL.md](../THREAT_MODEL.md) |
| How reviews are done | [review-checklist.md](review-checklist.md) |
| How it compares with pkexec, line by line | [pkexec-comparison.md](notes/pkexec-comparison.md) |
| What is installed, `unsafe` code, reporting a bug | [SECURITY.md](../SECURITY.md) |
| What is planned | [PLAN.md](../PLAN.md) |
