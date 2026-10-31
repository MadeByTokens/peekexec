# Review checklist: requester inputs × daemon uses

Reviews check every cell against the [design rules](../THREAT_MODEL.md#design-rules)
(R1–R7). A new feature adds rows (new inputs) or columns (new uses); a cell
nobody has filled in is where the next hole is. A row is one *part* of an
input: a name and its value are two rows, because both are requester text.

Columns, the places the daemon uses an input:

- **Pre** — looked at before approval (validation, inspection)
- **Ans** — in an answer without a human (preview, error, `wait`)
- **Dialog** — in peekexec's own window
- **Prompt** — in the desktop's polkit prompt (Wayland), the only view on
  that path that a decoy window cannot replace; it must carry every fact
  on its own (R4)
- **Run** — what root executes or writes
- **Log** — the journal

Status: ✓ held (how) · ⚠ open (planned fix) · — not used there.

## Request fields

| Input | Pre | Ans | Dialog | Prompt | Run | Log |
|---|---|---|---|---|---|---|
| `argv` | R3: NUL refused. A bare argv[0] is looked up in SAFE_PATH, one with a `/` is taken relative to cwd; either way a root-owned chain, not nosuid; args that name a path (also `--opt=/p`, `-f/p`, `-Cdir`, `/a:/b`, `host:/p`, `file:///p`, `@/p`; not the program's own `/dev/std*`, `/dev/fd/N`, `/proc/self/fd/N` or `/proc/self/<status file>`, but `/proc/self/root/...` and `cwd/...` are checked), and every absolute or `./` word inside an argument that is code (`sh -c 'dpkg -i /home/u/x.deb'`), get the "root does not control" note when any existing prefix of the path as written (symlinks, directories, a file not created yet) is not root-controlled; all as the user, in the helper (✓ R1) | errors are what the user could learn (✓ R1) | R3: one line per argument, controls escaped; after `sh -c SCRIPT`, each further argument is an `argv[i]` invocation line, in full (✓) | shell-quoted, wrapped, never cut; invocation lines counted with the content (✓) | R2: program by a canonical path whose every component only root can change (root-owned, not writable by others, not nosuid; checked by the helper and again by root), so the name is as good as the object (✓) | Debug-quoted (✓) |
| script `content` | R3: `#!` interpreter resolved and trusted, flags allowlisted per interpreter; every absolute or `./` word of the text gets the argv path note (at most 1000 paths checked, more is a note too); content must decode as shown: no coding cookie but UTF-8/ASCII in lines 1-2 of any script or installed file (raw bytes, as CPython reads it), no zip archive in any script or in an installed Python-looking file (✓) | — | Full text, findings marked (bytes that are not UTF-8 show as `⟨invalid⟩` and disable Enter: it says what it cannot show); runs of blank lines, and of spaces or tabs, collapse into a visible marker; a newline inside a word (`$(...)`, quotes) ends a line like any other, and the highlighter draws a line uncoloured unless its spans are exactly the text (✓) | every line, indentation as a count, after the daemon's facts and warnings; the whole message laid out as GNOME draws it (measured widths, words wider than a line broken and marked) must fit 22 screen lines (`--prompt-lines`), else refused on this path; this holds at default text size only, so the prompt opens by naming its last line `■ END`, which requester text cannot hold: a prompt cut by a larger text size or an unmeasured font shows that it was cut (✓ R4) | R2: root-only snapshot with a daemon-chosen name (✓) | sha256 (✓) |
| script interpreter, `#!` flag | resolved by the helper; root parses the content's `#!` line again and requires the same interpreter and an allowlisted flag (✓ R1) | — | `argv[0]`, `argv[1]` invocation lines (✓) | counted invocation lines (✓) | the verified interpreter and flag (✓) | — |
| script `path` (label) | — | — | escaped, after the arguments (✓) | file name in the title; full label after the arguments (✓) | never used (✓) | Debug-quoted (✓) |
| script `args` | NUL refused; the same path note as `argv`; after `awk -f`/`sed -f` the daemon adds `--` so none is read as an option, but make, flagless sed and awk, and any other trusted program are accepted as `#!` interpreters (⚠ F6) | — | one `argv[i]` invocation line each, escaped, never cut (✓) | counted invocation lines (✓) | verbatim argv (✓) | Debug-quoted (✓) |
| install `content` | every absolute or `./` word gets the argv path note (a unit's `ExecStart=/home/u/x` runs as root later) (✓) | — | text shown, binary described (✓) | as script `content` (✓ R4) | written by the daemon, atomic (✓) | sha256 (✓) |
| install `dest` | Root-owned parent chain, regular single-link target, inspected as the user (✓ R1); only printable ASCII, also in the file name taken from `src`, like `--write` (✓ R3) | errors and existing-file facts as the user sees them (✓ R1) | diff only if the kernel lets the user read the file (✓ R1); escaped in the title and the summary (✓) | title cut at 80 characters, summary at 160; owner and mode are counted invocation lines (✓) | R6: owner, group, mode, label kept; written into a canonical root-controlled directory with `O_NOFOLLOW`, `create_new` and `rename` (✓ R2) | Debug-quoted (✓) |
| `cwd` | canonicalized, checked and opened by the helper as the user; the descriptor is passed back, but the shown path is compared by a name that follows symlinks (⚠ F4) | errors as the user (✓ R1) | escaped; untrusted directory flagged (✓) | `in:` line (✓) | `fchdir` to the descriptor (✓) | Debug-quoted (✓) |
| `env` name | R3: exact allowlist of names (the locale categories are listed one by one), so the count is bounded too (✓) | — | escaped (`Shown`); listed after the summary and warnings, and the header scrolls past 45% of the window, so they push neither the daemon's facts nor the code out of view (checked on Xvfb) (✓) | every variable listed, after the command, so none pushes a fact or warning down (✓ R4) | rebuilt from scratch (✓) | — |
| `env` value | `[A-Za-z0-9_.@:+,-]`, no paths (✓) | — | escaped (✓) | listed (✓) | rebuilt from scratch (✓) | — |
| `write` | absolute, only printable ASCII (✓ R3) | — | in the summary, before the warnings and with no bound on the count (⚠ F11) | in the summary (✓) | declared only, reported as such (✓) | — |
| `why` | — | — | escaped, labelled unverified (✓) | never shown (✓) | — | quoted in plain ASCII and cut at 512 bytes like every requester string (32 arguments at most), so no audit line reaches journald's `LineMax` and is split; the unit has no log rate limit (✓) |
| `timeout_secs` | clamped 5–600 s (✓) | — | — | — | — | — |
| `no_net` | — | — | reported with its level (✓) | in the summary (✓) | new netns, best effort (✓) | — |

## Other messages

| Input | Pre | Ans | Dialog | Prompt | Run | Log |
|---|---|---|---|---|---|---|
| `wait`/`cancel` id | owner checked; others' ids look nonexistent (✓) | own results only (✓) | — | — | — | — |
| `register` name, pid | name escaped; pid must be the caller or an ancestor (✓) | — | escaped (✓) | escaped (✓) | nothing runs (✓) | Debug-quoted (✓) |
| connection itself | SO_PEERCRED uid; admin group before reading, from the account's groups in the user database, never the caller's egid (✓ R2) | — | — | — | — | uid, pid (✓) |
| volume | 32 MiB/message sent within 30 s, 16 connections (no thread or descriptor outlives one), 3 pending (✓) | — | — | — | output capped at 16 MiB/stream (✓) | — |

## What the requester can arrange around a request

| Input | Where it matters | Status |
|---|---|---|
| Its process names, command lines | Dialog: escaped, labelled as self-reported (✓); at most 64 ancestors are read, and an agent beyond that is not found, so the request counts as unregistered (✓) | ✓ |
| Its executable path (mount namespaces) | Dialog and provenance: must be the same inode as the path in the daemon's view (✓) | ✓ |
| Its environment | Display fallback only; read only from processes the requester's uid owns (the opened file's owner); Wayland socket name and runtime dir checked; marked unverified (✓ R1) | ✓ |
| Its egid (`newgrp`, `sg`) | ignored: the admin check and the dialog's gid come from the user database (✓ R2) | ✓ |
| Symlinks, files in its own directories | Pre: resolved as the user (✓). Run: only canonical paths inside root-controlled chains are used, where the user can place no symlink (✓) | ✓ |
| User mounts (udisks images, FUSE) | Pre: nosuid mounts never trusted; a mount that never answers ends the inspection after 10 s (✓) | ✓ |
| Its own polkit agents, other login sessions | Prompt (Wayland): only GNOME Shell's agent is used: the session's controller in logind's record (the compositor), resolved to a pid by the bus daemon, must be a root-controlled `gnome-shell` of the user's; a shell or agent the requester starts cannot take the session, but the binary proves nothing about the code and settings it runs, which come from the user's files (⚠ F3); guard agent holds the subject's slot (✓); subject must be in a session with a seat that is the seat's active one, or in none: positive evidence, so `ssh localhost` (seatless, hence "active", and not "remote") is refused (✓) | ✓ |
| A nested or relaying display server | Dialog: X11 verified through logind and the Xorg process; otherwise unverified, and the password goes to the desktop's prompt when GNOME Shell's can be shown to hold it, else the request is refused unless root passed `--allow-unverified-display` (✓) | ✓ |
| Timing: dialog start-up | /proc reopening defeated by a socket pair; started through `spawn::command` with `no_new_privs`, only stdio, credentials dropped for good (✓). `peekexec-ui` is installed 0711 like the helper, so it is non-dumpable from exec, before its own `prctl`; a root daemon refuses to start when either is readable by others (✓). Descriptors are marked close-on-exec by `close_range`, or one by one before Linux 5.11; if neither works the process is not started (✓ R5). | ✓ |
| Timing: between showing and running | R2: cwd by descriptor, snapshot by copy; program and install directory are root-controlled chains, unchangeable by the requester (✓) | ✓ |
| Timing: pid reuse | pidfds for the requester and agents. The approved command stays unreaped (`waitid(WNOWAIT)`) until its group is killed, which is exactly the condition `pidfd_open(2)` gives for a pid that cannot be reused, so a pidfd would add nothing (R7) (✓) | ✓ |
| Processes the approved command starts | in its cgroup, which it entered before `exec`; all killed when it exits, `setsid` and double forks included (`cgroup.kill`; tested with a `setsid` child); only work handed to systemd outlives it (a root command written to escape can move itself out); without cgroup v2, its process group, logged (✓) | ✓ |
| The inspection helper's answer (it runs as the user) | Pre: what root can derive from the request is derived again and compared (the program argv[0] resolves to, the `#!` interpreter and flag, the install destination); the install directory is re-checked as root-controlled; the descriptor must be the directory shown; cwd warning recomputed; failures are generic (✓). The helper is non-dumpable from exec (binary mode 0711) and by `prctl` (✓). Residual: with ptrace_scope 0 (already noted in the dialog) a tampered helper could misstate an existing file's old content; the new content is always shown in full | ✓ |
| The password, in memory | a `Secret` from the dialog's field to PAM: moved, never copied into a plain `String`, wiped on drop, redacted in `Debug`; every message buffer is wiped after use; PAM's answer is wiped; the strdup copy's `memset` before `free` is optimized away (⚠ F13). Residual: egui's text field and serde's internal buffers are not ours to wipe; daemon reader and egui undo are C10d | ⚠ |
| Panics it can trigger | release builds abort; socket activation restarts (✓) | ✓ |

## Planned structural fixes

- **(a)** Done: pre-approval inspection in a helper with the user's
  credentials and `no_new_privs`, returning facts and the working directory
  (`SCM_RIGHTS`); see `crates/peekexecd/src/inspect.rs`. R1 by
  construction.
- **(b)** Decided, no code: programs, interpreters and install
  directories are used by canonical paths inside chains only root can
  change, which binds the name to the object as well as a descriptor
  would. Running by descriptor (`/proc/self/fd/N`) would break `#!`
  programs, whose interpreter gets an already-closed `/dev/fd/N` (R7).
  Revisit if the trust rule ever admits paths the requester can change.
- **(c)** Done: `Shown` in `crates/peekexec-proto/src/view.rs`. Every
  one-line field of the view has this type, made only by escaping or from
  a daemon constant; it caught a header line built from unescaped argv.
  `enforced.write` stays plain strings (it is also the JSON answer), and
  the summary escapes each path when it draws it.
- **(d)** Done: `crates/peekexecd/src/spawn.rs` starts every process
  (dialog, inspection helper, approved command) with an explicit
  environment and stdio, no other descriptors, verified credential drops,
  and `no_new_privs` for all but the approved command. R5 by construction.
  No `CLONE_PIDFD`: see the pid-reuse row.
- **(e)** Done: no executed data in headers. `Section::invocation`
  replaces the one-line header: the exact argv (one escaped `argv[i]`
  per line, never cut) and the target's facts, shown in full above the
  content in the dialog and counted with it in the desktop prompt, which
  are built from the same lines. `PromptView::findings` counts them too,
  in the daemon and the dialog alike.
- **(f)** Done: `allow_any` and `allow_inactive` are `no` in
  `org.peekexec.approve.policy`, so polkit itself refuses subjects the
  daemon already refuses (defence in depth). Checked in the VM with
  `pkcheck` on polkit 124: an ssh session's process is "Not authorized";
  gnome-shell and a `systemd-run --user` process (in no session, judged
  by the display session) still get `auth_self`. An older polkit without
  that display-session fallback refuses session-less requesters: fail
  closed.
