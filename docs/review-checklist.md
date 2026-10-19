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
| `argv` | R3: NUL refused. A bare argv[0] is looked up in SAFE_PATH, one with a `/` is taken relative to cwd; either way a root-owned chain, not nosuid; file-like args checked for the "root does not control" note; all as the user, in the helper (✓ R1) | errors are what the user could learn (✓ R1) | R3: one line per argument, controls escaped; after `sh -c SCRIPT`, each further argument is an `argv[i]` invocation line, in full (✓) | shell-quoted, wrapped, never cut; invocation lines counted with the content (✓) | R2: program by a canonical path whose every component only root can change (root-owned, not writable by others, not nosuid; checked by the helper and again by root), so the name is as good as the object (✓) | Debug-quoted (✓) |
| script `content` | R3: `#!` interpreter resolved and trusted, flags allowlisted per interpreter (✓) | — | Full text, findings marked; runs of blank lines, and of spaces or tabs, collapse into a visible marker (✓) | 12 lines, then INCOMPLETE (✓) | R2: root-only snapshot with a daemon-chosen name (✓) | sha256 (✓) |
| script interpreter, `#!` flag | resolved by the helper (✓). ⚠ root re-checks only that the interpreter is root-controlled, not that it and the flag follow from the content | — | `argv[0]`, `argv[1]` invocation lines (✓) | counted invocation lines (✓) | from the helper's answer | — |
| script `path` (label) | — | — | escaped, after the arguments (✓) | file name in the title; full label after the arguments (✓) | never used (✓) | Debug-quoted (✓) |
| script `args` | NUL refused (✓) | — | one `argv[i]` invocation line each, escaped, never cut (✓) | counted invocation lines (✓) | verbatim argv (✓) | Debug-quoted (✓) |
| install `content` | — | — | text shown, binary described (✓) | 12 lines, then INCOMPLETE (✓) | written by the daemon, atomic (✓) | sha256 (✓) |
| install `dest` | Root-owned parent chain, regular single-link target, inspected as the user (✓ R1); control and hidden characters refused, like `--write` (✓ R3) | errors and existing-file facts as the user sees them (✓ R1) | diff only if the kernel lets the user read the file (✓ R1); escaped in the title and the summary (✓) | title cut at 80 characters, summary at 160; owner and mode are counted invocation lines (✓) | R6: owner, group, mode, label kept; written into a canonical root-controlled directory with `O_NOFOLLOW`, `create_new` and `rename` (✓ R2) | Debug-quoted (✓) |
| `cwd` | canonicalized, checked and opened by the helper as the user; the descriptor is passed back (✓ R1, R2) | errors as the user (✓ R1) | escaped; untrusted directory flagged (✓) | `in:` line (✓) | `fchdir` to the descriptor (✓) | Debug-quoted (✓) |
| `env` name | R3: exact allowlist of names (the locale categories are listed one by one), so the count is bounded too (✓) | — | escaped (`Shown`); the header scrolls past 45% of the window, so nothing in it can push the code out of view (✓) | every variable listed (✓) | rebuilt from scratch (✓) | — |
| `env` value | `[A-Za-z0-9_.@:+,-]`, no paths (✓) | — | escaped (✓) | listed (✓) | rebuilt from scratch (✓) | — |
| `write` | absolute, no control or hidden characters (✓) | — | in the summary (✓) | in the summary (✓) | declared only, reported as such (✓) | — |
| `why` | — | — | escaped, labelled unverified (✓) | never shown (✓) | — | Debug-quoted (✓) |
| `timeout_secs` | clamped 5–600 s (✓) | — | — | — | — | — |
| `no_net` | — | — | reported with its level (✓) | in the summary (✓) | new netns, best effort (✓) | — |

## Other messages

| Input | Pre | Ans | Dialog | Prompt | Run | Log |
|---|---|---|---|---|---|---|
| `wait`/`cancel` id | owner checked; others' ids look nonexistent (✓) | own results only (✓) | — | — | — | — |
| `register` name, pid | name escaped; pid must be the caller or an ancestor (✓) | — | escaped (✓) | escaped (✓) | nothing runs (✓) | Debug-quoted (✓) |
| connection itself | SO_PEERCRED uid; admin group before reading (✓). ⚠ membership is computed from the caller's egid, not the account's primary group | — | — | — | — | uid, pid (✓) |
| volume | 32 MiB/message, 16 connections, 3 pending (✓) | — | — | — | output capped at 16 MiB/stream (✓) | — |

## What the requester can arrange around a request

| Input | Where it matters | Status |
|---|---|---|
| Its process names, command lines | Dialog: escaped, labelled as self-reported (✓). ⚠ the ancestry walk has no depth limit | ⚠ |
| Its executable path (mount namespaces) | Dialog and provenance: must be the same inode as the path in the daemon's view (✓) | ✓ |
| Its environment | Display fallback only; Wayland socket name and runtime dir checked; marked unverified (✓). ⚠ root reads the environment of every ancestor, other users' included | ⚠ |
| Its egid (`newgrp`, `sg`) | ⚠ used for the admin check and as the dialog's gid | ⚠ |
| Symlinks, files in its own directories | Pre: resolved as the user (✓). Run: only canonical paths inside root-controlled chains are used, where the user can place no symlink (✓) | ✓ |
| User mounts (udisks images, FUSE) | Pre: nosuid mounts never trusted; a mount that never answers ends the inspection after 10 s (✓) | ✓ |
| Its own polkit agents, other login sessions | Prompt (Wayland): guard agent holds the subject's slot (✓); subject must be in a session with a seat that is the seat's active one, or in none: positive evidence, so `ssh localhost` (seatless, hence "active", and not "remote") is refused (✓) | ✓ |
| A nested or relaying display server | Dialog: X11 verified through logind and the Xorg process; otherwise unverified, password goes to the desktop's prompt (✓) | ✓ |
| Timing: dialog start-up | /proc reopening defeated by a socket pair; started through `spawn::command` with `no_new_privs`, only stdio, credentials dropped for good (✓). ⚠ `peekexec-ui` is installed 0755, so it is dumpable until `harden()` runs; with ptrace_scope 0 a tracer can attach in that window. ⚠ a failing `close_range` is ignored | ⚠ |
| Timing: between showing and running | R2: cwd by descriptor, snapshot by copy; program and install directory are root-controlled chains, unchangeable by the requester (✓) | ✓ |
| Timing: pid reuse | pidfds for the requester and agents. The approved command stays unreaped (`waitid(WNOWAIT)`) until its group is killed, which is exactly the condition `pidfd_open(2)` gives for a pid that cannot be reused, so a pidfd would add nothing (R7) (✓) | ✓ |
| Processes the approved command starts | killed with its process group; detached ones cannot hold the request (✓) | ✓ |
| The inspection helper's answer (it runs as the user) | Pre: program, interpreter and install directory re-checked as root; destination must be the requested one; descriptor must be the directory shown; cwd warning recomputed; failures are generic (✓). ⚠ the program and the `#!` interpreter and flag are not recomputed (see the rows above). The helper is non-dumpable from exec (binary mode 0711) and by `prctl` (✓). Residual: with ptrace_scope 0 (already noted in the dialog) a tampered helper could misstate an existing file's old content; the new content is always shown in full | ⚠ |
| The password, in memory | ⚠ the dialog scrubs its copy; the daemon's copies (the message, PAM's answer) are freed without being wiped | ⚠ |
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
