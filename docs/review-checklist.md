# Review checklist: requester inputs × daemon uses

Reviews check every cell against the [design rules](../THREAT_MODEL.md#design-rules)
(R1–R7). A new feature adds rows (new inputs) or columns (new uses); a cell
nobody has filled in is where the next hole is.

Columns, the places the daemon uses an input:

- **Pre** — looked at before approval (validation, inspection)
- **Ans** — in an answer without a human (preview, error, `wait`)
- **Show** — in the dialog or the desktop's polkit prompt
- **Run** — what root executes or writes
- **Log** — the journal

Status: ✓ held (how) · ⚠ open (planned fix) · — not used there.

## Request fields

| Input | Pre | Ans | Show | Run | Log |
|---|---|---|---|---|---|
| `argv` | R3: NUL refused. argv[0] resolved in SAFE_PATH, root-owned chain, not nosuid (✓). File-like args looked at for the "root does not control" note: ⚠ as root → (a) | ⚠ resolution errors computed as root → (a) | R3: one line per argument, controls escaped (✓) | R2: program by canonical path in a root-owned chain (✓); ⚠ by path, not descriptor → (b) | Debug-quoted (✓) |
| script `content` | R3: `#!` interpreter resolved and trusted, flags allowlisted per interpreter (✓) | — | Full text, findings marked (✓) | R2: root-only snapshot with a daemon-chosen name (✓) | sha256 (✓) |
| script `path` (label) | — | — | escaped (✓) | never used (✓) | Debug-quoted (✓) |
| script `args` | NUL refused (✓) | — | in the header, escaped (✓) | verbatim argv (✓) | Debug-quoted (✓) |
| install `content` | — | — | text shown, binary described (✓) | written by the daemon, atomic (✓) | sha256 (✓) |
| install `dest` | Root-owned parent chain, regular single-link target: ⚠ inspected as root → (a) | ⚠ errors and existing-file facts computed as root → (a) | diff only if the user can read the file: ⚠ judged from mode bits → (a) | R6: owner, group, mode, label kept (✓); ⚠ by path → (b) | Debug-quoted (✓) |
| `cwd` | opened once, by descriptor (✓); ⚠ canonicalized and checked as root → (a) | ⚠ errors as root → (a) | escaped; untrusted directory flagged (✓) | `fchdir` to the descriptor (✓) | Debug-quoted (✓) |
| `env` | R allowlist of names, path-free values (✓) | — | listed (✓) | rebuilt from scratch (✓) | — |
| `write` | absolute, no control characters (✓) | — | in the summary (✓) | declared only, reported as such (✓) | — |
| `why` | — | — | escaped, labelled unverified, never in the polkit prompt (✓) | — | Debug-quoted (✓) |
| `timeout_secs` | clamped 5–600 s (✓) | — | — | — | — |
| `no_net` | — | — | reported with its level (✓) | new netns, best effort (✓) | — |

## Other messages

| Input | Pre | Ans | Show | Run | Log |
|---|---|---|---|---|---|
| `wait`/`cancel` id | owner checked; others' ids look nonexistent (✓) | own results only (✓) | — | — | — |
| `register` name, pid | name escaped; pid must be the caller or an ancestor (✓) | — | escaped (✓) | nothing runs (✓) | Debug-quoted (✓) |
| connection itself | SO_PEERCRED uid; admin group before reading (✓) | — | — | — | uid, pid (✓) |
| volume | 32 MiB/message, 16 connections, 3 pending (✓) | — | — | output capped at 16 MiB/stream (✓) | — |

## What the requester can arrange around a request

| Input | Where it matters | Status |
|---|---|---|
| Its process names, command lines | Show: escaped, labelled as self-reported (✓) | ✓ |
| Its executable path (mount namespaces) | Show and provenance: must be the same inode as the path in the daemon's view (✓) | ✓ |
| Its environment | Display fallback only; Wayland socket name and runtime dir checked; marked unverified (✓) | ✓ |
| Symlinks, files in its own directories | Pre: ⚠ resolved as root → (a). Run: by path → (b) | ⚠ |
| User mounts (udisks images, FUSE) | Pre: nosuid mounts never trusted (✓); a helper as the user can be made to wait on its own FUSE mount → timeout in (a) | ⚠ |
| Its own polkit agents, other login sessions | Show (Wayland): guard agent holds the subject's slot; subject must be in the active local session or none (✓) | ✓ |
| A nested or relaying display server | Show: X11 verified through logind and the Xorg process; otherwise unverified, password goes to the desktop's prompt (✓) | ✓ |
| Timing: dialog start-up | /proc reopening defeated by a socket pair (✓); ⚠ no `no_new_privs` on the dialog → (d) | ⚠ |
| Timing: between showing and running | R2: cwd by descriptor, snapshot by copy (✓); program and install target by path → (b) | ⚠ |
| Timing: pid reuse | pidfds for the requester and agents (✓); ⚠ approved command tracked by pid → (d) | ⚠ |
| Processes the approved command starts | killed with its process group; detached ones cannot hold the request (✓) | ✓ |
| Panics it can trigger | release builds abort; socket activation restarts (✓) | ✓ |

## Planned structural fixes

- **(a)** Pre-approval inspection in a helper with the user's credentials
  and `no_new_privs`, returning facts and descriptors (`SCM_RIGHTS`). R1 by
  construction.
- **(b)** `openat2` with `RESOLVE_NO_MAGICLINKS`; run by descriptor
  (`execveat`), write through the directory descriptor. R2 by construction.
- **(c)** A text type for everything shown, constructible only by escaping.
  R3 by construction.
- **(d)** One spawn helper: explicit descriptors, environment and
  credentials, `no_new_privs`, `CLONE_PIDFD`. R5 by construction.
