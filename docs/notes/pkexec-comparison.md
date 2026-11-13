# pkexec, read against peekexec

Read on 2026-11-13 from polkit's source at
[`4c2422f`](https://github.com/polkit-org/polkit/tree/4c2422fe406ae64e0d86a357d835e9e3962d3b57)
(release 128 plus 6 commits), and tag `0.105` for comparison. The machine
this was written on (Ubuntu 22.04) runs Ubuntu's `0.105-33ubuntu0.2`; the
Wayland test VM (Ubuntu 24.04) runs 124. Links below are to
[`src/programs/pkexec.c`](https://github.com/polkit-org/polkit/blob/4c2422fe406ae64e0d86a357d835e9e3962d3b57/src/programs/pkexec.c)
at that commit.

## What the prompt shows

- **Up to polkit 122** (so Ubuntu 22.04's 0.105): "Authentication is needed
  to run `$(program)` as the super user": the program's path only, no
  arguments (`git show 0.105:src/programs/pkexec.c`, line 688). `pkexec sh -c
  '...'` reads as "run /bin/sh".
- **Since 123** (commit `322c014`, 2023-03-15): `$(cmdline_short)`, the
  arguments joined with spaces and, past 80 bytes, the first 38 and the last
  37 with " ... " between
  ([L866-L875](https://github.com/polkit-org/polkit/blob/4c2422fe406ae64e0d86a357d835e9e3962d3b57/src/programs/pkexec.c#L866-L875),
  [L877-L898](https://github.com/polkit-org/polkit/blob/4c2422fe406ae64e0d86a357d835e9e3962d3b57/src/programs/pkexec.c#L877-L898)).
  The middle of a long command is not shown, and the requester decides what
  lands there. Arguments with spaces cannot be told apart from separate ones.
- polkitd puts the value in as it is, unescaped
  (`append_property` in `src/polkitbackend/polkitbackendinteractiveauthority.c`),
  and GNOME Shell shows the message multi-line (seen in our VM, PLAN.md
  "Check polkit"), so a newline in an argument starts a new line in the
  prompt.
- Nothing about a script's content, what is written, who asks (beyond the
  user), or why.

peekexec: the whole command, each argument on its own, hidden characters
made visible, a script's snapshot in full, the caller chain, the reason,
notes; Enter only for a short allowlist. On Wayland it uses this same polkit
prompt, so it builds the message itself, escaped, at most 22 lines, ending
with "■ END" (THREAT_MODEL, the Wayland path).

## Step by step

| Step | pkexec | peekexec |
|---|---|---|
| How it gets root | setuid root, so it starts inside a process the caller set up | a root daemon started by systemd (socket activation); the caller only sends a request |
| argc 0 (PwnKit, CVE-2021-4034) | `argc < 1` exits since `a2bf5c9` (2022) ([L530-L533](https://github.com/polkit-org/polkit/blob/4c2422fe406ae64e0d86a357d835e9e3962d3b57/src/programs/pkexec.c#L530-L533)); before that, argv[1] read past the end into envp | not applicable: the client is not setuid, and the daemon reads a JSON request, not the caller's argv or environment |
| Who asks | the parent PID, its start time, and the real uid ([L803-L834](https://github.com/polkit-org/polkit/blob/4c2422fe406ae64e0d86a357d835e9e3962d3b57/src/programs/pkexec.c#L803-L834)); dies with the parent (PDEATHSIG) | the socket's peer credentials, pinned with a pidfd on Linux 6.5+ (`platform/linux/peer.rs`) |
| Finding the program | the **caller's** `PATH`, read before the environment is cleared ([L682-L706](https://github.com/polkit-org/polkit/blob/4c2422fe406ae64e0d86a357d835e9e3962d3b57/src/programs/pkexec.c#L682-L706)), then `realpath` | a fixed `SAFE_PATH` (`trust.rs`), never the caller's |
| Who may own the program | not checked: `access(F_OK)` only ([L718](https://github.com/polkit-org/polkit/blob/4c2422fe406ae64e0d86a357d835e9e3962d3b57/src/programs/pkexec.c#L718)); a file the user owns runs as root | root-controlled file and directories only (`trust::check`); the user's own code goes through `script`, which snapshots it |
| Between approval and run | `execv(path)` by name ([L1110](https://github.com/polkit-org/polkit/blob/4c2422fe406ae64e0d86a357d835e9e3962d3b57/src/programs/pkexec.c#L1110)): a user-owned program or script can be replaced after the prompt | checked again just before running (`ready_to_run`); a script runs from its snapshot; disks named are re-checked |
| Environment | cleared, then an allowlist (SHELL in /etc/shells, locale, TERM, COLORTERM; DISPLAY and XAUTHORITY only with `allow_gui`); values with `/`, `%` or `..` refused ([L490-L520](https://github.com/polkit-org/polkit/blob/4c2422fe406ae64e0d86a357d835e9e3962d3b57/src/programs/pkexec.c#L490-L520), [L415-L462](https://github.com/polkit-org/polkit/blob/4c2422fe406ae64e0d86a357d835e9e3962d3b57/src/programs/pkexec.c#L415-L462)); `PATH` includes `/root/bin` ([L979-L985](https://github.com/polkit-org/polkit/blob/4c2422fe406ae64e0d86a357d835e9e3962d3b57/src/programs/pkexec.c#L979-L985)) | cleared, then `ENV_ALLOW` (`prepare.rs`), values letters, digits and `_.@:+,-` only, shown in the dialog |
| Descriptors | close-on-exec from 3 up ([L1024-L1029](https://github.com/polkit-org/polkit/blob/4c2422fe406ae64e0d86a357d835e9e3962d3b57/src/programs/pkexec.c#L1024-L1029)); stdin/out/err are the caller's | close-on-exec from 3 up (`spawn.rs`); stdio are the daemon's pipes |
| Working directory | the target's home, or the caller's with `--keep-cwd` ([L1096-L1104](https://github.com/polkit-org/polkit/blob/4c2422fe406ae64e0d86a357d835e9e3962d3b57/src/programs/pkexec.c#L1096-L1104)) | `/`, or `--cwd`, held as a descriptor and flagged when the user controls it |
| Inherited process state | rlimits, ignored signals, cgroup, controlling terminal come from the caller; pkexec sets none of them. umask is not set by pkexec; on Ubuntu the PAM session it opens (`polkit-1`, `common-session-noninteractive`) runs `pam_umask` | a fresh child of the daemon; `umask 022`, own cgroup, `no_new_privs` for helpers |
| Remembered approval | `org.freedesktop.policykit.exec` is `auth_admin`, asked every time (`actions/org.freedesktop.policykit.policy.in`); local rules can change that | never remembered (THREAT_MODEL); on Wayland, refused if polkit answers without asking |
| Output | the program writes straight to the caller's terminal | captured and returned to the requester (which is why Enter refuses root-only reads) |

## Past bugs, and whether their kind applies here

- **CVE-2021-4034 (PwnKit)**, pkexec: argv/envp confusion in a setuid
  program. The class needs a setuid entry point; peekexec has none.
- **CVE-2011-1485**, pkexec: the parent could exec a setuid program after
  asking, so the check looked at the wrong uid. Fixed in `3b12cfa`
  ("pkexec: Avoid TOCTTOU problems with parent process", 2011-04-01); see
  the comment at
  [L814-L826](https://github.com/polkit-org/polkit/blob/4c2422fe406ae64e0d86a357d835e9e3962d3b57/src/programs/pkexec.c#L814-L826)
  (real uid from pkexec itself). peekexec takes identity from the socket
  and a pidfd, not from a PID read later; the PID chain shown in the dialog
  is labelled as such (THREAT_MODEL).
- **CVE-2013-4288** (`pkcheck --process`) and **CVE-2018-1116** (trusting a
  client-supplied uid), polkit: who is asking, decided from a PID or a
  claim. Same answer as above.
- **CVE-2021-3560** (polkitd treated a caller that left mid-check as
  authorized) and **CVE-2021-4115** (a descriptor leak in polkitd): in
  polkitd itself. They matter to peekexec only on the Wayland path, which
  asks polkitd; peekexec also refuses when polkit answers "yes" without
  having asked (THREAT_MODEL).
- **CVE-2026-4897** and **CVE-2026-85498** (commits `7e122c8`, `eea1729`):
  input handling in `polkit-agent-helper-1`, the setuid helper that checks
  the password for an agent. On the Wayland path GNOME's agent uses it, so
  a peekexec request goes through it; keep polkit updated.

## What this changes for peekexec

- README and PLAN said pkexec's prompt reads "run /bin/sh as super user".
  True for polkit before 123 (Ubuntu 22.04); since 123 it shows a command
  line, cut in the middle past 80 bytes. Both now say so.
- Nothing found in pkexec that peekexec should copy and does not have.
  pkexec refuses `/`, `%` and `..` in the values it passes through;
  peekexec's are stricter, letters, digits and `_.@:+,-` only
  (`env_value_ok` in `prepare.rs`).
- The comparison supports two README claims: peekexec's prompt shows more,
  and it does not run what the user can change. It is no answer to the
  shared weakness: on X11 any program of the user can read the password and
  click, with pkexec as with peekexec.
