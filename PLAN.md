# peekexec — plan

**peek**, then **exec**. An approval dialog for root commands that shows the
human the exact command, script or file being installed, binds the approval
to what was shown, and reports honestly what it does and does not limit. Built
so AI coding agents can ask for root with a reason the human can read.

## The problem

pkexec's dialog says "run /bin/sh as super user". You cannot see the command or
the script, and nothing stops the script from changing between the prompt and
the run.

## What it guarantees, and what not

See [THREAT_MODEL.md](THREAT_MODEL.md) for the precise version.

1. **Visibility.** The dialog shows the argv, the full script or file content
   (with a diff when replacing a file), the environment additions, the working
   directory, who connected (uid from the kernel; process names are the
   processes' own claims, and untrusted executables are marked) and the
   requester's reason (labelled unverified).
2. **Binding.** What runs is what was shown: scripts run from a root-owned
   snapshot, programs must be root-owned up the directory chain, the working
   directory is entered by the descriptor opened when it was shown. Files the
   command reads at runtime are **not** covered.
3. **Honest limits.** `--write` is declared only and `--no-net` is best effort
   (a root process can undo a network namespace). Each response says which
   level applied; nothing is called enforced unless it is. Real containment
   via systemd's sandboxing is planned.
4. **Honest display tiers.** X11 with a verified X server; on displays it
   cannot verify (Wayland), the password goes into the desktop's own polkit
   prompt, which repeats the decisive facts (with no such prompt the request
   is refused, unless an administrator allowed the unverified window); a
   dedicated VT or FIDO2 later.

## The dialog

A sketch; the layout is in `crates/peekexec-ui/src/main.rs`.

```
┌─ Root access requested ─────────────────────────────────────────┐
│ From  claude (pid 4121) ← bash ← claude-code                    │
│ In    ~/proj/stm32                             Runs as  root    │
│ writes: none declared   ✓ no network   ⚠ 1 risk flag            │
│ The requester says: "reload udev rules"             (unverified)│
├─ script setup.sh ───────────────────────── [Formatted|Raw] ─────┤
│  1  #!/bin/sh -e                                                │
│  2  udevadm control --reload-rules                              │
│  3  udevadm trigger --subsystem-match=usb                       │
├─────────────────────────────────────────────────────────────────┤
│ Password: [••••••••_________]                 [Cancel] [Approve]│
│ sha256 3f9a…c21e                       Deny with reason…        │
└─────────────────────────────────────────────────────────────────┘
```

- **Readable like an IDE:** syntax colours, line numbers, wrapped lines, tabs
  with line counts. One-line `sh -c` is broken into lines for display only
  (each line is an exact slice of the original, checked in code); a Raw toggle
  shows the exact bytes.
- **Marked, not hidden:** every non-ASCII and control character (bidi
  overrides, invisible characters, look-alikes), runs of spaces or tabs, and
  runs of blank lines are shown as visible markers. Each argument root
  passes is a line of its own (`argv[i] ...`), in full.
- **Flags:** a working directory root does not control, targets that make root
  run things later (sudoers, cron, systemd, udev, pam.d, profile, ld.so...),
  unverified display, executables in the install.
- **Fast path:** focus starts in the password field; for a plain `run` (no
  shell, interpreter or program runner in any word, no spaces or shell
  syntax in an argument) with nothing to warn about,
  type it and press Enter. Scripts, installs, `sh -c` and any flag need a
  click, and a dialog right after another one ignores keys for longer.
- **Cancel:** button, Esc, closing the window, or timeout (default 120 s).
  Nothing runs; the snapshot is removed.
- **Deny with reason:** a text box whose content goes back to the agent as
  `deny_reason`. The requester cannot write to that channel directly; on X11
  another program of the same user could drive the dialog, so agents should
  treat it as the human's advice.
- **Safety details:** 3 password attempts; keystrokes ignored for 400 ms after
  the dialog appears (1.5 s when it follows another dialog) so typing aimed
  elsewhere doesn't land in it, and a key pressed in that time turns off
  Enter-to-approve for this dialog.

## Built for agents

- `--help` teaches everything. `peekexec help agents` is the full guide,
  `peekexec help schema` is the JSON Schema of `--json` output. The schema
  and the exit codes are generated from the code; tests check that the
  guide names every status and level, and keep [docs/cli.md](docs/cli.md)
  in sync.
- Commands: `run`, `script`, `install` (content and diff shown), `preview`
  (shows what the human will see, without asking), `submit` / `wait` /
  `cancel` for long waits.
- `--json` output: `status`, `exit_code`, `stdout`, `stderr`, `deny_reason`,
  `enforced`, `sha256`, `request_id`, `error`, `display_tier`,
  `display_verified`, `dev_mode`, `session`.
- Exit codes: 0–125 the command's own; 130 cancelled, 131 denied, 132 auth
  failed, 133 timeout, 134 error, 135 pending.
- Resending an identical request (same sha256) within an hour of a denial is
  refused, as a courtesy (any change makes a new request).
- No flag lets the caller approve, pre-approve or skip the dialog (see the
  display tiers for what a malicious same-user program can still do on X11).

## Architecture

```
peekexec (CLI, unprivileged) ──Unix socket + kernel peer creds──▶ peekexecd (root)
                                                                   ├─ inspection helper (peekexecd --inspect-helper,
                                                                   │    as the user, no_new_privs: every path, before approval)
                                                                   ├─ snapshot + sha256
                                                                   ├─ peekexec-ui (dialog, as the user, non-dumpable)
                                                                   │    or the desktop's polkit prompt (Wayland)
                                                                   ├─ authenticate (PAM, or polkit)
                                                                   └─ exec (snapshot, pinned cwd) + audit log
```

```
crates/
  peekexec-core   request model, hashing, display helpers, text checks   (no OS code)
  peekexec-proto  client ⇄ daemon ⇄ dialog messages, Status, Response    (no OS code)
  peekexec-ui     the dialog (egui), a normal window (no keyboard grab)
  peekexec        the CLI (binary `peekexec`)
  peekexecd       daemon logic + platform traits (macos: planned for M4;
                  today `platform/macos.rs` is a stub that refuses everything):
                    PeerInfo       linux: SO_PEERCRED + /proc  | macos: getpeereid + LOCAL_PEERPID
                    Authenticator  linux: PAM, or polkit       | macos: LocalAuthentication / Touch ID
                    Sandbox        linux: netns (best effort)  | macos: sandbox-exec (best effort)
                    Listener       linux: systemd socket / bind| macos: launchd
```

### Porting rules (Linux first, macOS-ready)

- All OS-specific code lives behind the traits in
  `crates/peekexecd/src/platform/` and `peekexec-ui`. A port fills in
  `platform/macos.rs`; daemon logic does not change.
- `peekexec-core` and `peekexec-proto` must never use OS APIs. CI checks the
  whole workspace on a macOS runner from day one.
- Every `Sandbox` reports what it really enforces (`kernel` / `best_effort` /
  `declared_only` / `not_requested`; `builtin` when peekexec itself did the
  work, as `install` does). Weaker platforms show weaker guarantees
  with no special-casing in the UI.
- The dialog is a separate process speaking `peekexec-proto`, so a native
  SwiftUI dialog can replace it later. In M1 it runs as the approving user
  (non-dumpable); a dedicated system user is a later hardening step.

## Stack

Rust. Memory safety removes one class of bugs (not logic bugs: sudo-rs had
CVEs too); `unsafe` is confined to FFI sites listed in
[SECURITY.md](SECURITY.md), most of them a small hand-written PAM binding.
Crates: `nix`, `libc`, `egui`/`eframe`, `syntect`, `similar`, `clap`, `serde`,
`schemars`, `sha2`, `zbus` (polkit, for the Wayland path).

## Distribution

- Today: `packaging/install.sh` from a release build. Planned: `.deb`, `.rpm`,
  AUR, static musl tarball.
- CI today: fmt, clippy, shellcheck, docs freshness, `cargo deny` and
  `cargo audit`, tests on Ubuntu 22.04/24.04, and on macOS a workspace check
  plus the portable crates' tests; actions pinned to commits, read-only
  token. Planned: Debian, Fedora, Arch, Alpine.
- Planned: reproducible builds, signed releases, SBOM.
- A fake approver for tests exists only behind a cargo feature that is
  compile-time excluded from release builds; `packaging/install.sh` refuses
  a daemon binary that contains it.
- macOS later: Homebrew formula built from source (no notarization needed).
- Windows: out of scope (UAC already provides an elevation prompt). WSL is untested.
- License: MIT OR Apache-2.0.

## Milestones

| | Scope |
|---|---|
| **M0** ✅ | Plan, threat model, CLI spec; workspace with platform traits; `preview` and `help` work; Linux peer identification |
| **M1** ✅ | Linux MVP: daemon, egui dialog (fast path, Cancel, Formatted/Raw, Unicode marks, Deny with reason), PAM, snapshot execution, trusted-program rule, env allowlist, `--json`, pidfd-pinned peer, `--no-net` via netns, `--dev` mode, systemd units + install script |
| **M2** | **Wayland via the desktop's polkit prompt** (validated in a VM, see below); **trustworthy caller identity** (registered agent sessions); real containment by running approved commands as transient systemd units; remaining review items below |
| **M3** | Packaging + CI matrix → **first public release** |
| **M4** | macOS backends + Homebrew |
| **M5** | FIDO2 (the dedicated-VT approver moved into M2; an MCP channel was dropped: agents use the CLI) |

### M2 detail: verified display on Wayland

On X11 the daemon verifies the X server through logind (session scope, leader,
VT). On Wayland the compositor *is* the display server and, on GNOME, runs as a
systemd **user** service, so the same check cannot tell it from an impostor;
the requester also owns `/run/user/$UID` and could replace the socket. Today
such displays are reported as unverified. Work, in a Ubuntu 24.04 desktop VM:

1. **Check polkit** ✅ (Ubuntu 24.04, GNOME 46, polkit 124, in the VM): a root
   caller's `polkit.message` is shown verbatim, multi-line, in GNOME Shell's
   own prompt, and `CheckAuthorization` returns `is_authorized` after the
   password is typed there. Use a `unix-process` subject (pid + start time,
   or pidfd): a `unix-session` subject crashes polkitd on both 0.105 and 124,
   even for unprivileged callers (Launchpad #1562721). Any caller can set
   `polkit.message` for its own request, so the prompt itself must carry the
   decisive facts; a decoy viewer next to it is the remaining risk.
2. **Option B: password through the desktop's polkit agent** ✅ (verified in the
   VM: read-only peekexec window, Continue, GNOME's prompt with the daemon's
   summary, approve / dismiss / no-agent paths). The agent is
   registered with polkitd at login (in GNOME it is drawn by the shell itself),
   so a requester cannot reroute it. The peekexec window shows the code,
   read-only, with Continue and Deny; the agent's prompt carries the summary
   (who, what, writes, every warning), not only a hash.
3. **Option C: dedicated VT (tier 3)**, opt-in high-assurance mode and the
   fallback whenever the display is unverified: the daemon switches to its
   own console, shows the request (colours, scrolling), takes the password
   there, switches back. Works for every display server.
4. Option A, identifying the compositor as the DRM master of the seat, is
   kept as a fallback idea (debugfs-dependent, fragile).

### M2 detail: who is asking, for sure

The uid is certain; process names are not (any program of the user can name
itself "claude"). Plan:

1. **Registered agent sessions** ✅ (`peekexec register`). The human approves once, at agent start:
   "register Claude Code (pid N) in ~/proj". The daemon pins that process
   (pidfd) and checks every later request's ancestry against it: "from this
   agent's session", with scripts and programs in between flagged. It cannot
   tell the agent's own commands from a program that exec'd into a shell;
   that needs step 2.
2. **MCP channel: dropped.** A private pipe between the agent and a
   `peekexec mcp` process would let the system check "the agent's own tool
   call", but a prompt-injected agent would call that tool just the same,
   and agents do well with the CLI and its `--help`. The console approval
   (every request read in full, outside the session) covers most of what
   the label would.

### M2 detail: containment and audit

- Run approved commands as transient systemd units (`PrivateNetwork=`,
  `ProtectSystem=strict`, `ReadWritePaths=`, `CapabilityBoundingSet=`,
  `NoNewPrivileges=`), so `enforced` can say `kernel` truthfully and a PAM
  session applies, and so a command outlives a daemon restart (today its
  output goes to the daemon, and stopping the daemon ends it). Until then:
  best effort. (Done already: each command has a cgroup of its own, killed
  as a whole when it exits.)
- libaudit `USER_AUTH` / `USER_CMD` records; store the shown text by sha256.

### M2 detail: hardening from the pre-install review

- Done: per-uid caps on connections (16), pending requests (3) and
  registrations (one at a time); one 30 s deadline per message;
  non-admins rejected before reading. Left: smaller message limit for
  wait/cancel/preview; bounded worker pool; `LimitNOFILE` in the unit.
- Done: worker panics cannot leave a `run` client blocked; release builds
  abort on panic and socket activation starts a fresh daemon.
- Cap script/argv size shown in the dialog and virtualise its scrolling.
- Root mode: refuse instead of warning when the display is unverified (once
  the Wayland work gives verified paths there).
- Expired passwords: report "password expired" instead of a generic failure.


### Fourth review: follow-ups (checklist)

From the fourth review (2026-10-19). One commit per item, each tested
first; ticked when committed. Decided with the owner: no MCP channel (a
good `--help` and a shell are enough for agents); `install.sh`
`--expect-sha256` waits for signed releases; console approval becomes
the default wherever the display cannot be verified.

- [x] A1 `dev/wayland-vm/approve-test.sh`: the polkit path end to end in
      the VM (approve, deny with reason, wrong password, too long).
- [x] A2 First push to GitHub, CI green (asks the owner first: the
      repository is public).
- [x] B3 `deny_reason`: the guide says it may only narrow what the agent
      does and mentions `display_verified`; denials stored per requester.
- [x] B4 Daemon refuses to start when the dialog or helper is readable by
      others.
- [x] B5 Flags for lasting root: group changes, setuid chmod, setcap,
      systemd-run, at/batch, crontab, `systemctl enable`.
- [x] B6 Facts say the output goes back to the requester.
- [x] B7a Results expire from when they finished.
- [x] B7b `is_admin` uses the first admin group only.
- [x] B7c The dialog's Enter path honours the approve delay.
- [x] B7d `Shown` escapes characters with zero advance.
- [x] C8a Diff against the previous request when one follows soon.
- [x] C8b "N more requests waiting" note.
- [x] C8c Neutral agent-session badge.
- [x] C9a Client escapes daemon text and output unless the daemon is root.
- [x] C9b `PEEKEXEC_SOCKET` set means `dev_mode`.
- [x] C10a Ancestry walk: parent re-read, started before its child.
- [x] C10b No world-writable sticky directory in a trusted chain.
- [ ] C10c No vfat/exfat/ntfs/cifs/nfs/fuse filesystem in a trusted chain.
- [ ] C10d Password buffers wiped (daemon reader, egui undo).
- [ ] D11a `install.sh` refuses to run inside the service.
- [ ] D11c Rust toolchain pinned for CI.
- [ ] D11d `forbid(unsafe_code)` where there is none; unsafe-doc lint.
- [ ] D11e schemars behind a feature (not linked into the daemon).
- [ ] E12 Console (VT) approval, the default on unverified displays:
      prototype in the VM, then module, renderer, approval path, docs.
- [ ] E14 Commands as transient systemd units: kernel-enforced `--write`
      and `--no-net`, output a new daemon can reattach to.

### Fifth review: follow-ups (checklist)

From the fifth review (2026-10-31); details and evidence in
[docs/notes/fifth-review.md](docs/notes/fifth-review.md), failing tests in
`docs/notes/fifth-review-tests/`. One commit per item, each tested first,
then a bypass pass. In order of priority:

- [x] F1 A formatted `Line` never holds a newline; drawn spans rejoin to the
      text (critical: the dialog's default view can differ from what runs).
- [x] F2 Desktop prompt: truncation visible on screen (end marker). Measuring
      scale or height was left out: the requester controls them.
- [ ] F3 Tier 2: state the limit; refuse on code in the shell from outside
      root-controlled paths; weighs on E12.
- [ ] F4 Working directory: shown path taken from the descriptor.
- [ ] F5 Replies: one budget by encoded size; "outcome unknown" in the client.
- [ ] F6 Allowlist of `#!` interpreter families.
- [ ] F7 Enter-to-approve: remove, or an allowlist of inert programs (owner
      decides: the fast path was a requirement).
- [ ] F8 Note gaps: `mode & 0o6000`, `--mode=`, `--groups=`, `if`/`while`,
      backslash-newline; path note on relative and joined options.
- [ ] F9 Comparison: remember only what a dialog showed; compare by digest.
- [ ] F10 Request table bounded; `lookup` honours expiry.
- [ ] F11 Dialog header: bounded lists, daemon facts first, tabs wrap.
- [ ] F12 Audit: bound on refused-request lines; log every message.
- [ ] F13 Low findings in the review notes, pinned tests for surviving
      mutations (M1, M3, M4, M5, M6, M9, M14), doc corrections.
- [ ] F14 Installer shows and confirms the admin group (`--admin-group`).
- [ ] F15 Yama: positive evidence required on the desktop-prompt path.
- [ ] F16 Triage the notes' "Also found, not verified" list: verify each,
      then fix or drop it.
