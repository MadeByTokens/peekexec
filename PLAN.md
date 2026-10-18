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
4. **Honest display tiers.** X11 with a verified X server, unverified displays
   (Wayland today) flagged on every request, then the desktop's own polkit
   prompt (M2) and a dedicated VT or FIDO2 (later).

## The dialog

```
┌─ Root access requested ─────────────────────────────────────────┐
│ claude (pid 4121) ← bash ← claude-code     in ~/proj/stm32      │
│ Says: "install STM32 udev rule"                     (unverified)│
│ ⚠ writes /etc/udev/rules.d   ✓ no network   ⚠ 1 risk flag       │
├─────────────────────────────────────────── [Formatted|Raw] ─────┤
│  1  cp 49-stlink.rules \                                        │
│  2     /etc/udev/rules.d/                                       │
│  3  && udevadm control --reload-rules                           │
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
  overrides, invisible characters, look-alikes), runs of spaces, and runs of
  blank lines are shown as visible markers.
- **Flags:** a working directory root does not control, targets that make root
  run things later (sudoers, cron, systemd, udev, pam.d, profile, ld.so...),
  unverified display, executables in the install.
- **Fast path:** focus starts in the password field; with nothing to warn
  about, type it and press Enter. With any flag, approving needs a click, and
  a dialog right after another one ignores keys for longer.
- **Cancel:** button, Esc, closing the window, or timeout (default 120 s).
  Nothing runs; the snapshot is removed.
- **Deny with reason:** a text box whose content goes back to the agent as
  `deny_reason`. The requester cannot write to that channel directly; on X11
  another program of the same user could drive the dialog, so agents should
  treat it as the human's advice.
- **Safety details:** 3 password attempts; keystrokes ignored for ~400 ms after
  the dialog appears so typing aimed elsewhere doesn't land in it.

## Built for agents

- `--help` teaches everything. `peekexec help agents` is the full guide,
  `peekexec help schema` is the JSON Schema of `--json` output. Both are
  generated from the code; tests keep them and [docs/cli.md](docs/cli.md) in sync.
- Commands: `run`, `script`, `install` (content and diff shown), `preview`
  (shows what the human will see, without asking), `submit` / `wait` /
  `cancel` for long waits.
- `--json` output: `status`, `exit_code`, `stdout`, `stderr`, `deny_reason`,
  `enforced`, `sha256`, `request_id`, `error`.
- Exit codes: 0–125 the command's own; 130 cancelled, 131 denied, 132 auth
  failed, 133 timeout, 134 error, 135 pending.
- Resending an identical request (same sha256) within an hour of a denial is
  refused, as a courtesy (any change makes a new request).
- No flag lets the caller approve, pre-approve or skip the dialog (see the
  display tiers for what a malicious same-user program can still do on X11).

## Architecture

```
peekexec (CLI, unprivileged) ──Unix socket + kernel peer creds──▶ peekexecd (root)
                                                                   ├─ snapshot + sha256
                                                                   ├─ peekexec-ui (dialog, separate process, non-dumpable)
                                                                   ├─ authenticate
                                                                   └─ exec (snapshot, pinned cwd) + audit log
```

```
crates/
  peekexec-core   request model, hashing, display helpers, text checks   (no OS code)
  peekexec-proto  client ⇄ daemon ⇄ dialog messages, Status, Response    (no OS code)
  peekexec-ui     the dialog (egui), a normal window (no keyboard grab)
  peekexec        the CLI (binary `peekexec`, optional alias `pkx`)
  peekexecd       daemon logic + platform traits:
                    PeerInfo       linux: SO_PEERCRED + /proc  | macos: getpeereid + LOCAL_PEERPID
                    Authenticator  linux: PAM                  | macos: LocalAuthentication / Touch ID
                    Sandbox        linux: netns (best effort)  | macos: sandbox-exec (best effort)
                    Listener       linux: systemd socket / bind| macos: launchd
```

### Porting rules (Linux first, macOS-ready)

- All OS-specific code lives behind the traits in
  `crates/peekexecd/src/platform/` and `peekexec-ui`. A port adds
  `platform/macos.rs`; daemon logic does not change.
- `peekexec-core` and `peekexec-proto` must never use OS APIs. CI checks the
  whole workspace on a macOS runner from day one.
- Every `Sandbox` reports what it really enforces (`kernel` / `best_effort` /
  `declared_only` / `not_requested`). Weaker platforms show weaker guarantees
  with no special-casing in the UI.
- The dialog is a separate process speaking `peekexec-proto`, so a native
  SwiftUI dialog can replace it later. In M1 it runs as the approving user
  (non-dumpable); a dedicated system user is a later hardening step.

## Stack

Rust. Memory safety removes one class of bugs (not logic bugs: sudo-rs had
CVEs too); `unsafe` is confined to FFI sites listed in
[SECURITY.md](SECURITY.md), most of them a small hand-written PAM binding.
Crates: `nix`, `libc`, `egui`/`eframe`, `syntect`, `similar`, `clap`, `serde`,
`schemars`, `sha2`.

## Distribution

- Today: `packaging/install.sh` from a release build. Planned: `.deb`, `.rpm`,
  AUR, static musl tarball.
- CI today: fmt, clippy, shellcheck, docs freshness, tests on Ubuntu
  22.04/24.04, macOS compile check. Planned: Debian, Fedora, Arch, Alpine.
- Planned: reproducible builds, signed releases, SBOM, pinned CI actions,
  `cargo audit` / `cargo deny`.
- A fake approver for tests exists only behind a cargo feature that is
  compile-time excluded from release builds; CI checks it is absent.
- macOS later: Homebrew formula built from source (no notarization needed).
- Windows: out of scope (UAC already provides an elevation prompt); WSL works.
- License: MIT OR Apache-2.0.

## Milestones

| | Scope |
|---|---|
| **M0** ✅ | Plan, threat model, CLI spec; workspace with platform traits; `preview` and `help` work; Linux peer identification |
| **M1** ✅ | Linux MVP: daemon, egui dialog (fast path, Cancel, Formatted/Raw, Unicode marks, Deny with reason), PAM, snapshot execution, trusted-program rule, env allowlist, `--json`, pidfd-pinned peer, `--no-net` via netns, `--dev` mode, systemd units + install script |
| **M2** | **Wayland via the desktop's polkit prompt** (validated in a VM, see below); **trustworthy caller identity** (registered agent sessions, then an MCP channel); real containment by running approved commands as transient systemd units; remaining review items below |
| **M3** | Packaging + CI matrix → **first public release** |
| **M4** | macOS backends + Homebrew |
| **M5** | MCP server + Claude Code skill, dedicated-VT approver, FIDO2 |

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
2. **Option B: password through the desktop's polkit agent.** The agent is
   registered with polkitd at login (in GNOME it is drawn by the shell itself),
   so a requester cannot reroute it. The peekexec window shows the code and
   Approve/Deny; the agent's prompt must carry the summary (who, what, writes),
   not only a hash.
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
2. **MCP channel.** Requests arrive over a private pipe between the agent and
   a root-installed `peekexec mcp` process; scripts the agent runs cannot
   reach it, so "the agent's own tool call" becomes something the system can
   check.

### M2 detail: containment and audit

- Run approved commands as transient systemd units (`PrivateNetwork=`,
  `ProtectSystem=strict`, `ReadWritePaths=`, `CapabilityBoundingSet=`,
  `NoNewPrivileges=`), so `enforced` can say `kernel` truthfully, the unit can
  be killed as a whole, and a PAM session applies. Until then: best effort.
- libaudit `USER_AUTH` / `USER_CMD` records; store the shown text by sha256.

### M2 detail: hardening from the pre-install review

- Done: per-uid caps on connections (16) and pending requests (3);
  non-admins rejected before reading. Left: smaller message limit for
  wait/cancel/preview; bounded worker pool; `LimitNOFILE` in the unit.
- Catch worker panics so a `run` client never blocks forever.
- Cap script/argv size shown in the dialog and virtualise its scrolling.
- Root mode: refuse instead of warning when the display is unverified (once
  the Wayland work gives verified paths there).
- Expired passwords: report "password expired" instead of a generic failure.

