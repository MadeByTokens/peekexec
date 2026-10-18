# peekexec — plan

**peek**, then **exec**. A replacement for `pkexec` that shows the human exactly
what will run as root, binds the approval to exactly that, and limits what it
can touch. Built for humans and for AI agents that need root now and then.

## The problem

pkexec's dialog says "run /bin/sh as super user". You cannot see the command or
the script, and nothing stops the script from changing between the prompt and
the run.

## Guarantees

1. **Visibility.** The dialog shows the full command, the full contents of any
   script, env, cwd, and who is asking (the process and its parent chain,
   established by the kernel, not claimed by the caller).
2. **Binding.** Root snapshots everything into a root-owned location and hashes
   it *before* showing it, then executes **only that snapshot**. Editing files
   afterwards has no effect.
3. **Effect limits.** `--write PATH` and `--no-net` are enforced by the kernel
   (Landlock + network namespaces). Each response says what was *actually*
   enforced vs. only declared — never overstated.
4. **Honest tiers.** X11 dialog (protects against buggy/overeager agents) →
   Wayland (clients isolated) → dedicated VT + FIDO2 key (later). The tool
   always says which tier it is running at. See [THREAT_MODEL.md](THREAT_MODEL.md).

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

- **Readable like an IDE:** syntax colours, line numbers, scrolling, tabs for
  multiple files. One-line `sh -c` is formatted for display only, re-parsed to
  check it matches the original (falls back to Raw if not); a Raw toggle shows
  the exact bytes.
- **Nothing hidden:** control chars, bidi overrides ("Trojan Source"),
  invisible and look-alike Unicode are marked in red.
- **Risk flags:** `rm -rf`, writes to sudoers/pam.d, `curl | sh`, `chmod 777`, …
- **Fast path:** focus starts in the password field; type it, press Enter,
  done. Reading is never forced; the summary line is enough at a glance.
  PgUp/PgDn and the wheel scroll the code without leaving the field.
- **Cancel:** button, Esc, closing the window, or timeout (default 120 s).
  Nothing runs; the snapshot is removed.
- **Deny with reason:** a text box whose content goes back to the agent as
  `deny_reason` — a channel from the human to the agent that other processes
  cannot forge.
- **Safety details:** 3 password attempts; keystrokes ignored for ~400 ms after
  the dialog appears so typing aimed elsewhere doesn't land in it.

## Built for agents

- `--help` teaches everything. `peekexec help agents` is the full guide,
  `peekexec help schema` is the JSON Schema of `--json` output. Both are
  generated from the code; tests keep them and [docs/cli.md](docs/cli.md) in sync.
- Commands: `run`, `script`, `install` (diff shown), `preview` (unprivileged,
  shows what the human will see), `submit` / `wait` / `cancel` for long waits.
- `--json` output: `status`, `exit_code`, `stdout`, `stderr`, `deny_reason`,
  `enforced`, `sha256`, `request_id`, `error`.
- Exit codes: 0–125 the command's own; 130 cancelled, 131 denied, 132 auth
  failed, 133 timeout, 134 error, 135 pending.
- Resending an identical request (same sha256) after a denial is refused.
- The caller cannot approve, pre-approve, or skip the dialog. No flag exists.

## Architecture

```
peekexec (CLI, unprivileged) ──Unix socket + kernel peer creds──▶ peekexecd (root)
                                                                   ├─ snapshot + sha256
                                                                   ├─ peekexec-ui (dialog, separate process, non-dumpable)
                                                                   ├─ authenticate
                                                                   └─ sandboxed exec + audit log
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
                    Sandbox        linux: Landlock + netns     | macos: sandbox-exec (best effort)
                    Listener       linux: systemd socket / bind| macos: launchd
```

### Porting rules (Linux first, macOS-ready)

- All OS-specific code lives behind the traits in
  `crates/peekexecd/src/platform/` and `peekexec-ui`. A port adds
  `platform/macos.rs`; daemon logic does not change.
- `peekexec-core` and `peekexec-proto` must never use OS APIs. CI checks the
  whole workspace on a macOS runner from day one.
- Every `Sandbox` reports what it really enforces (`kernel` /
  `declared_only` / `not_requested`). Weaker platforms show weaker guarantees
  with no special-casing in the UI.
- The dialog is a separate process speaking `peekexec-proto`, so a native
  SwiftUI dialog can replace it later. In M1 it runs as the approving user
  (non-dumpable); a dedicated system user is a later hardening step.

## Stack

Rust (memory-safe root daemon; same reasoning as Ubuntu's move to sudo-rs after
pkexec's PwnKit). Crates: `nix`, `pam-client`, `landlock`, `egui`/`eframe` +
`syntect` + tree-sitter-bash, `clap`, `serde`, `schemars`.

## Distribution

- Linux: `.deb` (cargo-deb), `.rpm` (cargo-generate-rpm), AUR, static musl
  tarball + `install.sh`. Full enforcement needs kernel ≥ 5.13; older kernels
  work with limits honestly labelled `declared_only`.
- CI: Ubuntu 22.04/24.04, Debian 12, Fedora, Arch, Alpine containers; one VM
  that exercises Landlock for real; macOS compile check.
- Reproducible builds, minisign-signed releases, SBOM.
- A fake approver for tests exists only behind a cargo feature that is
  compile-time excluded from release builds; CI checks it is absent.
- macOS later: Homebrew formula built from source (no notarization needed).
- Windows: out of scope (UAC's secure desktop is already stronger than a
  custom prompt could be); WSL works.
- License: MIT OR Apache-2.0.

## Milestones

| | Scope |
|---|---|
| **M0** ✅ | Plan, threat model, CLI spec; workspace with platform traits; `preview` and `help` work; Linux peer identification |
| **M1** ✅ | Linux MVP: daemon, egui dialog (fast path, Cancel, Formatted/Raw, Unicode marks, Deny with reason), PAM, snapshot execution, trusted-program rule, env allowlist, `--json`, pidfd-pinned peer, `--no-net` via netns, `--dev` mode, systemd units + install script |
| **M2** | **Wayland display verification first** (the user's other machines run Wayland; see below), then Landlock write limits, `install` diffs, risk flags (runtime-read user files, udev/systemd/cron/sudoers targets) |
| **M3** | Packaging + CI matrix → **first public release** |
| **M4** | macOS backends + Homebrew |
| **M5** | MCP server + Claude Code skill, dedicated-VT approver, FIDO2 |

### M2 detail: verified display on Wayland

On X11 the daemon verifies the X server through logind (session scope, leader,
VT). On Wayland the compositor *is* the display server and, on GNOME, runs as a
systemd **user** service, so the same check cannot tell it from an impostor;
the requester also owns `/run/user/$UID` and could replace the socket. Today
such displays are reported as unverified. Work, in a Ubuntu 24.04 desktop VM:

1. **Check polkit**: can a root mechanism set the message (`polkit.message`
   detail) that GNOME Shell's built-in agent shows? If yes, option B below
   becomes viable.
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

### M2 detail: hardening from the pre-install review

- Per-uid caps on connections and pending requests; smaller message limit
  for wait/cancel/preview; bounded worker pool; `LimitNOFILE` in the unit.
- Catch worker panics so a `run` client never blocks forever.
- Cap script/argv size shown in the dialog and virtualise its scrolling.
- Root mode: refuse instead of warning when the display is unverified (once
  the Wayland work gives verified paths there).
- Expired passwords: report "password expired" instead of a generic failure.

