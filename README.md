# peekexec

**peek**, then **exec**: an approval dialog for root commands that shows the
human what they are approving: the exact command, the full script, or the
file being installed, plus who is asking and why. Built so AI coding agents
can ask for root with a reason the human can read, and get a structured
answer back.

> **Pre-alpha. Not audited. Do not use it on machines you care about yet.**
> Linux only. On Wayland desktops (the default on current Ubuntu, Fedora and
> KDE) the dialog cannot yet verify which display server shows it, and says
> so on every request; see [THREAT_MODEL.md](THREAT_MODEL.md).

pkexec asks for your password to "run /bin/sh as super user". peekexec shows:

- the command's argv, the script's bytes, or the installed file's content
  (with a diff when it replaces a file), highlighted, with every non-ASCII and
  control character, long space runs and blank-line padding marked;
- who connected (uid from the kernel; the process chain, with processes whose
  executable root does not own marked as such) and the reason they give
  (labelled unverified);
- what it declares it will touch, and how much of that is actually enforced.

You approve with your password, cancel, or deny with a written reason that the
requester receives.

```bash
peekexec run --json --why "reload udev rules for the ST-LINK probe" -- udevadm control --reload-rules
peekexec install --json --why "add the vendor's udev rule" 49-stlink.rules /etc/udev/rules.d/
peekexec script --json --why "set up the toolchain" ./setup.sh
peekexec help agents     # the guide for automated callers
```

## What it does and does not promise

| | |
|---|---|
| **Bound to what was shown** | The argv, script bytes, environment, install content and target, and working directory that run are the ones shown. Scripts run from a root-owned snapshot; programs must be root-owned with root-owned parent directories; the working directory is opened when shown and entered by descriptor. |
| **Not shown** | Files and directories the command reads while it runs (`cp ./x /etc/` shows the command, not `./x`). Use `peekexec install` for files. |
| **Limits** | `--write` is declared only. `--no-net` puts the command in a new network namespace: this stops well-behaved programs, but a root process can rejoin the host network, so it is reported as `best_effort`. Neither is containment. |
| **Who is asking** | The uid comes from the kernel and decides everything. Process names and command lines are chosen by the processes themselves and are informational. |
| **The human channel** | On X11, any program running as you can see and drive the dialog (as with sudo and pkexec). Treat `deny_reason` as the human's advice, not an authenticated instruction. |

## When to use something else

- **Interactive root work** (shells, editors, prompts): `sudo` / `sudo-rs` or
  `run0`. peekexec gives commands no terminal.
- **SSH, servers, policy rules** ("this user may run X without a password"):
  `sudo-rs`, `doas`, polkit rules. peekexec needs a local graphical session.
- **Containing a root command**: `systemd-run` / `run0` with sandboxing
  properties (`PrivateNetwork=`, `ProtectSystem=strict`, ...).
- **A malicious agent running as your user**: nothing at this level helps
  (sudo and pkexec included). Run the agent as another user or in a VM.

## Try it without installing (development mode)

Development mode runs the whole flow (dialog, your real password via PAM,
snapshot, execution) as **your own user**, so nothing runs as root.

```bash
cargo build
target/debug/peekexecd --dev &
export PEEKEXEC_SOCKET=$XDG_RUNTIME_DIR/peekexec-dev.sock
target/debug/peekexec run --why "say hi" -- sh -c 'echo hi && id -un'
```

## Install (root)

```bash
cargo build --release
pkexec "$PWD/packaging/install.sh"            # or: sudo
pkexec "$PWD/packaging/install.sh" --uninstall
```

The script copies the built binaries into a root-only staging directory,
refuses a test build, then installs `/usr/local/bin/peekexec`,
`/usr/libexec/peekexec/{peekexecd,peekexec-ui}`, `peekexecd.socket` and
`/etc/pam.d/peekexec`. It still runs as root from your checkout, so build and
install from a tree only you can write. Packages are planned.

Only members of `sudo`, `wheel` or `admin` can approve, with their own
password, the same model as sudo.

## Develop

```bash
cargo test --workspace --features peekexecd/test-approver   # includes end-to-end tests
cargo test -p peekexecd -- --ignored pam                    # real PAM (may count toward lockout)
dev/wayland-vm/README.md                                    # Ubuntu 24.04 Wayland test VM
```

- [PLAN.md](PLAN.md): design, architecture, milestones
- [THREAT_MODEL.md](THREAT_MODEL.md): what holds against whom
- [SECURITY.md](SECURITY.md): reporting vulnerabilities, `unsafe` inventory
- [docs/cli.md](docs/cli.md): the CLI contract

## License

MIT OR Apache-2.0
