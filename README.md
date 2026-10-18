# peekexec

**peek**, then **exec**: run a command as root, showing the human exactly what
will run, binding the approval to exactly that, and limiting what it can touch.

pkexec asks for your password to "run /bin/sh as super user". peekexec shows
you the script — highlighted, formatted, with hidden characters marked — tells
you who is asking and what it may write, and lets you approve, cancel, or deny
with a reason that goes back to whoever asked (human or AI agent).

> **Status: M1, pre-alpha (Linux).** Works end to end; not yet packaged.
> `--write` limits are shown but not enforced until M2 (`enforced` says so).

```bash
peekexec run --why "install STM32 udev rule" --write /etc/udev/rules.d --no-net -- \
    sh -c 'udevadm control --reload-rules && udevadm trigger'
peekexec install 49-stlink.rules /etc/udev/rules.d/
peekexec help agents     # the guide for automated callers
```

- [PLAN.md](PLAN.md): design, architecture, milestones
- [THREAT_MODEL.md](THREAT_MODEL.md): what is guaranteed, and what is not
- [docs/cli.md](docs/cli.md): the CLI contract

## Try it without installing (development mode)

Development mode runs the whole flow — dialog, your real password via PAM,
snapshot, execution — as **your own user**, so nothing runs as root.

```bash
cargo build
target/debug/peekexecd --dev &          # dialog appears on your desktop
export PEEKEXEC_SOCKET=$XDG_RUNTIME_DIR/peekexec-dev.sock
target/debug/peekexec run --why "say hi" -- sh -c 'echo hi && id -un'
```

## Install (root)

```bash
cargo build --release                       # as your user
pkexec "$PWD/packaging/install.sh"          # installs binaries, systemd socket, PAM file
pkexec "$PWD/packaging/install.sh" --uninstall
```

Installs `/usr/local/bin/peekexec`, `/usr/libexec/peekexec/{peekexecd,peekexec-ui}`,
`peekexecd.socket` (enabled) and `/etc/pam.d/peekexec`. Only members of `sudo`,
`wheel` or `admin` can approve requests.

## Develop

```bash
cargo test --workspace --features peekexecd/test-approver   # includes end-to-end tests
cargo test -p peekexecd -- --ignored pam                    # real PAM (may count toward lockout)
```

## License

MIT OR Apache-2.0
