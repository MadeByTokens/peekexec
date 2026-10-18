# peekexec

**peek**, then **exec**: run a command as root, showing the human exactly what
will run, binding the approval to exactly that, and limiting what it can touch.

pkexec asks for your password to "run /bin/sh as super user". peekexec shows
you the script — highlighted, formatted, with hidden characters marked — tells
you who is asking and what it may write, and lets you approve, cancel, or deny
with a reason that goes back to whoever asked (human or AI agent).

> **Status: M0, pre-alpha.** Only `peekexec preview` and `peekexec help` work.
> Nothing runs as root yet.

```bash
peekexec preview run --why "install STM32 udev rule" --write /etc/udev/rules.d --no-net -- \
    sh -c 'cp 49-stlink.rules /etc/udev/rules.d/ && udevadm control --reload-rules'
peekexec help agents     # the guide for automated callers
```

- [PLAN.md](PLAN.md): design, architecture, milestones
- [THREAT_MODEL.md](THREAT_MODEL.md): what is guaranteed, and what is not
- [docs/cli.md](docs/cli.md): the CLI contract

## Build

```bash
cargo build --workspace && cargo test --workspace
```

## License

MIT OR Apache-2.0
