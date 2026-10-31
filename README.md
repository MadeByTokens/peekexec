# peekexec

**Peek, then exec.** When a program asks for root, peekexec shows you exactly
what it wants to run before you type your password.

It was built for AI coding agents. They often need root for a step or two, and
the usual prompt tells you almost nothing: pkexec asks for your password to
"run /bin/sh as super user". peekexec shows you the real command instead, along
with who is asking and why.

> [!WARNING]
> **This is experimental, pre-alpha software, and no independent security
> expert has reviewed it.** It installs a service that runs as root, and a bug
> in it could give a local program root without your approval. It comes with
> no warranty.
>
> Use it on your own single-user machine, and not on shared machines or ones
> you can't afford to lose.
>
> **It helps you catch an agent's mistakes. It does not stop an agent that is
> deliberately trying to get root.** Please read
> [What it won't protect you from](#what-it-wont-protect-you-from).

## What it looks like

An agent asks for root like this:

```bash
peekexec run --why "reload udev rules for the ST-LINK probe" -- udevadm control --reload-rules
```

A window opens on your desktop, showing:

- **What will run.** Every argument on its own line, or the full script with
  syntax colours, or the file being installed, with the changes if it replaces
  a file.
- **Anything hidden.** Invisible characters, look-alike letters, and long runs
  of spaces or blank lines are marked, so they can't disguise anything.
- **Who is asking,** and the reason they give. The reason is labelled
  "unverified", because it's only their claim.
- **Warnings,** such as a file that could make root run something later (cron,
  sudoers, systemd), or a request that arrived right after another one.

Then you choose:

- **Approve** with your password. What runs is what you were shown: scripts
  run from a private copy, so editing the file afterwards changes nothing.
- **Cancel.** Nothing runs.
- **Deny with a reason.** Your message goes back to the agent, so you can say
  "use the vendor's rules file instead".

If the request has anything risky about it, you have to click Approve. For
simple read-only commands you can just type your password and press Enter.

## Will it work on my desktop?

peekexec only asks for your password somewhere it trusts, so it refuses to run
on setups it can't check.

| Your desktop | What happens |
|---|---|
| **GNOME on Wayland** | Works. You read the request in peekexec's window, then type your password into GNOME's own prompt, which repeats the request. Requests must be short (see below). |
| **GNOME on X11 with GDM** | Works. Everything happens in peekexec's window, but any program running as you can see what you type there. |
| **Wayland with `ptrace_scope` set to 0** | Refused until you run `sysctl kernel.yama.ptrace_scope=1`. Some distributions may default to 0. |
| **KDE, Sway, other Wayland desktops** | Refused. |
| **X11 with another login manager** (LightDM, SDDM), `startx` | Refused. |
| **SSH, no desktop, containers, WSL** | Refused. peekexec needs a person at a local desktop. |
| **macOS, Windows** | Not supported. |

An administrator can allow the refused desktops by starting the daemon with
`--allow-unverified-display`, but your password then goes into a window that
another program may be able to read.

So far it has only been tested on Ubuntu 22.04 and 24.04. Other distributions
may work, but nobody has tried them yet.

## What it won't protect you from

Please read this part before you rely on it.

- **An agent that wants to cheat, on X11.** Any program running as you can read
  the password as you type it, then click Approve itself. That includes any
  program your agent starts. sudo and pkexec have the same weakness, so
  peekexec isn't worse, but it doesn't fix this.
- **An agent that wants to cheat, on Wayland, if it planned ahead.** Your
  password goes into GNOME's prompt, which is much harder to attack. But a
  program that can write to your home folder could install a GNOME Shell
  extension, wait for your next login, and tamper with that prompt.
  peekexec can't detect this.
- **Commands that are bad ideas.** Once approved, a command runs as full root.
  peekexec flags common dangers, but its lists can't be complete.
- **Files the command reads.** You see `cp ./x /etc/`, not what's inside `./x`,
  and that file can change after you approve. Use `peekexec install`, which
  shows you the content.
- **What a command does while it runs.** `--write` only tells you what the
  command says it will touch; nothing enforces it. `--no-net` stops ordinary
  programs from using the network, but a program running as root can undo it.
- **Your screen settings, on Wayland.** GNOME's prompt can't scroll. If you
  don't see the line starting with **■ END**, part of the request is off
  screen: cancel it.

Some other things worth knowing:

- **The output goes back to the agent.** If you approve `cat /etc/shadow`, the
  agent receives it.
- **Requests must be short on Wayland.** About 22 lines of 45 characters,
  warnings included, on a 768-pixel-tall screen. Longer requests are refused,
  so agents have to split them into steps.
- **"Who is asking" is partly a claim.** Your user id is certain. Process names
  are chosen by the processes themselves. If you register an agent, peekexec
  can show that a request came from inside its session, but anything the agent
  started could have sent it.
- **There's no terminal.** Commands can't prompt you for anything, so interactive
  commands won't work.
- **Stopping or upgrading peekexec ends running commands.** The installer waits
  for them first.

If you're not sure how much to trust it, read every script in full, and switch
to the **Raw** view if anything looks odd.

## When to use something else

| You want | Use |
|---|---|
| A root shell, or commands that need a terminal | `sudo`, `sudo-rs` or `run0` |
| SSH, servers, or "this user may run X" rules | `sudo-rs`, `doas` or polkit rules |
| To limit what a root command can touch | `systemd-run` or `run0` with sandboxing options |
| Protection from an agent you don't trust | Run the agent as another user, or in a VM |

## Try it without installing

Development mode runs everything (the window, your password, the snapshot) as
**your own user**, so nothing runs as root. You'll need Rust 1.95 or newer.

```bash
cargo build
target/debug/peekexecd --dev &
export PEEKEXEC_SOCKET=$XDG_RUNTIME_DIR/peekexec-dev.sock
target/debug/peekexec run --why "say hi" -- sh -c 'echo hi && id -un'
```

## Install

Build as your normal user, then run the installer as root:

```bash
cargo build --release --locked
pkexec "$PWD/packaging/install.sh" --admin-group=sudo
```

**`--admin-group` matters.** Every member of that group can use peekexec, and
gets full root with their own password, even if sudoers limits them. If you
leave it out, the installer lists your options and their members, then stops.

Run the installer yourself, from a folder only you can write to. It installs
whatever binaries it finds there, so don't let an agent run it for you: you'd
be shown the install script, not the root service it installs.

To remove peekexec:

```bash
pkexec "$PWD/packaging/install.sh" --uninstall
```

The full list of installed files is in [SECURITY.md](SECURITY.md#what-the-installer-puts-on-your-system).

## Using it from an agent

`peekexec help agents` is the complete guide, written for agents to read. The
commands look like this:

```bash
peekexec run --json --why "..." -- COMMAND          # run a command
peekexec install --json --why "..." FILE /etc/...   # put a file in place, and show it
peekexec script --json --why "..." ./setup.sh       # run a script, and show it
peekexec preview run -- COMMAND                     # see what the human will see
peekexec register --json --name "My Agent" --why "..."   # label your session
```

With `--json`, the agent gets a structured answer: whether it was approved, the
command's output, and your reason if you denied it. An agent can't approve,
pre-approve or skip the window; there's no option for that.

## Learn more

| Read this | For |
|---|---|
| [THREAT_MODEL.md](THREAT_MODEL.md) | What holds against whom, in detail, and why |
| [SECURITY.md](SECURITY.md) | Reporting a vulnerability, what's installed, `unsafe` code |
| [docs/cli.md](docs/cli.md) | The full command-line and JSON reference |
| [PLAN.md](PLAN.md) | Design, architecture and what's planned |
| [docs/review-checklist.md](docs/review-checklist.md) | How security reviews are done |
| [docs/notes/fifth-review.md](docs/notes/fifth-review.md) | The latest review, and what it left open |

To work on peekexec itself:

```bash
cargo test --workspace --features peekexecd/test-approver   # includes end-to-end tests
cargo test -p peekexecd -- --ignored pam                    # real PAM (may count toward lockout)
```

`dev/wayland-vm/README.md` sets up the Ubuntu 24.04 test VM.

## License

MIT OR Apache-2.0
