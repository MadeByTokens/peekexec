![peekexec: see it before you approve it](docs/header.png)

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
- **Which disk is which.** Every disk the command names (`/dev/sdb`,
  `/dev/disk/by-id/...`) gets a line saying what it is: its model, size, USB or
  internal, and what's mounted on it. A disk that's in use, such as the one
  holding `/`, gets a warning, so a `dd of=/dev/sda` meant for a USB stick
  stands out. Naming a disk at all needs a click unless you could read it
  yourself (members of `disk` can). The model is the device's own claim; the
  size and the mounts come from the kernel.

Then you choose:

- **Approve** with your password. What runs is what you were shown: scripts
  run from a private copy, so editing the file afterwards changes nothing.
- **Cancel.** Nothing runs.
- **Deny with a reason.** Your message goes back to the agent, so you can say
  "use the vendor's rules file instead".

**Enter or click?** A plain read-only command such as `ls`, `id` or `df` can be
approved with your password and Enter, as long as every file it names is
one you could read yourself, and it doesn't walk into directories below
them (`ls -R`, `du` other than `du -sh`). So can a few everyday ones that
re-apply system settings, such as `udevadm control --reload-rules`,
`udevadm trigger` (which replays device events, so rules run again) and
`systemctl daemon-reload`. Everything else needs a click on Approve:
scripts, installs, `sh -c`, other commands that change the system, anything
with a warning, and any request that arrives right after another. The bottom of the
window says which applies. This stops typing aimed at another window from
approving anything, and makes you pause on what matters.

## Will it work on my desktop?

peekexec only asks for your password somewhere it trusts, so it refuses to run
on setups it can't check.

| Your desktop | What happens |
|---|---|
| **GNOME on Wayland** | Works. You read the request in peekexec's window, then type your password into GNOME's own prompt, which repeats the request. Requests must be short (see below). |
| **X11 started by GDM** (tested with GNOME; other desktops on GDM's X11 pass the same check, but are untested) | Works. Everything happens in peekexec's window, but any program running as you can see what you type there. |
| **GNOME on Wayland with `ptrace_scope` set to 0** | Refused until you run `sysctl kernel.yama.ptrace_scope=1`, because your own programs could attach to GNOME Shell (unless GNOME Shell makes itself non-dumpable, which it normally doesn't). Some distributions may default to 0. |
| **KDE, Sway, other Wayland desktops** | Refused. |
| **X11 with another login manager** (LightDM, SDDM), `startx` | Refused. |
| **SSH, no desktop, containers, WSL** | Refused, with one exception: if you're also logged in at an X11 desktop started by GDM, a request sent over SSH opens its window there, and you approve it at that desktop. |
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
  shows you the content. For an image you flash (`dd if=/home/me/fw.img`),
  that's expected: the window notes that programs of yours can change the
  file, so compare its checksum first if it matters.
- **What a command does while it runs.** `--write` only tells you what the
  command says it will touch; nothing enforces it. `--no-net` stops the command
  itself from using the network. It doesn't stop a system service from using
  the network on the command's behalf (`systemctl start`, `snap`, a package
  manager's daemon), and a program running as root can undo it.
- **Your screen settings, on Wayland.** GNOME's prompt can't scroll. If you
  don't see the line starting with **■ END**, part of the request is off
  screen: cancel it.
- **Groups that already give your account root, or your keystrokes.** If
  you're in `docker`, `lxd`, `incus-admin`, `libvirt` or `disk`, any program
  running as you, your agent included, can get root without asking
  peekexec. If you're in `input`, it can read every key you type, your
  password too. See [Your account's groups](#your-accounts-groups) below.

Some other things worth knowing:

- **The output goes back to the agent.** If you approve `cat /etc/shadow`, the
  agent receives it. So a command that names a file you couldn't read
  yourself (`/etc/gshadow`, your Wi-Fi passwords, a raw disk) gets a warning
  and needs a click.
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
  for them first, on systems with cgroup v2; on others it says it can't.

If you're not sure how much to trust it, read every script in full, and switch
to the **Raw** view if anything looks odd.

## Your account's groups

People who work with hardware often add themselves to groups, so their tools
work without root. Most of these are fine. A few give away root, or your
keystrokes, to every program you run. Your agent is one of those programs, so
with those groups peekexec's window is no longer what stands between it and
root. Run `id -nG` to see your groups.

| Access | What any program running as you can do |
|---|---|
| `docker`, `lxd`, `incus-admin`, `libvirt`, `disk` | **Get root, with no password.** It can start a container or virtual machine with your disk mounted inside, or write to the raw disk. |
| `input` | **Read every key you type,** your password included, on X11 and Wayland alike, and in GNOME's prompt too. |
| Write access to `/dev/uinput` | **Type and click as you.** It can't read your password, but once you've typed it, it can press Enter for you. So read the request *before* you type your password. This access often comes from a udev rule rather than a group (Solaar's, for example), so `id` won't show it. Check with `getfacl /dev/uinput`. |
| A sudoers rule with `NOPASSWD` | **Get root, with no password,** through `sudo`. Being in `sudo` or `wheel` is fine: sudo asks for your password, just as peekexec does. Check with `sudo -l`, which lists any `NOPASSWD` entries. |
| `shadow`, `adm`, `systemd-journal`, `wireshark` | No root, but it can read things worth hiding: password hashes, logs that may hold tokens, all network traffic. |
| `kvm` | No root. It runs virtual machines at full speed. peekexec warns when a command adds someone to it, which is more cautious than it needs to be. |
| `dialout`, `uucp`, `dip`, `plugdev`, `cdrom`, `i2c`, `spi`, `gpio`, `bluetooth`, `lp` | Fine. These let you talk to devices: serial ports, dial-up, USB devices, removable disks, buses. A mistake can still damage a device (by overwriting its EEPROM, for example), but these groups don't give root or reveal your password. |

If you're in a group from the first two rows, you can:

- leave it: `sudo gpasswd -d $USER docker`, then log out and back in;
- use rootless alternatives: Podman or rootless Docker, or libvirt's
  `qemu:///session`;
- or keep it, knowing that peekexec still catches your agent's *mistakes*, but
  can't stop an agent that is trying to get root.

Sources, checked on 2026-11-13:

- Docker: ["The `docker` group grants root-level privileges to the user"](https://docs.docker.com/engine/install/linux-postinstall/).
- LXD: local socket access ["always grants full access"; give it only to users "you'd trust with root access"](https://canonical.com/lxd/docs/latest/explanation/security/).
- Incus: [`incus-admin` "can fully control Incus"](https://linuxcontainers.org/incus/docs/main/explanation/security/); the [`incus` group "will only grant access to the Incus user socket"](https://linuxcontainers.org/incus/docs/main/installing/).
- libvirt: a connection to the system daemon's read-write socket ["gives the client privileges that are equivalent to having a root shell"](https://libvirt.org/daemons.html).
- Debian's [list of system groups](https://wiki.debian.org/SystemGroups): `disk` is "mostly equivalent to root access"; `dialout` gives "full and direct access to serial ports"; `shadow` can read `/etc/shadow`.
- Kernel docs: [uinput](https://www.kernel.org/doc/html/latest/input/uinput.html) "makes it possible to emulate input devices from userspace". systemd docs: on a device tagged [`uaccess`](https://www.freedesktop.org/software/systemd/man/latest/sd-login.html), "access to this device is tied to an active seat".
- `input`: on Ubuntu, `/dev/input/event*` is mode 0660, group `input`.

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
command's output, and your reason if you denied it. There's no option to
approve, pre-approve or skip the window (on X11, see
[What it won't protect you from](#what-it-wont-protect-you-from)).

## Learn more

Once installed, `man peekexec` covers everything about using it, including
troubleshooting.

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

`dev/wayland-vm/README.md` sets up the Ubuntu 24.04 test VM. To change the man
page, edit `crates/peekexec/src/manual.md` and run `scripts/gen-cli-doc.sh`: its
commands, options and exit codes come from the code, and a test fails if the
page goes stale.

## License

MIT OR Apache-2.0
