# NAME
peekexec - see exactly what a program wants to run as root, before you approve it

# SYNOPSIS
```
peekexec run [OPTIONS] -- COMMAND [ARG...]
peekexec script [OPTIONS] FILE [ARG...]
peekexec install [OPTIONS] FILE DEST
peekexec preview run|script|install ...
peekexec submit run|script|install ...
peekexec wait ID
peekexec cancel ID
peekexec register --name NAME
peekexec unregister
peekexec help [agents|schema|man]
```

# DESCRIPTION
When a program asks for root, peekexec shows you what it wants to run: every argument, the full script, or the file being installed. It also shows who is asking and why. You then approve with your password, cancel, or deny with a reason.

It was built for AI coding agents, which often need root for a step or two, but anything can use it. Nothing runs without a person.

**This is pre-alpha software, and no independent expert has reviewed it.** It helps you catch an agent's mistakes. It does not stop an agent that is deliberately trying to get root: see LIMITS.

In a man page viewer, press / and type a section's name to jump to it.

@contents

# THE APPROVAL WINDOW
## What it shows
- What will run: each argument on its own line, the full script with line numbers and colours, or the file being installed, with the changes if it replaces a file.
- Anything hidden: invisible characters, look-alike letters, and long runs of spaces or blank lines are marked.
- Who is asking. Your user id comes from the kernel. Process names are chosen by the processes themselves.
- The reason given, labelled "unverified" because it is only a claim.
- Warnings, such as a file that could make root run something later, or a request that arrived right after another.

## Formatted and Raw
Formatted adds line breaks and indentation so that a long `sh -c` command is easier to read. Raw shows the lines as they are, with long runs of spaces and blank lines still shown as markers. If anything looks odd, use Raw.

## Your choices
- **Approve**: type your password, then press Enter or click Approve (see ENTER OR CLICK).
- **Cancel**: nothing runs. Esc and closing the window do the same.
- **Deny with reason**: your message goes back to the requester.

You have 3 attempts at the password. If nobody answers, the request times out after 120 seconds unless the requester asked for more (`--timeout`, up to 600).

# ENTER OR CLICK
Pressing Enter approves a request only if it is simple enough to judge at a glance. Everything else needs a click on Approve. The bottom of the window says which applies.

Enter works only if all of this is true:
- It is a single `peekexec run` of a program that only reads and reports, such as `ls`, `cat`, `id`, `uname` or `df`, or one of a few everyday commands, such as `systemctl status` or `udevadm control --reload-rules`.
- It has at most 16 words, and no argument holds spaces or shell syntax.
- Nothing in it triggered a warning.
- It did not arrive right after another dialog, with others waiting, or as a near-copy of a recent request.
- You were not already typing when the window opened.

So scripts, installs, `sh -c`, registrations and commands such as `rm` always need a click. This keeps typing aimed at another window from approving anything, and it makes you pause on whatever is more than a look at the system.

# WORKS ON
peekexec only asks for your password somewhere it trusts, so it refuses setups it cannot check.

- **GNOME on Wayland**: you read the request in peekexec's window, click Continue, and type your password into GNOME's own prompt, which repeats the request.
- **GNOME on X11 with GDM**: everything happens in peekexec's window.
- **Wayland with ptrace_scope 0**: refused until you set the sysctl `kernel.yama.ptrace_scope` to 1.
- **Other Wayland desktops, X11 with another login manager, startx**: refused.
- **SSH, no desktop, containers, WSL**: refused. A person must be at a local desktop.

An administrator can allow the refused desktops by starting the daemon with `--allow-unverified-display`. Your password then goes into a window that another program may be able to read.

So far peekexec has been tested on Ubuntu 22.04 and 24.04 only.

## The GNOME prompt
GNOME's prompt cannot scroll, so a request must fit: about 22 lines of 45 characters on a screen 768 pixels tall, warnings included. Longer requests are refused, so split them into steps. An administrator with a larger screen can raise this with `--prompt-lines`.

The prompt's last line starts with **■ END**. **If you do not see that line, part of the request is off screen: cancel.**

In the prompt, `| ` marks a line of the request, `⟨blank⟩` is an empty line, and `⟨U+XXXX⟩` is a character that is not plain ASCII.

# LIMITS
peekexec helps, but do not rely on it for more than this.

- **An agent that wants to cheat, on X11.** Any program running as you can read the password as you type it, then click Approve itself. That includes any program your agent starts. sudo and pkexec have the same weakness.
- **An agent that wants to cheat, on Wayland, if it planned ahead.** A program that can write to your home folder could install a GNOME Shell extension, wait for your next login, and tamper with the prompt. peekexec cannot detect this.
- **Commands that are bad ideas.** An approved command runs as full root. Warnings come from lists of known dangers, and those lists cannot be complete.
- **Files a command reads.** You see `cp ./x /etc/`, not what is inside `./x`, and it can change after you approve. Use `peekexec install`, which shows the content.
- **What a command does while it runs.** `--write` only says what the command claims it will touch; nothing enforces it. `--no-net` stops ordinary programs from using the network, but a root program can undo it.

Also worth knowing:
- The output goes back to the requester. Approving `cat /etc/shadow` hands that file to the agent.
- Commands have no terminal, so interactive programs will not work.
- Anything a command leaves running is ended when it exits. To start a service, use `systemctl start`.
- Stopping or upgrading peekexec ends running commands. The installer waits for them first.
- "From inside an agent's session" means the request came from that agent's process tree. Anything the agent started could have sent it.
- A reason given with `deny_reason` may have been written by another program on X11. Treat it as advice.

# COMMANDS
@commands

# GLOBAL OPTIONS
@global-options

# EXIT STATUS
@exit-codes

# JSON OUTPUT
With `--json`, peekexec prints one JSON object. Always read `status` rather than the exit code. `peekexec help schema` prints the full JSON Schema.

@json-fields

# FOR AGENTS AND SCRIPTS
This is the guide `peekexec help agents` prints.

@agents

# TROUBLESHOOTING
## "cannot connect": only members of the administrator group
You are not in the group chosen at install, or you joined it and have not logged out and back in.

## "cannot reach peekexecd"
peekexec is not installed, or its socket is off. Check with `systemctl status peekexecd.socket`.

## "the display could not be verified" or a refusal about the desktop
See WORKS ON. The error says what it could not check.

## "does not scroll" or "needs N more"
The request does not fit GNOME's prompt. Split it into smaller steps. Each warning takes lines too.

## "the human denied this exact request"
Someone denied the same request in the last hour, so it is refused without asking again. Change the request, or find out why it was denied.

## Status "unknown" (exit 136)
The request went out and no answer came back, so it may have run. Do not send it again. Check what it would have changed.

## A program is "not root-controlled"
`peekexec run` only starts programs that root controls. To run a file you wrote, use `peekexec script`.

## Enter does nothing
That request needs a click: see ENTER OR CLICK.

## Where is the record of what ran?
In the journal: `journalctl -u peekexecd`. Every request that reaches a dialog is there, and an approved one has a line before it starts, with what root resolved it to, and one when it ends.

# INSTALL AND REMOVE
Build as your normal user, from a folder only you can write to, then run the installer yourself as root:
```
cargo build --release --locked
pkexec "$PWD/packaging/install.sh" --admin-group=sudo
pkexec "$PWD/packaging/install.sh" --uninstall
```
Every member of the group named by `--admin-group` can use peekexec, and gets full root with their own password, even if sudoers limits them. Upgrades keep the group. Do not let an agent run the installer for you: you would be shown the script, not the root service it installs.

To try peekexec without installing, start `peekexecd --dev`, which runs everything as your own user.

# FILES
- `/usr/local/bin/peekexec`: this command.
- `/usr/libexec/peekexec/peekexecd`: the daemon, which runs as root and starts on first use.
- `/usr/libexec/peekexec/peekexec-ui`: the approval window.
- `/run/peekexec/peekexec.sock`: the socket, open to the administrator group only.
- `/etc/systemd/system/peekexecd.service` and `peekexecd.socket`: the service.
- `/etc/systemd/system/peekexecd.socket.d/admin-group.conf`: the group chosen at install.
- `/etc/pam.d/peekexec`: how passwords are checked.
- `/usr/share/polkit-1/actions/org.peekexec.approve.policy`: the action behind GNOME's prompt.

# ENVIRONMENT
**PEEKEXEC_SOCKET** names another socket, for a development daemon. Answers from it say `dev_mode`: nothing ran as root, and they are not from a person.

# REPORTING PROBLEMS
Report security problems privately, through GitHub's "Report a vulnerability" on the project, not in a public issue. SECURITY.md in the project says what is in scope.

# SEE ALSO
sudo(8), pkexec(1), run0(1), systemd-run(1), polkit(8)

In the project: README.md for an overview, THREAT_MODEL.md for what holds against whom in detail, and docs/cli.md for the command-line reference.
