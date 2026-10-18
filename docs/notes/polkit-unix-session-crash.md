# polkitd aborts on a `unix-session` subject

Found on 2026-10-18 while testing the Wayland approval path. Not reported yet:
check it more carefully before deciding on a report (private to the polkit
maintainers if it holds).

## What happens

A `CheckAuthorization` call whose subject is `unix-session` makes polkitd hit
an assertion and abort (SIGABRT, core dump). systemd marks `polkit.service`
failed. The next D-Bus call to polkit activates it again, so on our machines
it came back after a few seconds, but every polkit prompt fails until then.

```
polkit_unix_process_get_pidfd: assertion 'POLKIT_IS_UNIX_PROCESS (process)' failed
ERROR: polkitbackendsessionmonitor-systemd.c:391:polkit_backend_session_monitor_get_session_for_subject: assertion failed: (process != NULL)
```

## Where we saw it

| System | polkit | Caller | Result |
|---|---|---|---|
| Ubuntu 22.04 (host) | 0.105 (Ubuntu fork) | root | polkitd aborted |
| Ubuntu 24.04.5 (VM) | 124 | root | polkitd aborted |
| Ubuntu 24.04.5 (VM) | 124 | unprivileged user | polkitd aborted |

The same request with a `unix-process` subject (pid + start-time + uid) works.

## Minimal reproduction (in a VM only)

```bash
gdbus call --system --dest org.freedesktop.PolicyKit1 \
  --object-path /org/freedesktop/PolicyKit1/Authority \
  --method org.freedesktop.PolicyKit1.Authority.CheckAuthorization \
  "('unix-session', {'session-id': <'1'>})" org.freedesktop.policykit.exec "{}" 0 ""
systemctl is-active polkit      # -> failed
```

## Known?

Ubuntu Launchpad bug #1562721 (2016, policykit-1 on 16.04) reports the same
assertion and is still open:
https://bugs.launchpad.net/ubuntu/+source/policykit-1/+bug/1562721

## Before reporting, check

- Whether current upstream polkit (main) still asserts; the `get_session_for_subject` path in
  `src/polkitbackend/polkitbackendsessionmonitor-systemd.c`.
- Whether systemd's restart behaviour on the affected distributions turns this
  into a lasting denial of service (Ubuntu: `failed`, no automatic restart;
  D-Bus activation restarts it on the next call).
- Whether other subject kinds (`system-bus-name` for a gone name) trigger it.

## Impact on peekexec

None on the current X11 path. The Wayland path (polkit prompt) must use a
`unix-process` subject, never `unix-session`.
