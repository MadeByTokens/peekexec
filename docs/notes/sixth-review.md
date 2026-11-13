# Sixth review (2026-11-13, commit 99f2713): does it live by its philosophy?

Review only: no code changed. The question was not "find more holes" but "is
peekexec as safe as the idea allows?" A root daemon that runs what an agent
asks cannot be intrinsically safe; the test is whether each remaining risk is
**(A) intrinsic** to the idea, **(B) closable only by planned work** (E12
console approval, E14 transient units), or **(C) closable now**. Bucket C is
where the project falls short of its own philosophy.

Method. Since the fifth review's bypass pass (221e528) the daemon and the
dialog are unchanged. What changed: the client crate (`help man`, help item
10, doc comments in `peekexec-proto`), CI checking the man page, and
`install.sh` installing the man page from its staging copy (read: no new root
behaviour beyond one `install -d` and one `install`). The installed binaries
date from 7e431b3; only README and an image changed after it (by file times,
not hashed). Work done: the fifth review's `prepare.rs` test hunks re-run at
HEAD (the other hunks no longer apply); probes of the installed daemon with
`preview` (no password, no dialog); one reviewer checking README, man page,
`help agents` and SECURITY.md against the code; one inventory of what root
does before approval. Evidence: **run** = probed or tested; **read** = code
only, spot-checked.

## Verdict

Carried over from the fifth review, not re-hunted here: no path that runs a
request without a human, gives a non-administrator root, or attaches an
approval to another request. The re-run `prepare.rs` tests pass, except two
that fail only because the fix now refuses outright.

The philosophy is mostly honoured, and the docs are unusually candid. Where it
falls short, in order:

## 1. Enter approves disclosure of root-only data (run, new class)

The Enter allowlist (`prepare.rs:383`) is "programs that only read and report",
and THREAT_MODEL:399-402 already says the output goes back to the requester
(`cat /etc/shadow`). Yet the two were never put together: for this tool,
**reading is the harm**. On the installed daemon `preview` reports
`enter_approves: true`, no notes, for:

- `cat /etc/gshadow`
- `cat /etc/NetworkManager/system-connections/<wifi>.nmconnection` (Wi-Fi keys)
- `cat /proc/1/environ`
- `cat /etc/ssl/private/ssl-cert-snakeoil.key` (a directory the user cannot even enter, see 1b)
- `cat /dev/sda`, `head -c 64 /dev/mem` (raw devices; with `tail -c +N`, any
  16 MiB of the disk per request: read, not run)
- `ls /root`, `du /root`; recursive forms (`ls -R /etc`, `du /etc`) reach
  unreadable subdirectories even when the argument itself is readable.

`/etc/shadow` and `/root/.ssh` are flagged only by accident, because they are on
the "runs as root later" list.

Severity: the password is still typed and the command is on screen. What is lost
is the click that forces a pause, on exactly the requests whose effect, a secret
handed to the agent, cannot be undone.

**New class: "read-only taken as harmless" when the output reaches the
requester.** The checklist has no column for "returned to the requester", and
none for Enter (the fifth review asked for one). Add both.

Fix (R1, structural, not another denylist): Enter only when the user could do the same
without root, i.e. every path argument is readable by the user (the helper already looks at each as the user),
no device nodes, and no recursion flags on a list program. Otherwise a click, and a note: "root-only content
goes back to the requester". "The helper cannot tell" means no Enter. The fast path
the owner asked for stays for `id`, `df`, `lsblk`, `uptime`, `systemctl status`.
Bucket C.

### 1b. "A path the user cannot reach is refused" holds only for some paths (run)

THREAT_MODEL:39 says so in general. `trust::check_named` (`trust.rs:121-127`)
skips every component it cannot stat (`Err(_) => {}`), so an argument under a
directory the user cannot enter gets no note and no refusal. The rule holds for
the program, the cwd and install targets, not for paths named in arguments or
script text. The same EACCES is the signal §1 needs: keep "does not exist yet"
apart from "the user may not look", and turn the second into a note that disables Enter.

## 2. Root work before approval that need not be (read, R1/R7)

| Item | Where | Bucket |
|---|---|---|
| Script snapshot (up to ~32 MiB of requester bytes in /run) written in `prepare`, before approval, and before the "no display" refusal | `prepare.rs:166`, `server.rs:990` vs `:994` | C: write it after `Approved` |
| `identify` walks up to 64 ancestors as root **before** the admin check, the slot cap and reading the message | `server.rs:275` vs `:288`, `:306` | C: uid → admin → slot, then walk |
| The walk has no uid filter: for a root ancestor (sshd, gdm-session-worker) root reads its `exe` link, which the user cannot read, and Preview returns it. Low (the path is usually guessable), but it contradicts R1's "reads only the requester's own" | `peer.rs:185-199`, `:225` | C: stop at the first ancestor of another uid |
| Preview runs the full display scan, polkit/logind/bus calls and the gnome-shell maps check; unlogged, no pending cap | `server.rs:598-640` | C: decide those at submit |
| exe identity and trust checks of a requester-influenced path done as root, result in Preview | `peer.rs:172`, `prepare.rs:1509` | C: in the helper |
| `verify()` re-checks program/interpreter/install dir by name, no timeout | `inspect.rs:203-279` | C: by the helper's descriptors, as cwd already is |
| Diff with the previous request computed under `prompt_lock`, no size cap or deadline | `prepare.rs:1454`, `server.rs:1037` | C: cap lines |
| Display fallback reads `/proc/*/environ` as root | `session.rs:24-40` | C (small): in the helper |
| Display verification, polkit pre-checks, PAM | `display.rs`, `polkit.rs` | A |

THREAT_MODEL does not mention the snapshot before approval, preview's probing,
root's environ reads or root-side exe stats.

## 3. Open items that are just unfinished (bucket C)

- C10c: the trusted chain checks nosuid, not the filesystem type (`trust.rs:145`);
  a non-nosuid nfs/cifs mount passes.
- C10d: the dialog reader's `BufReader` buffer is not wiped (`prompt.rs:121`).
- D11a/c/d/e: install.sh inside the service, pinned toolchain, `forbid(unsafe_code)`,
  schemars out of the daemon.
- M4, M5, M9 still unpinned (need a harness around the client or the queue).
- Queued requests from clients that left keep their slot until their turn (cancel is
  read only after `prompt_lock`); writing Show has a per-write timeout, not a total one;
  polkit deadline, read deadline and TTLs use `Instant`, which stops in suspend.
- Dialog stderr is read with `lines()` before the cut (`prompt.rs:108`).

## 4. The deployment can make peekexec moot (run)

The account on the dev host is in `docker`, `lxd` and `libvirt`. Each is root in all but name,
with no password. Any agent running as that user has root without asking
peekexec. The daemon already keeps `ROOT_GROUPS` (`prepare.rs:1064`) to flag
requests that *add* someone to them, but it never checks whether the
**requester** is already in one. In the spirit of honest tiers: say so in every
dialog and every answer ("this user is already root-equivalent through docker"),
warn in `install.sh` and in the README. Bucket C, and the cheapest real gain in
this review.

## 5. The biggest gap the idea allows closing: X11 (B)

On X11, the default working tier, any program of the user's can read the password and
click Approve. README states this honestly. The only fix is a prompt outside the user's
session (E12 console/VT), but PLAN.md scopes E12 as the default only on unverified
displays and opt-in elsewhere. Make it available on X11 (an option at install, or
for requests that need a click), and state that as E12's goal.

## 6. Docs that claim more than the code (read)

Where README, man page or `help agents` differ from THREAT_MODEL, the code matches THREAT_MODEL.

- README:54, help.rs:121: "Everything else needs a click … anything that changes the
  system". But Enter approves `udevadm control|trigger|settle` and `systemctl
  daemon-reload` (`prepare.rs:389`). Fix the wording or the list.
- README:71, manual.md:66: "SSH … Refused". On X11 the verified X server is used whatever the
  requester's session (`session.rs:23`), so a request sent over SSH appears on the
  local desktop. A human still approves; this is a wording fix. (The Wayland
  session rule exists because polkit picks the agent by session; X11 has no such
  mechanism to protect.)
- THREAT_MODEL:39: "a path the user cannot reach is refused". Only for some paths (§1b).
- help item 3: `dev_mode: false` presented as proof that the root daemon answered;
  THREAT_MODEL says a `peekexec` earlier in PATH can forge it. The conclusion ("may
  only narrow") is right; the premise is not.
- README:100, manual.md:86: `--no-net` "stops ordinary programs": ordinary tools that
  work through a system service (snap, `systemctl start`, packagekit) still reach the
  network (`sandbox.rs:12-15` says so; the docs don't).
- README:119: "the installer waits": not without cgroup v2, and the socket stays up,
  so a request approved after the wait is still killed.
- Minor: README:68's ptrace_scope row is stricter than the code (a non-dumpable shell
  passes); README:67/69 X11 means any GDM X11 session, not only GNOME; README:185
  "an agent can't approve" reads oddly next to README:85 (say "there is no option
  to"); help lists the `kernel` level, which is never produced.

Accurate: test-approver exclusion, dev mode, the polkit no-ask refusal, the Enter
conditions, snapshots, the 22-line rule, installer behaviour, and the `unsafe` counts in all ten files.

## Suggested order

1. §1 and §1b: Enter only for what the user could read anyway; EACCES becomes a note.
2. §4: say when the requester is already root-equivalent.
3. §6: doc fixes (cheap; honesty is the product).
4. §2: snapshot after approval; identify reordered and uid-bounded; preview without probing.
5. §3 leftovers; then E12 with X11 in scope.

## Second pass (same day): re-rated for the people it is for

The owner's framing: peekexec is for people automating hardware work (flashing a
device, recovering a disk, bringing an old device back to life), who trust their
agent with that work anyway. So look for real safety holes without being
paranoid. Each finding was asked: who must the adversary be (a mistaken agent,
an injected one, or a same-user program that already wins on X11)? What does the
human see at approval? What would the fix cost a flashing or recovery job?

### Promoted: the wrong disk (run, new)

The classic hardware disaster is an agent writing to the system disk instead of
the target. On the installed daemon, `wipefs -a /dev/sda`, `mkfs.ext4 /dev/sda1`
and `dd if=/dev/zero of=/dev/sda1`, where sda is a mounted disk (on this host
the backup disk; the system disk is nvme0n1, see the fixes below), get **no
note at all**. `dd if=x.img of=/dev/sda` gets only the generic note about the image
file. The human sees `/dev/sda` and must remember which disk that is.

Fix, as a description rather than a list of dangerous commands: for every block
device a request names, the helper (as the user: `/sys/class/block`,
`/proc/self/mountinfo`, all readable) adds one line saying what it is: model,
size, removable or not, and **"holds / (mounted)"** or "mounted at X" or "not
mounted". A mounted target turns Enter off. This fits the README's promise ("it
helps you catch an agent's mistakes") better than anything else here.

### New: naming a disk the safe way is flagged, the risky way is not (run; cause read)

`/dev/disk/by-id/...`, `/dev/disk/by-uuid/...` and `/dev/mapper/...` get "Names X,
which root does not control", while plain `/dev/sda` gets nothing.
`check_named` skips a device node's own mode on purpose (`trust.rs:122`). A
symlink to one, though, goes through `check_with`, which reads the node's `0660`
group-write bit as "writable by others" (`trust.rs:156`). Fix: judge a device
reached through a link the same way as one named directly.

### New: note fatigue on firmware images (run)

`dd if=~/fw.img of=/dev/sdb` and similar always get "Names ~/fw.img, which root
does not control … use `peekexec script` … `peekexec install`". The warning is
true (the image can change after approval), but its advice does not fit an input
file, and it fires on every flashing job, which teaches people to skip notes. Reword it
for files a command *reads*, e.g. "its content is not shown and can change after
approval", and keep the install/script advice for files that run.

### Kept, lower: Enter and root-only reads (§1, §1b)

Adversary: an injected agent. The human sees `cat /etc/NetworkManager/…` in plain
text and types a password, so this is low-medium. The fix still costs hardware
work little. Previewed, under "Enter only when the user could read every named
path":

- keeps Enter: `lsusb -v`, `lsblk -f`, `cat /proc/mtd`, `ls /dev/serial/by-id`,
  `stat /dev/ttyUSB0`, `cat /sys/class/power_supply/BAT0/uevent`;
- loses Enter: `head -c 512 /dev/sda` (a raw disk read: one click);
- already takes a click: `cat /sys/kernel/debug/usb/devices`, `dmesg`,
  `udevadm info -a`.

Worth doing, after the disk items. §1b turns into a THREAT_MODEL wording fix plus the
EACCES signal that §1 needs.

### Downgraded to docs only: root work before approval (§2)

Only members of the administrator group can connect, and the adversary would be a
program of the user's own, which already wins on X11. The snapshot is removed on
every path that ends without approval (`server.rs:995`, `:1007`, `:1099`; startup
sweep `main.rs:129`; release builds abort on panic). So: correct THREAT_MODEL's R1
sentence (ancestors of any uid are read; the snapshot is written before approval;
preview probes the display) and leave the code. Optional: cap the comparison diff,
which can hold `prompt_lock`.

### Kept as is

- §6 doc fixes: still true. For `udevadm`/`daemon-reload`, fix the wording, not
  the list: those are everyday hardware steps.
- §5 X11/E12: roadmap, not urgent for this audience.
- §3: C10c dropped (an nfs mount in a root chain on a single-seat desktop is rare);
  C10d, D11, `Instant` stay as low hygiene.

### §4, the account's groups: documented

Done in README ("Your account's groups"), THREAT_MODEL ("The account's own
groups"; tier 2 and tier 3 lines qualified) and the man page's LIMITS. Facts behind
it (run, on this host): the user is in `docker`, `lxd`, `libvirt`; `sudo -n true`
asks for a password; `/dev/uinput` is writable by the seat user through Solaar's
`uaccess` rule (`/lib/udev/rules.d/60-solaar.rules`), invisible to `id`. Not tested:
whether uinput input reaches a VT (matters for E12). Small code follow-up:
`ROOT_GROUPS` lists `incus`, but the root-equivalent Incus group is `incus-admin`
(`incus` is the restricted one).

### Revised order

1. The wrong disk: describe each block device named, Enter off for a mounted one.
2. The by-id false note (one-line class fix) and the reworded image-file note.
3. §6 doc fixes; THREAT_MODEL R1 wording (§2); `ROOT_GROUPS` incus-admin.
4. §1: Enter only for what the user could read.
5. Hygiene: C10d, D11, `Instant`, diff cap.

## Docs corrected (same day)

The §6 overclaims and §1b/§2 wording are fixed in README, the man page,
`help agents` and THREAT_MODEL. The checklist got ⚠ rows (since turned ✓, except §4) for §1, §1b, §4 and the
block-device findings. The group facts cite primary sources (Docker, LXD, Incus,
libvirt, Debian's SystemGroups, kernel and systemd docs), quoted verbatim and
checked on 2026-11-13; the list is in README "Your account's groups". Code
references in the docs name functions (`trust::check_named`, `peer::walk`,
`session::find`), not line numbers, so they go stale less quietly. The line numbers
in this note refer to commit 99f2713.

## Fixes after the second pass

- In `c89f9e5`: a device reached through a link is judged as the device, so
  `/dev/disk/by-id/...`, `by-uuid` and `/dev/mapper/...` lose the false note.
- Also in `c89f9e5`: every link a name leads through is checked, closing an
  older gap (a root-owned link to a user's link) that judging links as
  devices had made reachable. Raised by an automated review of that step.
- Disks described (`blockdev.rs`): run on this host with `preview` against a
  dev daemon, which reported
  `/dev/nvme0n1: internal disk "KBG30ZMS512G NVMe TOSHIBA 512GB", 512.1 GB;
  in use: / (on vgubuntu-root), /boot/efi (on nvme0n1p1), swap (on
  vgubuntu-swap_1).`, and on Xvfb for the dialog. Seen there: every note is
  drawn in small text, the disk warning included (fixed later in `7732721`).
- An automated review of the disk commit raised three points: (1) root does
  not re-check the helper's description: accepted, like the other notes, and
  stated in THREAT_MODEL; (2) `--cwd /dev` with a bare `sda` or `of=sda` was
  missed: fixed; (3) the requester's name led the line: the kernel's `/dev`
  name and facts now lead, the name used comes last, plain and cut. A second
  pass found that checking every word let a long script use up the 1000-word
  bound before naming a disk: now only distinct words count, and past the
  bound a note says disks after it were not looked for.
- Found then, fixed later in `bc5491e`: `/etc/resolv.conf` (owned by
  systemd-resolve) and `/run/utmp` (group-writable) got "root does not
  control" notes, and `--cwd /dev` was called a nosuid mount "for a user".
- Later work (items 3, 4, the window, the walk rules, the final review) is
  tracked in [sixth-review-followups.md](sixth-review-followups.md).
