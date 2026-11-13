# Sixth review: follow-ups (working list)

Kept on disk so the state survives a long session. Owner's instructions
(2026-11-13): implement, document, review and commit; **do not push until the
owner confirms**. The owner is away, so anything that needs a human or the
real desktop is under "To test when you are back".

## State

All work below is committed on `main`, **not pushed**: 8 commits after
`99f2713`, squashed on 2026-11-13 from 34 working commits (kept on the local
branch `backup/pre-squash-sixth-review`; each of the first seven squashed
commits has the same tree as the tested working commit it ends on). The last
commit then took in four later ones (the `id` exemption, the `Cargo.lock`
bump, the pkexec comparison; kept on `backup/pre-fold-sixth-review`), and
differs from that branch only in these notes. Reinstalled on this machine
from this code (`peekexecd.socket` active; a preview of `ls root` shows the
new root-only note); only notes and docs changed after the install. Local CI passes at the
last code change: `cargo fmt --check`, both clippy runs, `cargo test
--workspace --features peekexecd/test-approver`, the macOS `cargo check`,
shellcheck, `gen-cli-doc.sh` up to date, `cargo deny check` (ok), `cargo
audit` (only its 7 allowed warnings), and the release build with no test
approver in it. Dependencies did not change.

Tested in the Wayland VM (Ubuntu 24.04, GNOME 46, polkit 124) with this
build installed: `dev/wayland-vm/approve-test.sh` passes all five cases
(approve through GNOME's prompt, dismiss, wrong password, deny with reason,
too long), and a disk-naming request shows the disk warning first in both
peekexec's window and GNOME's prompt, which fits and ends with "■ END". The
test's Continue position moved with the new window (now y=700).
Also run through the real helper process: a disk named plainly, bare from
/dev and as `of=` is described, bound, and passes root's `verify`.

## Done

- Review and docs: `a14bbf2` (sixth review; groups that bypass peekexec,
  with sources; overclaims), `d1714e5` (independent docs-vs-code review).
- Disks: `c89f9e5` (by-id names judged as the device; every link hop
  checked; each named disk described: model, size, USB or internal, what is
  mounted, swap, LVM; in use is a warning), `d1714e5` (names bound to the
  disk shown and checked again by root just before running: a decoy with the
  same label, detached after approval, stops the run).
- Path note (I3): `bc5491e` asks "could programs of yours change it?" as the
  user (owner or `access(W_OK)`); fits an image a command only reads; false
  notes gone (`/etc/resolv.conf`, `/run/utmp`, `--cwd /dev`). `d1714e5`:
  `/media/$USER` counts as the user's (udisks mounts there); the user's own
  `/proc/PID` stays theirs; the reader's `/proc/self` does not.
- Enter (I4): `4886cce` a named path the user cannot read needs a click;
  `fca42d6` walks (`ls -R`, `--recursive` by any prefix, `--files0-from`,
  `du` unless an exact total-only form) need a click; `d1714e5` under `/proc`
  only an allowlist of files every reader sees the same keeps Enter.
- Dialog (W1): `7732721` opens at 85% of the monitor (at most 1500 points
  wide), centred, resizable; warnings at reading size in a box with a count,
  repeated in the footer; disk warnings first. Rendered on Xvfb at 800x600,
  1280x720, 1366x768, 1920x1080.
- Notes quote requester words plainly (`d1714e5`).
- After the advisor's end check, in the last commit ("End-check fixes, VM
  and desktop results"): reader's own /proc decided on components; naming a
  disk always takes a click, no root-only note for a disk, so a disk-to-disk
  copy fits GNOME's prompt; disk warnings stay first after later notes;
  virtio "0x1af4" is no model; VM test positions; `id root` keeps Enter;
  Yama-guarded tests; sources and pointers; only a directory in / is read as
  a name (`cat swapfile` still takes a click). After the squash, automated
  reviews found `ls root` (in /, so /root) kept Enter: a directory in / is
  now a name only for `id`, judged by both the name asked for and the file
  it leads to (a link named `id` to `ls` is not `id`). Also folded in:
  `async-executor` 1.14.0 was yanked, so `Cargo.lock` takes 1.14.1, and
  [pkexec-comparison.md](pkexec-comparison.md), pkexec's source read against
  peekexec.
- Final review by two independent agents: docs vs code (all fixed) and a code
  bypass pass, tested live, whose findings B1-B6 are fixed; its five tests are
  in the tree as `bypass_*`. B7 (what "in use" cannot see: a VM's open disk,
  ZFS members, a second btrfs device, other mount namespaces) is documented in
  THREAT_MODEL.
- Every working commit was also read by an automated security review; each
  finding was fixed or answered in the working commit that followed (now
  folded into the squashed commits above).

## Known limits left as they are

- Root does not re-check the helper's disk descriptions or notes (rule 1);
  the bindings it does re-check are limited to names the request uses.
- `du DIR` totals include root-only subdirectories (`du -sh` keeps Enter).
- A disk named by a computation in a script (`/dev/sd$x`) or a glob is not
  described.
- `ROOT_GROUPS` still flags adding someone to `kvm` or `shadow` (cautious).

## To test when you are back (needs a human or the real desktop)

- [x] Installed (2026-11-13) with `cargo build --release --locked`, then
      `pkexec "$PWD/packaging/install.sh" --admin-group=sudo`. On the real X11
      desktop, approved: one plain `run` (`lsblk -f`), one script (names both
      disks: two disk notes), one install (`/usr/local/share/peekexec-install-test.txt`,
      root 644). All exit 0. Leftover test file to remove.
- [ ] The new window on your real screen(s), with a real window manager (Xvfb
      has none): opens large and centred, can be resized, moved, and left
      (no grab). Also on a HiDPI screen if you have one. In the Wayland VM it
      fills most of the 1024x768 screen (seen, fine).
- [ ] A disk warning: `peekexec run --why test -- lsblk /dev/nvme0n1` needs a
      click and says "in use: / (on vgubuntu-root), ...".
- [ ] A USB stick plugged in, not mounted: `peekexec run --why test -- lsblk
      /dev/disk/by-id/usb-...` names it ("USB disk ...", "nothing on it is
      mounted or swap") and needs a click (naming a disk always does).
- [ ] Enter still works for an everyday read: `peekexec run --why test --
      lsblk -f`, password, Enter.
- [ ] Your account has `docker`, `lxd`, `libvirt` (README "Your account's
      groups"): decide whether to keep them.
- [ ] Then confirm the push.
