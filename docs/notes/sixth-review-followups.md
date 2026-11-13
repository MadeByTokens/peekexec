# Sixth review: follow-ups (working list)

Kept on disk so the state survives a long session. Owner's instructions
(2026-11-13): implement, document, review and commit; **do not push until the
owner confirms**. The owner is away, so anything that needs a human or the
real desktop is under "To test when you are back".

## State

All work below is committed on `main` (25 commits after `99f2713`), **not
pushed**. Local CI passes at the last code commit: `cargo fmt --check`, both
clippy runs, `cargo test --workspace --features peekexecd/test-approver`,
the macOS `cargo check`, shellcheck, and `gen-cli-doc.sh` up to date
(dependencies did not change, so `cargo deny` and `cargo audit` are as at
`99f2713`).

## Done

- Review and docs: `ba2c453` (sixth review), `b5bada8` (groups that bypass
  peekexec, with sources; overclaims), `8d2fdd7` and `eb81515` (independent
  docs-vs-code review).
- Disks: `f01a66a` (by-id names judged as the device), `714e9de` (every link
  hop checked), `68d78a9` (each named disk described: model, size, USB or
  internal, what is mounted, swap, LVM; in use is a warning), `031cddf`,
  `d30a98c`, `e846d9f` (names bound to the disk shown and checked again by
  root just before running: a decoy with the same label, detached after
  approval, stops the run).
- Path note (I3): `b4a5d7a` asks "could programs of yours change it?" as the
  user (owner or `access(W_OK)`); fits an image a command only reads; false
  notes gone (`/etc/resolv.conf`, `/run/utmp`, `--cwd /dev`). `efd90b3`:
  `/media/$USER` counts as the user's (udisks mounts there). `61e78fe`: the
  user's own `/proc/PID` stays theirs; the reader's `/proc/self` does not.
- Enter (I4): `a239d0e` a named path the user cannot read needs a click;
  walks (`ls -R`, `--recursive` by any prefix, `--files0-from`, `du` unless an
  exact total-only form) need a click (`4561498`, `6299c1e`, `d3b4e24`,
  `e8a3484`); under `/proc` only an allowlist of files every reader sees the
  same keeps Enter (`397057e`, `704b1e2`).
- Dialog (W1): `12fde9d` opens at 85% of the monitor (at most 1500 points
  wide), centred, resizable; warnings at reading size in a box with a count,
  repeated in the footer; disk warnings first. Rendered on Xvfb at 800x600,
  1280x720, 1366x768, 1920x1080.
- Notes quote requester words plainly (`b26124d`).
- Final review by two independent agents: docs vs code (all fixed) and a code
  bypass pass, tested live, whose findings B1-B6 are fixed; its five tests are
  in the tree as `bypass_*`. B7 (what "in use" cannot see: a VM's open disk,
  ZFS members, a second btrfs device, other mount namespaces) is documented in
  THREAT_MODEL.
- Every commit was also read by an automated security review; each finding
  was fixed or answered in the commit that followed.

## Known limits left as they are

- Root does not re-check the helper's disk descriptions or notes (rule 1);
  the bindings it does re-check are limited to names the request uses.
- `du DIR` totals include root-only subdirectories (`du -sh` keeps Enter).
- A disk named by a computation in a script (`/dev/sd$x`) or a glob is not
  described.
- `ROOT_GROUPS` still flags adding someone to `kvm` or `shadow` (cautious).

## To test when you are back (needs a human or the real desktop)

- [ ] Install the build (`cargo build --release --locked`, then
      `pkexec "$PWD/packaging/install.sh" --admin-group=sudo`) and approve one
      plain `run`, one script, one install, on the real X11 desktop.
- [ ] The new window on your real screen(s), with a real window manager (Xvfb
      has none): opens large and centred, can be resized, moved, and left
      (no grab). Also on a HiDPI screen if you have one, and in the Wayland VM
      (the compositor places windows there).
- [ ] A disk warning: `peekexec run --why test -- lsblk /dev/nvme0n1` needs a
      click and says "in use: / (on vgubuntu-root), ...".
- [ ] A USB stick plugged in, not mounted: `peekexec run --why test -- lsblk
      /dev/disk/by-id/usb-...` names it ("USB disk ...", "nothing on it is
      mounted or swap") and needs a click (you are not in `disk`).
- [ ] Enter still works for an everyday read: `peekexec run --why test --
      lsblk -f`, password, Enter.
- [ ] Wayland VM (`dev/wayland-vm/approve-test.sh --install`): the desktop
      prompt carries the disk line and still fits (22 lines).
- [ ] Your account has `docker`, `lxd`, `libvirt` (README "Your account's
      groups"): decide whether to keep them.
- [ ] Then confirm the push.
