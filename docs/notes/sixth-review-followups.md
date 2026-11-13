# Sixth review: follow-ups (working list)

Kept on disk so the state survives a long session. Owner's instructions
(2026-11-13): implement, document, review and commit; **do not push until the
owner confirms**. The owner is away, so anything that needs a human or the
real desktop goes under "To test when you are back".

## Done (committed, not pushed)

- `ba2c453` sixth review note; `b5bada8` docs: groups, overclaims.
- `f01a66a` by-id links judged as the device; `714e9de` every link hop checked.
- `68d78a9` disks described (`blockdev.rs`); `031cddf` kernel name first, bare
  names; `d30a98c` fail closed past the word bound.

## In progress / next

- [x] W1 Dialog opens at 85% of the monitor (width at most 1500 points,
      min 560x420), centred from the size asked for; warnings in a framed box
      at reading size with a count, repeated in the footer; disk warnings
      first (sorted in the daemon, so the desktop prompt agrees). Rendered on
      Xvfb at 800x600, 1280x720, 1366x768, 1920x1080: centred, fits, and at
      800x600 the box scrolls while the footer keeps the count.
- [x] I3 The path note asks "could programs of yours change it?" (as the
      user, by the kernel: owner or `access(W_OK)`, groups and ACLs), not
      "does root own it?"; wording fits an image a command only reads. Gone:
      the `/etc/resolv.conf`, `/run/utmp` and `--cwd /dev` false notes. The
      helper's cwd warning now uses root's by-descriptor check, so dev
      previews match production.
- [x] I4 A path named that the user cannot read or reach without root gets a
      note (`inspect::root_only`), so a click; raw disks follow from the same
      rule. Everyday hardware reads keep Enter (lsusb -v, lsblk -f,
      /proc/mtd, /dev/serial/by-id, sysfs). Docs updated.
- [x] Docs for all of the above (README, man page via manual.md +
      gen-cli-doc.sh, help agents, THREAT_MODEL, checklist).
- [x] `4561498` Enter: no walks (ls -R, du -a, --files0-from), from an
      automated review of the root-only change.
- [ ] Final review: two independent agents (code bypass; docs vs code) on
      99f2713..HEAD, started 2026-11-13. Findings go below.
- [ ] Final review / bypass pass on everything since 99f2713.
- [ ] Ask the owner before `git push`.

## To test when you are back (needs a human or the real desktop)

- [ ] Install the build (`packaging/install.sh --admin-group=sudo`) and approve
      one plain `run`, one script, one install, on the real X11 desktop.
- [ ] The new window size on your real screen(s), with a real window manager
      (Xvfb has none): does it open large and centred, can you resize it, move
      it, and switch away (no grab). Also on a HiDPI screen if you have one
      (egui points vs pixels), and in the Wayland VM (the compositor places
      windows there; centring is not ours).
- [ ] A disk warning on your real screen: e.g. `peekexec run --why test --
      lsblk /dev/nvme0n1` should need a click and say "in use: / ...".
- [ ] With a USB stick plugged in and not mounted: `peekexec run -- lsblk
      /dev/sdX` keeps Enter, and the dialog names the stick ("USB disk ...").
- [ ] Wayland (VM, `dev/wayland-vm/approve-test.sh --install`): the desktop
      prompt carries the disk line and still fits (22 lines).
