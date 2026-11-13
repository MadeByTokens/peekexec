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

- [ ] W1 Dialog: large and resizable (about 85% of the monitor, centred,
      min 560x420 kept), warnings at reading size in a box above the command
      with a count, disk warnings first. Off-screen renders at 1280x720,
      1366x768, 1920x1080.
- [x] I3 The path note asks "could programs of yours change it?" (as the
      user, by the kernel: owner or `access(W_OK)`, groups and ACLs), not
      "does root own it?"; wording fits an image a command only reads. Gone:
      the `/etc/resolv.conf`, `/run/utmp` and `--cwd /dev` false notes. The
      helper's cwd warning now uses root's by-descriptor check, so dev
      previews match production.
- [ ] I4 Enter only when the user could read every named path (EACCES = note,
      click); raw devices always a click; THREAT_MODEL line about unreachable
      paths updated.
- [ ] Docs for all of the above (README, man page via manual.md +
      gen-cli-doc.sh, help agents, THREAT_MODEL, checklist).
- [ ] Final review / bypass pass on everything since 99f2713.
- [ ] Ask the owner before `git push`.

## To test when you are back (needs a human or the real desktop)

- [ ] Install the build (`packaging/install.sh --admin-group=sudo`) and approve
      one plain `run`, one script, one install, on the real X11 desktop.
- [ ] The new window size on your real screen(s): does it open large, centred,
      resizable; is it comfortable; can you still switch away (no grab).
- [ ] A disk warning on your real screen: e.g. `peekexec run --why test --
      lsblk /dev/nvme0n1` should need a click and say "in use: / ...".
- [ ] With a USB stick plugged in and not mounted: `peekexec run -- lsblk
      /dev/sdX` keeps Enter, and the dialog names the stick ("USB disk ...").
- [ ] Wayland (VM, `dev/wayland-vm/approve-test.sh --install`): the desktop
      prompt carries the disk line and still fits (22 lines).
