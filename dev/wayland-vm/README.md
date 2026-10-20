# Wayland test VM

Ubuntu 24.04 with GNOME on Wayland, for developing peekexec's Wayland support
(PLAN.md, M2). Runs as your user with plain QEMU + KVM: no root, nothing on the
host's system services. Files live in `$VM_DIR` (default `~/vms/peekexec-noble`).

Not for a shared host: the VM has password ssh (`tester`/`tester`) on
127.0.0.1:2222, passwordless sudo, and VNC with no password on
127.0.0.1:5905, so any local user of the host gets root in the VM. The image
is checked against `SHA256SUMS` from the same server; for more, verify
`SHA256SUMS.gpg` with Ubuntu's cloud image key as well.

```bash
mkdir -p ~/vms/peekexec-noble && cd ~/vms/peekexec-noble
curl -LO https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img
curl -LO https://cloud-images.ubuntu.com/noble/current/SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
cd -; dev/wayland-vm/create.sh
dev/wayland-vm/start.sh &        # first boot installs the desktop, then reboots
dev/wayland-vm/ssh.sh            # user tester / password tester
dev/wayland-vm/screenshot.sh /tmp/vm.png
dev/wayland-vm/type.sh tester     # type into the VM (e.g. a password prompt), then Enter
dev/wayland-vm/click.sh 971 718   # left-click at a screen pixel (1024x768)
dev/wayland-vm/key.sh esc         # press one key (a QEMU qcode)
dev/wayland-vm/approve-test.sh --install   # the polkit path end to end
remote-viewer vnc://127.0.0.1:5905
```
