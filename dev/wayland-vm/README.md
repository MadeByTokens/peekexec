# Wayland test VM

Ubuntu 24.04 with GNOME on Wayland, for developing peekexec's Wayland support
(PLAN.md, M2). Runs as your user with plain QEMU + KVM: no root, nothing on the
host's system services. Files live in `$VM_DIR` (default `~/vms/peekexec-noble`).

```bash
mkdir -p ~/vms/peekexec-noble && cd ~/vms/peekexec-noble
curl -LO https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img
curl -LO https://cloud-images.ubuntu.com/noble/current/SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
cd -; dev/wayland-vm/create.sh
dev/wayland-vm/start.sh &        # first boot installs the desktop, then reboots
dev/wayland-vm/ssh.sh            # user tester / password tester
dev/wayland-vm/screenshot.sh /tmp/vm.png
remote-viewer vnc://127.0.0.1:5905
```
