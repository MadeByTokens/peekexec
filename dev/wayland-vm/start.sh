#!/bin/sh
# Boot the test VM. Screen: VNC on 127.0.0.1:5905 (e.g. remote-viewer
# vnc://127.0.0.1:5905). ssh: ./ssh.sh. Control socket: $VM_DIR/qmp.sock.
set -eu
VM_DIR=${VM_DIR:-$HOME/vms/peekexec-noble}
cd "$VM_DIR"
exec qemu-system-x86_64 -name peekexec-noble -enable-kvm -cpu host -smp 4 -m 6144 \
    -drive file=disk.qcow2,if=virtio -drive file=seed.iso,media=cdrom,readonly=on \
    -device virtio-vga -display vnc=127.0.0.1:5 \
    -usb -device usb-tablet \
    -netdev user,id=n0,hostfwd=tcp:127.0.0.1:2222-:22 -device virtio-net-pci,netdev=n0 \
    -qmp unix:qmp.sock,server=on,wait=off
