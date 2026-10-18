#!/bin/sh
# Create the Ubuntu 24.04 GNOME-on-Wayland test VM. User-mode QEMU, no root.
# The first boot installs a minimal desktop (several minutes), then reboots
# into an auto-login Wayland session for user "tester" (password "tester").
set -eu
VM_DIR=${VM_DIR:-$HOME/vms/peekexec-noble}
BASE=noble-server-cloudimg-amd64.img
cd "$VM_DIR"
if [ ! -f "$BASE" ]; then
    echo "create.sh: $VM_DIR/$BASE missing; see README.md" >&2
    exit 1
fi
[ -f id_ed25519 ] || ssh-keygen -q -t ed25519 -N "" -f id_ed25519 -C peekexec-vm
rm -f disk.qcow2 seed.iso known_hosts
qemu-img create -q -f qcow2 -b "$BASE" -F qcow2 disk.qcow2 30G
pub=$(cat id_ed25519.pub)
cat > user-data <<EOF
#cloud-config
hostname: peekexec-noble
users:
  - name: tester
    groups: [sudo]
    shell: /bin/bash
    lock_passwd: false
    plain_text_passwd: tester
    ssh_authorized_keys: [$pub]
    # Lets scripts set up the VM over ssh. peekexec itself authenticates
    # through PAM (the password), not sudoers.
    sudo: "ALL=(ALL) NOPASSWD:ALL"
package_update: true
packages: [ubuntu-desktop-minimal]
runcmd:
  - printf '[daemon]\nAutomaticLoginEnable=true\nAutomaticLogin=tester\nWaylandEnable=true\n' > /etc/gdm3/custom.conf
  - systemctl set-default graphical.target
power_state:
  mode: reboot
  condition: true
EOF
printf 'instance-id: peekexec-noble\nlocal-hostname: peekexec-noble\n' > meta-data
genisoimage -quiet -output seed.iso -volid cidata -joliet -rock user-data meta-data
echo "created $VM_DIR/disk.qcow2; now run start.sh"
