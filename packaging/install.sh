#!/bin/sh
# Install (or remove) peekexec from a release build of this repository.
#
#   cargo build --release            # as your user, never as root
#   pkexec "$PWD/packaging/install.sh"            # install
#   pkexec "$PWD/packaging/install.sh" --uninstall
set -eu

repo=$(cd "$(dirname "$0")/.." && pwd)
libexec=/usr/libexec/peekexec
bin=/usr/local/bin/peekexec
units=/etc/systemd/system
pam=/etc/pam.d/peekexec

if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh: run as root (e.g. pkexec \"$repo/packaging/install.sh\")" >&2
    exit 1
fi

if [ "${1:-}" = "--uninstall" ]; then
    systemctl disable --now peekexecd.socket peekexecd.service 2>/dev/null || true
    rm -f "$units/peekexecd.socket" "$units/peekexecd.service" "$bin"
    rm -rf "$libexec"
    systemctl daemon-reload
    # Remove the PAM file only if it is exactly one we ship (not edited).
    if cmp -s "$pam" "$repo/packaging/pam/peekexec.debian" \
        || cmp -s "$pam" "$repo/packaging/pam/peekexec.redhat"; then
        rm -f "$pam"
        echo "peekexec removed"
    elif [ -e "$pam" ]; then
        echo "peekexec removed (kept $pam: it was modified)"
    else
        echo "peekexec removed"
    fi
    exit 0
fi

rel="$repo/target/release"
for f in peekexec peekexecd peekexec-ui; do
    if [ ! -x "$rel/$f" ]; then
        echo "install.sh: $rel/$f missing; run 'cargo build --release' first" >&2
        exit 1
    fi
done
# target/release is writable by the user who built it. Copy it once into a
# root-only directory, then check and install from that copy, so nothing
# can be swapped between the check and the install.
stage=$(mktemp -d /tmp/peekexec-install.XXXXXX)
trap 'rm -rf "$stage"' EXIT
chmod 700 "$stage"
for f in peekexec peekexecd peekexec-ui; do
    cp "$rel/$f" "$stage/$f"
done
cp -r "$repo/packaging/systemd" "$repo/packaging/pam" "$stage/"
# The test approver answers without a human; it must never be installed.
if LC_ALL=C grep -a -q PEEKEXEC_TEST_APPROVER "$stage/peekexecd"; then
    echo "install.sh: $rel/peekexecd was built with the test-approver feature; refusing" >&2
    exit 1
fi

install -d -o root -g root -m 0755 "$libexec"
install -o root -g root -m 0755 "$stage/peekexecd" "$libexec/peekexecd"
install -o root -g root -m 0755 "$stage/peekexec-ui" "$libexec/peekexec-ui"
install -o root -g root -m 0755 "$stage/peekexec" "$bin"
install -o root -g root -m 0644 "$stage/systemd/peekexecd.socket" "$units/"
install -o root -g root -m 0644 "$stage/systemd/peekexecd.service" "$units/"
if [ ! -e "$pam" ]; then
    if [ -e /etc/pam.d/common-auth ]; then
        install -o root -g root -m 0644 "$stage/pam/peekexec.debian" "$pam"
    else
        install -o root -g root -m 0644 "$stage/pam/peekexec.redhat" "$pam"
    fi
fi

systemctl daemon-reload
# Stop a running daemon so an upgrade takes effect on the next request.
systemctl stop peekexecd.service 2>/dev/null || true
systemctl enable peekexecd.socket
systemctl restart peekexecd.socket
echo "peekexec installed: $bin, $libexec, peekexecd.socket enabled"
