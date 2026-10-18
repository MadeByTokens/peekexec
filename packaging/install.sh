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
    echo "peekexec removed (left $pam in place; delete it if unused)"
    exit 0
fi

rel="$repo/target/release"
for f in peekexec peekexecd peekexec-ui; do
    if [ ! -x "$rel/$f" ]; then
        echo "install.sh: $rel/$f missing; run 'cargo build --release' first" >&2
        exit 1
    fi
done
# The test approver answers without a human; it must never be installed.
if grep -q PEEKEXEC_TEST_APPROVER "$rel/peekexecd"; then
    echo "install.sh: $rel/peekexecd was built with the test-approver feature; refusing" >&2
    exit 1
fi

install -d -o root -g root -m 0755 "$libexec"
install -o root -g root -m 0755 "$rel/peekexecd" "$libexec/peekexecd"
install -o root -g root -m 0755 "$rel/peekexec-ui" "$libexec/peekexec-ui"
install -o root -g root -m 0755 "$rel/peekexec" "$bin"
install -o root -g root -m 0644 "$repo/packaging/systemd/peekexecd.socket" "$units/"
install -o root -g root -m 0644 "$repo/packaging/systemd/peekexecd.service" "$units/"
if [ ! -e "$pam" ]; then
    if [ -e /etc/pam.d/common-auth ]; then
        install -o root -g root -m 0644 "$repo/packaging/pam/peekexec.debian" "$pam"
    else
        install -o root -g root -m 0644 "$repo/packaging/pam/peekexec.redhat" "$pam"
    fi
fi

systemctl daemon-reload
# Stop a running daemon so an upgrade takes effect on the next request.
systemctl stop peekexecd.service 2>/dev/null || true
systemctl enable peekexecd.socket
systemctl restart peekexecd.socket
echo "peekexec installed: $bin, $libexec, peekexecd.socket enabled"
