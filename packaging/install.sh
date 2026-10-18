#!/bin/sh
# Install (or remove) peekexec from a release build of this repository.
#
#   cargo build --release            # as your user, never as root
#   pkexec "$PWD/packaging/install.sh"            # install
#   pkexec "$PWD/packaging/install.sh" --uninstall
#
# Upgrading through peekexec itself (the script then runs from a snapshot,
# so name the checkout):
#   peekexec script --why "..." packaging/install.sh --from="$PWD"
set -eu

action=install
from=""
for arg in "$@"; do
    case "$arg" in
        --uninstall) action=uninstall ;;
        --from=*) from=${arg#--from=} ;;
        *)
            echo "usage: install.sh [--uninstall] [--from=REPO_DIR]" >&2
            exit 2
            ;;
    esac
done
repo=${from:-$(cd "$(dirname "$0")/.." && pwd)}
libexec=/usr/libexec/peekexec
bin=/usr/local/bin/peekexec
units=/etc/systemd/system
pam=/etc/pam.d/peekexec
policy=/usr/share/polkit-1/actions/org.peekexec.approve.policy

if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh: run as root (e.g. pkexec \"$repo/packaging/install.sh\")" >&2
    exit 1
fi

# Run through peekexec, this script lives inside peekexecd.service: stopping
# that service directly would kill the script halfway. Such steps are handed
# to a short-lived transient unit that runs them a few seconds later.
in_service() {
    grep -q 'peekexecd\.service' /proc/self/cgroup 2>/dev/null
}
later() {
    systemd-run --quiet --collect --on-active=3 --timer-property=AccuracySec=100ms \
        --unit="peekexec-upgrade-$$" systemctl "$@"
}

if [ "$action" = uninstall ]; then
    rm -f "$units/peekexecd.socket" "$units/peekexecd.service" "$bin" "$policy"
    rm -rf "$libexec"
    if in_service; then
        later disable --now peekexecd.socket peekexecd.service
    else
        systemctl disable --now peekexecd.socket peekexecd.service 2>/dev/null || true
        systemctl daemon-reload
    fi
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
cp -r "$repo/packaging/systemd" "$repo/packaging/pam" "$repo/packaging/polkit" "$stage/"
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
if [ -d "$(dirname "$policy")" ]; then
    install -o root -g root -m 0644 "$stage/polkit/org.peekexec.approve.policy" "$policy"
fi
if [ ! -e "$pam" ]; then
    if [ -e /etc/pam.d/common-auth ]; then
        install -o root -g root -m 0644 "$stage/pam/peekexec.debian" "$pam"
    else
        install -o root -g root -m 0644 "$stage/pam/peekexec.redhat" "$pam"
    fi
fi

systemctl daemon-reload
systemctl enable peekexecd.socket
# Stop a running daemon so the next request starts the new one.
if in_service; then
    later stop peekexecd.service
    echo "peekexec installed: $bin, $libexec; the daemon restarts in 3 s"
else
    systemctl stop peekexecd.service 2>/dev/null || true
    systemctl restart peekexecd.socket
    echo "peekexec installed: $bin, $libexec, peekexecd.socket enabled"
fi
