#!/bin/sh
# Install (or remove) peekexec from a release build of this repository.
#
#   cargo build --release --locked   # as your user, never as root
#   pkexec "$PWD/packaging/install.sh" --admin-group=sudo     # install
#   pkexec "$PWD/packaging/install.sh" --uninstall
#
# --admin-group names the group whose members may ask for root. peekexec
# gives them full root for their own password, whatever sudoers says about
# that group, so the choice is made by a person, once. Later upgrades keep it.
#
# Running this as root trusts every file in the tree: the binaries in
# target/release and the files in packaging/ are installed as they are,
# and whoever can write the tree chose them. So do not approve it on
# someone else's (or an agent's) behalf: `peekexec script` would show you
# this script, not the root daemon it installs. --from names the tree when
# the script runs from a copy.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

action=install
from=""
admin_group=""
for arg in "$@"; do
    case "$arg" in
        --uninstall) action=uninstall ;;
        --from=*) from=${arg#--from=} ;;
        --admin-group=*) admin_group=${arg#--admin-group=} ;;
        *)
            echo "usage: install.sh [--uninstall] [--from=REPO_DIR] [--admin-group=GROUP]" >&2
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
dropin=/etc/systemd/system/peekexecd.socket.d
manpage=/usr/local/share/man/man1/peekexec.1

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
# Approved commands run in cgroups below the daemon's own, and stopping the
# daemon ends them: wait until none is running (an apt upgrade finishes
# first). Run through peekexec, this script is one of them until it exits,
# so the restart it hands over waits for it too. Expanded by the shell
# that runs it, which may be a transient unit's.
# shellcheck disable=SC2016
wait_idle='cg=/sys/fs/cgroup$(systemctl show -p ControlGroup --value peekexecd.service)
if grep -qsx "populated 1" "$cg"/peekexec-cmd-*/cgroup.events; then
    echo "install.sh: waiting for approved commands that are still running" >&2
fi
while grep -qsx "populated 1" "$cg"/peekexec-cmd-*/cgroup.events; do sleep 2; done'
later() {
    systemd-run --quiet --collect --on-active=3 --timer-property=AccuracySec=100ms \
        --unit="peekexec-upgrade-$$" /bin/sh -c "$wait_idle; systemctl $*"
}

if [ "$action" = uninstall ]; then
    # Stop and disable while the unit files still exist: disable cannot
    # find a removed unit, and the socket would keep listening.
    if in_service; then
        echo "install.sh: --uninstall cannot run inside peekexecd.service; use pkexec" >&2
        exit 1
    fi
    sh -c "$wait_idle"
    systemctl disable --now peekexecd.socket peekexecd.service 2>/dev/null || true
    rm -f "$units/peekexecd.socket" "$units/peekexecd.service" "$bin" "$policy" "$manpage"
    rm -rf "$dropin"
    rm -rf "$libexec"
    systemctl daemon-reload || true
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

# Everything that can be refused is refused here, before anything changes.
if ! command -v systemctl >/dev/null; then
    echo "install.sh: this needs systemd" >&2
    exit 1
fi
if [ -z "$admin_group" ] && [ -e "$dropin/admin-group.conf" ]; then
    admin_group=$(sed -n 's/^SocketGroup=//p' "$dropin/admin-group.conf")
fi
if [ -z "$admin_group" ]; then
    echo "install.sh: name the group whose members may ask for root:" >&2
    for g in sudo wheel admin; do
        if line=$(getent group "$g"); then
            echo "  --admin-group=$g   members: ${line##*:}" >&2
        fi
    done
    echo "Each member gets full root with their own password, whatever sudoers says." >&2
    exit 1
fi
if ! members=$(getent group "$admin_group"); then
    echo "install.sh: no group named $admin_group" >&2
    exit 1
fi
if [ "$admin_group" = root ]; then
    echo "install.sh: the group must not be root: the daemon would admit no one" >&2
    exit 1
fi
echo "install.sh: administrators are the members of $admin_group: ${members##*:}"
if [ ! -e /sys/fs/cgroup/cgroup.controllers ]; then
    echo "install.sh: no cgroup v2: commands' background processes are not ended, and this" >&2
    echo "  script cannot wait for running commands before it restarts the daemon" >&2
fi
systemd_version=$(systemctl --version | sed -n '1s/^systemd \([0-9]*\).*/\1/p')
if [ "${systemd_version:-0}" -lt 240 ]; then
    echo "install.sh: systemd older than 240 applies its log rate limit to audit lines" >&2
fi

rel="$repo/target/release"
for f in peekexec peekexecd peekexec-ui; do
    if [ ! -e "$rel/$f" ]; then
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
    cp -P "$rel/$f" "$stage/$f"
done
cp -rP "$repo/packaging/systemd" "$repo/packaging/pam" "$repo/packaging/polkit" \
    "$repo/packaging/man" "$stage/"
# -P copies symlinks as links, and install(1) would follow them, reading
# whatever they point to as root. Only plain files and directories are
# installed, checked on the copy.
if [ -n "$(find "$stage" ! -type f ! -type d)" ]; then
    echo "install.sh: links or special files in $repo/packaging or target/release; refusing" >&2
    exit 1
fi
for f in peekexec peekexecd peekexec-ui; do
    # By its mode: on a noexec /tmp, -x is false whatever the file is.
    if [ -z "$(find "$stage/$f" -perm -u+x)" ]; then
        echo "install.sh: $rel/$f is not executable" >&2
        exit 1
    fi
done
# What is about to run as root, for the record (the human approving an
# upgrade through peekexec sees this script, not the binaries).
sha256sum "$stage/peekexec" "$stage/peekexecd" "$stage/peekexec-ui" | sed "s|$stage/||"
# The test approver answers without a human; it must never be installed.
if LC_ALL=C grep -a -q PEEKEXEC_TEST_APPROVER "$stage/peekexecd"; then
    echo "install.sh: $rel/peekexecd was built with the test-approver feature; refusing" >&2
    exit 1
fi

install -d -o root -g root -m 0755 "$libexec"
# 0711: executable, not readable by users. The daemon runs both as the
# user (the inspection helper, the dialog); a process running a file it
# cannot read is non-dumpable from exec on, so other programs of the user
# cannot attach to it, not even before the dialog's own prctl runs.
install -o root -g root -m 0711 "$stage/peekexecd" "$libexec/peekexecd"
install -o root -g root -m 0711 "$stage/peekexec-ui" "$libexec/peekexec-ui"
install -o root -g root -m 0755 "$stage/peekexec" "$bin"
install -d -o root -g root -m 0755 "$(dirname "$manpage")"
install -o root -g root -m 0644 "$stage/man/peekexec.1" "$manpage"
install -o root -g root -m 0644 "$stage/systemd/peekexecd.socket" "$units/"
install -o root -g root -m 0644 "$stage/systemd/peekexecd.service" "$units/"
# Only the administrators may connect to the socket.
install -d -o root -g root -m 0755 "$dropin"
printf '[Socket]\nSocketGroup=%s\n' "$admin_group" > "$dropin/admin-group.conf"
chmod 0644 "$dropin/admin-group.conf"
if [ -d "$(dirname "$policy")" ]; then
    install -o root -g root -m 0644 "$stage/polkit/org.peekexec.approve.policy" "$policy"
fi
if [ ! -e "$pam" ]; then
    if [ -e /etc/pam.d/common-auth ]; then
        install -o root -g root -m 0644 "$stage/pam/peekexec.debian" "$pam"
    else
        install -o root -g root -m 0644 "$stage/pam/peekexec.redhat" "$pam"
    fi
elif ! cmp -s "$pam" "$stage/pam/peekexec.debian" && ! cmp -s "$pam" "$stage/pam/peekexec.redhat"; then
    echo "install.sh: kept $pam, which differs from the ones shipped" >&2
fi

systemctl daemon-reload
systemctl enable peekexecd.socket
# Recreate the socket (so its mode and group apply) and stop a running
# daemon (it requires the socket), so the next request starts the new one.
if in_service; then
    later restart peekexecd.socket
    echo "peekexec installed: $bin, $libexec; the daemon restarts in 3 s"
else
    sh -c "$wait_idle"
    systemctl stop peekexecd.service 2>/dev/null || true
    systemctl restart peekexecd.socket
    echo "peekexec installed: $bin, $libexec, peekexecd.socket enabled"
fi
