#!/bin/sh
# The polkit approval path end to end, in the VM (GNOME on Wayland, so the
# display is unverified and GNOME Shell's prompt takes the password).
#
#   dev/wayland-vm/approve-test.sh [--install]
#
# --install first copies target/release and packaging/ into the VM and runs
# install.sh there (the VM's sudo needs no password). Requests are sent from
# a `systemd-run --user` unit, as an app in the desktop session would (ssh
# sessions are refused by design). Clicks and keys go through QEMU; the
# positions are for the 1024x768 screen. On a failure the screen is saved
# to /tmp/approve-test-CASE.png.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
user_env='export DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus XDG_RUNTIME_DIR=/run/user/1000'

vm() { "$here/ssh.sh" "$@" 2>&1 | grep -v xauth || true; }

if [ "${1:-}" = --install ]; then
    # $HOME is the VM's: expanded there.
    # shellcheck disable=SC2016
    tar czf - -C "$repo" target/release/peekexec target/release/peekexecd \
        target/release/peekexec-ui packaging \
        | "$here/ssh.sh" 'rm -rf ~/pe && mkdir -p ~/pe && tar xzf - -C ~/pe &&
            sudo ~/pe/packaging/install.sh --from="$HOME/pe" >/dev/null && echo installed' \
            2>&1 | grep -v xauth
fi

failed=0
# A word in every request, so that no earlier run's denial (remembered for
# an hour) matches it.
nonce=$(date +%s)
# start CASE COMMAND...: send a request in the background; its JSON answer
# goes to /tmp/pe-CASE.json in the VM.
start() {
    case_name=$1
    shift
    vm "$user_env; rm -f /tmp/pe-$case_name.json; systemctl --user reset-failed pe-$case_name 2>/dev/null;
        systemd-run --user -q --unit=pe-$case_name sh -c 'peekexec $* > /tmp/pe-$case_name.json'"
    sleep 4
}
# check CASE PYTHON-EXPR: wait for the answer and test it (`r` is the JSON).
check() {
    i=0
    while [ $i -lt 30 ]; do
        out=$(vm "cat /tmp/pe-$1.json 2>/dev/null")
        [ -n "$out" ] && break
        sleep 1
        i=$((i + 1))
    done
    if printf '%s' "$out" | python3 -c "import json,sys; r=json.load(sys.stdin); sys.exit(0 if ($2) else 1)" 2>/dev/null; then
        echo "ok    $1"
    else
        echo "FAIL  $1: ${out:-no answer}"
        "$here/screenshot.sh" "/tmp/approve-test-$1.png" >/dev/null
        vm "$user_env; systemctl --user stop pe-$1 2>/dev/null"
        failed=1
    fi
}

# Approve: Continue in peekexec's window, then the password in GNOME's prompt.
start approve run --json -- id -u
"$here/click.sh" 968 718
sleep 3
"$here/type.sh" tester
check approve 'r["status"] == "approved" and r["stdout"] == "0\n" and r["display_verified"] is False'

# Dismissing GNOME's prompt cancels the request.
start dismiss run --json -- true "dismiss-$nonce"
"$here/click.sh" 968 718
sleep 3
"$here/key.sh" esc
check dismiss 'r["status"] == "cancelled"'

# A wrong password is not an approval.
start wrong run --json -- true "wrong-$nonce"
"$here/click.sh" 968 718
sleep 3
"$here/type.sh" wrongpassword
sleep 3
"$here/key.sh" esc
check wrong 'r["status"] in ("auth_failed", "cancelled")'

# Deny with a reason, in peekexec's window: the reason comes back.
start deny run --json -- true "deny-$nonce"
"$here/click.sh" 945 743
sleep 1
"$here/click.sh" 540 710
"$here/type.sh" "use apt instead"
"$here/click.sh" 119 741
check deny 'r["status"] == "denied" and r["deny_reason"].startswith("use apt instead")'

# A request that does not fit GNOME's prompt is refused before anything is
# shown (no clicks: there is no window).
vm "printf '#!/bin/sh\n' > /tmp/long.sh; for i in \$(seq 1 30); do echo 'echo step' >> /tmp/long.sh; done"
start long script --json /tmp/long.sh
check long 'r["status"] == "error" and "does not scroll" in r["error"]'

exit $failed
