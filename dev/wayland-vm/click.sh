#!/bin/sh
# Left-click at screen pixel X Y (1024x768 VM screen): click.sh 971 718
set -eu
VM_DIR=${VM_DIR:-$HOME/vms/peekexec-noble}
python3 - "$VM_DIR/qmp.sock" "${1:?usage: click.sh X Y}" "${2:?usage: click.sh X Y}" <<'EOF'
import json, socket, sys, time
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
f = s.makefile("rw")
f.readline()
def cmd(c):
    f.write(json.dumps(c) + "\n"); f.flush()
    r = json.loads(f.readline())
    if "error" in r:
        sys.exit(r["error"]["desc"])
cmd({"execute": "qmp_capabilities"})
x, y = int(int(sys.argv[2]) * 32767 / 1024), int(int(sys.argv[3]) * 32767 / 768)
move = [{"type": "abs", "data": {"axis": "x", "value": x}},
        {"type": "abs", "data": {"axis": "y", "value": y}}]
cmd({"execute": "input-send-event", "arguments": {"events": move}})
for down in (True, False):
    time.sleep(0.05)
    cmd({"execute": "input-send-event", "arguments": {"events": [
        {"type": "btn", "data": {"down": down, "button": "left"}}]}})
EOF
