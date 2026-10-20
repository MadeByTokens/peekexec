#!/bin/sh
# Press one key in the VM (a QEMU qcode: esc, ret, tab, ...):
#   key.sh esc
set -eu
VM_DIR=${VM_DIR:-$HOME/vms/peekexec-noble}
python3 - "$VM_DIR/qmp.sock" "${1:?usage: key.sh QCODE}" <<'EOF'
import json, socket, sys
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
cmd({"execute": "send-key", "arguments": {"keys": [{"type": "qcode", "data": sys.argv[2]}]}})
EOF
