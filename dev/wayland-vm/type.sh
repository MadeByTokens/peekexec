#!/bin/sh
# Type text into the VM (lowercase letters, digits, space), then Enter:
#   type.sh tester
set -eu
VM_DIR=${VM_DIR:-$HOME/vms/peekexec-noble}
python3 - "$VM_DIR/qmp.sock" "${1:?usage: type.sh TEXT}" <<'EOF'
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
keys = [{"space": "spc"}.get(ch, ch) for ch in sys.argv[2]] + ["ret"]
for k in keys:
    cmd({"execute": "send-key", "arguments": {"keys": [{"type": "qcode", "data": k}]}})
EOF
