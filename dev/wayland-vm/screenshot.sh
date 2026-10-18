#!/bin/sh
# Save the VM screen as a PNG: screenshot.sh OUT.png
set -eu
VM_DIR=${VM_DIR:-$HOME/vms/peekexec-noble}
out=$(realpath -m "${1:?usage: screenshot.sh OUT.png}")
python3 - "$VM_DIR/qmp.sock" "$out.ppm" <<'EOF'
import json, socket, sys
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
f = s.makefile("rw")
f.readline()
for cmd in ({"execute": "qmp_capabilities"},
            {"execute": "screendump", "arguments": {"filename": sys.argv[2]}}):
    f.write(json.dumps(cmd) + "\n"); f.flush()
    reply = json.loads(f.readline())
    if "error" in reply:
        sys.exit(reply["error"]["desc"])
EOF
convert "$out.ppm" "$out" && rm -f "$out.ppm"
echo "$out"
