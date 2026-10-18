#!/bin/sh
# ssh into the test VM as "tester".
VM_DIR=${VM_DIR:-$HOME/vms/peekexec-noble}
exec ssh -i "$VM_DIR/id_ed25519" -p 2222 -o UserKnownHostsFile="$VM_DIR/known_hosts" \
    -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 tester@127.0.0.1 "$@"
