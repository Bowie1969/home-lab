#!/usr/bin/env bash
set -euo pipefail

readonly PI_TARGET="${PI_TARGET:-kali@10.10.66.143}"
readonly PI_KEY="/home/will_cyber/.ssh/id_ed25519_evilkimi_pi"
readonly KEYSTONE_START="/home/will_cyber/Projects/keystone-range/bin/start.sh"

ssh \
  -i "$PI_KEY" \
  -o BatchMode=yes \
  -o ConnectTimeout=8 \
  "$PI_TARGET" \
  'sudo -n systemctl start evilk-mesh-worker-pi.service'

set +e
"$KEYSTONE_START"
keystone_rc=$?
set -e

if (( keystone_rc != 0 )); then
  ssh \
    -i "$PI_KEY" \
    -o BatchMode=yes \
    -o ConnectTimeout=8 \
    "$PI_TARGET" \
    'sudo -n systemctl stop evilk-mesh-worker-pi.service' || true
  exit "$keystone_rc"
fi
