#!/usr/bin/env bash
set -uo pipefail

readonly PI_TARGET="${PI_TARGET:-kali@10.10.66.146}"
readonly PI_KEY="/home/will_cyber/.ssh/id_ed25519_evilkimi_pi"
readonly KEYSTONE_STOP="/home/will_cyber/Projects/keystone-range/bin/stop.sh"

ssh \
  -i "$PI_KEY" \
  -o BatchMode=yes \
  -o ConnectTimeout=8 \
  "$PI_TARGET" \
  'sudo -n systemctl stop evilk-mesh-worker-pi.service'
pi_rc=$?

"$KEYSTONE_STOP"
keystone_rc=$?

if (( pi_rc != 0 )); then
  exit "$pi_rc"
fi
exit "$keystone_rc"
