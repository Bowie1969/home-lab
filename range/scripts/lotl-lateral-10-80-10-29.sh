#!/usr/bin/env bash
# lotl-lateral-10-80-10-29.sh
# Category: lateral | Node: 10.80.10.29 | Reusable: share-anon, ks-ws01, ks-files01
set -euo pipefail

TARGET="${TARGET:-10.80.10.29}"
CRED="${CRED:-}"
SCAN_TYPE="${SCAN_TYPE:-full}"

if [[ -z "$TARGET" ]]; then
    echo "ERROR: TARGET must be set (export TARGET=10.80.x.x)" >&2
    exit 1
fi

echo "[lotl] Starting lateral on $TARGET (type=$SCAN_TYPE)"

case "$SCAN_TYPE" in
    quick)
        nmap -sS -T4 -p 22,80,443,445,3306 --open "$TARGET" -oN "lotl-quick-$TARGET.txt" || true
        ;;
    full)
        nmap -sS -sV -sC -T4 "$TARGET" -oN "lotl-full-$TARGET.txt" || true
        ;;
    udp)
        nmap -sU -T4 --top-ports 20 "$TARGET" -oN "lotl-udp-$TARGET.txt" || true
        ;;
esac

if [[ -n "$CRED" ]]; then
    echo "[lotl] Credential supplied - attempting limited SMB/SSH enum"
    smbclient -L "//$TARGET" -U "$CRED" -N 2>/dev/null || true
fi

echo "[lotl] Completed. Output in lotl-*-$TARGET.txt"
ls -la lotl-*-"$TARGET".txt 2>/dev/null || true
