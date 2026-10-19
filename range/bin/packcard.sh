#!/usr/bin/env bash
# Pack one estate onto an SD card: ./bin/packcard.sh <range_id> <card_mount>
# The card becomes a self-contained range pack (see keystone/sdcard.py).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
exec python3 -m keystone.sdcard pack "$@"
