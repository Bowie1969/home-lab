#!/usr/bin/env bash
# Pack one estate onto an USB stick: ./bin/packstick.sh <range_id> <stick_mount>
# The stick becomes a self-contained range pack (see keystone/usbstick.py).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
exec python3 -m keystone.usbstick pack "$@"
