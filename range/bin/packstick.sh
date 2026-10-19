#!/usr/bin/env bash
# Pack one estate onto a USB stick: ./bin/packstick.sh <range_id> <stick_mount>
# The stick becomes a self-contained range pack (see keystone/usbstick.py).
# Add --force to refresh a stale pack of the same range already on the stick.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
exec python3 -m keystone.usbstick pack "$@"
