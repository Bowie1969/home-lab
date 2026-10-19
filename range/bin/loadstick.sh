#!/usr/bin/env bash
# Load a range pack off an USB stick into range/estates/: ./bin/loadstick.sh <stick_mount>
# Verifies the stick's manifest before copying; refuses to clobber an existing
# estate without --force. See keystone/usbstick.py.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
exec python3 -m keystone.usbstick load "$@"
