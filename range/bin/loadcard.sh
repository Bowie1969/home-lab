#!/usr/bin/env bash
# Load a range pack off an SD card into range/estates/: ./bin/loadcard.sh <card_mount>
# Verifies the card's manifest before copying; refuses to clobber an existing
# estate without --force. See keystone/sdcard.py.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
exec python3 -m keystone.sdcard load "$@"
