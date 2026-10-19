#!/usr/bin/env bash
# Plug and play a range stick: ./bin/playstick.sh [stick_mount]
# Auto-detects the mounted stick when no mount is given, verifies its manifest,
# then brings that estate up on ephemeral localhost ports and prints the port
# map. One range per stick; Ctrl-C stops it. See keystone/usbstick.py.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
exec python3 -m keystone.usbstick play "$@"
