#!/usr/bin/env bash
# Plug and play a range card: ./bin/playcard.sh [card_mount]
# Auto-detects the mounted card when no mount is given, verifies its manifest,
# then brings that estate up on ephemeral localhost ports and prints the port
# map. One range per card; Ctrl-C stops it. See keystone/sdcard.py.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
exec python3 -m keystone.sdcard play "$@"
