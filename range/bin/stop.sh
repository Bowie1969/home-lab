#!/usr/bin/env bash
# Stop tracking the active Keystone run — the dashboard's "Stop" control.
#
# Marks the run the board is currently tracking as "finished" so the live-brain
# view returns. Same delegated command as bin/homelab-run-stop; it stops tracking,
# not the range or the operator.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
exec python3 -m keystone.run_control stop "$@"
