#!/usr/bin/env bash
# Start tracking a prepared Keystone run — the dashboard's "Start" control.
#
# The board invokes this with no arguments (server.py -> watcher.run_control), so
# it delegates to the same command the homelab-run-* wrappers use. That command
# marks the newest idle/ready prepared run as "starting" and then waits for the
# separately launched operator's telemetry: it does NOT launch the range, the
# operator, or any security action.
#
# The expected path for a podman-tier run is: bin/launch.sh (or bin/reset.sh)
# publishes a prepared run, then this marks it live so the board switches off the
# live-brain view and onto the run.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
exec python3 -m keystone.run_control start "$@"
