#!/usr/bin/env bash
# evilkit-kimi-dashboard.sh — launch the Kimi Code brain (EvilKit) and stream the
# run straight onto the live lab dashboard.
#
# The Kimi model comes from the evilkit-kimi profile. `evilkit brain` writes
# sanitized per-action telemetry — tool-coloured edges (each MCP tool call gets
# its own pulsing line) and host_compromised (victim turns red) — directly into a
# fresh Keystone run dir. The dashboard's find_live_run() promotes that run to the
# live view automatically, so nothing else has to be wired.
#
# Usage:
#   evilkit-kimi-dashboard.sh [SCOPE]
#     SCOPE  comma-separated targets (default: the Keystone range subnets)
#   Env:
#     EVILKIT_CONFIG    profile (default: evilkit-kimi.toml)
#     EVILKIT_OBJECTIVE objective JSON passed to --objective
#     EVILKIT_DRY=1     wiring test: canned model responses, simulation executor
#                       (no real API calls, no real shell) — proves the dashboard
#                       link without running a live engagement.
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
export EVILKIT_CONFIG="${EVILKIT_CONFIG:-$HOME/.config/evilkit/profiles/evilkit-kimi.toml}"

SCOPE="${1:-10.99.50.0/24,10.50.0.0/24}"   # estate + keystone range subnets
STAMP="$(date +%Y%m%d-%H%M%S)"
RUN_ID="evilkit-kimi-$STAMP"
RUN_DIR="$HOME/Projects/keystone-range/runs/$RUN_ID"
TRACE="$HOME/evilkit/runs/$RUN_ID.jsonl"
DASH_URL="http://100.88.148.72:8793/"
mkdir -p "$RUN_DIR/dashboard" "$RUN_DIR/evidence" "$(dirname "$TRACE")"

# Seed the run's topology from the current live-brain view so the brain's tool
# edges have nodes to light up from the first turn (the brain refreshes it later).
LIVE="$HOME/Projects/keystone-range/runs/live-brain/dashboard/topology.json"
[ -f "$LIVE" ] && cp "$LIVE" "$RUN_DIR/dashboard/topology.json"

MODE_ARGS=(-s "$SCOPE" -y --live)
if [ "${EVILKIT_DRY:-0}" = "1" ]; then
  MODE_ARGS=(-s solo -y --dry-run-models)   # canned, no live shell/API
fi

echo "[evilkit->dash] model:     kimi-k3 (profile: $EVILKIT_CONFIG)"
echo "[evilkit->dash] scope:     ${MODE_ARGS[1]}"
echo "[evilkit->dash] run dir:   $RUN_DIR"
echo "[evilkit->dash] trace:     $TRACE"
echo "[evilkit->dash] dashboard: $DASH_URL  (switches to this run once it starts)"
echo

exec evilkit brain \
  "${MODE_ARGS[@]}" \
  --dashboard-run-dir "$RUN_DIR" \
  --trace "$TRACE" \
  --evidence-dir "$RUN_DIR/evidence" \
  ${EVILKIT_OBJECTIVE:+--objective "$EVILKIT_OBJECTIVE"}
