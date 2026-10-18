#!/usr/bin/env bash
# Periodic dashboard capture — a visual + data timeline of the lab dashboard
# while a run is in progress. Each tick writes a timestamped PNG (headless
# Chrome) and the matching /api/status JSON, so the board can be reviewed and
# cross-checked against the run afterwards (e.g. dashboard score vs verify.sh).
#
# Usage:
#   scripts/dashboard_capture.sh [interval_seconds] [out_dir]
#   DASH_URL=http://host:8793/ scripts/dashboard_capture.sh 60 /path/to/out
#
# Stop with Ctrl-C, or `kill <pid>` when run in the background.
set -uo pipefail

URL="${DASH_URL:-http://100.88.148.72:8793/}"
INTERVAL="${1:-60}"
OUTDIR="${2:-$HOME/Projects/lab-dashboard/captures/$(date +%Y%m%d-%H%M%S)}"
WIN="${DASH_WIN:-1600x1000}"

mkdir -p "$OUTDIR"
echo "dashboard_capture: $URL every ${INTERVAL}s -> $OUTDIR"
echo "  (stop with Ctrl-C or: kill $$)"

shot() {
  local ts png udd
  ts="$1"; png="$OUTDIR/dash-$ts.png"; udd="$(mktemp -d)"
  google-chrome --headless=new --disable-gpu --no-sandbox \
    --user-data-dir="$udd" --no-first-run --no-default-browser-check \
    --hide-scrollbars --window-size="${WIN/x/,}" --timeout=12000 \
    --screenshot="$png" "$URL" >/dev/null 2>&1
  local rc=$?
  rm -rf "$udd"
  return $rc
}

i=0
while true; do
  ts="$(date +%Y%m%d-%H%M%S)"
  if shot "$ts"; then state="ok"; else state="FAILED"; fi
  curl -s "${URL%/}/api/status" -o "$OUTDIR/status-$ts.json" 2>/dev/null || true
  # one-line summary pulled from the status snapshot, if jq-free python is around
  summary="$(python3 - "$OUTDIR/status-$ts.json" 2>/dev/null <<'PY'
import sys, json
try:
    d = json.load(open(sys.argv[1]))
    s = d.get("status", {})
    print(f"mode={d.get('mode')} state={s.get('state')} score={s.get('score')}/{s.get('score_max')} nodes={len(d.get('nodes',[]))} edges={len(d.get('edges',[]))} events={len(d.get('events',[]))}")
except Exception:
    print("")
PY
)"
  i=$((i+1))
  echo "  [$ts] #$i shot=$state  $summary"
  sleep "$INTERVAL"
done
