#!/usr/bin/env bash
# Bring up the implemented range, enforce rootless segmentation, verify, publish.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export KEYSTONE_SECURE_DIR="${KEYSTONE_SECURE_DIR:-$HOME/.local/share/keystone-secure}"
python3 -m keystone.generator
python3 -m keystone.live networks
python3 -m keystone.live host-firewall
python3 -m keystone.live firewall
python3 -m keystone.live up
python3 -m keystone.live firewall
if [ ! -f "$KEYSTONE_SECURE_DIR/ground_truth.json" ]; then
  python3 -m keystone.live rotate
fi
python3 -m keystone.live stamp
python3 -m keystone.live vms
python3 -m keystone.live verify
# CORP/DATA tier on the brain (Proxmox LXCs), reached over SSH. Only when a brain
# is configured; otherwise the Parrot container tier is brought up alone.
if [ -n "${KEYSTONE_BRAIN_SSH:-}" ]; then
  echo "[launch] brain at ${KEYSTONE_BRAIN_SSH} — provisioning + verifying CORP/DATA LXC tier"
  python3 -m keystone.live lxc
  python3 -m keystone.live lxc-firewall
  python3 -m keystone.live lxc-stamp
  python3 -m keystone.live lxc-verify
else
  echo "[launch] KEYSTONE_BRAIN_SSH unset — skipping CORP/DATA LXC tier (container tier only)"
fi
python3 -m keystone.live publish --model "${1:-no-attacking-operator}"
