#!/usr/bin/env bash
# Recreate only implemented containers, rotate private flags, recheck, publish.
# Unprovisioned VMs remain blocked; never invent a clean snapshot.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export KEYSTONE_SECURE_DIR="${KEYSTONE_SECURE_DIR:-$HOME/.local/share/keystone-secure}"
python3 -m keystone.generator
python3 -m keystone.live networks
python3 -m keystone.live firewall
python3 -m keystone.live recreate
python3 -m keystone.live firewall
python3 -m keystone.live rotate
python3 -m keystone.live stamp
python3 -m keystone.live vms
python3 -m keystone.live verify
# CORP/DATA tier lives on the brain (Proxmox LXCs), reached over SSH. Only run it
# when a brain is configured; a plain Parrot host brings up the container tier
# alone. rotate (above) already wrote the shared ground truth lxc-stamp needs.
if [ -n "${KEYSTONE_BRAIN_SSH:-}" ]; then
  echo "[reset] brain at ${KEYSTONE_BRAIN_SSH} — recreating + verifying CORP/DATA LXC tier"
  python3 -m keystone.live lxc-recreate
  python3 -m keystone.live lxc-firewall
  python3 -m keystone.live lxc-stamp
  python3 -m keystone.live lxc-verify
else
  echo "[reset] KEYSTONE_BRAIN_SSH unset — skipping CORP/DATA LXC tier (container tier only)"
fi
python3 -m keystone.live publish --model "${1:-no-attacking-operator}"
