#!/usr/bin/env bash
# Run the flow monitor for the rootless-podman keystone DMZ range.
#
# Joins the rootless podman network namespace so tcpdump can see the range's
# bridges (ks-dmz 10.80.10.0/24, ks-attacker 10.80.0.0/24), classifies the
# 10.80.x traffic with keystone_flow_monitor.py, and writes the flows JSON to a
# path writable by the rootless user (default $XDG_RUNTIME_DIR/keystone-podman-flows.json).
# VULN_PORTS are derived live from the keystone-range manifests + topology, so a
# rebuilt range is picked up automatically.
#
# Usage:
#   scripts/keystone_podman_flow_monitor.sh            # foreground
#   KEYSTONE_PODMAN_FLOWS_PATH=/path/flows.json ...    # override output path
#   KEYSTONE_RANGE_DIR=~/Projects/keystone-range ...   # override range checkout
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
monitor="$here/keystone_flow_monitor.py"
range_dir="${KEYSTONE_RANGE_DIR:-$HOME/Projects/keystone-range}"
runtime_dir="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
out="${KEYSTONE_PODMAN_FLOWS_PATH:-$runtime_dir/keystone-podman-flows.json}"

echo "keystone-podman-flow-monitor: sniffing ks-dmz+ks-attacker in rootless netns -> $out"
exec podman unshare --rootless-netns -- \
  env KEYSTONE_BRIDGES="ks-dmz,ks-attacker" \
      KEYSTONE_SUBNETS="10.80.10.,10.80.0." \
      KEYSTONE_HOST_IPS="10.80.10.1,10.80.0.1" \
      KEYSTONE_SERVICE_PORTS="22,445,6379,8080,8081,8082,8083,8084,8085,8086" \
      KEYSTONE_VULN_PORTS_FROM="$range_dir" \
      KEYSTONE_FLOWS_PATH="$out" \
  python3 "$monitor"
