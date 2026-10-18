#!/usr/bin/env python3
"""keystone_full_topology.py — publish the FULL keystone range into a run.

`keystone.live publish` writes only the modules that actually came up, so a
partial bring-up shows a handful of nodes. For the dashboard we want the whole
designed range visible and labelled, with the live hosts highlighted and the
un-provisioned ones greyed out (honest: present in the design, not up this run).

This reads the generator's `build/topology.json` (the full 20-node design) plus
`build/live-state.json` (which hosts are actually up) and rewrites a run's
`dashboard/topology.json` to contain every node, each stamped with a state:

  running    the operator/attacker box
  reachable  a live, provisioned target (from live-state "selected")
  locked     a blocked VM (missing disk / no clean snapshot)
  stopped    defined in the design but not provisioned this run

Edges touching a non-live host are marked disconnected so they render dim; the
live sub-graph stays solid. Node colour on the dashboard is driven by state.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

DISPLAY_SEGMENTS = [
    {"id": "operators", "label": "Red Team Platform"},
    {"id": "perimeter", "label": "Network Perimeter"},
    {"id": "guest", "label": "Guest Access"},
    {"id": "management", "label": "Management Plane"},
    {"id": "public", "label": "Public Services"},
    {"id": "automation", "label": "Automation Services"},
    {"id": "users", "label": "User Workstations"},
    {"id": "business", "label": "Business Data"},
    {"id": "ksdmz", "label": "Application DMZ"},
    {"id": "privileged", "label": "Privileged Services"},
    {"id": "identity", "label": "Identity Services"},
]

FRIENDLY_NAMES = {
    "attacker": "Red Team Control Station",
    "bmc-super": "Infrastructure Controller",
    "cache-open": "Shared Cache",
    "corp-keyjump": "Admin Jump Host",
    "cron-root": "Job Scheduler",
    "dc-roast": "Corporate Domain Controller",
    "drop01": "Guest Network Kiosk",
    "edge-botnet": "Edge Analytics Service",
    "edge-upload": "Upload Service",
    "gitleak-api": "Source Search Service",
    "key-reuse": "Deployment Service",
    "kiosk-kernel": "Visitor Kiosk",
    "ks-files01": "Executive File Services",
    "ks-intranet01": "Staff Intranet",
    "ks-ws01": "Executive Workstation",
    "legacy-cve": "Legacy Integration Service",
    "mac-debian13": "Engineering Workstation",
    "macos-highsierra": "Legacy Design Workstation",
    "meta-ssrf": "Metadata Proxy",
    "modelhub-pickle": "Model Registry",
    "ntlm-relay-corp": "Document Processing Service",
    "portal-sqli": "Customer Portal API",
    "render-ssti": "Report Rendering Service",
    "runner-escape": "Build Runner",
    "samba-45": "Legacy File Services",
    "share-anon": "Partner File Exchange",
    "ssh-weak": "Remote Access Gateway",
    "token-jwt": "Token Gateway",
    "ubuntu-dirtycow": "Linux Application Server",
    "vault-keystone": "Credentials Vault",
    "win2025-smb": "Windows File Services",
    "win7-eternalblue": "Legacy Windows Workstation",
    "dmz-web-a": "DMZ Web Host 01",
    "dmz-web-b": "DMZ Web Host 02",
    "dmz-svc": "DMZ Shared Services Host",
    "dmz-runner": "DMZ Build Host",
}

DISPLAY_ZONE_BY_ID = {
    "attacker": "operators",
    "drop01": "guest", "kiosk-kernel": "guest",
    "bmc-super": "management", "corp-keyjump": "management",
    "dc-roast": "identity", "ntlm-relay-corp": "identity",
    "ks-ws01": "privileged", "ks-files01": "privileged",
    "ks-intranet01": "privileged", "vault-keystone": "privileged",
    "modelhub-pickle": "automation", "cron-root": "automation",
    "runner-escape": "automation",
    "mac-debian13": "users", "macos-highsierra": "users",
    "ubuntu-dirtycow": "users", "win7-eternalblue": "users",
    "win2025-smb": "business", "samba-45": "business",
    "key-reuse": "business",
}


def _display_zone(node: dict) -> str:
    node_id = str(node.get("id") or "")
    if node_id in DISPLAY_ZONE_BY_ID:
        return DISPLAY_ZONE_BY_ID[node_id]
    if node_id.startswith("dmz-") or str(node.get("network_zone") or node.get("zone")) == "dmz":
        return "ksdmz"
    return {"corp": "business", "data": "privileged"}.get(str(node.get("zone")), "public")


def _zone_objects(zones) -> list[dict]:
    # These are presentation segments only. Each node retains network_zone so
    # scoring and enforced four-zone reachability remain unchanged.
    return [dict(zone) for zone in DISPLAY_SEGMENTS]


def build_full_topology(build_dir: Path) -> dict:
    topo = json.loads((build_dir / "topology.json").read_text(encoding="utf-8"))
    try:
        live = json.loads((build_dir / "live-state.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        live = {}

    selected = set(live.get("selected", []))
    # Brain LXC guests (CORP/DATA) come up via keystone.live lxc-recreate, which
    # records them under lxc_selected. Treat those as live too. Entries may be
    # plain ids or {"id": ...} dicts depending on tool version.
    for entry in live.get("lxc_selected", []):
        selected.add(entry.get("id") if isinstance(entry, dict) else entry)
    blocked = {vm.get("id") for vm in live.get("vms", []) if str(vm.get("state", "")).lower() == "blocked"}

    def state_for(node_id: str) -> str:
        if node_id == "attacker":
            return "running"
        if node_id in selected:
            return "reachable"
        if node_id in blocked:
            return "locked"
        return "stopped"

    nodes = []
    live_ids = set()
    for n in topo.get("nodes", []):
        nid = n.get("id")
        state = state_for(nid)
        if state in ("running", "reachable"):
            live_ids.add(nid)
        node = dict(n)
        node["network_zone"] = n.get("network_zone") or n.get("zone")
        node["zone"] = _display_zone(node)
        node["label"] = FRIENDLY_NAMES.get(str(nid), n.get("label") or str(nid))
        if nid == "attacker":
            node["operator_platform"] = True
        node["state"] = state
        node["address"] = n.get("address") or n.get("ip") or "—"
        nodes.append(node)

    edges = []
    for e in topo.get("edges", []):
        edge = dict(e)
        # Dim any edge that touches a host which is not actually up this run.
        if e.get("src") not in live_ids or e.get("dst") not in live_ids:
            edge["connected"] = False
        edges.append(edge)

    return {"nodes": nodes, "edges": edges, "zones": _zone_objects(topo.get("zones", []))}


def publish_full(run_dir: str | Path, build_dir: Optional[str | Path] = None) -> Optional[int]:
    """Rewrite run_dir/dashboard/topology.json with the full range. Returns node
    count, or None if the build design could not be read (caller treats as no-op)."""
    run_dir = Path(run_dir).expanduser()
    if build_dir is None:
        # runs/<id> -> ../../build
        build_dir = run_dir.parent.parent / "build"
    build_dir = Path(build_dir).expanduser()
    if not (build_dir / "topology.json").is_file():
        return None
    full = build_full_topology(build_dir)
    dashboard = run_dir / "dashboard"
    dashboard.mkdir(parents=True, exist_ok=True)
    path = dashboard / "topology.json"
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(full, indent=2), encoding="utf-8")
    tmp.replace(path)
    return len(full["nodes"])


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run-dir", required=True, help="Keystone runs/<id> to rewrite")
    ap.add_argument("--build-dir", default=None, help="keystone build/ dir (default: <run>/../../build)")
    args = ap.parse_args(argv)
    count = publish_full(args.run_dir, args.build_dir)
    if count is None:
        print("error: build/topology.json not found; nothing published", flush=True)
        return 2
    print(f"published full topology: {count} nodes -> {args.run_dir}/dashboard/topology.json", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
