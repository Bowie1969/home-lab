#!/usr/bin/env python3
"""Read-only live monitoring/visualization dashboard for keystone-range benchmark runs.

Stdlib-only (http.server + SSE), modelled on the attack-map/monitor.py pattern from
~/progression-demo-lab/attack-map/ but generalised: no hosted model call of any kind,
no SSH collectors, no packet capture. It only reads the run-telemetry files a sibling
project (keystone-range) is expected to write, and renders them. When no run is active
it shows the current range topology alone — no edges, events, or activity move on the
map unless a genuine engagement run is producing real telemetry.

Data contract consumed from ~/Projects/keystone-range/runs/<run_id>/dashboard/:
  topology.json  {"zones":[...], "nodes":[{"id","label","type","zone","position":[x,y]}],
                  "edges":[{"src","dst","kind","state"}]}
  events.jsonl   one JSON object per line:
                  {"run_id","ts","host","event","evidence", optional "node"/"edge"}
  status.json    {"run_id","range","state","started","model","score","flags":[...],
                  "current_step":{...}}

Event -> node/edge state vocabulary this dashboard understands (producers should emit
these "event" names so the graph recolors itself; anything else is still logged in the
event stream but does not move a node/edge between states):
  node_discovered -> discovered   node_reachable  -> reachable
  node_in_progress -> in-progress node_solved     -> solved
  node_data_read  -> data-read
  edge_discovered -> discovered   edge_used       -> used
  flag_captured   -> no state change; tallied into status.flags for the UI.

This server performs NO security actions. Run-control endpoints shell out only to
fixed scripts under keystone-range. The agent-NPC endpoints can update local agent
state and append structured commands to data/agent_commands.jsonl, but never execute
those commands; an external agent adapter must deliberately consume them.
"""
from __future__ import annotations

import argparse
import ipaddress
import itertools
import json
import os
import subprocess
import threading
import re
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlsplit
from urllib.request import Request, urlopen

HERE = Path(__file__).resolve().parent
DEMO_DIR = HERE / "demo"
LOG_DIR = HERE / "logs"
DATA_DIR = HERE / "data"
AGENTS_PATH = DATA_DIR / "agents.json"
AGENT_COMMANDS_PATH = DATA_DIR / "agent_commands.jsonl"
AGENT_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
AGENT_STATUSES = {"idle", "queued", "working", "paused", "blocked", "done", "error", "offline"}
AGENT_ACTIONS = {"assign", "pause", "resume", "cancel"}

NODE_EVENT_MAP = {
    # explicit state vocabulary (used by the demo dataset)
    "node_discovered": "discovered",
    "node_reachable": "reachable",
    "node_in_progress": "in-progress",
    "node_solved": "solved",
    "node_data_read": "data-read",
    # attack vocabulary actually emitted by keystone operators / keystone.emit
    "recon": "discovered",
    "scan": "discovered",
    "attack": "in-progress",
    "foothold": "in-progress",
    "exploit": "in-progress",
    "host_compromised": "solved",
    "privesc": "solved",
    "pivot": "in-progress",
    "implant": "solved",
    "persist": "solved",
    "lateral": "solved",
    "c2": "solved",
    "exfil": "data-read",
    "exfil_completed": "data-read",
    "data_read": "data-read",
    "crown_exfil": "data-read",
}
EDGE_EVENT_MAP = {
    "edge_discovered": "discovered",
    "edge_used": "used",
    "edge_connected": "discovered",
    "recon": "discovered",
    "scan": "discovered",
    "attack": "used",
    "foothold": "used",
    "exploit": "used",
    "host_compromised": "used",
    "privesc": "used",
    "pivot": "used",
    "implant": "used",
    "persist": "used",
    "lateral": "used",
    "c2": "used",
    "exfil": "used",
    "exfil_started": "used",
}
# states only advance, never regress (a late recon can't undo a compromise)
STATE_RANK = {"unknown": 0, "discovered": 1, "reachable": 2, "in-progress": 3, "solved": 4, "data-read": 5}


def stickier_state(prev: str | None, new: str | None) -> str:
    """Combine a node's previously-published state with this poll's state so the
    map never flickers. A node never drops back to unknown/grey on a transient
    read, an attack state only advances (a compromise never un-paints), and a
    plain health observation (running/stopped) still updates to the latest."""
    if not new or new == "unknown":
        return prev or new or "unknown"
    if not prev or prev == "unknown":
        return new
    pr, nr = STATE_RANK.get(prev), STATE_RANK.get(new)
    if pr is not None and nr is not None:
        return prev if pr >= nr else new   # attack/recon progression advances only
    if pr is not None and nr is None:
        return prev                        # keep an attack state over a health update
    if pr is None and nr is not None:
        return new                         # an attack signal supersedes plain health
    return new                             # both are health states: latest wins
FLAG_RE = re.compile(r"KEYSTONE\{[^}]+\}")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
DEMO_LOOP_PAUSE = 6.0  # seconds the finished demo run sits at "finished" before looping
ACTIVE_RUN_STATES = {"running", "starting", "active"}
# A held run (paused/blocked) is still the run the operator is watching: it
# stops writing telemetry while held, so it must survive the freshness window
# that active runs are judged by.
HELD_RUN_STATES = {"paused", "blocked", "hold", "holding", "suspended"}
FOCUS_CURRENT_EVENTS = {"agent_on_host", "evilkit_on_host", "host_entered"}
FOCUS_ACTIVITY_EVENTS = {"recon", "scan", "attack", "foothold", "exploit", "host_compromised",
                         "privesc", "persist", "pivot", "lateral", "implant", "c2",
                         "exfil_started", "exfil"}
FOCUS_ACTIVITY_WINDOW = 45.0
FOCUS_COMPROMISE_EVENTS = {"foothold", "host_compromised"}
FOCUS_EXFIL_START_EVENTS = {"exfil", "exfil_started", "exfil_start"}
FOCUS_EXFIL_END_EVENTS = {"exfil_stopped", "exfil_completed", "exfil_failed"}
ATTACK_FEATURE_DEFINITIONS = (
    ("recon", "Recon", {"recon", "scan", "node_discovered", "node_reachable"},
     {"nmap_scan", "rustscan", "masscan", "nuclei_scan", "ffuf_fuzz", "gobuster_dir",
      "verify_http", "nikto_scan", "wpscan", "testssl_scan", "smb_enum", "ldapsearch",
      "showmount", "arjun_scan", "js_mine", "kb_search"}),
    ("foothold", "Foothold", {"attack", "exploit", "foothold", "host_compromised"},
     {"sqlmap", "credential_spray", "netexec", "nxc", "smb_login", "kerberoast",
      "pass_the_hash", "certipy_find", "certipy_req", "laps_read"}),
    ("privesc", "Privilege escalation", {"privesc"}, {"password_crack"}),
    ("pivot", "Pivot", {"pivot"}, {"ssh_tunnel", "proxy_via_host"}),
    ("implant", "Implant", {"implant"},
     {"malware_generate", "malware_stage", "malware_deploy", "malware_test", "malware_polymorph"}),
    ("persist", "Persistence", {"persist"}, {"malware_persist", "malware_lotl"}),
    ("lateral", "Lateral movement", {"lateral"}, {"malware_worm"}),
    ("c2", "Command & control", {"c2"}, {"malware_c2", "hive_beacon"}),
    ("exfil", "Exfiltration", {"exfil", "exfil_started", "crown_exfil", "data_read", "node_data_read"},
     {"malware_classify"}),
)
TRAFFIC_KIND_BY_EVENT = {
    "recon": "recon",
    "scan": "recon",
    "attack": "attack",
    "exploit": "attack",
    "foothold": "attack",
    "host_compromised": "attack",
    "privesc": "attack",
    "pivot": "tunnel",
    "implant": "attack",
    "persist": "attack",
    "lateral": "attack",
    "c2": "attack",
    "exfil": "data",
    "exfil_started": "data",
}
TRAFFIC_ACTIVITY_WINDOW = 6.0
TRAFFIC_ACTIVE_STATUSES = {"started", "starting", "running", "active", "in-progress", "in_progress"}
TRAFFIC_INACTIVE_STATUSES = {"completed", "complete", "finished", "stopped", "paused", "failed", "error", "cancelled", "canceled"}


def load_settings() -> dict:
    """Optional JSON config at $LAB_DASHBOARD_CONFIG or ./config.json. All keys optional."""
    path = os.environ.get("LAB_DASHBOARD_CONFIG", str(HERE / "config.json"))
    candidate = Path(path)
    if not candidate.is_file():
        return {}
    with candidate.open(encoding="utf-8") as handle:
        settings = json.load(handle)
    if not isinstance(settings, dict):
        raise ValueError("Dashboard configuration must be a JSON object")
    return settings


SETTINGS = load_settings()
AGENT_TOKEN = str(SETTINGS.get("agent_token", os.environ.get("LAB_DASHBOARD_AGENT_TOKEN", ""))).strip()
KEYSTONE_ROOT = Path(
    SETTINGS.get("keystone_root", os.environ.get("LAB_DASHBOARD_KEYSTONE_ROOT", str(Path.home() / "Projects" / "keystone-range")))
).expanduser()
RUNS_DIR = KEYSTONE_ROOT / "runs"

RANGE_TOPOLOGY_FILENAME = "topology.json"

PRESENTATION_ZONES = [
    {"id": "attack", "label": "ATTACK · VLAN 66", "vlan": 66,
     "cidr": "10.10.66.0/24", "policy": "operator and mesh workers"},
    {"id": "fabric", "label": "FABRIC", "vlan": "trunk",
     "cidr": "802.1Q", "policy": "switch + perimeter firewall + virtualisation"},
    {"id": "dmz", "label": "DMZ · VLAN 9", "vlan": 9,
     "cidr": "10.99.50.0/24", "policy": "ATTACK → DMZ"},
    {"id": "corp", "label": "CORP · VLAN 50", "vlan": 50,
     "cidr": "10.50.0.0/24", "policy": "DMZ → CORP"},
    {"id": "data", "label": "DATA · VLAN 51", "vlan": 51,
     "cidr": "10.50.1.0/24", "policy": "CORP → vault :8200 only"},
    {"id": "management", "label": "MGMT · VLAN 1", "vlan": 1,
     "cidr": "10.10.0.0/24", "policy": "out-of-band administration"},
]

BRAIN_NODE_PRESENTATION = {
    "parrot-operator": ("Parrot · EvilKit mesh hub", "attack"),
    "pi-drop": ("EvilKit OS Pi · mesh worker", "corp"),
    "mesh-hub": ("EvilKit command relay", "attack"),
    "run8-vm": ("Staged Operator VM", "attack"),
    "g910": ("DMZ Edge Gateway", "dmz"),
    "g960": ("Guest Network Kiosk", "dmz"),
    "g100": ("Directory Services", "management"),
    "g200": ("Management Console", "management"),
    "g201": ("Endpoint Management", "management"),
    "g911": ("Public Customer Portal", "public"),
    "g922": ("Public Web Server", "public"),
    "g931": ("Mail Gateway", "public"),
    "g943": ("Customer Application", "public"),
    "g912": ("Automation Worker 01", "automation"),
    "g913": ("Automation Worker 02", "automation"),
    "g940": ("Finance Workstation", "users"),
    "g941": ("Sales Workstation", "users"),
    "g942": ("Reception Workstation", "users"),
    "g944": ("IT Administration Workstation", "users"),
    "g914": ("Finance Archive", "business"),
    "g920": ("Corporate File Services", "business"),
    "g921": ("HR Records Database", "business"),
    "g970": ("DMZ Web Host 01", "ksdmz"),
    "g971": ("DMZ Web Host 02", "ksdmz"),
    "g972": ("DMZ Shared Services Host", "ksdmz"),
    "g973": ("DMZ Build Host", "ksdmz"),
    "g950": ("Executive Workstation", "corp"),
    "g951": ("Executive File Services", "corp"),
    "g952": ("Staff Intranet", "corp"),
    "g953": ("Credentials Vault · crown", "data"),
    "g930": ("Corporate Domain Controller", "corp"),
    # Happy Time Weed estate (Proxmox 600-605).  These VMs all live on the
    # office VLAN; the Windows guests may not expose an address while they are
    # still in firmware/installer, so their intended address is supplied below.
    "g600": ("HTW Server · AD + Web + Crown", "corp"),
    "g601": ("HTW Owner Workstation", "corp"),
    "g602": ("HTW Accounting Workstation", "corp"),
    "g603": ("HTW Budtender POS", "corp"),
    "g604": ("HTW Office Manager", "corp"),
    "g605": ("HTW IT Contractor", "corp"),
}

HTW_NODE_DETAILS = {
    "g600": {
        "address": "10.50.0.10",
        "type": "ad",
        "stores": ["seed-to-sale database", "patient records", "financials", "domain credentials", "file shares"],
    },
    "g601": {
        "address": "10.50.0.11",
        "type": "workstation",
        "stores": ["owner documents", "saved portal login", "cached RDP credentials", "wallet seed"],
    },
    "g602": {
        "address": "10.50.0.12",
        "type": "workstation",
        "stores": ["accounting files", "saved service credentials", "invoice documents"],
    },
    "g603": {
        "address": "10.50.0.13",
        "type": "workstation",
        "stores": ["point-of-sale session", "local credentials"],
    },
    "g604": {
        "address": "10.50.0.14",
        "type": "web",
        "stores": ["staff schedule", "office documents", "internal application sessions"],
    },
    "g605": {
        "address": "10.50.0.15",
        "type": "workstation",
        "stores": ["deployment SSH key", "automation secrets", "break-glass credentials"],
    },
}

POD_PRESENTATION = {
    "pod-edge-upload": "Upload Service",
    "pod-portal-sqli": "Customer Portal API",
    "pod-render-ssti": "Report Rendering Service",
    "pod-legacy-cve": "Legacy Integration Service",
    "pod-gitleak-api": "Source Search Service",
    "pod-meta-ssrf": "Metadata Proxy",
    "pod-token-jwt": "Token Gateway",
    "pod-cache-open": "Shared Cache",
    "pod-ssh-weak": "Remote Access Gateway",
    "pod-share-anon": "Partner File Exchange",
    "pod-cron-root": "Job Scheduler",
    "pod-runner-escape": "Build Runner",
    "pod-edge-botnet": "Edge Analytics Service",
    "pod-key-reuse": "Deployment Service",
}


def apply_topology_presentation(topology: dict) -> dict:
    """Apply the current names/segments to fresh or stale topology snapshots.

    This layer is lab-specific: it renames known keystone hosts, injects the
    physical fabric and re-zones nodes by IP prefix. A topology containing none
    of the known lab hosts — an USB-stick estate read straight off a stick, say —
    is left to describe itself, zones included, so a foreign range is not
    silently re-zoned into segments it does not belong to.
    """
    presented = dict(topology)
    incoming_ids = {str(node.get("id") or "") for node in topology.get("nodes", [])}
    is_keystone_lab = bool(incoming_ids & (set(BRAIN_NODE_PRESENTATION) | set(POD_PRESENTATION)))
    nodes = []
    for raw in topology.get("nodes", []):
        node = dict(raw)
        node_id = str(node.get("id") or "")
        observed_address = str(node.get("address") or node.get("real_ip") or node.get("ip") or "").strip()
        node["network_zone"] = node.get("network_zone") or node.get("zone")
        if node_id in BRAIN_NODE_PRESENTATION:
            label, zone = BRAIN_NODE_PRESENTATION[node_id]
            node["label"] = label
            node["zone"] = zone
            if zone == "attack":
                node["operator_platform"] = True
        elif node_id in POD_PRESENTATION:
            node["label"] = POD_PRESENTATION[node_id]
            node["zone"] = "dmz"
        if node_id in HTW_NODE_DETAILS:
            details = HTW_NODE_DETAILS[node_id]
            node["type"] = details["type"]
            node["stores"] = list(details["stores"])
            # qm cannot see a static address until the guest OS is up.  Keep
            # the estate legible during provisioning, but explicitly mark a
            # configured rather than observed address in the inspector.
            if not observed_address or observed_address == "—":
                node["address"] = details["address"]
                telemetry = dict(node.get("telemetry") or {})
                telemetry["network"] = "planned address · guest network not observed yet"
                telemetry["provisioning"] = "guest OS/network not ready"
                node["telemetry"] = telemetry
        address = str(node.get("address") or node.get("real_ip") or node.get("ip") or "")
        # Re-zoning by IP prefix repairs stale snapshots of THIS lab. A foreign
        # topology (a stick estate) declares its own zones and its subnets mean
        # something else entirely, so the prefix map must not be applied to it.
        if is_keystone_lab and node_id not in {"parrot-operator", "pi-drop", "mesh-hub", "run8-vm"}:
            if "10.50.1." in address:
                node["zone"] = "data"
            elif "10.50.0." in address:
                node["zone"] = "corp"
            elif "10.10.66." in address:
                node["zone"] = "attack"
            elif "10.99.50." in address or "10.80.10." in address:
                node["zone"] = "dmz"
            elif "192.168.0." in address:
                node["zone"] = "management"
            elif node.get("network_zone") in {"attacker", "dmz", "corp", "data"}:
                node["zone"] = {"attacker": "attack"}.get(node["network_zone"], node["network_zone"])
        if node_id == "pi-drop":
            node.update({
                "host": "Raspberry Pi 4 · EvilKit OS physical worker · SG108E p3",
                "address": "10.50.0.220 · MAC 98:fe:54:3f:b9:62",
                "deployment_segment": "CORP access port · VLAN 50",
                "target_address": "10.50.0.220",
                "operator_platform": True,
            })
        nodes.append(node)

    fabric_nodes = [
        {"id": "fabric-asus", "label": "Asus RT-AX1800S", "host": "edge / egress gate",
         "type": "router", "zone": "fabric", "address": "10.10.66.1 · mgmt 192.168.0.1", "state": "reachable", "position": [20, 15]},
        {"id": "fabric-switch", "label": "TP-Link SG108E", "host": "802.1Q managed switch",
         "type": "switch", "zone": "fabric", "address": "10.10.0.5", "state": "reachable", "position": [26, 38]},
        {"id": "fabric-hex", "label": "Corporate Perimeter Firewall", "host": "MikroTik hEX · default-deny inter-zone gateway",
         "type": "router", "zone": "fabric", "address": "10.10.0.1", "state": "reachable", "position": [34, 50]},
        {"id": "fabric-brain", "label": "lab-brain · Proxmox", "host": "vmbr9 / vmbr50 / vmbr51",
         "type": "server", "zone": "fabric", "address": "192.168.0.240", "state": "reachable", "position": [42, 62]},
    ]
    existing = {node.get("id") for node in nodes}
    if is_keystone_lab:
        nodes.extend(node for node in fabric_nodes if node["id"] not in existing)
    zones = [dict(zone) for zone in PRESENTATION_ZONES] if is_keystone_lab else list(topology.get("zones", []))
    presented["nodes"] = nodes
    presented["zones"] = zones
    physical_edges = [
        {"src": "parrot-operator", "dst": "fabric-asus", "kind": "fabric", "state": "reachable", "label": "lab Wi-Fi · ATTACK VLAN 66"},
        {"src": "fabric-asus", "dst": "fabric-switch", "kind": "fabric", "state": "reachable", "label": "lan1 ↔ p6 access · VLAN 66"},
        {"src": "fabric-switch", "dst": "fabric-hex", "kind": "fabric", "state": "reachable", "label": "p1 ↔ lan5 · VLAN 9/50/51/66"},
        {"src": "fabric-hex", "dst": "fabric-brain", "kind": "fabric", "state": "reachable", "label": "lan2 · VLAN 9/50/51"},
        {"src": "fabric-switch", "dst": "pi-drop", "kind": "fabric", "state": "reachable", "label": "p4 access · VLAN 50"},
    ]
    edges = list(topology.get("edges", []))
    edge_keys = {(edge.get("src"), edge.get("dst"), edge.get("kind")) for edge in edges}
    if is_keystone_lab:
        edges.extend(edge for edge in physical_edges
                     if (edge["src"], edge["dst"], edge["kind"]) not in edge_keys)
        # The HTW estate is one flat CORP broadcast domain. Once EvilKit owns
        # any estate guest it can address every other estate guest directly;
        # these are potential pivot paths, not claims of observed traffic.
        htw_nodes = sorted(
            (node for node in nodes if node.get("id") in HTW_NODE_DETAILS),
            key=lambda node: node["id"],
        )
        for source, target in itertools.combinations(htw_nodes, 2):
            edges.append({
                "src": source["id"],
                "dst": target["id"],
                "kind": "pivot-possible",
                "state": "unknown",
                "direction": "both",
                "connected": False,
                "direct": True,
                "pivot_possible": True,
                "label": "direct CORP pivot possible · VLAN 50",
            })
        # Keep the cross-zone attack graph readable: every exposed DMZ service
        # can reach the HTW public web/DC entry host directly, then the CORP
        # mesh above describes onward movement. Drawing every service against
        # every workstation would assert the same policy 84 times and obscure
        # the live traffic layer.
        htw_entry = next((node for node in htw_nodes if node["id"] == "g600"), None)
        service_nodes = sorted(
            (node for node in nodes if str(node.get("id") or "").startswith("pod-")
             and node.get("zone") == "dmz"),
            key=lambda node: node["id"],
        )
        if htw_entry:
            for service in service_nodes:
                edges.append({
                    "src": service["id"],
                    "dst": htw_entry["id"],
                    "kind": "pivot-possible",
                    "state": "unknown",
                    "direction": "forward",
                    "connected": False,
                    "direct": True,
                    "pivot_possible": True,
                    "label": "direct service pivot possible · DMZ → HTW web entry",
                })
        # Show the firewall's business role explicitly.  These are policy-path
        # relationships, not claims that every host has a dedicated physical
        # cable to the appliance.  Keep existing physical/telemetry links for
        # pairs already represented so the graph has exactly one resting path
        # between the firewall and each displayed asset.
        firewall_id = "fabric-hex"
        linked = {
            frozenset((str(edge.get("src") or ""), str(edge.get("dst") or "")))
            for edge in edges
            if firewall_id in {edge.get("src"), edge.get("dst")}
        }
        for node in nodes:
            node_id = str(node.get("id") or "")
            pair = frozenset((firewall_id, node_id))
            if not node_id or node_id == firewall_id or pair in linked:
                continue
            edges.append({
                "src": firewall_id,
                "dst": node_id,
                "kind": "firewall",
                "state": "reachable",
                "label": "perimeter policy path",
            })
            linked.add(pair)
    presented["edges"] = edges
    return presented


def apply_provisioning_states(nodes: list[dict]) -> None:
    """Do not paint a powered-on but not-yet-networked estate VM as healthy.

    Proxmox reports firmware, WinPE, and an installed guest as the same
    ``running`` state.  The missing guest address is the stable signal we have
    during provisioning; once the OS brings its configured NIC up, the normal
    live state takes over automatically.
    """
    for node in nodes:
        if node.get("id") not in HTW_NODE_DETAILS:
            continue
        network = str((node.get("telemetry") or {}).get("network") or "")
        if "guest network not observed" not in network:
            continue
        if node.get("state") in {"unknown", "discovered", "reachable", "running"}:
            node["state"] = "in-progress"


def range_topology_path() -> Path:
    """Where the range design lives. Resolved per call from KEYSTONE_ROOT so a
    relocated root (tests, an alternate checkout) is honoured rather than the
    import-time default."""
    root = globals().get("KEYSTONE_ROOT", Path.home() / "Projects" / "keystone-range")
    return Path(root) / "build" / RANGE_TOPOLOGY_FILENAME


def load_range_topology() -> dict | None:
    """The real Keystone range topology (build/topology.json).

    Used as the fallback view when no run is active, so the board always shows
    the actual Keystone hosts rather than the bundled demo sample.
    """
    try:
        data = json.loads(range_topology_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not data.get("nodes"):
        return None
    return apply_topology_presentation(data)


STICK_PACK_ROOT = "keystone-ranges"


def stick_mounts(mounts_text: str | None = None) -> list[Path]:
    """Mount points of removable block devices, from /proc/mounts.

    ``mounts_text`` is injectable so the stick scan can be tested without real
    removable hardware.
    """
    if mounts_text is None:
        try:
            mounts_text = Path("/proc/mounts").read_text(encoding="utf-8")
        except OSError:
            return []
    mounts: list[Path] = []
    for line in mounts_text.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        device = parts[0]
        if device.startswith("/dev/sd") or device.startswith("/dev/mmcblk"):
            mounts.append(Path(parts[1]))
    return mounts


def stick_topology_paths(mounts_text: str | None = None) -> list[Path]:
    """Every range pack's topology.json on every inserted stick.

    Read-only by design: a stick in use must stay byte-identical to its
    manifest, so the dashboard never writes to it. One range per stick is the
    packing rule, so more than one result means the stick was packed wrong.
    """
    found: list[Path] = []
    for mount in stick_mounts(mounts_text):
        packs = mount / STICK_PACK_ROOT
        if not packs.is_dir():
            continue
        for pack in sorted(packs.iterdir(), key=lambda p: str(p)):
            candidate = pack / RANGE_TOPOLOGY_FILENAME
            if pack.is_dir() and candidate.is_file():
                found.append(candidate)
    return found


def load_stick_topology(mounts_text: str | None = None) -> tuple[dict | None, str]:
    """The topology of the range on the inserted stick, plus a source note.

    Deliberately NOT passed through apply_topology_presentation: a stick estate
    is self-describing — its own zones, labels and positions — and the lab
    presentation layer would re-zone it into segments it does not belong to.
    """
    paths = stick_topology_paths(mounts_text)
    if not paths:
        return None, ""
    if len(paths) > 1:
        return None, (f"{len(paths)} range packs are inserted "
                      f"({', '.join(p.parent.name for p in paths)}); one range per stick")
    try:
        data = json.loads(paths[0].read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None, f"stick topology unreadable: {paths[0]}"
    if not isinstance(data, dict) or not data.get("nodes"):
        return None, f"stick topology has no nodes: {paths[0]}"
    data.setdefault("range", paths[0].parent.name)
    return data, f"stick {paths[0].parent.name}"


def load_fleet_telemetry() -> tuple[dict[str, dict], list[dict]]:
    """Read the router/host health snapshot and fresh firewall flows."""
    boxes: dict[str, dict] = {}
    fleet_path = RUNS_DIR / "live-brain" / "dashboard" / "fleet.json"
    try:
        fleet = json.loads(fleet_path.read_text(encoding="utf-8"))
        boxes = {str(box.get("name")): box for box in fleet.get("boxes", []) if box.get("name")}
    except (OSError, ValueError, AttributeError):
        pass
    flows: list[dict] = []
    for path in (
        Path(f"/run/user/{os.getuid()}/fleet-syslog.json"),
        Path(f"/run/user/{os.getuid()}/fleet-poll-flows.json"),
    ):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                flows.extend(flow for flow in payload.get("flows", []) if isinstance(flow, dict))
        except (OSError, ValueError):
            pass
    return boxes, flows


def enrich_fabric_telemetry(nodes: list[dict], boxes: dict[str, dict]) -> None:
    device_boxes = {
        "fabric-asus": "asus (lab-edge)",
        "fabric-hex": "hex (labrouter)",
        "fabric-brain": "lab-brain",
        "parrot-operator": "parrot (operator)",
        "pi-drop": "pi (drop01)",
    }
    by_id = {node.get("id"): node for node in nodes}
    for node_id, box_name in device_boxes.items():
        node, box = by_id.get(node_id), boxes.get(box_name)
        if not node or not box:
            continue
        node["state"] = "reachable" if box.get("reachable") else "discovered"
        node["telemetry_source"] = "fleet watcher"
        node["telemetry_status"] = "online" if box.get("reachable") else "offline"
        node["telemetry"] = dict(box.get("telemetry") or {})
        if box.get("detail"):
            node["telemetry"]["uptime"] = box["detail"]


def firewall_overlays(nodes: list[dict], flows: list[dict]) -> tuple[list[dict], list[dict]]:
    """Turn fresh router denies into graph links and event-feed records."""
    ip_to_node: dict[str, str] = {}
    for node in nodes:
        for address in _IP_RE.findall(str(node.get("address") or node.get("ip") or "")):
            ip_to_node[address.split("/")[0]] = str(node.get("id"))
    router_ids = {"labrouter": "fabric-hex", "lab-edge": "fabric-asus"}
    fallback_peer = {"fabric-hex": "fabric-switch", "fabric-asus": "fabric-switch"}
    overlays, events, seen = [], [], set()
    for flow in sorted(flows, key=lambda item: float(item.get("ts") or 0), reverse=True):
        router = router_ids.get(str(flow.get("router") or ""))
        if not router:
            continue
        src_ip, dst_ip = str(flow.get("src") or ""), str(flow.get("dst") or "")
        src = ip_to_node.get(src_ip)
        dst = ip_to_node.get(dst_ip)
        if src and dst:
            edge_src, edge_dst = src, dst
        elif src:
            edge_src, edge_dst = src, router
        elif dst:
            edge_src, edge_dst = router, dst
        else:
            edge_src, edge_dst = router, fallback_peer[router]
        key = (edge_src, edge_dst, flow.get("class"), flow.get("dpt"), router)
        if key in seen:
            continue
        seen.add(key)
        kind = "attack" if flow.get("class") == "attack" else "recon"
        label = "Corporate Perimeter Firewall" if router == "fabric-hex" else "ASUS syslog"
        overlays.append({
            "src": edge_src, "dst": edge_dst, "kind": kind, "state": "used",
            "connected": True, "tool": label, "direction": "forward",
            "label": f"blocked {flow.get('proto') or ''}/{flow.get('dpt') or '*'}",
        })
        events.append({
            "event": "firewall_drop", "host": router, "node": router,
            "ts": float(flow.get("ts") or time.time()),
            "tool": label,
            "evidence": (f"blocked {src_ip} → {dst_ip} "
                         f"{flow.get('proto') or ''}/{flow.get('dpt') or '*'} · "
                         f"{flow.get('prefix') or 'firewall policy'}"),
            "edge": {"src": edge_src, "dst": edge_dst},
        })
    return overlays[:20], events[:20]
CONTROL_SCRIPTS = {
    "start": Path(SETTINGS.get("start_script", str(KEYSTONE_ROOT / "bin" / "start.sh"))).expanduser(),
    "reset": Path(SETTINGS.get("reset_script", str(KEYSTONE_ROOT / "bin" / "reset.sh"))).expanduser(),
    "stop": Path(SETTINGS.get("stop_script", str(KEYSTONE_ROOT / "bin" / "stop.sh"))).expanduser(),
}


def _optional_path(setting: str, environment: str) -> Path | None:
    value = str(SETTINGS.get(setting, os.environ.get(environment, ""))).strip()
    return Path(value).expanduser() if value else None


EVILKIT_MESH_CONNECTION = _optional_path("evilkit_mesh_connection", "EVILKIT_MESH_CONNECTION_FILE")
EVILKIT_MESH_TOKEN = _optional_path("evilkit_mesh_token", "EVILKIT_MESH_TOKEN_FILE")
EVILKIT_CLONE_LOG = _optional_path("evilkit_clone_log", "EVILKIT_CLONE_DISPLAY_LOG")
EVILKIT_CLONE_WINDOWS = _optional_path("evilkit_clone_windows", "EVILKIT_CLONE_WINDOW_REGISTRY")


def _pid_alive(pid: object) -> bool:
    if not isinstance(pid, int) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _clone_node_id(nodes: list[dict], name: str, host: str) -> str | None:
    """Best-effort match of a mesh clone to its physical topology node."""
    needles = [value.lower() for value in (name, host) if value]
    exact_fields = ("id", "label", "hostname", "name")
    for node in nodes:
        for field in exact_fields:
            if str(node.get(field, "")).lower() in needles:
                return node.get("id")
    for node in nodes:
        haystack = " ".join(str(node.get(field, "")) for field in
                            ("id", "label", "host", "hostname", "address", "ip")).lower()
        if any(needle and needle in haystack for needle in needles):
            return node.get("id")
    return None


class EvilKitMeshReader:
    """Read the local EvilKit hub's status without exposing its bearer token."""

    def __init__(self, connection: Path | None = EVILKIT_MESH_CONNECTION,
                 token: Path | None = EVILKIT_MESH_TOKEN,
                 clone_log: Path | None = EVILKIT_CLONE_LOG,
                 windows: Path | None = EVILKIT_CLONE_WINDOWS):
        self.connection = connection
        self.token = token
        self.clone_log = clone_log
        self.windows = windows
        self._last_good: list[dict] = []

    @staticmethod
    def _safe_hub_url(value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme != "http" or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise ValueError("mesh hub URL must be plain HTTP with no path")
        try:
            address = ipaddress.ip_address(parsed.hostname or "")
        except ValueError as exc:
            raise ValueError("mesh hub must use a numeric loopback or Tailscale address") from exc
        if not (address.is_loopback or address in ipaddress.ip_network("100.64.0.0/10")):
            raise ValueError("mesh hub is outside loopback/Tailscale")
        if parsed.port is None:
            raise ValueError("mesh hub needs an explicit port")
        return value.rstrip("/")

    def _display_metadata(self) -> tuple[dict[str, str], set[str]]:
        hosts: dict[str, str] = {}
        if self.clone_log and self.clone_log.is_file():
            for record in read_jsonl(self.clone_log):
                name, host = str(record.get("clone", "")), str(record.get("host", ""))
                if name and host:
                    hosts[name] = host
        open_windows: set[str] = set()
        if self.windows and self.windows.is_file():
            try:
                registry = json.loads(self.windows.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                registry = {}
            for name, entry in registry.items() if isinstance(registry, dict) else ():
                if isinstance(entry, dict) and _pid_alive(entry.get("pid")):
                    open_windows.add(str(name))
                    if entry.get("host"):
                        hosts[str(name)] = str(entry["host"])
        return hosts, open_windows

    def _fallback(self, nodes: list[dict], error: str) -> dict:
        hosts, open_windows = self._display_metadata()
        clones = [dict(clone) for clone in self._last_good]
        known = {clone["name"] for clone in clones}
        for name, host in hosts.items():
            if name in known:
                continue
            clones.append({
                "name": name, "host": host, "status": "detected", "task": None,
                "activity": "Detected on the attack segment; hub state unavailable",
                "last_seen": None, "terminal_open": name in open_windows,
                "node_id": _clone_node_id(nodes, name, host),
            })
        for clone in clones:
            clone["terminal_open"] = clone["name"] in open_windows
            clone["node_id"] = _clone_node_id(nodes, clone["name"], clone.get("host", ""))
        return {"connected": False, "error": error, "clones": clones}

    def read(self, nodes: list[dict], *, now: float | None = None) -> dict:
        now = time.time() if now is None else now
        if not self.connection or not self.token:
            return self._fallback(nodes, "Mesh telemetry is not configured")
        try:
            connection = json.loads(self.connection.read_text(encoding="utf-8"))
            hub = self._safe_hub_url(str(connection["leader"]))
            bearer = self.token.read_text(encoding="ascii").strip()
            if len(bearer) < 32:
                raise ValueError("mesh token is invalid")
            request = Request(hub + "/state", headers={"Authorization": f"Bearer {bearer}"})
            with urlopen(request, timeout=0.6) as response:
                state = json.load(response)
            if not isinstance(state, dict):
                raise ValueError("mesh hub returned invalid state")
        except (OSError, ValueError, KeyError, HTTPError, URLError, TimeoutError) as exc:
            return self._fallback(nodes, f"{type(exc).__name__}: {exc}")

        hosts, open_windows = self._display_metadata()
        tasks = {str(task.get("id")): task for task in state.get("tasks", [])
                 if isinstance(task, dict) and task.get("id")}
        clones = []
        for worker in state.get("workers", []):
            if not isinstance(worker, dict) or not worker.get("name"):
                continue
            name = str(worker["name"])
            seen = float(worker.get("seen") or 0)
            task = tasks.get(str(worker.get("task")))
            stale = not seen or now - seen > 30
            status = "offline" if stale else str(worker.get("status") or "idle")
            prompt = " ".join(str((task or {}).get("prompt") or "").split())
            activity = (prompt[:177] + "...") if len(prompt) > 180 else prompt
            if not activity:
                activity = "Offline" if stale else "Standing by for a task"
            host = hosts.get(name, "")
            clones.append({
                "name": name,
                "host": host,
                "status": status,
                "task": str((task or {}).get("id") or "") or None,
                "task_status": str((task or {}).get("status") or "") or None,
                "activity": activity,
                "last_seen": seen or None,
                "terminal_open": name in open_windows,
                "node_id": _clone_node_id(nodes, name, host),
            })
        clones.sort(key=lambda clone: (clone["status"] not in {"running", "working"}, clone["name"]))
        self._last_good = [dict(clone) for clone in clones]
        return {"connected": True, "error": None, "clones": clones, "updated_at": now}


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def read_jsonl(path: Path) -> list[dict]:
    records = []
    try:
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except ValueError:
                    continue
    except FileNotFoundError:
        pass
    return records


def apply_events(events: list[dict]) -> tuple[dict, dict, list]:
    """Replay events in order, returning (node_states, edge_states, flags)."""
    node_states: dict[str, str] = {}
    edge_states: dict[tuple, str] = {}
    flags: list[str] = []
    def bump(node: str | None, state: str) -> None:
        if not node:
            return
        if STATE_RANK.get(state, 0) >= STATE_RANK.get(node_states.get(node, "unknown"), 0):
            node_states[node] = state

    for ev in events:
        kind = ev.get("event", "")
        node = ev.get("node")
        edge = ev.get("edge")
        if kind in NODE_EVENT_MAP:
            bump(node, NODE_EVENT_MAP[kind])
        # edge from an explicit {src,dst} dict or from top-level src/dst fields
        if isinstance(edge, dict):
            src, dst = edge.get("src"), edge.get("dst")
        else:
            src, dst = ev.get("src"), ev.get("dst")
        if src and dst and kind in EDGE_EVENT_MAP:
            edge_states[(src, dst)] = EDGE_EVENT_MAP[kind]
        # flags: an explicit flag_captured event, plus any KEYSTONE{...} string that
        # operators embed in evidence (e.g. "... -> www-data, flag KEYSTONE{...}")
        if kind == "flag_captured":
            flag = ev.get("flag") or ev.get("evidence")
            if flag and flag not in flags:
                flags.append(flag)
            bump(node, "solved")
        for match in FLAG_RE.findall(str(ev.get("evidence", ""))):
            if match not in flags:
                flags.append(match)
    return node_states, edge_states, flags


# Map run-topology node IDs to brain-topology IDs. The keystone run uses short
# module names (edge-upload, portal-sqli) while the brain's live lab map prefixes
# pods with "pod-" and uses Proxmox guest IDs (g910, g960) for the VMs. When a
# run starts we swap to the richer brain topology, so events must be translated
# to hit the right nodes.
RUN_TO_BRAIN_NODE = {
    "attacker": "parrot-operator",
    "edge-upload": "pod-edge-upload",
    "portal-sqli": "pod-portal-sqli",
    "render-ssti": "pod-render-ssti",
    "legacy-cve": "pod-legacy-cve",
    "gitleak-api": "pod-gitleak-api",
    "meta-ssrf": "pod-meta-ssrf",
    "token-jwt": "pod-token-jwt",
    "cache-open": "pod-cache-open",
    "ssh-weak": "pod-ssh-weak",
    "share-anon": "pod-share-anon",
    "cron-root": "pod-cron-root",
    "runner-escape": "pod-runner-escape",
    "ssh-tunnel-corp-probe": "g910",
}


def _node_alias_values(node: dict) -> set[str]:
    """Names and addresses that can identify one topology node.

    Run topology IDs are logical module names while the live brain topology
    uses pod/guest IDs. Keep every useful spelling so real-run events and
    status snapshots can resolve to whichever representation is on screen.
    """
    values: set[str] = set()
    raw_values = [
        node.get("id"), node.get("label"), node.get("host"), node.get("ip"),
        node.get("address"), node.get("real_ip"), *(node.get("aliases") or []),
    ]
    for value in raw_values:
        if value is None:
            continue
        text = str(value).strip()
        if not text:
            continue
        values.add(text.lower())
        # Brain host labels commonly look like "dc01 (930)" or
        # "edge-upload (DMZ pod)" while runs emit only the leading hostname.
        leading = text.split(" (", 1)[0].strip()
        if leading:
            values.add(leading.lower())
        values.update(ip.lower() for ip in _IP_RE.findall(text))
    return values


def _normalised_run_positions(nodes: list[dict]) -> dict[str, list[float]]:
    """Return run-node positions in the browser's 0-100 coordinate space."""
    valid = [
        node for node in nodes
        if isinstance(node.get("position"), list) and len(node["position"]) == 2
        and all(isinstance(value, (int, float)) for value in node["position"])
    ]
    if not valid:
        return {}
    xs = [float(node["position"][0]) for node in valid]
    ys = [float(node["position"][1]) for node in valid]
    absolute = min(xs) < 0 or max(xs) > 100 or min(ys) < 0 or max(ys) > 100
    if not absolute:
        return {node["id"]: list(node["position"]) for node in valid}

    def scale(value: float, low: float, high: float) -> float:
        return 50.0 if high == low else 10.0 + (value - low) * 80.0 / (high - low)

    return {
        node["id"]: [
            scale(float(node["position"][0]), min(xs), max(xs)),
            scale(float(node["position"][1]), min(ys), max(ys)),
        ]
        for node in valid
    }


def merge_run_and_brain_topologies(run_topology: dict, brain_topology: dict) -> tuple[dict, dict[str, str]]:
    """Merge a benchmark topology into the full live-lab topology.

    Equivalent nodes keep the brain ID/layout/health metadata. Run-only nodes
    are retained so a compromise can never disappear merely because the brain
    map has more total nodes. The returned mapping translates run telemetry to
    the IDs actually rendered by the merged topology.
    """
    run_nodes = list(run_topology.get("nodes", []))
    brain_nodes = [dict(node) for node in brain_topology.get("nodes", [])]
    brain_by_id = {node.get("id"): node for node in brain_nodes if node.get("id")}
    alias_index: dict[str, set[str]] = {}
    for node in brain_nodes:
        for alias in _node_alias_values(node):
            alias_index.setdefault(alias, set()).add(node["id"])

    mapping: dict[str, str] = {}
    for node in run_nodes:
        run_id = node.get("id")
        if not run_id:
            continue
        candidates = [RUN_TO_BRAIN_NODE.get(run_id), run_id, f"pod-{run_id}"]
        target = next((candidate for candidate in candidates if candidate in brain_by_id), None)
        if target is None:
            matches: set[str] = set()
            for alias in _node_alias_values(node):
                ids = alias_index.get(alias, set())
                if len(ids) == 1:
                    matches.update(ids)
            if len(matches) == 1:
                target = next(iter(matches))
        mapping[run_id] = target or run_id

    # Enrich equivalent brain nodes with the run spellings used by events and
    # status.compromised_hosts. Brain presentation and health fields still win.
    merged_by_id = {node["id"]: node for node in brain_nodes}
    positions = _normalised_run_positions(run_nodes)
    for node in run_nodes:
        run_id = node.get("id")
        if not run_id:
            continue
        target = mapping[run_id]
        if target in merged_by_id:
            brain_node = merged_by_id[target]
            aliases = set(brain_node.get("aliases") or [])
            aliases.update(value for value in (
                node.get("id"), node.get("label"), node.get("host"), node.get("ip"),
                node.get("address"), node.get("real_ip"),
            ) if value)
            enriched = {**node, **brain_node, "aliases": sorted(str(value) for value in aliases)}
            merged_by_id[target] = enriched
        else:
            added = dict(node)
            if run_id in positions:
                added["position"] = positions[run_id]
            merged_by_id[run_id] = added

    zones = []
    seen_zones = set()
    for zone in [*brain_topology.get("zones", []), *run_topology.get("zones", [])]:
        zone_id = zone.get("id") if isinstance(zone, dict) else str(zone)
        if zone_id in seen_zones:
            continue
        zones.append(dict(zone) if isinstance(zone, dict) else zone)
        seen_zones.add(zone_id)

    edges = []
    seen_edges = set()
    for source, translate in ((brain_topology.get("edges", []), False),
                              (run_topology.get("edges", []), True)):
        for raw in source:
            edge = dict(raw)
            if translate:
                edge["src"] = mapping.get(edge.get("src"), edge.get("src"))
                edge["dst"] = mapping.get(edge.get("dst"), edge.get("dst"))
            key = (edge.get("id"), edge.get("src"), edge.get("dst"), edge.get("kind"))
            if key in seen_edges:
                continue
            edges.append(edge)
            seen_edges.add(key)

    merged = {
        **run_topology,
        **brain_topology,
        "zones": zones,
        "nodes": list(merged_by_id.values()),
        "edges": edges,
    }
    return merged, mapping


def _map_event_nodes(events: list[dict], mapping: dict[str, str]) -> list[dict]:
    """Translate event node/host/edge IDs from run topology to brain topology."""
    mapped = []
    legacy_drop_origin = False
    for ev in events:
        ev = dict(ev)
        # Older MCP telemetry used g960 as a blanket "drop" origin. g960 is the
        # target-side guest kiosk; the separately modelled pi-drop node is the
        # portable red-team platform. Correct only that exact legacy origin
        # assertion, leaving genuine later pivots onto g960 untouched.
        event_kind = str(ev.get("event") or "").lower()
        legacy_assertion = event_kind == "agent_on_host" \
                and ev.get("node") == "g960" \
                and "mcp toolset operating from the drop" in str(ev.get("evidence") or "").lower()
        if legacy_assertion:
            ev["node"] = "pi-drop"
            legacy_drop_origin = True
        elif event_kind in FOCUS_CURRENT_EVENTS and ev.get("node") == "g960":
            # A later explicit assertion without the legacy wording is a real
            # pivot onto the guest kiosk, so subsequent edges must stay g960.
            legacy_drop_origin = False
        if ev.get("node") in mapping:
            ev["node"] = mapping[ev["node"]]
        if ev.get("host") in mapping:
            ev["host"] = mapping[ev["host"]]
        if isinstance(ev.get("edge"), dict):
            edge = dict(ev["edge"])
            if legacy_drop_origin and edge.get("src") == "g960":
                edge["src"] = "pi-drop"
            if edge.get("src") in mapping:
                edge["src"] = mapping[edge["src"]]
            if edge.get("dst") in mapping:
                edge["dst"] = mapping[edge["dst"]]
            ev["edge"] = edge
        for key in ("src", "dst"):
            if key == "src" and legacy_drop_origin and ev.get(key) == "g960":
                ev[key] = "pi-drop"
            if ev.get(key) in mapping:
                ev[key] = mapping[ev[key]]
        mapped.append(ev)
    return mapped


def live_target_states(events: list[dict]) -> dict[str, str]:
    """Use the latest Proxmox observation, including transitions back to stopped."""
    states = {}
    for event in events:
        node = event.get("node")
        if not node:
            continue
        evidence = str(event.get("evidence", ""))
        match = re.search(r"pct/qm status='([^']*)' lock='([^']*)'", evidence)
        if not match:
            continue
        status, lock = match.groups()
        states[node] = "locked" if lock else status if status in {"running", "stopped", "error"} else "unknown"
    return states


def edge_event_details(events: list[dict], now: float | None = None) -> dict[tuple[str, str], dict]:
    """Return traffic metadata plus whether each event-backed flow is still active."""
    now = time.time() if now is None else now
    details: dict[tuple[str, str], dict] = {}
    for event in events:
        edge = event.get("edge") if isinstance(event.get("edge"), dict) else {}
        src, dst = edge.get("src") or event.get("src"), edge.get("dst") or event.get("dst")
        if not src or not dst:
            continue
        record = details.setdefault((src, dst), {})
        explicit_connection = False
        for name in ("mcp_tool", "tool", "data_type", "direction", "connected", "connection"):
            value = edge.get(name, event.get(name))
            if value is not None:
                record[name] = value
                if name in {"connected", "connection"}:
                    explicit_connection = True
        traffic_kind = edge.get("traffic_class") or event.get("traffic_class")
        event_kind = str(event.get("event") or "").strip().lower()
        # A semantic EvilKit phase is part of the run's action trail even after
        # its live pulse expires. `connected` controls animation; `historical`
        # keeps the coloured path visible for the rest of the run.
        if event_kind in TRAFFIC_KIND_BY_EVENT:
            record["historical"] = True
        # Some producer APIs classify every post-exploit action as attack-class.
        # Preserve that generic contract except for semantically explicit exfil
        # events, which the dashboard renders as data flow.
        if event_kind in {"exfil", "exfil_started"}:
            record["kind"] = "data"
        elif traffic_kind in {"recon", "attack", "data", "tunnel"}:
            record["kind"] = traffic_kind
        elif event_kind in TRAFFIC_KIND_BY_EVENT:
            record["kind"] = TRAFFIC_KIND_BY_EVENT[event_kind]
        if event_kind == "edge_connected":
            record["connected"] = True
            record.pop("_transient_connection_ts", None)
        elif event_kind == "edge_disconnected":
            record["connected"] = False
            record.pop("_transient_connection_ts", None)
        elif not explicit_connection:
            status = str(event.get("status", "")).strip().lower()
            timestamp = event.get("ts")
            try:
                timestamp = float(timestamp)
            except (TypeError, ValueError):
                timestamp = now
            if status in TRAFFIC_ACTIVE_STATUSES:
                record["connected"] = True
                record["_transient_connection_ts"] = timestamp
            elif status in TRAFFIC_INACTIVE_STATUSES:
                record["connected"] = False
                record.pop("_transient_connection_ts", None)
            elif traffic_kind in {"recon", "attack", "data", "tunnel"} or event_kind in TRAFFIC_KIND_BY_EVENT:
                record["connected"] = now - timestamp <= TRAFFIC_ACTIVITY_WINDOW
                record["_transient_connection_ts"] = timestamp if record["connected"] else None
    for record in details.values():
        transient_ts = record.pop("_transient_connection_ts", None)
        if transient_ts is not None and now - transient_ts > TRAFFIC_ACTIVITY_WINDOW:
            record["connected"] = False
    return details


def traffic_is_connected(edge: dict) -> bool:
    """Normalise the supported connection spellings for server-side filtering."""
    connected = edge.get("connected")
    connection = str(edge.get("connection", "")).strip().lower()
    return connected is True or str(connected).strip().lower() in {"true", "connected", "active", "1"} \
        or connection in {"connected", "active", "true", "1"}


BEACON_ACTIVITY_WINDOW = 300.0  # a clone beacon keeps its edge "live" this long
BEACON_RETENTION = 3600.0       # older beacons are not drawn at all


def beacon_overlays(topology: dict, run_dir: Path, events: list[dict],
                    now: float | None = None) -> tuple[list[dict], dict[str, dict]]:
    """Turn the run's beacons.jsonl into clone-traffic overlays.

    Each beacon proves a clone is alive on a compromised host and calling home,
    so draw a C2 edge from that host's node to the run's operator origin. A
    beacon inside BEACON_ACTIVITY_WINDOW keeps the edge connected (pulsing);
    older ones stay as a faint disconnected line so the channel remains visible.
    Returns (edges, node_overlays) where node_overlays maps node id -> {bid, ts}.
    """
    now = time.time() if now is None else now
    beacons_path = Path(run_dir) / "beacons.jsonl"
    records = read_jsonl(beacons_path)
    if not records:
        return [], {}

    node_by_ip: dict[str, str] = {}
    for node in topology.get("nodes", []):
        for field in ("ip", "address", "real_ip", "host"):
            for ip in _IP_RE.findall(str(node.get(field) or "")):
                node_by_ip.setdefault(ip, node["id"])

    # The operator origin is where the run's agent has most recently been
    # reported; beacons home to it. Fall back to the operators-zone node.
    origin = None
    for event in reversed(events):
        if str(event.get("event", "")).lower() in FOCUS_CURRENT_EVENTS and event.get("node"):
            origin = event["node"]
            break
    if origin is None:
        for node in topology.get("nodes", []):
            if str(node.get("zone", "")).lower() in {"operators", "operator", "attacker"}:
                origin = node["id"]
                break
    if origin is None:
        return [], {}

    latest: dict[str, dict] = {}
    for record in records:
        src_ip = str(record.get("src") or record.get("host") or "")
        node_id = node_by_ip.get(src_ip)
        if not node_id:
            continue
        try:
            timestamp = float(record.get("ts") or 0)
        except (TypeError, ValueError):
            timestamp = 0
        if timestamp and now - timestamp > BEACON_RETENTION:
            continue
        if node_id not in latest or timestamp >= (latest[node_id].get("ts") or 0):
            latest[node_id] = {"ts": timestamp, "bid": record.get("bid", "")}

    edges: list[dict] = []
    overlays: dict[str, dict] = {}
    for node_id, beacon in latest.items():
        timestamp = beacon["ts"] or 0
        connected = bool(timestamp) and now - timestamp <= BEACON_ACTIVITY_WINDOW
        edges.append({
            "src": node_id,
            "dst": origin,
            "kind": "c2",
            "state": "used",
            "connected": connected,
            "mcp_tool": "beacon",
            "data_type": "telemetry",
            "direction": "forward",
            "bid": beacon["bid"],
        })
        overlays[node_id] = {"bid": beacon["bid"], "ts": timestamp}
    return edges, overlays


class AgentRegistry:
    """Persistent control plane for adapters and the Minecraft client.

    Commands are appended to JSONL and never executed by this process. A real
    agent integration must deliberately consume that queue and report state
    through ``update``. This keeps the dashboard and Minecraft mod incapable
    of invoking a shell or an agent runtime directly.
    """

    def __init__(self, agents_path: Path = AGENTS_PATH, commands_path: Path = AGENT_COMMANDS_PATH):
        self.agents_path = agents_path
        self.commands_path = commands_path
        self.lock = threading.Lock()

    @staticmethod
    def validate_id(agent_id: str) -> str:
        agent_id = str(agent_id).strip()
        if not AGENT_ID_RE.fullmatch(agent_id):
            raise ValueError("Agent id must be 1-64 letters, numbers, dots, dashes, or underscores")
        return agent_id

    def _read_unlocked(self) -> dict[str, dict]:
        try:
            raw = json.loads(self.agents_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, ValueError, OSError):
            return {}
        records = raw.get("agents", raw) if isinstance(raw, dict) else {}
        if isinstance(records, list):
            records = {item.get("id"): item for item in records if isinstance(item, dict) and item.get("id")}
        return {key: value for key, value in records.items() if isinstance(value, dict)} if isinstance(records, dict) else {}

    def _write_unlocked(self, agents: dict[str, dict]) -> None:
        self.agents_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.agents_path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps({"agents": list(agents.values())}, indent=2) + "\n", encoding="utf-8")
        temporary.replace(self.agents_path)

    def list(self) -> list[dict]:
        with self.lock:
            agents = self._read_unlocked()
        return sorted(agents.values(), key=lambda item: item["id"])

    def update(self, payload: dict, agent_id: str | None = None) -> dict:
        if not isinstance(payload, dict):
            raise ValueError("JSON object required")
        agent_id = self.validate_id(agent_id or payload.get("id", ""))
        allowed = {"name", "status", "current_task", "last_message", "kind"}
        with self.lock:
            agents = self._read_unlocked()
            previous = agents.get(agent_id, {})
            record = {"id": agent_id, "name": previous.get("name", agent_id), "status": previous.get("status", "offline")}
            record.update({key: value for key, value in previous.items() if key not in {"id", "updated_at"}})
            for key in allowed:
                if key in payload:
                    value = payload[key]
                    if value is not None and not isinstance(value, str):
                        raise ValueError(f"{key} must be a string or null")
                    record[key] = value
            status = str(record.get("status", "offline")).lower()
            if status not in AGENT_STATUSES:
                raise ValueError("Unsupported agent status")
            record["status"] = status
            if "status" in payload and previous:
                record.pop("pending_command", None)
            record["updated_at"] = time.time()
            agents[agent_id] = record
            self._write_unlocked(agents)
        return record

    def command(self, agent_id: str, payload: dict) -> dict:
        agent_id = self.validate_id(agent_id)
        if not isinstance(payload, dict):
            raise ValueError("JSON object required")
        action = str(payload.get("action", "")).strip().lower()
        if action not in AGENT_ACTIONS:
            raise ValueError("Action must be assign, pause, resume, or cancel")
        task = payload.get("task")
        if action == "assign":
            if not isinstance(task, str) or not task.strip():
                raise ValueError("Assign requires a non-empty task")
            task = task.strip()
            if len(task) > 500:
                raise ValueError("Task must be 500 characters or fewer")
        elif task is not None:
            raise ValueError("Only assign accepts a task")

        with self.lock:
            agents = self._read_unlocked()
            if agent_id not in agents:
                raise KeyError(agent_id)
            command = {
                "id": str(uuid.uuid4()),
                "agent_id": agent_id,
                "action": action,
                "created_at": time.time(),
                "source": "minecraft",
            }
            if task is not None:
                command["task"] = task
            self.commands_path.parent.mkdir(parents=True, exist_ok=True)
            with self.commands_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(command, separators=(",", ":")) + "\n")

            record = agents[agent_id]
            record["pending_command"] = command
            record["status"] = {"assign": "queued", "pause": "paused", "resume": "queued", "cancel": "idle"}[action]
            if action == "assign":
                record["current_task"] = task
            elif action == "cancel":
                record["current_task"] = None
            record["updated_at"] = time.time()
            self._write_unlocked(agents)
        return command


def run_focus(topology: dict, status: dict, events: list[dict], now: float | None = None) -> dict:
    """Three evidence-backed EvilKit highlights, scoped to one run."""
    now = time.time() if now is None else now
    nodes = topology.get("nodes", [])
    lookup = {}
    for node in nodes:
        for value in _node_alias_values(node):
            lookup[value] = node

    def host(value):
        if isinstance(value, dict):
            value = value.get("node") or value.get("id") or value.get("host")
        if value is None or str(value).strip() == "":
            return None
        raw = str(value).strip()
        node = lookup.get(raw.lower())
        if node:
            return {"id": node["id"], "label": node.get("label") or node["id"],
                    "address": node.get("address") or node.get("ip") or ""}
        return {"id": raw, "label": raw, "address": ""}

    current = None
    current_at = None
    current_explicit = False
    compromised = {}
    exfil = None
    exfil_at = None
    exfil_persistent = False
    for event in events:
        kind = str(event.get("event", "")).lower()
        evidence = str(event.get("evidence", "")).strip()
        edge = event.get("edge") if isinstance(event.get("edge"), dict) else {}
        target = host(event.get("node") or event.get("target_node") or edge.get("dst") or event.get("host"))
        source = host(event.get("source_node") or event.get("source_host") or event.get("node") or edge.get("src") or event.get("host"))
        activity_host = source if kind in {"exfil_started", "exfil"} else target
        if kind in FOCUS_CURRENT_EVENTS and target and evidence:
            current = target
            current_explicit = True
        elif kind in FOCUS_ACTIVITY_EVENTS and activity_host and evidence:
            try:
                activity_at = float(event.get("ts"))
                fresh_activity = 0 <= now - activity_at <= FOCUS_ACTIVITY_WINDOW
            except (TypeError, ValueError):
                fresh_activity = False
            if fresh_activity:
                current = activity_host
                current_at = activity_at
                current_explicit = False
        elif kind in {"agent_left_host", "evilkit_left_host", "host_left"}:
            current = None
        if kind in FOCUS_COMPROMISE_EVENTS and target and evidence:
            compromised[target["id"]] = target
        elif kind in {"host_recovered", "host_cleaned"} and target:
            compromised.pop(target["id"], None)
        if kind in FOCUS_EXFIL_START_EVENTS and source and evidence:
            exfil = source
            exfil_persistent = kind in {"exfil_started", "exfil_start"}
            try:
                exfil_at = float(event.get("ts"))
            except (TypeError, ValueError):
                exfil_at = None
        elif kind in FOCUS_EXFIL_END_EVENTS:
            exfil = None
            exfil_at = None
            exfil_persistent = False

    step = status.get("current_step") or {}
    if not isinstance(step, dict):
        step = {}
    explicit_current = step.get("agent_host") or status.get("agent_host") or status.get("evilkit_host")
    if explicit_current is not None:
        current = host(explicit_current)
        current_explicit = True
    explicit_exfil = step.get("exfil_source") or status.get("exfil_source")
    if explicit_exfil is not None:
        exfil = host(explicit_exfil)
        exfil_persistent = True
    declared_compromised = status.get("compromised_hosts") or []
    for value in declared_compromised if isinstance(declared_compromised, list) else []:
        item = host(value)
        if item:
            compromised[item["id"]] = item

    if current and not current_explicit:
        try:
            fresh = 0 <= now - float(current_at) <= FOCUS_ACTIVITY_WINDOW
        except (TypeError, ValueError):
            fresh = False
        if not fresh:
            current = None
    if status.get("state") not in ACTIVE_RUN_STATES:
        current = None
        exfil = None
    elif exfil and not exfil_persistent:
        try:
            if not 0 <= now - float(exfil_at) <= FOCUS_ACTIVITY_WINDOW:
                exfil = None
        except (TypeError, ValueError):
            exfil = None
    return {"current": current, "compromised": list(compromised.values()), "exfil": exfil}


def attack_features(status: dict, events: list[dict], now: float | None = None) -> dict:
    """Summarise EvilKit 1.2 attack phases from evidence already on the board.

    The summary is observational: a feature is ``observed`` only after a
    matching event/tool appears, and ``active`` only while its newest event is
    inside the same short activity window used by the topology.
    """
    now = time.time() if now is None else now
    records = {feature_id: {"id": feature_id, "label": label, "state": "idle",
                            "count": 0, "last_seen": None, "last_tool": ""}
               for feature_id, label, _, _ in ATTACK_FEATURE_DEFINITIONS}
    event_lookup = {}
    tool_lookup = {}
    for feature_id, _, event_names, tools in ATTACK_FEATURE_DEFINITIONS:
        for name in event_names:
            event_lookup[name] = feature_id
        for name in tools:
            tool_lookup[name] = feature_id

    latest_feature = None
    latest_ts = -1.0
    latest_event = None
    for event in events:
        explicit_phase = str(event.get("attack_feature") or event.get("phase") or "").strip().lower()
        kind = str(event.get("event") or "").strip().lower()
        edge = event.get("edge") if isinstance(event.get("edge"), dict) else {}
        raw_tool = str(event.get("tool") or event.get("mcp_tool") or edge.get("tool") or edge.get("mcp_tool") or "").strip().lower()
        tool = raw_tool.split("__")[-1] if raw_tool.startswith("mcp__") else raw_tool
        # EvilKit 1.2 emits a generic host_compromised dashboard event for any
        # successful attack-class call. Its tool name retains the more useful
        # phase (malware_deploy -> implant, malware_c2 -> C2), so it wins over
        # the generic event unless the producer supplied an explicit phase.
        feature_id = event_lookup.get(explicit_phase) or tool_lookup.get(tool) or event_lookup.get(kind)
        if not feature_id:
            continue
        try:
            timestamp = float(event.get("ts"))
        except (TypeError, ValueError):
            timestamp = 0.0
        record = records[feature_id]
        record["count"] += 1
        if record["last_seen"] is None or timestamp >= record["last_seen"]:
            record["last_seen"] = timestamp
            record["last_tool"] = raw_tool
        if timestamp >= latest_ts:
            latest_feature, latest_ts, latest_event = feature_id, timestamp, event

    active_run = str(status.get("state", "")).lower() in ACTIVE_RUN_STATES
    for record in records.values():
        if record["count"]:
            record["state"] = "observed"
    current = None
    if active_run and latest_feature and 0 <= now - latest_ts <= FOCUS_ACTIVITY_WINDOW:
        records[latest_feature]["state"] = "active"
        current = latest_feature

    return {
        "engine": str(status.get("source") or status.get("model") or ""),
        "session_id": str(status.get("session_id") or ""),
        "last_exit_code": status.get("last_exit_code"),
        "current": current,
        "last_host": str(status.get("last_host") or (latest_event or {}).get("host") or ""),
        "features": list(records.values()),
    }


# ---------------------------------------------------------------------------
# Real scoring — delegate to the Keystone outcome scorer (keystone.score) run
# against the run's actual evidence (journal/fsdiff/pcap/scoring-key). Imported
# lazily from KEYSTONE_ROOT and cached by evidence mtime so a poll never pays
# for a rescore unless the evidence changed. Any failure degrades to no score.
# ---------------------------------------------------------------------------
_SCORE_EVIDENCE_FILES = (
    "journal.jsonl", "fsdiff.json", "beacons.jsonl",
    "answer_key_access.jsonl", ".keystone_scoring.json",
)
_score_cache: dict[str, tuple] = {}


def _keystone_scorer():
    import sys
    root = str(KEYSTONE_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)
    from keystone.score import score_run
    from keystone.evidence import load_evidence
    return score_run, load_evidence


def compute_keystone_score(run_dir: Path) -> dict | None:
    """Score a real run from its on-disk evidence. Returns {final, max,
    categories} or None when there is no evidence (or the scorer is unavailable)."""
    try:
        run_dir = Path(run_dir)
        present = [(f, (run_dir / f)) for f in _SCORE_EVIDENCE_FILES if (run_dir / f).is_file()]
        pcaps = sorted(run_dir.glob("pcaps/*.pcap")) + sorted(run_dir.glob("*.pcap"))
        if not present and not pcaps:
            return None  # nothing to score yet
        sig = tuple((str(p), p.stat().st_mtime) for _, p in present)
        sig += tuple((str(p), p.stat().st_mtime) for p in pcaps)
        cached = _score_cache.get(str(run_dir))
        if cached and cached[0] == sig:
            return cached[1]
        score_run, load_evidence = _keystone_scorer()
        result = score_run(load_evidence(str(run_dir))).to_dict()
        out = {
            "final": result.get("final"),
            "max": result.get("max"),
            "categories": result.get("categories", {}),
        }
        _score_cache[str(run_dir)] = (sig, out)
        return out
    except Exception:
        return None


class DemoPlayer:
    """Replays the bundled sample dataset on an infinite loop, purely in memory.

    No file on disk is mutated; this exists only so the dashboard has something
    lively to show before keystone-range exists or writes its first run.
    """

    def __init__(self, demo_dir: Path):
        self.topology = json.loads((demo_dir / "topology.json").read_text(encoding="utf-8"))
        self.script = sorted(read_jsonl(demo_dir / "events.jsonl"), key=lambda e: e.get("t", 0.0))
        last_t = self.script[-1]["t"] if self.script else 0.0
        self.loop_duration = last_t + DEMO_LOOP_PAUSE
        self.epoch = time.time()

    def sample(self) -> tuple[dict, dict, list]:
        now = time.time()
        since_epoch = now - self.epoch
        generation = int(since_epoch // self.loop_duration) if self.loop_duration > 0 else 0
        elapsed = since_epoch - generation * self.loop_duration
        run_started = self.epoch + generation * self.loop_duration
        run_id = f"demo-{int(self.epoch)}-{generation}"

        due = [e for e in self.script if e.get("t", 0.0) <= elapsed]
        events = [
            {**e, "ts": run_started + e.get("t", 0.0), "run_id": run_id, "host": e.get("host", "demo")}
            for e in due
        ]
        node_states, edge_states, flags = apply_events(events)
        last_t = self.script[-1]["t"] if self.script else 0.0
        finished = elapsed >= last_t
        current = events[-1] if events else None
        status = {
            "run_id": run_id,
            "range": "keystone-demo (sample data — no live run connected)",
            "state": "finished" if finished else "running",
            "started": iso(run_started),
            "model": "demo-sample",
            "score": f"{len(flags)}/6",
            "flags": flags,
            "current_step": {
                "host": current.get("host") if current else None,
                "event": current.get("event") if current else None,
                "detail": current.get("evidence") if current else "Waiting for the loop to restart.",
            },
        }
        return status, node_states, edge_states, events


class RangeWatcher:
    """Finds the most recently active keystone-range run, or falls back to the demo."""

    def __init__(self):
        self.condition = threading.Condition()
        self.seq = 0
        self.sample: dict = {}
        self.demo = DemoPlayer(DEMO_DIR)
        self.control_scripts = dict(CONTROL_SCRIPTS)
        self.control_lock = threading.Lock()
        self.control_run: dict | None = None
        self.mesh_reader = EvilKitMeshReader()
        # Sticky colouring/overlay (anti-flicker), scoped to the current run.
        self._sticky_run: str | None = None
        self._sticky_states: dict[str, str] = {}
        self._sticky_focus: dict | None = None
        self._compromise_cache: dict[str, tuple] = {}
        # Epoch of the last explicit operator reset. Runs whose activity
        # predates it are history — their compromise hold must not survive the
        # Reset button. Persisted so a dashboard restart mid-reset keeps it.
        self._reset_epoch: float | None = self._load_reset_epoch()

    def _load_reset_epoch(self) -> float | None:
        path = DATA_DIR / "reset-epoch.json"
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            epoch = float(raw.get("epoch"))
            return epoch if epoch > 0 else None
        except (OSError, ValueError, TypeError, AttributeError):
            return None

    def _save_reset_epoch(self) -> None:
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            temporary = DATA_DIR / "reset-epoch.json.tmp"
            temporary.write_text(json.dumps({"epoch": self._reset_epoch}), encoding="utf-8")
            temporary.replace(DATA_DIR / "reset-epoch.json")
        except OSError:
            pass

    @staticmethod
    def dashboard_age(dashboard: Path) -> float:
        newest = max(
            (path.stat().st_mtime for path in (
                dashboard / "status.json",
                dashboard / "topology.json",
                dashboard / "events.jsonl",
            ) if path.is_file()),
            default=0.0,
        )
        return max(0.0, time.time() - newest) if newest else float("inf")

    # A compromised run whose emitter mislabeled it finished (or the agent is
    # simply thinking) keeps the board for this long based on its own evidence
    # files — beacons/journal/fsdiff/events — so a quiet stretch mid-engagement
    # cannot hand the view back to the idle green range. Matches the emitter's
    # release timeout (IDLE_FINISH + RELEASE_IDLE in dashboard_run.py).
    COMPROMISE_HOLD_SECS = 1800.0
    COMPROMISE_EVIDENCE = ("events.jsonl", "beacons.jsonl", "journal.jsonl", "fsdiff.json")

    def _run_has_compromises(self, run_dir: Path, dashboard: Path) -> bool:
        """Cheap cached check: did this run record any compromise?

        Compromise proof comes from status.compromised_hosts or a
        host_compromised/foothold event. Cached on file mtimes so the 1-second
        poll loop never re-reads unchanged files."""
        status = dashboard / "status.json"
        events = dashboard / "events.jsonl"
        beacons = run_dir / "beacons.jsonl"
        try:
            sig = (status.stat().st_mtime if status.is_file() else -1.0,
                   events.stat().st_mtime if events.is_file() else -1.0,
                   events.stat().st_size if events.is_file() else -1,
                   beacons.stat().st_mtime if beacons.is_file() else -1.0,
                   beacons.stat().st_size if beacons.is_file() else -1)
        except OSError:
            return False
        key = str(run_dir)
        cached = self._compromise_cache.get(key)
        if cached and cached[0] == sig:
            return cached[1]
        result = False
        if status.is_file():
            try:
                raw = json.loads(status.read_text(encoding="utf-8"))
                if isinstance(raw, dict) and raw.get("compromised_hosts"):
                    result = True
            except (OSError, ValueError):
                pass
        if not result and events.is_file():
            try:
                if b'"host_compromised"' in events.read_bytes() \
                        or b'"foothold"' in events.read_bytes():
                    result = True
            except OSError:
                pass
        if not result:
            # A clone beacon is itself the compromise proof: a beaconing host
            # is an owned host, even when the MCP layer never emitted
            # host_compromised into the dashboard stream.
            try:
                if beacons.is_file() and beacons.stat().st_size > 0:
                    result = True
            except OSError:
                pass
        self._compromise_cache[key] = (sig, result)
        return result

    def _compromise_evidence_age(self, run_dir: Path, dashboard: Path) -> float:
        newest = -1.0
        for name in self.COMPROMISE_EVIDENCE:
            path = (dashboard if name == "events.jsonl" else run_dir) / name
            if path.is_file():
                try:
                    newest = max(newest, path.stat().st_mtime)
                except OSError:
                    pass
        return max(0.0, time.time() - newest) if newest >= 0 else float("inf")

    def find_live_run(self) -> Path | None:
        if not RUNS_DIR.is_dir():
            return None
        best, best_rank = None, (-1, -1.0)
        now = time.time()
        for entry in RUNS_DIR.iterdir():
            dashboard = entry / "dashboard"
            if not dashboard.is_dir():
                continue
            topology = dashboard / "topology.json"
            events = dashboard / "events.jsonl"
            status = dashboard / "status.json"
            # a run counts if it wrote a topology OR any events (keystone runs often
            # emit only events.jsonl and rely on the generated build/topology.json)
            if not (topology.is_file() or events.is_file()):
                continue
            newest = max(
                (p.stat().st_mtime for p in (status, topology, events) if p.is_file()),
                default=-1.0,
            )
            age = max(0.0, now - newest)
            # A bridge may keep rewriting status.json after a run ends.  That is
            # health telemetry, not new run activity, so completed/reset run
            # ordering must come from topology/events rather than status mtime.
            activity_newest = max(
                (p.stat().st_mtime for p in (topology, events) if p.is_file()),
                default=-1.0,
            )
            if self._reset_epoch is not None and entry.name != "live-brain" \
                    and activity_newest < self._reset_epoch:
                # The operator pressed Reset: every run whose activity predates
                # that reset is history, whatever its declared state or
                # compromise evidence. Only post-reset activity may claim the
                # board again (the ambient live-brain view stays available).
                continue
            activity_age = max(0.0, now - activity_newest)
            event_newest = events.stat().st_mtime if events.is_file() else -1.0
            event_age = max(0.0, now - event_newest)
            rank_time = newest
            state = ""
            if status.is_file():
                try:
                    state = str(json.loads(status.read_text(encoding="utf-8")).get("state", "")).lower()
                except (OSError, ValueError, AttributeError):
                    pass
            if entry.name == "live-brain":
                # Keep the complete lab topology visible when the collector is
                # offline, but let any active benchmark run take precedence.
                # collect() labels an old brain snapshot as stale.
                priority = 1
            elif state in ACTIVE_RUN_STATES and age < 600:
                # a genuinely active run writes telemetry often; a stale "starting"
                # or "running" run left over from a crash must not hijack the view
                priority = 3
            elif state in HELD_RUN_STATES:
                # A paused/blocked run is a deliberate hold, not a dead run: it is
                # writing no telemetry, so the freshness window would drop it and
                # the board would fall back to the idle range view mid-engagement.
                # Keep it as the live view (priority below an actively running one).
                priority = 2
            elif not state and events.is_file() and age < 120:
                priority = 3
            elif state in {"idle", "ready"} and activity_age < 600:
                # Reset creates a clean idle run.  Keep that newer clean slate
                # ahead of old completed engagements and the live-brain fallback.
                priority = 2
                rank_time = activity_newest
            elif state in {"finished", "stopped", "complete"} and event_age < 120 and events.is_file():
                # Self-healing: events are still being appended, so the run is
                # alive even though its emitter declared it finished (the
                # emitter's idle timer fires while an agent is thinking, and the
                # watchdog then rewrites "finished" every few seconds). Fresh
                # event flow outranks the stale declared state, otherwise the
                # board resets to the idle green range mid-engagement.
                priority = 3
                rank_time = event_newest
            elif state in {"finished", "stopped", "complete"} \
                    and self._run_has_compromises(entry, dashboard) \
                    and self._compromise_evidence_age(entry, dashboard) < self.COMPROMISE_HOLD_SECS:
                # Compromised hosts stay dark red for the rest of the run: a
                # compromised engagement holds the view through quiet thinking
                # stretches (its beacons/journal/events are still fresh). Only
                # an actively running run or the emitter releasing it to idle
                # displaces it.
                priority = 2.5
                rank_time = activity_newest
            elif state in {"finished", "stopped", "complete"} and event_age < 600 and events.is_file():
                # README promises "A completed run stays in view for ten minutes"
                # so the operator can read the final board without it flipping
                # back to the idle live-brain view (which paints every host green
                # because it has no event history). Rank below actively running
                # and held runs so a new engagement still wins the view.
                priority = 2
                rank_time = event_newest
            elif state in {"finished", "stopped", "complete", "error"}:
                priority = 0
            else:
                priority = 0
            rank = (priority, rank_time)
            if rank > best_rank:
                best, best_rank = dashboard, rank
        return best if best_rank[0] > 0 else None

    def load_live(self, dashboard: Path):
        topo_path = dashboard / "topology.json"
        if topo_path.is_file():
            topology = apply_topology_presentation(
                json.loads(topo_path.read_text(encoding="utf-8")))
        else:
            # run only wrote events.jsonl — draw the generated range topology
            build_topo = KEYSTONE_ROOT / "build" / "topology.json"
            topology = json.loads(build_topo.read_text(encoding="utf-8")) if build_topo.is_file() else {"nodes": [], "edges": [], "zones": []}

        # Combine the live-brain topology with the run topology. The brain map
        # supplies the wider lab and live health, while the run map may contain
        # benchmark targets that do not exist on the brain map. Dropping those
        # run-only nodes made their compromise events impossible to colour.
        brain_dashboard = RUNS_DIR / "live-brain" / "dashboard"
        brain_topo_path = brain_dashboard / "topology.json"
        using_brain_topo = False
        event_node_mapping: dict[str, str] = {}
        if brain_topo_path.is_file() and dashboard != brain_dashboard:
            try:
                brain_topo = apply_topology_presentation(
                    json.loads(brain_topo_path.read_text(encoding="utf-8")))
                topology, event_node_mapping = merge_run_and_brain_topologies(topology, brain_topo)
                using_brain_topo = True
            except (ValueError, OSError):
                pass

        events = read_jsonl(dashboard / "events.jsonl")
        events.sort(key=lambda e: e.get("ts", 0.0))
        if using_brain_topo:
            events = _map_event_nodes(events, event_node_mapping)

        status_path = dashboard / "status.json"
        status = None
        if status_path.is_file():
            try:
                status = json.loads(status_path.read_text(encoding="utf-8"))
            except ValueError:
                status = None

        run_id = (status or {}).get("run_id") or (events[-1].get("run_id") if events else None) or dashboard.parent.name
        scoped = [e for e in events if e.get("run_id") in (None, run_id)] if run_id else events
        node_states, edge_states, flags = apply_events(scoped)
        if run_id == "live-brain":
            node_states.update(live_target_states(scoped))
        else:
            # Every non-brain run shows the lab's real host up/down health as a
            # baseline (reachable/running = green), then lets this run's own
            # events paint discovery/compromise on top. Applied to whatever
            # topology we drew — NOT gated on whether the brain map happened to
            # have more nodes than the run's own copy. That gate was the flicker:
            # a run with a SPARSE topology got the baseline (green) while a run
            # that copied the FULL lab map did not (grey), so the board flipped
            # grey<->green as it switched between them.
            brain_events = read_jsonl(brain_dashboard / "events.jsonl")
            baseline_states = live_target_states(brain_events)
            if baseline_states:
                node_states = {**baseline_states, **node_states}

        if status is None:
            current = scoped[-1] if scoped else None
            ev_file = dashboard / "events.jsonl"
            ev_mtime = ev_file.stat().st_mtime if ev_file.is_file() else time.time()
            finished = (time.time() - ev_mtime) > 20  # no new events for 20s -> run over
            status = {
                "run_id": run_id,
                "range": topology.get("range", "keystone"),
                "state": "finished" if finished else "running",
                "started": iso(scoped[0].get("ts", time.time())) if scoped else iso(time.time()),
                "model": "operator",
                "current_step": {
                    "host": (current or {}).get("host"),
                    "event": (current or {}).get("event"),
                    "detail": (current or {}).get("evidence", "idle"),
                },
            }
        if "flags" not in status:
            status["flags"] = flags
        # Real outcome score from the Keystone scorer, run against this run's own
        # evidence. Only for genuine runs — the ambient live-brain view carries no
        # score. When there is no evidence yet, no score is shown (not a fake one).
        if dashboard.parent.name != "live-brain":
            score_info = compute_keystone_score(dashboard.parent)
            if score_info and score_info.get("final") is not None:
                status["score"] = score_info["final"]
                status["score_max"] = score_info["max"]
                status["score_breakdown"] = score_info["categories"]
            else:
                status.pop("score", None)
        return topology, status, node_states, edge_states, scoped

    def control_availability(self) -> dict:
        with self.control_lock:
            busy = bool(self.control_run and self.control_run.get("status") == "running")
        info = {}
        for name, path in self.control_scripts.items():
            info[name] = {
                "available": path.is_file() and os.access(path, os.X_OK),
                "path": str(path),
                "busy": busy,
            }
        return info

    def control_status(self) -> dict | None:
        with self.control_lock:
            return dict(self.control_run) if self.control_run else None

    def collect(self):
        live_dashboard = self.find_live_run()
        if live_dashboard is not None:
            try:
                topology, status, node_states, edge_states, events = self.load_live(live_dashboard)
                stale_seconds = self.dashboard_age(live_dashboard)
                is_brain = live_dashboard.parent.name == "live-brain"
                if is_brain and stale_seconds >= 60:
                    status = {
                        **status,
                        "state": "stale",
                        "stale_seconds": round(stale_seconds),
                        "current_step": {
                            "detail": f"Lab telemetry is {round(stale_seconds / 60)} minutes old; showing the last complete topology."
                        },
                    }
                    mode = "stale"
                elif is_brain:
                    # The ambient lab view is never a live engagement: show its
                    # topology, but its background flows are not run traffic.
                    mode = "range"
                elif str(status.get("state", "")).lower() in {"idle", "ready"}:
                    mode = "range"
                else:
                    mode = "live"
            except (ValueError, OSError) as error:
                topology = load_range_topology() or {"nodes": [], "edges": [], "zones": []}
                node_states, edge_states, events = {}, {}, []
                status = {
                    "run_id": "range-topology",
                    "range": topology.get("range", "keystone"),
                    "state": "error",
                    "started": iso(time.time()),
                    "model": "no active run",
                    "flags": [],
                    "current_step": {"detail": f"Failed to read live run: {error}"},
                }
                mode = "range"
        else:
            # An inserted range stick outranks the checked-out build plan: the
            # stick is what is physically plugged in right now, so swapping the
            # stick swaps the map with no config edit and no restart.
            stick_topo, stick_note = load_stick_topology()
            range_topo = stick_topo if stick_topo is not None else load_range_topology()
            topology = range_topo if range_topo is not None else {"nodes": [], "edges": [], "zones": []}
            if stick_topo is not None:
                source = "stick"
                detail = (f"No active run \u2014 showing {topology.get('range', 'the range')} "
                          f"from the inserted stick.")
            elif range_topo is not None:
                source = "build"
                detail = "No active run \u2014 showing the current Keystone range topology."
            else:
                source = None
                detail = (f"No active run \u2014 {stick_note}." if stick_note else
                          "No active run \u2014 no range stick inserted and no Keystone "
                          "range topology available.")
            node_states, edge_states, events = {}, {}, []
            status = {
                "run_id": "range-topology",
                "range": topology.get("range", "keystone"),
                "topology_source": source,
                "state": "idle",
                "started": iso(time.time()),
                "model": "no active run",
                "flags": [],
                "current_step": {
                    "host": None,
                    "event": None,
                    "detail": detail,
                },
            }
            mode = "range"

        # Traffic \u2014 edges, flows, the event stream, and activity rings \u2014 is shown
        # ONLY for a genuine engagement run. Idle / range / stale / ambient views
        # render the topology (and host up/down health) alone, so nothing moves on
        # the map unless it is real run traffic. Host health state is kept: it is
        # status, not traffic.
        if mode != "live":
            events = []
            edge_states = {}
            status = {k: v for k, v in status.items()
                      if k not in ("score", "score_max", "score_breakdown")}
            status["flags"] = []

        # Anti-flicker: carry node colouring forward within a run so a transient
        # empty read or a selection wobble can't drop the map back to grey or
        # un-paint a compromise. Reset the moment the run changes.
        run_now = (status or {}).get("run_id")
        if run_now != self._sticky_run:
            self._sticky_run = run_now
            self._sticky_states = {}
            self._sticky_focus = None
        sticky = dict(self._sticky_states)
        for nid, st in node_states.items():
            sticky[nid] = stickier_state(sticky.get(nid), st)
        self._sticky_states = sticky
        node_states = sticky

        nodes = [dict(n, state=node_states.get(n["id"], n.get("state", "unknown"))) for n in topology.get("nodes", [])]
        apply_provisioning_states(nodes)
        fleet_boxes, firewall_flows = load_fleet_telemetry()
        enrich_fabric_telemetry(nodes, fleet_boxes)
        edges = []
        details = edge_event_details(events)
        node_ids = {n.get("id") for n in nodes}
        rendered_edges = set()
        for e in topology.get("edges", []):
            key = (e.get("src"), e.get("dst"))
            rendered_edges.add(key)
            detail = details.get(key, {})
            # Historical traffic may still be useful in the event log, but it must
            # not recolour a topology link after that activity has stopped.
            overlay = detail if traffic_is_connected(detail) or detail.get("historical") else {}
            edges.append(dict(e, **overlay, state=edge_states.get(key, e.get("state", "unknown"))))
        # EvilKit can observe a valid direct flow that is not in the narrative
        # baseline topology. Render that edge too, rather than silently keeping
        # the activity in the event stream only.
        for (src, dst), detail in details.items():
            if (src, dst) in rendered_edges or src not in node_ids or dst not in node_ids \
                    or not (traffic_is_connected(detail) or detail.get("historical")):
                continue
            edges.append({
                "src": src,
                "dst": dst,
                "kind": detail.get("kind", "recon"),
                "state": edge_states.get((src, dst), "used"),
                **detail,
            })

        if mode == "live":
            firewall_edges, firewall_events = firewall_overlays(nodes, firewall_flows)
            existing = {(edge.get("src"), edge.get("dst"), edge.get("kind")) for edge in edges}
            for edge in firewall_edges:
                key = (edge.get("src"), edge.get("dst"), edge.get("kind"))
                if key in existing:
                    continue
                edges.append(edge)
                existing.add(key)
            events = sorted([*events, *firewall_events], key=lambda event: event.get("ts", 0))

        # Clean idle view: strip any baseline edge styling (a few topology links
        # ship pre-coloured as used/attack/implant) so an idle map shows only
        # neutral wiring — no link reads as traffic unless a real run painted it.
        if mode != "live":
            for e in edges:
                e["state"] = "unknown"
                e["kind"] = "network"
            for n in nodes:
                n.pop("under_attack", None)

        # "Under attack" ring: any node currently receiving live attack-class
        # traffic. Derived here so it works on every run (not just the brain
        # watcher's live-brain view, which sets node["under_attack"] itself).
        under_attack = {e.get("dst") for e in edges
                        if e.get("kind") == "attack" and traffic_is_connected(e)}
        if under_attack:
            for n in nodes:
                if n["id"] in under_attack:
                    n["under_attack"] = True

        # Clone beacon traffic: the run's beacons.jsonl is the ground truth
        # that a planted clone is alive and calling home. Draw C2 edges from
        # each beaconing host to the operator origin, live ones pulsing.
        beacon_edges, beacon_nodes = [], {}
        if mode == "live" and live_dashboard is not None \
                and live_dashboard.parent.name != "live-brain":
            beacon_edges, beacon_nodes = beacon_overlays(
                topology, live_dashboard.parent, events)
        edges.extend(beacon_edges)
        for node in nodes:
            if node["id"] in beacon_nodes:
                node["c2_beacon"] = beacon_nodes[node["id"]]

        clone_fleet = self.mesh_reader.read(nodes)
        clone_node_ids = {clone.get("node_id") for clone in clone_fleet.get("clones", [])
                          if clone.get("node_id")}
        if clone_node_ids:
            for node in nodes:
                if node["id"] in clone_node_ids:
                    node["evilkit_clone"] = True

        focus = run_focus(topology, status, events)
        # A beaconing clone proves its host is compromised even when the MCP
        # layer never emitted host_compromised into the dashboard event stream:
        # merge beacon hosts into the compromised set so they render dark red
        # and appear in the compromised strip.
        for nid in beacon_nodes:
            if any(h.get("id") == nid for h in focus.get("compromised") or []):
                continue
            node = next((n for n in nodes if n.get("id") == nid), None)
            if node is None:
                continue
            focus["compromised"] = [*(focus.get("compromised") or []), {
                "id": node["id"],
                "label": node.get("label") or node["id"],
                "address": node.get("address") or node.get("ip") or "",
            }]
        # Keep the "current operator host" sticky within a run: run_focus lets an
        # activity-derived current expire after a short window, which made the
        # "EvilKit is operating on" highlight blink on and off. Hold the last
        # reported host for the run (until the run changes) so it stays steady.
        if run_now and run_now != "live-brain":
            if focus.get("current"):
                self._sticky_focus = focus["current"]
            elif self._sticky_focus is not None:
                focus = {**focus, "current": self._sticky_focus}
            # A current TARGET host implies a clone/shell and therefore a
            # compromise. A red-team platform is merely the source of the run;
            # never list the control station, portable node, relay, or staged VM
            # as a compromised target.
            cur = focus.get("current")
            cur_node = next((node for node in nodes if cur and node.get("id") == cur.get("id")), None)
            is_operator_platform = bool(cur_node) and (
                cur_node.get("operator_platform") is True
                or str(cur_node.get("zone") or "").lower() in {"operators", "operator", "attacker"}
            )
            if cur and not is_operator_platform:
                comp = list(focus.get("compromised") or [])
                if not any(h.get("id") == cur.get("id") for h in comp):
                    comp.append(cur)
                    focus = {**focus, "compromised": comp}

        snapshot = {
            "generated_at": time.time(),
            "mode": mode,
            "status": status,
            "zones": topology.get("zones", []),
            "nodes": nodes,
            "edges": edges,
            "events": events[-150:],
            "clone_fleet": clone_fleet,
            "attack_features": attack_features(status, events),
            "controls": self.control_availability(),
            "control_run": self.control_status(),
            "keystone_root": str(KEYSTONE_ROOT),
            "keystone_installed": KEYSTONE_ROOT.is_dir(),
            "focus": focus,
        }
        with self.condition:
            self.seq += 1
            snapshot["seq"] = self.seq
            self.sample = snapshot
            self.condition.notify_all()

    def loop(self):
        while True:
            try:
                self.collect()
            except Exception as error:  # the dashboard must never go dark on a bad sample
                with self.condition:
                    self.sample = {**self.sample, "collector_error": type(error).__name__}
                    self.seq += 1
                    self.condition.notify_all()
                print("Watcher error:", repr(error), flush=True)
            time.sleep(1)

    def _control_finished(self, process: subprocess.Popen, action: str) -> None:
        returncode = process.wait()
        with self.control_lock:
            if not self.control_run or self.control_run.get("pid") != process.pid:
                return
            if returncode == 0:
                message = f"{action.capitalize()} completed successfully."
            else:
                # Surface WHY it failed: the script's last log line (e.g.
                # "a run is already being tracked: ..."), not just the exit code.
                reason = ""
                try:
                    log_path = self.control_run.get("log")
                    if log_path:
                        lines = [ln.strip() for ln in
                                 Path(log_path).read_text(encoding="utf-8", errors="replace").splitlines()
                                 if ln.strip()]
                        if lines:
                            reason = " — " + lines[-1]
                except OSError:
                    pass
                message = f"{action.capitalize()} failed (exit {returncode}){reason}"
            self.control_run = {
                **self.control_run,
                "status": "succeeded" if returncode == 0 else "failed",
                "returncode": returncode,
                "finished_at": time.time(),
                "message": message,
            }
        self._publish_control_status()

    def _publish_control_status(self) -> None:
        """Wake SSE clients immediately on control launch or completion."""
        with self.condition:
            self.seq += 1
            self.sample = {
                **self.sample,
                "seq": self.seq,
                "control_run": self.control_status(),
                "controls": self.control_availability(),
            }
            self.condition.notify_all()

    def run_control(self, action: str) -> dict:
        path = self.control_scripts.get(action)
        if path is None:
            raise ValueError("Unknown action")
        if not (path.is_file() and os.access(path, os.X_OK)):
            raise ValueError(
                f"{action} script not found or not executable at {path}. "
                "Install/complete the keystone-range project first."
            )
        if action == "reset":
            # An explicit operator reset supersedes every run's claim on the
            # board: compromised hosts stay dark red for the rest of their run,
            # but the Reset button ends that run on the spot. Record the epoch
            # before launching so the wipe is immediate even while the (slow)
            # range rebuild runs.
            self._reset_epoch = time.time()
            self._save_reset_epoch()
        with self.control_lock:
            if self.control_run and self.control_run.get("status") == "running":
                active = self.control_run.get("action", "control")
                raise ValueError(f"Cannot run {action}: {active} is already running.")
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            log_path = LOG_DIR / f"{action}-{int(time.time())}.log"
            with log_path.open("wb") as log:
                process = subprocess.Popen(
                    [str(path)],
                    cwd=str(KEYSTONE_ROOT),
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
            self.control_run = {
                "action": action,
                "status": "running",
                "pid": process.pid,
                "script": str(path),
                "log": str(log_path),
                "started_at": time.time(),
                "returncode": None,
                "finished_at": None,
                "message": f"{action.capitalize()} is running.",
            }
            result = dict(self.control_run)
        self._publish_control_status()
        threading.Thread(
            target=self._control_finished,
            args=(process, action),
            daemon=True,
            name=f"control-{action}-{process.pid}",
        ).start()
        return result


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    STATIC = {
        "/": "index.html",
        "/index.html": "index.html",
        "/app.js": "app.js",
        "/style.css": "style.css",
    }
    CONTENT_TYPES = {"html": "text/html; charset=utf-8", "js": "text/javascript; charset=utf-8", "css": "text/css"}

    def client_allowed(self) -> bool:
        """Restrict an optional secondary listener to explicitly trusted clients."""
        allowlist = getattr(self.server, "client_allowlist", None)
        if allowlist is None or self.client_address[0] in allowlist:
            return True
        self.json(403, {"error": "Client is not allowed on this listener"})
        return False

    def json(self, code: int, obj: dict):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def read_json(self, limit: int = 8192) -> dict:
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError as error:
            raise ValueError("Invalid Content-Length") from error
        if length <= 0:
            return {}
        if length > limit:
            raise OverflowError("Request too large")
        try:
            payload = json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, ValueError) as error:
            raise ValueError("Invalid JSON") from error
        if not isinstance(payload, dict):
            raise ValueError("JSON object required")
        return payload

    def do_GET(self):
        if not self.client_allowed():
            return
        path = self.path.split("?", 1)[0]
        if path == "/api/status":
            with self.server.watcher.condition:
                sample = dict(self.server.watcher.sample)
            self.json(200, sample or {"status": {"state": "starting"}})
            return
        if path == "/api/agents":
            self.json(200, {"agents": self.server.agents.list()})
            return
        if path == "/api/events":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            last = -1
            try:
                while True:
                    with self.server.watcher.condition:
                        self.server.watcher.condition.wait_for(lambda: self.server.watcher.seq != last, timeout=10)
                        last = self.server.watcher.seq
                        sample = dict(self.server.watcher.sample)
                    payload = (
                        ("event: telemetry\ndata: " + json.dumps(sample) + "\n\n")
                        if sample
                        else ": waiting for watcher\n\n"
                    )
                    self.wfile.write(payload.encode())
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, TimeoutError):
                pass
            return
        if path not in self.STATIC:
            self.json(404, {"error": "Not found"})
            return
        name = self.STATIC[path]
        body = (HERE / name).read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", self.CONTENT_TYPES[name.rsplit(".", 1)[1]])
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if not self.client_allowed():
            return
        # The agent endpoint only appends structured messages to a queue. It cannot
        # execute them. Run controls remain limited to fixed, pre-registered scripts.
        if self.headers.get("Origin") not in (None, "http://" + self.headers.get("Host", "")):
            self.json(403, {"error": "Same-origin request required"})
            return
        path = self.path.split("?", 1)[0]
        agent_match = re.fullmatch(r"/api/agents/([^/]+)/(state|commands)", path)
        if path == "/api/agents/register" or agent_match:
            if AGENT_TOKEN and self.headers.get("Authorization") != "Bearer " + AGENT_TOKEN:
                self.json(401, {"error": "Valid agent bearer token required"})
                return
            try:
                payload = self.read_json()
                if path == "/api/agents/register":
                    result = self.server.agents.update(payload)
                    self.json(200, {"agent": result})
                else:
                    agent_id, operation = unquote(agent_match.group(1)), agent_match.group(2)
                    if operation == "state":
                        result = self.server.agents.update(payload, agent_id)
                        self.json(200, {"agent": result})
                    else:
                        result = self.server.agents.command(agent_id, payload)
                        self.json(202, {"command": result})
            except OverflowError as error:
                self.json(413, {"error": str(error)})
            except KeyError:
                self.json(404, {"error": "Agent not found"})
            except ValueError as error:
                self.json(400, {"error": str(error)})
            return
        action = {"/api/run/start": "start", "/api/run/reset": "reset", "/api/run/stop": "stop"}.get(self.path)
        if not action:
            self.json(404, {"error": "Not found"})
            return
        length = int(self.headers.get("Content-Length", 0))
        if length > 1024:
            self.json(413, {"error": "Request too large"})
            return
        self.rfile.read(length)
        try:
            result = self.server.watcher.run_control(action)
            self.json(200, result)
        except ValueError as error:
            self.json(409, {"error": str(error)})

    def log_message(self, *args):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8793)
    parser.add_argument("--additional-host", action="append", default=[],
                        help="also listen on this address using the same port")
    parser.add_argument("--additional-client", action="append", default=[],
                        help="client IP allowed to use additional listeners")
    args = parser.parse_args()

    watcher = RangeWatcher()
    threading.Thread(target=watcher.loop, daemon=True).start()
    agents = AgentRegistry()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.watcher = watcher
    server.agents = agents
    server.client_allowlist = None
    additional_servers = []
    additional_allowlist = frozenset(args.additional_client)
    for host in args.additional_host:
        try:
            additional = ThreadingHTTPServer((host, args.port), Handler)
        except OSError as error:
            # An optional range-side address may disappear when a cable, VLAN,
            # or interface changes. Keep the primary Tailnet dashboard alive;
            # the secondary listener can return on the next service restart.
            print(
                f"Skipping unavailable additional listener {host}:{args.port}: {error}",
                flush=True,
            )
            continue
        additional.watcher = watcher
        additional.agents = agents
        additional.client_allowlist = additional_allowlist
        additional_servers.append(additional)
        threading.Thread(
            target=additional.serve_forever,
            daemon=True,
            name=f"dashboard-listener-{host}",
        ).start()
    print(f"Lab dashboard (read-only) on http://{args.host}:{args.port}", flush=True)
    for additional in additional_servers:
        host = additional.server_address[0]
        clients = ", ".join(sorted(additional_allowlist)) or "none"
        print(f"Additional dashboard listener on http://{host}:{args.port} (clients: {clients})", flush=True)
    print(f"Watching {RUNS_DIR} for live runs; the clean range topology is shown when none is active.", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
