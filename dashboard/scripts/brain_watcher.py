#!/usr/bin/env python3
"""Brain state watcher — writes the Keystone dashboard's live run dir from the
Proxmox host's current CT/VM state.

Polls lab-brain over SSH, derives a topology (zones from the bridges each guest
sits on, nodes from pct/qm list, edges from the known routing/trust structure),
and writes topology.json / events.jsonl / status.json into
    ~/Projects/keystone-range/runs/live-brain/dashboard/
every POLL_INTERVAL seconds. The dashboard's find_live_run() picks the newest
mtime and streams it out via SSE, so no dashboard-server change is needed.
"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

BRAIN_HOST  = os.environ.get("BRAIN_HOST", "root@192.168.0.240")
BRAIN_KEY   = os.environ.get("BRAIN_KEY",  str(Path.home() / ".ssh/id_ed25519_labvm"))
POLL_SECS   = float(os.environ.get("BRAIN_POLL_SECS", "10"))
RUN_DIR     = Path.home() / "Projects/keystone-range/runs/live-brain/dashboard"
RUN_ID      = "live-brain"
MODEL_FILE  = RUN_DIR / "model.txt"


def read_model() -> str:
    """Operator-set attacking model(s); falls back to the live-state label."""
    try:
        value = MODEL_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        value = ""
    return value or "n/a (live state view)"


# A "real" run publishing telemetry is what licenses red/yellow colouring.
# The live-brain view itself is excluded, and the freshness window is generous
# enough to cover a model thinking between tool calls.
RUNS_DIR = Path.home() / "Projects/keystone-range/runs"
ENGAGEMENT_FRESH_SECS = float(os.environ.get("ENGAGEMENT_FRESH_SECS", "600"))


def engagement_active() -> bool:
    """True while an actual Keystone/EvilKit run is publishing fresh telemetry.

    Without this gate, the map's red (attack/compromise) and yellow (exfil)
    colouring came from ordinary lab traffic — admin probes, hEX drop-log
    syslog, fleet polling — and made an idle range look like it was under
    attack. When no run is live, flows stay dim/neutral.
    """
    try:
        candidates = [p for p in RUNS_DIR.iterdir() if p.is_dir() and p.name != RUN_ID]
    except OSError:
        return False
    newest = 0.0
    for run in candidates:
        status = run / "dashboard" / "status.json"
        try:
            if time.time() - status.stat().st_mtime > ENGAGEMENT_FRESH_SECS:
                continue
            blob = json.loads(status.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if str(blob.get("state") or "").lower() in ("running", "live", "active"):
            newest = max(newest, status.stat().st_mtime)
    return newest > 0.0
RANGE_NAME  = "lab-brain live state"

# Zone definitions — ordered left-to-right in the dashboard. First match wins.
# Each rule: id, label, col, and one of {ids, name_prefix, bridges}.
# Presentation segments. These make trust boundaries legible without changing
# the underlying VLANs, routes, firewall policy, targets, or scoring. In other
# words, the range is easier to understand, not harder to complete.
ZONES = [
    {"id": "operators",  "label": "Red Team Platform",   "col": 0, "ids": set()},
    {"id": "perimeter",  "label": "Network Perimeter",   "col": 1, "ids": {"910"}},
    {"id": "guest",      "label": "Guest Access",        "col": 1, "ids": {"960"}},
    {"id": "management", "label": "Management Plane",   "col": 2, "ids": {"100", "200", "201"}},
    {"id": "public",     "label": "Public Services",     "col": 3, "ids": {"911", "922", "931", "943"}},
    {"id": "automation", "label": "Automation Services", "col": 3, "ids": {"912", "913"}},
    {"id": "users",      "label": "User Workstations",   "col": 4, "ids": {"940", "941", "942", "944"}},
    {"id": "business",   "label": "Business Data",       "col": 5, "ids": {"914", "920", "921"}},
    # DMZ service hosts (VLAN 9) — the podman runtimes the Keystone DMZ pods
    # ride macvlan on, per the 2026-10-15 VM redesign.
    {"id": "ksdmz",      "label": "Application DMZ",      "col": 6, "ids": {"970", "971", "972", "973"}},
    {"id": "privileged", "label": "Privileged Services", "col": 7, "ids": {"950", "951", "952", "953"}},
    {"id": "identity",   "label": "Identity Services",   "col": 8, "ids": {"930"}},
]
UNKNOWN_ZONE = {"id": "unknown", "label": "Unassigned", "col": 8}

# The keystone range design (build/topology.json). brain_watcher overlays its
# dmz pods onto the service-host VMs so the map shows the real attack surface,
# not just the Proxmox guests that host it.
KEYSTONE_RANGE_BUILD = Path(os.environ.get(
    "KEYSTONE_RANGE_BUILD", str(Path.home() / "Projects/keystone-range/build")))


# The 12 DMZ pods, dressed with the same fictional-business naming as the
# rest of the map (module id stays in each node's "host" field).
POD_FRIENDLY_NAMES = {
    "edge-upload":   "Upload Service",
    "portal-sqli":   "Customer Portal API",
    "render-ssti":   "Report Rendering Service",
    "legacy-cve":    "Legacy Integration Service",
    "gitleak-api":   "Source Search Service",
    "meta-ssrf":     "Metadata Proxy",
    "token-jwt":     "Token Gateway",
    "cache-open":    "Shared Cache",
    "ssh-weak":      "Remote Access Gateway",
    "share-anon":    "Partner File Exchange",
    "cron-root":     "Job Scheduler",
    "runner-escape": "Build Runner",
}


def load_range_dmz() -> tuple[list[dict], list[dict]]:
    """DMZ pods + their host-VM edges from the keystone range design.

    Returns (pods, hosts_edges). Pods are the 12 container modules; the edges
    wire each pod to the service-host VM named in its manifest. Empty when the
    design build is absent — the map then simply omits the pod layer.
    """
    try:
        topo = json.loads((KEYSTONE_RANGE_BUILD / "topology.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return [], []
    hosts = {n["id"] for n in topo.get("nodes", [])
             if n.get("technique_class") == "service-host"}
    pods = [n for n in topo.get("nodes", [])
            if n.get("zone") == "dmz" and n["id"] not in hosts]
    edges = [e for e in topo.get("edges", [])
             if e.get("kind") == "hosts" and e.get("src") in hosts]
    return pods, edges


# Guests that exist on the hypervisor but are not part of the live range, so
# they stay off the map: the build template, and the stopped vault VM clone
# (it duplicates CT 953's address and is only a migration standby).
HIDDEN_VMIDS = {"9000", "980"}

# Node type guesses from hostname.
TYPE_BY_NAME = [
    (re.compile(r"(?i)^(dc|ad)\d*$|ad01"),            "ad"),
    (re.compile(r"(?i)^(ws|workstation|desktop)"),    "workstation"),
    (re.compile(r"(?i)files|share|smb|nfs"),          "data"),
    (re.compile(r"(?i)^(web|www|nginx|apache)"),      "web"),
    (re.compile(r"(?i)^(db|sql|mysql|postgres)"),     "db"),
    (re.compile(r"(?i)^(range|gw|router|edge)"),      "router"),
    (re.compile(r"(?i)crown|vault|exfil"),            "data"),
    (re.compile(r"(?i)bot\d*"),                       "workstation"),
    (re.compile(r"(?i)^lab-?(svc|services|agent)"),   "ad"),  # mgmt plane
]

def node_type(name: str) -> str:
    for pat, t in TYPE_BY_NAME:
        if pat.search(name or ""):
            return t
    return "workstation"


def ssh(cmd: str) -> str:
    out = subprocess.run(
        ["ssh", "-o", "ConnectTimeout=4", "-o", "BatchMode=yes",
         "-i", BRAIN_KEY, BRAIN_HOST, cmd],
        capture_output=True, text=True, timeout=15,
    )
    if out.returncode != 0:
        raise RuntimeError(f"ssh {cmd!r} rc={out.returncode}: {out.stderr.strip()[:200]}")
    return out.stdout


def fetch_podman_states() -> dict[str, str]:
    """Return current Keystone container states from the local Podman runtime."""
    result = subprocess.run(
        ["podman", "ps", "-a", "--format", "{{.Names}}\t{{.State}}"],
        capture_output=True, text=True, timeout=8,
    )
    if result.returncode != 0:
        return {}
    states = {}
    for line in result.stdout.splitlines():
        name, separator, status = line.partition("\t")
        if separator and name.startswith("keystone-"):
            states[name.removeprefix("keystone-")] = status.strip().lower()
    return states


def fetch_state() -> dict:
    """One fast SSH round trip: lists + /etc/pve configs (no slow pct/qm config)."""
    script = r'''
set -u
echo "===CT_LIST==="; pct list 2>/dev/null | tail -n +2
echo "===VM_LIST==="; qm list 2>/dev/null | tail -n +2
echo "===CT_CFGS==="
for f in /etc/pve/lxc/*.conf; do
  echo "---CT:$(basename $f .conf)---"
  # `|| true`: grep exits 1 when a guest config has none of these keys, and
  # under `set -e` that aborted the whole report before the FLOWS section —
  # which is how the dashboard silently stopped seeing range traffic.
  awk 'BEGIN{p=1} /^\[/{p=0} p{print}' $f | grep -E '^(hostname|net[0-9]+|onboot|lock):' || true
done
echo "===VM_CFGS==="
for f in /etc/pve/qemu-server/*.conf; do
  echo "---VM:$(basename $f .conf)---"
  awk 'BEGIN{p=1} /^\[/{p=0} p{print}' $f | grep -E '^(name|net[0-9]+|ipconfig[0-9]+|onboot|lock|ostype|template):' || true
done
echo "===HTW_PROBES==="
# These Windows guests use static addressing and do not have QEMU Guest Agent,
# so qm cannot report their live NICs. Prefer the management endpoint. During
# recovery/Safe Mode, actively refresh ARP and accept only the VM's configured
# MAC; this proves the guest NIC owns the planned address without pretending
# WinRM is available.
for spec in 600:10.50.0.10:5985:BC:24:11:00:00:60 601:10.50.0.11:5985:BC:24:11:00:00:61 602:10.50.0.12:5985:BC:24:11:00:00:62; do
  oldifs="$IFS"; IFS=:; set -- $spec; IFS="$oldifs"
  if timeout 1 bash -c "</dev/tcp/$2/$3" >/dev/null 2>&1; then
    echo "$1 $2 $3"
  else
    ip neigh del "$2" dev vmbr50 >/dev/null 2>&1 || true
    ping -c 1 -W 1 "$2" >/dev/null 2>&1 || true
    neigh="$(ip neigh show to "$2" dev vmbr50 2>/dev/null)"
    if echo "$neigh" | grep -qi "$4:$5:$6:$7:$8:$9" \
       && ! echo "$neigh" | grep -Eq 'FAILED|INCOMPLETE'; then
      echo "$1 $2 arp"
    fi
  fi
done
echo "===FLOWS==="
cat /run/keystone-flows.json 2>/dev/null || echo "{}"
'''
    raw = ssh(script)

    guests = {}  # id -> {"kind":"ct"|"vm", "hostname":..., "status":..., "lock":..., "nets":[{"bridge":..,"ip":..}]}
    flows_raw = []  # lines of the FLOWS section (a single JSON blob)
    section = None
    cur_id = None
    for line in raw.splitlines():
        if line.startswith("==="):
            section = line.strip("= ")
            cur_id = None
            continue
        if section == "FLOWS":
            flows_raw.append(line)
            continue
        if section == "HTW_PROBES" and line.strip():
            parts = line.split()
            if len(parts) == 3 and parts[0].isdigit():
                g = guests.get(parts[0])
                if g:
                    g["observed_ip"] = parts[1]
                    g["observed_port"] = parts[2]
            continue
        if section == "CT_LIST" and line.strip():
            parts = line.split()
            if len(parts) >= 3 and parts[0].isdigit():
                vmid, status = parts[0], parts[1]
                # pct list: "VMID Status Lock Name" with Lock sometimes blank — reconstruct
                lock = ""
                if len(parts) == 4:
                    lock = parts[2]
                    name = parts[3]
                else:
                    name = parts[-1]
                guests[vmid] = {"kind": "ct", "hostname": name, "status": status, "lock": lock, "nets": []}
        elif section == "VM_LIST" and line.strip():
            parts = line.split()
            if len(parts) >= 3 and parts[0].isdigit():
                vmid = parts[0]; name = parts[1]; status = parts[2]
                guests[vmid] = {"kind": "vm", "hostname": name, "status": status, "lock": "", "nets": []}
        elif section in ("CT_CFGS", "VM_CFGS"):
            m = re.match(r"---(?:CT|VM):(\d+)---", line)
            if m:
                cur_id = m.group(1)
                continue
            if cur_id is None:
                continue
            g = guests.get(cur_id)
            if not g:
                # Config file exists but guest not in list: build a stub so it still shows
                g = guests[cur_id] = {"kind": "ct" if section == "CT_CFGS" else "vm",
                                      "hostname": f"vm-{cur_id}", "status": "unknown", "lock": "", "nets": []}
            if line.startswith("hostname:") or line.startswith("name:"):
                g["hostname"] = line.split(":", 1)[1].strip()
            elif line.startswith("template:"):
                # Proxmox template VMs (e.g. the keystone-debian13 base at 9000)
                # are build artefacts, not range hosts — keep them off the map.
                g["template"] = line.split(":", 1)[1].strip() in ("1", "true")
            elif line.startswith("lock:"):
                g["lock"] = line.split(":", 1)[1].strip()
            elif re.match(r"net\d+:", line):
                val = line.split(":", 1)[1].strip()
                bridge = None; ip = None
                for part in val.split(","):
                    part = part.strip()
                    if part.startswith("bridge="):
                        bridge = part.split("=", 1)[1]
                    elif part.startswith("ip="):
                        ip = part.split("=", 1)[1].split("/", 1)[0]
                if bridge and not any(n["bridge"] == bridge for n in g["nets"]):
                    g["nets"].append({"bridge": bridge, "ip": ip})
            elif re.match(r"ipconfig\d+:", line):
                # Cloud-init NICs carry the address here, not on net<N>.
                val = line.split(":", 1)[1].strip()
                ip = None
                for part in val.split(","):
                    part = part.strip()
                    if part.startswith("ip="):
                        ip = part.split("=", 1)[1].split("/", 1)[0]
                if ip and ip != "dhcp" and not any(n.get("ip") == ip for n in g["nets"]):
                    bridge = g["nets"][0]["bridge"] if g["nets"] else None
                    g["nets"].append({"bridge": bridge, "ip": ip})

    flows = []
    try:
        blob = json.loads("\n".join(flows_raw) or "{}")
        flows = blob.get("flows", []) if isinstance(blob, dict) else []
    except ValueError:
        flows = []
    # Also merge the LOCAL rootless-podman keystone range flows. The brain file
    # above only ever carries Proxmox-tier (vmbr9/vmbr50) traffic; the podman
    # DMZ range (ks-dmz/ks-attacker) is sniffed on this host and written to a
    # separate path, so without this the dashboard shows no podman-range traffic.
    podman_path = os.environ.get(
        "KEYSTONE_PODMAN_FLOWS",
        f"/run/user/{os.getuid()}/keystone-podman-flows.json")
    try:
        blob = json.loads(Path(podman_path).read_text())
        if isinstance(blob, dict):
            flows = flows + blob.get("flows", [])
    except (OSError, ValueError):
        pass
    # Merge perimeter-router telemetry. The fleet syslog collector writes the
    # Asus lab-edge's pushed fw4 drop flows; fleet_watcher writes the hEX flows
    # it pulls over the brain SSH jump (the attack-segment L2 to Parrot is not
    # bridged, so hEX cannot push here). Both are absent-safe and share the flow
    # shape {src,dst,class}, so they recolour edges exactly like the others.
    for extra in (
        os.environ.get("FLEET_SYSLOG_FLOWS", f"/run/user/{os.getuid()}/fleet-syslog.json"),
        os.environ.get("FLEET_POLL_FLOWS", f"/run/user/{os.getuid()}/fleet-poll-flows.json"),
    ):
        try:
            blob = json.loads(Path(extra).read_text())
            if isinstance(blob, dict):
                flows = flows + blob.get("flows", [])
        except (OSError, ValueError):
            pass
    return {"guests": guests, "flows": flows, "pods": fetch_podman_states()}


def zone_of(vmid: str, g: dict) -> str:
    hostname = (g.get("hostname") or "").lower()
    for z in ZONES:
        if vmid in z.get("ids", set()):
            return z["id"]
        for p in z.get("name_prefix", ()):
            if hostname.startswith(p):
                return z["id"]
    return UNKNOWN_ZONE["id"]


_IP_RE = re.compile(r"\d+\.\d+\.\d+\.\d+")
_CLASS_RANK = {"normal": 1, "tunnel": 2, "recon": 3, "attack": 4}
_RANK_KIND = {1: "network", 2: "tunnel", 3: "recon", 4: "attack"}

# SSH tunnels/pivots should STAY lit for the life of the session, not blink off
# the first idle poll that shows no packets. Once a node-pair is seen as an
# established SSH tunnel we hold it as `tunnel` for this many seconds after its
# last sighting; a higher-severity class (recon/attack) in a later poll still
# wins, and the hold expires on its own so an idle/torn-down tunnel reverts.
TUNNEL_RANK = _CLASS_RANK["tunnel"]
TUNNEL_HOLD_SECS = float(os.environ.get("KEYSTONE_TUNNEL_HOLD", "90"))
_TUNNEL_HOLD: dict[frozenset, float] = {}   # node-pair -> last time seen as tunnel

# Legible device/service names for the dashboard, keyed by VM id. These frame the
# range as a fictional target business so the map reads at a glance; the real
# hostname+vmid is kept in each node's "host" field for operators. Roles come from
# the range manifest (vulnerable service per host) and the guest hostnames.
FRIENDLY_NAMES = {
    "100": "Directory Services",          # lab-services
    "200": "Management Console",          # lab-svc
    "201": "Endpoint Management",         # lab-agent
    "910": "Edge Gateway",                # range-gw
    "911": "Public Customer Portal",      # edge01   — SQLi login bypass
    "912": "Automation Worker 01",        # bot01    — unauth command exec
    "913": "Automation Worker 02",        # bot02
    "914": "Finance Archive",             # crown01  — crown-jewel data
    "920": "Corporate File Services",     # files01  — open SMB share
    "921": "HR Records Database",         # ws01     — unauth DB admin
    "922": "Public Web Server",           # www01    — upload RCE
    "930": "Corporate Domain Controller", # dc01
    "931": "Mail Gateway",                # mail01   — webmail / SMTP
    "940": "Finance Workstation",         # emp01
    "941": "Sales Workstation",           # emp02
    "942": "Reception Workstation",       # emp / mail01 workstation
    "943": "Customer Application",        # web01    — IDOR / hash leak
    "944": "IT Administration Workstation", # emp03
    "950": "Executive Workstation",       # ks-ws01
    "951": "Executive File Services",     # ks-files01
    "952": "Staff Intranet",              # ks-intranet01 — auth bypass
    "953": "Credentials Vault",           # vault-keystone
    "960": "Guest Network Kiosk",         # drop01   — physical-access target
    # 2026-10-15 redesign: DMZ lives on four podman service-host VMs on vmbr9
    # (VLAN 9), each running its module pods on macvlan.
    "970": "DMZ Web Host 01",           # dmz-web-a  — edge-upload/portal-sqli/render-ssti
    "971": "DMZ Web Host 02",           # dmz-web-b  — legacy-cve/gitleak-api/meta-ssrf/token-jwt
    "972": "DMZ Shared Services Host",  # dmz-svc    — cache-open/ssh-weak/share-anon/cron-root
    "973": "DMZ Build Host",            # dmz-runner — runner-escape
}


def apply_flow_overrides(nodes: list, edges: list, add_edge, flows: list) -> None:
    """Overlay live classified flows onto the nodes already on the map.

    Only endpoints that resolve to a node are drawn: a flow whose address is
    absent from the inventory has nothing to attach to, and inventing a
    "Live flow source/target" dot for it puts unnamed entries on the board. Give
    the real node the address instead if that traffic should be visible.
    """
    if not flows and not _TUNNEL_HOLD:
        return
    # Without a live run, traffic still shows (dim, neutral) but never as
    # recon/attack/exfil — an idle range must not read as under attack.
    # Real activity from the attacker seat is the exception: that is the
    # operator working the range, run dir or not.
    engaged = engagement_active() or any(
        str(f.get("src") or "").startswith(ATTACKER_SUBNET_PREFIX)
        or str(f.get("dst") or "").startswith(ATTACKER_SUBNET_PREFIX)
        for f in flows
    )
    # IP -> node id (a node address may list several IPs, e.g. the dual-homed gateway)
    ip2node = {}
    for n in nodes:
        for ip in _IP_RE.findall(n.get("address") or ""):
            ip2node[ip] = n["id"]
    # Operator seats rendered separately (pi-drop / parrot) — map their IPs too.
    for ip in PARROT_OPERATOR_IPS:
        ip2node.setdefault(ip, PARROT_OPERATOR_ID)
    ip2node.setdefault(PI_DROP_IP, PI_DROP_ID)
    # Collapse flows to the worst class seen per unordered node-pair.
    pair_rank: dict[frozenset, int] = {}
    pair_direction: dict[frozenset, tuple[str, str]] = {}
    attack_targets: set = set()   # victim node ids, for the "under attack" ring
    for f in flows:
        src = ip2node.get(f.get("src")); dst = ip2node.get(f.get("dst"))
        if not src or not dst or src == dst:
            continue
        cls = f.get("class")
        rank = _CLASS_RANK.get(cls, 1)
        if not engaged:
            rank = 1               # idle range: keep the link, drop the severity
        key = frozenset((src, dst))
        if rank > pair_rank.get(key, 0):
            pair_rank[key] = rank
            pair_direction[key] = (src, dst)
        if cls == "attack" and engaged:
            attack_targets.add(dst)  # the destination is the one being attacked
    # Flag victim nodes so the dashboard can ring them live, before (or without)
    # any explicit host_compromised event. Rebuilt each poll, so it clears itself
    # once the attack traffic stops.
    for n in nodes:
        if n["id"] in attack_targets:
            n["under_attack"] = True
    # Tunnel persistence: remember pairs seen as tunnels, re-assert held ones that
    # went quiet this poll, and expire holds past the window (or whose nodes are
    # gone). A live recon/attack class this poll still outranks the hold.
    now = time.time()
    node_ids = {n["id"] for n in nodes}
    for pair, rank in pair_rank.items():
        if rank == TUNNEL_RANK:
            _TUNNEL_HOLD[pair] = now
    for pair, seen in list(_TUNNEL_HOLD.items()):
        if now - seen > TUNNEL_HOLD_SECS or not pair <= node_ids:
            del _TUNNEL_HOLD[pair]
        elif engaged and pair_rank.get(pair, 0) < TUNNEL_RANK:
            pair_rank[pair] = TUNNEL_RANK
    # Apply: update an existing edge for the pair, or add a new one.
    for pair, rank in pair_rank.items():
        kind = _RANK_KIND[rank]
        # Idle range: the link is real but not "in use" — leave it dim/dashed.
        state = "used" if engaged else "unknown"
        a, b = pair_direction.get(pair, tuple(pair) if len(pair) == 2 else (next(iter(pair)), next(iter(pair))))
        existing = next((e for e in edges if {e["src"], e["dst"]} == pair), None)
        if existing:
            existing["kind"] = kind
            existing["state"] = state
            existing["connected"] = True
        else:
            add_edge(a, b, kind, state)
            edges[-1]["connected"] = True


PI_DROP_ID = "pi-drop"
PI_DROP_HOST = os.environ.get("PI_DROP_HOST", "evilkit-pi-01")
# The Pi's current management path is wlan0 on the attacker LAN. Its eth0 is
# physically on switch port 7 (Data VLAN 51) but still carries the old DMZ
# address, so that wired address is display-only until the port/address match.
PI_DROP_IP = os.environ.get("PI_DROP_IP", "10.10.66.146")
PI_DROP_SSH_PORT = int(os.environ.get("PI_DROP_SSH_PORT", "22"))
# Mini Evil Kit Pi joins the mesh via Tailscale; report liveness on the tailnet
# identity too so the seat is green once the drop is up, whichever path answers.
PI_DROP_TS_IP = os.environ.get("PI_DROP_TS_IP", "100.101.148.29")
# The Pi is controlled out-of-band above, while its target-facing Ethernet is
# dropped onto Guest Access. Leave the address unset until VLAN 60 is actually
# configured so the dashboard never presents a planned reservation as live.
PI_TARGET_SEGMENT = os.environ.get(
    "PI_TARGET_SEGMENT", "switch port 7 / Data VLAN 51 (address mismatch)"
)
PI_TARGET_IP = os.environ.get("PI_TARGET_IP", "10.99.50.120")
MESH_HUB_ID = "mesh-hub"
MESH_HUB_HOST = os.environ.get("MESH_HUB_HOST", "Parrot Tailscale hub")
MESH_HUB_IP = os.environ.get("MESH_HUB_IP", "100.88.148.72")
MESH_HUB_PORT = int(os.environ.get("MESH_HUB_PORT", "8765"))
PARROT_OPERATOR_IP = "192.168.0.10"
# The seat also holds an address on the attacker VLAN (its route to the range
# goes parrot -> Asus -> hEX), and range flow telemetry reports THAT address.
# Both must resolve to this node or scan traffic shows up as an unknown host.
PARROT_ATTACK_IP = os.environ.get("PARROT_ATTACK_IP", "10.10.66.127")
PARROT_OPERATOR_IPS = (PARROT_OPERATOR_IP, PARROT_ATTACK_IP)
ATTACKER_SUBNET_PREFIX = "10.10.66."
# Subnets the range actually occupies (attacker VLAN, DMZ/estate, corp, data).
RANGE_SUBNET_PREFIXES = ("10.99.50.", "10.50.0.", "10.50.1.", "10.10.66.")
PARROT_OPERATOR_ID = "parrot-operator"


def _pi_drop_live() -> bool:
    """Return whether the live Pi drop's SSH endpoint accepts connections.

    The physical Pi now hosts the EvilKit tool server on the ATTACK LAN, so its
    LAN endpoint is authoritative. The former Tailscale identity may stay
    offline without making the active drop unavailable.
    """
    targets = [(PI_DROP_IP, PI_DROP_SSH_PORT)]
    if PI_DROP_TS_IP:
        targets.append((PI_DROP_TS_IP, PI_DROP_SSH_PORT))
    for host, port in targets:
        try:
            with socket.create_connection((host, port), timeout=2):
                return True
        except OSError:
            continue
    return False


def build_topology(guests: dict, flows: list | None = None,
                   pod_states: dict[str, str] | None = None) -> dict:
    """Compute positions zone-by-zone (column by col idx, row by rank within zone)."""
    flows = flows or []
    pod_states = pod_states or {}
    all_zones = ZONES + [UNKNOWN_ZONE]
    by_zone: dict[str, list[tuple[str, dict]]] = {z["id"]: [] for z in all_zones}
    for vmid, g in guests.items():
        if g.get("template") or vmid in HIDDEN_VMIDS:
            continue          # build artefacts / migration standbys, not range hosts
        by_zone[zone_of(vmid, g)].append((vmid, g))

    # Only include zones that actually have guests.
    live_zones = [z for z in all_zones if by_zone[z["id"]]]
    max_col = max((z["col"] for z in live_zones), default=1)
    # x = 8..92 across columns, so even one column renders centered-ish.
    xs = {}
    for z in live_zones:
        xs[z["id"]] = 8 + (z["col"] * 84 / max(1, max_col))

    nodes = []
    homing_order = {h: i for i, h in enumerate(["911", "912", "914"])}
    for z in live_zones:
        zid = z["id"]
        lst = by_zone[zid]
        if zid == "homing":
            lst.sort(key=lambda t: homing_order.get(t[0], 99))
        else:
            lst.sort(key=lambda t: int(t[0]))
        rows = len(lst) or 1
        for i, (vmid, g) in enumerate(lst):
            y = 8 + (i + 0.5) * (84 / rows)
            name = g.get("hostname") or f"vm-{vmid}"
            ip = g.get("observed_ip") or next(
                (n["ip"] for n in g["nets"] if n.get("ip") and n["ip"] != "dhcp"),
                None,
            )
            addr  = ip or "—"
            node = {
                "id": f"g{vmid}",
                "label": FRIENDLY_NAMES.get(vmid) or f"{name} ({vmid})",
                "host": f"{name} ({vmid})",
                "type": node_type(name),
                "zone": zid,
                "address": addr,
                "state": status_to_node_state(g.get("status") or "", g.get("lock") or ""),
                "telemetry_source": "Proxmox pct" if g.get("kind") == "ct" else "Proxmox qm",
                "telemetry_status": g.get("status") or "unknown",
                "position": [round(xs[zid], 1), round(y, 1)],
                "_status": g.get("status"),
                "_lock":   g.get("lock"),
                "_vmid":   vmid,
                "_kind":   g.get("kind"),
            }
            if g.get("observed_ip"):
                observation = (
                    "ARP/MAC verified from Proxmox"
                    if g.get("observed_port") == "arp"
                    else f"{g['observed_ip']}:{g.get('observed_port', '?')} answered from Proxmox"
                )
                node["telemetry"] = {
                    "network": observation
                }
            nodes.append(node)

    edges: list = []
    seen_edges: set = set()

    def add_edge(src: str, dst: str, kind: str, state: str = "unknown") -> None:
        key = (src, dst, kind)
        if src == dst or key in seen_edges:
            return
        seen_edges.add(key)
        edges.append({"src": src, "dst": dst, "kind": kind, "state": state})

    def by_id(vmid: str):
        for n in nodes:
            if n["_vmid"] == vmid:
                return n
        return None

    def by_name(prefix: str, zone: str | None = None):
        for n in nodes:
            if zone and n["zone"] != zone:
                continue
            if (n.get("label") or "").lower().startswith(prefix):
                return n
        return None

    # ---------- intentional, narrative-driven mesh (not a tree) ----------
    # Narrative: an accounting firm's internal estate (emp01-03, mail01, web01,
    # files01, ws01, www01) joined to a corporate domain (dc01), plus a sister
    # "KS" subsidiary with its own files/intranet/vault — same AD trust. External
    # footprint: www01 (public web), mail01 (email). Internal pivot paths:
    # employee ws → mail → files; files → vault via subsidiary trust; the homing
    # chain is a prior red-team foothold left in place as an alternate ingress.
    # First-run initial access: a Raspberry Pi dropper plugged into edge01's
    # chain, giving the attacker a foothold inside the lab's homing segment.

    # 1) Homing chain (sequential network path through CTs 910-914)
    homing_nodes = sorted([n for n in nodes if n["zone"] == "homing"],
                          key=lambda n: homing_order.get(n["_vmid"], 99))
    for a, b in zip(homing_nodes, homing_nodes[1:]):
        add_edge(a["id"], b["id"], "network")
    # bot01 ↔ crown01 link (an attack path at run time; at rest it's just a link)
    bot01 = by_id("912")
    crown = by_id("914")
    if bot01 and crown:
        add_edge(bot01["id"], crown["id"], "network")

    # 2) Services as mgmt plane — reaches every zone
    svc_nodes = [n for n in nodes if n["zone"] == "services"]
    if svc_nodes:
        for svc in svc_nodes:
            for zid in sorted({n["zone"] for n in nodes} - {"services"}):
                first = next((n for n in nodes if n["zone"] == zid), None)
                if first:
                    add_edge(svc["id"], first["id"], "network")
        # The management pair are peers of the directory service.
        for svc in svc_nodes[1:]:
            add_edge(svc_nodes[0]["id"], svc["id"], "network")

    # 3) Corporate application/user mesh. Use stable VM IDs instead of display
    # labels so a naming refresh can never silently remove topology edges.
    emp_nodes  = [n for vmid in ("940", "941", "942", "944") if (n := by_id(vmid))]
    mail       = by_id("931")
    files_est  = by_id("920")
    ws_est     = by_id("921")
    web_est    = by_id("943")
    www        = by_id("922")
    for emp in emp_nodes:
        if mail:      add_edge(emp["id"], mail["id"], "network")      # employees → mail
        if ws_est:    add_edge(emp["id"], ws_est["id"], "network")    # employees → shared ws
        if files_est: add_edge(emp["id"], files_est["id"], "network") # employees → files share
    if ws_est and files_est: add_edge(ws_est["id"], files_est["id"], "network")
    if mail and files_est:   add_edge(mail["id"], files_est["id"], "network")
    if web_est and files_est: add_edge(web_est["id"], files_est["id"], "network")
    if www and web_est:      add_edge(www["id"], web_est["id"], "network")

    # 4) AD domain joins — every workstation/web/mail/file joins the domain
    dc = by_id("930")
    if dc:
        for n in nodes:
            if n["id"] == dc["id"]:
                continue
            if n["zone"] in {"public", "automation", "users", "business", "privileged"} \
                    and n["type"] in ("workstation", "ad", "db", "web", "data"):
                add_edge(n["id"], dc["id"], "network")

    # 5) Keystone (subsidiary) internal flow + cross-trust from estate
    ks_ws       = by_id("950")
    ks_files    = by_id("951")
    ks_intra    = by_id("952")
    ks_vault    = by_id("953")
    if ks_ws and ks_intra:   add_edge(ks_ws["id"], ks_intra["id"], "network")
    if ks_intra and ks_files: add_edge(ks_intra["id"], ks_files["id"], "network")
    if ks_files and ks_vault: add_edge(ks_files["id"], ks_vault["id"], "network")
    if ks_ws and ks_vault:   add_edge(ks_ws["id"], ks_vault["id"], "network")
    # Cross-tenant link: parent accounting firm's files reaches subsidiary files
    if files_est and ks_files: add_edge(files_est["id"], ks_files["id"], "network")

    # 6) Pivot bridges — homing chain to the estate
    edge01 = by_id("911")
    if edge01 and web_est: add_edge(edge01["id"], web_est["id"], "network")
    if edge01 and mail:    add_edge(edge01["id"], mail["id"], "network")
    if crown and ks_vault: add_edge(crown["id"], ks_vault["id"], "network")

    # 7) Red-team platform and physical-access target. The operator nodes are
    # separate from g960: g960 is always a target-side guest kiosk.
    drop01 = by_id("960")
    range_gw = by_id("910")
    # Position Parrot operator and Pi to the left of the entry zone nodes
    entry_nodes = [n for n in nodes if n["zone"] == "entry"]
    left_x = min(n["position"][0] for n in entry_nodes) if entry_nodes else 10.0
    pi_x = max(1.0, left_x - 8)
    entry_y = next((n["position"][1] for n in entry_nodes), 50.0)
    pi_y = min(92.0, entry_y + 12.0)
    parrot_x = max(1.0, left_x - 16)
    parrot_y = max(8.0, entry_y - 12.0)
    pi_live = _pi_drop_live()
    pi_node = {
        "id": PI_DROP_ID,
        "label": "Portable Red Team Node",
        "host": "Raspberry Pi 4 — portable operator node (mesh worker)",
        "type": "operator",
        "zone": "operators",
        "operator_platform": True,
        "address": (f"control: {PI_DROP_IP} / {PI_DROP_TS_IP} ({PI_DROP_HOST}, SSH) · "
                    f"eth0: {PI_TARGET_IP} on {PI_TARGET_SEGMENT}"),
        "deployment_segment": PI_TARGET_SEGMENT,
        "target_address": PI_TARGET_IP,
        # Dormant (grey) until the LAN or tailnet endpoint answers.
        "state": "reachable" if pi_live else "discovered",
        "position": [round(pi_x, 1), round(pi_y, 1)],
    }
    mesh_hub_node = {
        "id": MESH_HUB_ID,
        "label": "Command Relay",
        "host": MESH_HUB_HOST,
        "type": "operator",
        "zone": "operators",
        "operator_platform": True,
        "address": f"{MESH_HUB_IP}:{MESH_HUB_PORT}",
        "state": "reachable",
        "position": [round(pi_x, 1), round(pi_y + 10.0, 1)],
    }
    parrot_node = {
        "id": PARROT_OPERATOR_ID,
        "label": "Red Team Control Station",
        "host": "Primary red-team workstation",
        "type": "operator",
        "zone": "operators",
        "operator_platform": True,
        "address": PARROT_OPERATOR_IP,
        "state": "reachable",
        "position": [round(parrot_x, 1), round(parrot_y, 1)],
    }
    # At rest these are ordinary control/network links. The Pi and kiosk are
    # peers on Guest Access; they are separate devices and neither identity is
    # inferred from the other.
    if drop01:   add_edge(PI_DROP_ID, drop01["id"], "network")
    # Out-of-band control path: control station -> relay -> portable node.
    add_edge(PARROT_OPERATOR_ID, MESH_HUB_ID, "network")
    add_edge(MESH_HUB_ID, PI_DROP_ID, "network")
    if range_gw: add_edge(PI_DROP_ID, range_gw["id"], "network")
    if drop01 and range_gw: add_edge(drop01["id"], range_gw["id"], "network")
    if drop01 and edge01:  add_edge(drop01["id"], edge01["id"], "network")
    if drop01 and www:     add_edge(drop01["id"], www["id"], "network")
    if drop01 and web_est: add_edge(drop01["id"], web_est["id"], "network")
    if drop01 and bot01:   add_edge(drop01["id"], bot01["id"], "network")
    # Parrot operator baseline links into the range; live telemetry recolors them.
    if drop01:   add_edge(PARROT_OPERATOR_ID, drop01["id"], "network")
    if range_gw: add_edge(PARROT_OPERATOR_ID, range_gw["id"], "network")
    # range-gw routes to Keystone subnet
    if range_gw:
        for ks in [ks_ws, ks_files, ks_intra, ks_vault]:
            if ks: add_edge(range_gw["id"], ks["id"], "network", "used")

    # 8) DMZ pod layer — the keystone dmz pods the service-host VMs run.
    #    They are macvlan containers inside those VMs (not Proxmox guests), so
    #    they never appear in inventory; overlay them from the range design and
    #    wire pod -> host VM, host VM -> the corp hosts its firewall allows,
    #    and the operator seat -> host VMs (attacker -> dmz reach).
    pods, pod_edges = load_range_dmz()
    if pods:
        host_node_by_vmid = {n["_vmid"]: n for n in nodes}
        ksdmz_x = xs.get("ksdmz", 50.0)
        pod_x = round(min(96.0, ksdmz_x + 6.0), 1)
        for i, pod in enumerate(sorted(pods, key=lambda p: p["id"])):
            y = 8 + (i + 0.5) * (84 / max(1, len(pods)))
            pod_status = pod_states.get(pod["id"], "unknown")
            nodes.append({
                "id": f"pod-{pod['id']}",
                "label": POD_FRIENDLY_NAMES.get(pod["id"], pod.get("label") or pod["id"]),
                "host": f"{pod['id']} (DMZ pod)",
                "type": "web",
                "zone": "ksdmz",
                "address": (pod.get("real_ip") or pod.get("ip") or "—").split(" ")[0],
                "state": status_to_node_state(pod_status, ""),
                "telemetry_source": "Podman",
                "telemetry_status": pod_status,
                "position": [pod_x, round(y, 1)],
                "_status": pod_status,
                "_lock": "",
                "_vmid": "",
                "_kind": "pod",
                "_module": pod["id"],
            })
        pod_node_by_module = {n["_module"]: n for n in nodes if n.get("_kind") == "pod"}
        vmid_by_host = {"dmz-web-a": "970", "dmz-web-b": "971", "dmz-svc": "972", "dmz-runner": "973"}
        for e in pod_edges:
            host_node = host_node_by_vmid.get(vmid_by_host.get(e.get("src"), ""))
            pod_node = pod_node_by_module.get(e.get("dst"))
            if host_node and pod_node:
                add_edge(host_node["id"], pod_node["id"], "network")
        # dmz -> corp: the three hosts the hEX directed-allow actually reaches,
        # plus the crown vault on its own VLAN (corp -> data only).
        for host_name, vmid in vmid_by_host.items():
            host_node = host_node_by_vmid.get(vmid)
            if not host_node:
                continue
            for ks in (ks_ws, ks_files, ks_intra):
                if ks:
                    add_edge(host_node["id"], ks["id"], "network")
            if ks_vault:
                add_edge(host_node["id"], ks_vault["id"], "network")
        # Operator reach into the DMZ: attacker -> dmz is the one open edge.
        for host_name, vmid in vmid_by_host.items():
            host_node = host_node_by_vmid.get(vmid)
            if host_node:
                add_edge(PARROT_OPERATOR_ID, host_node["id"], "network")

    # 9) LIVE TRAFFIC overlay — recolor edges from classified flows (keystone_flow_monitor
    #    on brain). normal=blue baseline above; recon=yellow / attack=red for real activity.
    #    At rest `flows` is empty, so the map stays all-blue.
    apply_flow_overrides(nodes, edges, add_edge, flows)

    # Clean private fields from the public topology; the static operator-seat
    # nodes (parrot / pi / mesh hub) are already clean.
    public_nodes = [parrot_node, pi_node, mesh_hub_node] + [{k: v for k, v in n.items() if not k.startswith("_")} for n in nodes]

    live_zone_ids = {n["zone"] for n in nodes} | {n["zone"] for n in (parrot_node, pi_node, mesh_hub_node)}
    out_zones = [{"id": z["id"], "label": z["label"]} for z in all_zones if z["id"] in live_zone_ids]
    return {
        "range": RANGE_NAME,
        "title": "lab-brain — live Proxmox state",
        "zones": out_zones,
        "nodes": public_nodes,
        "edges": edges,
        "_nodes_with_meta": nodes,
    }


def status_to_node_state(status: str, lock: str) -> str:
    if lock == "mounted":
        return "in-progress"
    if status == "running":
        return "reachable"
    if status in {"stopped", "exited", "created"}:
        return "discovered"
    if status in {"error", "dead"}:
        return "error"
    return "unknown"


def write_atomic(path: Path, data: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(data)
    tmp.replace(path)


def emit(events: list, prev_state: dict, nodes_meta: list) -> dict:
    """Emit node_* events on state transitions; return the new state map."""
    now = time.time()
    new_state = {}
    for n in nodes_meta:
        st = status_to_node_state(n.get("_status") or "", n.get("_lock") or "")
        new_state[n["id"]] = st
        prev = prev_state.get(n["id"])
        if prev != st:
            evt_name = {
                "unknown":     "node_discovered",
                "discovered":  "node_discovered",
                "reachable":   "node_reachable",
                "in-progress": "node_in_progress",
                "solved":      "node_solved",
                "data-read":   "node_data_read",
            }.get(st, "node_discovered")
            events.append({
                "run_id": RUN_ID,
                "ts": now,
                "host": "lab-brain",
                "event": evt_name,
                "node": n["id"],
                "evidence": f"pct/qm status={n.get('_status')!r} lock={n.get('_lock')!r}",
            })
    return new_state


def main() -> int:
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    events_path   = RUN_DIR / "events.jsonl"
    topology_path = RUN_DIR / "topology.json"
    status_path   = RUN_DIR / "status.json"
    prev_state: dict[str, str] = {}
    events: list = []
    first = True
    brain_ok = False
    started_iso = datetime.now(timezone.utc).isoformat()

    while True:
        try:
            state  = fetch_state()
            brain_ok = True
            topo   = build_topology(state["guests"], state["flows"], state["pods"])
            nodes_meta = topo.pop("_nodes_with_meta")
            # emit transitions
            new_events: list = []
            prev_state = emit(new_events, prev_state, nodes_meta)
            events.extend(new_events)
            # trim to last 1000 lines on disk
            events = events[-1000:]

            write_atomic(topology_path, json.dumps(topo, indent=2))
            # append-only events.jsonl
            if first:
                events_path.write_text("".join(json.dumps(e) + "\n" for e in events))
                first = False
            elif new_events:
                with events_path.open("a") as f:
                    for e in new_events:
                        f.write(json.dumps(e) + "\n")

            running = sum(1 for n in nodes_meta if n.get("_status") == "running")
            total = len(nodes_meta)
            status = {
                "run_id": RUN_ID,
                "range":  RANGE_NAME,
                "state":  "running" if brain_ok else "stale",
                "started": started_iso,
                "model":   read_model(),
                "score":   None,
                "flags":   [],
                "current_step": {
                    "detail": (
                        f"{running}/{total} guests running \u00b7 polled {datetime.now(timezone.utc).strftime('%H:%M:%S UTC')}"
                        if brain_ok else
                        f"brain unreachable \u00b7 showing static topology \u00b7 polled {datetime.now(timezone.utc).strftime('%H:%M:%S UTC')}"
                    ),
                },
            }
            write_atomic(status_path, json.dumps(status, indent=2))
            print(f"[{datetime.now().strftime('%H:%M:%S')}] ok · {running}/{total} running · {len(new_events)} events emitted", flush=True)
        except Exception as e:
            brain_ok = False
            print(f"[{datetime.now().strftime('%H:%M:%S')}] ERROR: {e}", flush=True)
        time.sleep(POLL_SECS)


if __name__ == "__main__":
    sys.exit(main() or 0)
