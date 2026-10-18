#!/usr/bin/env python3
"""Keystone live traffic monitor — classifies real range traffic for the dashboard.

Runs wherever the range's bridges are visible and every packet on them can be
sniffed: on the Proxmox host (brain, 192.168.0.240) for the CT range — bridges
vmbr9 (10.99.50.0/24) and vmbr50 (10.50.0.0/24) — and inside the rootless-podman
network namespace (via `podman unshare --rootless-netns`) for the podman keystone
DMZ range — bridges ks-dmz (10.80.10.0/24) and ks-attacker (10.80.0.0/24).
Sniffing the range's bridges sees ALL range traffic — intra-subnet (switched) and
inter-subnet (routed).

It aggregates packets into short-lived flows, classifies each flow as one of
    normal  (blue)   — routine, established, low-volume service traffic
    recon   (yellow) — scanning / enumeration: SYN probes, high host/port fan-out,
                       connections to closed ports (RST), small-payload sweeps
    attack  (red)    — exploitation / lateral movement: substantial payload to a
                       known-vulnerable service, SSH sessions server-ward, or
                       repeated reconnects to one service (brute force)
    tunnel  (cyan)   — an established SSH session actually carrying data
and writes the currently-active classified flows to a JSON file every EMIT_SECS.

The dashboard side (brain_watcher.py on Parrot) reads that JSON each poll,
maps IPs to graph nodes, and recolors the matching edges. At rest (no traffic)
the file is just an empty flow list, so the map stays all-blue.

Configuration (env var or --flag; the DEFAULTS are the Proxmox brain range, so
the existing keystone-flow-monitor.service on the brain keeps working unchanged):
    KEYSTONE_BRIDGES / --bridges              comma-separated bridges (vmbr9,vmbr50)
    KEYSTONE_SUBNETS / --subnets              comma-separated /24 prefixes
                                              ("10.99.50.,10.50.0.")
    KEYSTONE_FLOWS_PATH / --out               output JSON (/run/keystone-flows.json)
    KEYSTONE_VULN_PORTS / --vuln-ports        JSON {"ip": [ports]} or path to such a file
    KEYSTONE_VULN_PORTS_FROM / --vuln-ports-from
                                              keystone-range checkout: derive the map from
                                              modules/*/manifest.yaml + build/topology.json
    KEYSTONE_SERVICE_PORTS / --service-ports  service-side ports kept in the client->service
                                              direction (default Proxmox set)
    KEYSTONE_HOST_IPS / --host-ips            host/bridge IPs excluded as infra noise
    KEYSTONE_BPF / --bpf                      tcpdump filter override (else derived from subnets)
    KEYSTONE_FLOW_WINDOW / --window           flow memory, seconds (6)
    KEYSTONE_FLOW_EMIT / --emit               write cadence, seconds (2)
    KEYSTONE_FLOW_ACTIVE / --active           "currently active" horizon, seconds (4)

For the podman keystone DMZ range run scripts/keystone_podman_flow_monitor.sh.

This tool performs NO security actions — it only observes and labels traffic.
Stdlib only; parses `tcpdump` text output (no scapy needed).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import threading
import time
from collections import defaultdict
from pathlib import Path

# ---- Proxmox brain-range defaults (kept as-is so the brain monitor is unaffected)
DEFAULT_OUT_PATH      = "/run/keystone-flows.json"
DEFAULT_BRIDGES       = "vmbr9,vmbr50"
DEFAULT_SUBNETS       = "10.99.50.,10.50.0."
# Service-side ports. A flow is only reported when its dst port is one of these
# (or a known-vulnerable port on that host), which keeps the meaningful
# client->service direction and drops ephemeral return flows.
DEFAULT_SERVICE_PORTS = {22, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389,
                         5432, 8000, 8080, 8090, 8091, 8092, 8200, 9001, 9000}
# The Proxmox host's own bridge IPs — management noise, not a range actor. Excluded.
# (range-gw lives on .254, a real CT node, and is kept.)
DEFAULT_HOST_IPS     = {"10.99.50.1", "10.50.0.1"}
# Known-vulnerable service ports per target host (from the range manifest).
# Substantial payload to one of these reads as exploitation rather than a plain
# service call.
DEFAULT_VULN_PORTS = {
    "10.99.50.11": {8080},        # edge01  SQLi login bypass
    "10.99.50.81": {80},          # www01   upload RCE
    "10.99.50.85": {80},          # web01   IDOR / hash leak
    "10.99.50.21": {9001},        # bot01   unauth cmd exec
    "10.99.50.41": {80, 445},     # files01 share / dir listing
    "10.99.50.51": {3306, 80},    # ws01    unauth DB admin
    "10.99.50.91": {80, 25},      # mail01  webmail / smtp harvest
    "10.99.50.31": {8080},        # crown01 basic-auth + sudo
    # Keystone subsidiary (vmbr50; reachable through the hEX VLAN trunk since
    # the 2026-10-14 re-homing — these real service ports replace the old
    # logical port-80 placeholders).
    "10.50.0.11": {8090},         # ks-ws01       cred harvest (VPN creds app)
    "10.50.0.12": {8091, 80},     # ks-files01    dir listing
    "10.50.0.13": {8092, 80},     # ks-intranet01 auth bypass
    "10.50.0.14": {8200},         # vault-keystone crown store
}
SSH_PORT = 22
# Thresholds
FANOUT_RECON   = 6     # distinct dst:port from one src in window -> scanning
ATTACK_BYTES   = 600   # payload bytes to a vuln port -> exploitation, not a probe
BRUTE_RECONN   = 5     # separate short connections to same dst:port -> brute force

# ---- runtime config (env at import for back-compat; _load_config() re-resolves
#      env + argv for every run)
OUT_PATH        = os.environ.get("KEYSTONE_FLOWS_PATH", DEFAULT_OUT_PATH)
BRIDGES         = os.environ.get("KEYSTONE_BRIDGES", DEFAULT_BRIDGES).split(",")
SUBNETS         = tuple(p for p in os.environ.get("KEYSTONE_SUBNETS", DEFAULT_SUBNETS).split(",") if p)
BPF             = ""   # set in _load_config(); empty here means "derive from SUBNETS"
SERVICE_PORTS   = set(DEFAULT_SERVICE_PORTS)
HOST_BRIDGE_IPS = set(DEFAULT_HOST_IPS)
VULN_PORTS      = dict(DEFAULT_VULN_PORTS)
WINDOW          = float(os.environ.get("KEYSTONE_FLOW_WINDOW", "6"))
EMIT_SECS       = float(os.environ.get("KEYSTONE_FLOW_EMIT", "2"))
ACTIVE_SECS     = float(os.environ.get("KEYSTONE_FLOW_ACTIVE", "4"))

# tcpdump line, e.g.:
#   1697050000.123456 IP 10.99.50.60.54321 > 10.99.50.11.8080: Flags [S], ... length 0
#   1697050000.200000 IP 10.50.0.14.22 > 10.99.50.60.40022: Flags [P.], ... length 52
#   1697050000.300000 IP 10.99.50.60.5000 > 10.50.0.14.53: UDP, length 40
LINE_RE = re.compile(
    r"^(?P<ts>\d+\.\d+)\s+IP\s+"
    r"(?P<src>\d+\.\d+\.\d+\.\d+)\.(?P<sport>\d+)\s+>\s+"
    r"(?P<dst>\d+\.\d+\.\d+\.\d+)\.(?P<dport>\d+):\s+"
    r"(?:Flags\s+\[(?P<flags>[^\]]*)\].*?)?"
    r"length\s+(?P<length>\d+)"
)

_lock = threading.Lock()
# flow key (src,dst,dport,proto) -> stats
_flows: dict[tuple, dict] = {}


# ---- configuration loading -------------------------------------------------

def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def _csv_list(spec: str) -> list:
    return [x.strip() for x in spec.split(",") if x.strip()]


def _csv_ints(spec: str) -> set[int]:
    return {int(x) for x in _csv_list(spec)}


def _parse_vuln_ports(spec: str) -> dict:
    """Parse a VULN_PORTS spec: inline JSON {"ip": [ports]} or a path to such a file."""
    text = spec
    if not spec.strip().startswith("{"):
        try:
            text = Path(spec).expanduser().read_text(encoding="utf-8")
        except OSError as e:
            raise SystemExit(f"cannot read vuln-ports file {spec}: {e}")
    try:
        raw = json.loads(text)
    except ValueError as e:
        raise SystemExit(f"invalid vuln-ports JSON: {e}")
    return {ip: {int(p) for p in ports} for ip, ports in raw.items()}


def _ports_from_manifest(text: str) -> list:
    """Pull the integer ports out of a manifest's `ports:` block (stdlib YAML subset)."""
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        if re.match(r"^ports:\s*", ln):
            ports = []
            for rest in lines[i + 1:]:
                m = re.match(r"^\s+-\s+(\d+)\b", rest)
                if m:
                    ports.append(int(m.group(1)))
                    continue
                stripped = rest.strip()
                if stripped and not stripped.startswith("#"):
                    break  # left the ports block
            return ports
    return []


def _vuln_ports_from_range(range_dir: str, subnets) -> dict:
    """Derive VULN_PORTS from a keystone-range checkout: every module's service
    ports (modules/*/manifest.yaml) keyed by the module's topology IP
    (build/topology.json), keeping only IPs inside the monitored subnets."""
    root = Path(range_dir).expanduser()
    topo_path = root / "build" / "topology.json"
    out: dict = {}
    try:
        topo = json.loads(topo_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"warning: cannot read {topo_path}: {e} — no vuln-ports map derived",
              flush=True)
        return out
    ip_by_id = {n["id"]: n["ip"] for n in topo.get("nodes", []) if n.get("ip")}
    for mf in sorted((root / "modules").glob("*/manifest.yaml")):
        try:
            text = mf.read_text(encoding="utf-8")
        except OSError:
            continue
        mid = re.search(r"^id:\s*(\S+)\s*$", text, re.M)
        ports = _ports_from_manifest(text)
        if not mid or not ports:
            continue
        ip = ip_by_id.get(mid.group(1))
        if not ip or not ip.startswith(subnets):
            continue
        out[ip] = set(ports)
    if not out:
        print(f"warning: no vuln ports derived from {range_dir} for subnets {subnets}",
              flush=True)
    return out


def _derive_bpf(subnets) -> str:
    nets = " or ".join(f"net {p.rstrip('.')}.0/24" for p in subnets)
    return f"ip and ({nets})"


def _load_config(argv=None) -> None:
    global OUT_PATH, BRIDGES, SUBNETS, BPF, SERVICE_PORTS, HOST_BRIDGE_IPS, VULN_PORTS
    global WINDOW, EMIT_SECS, ACTIVE_SECS
    ap = argparse.ArgumentParser(
        description="Classify keystone range traffic from tcpdump and publish active flows.")
    ap.add_argument("--bridges", default=_env("KEYSTONE_BRIDGES", DEFAULT_BRIDGES))
    ap.add_argument("--subnets", default=_env("KEYSTONE_SUBNETS", DEFAULT_SUBNETS))
    ap.add_argument("--out", default=_env("KEYSTONE_FLOWS_PATH", DEFAULT_OUT_PATH))
    ap.add_argument("--vuln-ports", default=_env("KEYSTONE_VULN_PORTS", ""),
                    help="JSON {\"ip\": [ports]} or path to such a file")
    ap.add_argument("--vuln-ports-from", default=_env("KEYSTONE_VULN_PORTS_FROM", ""),
                    help="keystone-range checkout; derive from manifests + topology")
    ap.add_argument("--service-ports", default=_env("KEYSTONE_SERVICE_PORTS", ""),
                    help="comma-separated service ports (default: Proxmox set)")
    ap.add_argument("--host-ips", default=_env("KEYSTONE_HOST_IPS", ""),
                    help="comma-separated infra IPs to exclude (default: Proxmox .1s)")
    ap.add_argument("--bpf", default=_env("KEYSTONE_BPF", ""),
                    help="tcpdump filter override (default: derived from --subnets)")
    ap.add_argument("--window", type=float, default=float(_env("KEYSTONE_FLOW_WINDOW", "6")))
    ap.add_argument("--emit", type=float, default=float(_env("KEYSTONE_FLOW_EMIT", "2")))
    ap.add_argument("--active", type=float, default=float(_env("KEYSTONE_FLOW_ACTIVE", "4")))
    args = ap.parse_args(argv)

    OUT_PATH        = args.out
    BRIDGES         = [b for b in args.bridges.split(",") if b]
    SUBNETS         = tuple(p for p in args.subnets.split(",") if p)
    BPF             = args.bpf or _derive_bpf(SUBNETS)
    SERVICE_PORTS   = _csv_ints(args.service_ports) if args.service_ports else set(DEFAULT_SERVICE_PORTS)
    HOST_BRIDGE_IPS = set(_csv_list(args.host_ips)) if args.host_ips else set(DEFAULT_HOST_IPS)
    WINDOW          = args.window
    EMIT_SECS       = args.emit
    ACTIVE_SECS     = args.active
    if args.vuln_ports:
        VULN_PORTS = _parse_vuln_ports(args.vuln_ports)
    elif args.vuln_ports_from:
        VULN_PORTS = _vuln_ports_from_range(args.vuln_ports_from, SUBNETS)
    else:
        VULN_PORTS = dict(DEFAULT_VULN_PORTS)


# ---- traffic processing -----------------------------------------------------

def _ingest(src, dst, dport, proto, flags, length, ts):
    key = (src, dst, dport, proto)
    with _lock:
        f = _flows.get(key)
        if f is None:
            f = _flows[key] = {
                "first": ts, "last": ts, "pkts": 0, "bytes": 0,
                "syn": 0, "synack": 0, "rst": 0, "data_pkts": 0, "reconns": 0,
                "_in_conn": False,
            }
        f["last"] = ts
        f["pkts"] += 1
        f["bytes"] += length
        if "S" in flags and "." not in flags:          # bare SYN (connection attempt)
            if not f["_in_conn"]:
                f["reconns"] += 1
                f["_in_conn"] = True
            f["syn"] += 1
        if flags == "S.":                                # SYN-ACK (server accepted)
            f["synack"] += 1
        if "R" in flags:                                 # RST (closed / refused)
            f["rst"] += 1
            f["_in_conn"] = False
        if "F" in flags:
            f["_in_conn"] = False
        if length > 0:
            f["data_pkts"] += 1


def _reader(bridge: str):
    """One tcpdump per bridge; feed parsed packets into the shared flow table."""
    cmd = ["tcpdump", "-i", bridge, "-n", "-nn", "-l", "-tt", BPF]
    while True:
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            for line in proc.stdout:
                m = LINE_RE.match(line.strip())
                if not m:
                    continue
                g = m.groupdict()
                proto = "udp" if "UDP" in line else "tcp"
                try:
                    ts = float(g["ts"]); dport = int(g["dport"]); length = int(g["length"])
                except ValueError:
                    continue
                _ingest(g["src"], g["dst"], dport, proto, g.get("flags") or "", length, ts)
        except FileNotFoundError:
            print("tcpdump not found", flush=True)
            return
        except Exception as e:  # keep the reader alive across transient errors
            print(f"[{bridge}] reader error: {e}", flush=True)
            time.sleep(2)


def _classify(key, f, now, fanout):
    src, dst, dport, proto = key
    established = f["synack"] > 0 or (f["data_pkts"] > 0 and f["pkts"] > 2)
    vuln = dport in VULN_PORTS.get(dst, set())

    # brute force first: a storm of short reconnects to a sensitive port is an
    # attack, not a session — even on :22.
    if f["reconns"] >= BRUTE_RECONN and (vuln or dport in (SSH_PORT, 25)):
        return "attack"
    # an established SSH session that is actually carrying data is an interactive
    # shell or a forwarded tunnel/pivot — shown as its own class, not "attack".
    if dport == SSH_PORT and established and f["data_pkts"] > 0:
        return "tunnel"
    # attack: real payload landing on a known-vulnerable service port
    if established and f["bytes"] >= ATTACK_BYTES and vuln:
        return "attack"

    # recon: scanning behaviour — fan-out, refused connections, SYN probes w/o session
    if fanout >= FANOUT_RECON:
        return "recon"
    if f["rst"] > 0 and not established:
        return "recon"
    if f["syn"] > 0 and not established and f["data_pkts"] == 0:
        return "recon"

    return "normal"


def _emit_loop():
    while True:
        time.sleep(EMIT_SECS)
        now = time.time()
        cutoff = now - WINDOW
        with _lock:
            # prune stale flows
            for k in [k for k, v in _flows.items() if v["last"] < cutoff]:
                del _flows[k]
            # per-source fan-out within the window
            fanout = defaultdict(set)
            for (src, dst, dport, proto), v in _flows.items():
                fanout[src].add((dst, dport))
            flows_out = []
            for key, f in _flows.items():
                if f["last"] < now - ACTIVE_SECS:
                    continue  # only report currently-active flows
                src, dst, dport, proto = key
                if not (src.startswith(SUBNETS) and dst.startswith(SUBNETS)):
                    continue
                if src in HOST_BRIDGE_IPS or dst in HOST_BRIDGE_IPS:
                    continue  # bridge/host management traffic, not a range actor
                # Keep only the client->service direction; drop ephemeral return flows.
                if dport not in SERVICE_PORTS and dport not in VULN_PORTS.get(dst, set()):
                    continue
                cls = _classify(key, f, now, len(fanout[src]))
                flows_out.append({
                    "src": src, "dst": dst, "dport": dport, "proto": proto,
                    "class": cls, "pkts": f["pkts"], "bytes": f["bytes"],
                    "age": round(now - f["last"], 1),
                })
        payload = {"generated": now, "window": WINDOW, "flows": flows_out}
        tmp = OUT_PATH + ".tmp"
        try:
            with open(tmp, "w") as fh:
                json.dump(payload, fh)
            os.replace(tmp, OUT_PATH)
        except OSError as e:
            print(f"write error: {e}", flush=True)


def main(argv=None) -> int:
    _load_config(argv)
    if os.geteuid() != 0:
        print("must run as root (tcpdump needs CAP_NET_RAW)", flush=True)
    threads = [threading.Thread(target=_reader, args=(b,), daemon=True) for b in BRIDGES]
    for t in threads:
        t.start()
    print(f"keystone-flow-monitor: sniffing {BRIDGES} -> {OUT_PATH} "
          f"(subnets={SUBNETS} window={WINDOW}s emit={EMIT_SECS}s)", flush=True)
    try:
        _emit_loop()
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
