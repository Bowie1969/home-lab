#!/usr/bin/env python3
"""infra_dashboard.py — a simple, always-current infrastructure truth map.

A deliberately small sibling to the full Keystone Range monitor (``server.py``,
port 8793). Where that dashboard replays run-scoped telemetry files, this one
asks the five infrastructure sources directly, every poll, and shows only what
they report *right now*:

    Internet → ASUS edge → hEX firewall → { Brain Box (+ Proxmox guests),
                                            this operator box, Raspberry Pi }

Design rules, inherited from the reference monitor and kept strict here:

* **Truth over optimism.** Each source is polled independently and in parallel.
  A failed poll renders as ``unavailable`` (grey) and raises a
  ``source-unreachable`` event — it is *never* back-filled with the last good
  reading. One dead box never blanks the others.
* **Everything is timestamped.** Each source carries its own ``collected_at``
  so "current" is something the page can prove, not imply.
* **Read-only.** Collectors mirror ``scripts/fleet_watcher.py``: BatchMode SSH,
  short timeouts, observation only. No box is modified; segmentation (notably
  ATTACK→CORP SSH staying blocked) is observed, never weakened for a health
  check.

The map is event-driven: each node takes the colour of its highest current
security condition, and each link pulses in a pattern keyed to its traffic
class (wan / transit / management / workload / sensor / blocked / allowed). A
``--demo`` engine synthesises the full catalogue of security events and traffic
so every colour and pulse is exercised when the live lab is out of reach.

Run it::

    python3 -m infra_dashboard serve --host 127.0.0.1 --port 8794
    python3 -m infra_dashboard serve --demo          # synthetic, no lab needed

Hosts/keys are taken from the same environment variables as ``fleet_watcher``
(``ASUS_HOST``, ``BRAIN_HOST``, ``HEX_HOST``, …) so the two agree.
"""
from __future__ import annotations

import argparse
import errno
import json
import os
import random
import re
import subprocess
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout

HERE = Path(__file__).resolve().parent
HTML_PATH = HERE / "infra_dashboard.html"
HOME = Path.home()

# --- source connection config (shared with scripts/fleet_watcher.py) --------
ASUS_HOST = os.environ.get("ASUS_HOST", "root@100.92.232.122")
ASUS_KEY = os.environ.get("ASUS_KEY", str(HOME / ".ssh/asus-openwrt-ed25519"))
BRAIN_HOST = os.environ.get("BRAIN_HOST", "root@192.168.0.240")
BRAIN_KEY = os.environ.get("BRAIN_KEY", str(HOME / ".ssh/id_ed25519_labvm"))
HEX_HOST = os.environ.get("HEX_HOST", "root@10.10.0.1")
PI_IP = os.environ.get("PI_IP", "10.50.0.220")

# A single poll must stay snappy; a dead box costs this, not a hang.
SOURCE_TIMEOUT = float(os.environ.get("INFRA_SOURCE_TIMEOUT", "14"))
# How far back an event still colours its node / counts as "current".
EVENT_WINDOW_SECS = float(os.environ.get("INFRA_EVENT_WINDOW", "120"))

# =========================================================================
# Event + traffic vocabulary
# =========================================================================
# severity rank: higher wins when a node has several current events.
SEVERITY_RANK = {"info": 0, "activity": 1, "warning": 2, "alert": 3}

# Each security-event type maps to a severity. The front-end colours the badge
# and the node from the severity; the type is what makes the stream readable.
EVENT_TYPES = {
    # perimeter / scanning
    "wan-probe":              {"severity": "warning", "label": "WAN probe"},
    "port-scan":              {"severity": "alert",   "label": "Port scan"},
    "recon":                  {"severity": "warning", "label": "Recon sweep"},
    # access / firewall
    "firewall-block":         {"severity": "alert",   "label": "Firewall block"},
    "brute-force":            {"severity": "alert",   "label": "Brute force"},
    "segmentation-violation": {"severity": "alert",   "label": "Segmentation breach"},
    "ids-alert":              {"severity": "alert",   "label": "IDS signature"},
    "dns-anomaly":            {"severity": "warning", "label": "DNS anomaly"},
    # presence / identity
    "new-device":             {"severity": "warning", "label": "New device"},
    "config-change":          {"severity": "activity", "label": "Config change"},
    # workload / health
    "conntrack-surge":        {"severity": "warning", "label": "Conntrack surge"},
    "cpu-pressure":           {"severity": "warning", "label": "CPU pressure"},
    "guest-start":            {"severity": "activity", "label": "Guest started"},
    "guest-stop":             {"severity": "activity", "label": "Guest stopped"},
    "traffic":                {"severity": "activity", "label": "Traffic"},
    # availability
    "link-down":              {"severity": "alert",   "label": "Link down"},
    "source-unreachable":     {"severity": "alert",   "label": "Source unreachable"},
    "healthy":                {"severity": "info",    "label": "Healthy"},
}

TRAFFIC_CLASSES = ("wan", "transit", "management", "workload", "sensor",
                   "allowed", "blocked")

# Firewall auth ports → a drop here reads as a credential attack, not just recon.
AUTH_PORTS = {"22", "3389", "445", "5985", "5986", "88", "389", "636", "1433", "3306"}
# Prefixes a router stamps on a flow it considers hostile (IDS-ish signatures).
_IDS_PREFIX = re.compile(r"(?i)crown|seal|vault|deny|attack|intru")
_KV = re.compile(r"\b(SRC|DST|PROTO|DPT)=([^\s]+)")
_PREFIX = re.compile(r"([A-Za-z][\w .:-]*?)\s*IN=")


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def classify_drop(prefix: str, dpt: str) -> str:
    """Turn a firewall drop line into a security-event type."""
    if prefix and _IDS_PREFIX.search(prefix):
        return "ids-alert"
    if dpt and dpt in AUTH_PORTS:
        return "brute-force"
    return "recon"


# =========================================================================
# Shell / SSH helpers (read-only, never raise) — ported from fleet_watcher
# =========================================================================
def sh(args: list[str], timeout: float) -> tuple[int, str]:
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout
    except (subprocess.TimeoutExpired, OSError) as exc:
        return 124, f"__error__ {exc}"


def ssh(target: str, remote_cmd: str, key: str | None = None,
        jump: str | None = None, timeout: float = SOURCE_TIMEOUT) -> tuple[int, str]:
    args = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
            "-o", "StrictHostKeyChecking=accept-new"]
    if key:
        args += ["-i", key, "-o", "IdentitiesOnly=yes"]
    if jump:
        args += ["-J", jump]
    args += [target, remote_cmd]
    return sh(args, timeout=timeout)


def _source(sid: str, label: str, role: str, address: str) -> dict:
    """A fresh source record. ``status`` starts unavailable and is only ever
    promoted by a successful poll — a failed poll leaves it unavailable."""
    return {
        "id": sid, "label": label, "role": role, "address": address,
        "status": "unavailable", "collected_at": now_iso(),
        "latency_ms": None, "detail": "", "facts": {}, "counters": {},
        "events": [],  # events this source raises, each {type, node, detail}
    }


# =========================================================================
# Live collectors — each returns a source record; one dead box never
# blanks the others (they run in parallel with per-source timeouts).
# =========================================================================
def collect_asus() -> dict:
    s = _source("asus", "ASUS edge", "WAN edge router / Wi-Fi", ASUS_HOST.split("@")[-1])
    t0 = time.time()
    rc, out = ssh(ASUS_HOST,
                  "uptime; echo ---; cat /tmp/dhcp.leases 2>/dev/null | wc -l; "
                  "echo ---; logread 2>/dev/null | grep -icE 'drop|reject'; "
                  "echo ---; logread 2>/dev/null | grep -iE 'drop|reject' | tail -8",
                  key=ASUS_KEY)
    s["latency_ms"] = round((time.time() - t0) * 1000)
    if rc != 0:
        s["detail"] = "edge router unreachable (SSH)"
        s["events"].append({"type": "source-unreachable", "node": "asus",
                             "detail": "ASUS edge did not answer SSH"})
        return s
    seg = out.split("---")
    leases = (seg[1].strip() if len(seg) > 1 else "0")
    drops = (seg[2].strip() if len(seg) > 2 else "0")
    s["status"] = "live"
    s["detail"] = seg[0].strip()[:120]
    s["counters"] = {"dhcp_leases": _int(leases), "fw_drop_lines": _int(drops)}
    s["facts"] = {"syslog_push": "live → collector:5514",
                  "role": "edge / NAT / Wi-Fi"}
    # WAN-side drops read as unsolicited probes at the perimeter.
    if _int(drops) > 0:
        s["events"].append({
            "type": "wan-probe", "node": "asus",
            "detail": f"{drops} drop/reject lines in edge log"})
    return s


def collect_hex() -> dict:
    """hEX is polled through the Brain SSH jump: the attack segment's L2 is not
    bridged to the operator box, so syslog cannot be pushed — the proven poll
    path is the only way to see its firewall, and segmentation stays intact."""
    s = _source("hex", "MikroTik hEX", "Range router / firewall", HEX_HOST.split("@")[-1])
    t0 = time.time()
    rc, out = ssh(HEX_HOST,
                  "uptime; echo ---CT---; wc -l < /proc/net/nf_conntrack 2>/dev/null; "
                  "echo ---DROPS---; logread 2>/dev/null | "
                  "grep -E 'IN=.*(DROP|drop|reject)|drop |reject ' | tail -40",
                  jump=BRAIN_HOST, timeout=SOURCE_TIMEOUT + 4)
    s["latency_ms"] = round((time.time() - t0) * 1000)
    if rc != 0:
        s["detail"] = "range firewall unreachable via Brain jump"
        s["events"].append({"type": "source-unreachable", "node": "hex",
                             "detail": "hEX did not answer over the Brain jump"})
        return s
    parts = re.split(r"---CT---|---DROPS---", out)
    ct = (parts[1].strip() if len(parts) > 1 else "")
    droplines = parts[2] if len(parts) > 2 else ""
    s["status"] = "live"
    s["detail"] = parts[0].strip()[:120]
    flows, by_src = [], {}
    for line in droplines.splitlines():
        kv = dict(_KV.findall(line))
        if not (kv.get("SRC") and kv.get("DST")):
            continue
        pm = _PREFIX.search(line)
        prefix = (pm.group(1).strip() if pm else "")[:48]
        dpt = kv.get("DPT", "")
        etype = classify_drop(prefix, dpt)
        flows.append({"src": kv["SRC"], "dst": kv["DST"], "dpt": dpt,
                      "proto": kv.get("PROTO", ""), "type": etype})
        by_src.setdefault(kv["SRC"], set()).add(dpt)
        # A drop crossing into mgmt/corp from the attack net is the policy event.
        crossing = _is_segmentation_violation(kv["SRC"], kv["DST"])
        s["events"].append({
            "type": "segmentation-violation" if crossing else etype,
            "node": "hex",
            "detail": f"{kv['SRC']} → {kv['DST']}"
                      + (f":{dpt}" if dpt else "") + f" dropped ({etype})"})
    # Many distinct ports from one source within one poll == a port scan.
    for src, ports in by_src.items():
        if len(ports) >= 4:
            s["events"].append({"type": "port-scan", "node": "hex",
                                 "detail": f"{src} hit {len(ports)} ports — scan"})
    s["counters"] = {"conntrack": _int(ct), "fw_drops_recent": len(flows)}
    s["facts"] = {"telemetry_path": "polled via Brain SSH jump",
                  "segments": "mgmt · attack · targets · corp"}
    s["_flows"] = flows  # consumed by the state builder for blocked links
    return s


def collect_brain() -> dict:
    s = _source("brain", "Brain Box", "Proxmox hypervisor", BRAIN_HOST.split("@")[-1])
    t0 = time.time()
    rc, out = ssh(BRAIN_HOST,
                  "uptime; echo ---; pct list 2>/dev/null | tail -n +2 | wc -l; "
                  "qm list 2>/dev/null | tail -n +2 | wc -l; "
                  "pct list 2>/dev/null | awk '$2==\"running\"'| wc -l; "
                  "echo ---; cat /proc/loadavg | awk '{print $1}'; "
                  "echo ---; pct list 2>/dev/null | tail -n +2; "
                  "qm list 2>/dev/null | tail -n +2",
                  key=BRAIN_KEY)
    s["latency_ms"] = round((time.time() - t0) * 1000)
    if rc != 0:
        s["detail"] = "hypervisor unreachable (SSH)"
        s["events"].append({"type": "source-unreachable", "node": "brain",
                             "detail": "Brain Box did not answer SSH"})
        return s
    seg = out.split("---")
    nums = re.findall(r"\d+", seg[1]) if len(seg) > 1 else []
    cts, vms, running = (nums + ["0", "0", "0"])[:3]
    load = _float(seg[2].strip() if len(seg) > 2 else "0")
    guest_lines = (seg[3].strip().splitlines() if len(seg) > 3 else [])
    s["status"] = "live"
    s["detail"] = seg[0].strip()[:120]
    s["counters"] = {"containers": _int(cts), "vms": _int(vms),
                     "running": _int(running), "loadavg": load}
    s["facts"] = {"role": "LXC + VM host for the range"}
    s["_guests"] = _parse_guests(guest_lines)
    if load >= 4.0:
        s["events"].append({"type": "cpu-pressure", "node": "brain",
                             "detail": f"loadavg {load} on hypervisor"})
    return s


def collect_thisbox() -> dict:
    """The operator box this dashboard runs on — local counters, always live."""
    s = _source("thisbox", "This box", "Operator workstation", "local")
    t0 = time.time()
    _, podman = sh(["bash", "-lc", "podman ps -q 2>/dev/null | wc -l"], timeout=6)
    _, virsh = sh(["bash", "-lc", "virsh list --name 2>/dev/null | grep -vc '^$'"], timeout=6)
    _, load = sh(["bash", "-lc", "cat /proc/loadavg | awk '{print $1}'"], timeout=4)
    _, cpus = sh(["bash", "-lc", "nproc 2>/dev/null || echo 1"], timeout=4)
    s["latency_ms"] = round((time.time() - t0) * 1000)
    la, nc = _float(load.strip() or "0"), max(1, _int(cpus.strip() or "1"))
    s["status"] = "live"
    s["detail"] = f"load {la} · {nc} cpu"
    s["counters"] = {"containers": _int(podman.strip() or "0"),
                     "libvirt_vms": _int(virsh.strip() or "0"),
                     "loadavg": la, "cpus": nc}
    s["facts"] = {"role": "operator seat on the attack segment"}
    if la > nc * 1.5:
        s["events"].append({"type": "cpu-pressure", "node": "thisbox",
                             "detail": f"loadavg {la} over {nc} cpu"})
    return s


def collect_pi() -> dict:
    """The Raspberry Pi drop. ATTACK→CORP SSH is deliberately denied, so the Pi
    is observed from the hEX (ICMP + ARP) rather than by weakening the policy."""
    s = _source("pi", "Raspberry Pi", "Drop sensor (CORP)", PI_IP)
    t0 = time.time()
    rc, out = ssh(HEX_HOST,
                  f"ping -c 1 -W 1 {PI_IP} >/dev/null 2>&1; rc=$?; "
                  f"ip neigh show {PI_IP}; exit $rc",
                  jump=BRAIN_HOST, timeout=12)
    s["latency_ms"] = round((time.time() - t0) * 1000)
    if rc != 0:
        s["detail"] = "not visible from hEX CORP interface"
        s["events"].append({"type": "link-down", "node": "pi",
                             "detail": "Pi not answering ICMP via hEX"})
        return s
    neigh = out.strip()
    mac = re.search(r"lladdr\s+([0-9a-f:]{17})", neigh, re.I)
    s["status"] = "live"
    s["detail"] = "hEX sees Pi on the CORP segment"
    s["counters"] = {"reachable": 1}
    s["facts"] = {"mac": mac.group(1).lower() if mac else "unknown",
                  "health_path": "hEX ICMP/ARP (ATTACK→CORP SSH stays blocked)",
                  "neighbor": neigh[:120]}
    return s


COLLECTORS = {
    "asus": collect_asus, "hex": collect_hex, "brain": collect_brain,
    "thisbox": collect_thisbox, "pi": collect_pi,
}


# --- small parse helpers ----------------------------------------------------
def _int(x: str | int) -> int:
    try:
        return int(str(x).strip())
    except (ValueError, TypeError):
        return 0


def _float(x: str | float) -> float:
    try:
        return round(float(str(x).strip()), 2)
    except (ValueError, TypeError):
        return 0.0


def _is_segmentation_violation(src: str, dst: str) -> bool:
    """A dropped flow from the attack net toward mgmt/corp is the one policy the
    whole segmentation exists to enforce."""
    attack = src.startswith("10.10.66.")
    protected = dst.startswith("10.10.0.") or dst.startswith("10.10.20.") or \
        dst.startswith("10.50.0.")
    return attack and protected


def _parse_guests(lines: list[str]) -> list[dict]:
    """Rows from `pct list` / `qm list`: '<id> <status> <name> ...'."""
    guests = []
    for line in lines:
        f = line.split()
        if len(f) >= 2 and f[0].isdigit():
            status = f[1]
            name = f[2] if len(f) >= 3 and not f[2].isdigit() else f"guest-{f[0]}"
            guests.append({"vmid": f[0], "status": status, "name": name})
    return guests


# =========================================================================
# Demo engine — synthesises the full event + traffic catalogue so every
# colour and pulse is exercised when the live lab is out of reach.
# =========================================================================
class DemoEngine:
    GUESTS = [
        {"vmid": "600", "name": "nord-srv01", "status": "running"},
        {"vmid": "601", "name": "nord-web",   "status": "running"},
        {"vmid": "602", "name": "nord-ws01",  "status": "running"},
        {"vmid": "650", "name": "range-dc",   "status": "running"},
    ]
    SCRIPT = [  # (source, event-type, node, detail) rotated over time
        ("asus",  "wan-probe",              "asus",  "45.148.x.x sweeping WAN 80/443"),
        ("hex",   "port-scan",              "hex",   "10.10.66.5 hit 11 ports in 2s — scan"),
        ("hex",   "segmentation-violation", "hex",   "10.10.66.5 → 10.10.0.2:22 dropped (mgmt)"),
        ("hex",   "brute-force",            "hex",   "10.10.66.5 → 10.10.20.10:445 ×24 dropped"),
        ("asus",  "new-device",             "asus",  "unknown MAC a4:83:e7:… joined Wi-Fi"),
        ("hex",   "ids-alert",              "hex",   "signature 'crown-exfil' matched on CORP"),
        ("brain", "guest-start",            "brain", "CT 601 nord-web started"),
        ("hex",   "conntrack-surge",        "hex",   "conntrack 18420 — 3.2× baseline"),
        ("thisbox", "cpu-pressure",         "thisbox", "loadavg 6.8 over 4 cpu"),
        ("asus",  "dns-anomaly",            "asus",  "212 NXDOMAIN in 60s from 10.10.66.5"),
        ("brain", "config-change",          "brain", "/etc/pve/firewall changed"),
        ("hex",   "firewall-block",         "hex",   "10.10.66.5 → 8.8.8.8:53 dropped (no WAN)"),
        ("pi",    "link-down",              "pi",    "Pi stopped answering ICMP via hEX"),
        ("brain", "guest-stop",             "brain", "VM 650 range-dc stopped"),
    ]

    def __init__(self, seed: int | None = None):
        self.t0 = time.time()
        self.rng = random.Random(seed)

    def sources(self) -> dict[str, dict]:
        age = time.time() - self.t0
        tick = int(age // 4)
        out = {}
        # ASUS
        a = _source("asus", "ASUS edge", "WAN edge router / Wi-Fi", "100.92.232.122")
        a.update(status="live", detail="up 9 days · demo",
                 counters={"dhcp_leases": 7 + tick % 3,
                           "fw_drop_lines": 40 + self.rng.randint(0, 20)})
        a["facts"] = {"syslog_push": "live → collector:5514", "role": "edge / NAT / Wi-Fi"}
        out["asus"] = a
        # hEX
        h = _source("hex", "MikroTik hEX", "Range router / firewall", "10.10.0.1")
        h.update(status="live", detail="up 21 days · demo",
                 counters={"conntrack": 5600 + (tick * 137) % 14000,
                           "fw_drops_recent": self.rng.randint(0, 9)})
        h["facts"] = {"telemetry_path": "polled via Brain SSH jump",
                      "segments": "mgmt · attack · targets · corp"}
        h["_flows"] = self._demo_flows()
        out["hex"] = h
        # Brain
        b = _source("brain", "Brain Box", "Proxmox hypervisor", "192.168.0.240")
        running = 3 + (tick % 2)
        b.update(status="live", detail="up 44 days · demo",
                 counters={"containers": 4, "vms": 2, "running": running,
                           "loadavg": round(1.2 + (tick % 5) * 0.4, 2)})
        b["facts"] = {"role": "LXC + VM host for the range"}
        b["_guests"] = [dict(g, status="running" if i < running else "stopped")
                        for i, g in enumerate(self.GUESTS)]
        out["brain"] = b
        # this box
        t = _source("thisbox", "This box", "Operator workstation", "local")
        la = round(0.8 + (tick % 7) * 0.9, 2)
        t.update(status="live", detail=f"load {la} · 4 cpu · demo",
                 counters={"containers": 3, "libvirt_vms": 1, "loadavg": la, "cpus": 4})
        t["facts"] = {"role": "operator seat on the attack segment"}
        out["thisbox"] = t
        # Pi — flips unavailable when the link-down beat is current, to show grey.
        p = _source("pi", "Raspberry Pi", "Drop sensor (CORP)", PI_IP)
        s_type = self.SCRIPT[tick % len(self.SCRIPT)][1]
        if s_type == "link-down":
            p["detail"] = "not visible from hEX CORP interface"
            p["events"].append({"type": "link-down", "node": "pi",
                                "detail": "Pi stopped answering ICMP via hEX"})
        else:
            p.update(status="live", detail="hEX sees Pi on the CORP segment",
                     counters={"reachable": 1},
                     facts={"mac": "dc:a6:32:11:22:33",
                            "health_path": "hEX ICMP/ARP (ATTACK→CORP SSH stays blocked)"})
        out["pi"] = p

        # Fold the rotating script beat onto its source.
        src, etype, node, detail = self.SCRIPT[tick % len(self.SCRIPT)]
        if etype != "link-down":
            out[src]["events"].append({"type": etype, "node": node, "detail": detail})
        # A second, overlapping beat keeps the map lively (different node colour).
        src2, etype2, node2, detail2 = self.SCRIPT[(tick + 5) % len(self.SCRIPT)]
        if etype2 != "link-down" and node2 != node:
            out[src2]["events"].append({"type": etype2, "node": node2, "detail": detail2})
        return out

    def _demo_flows(self) -> list[dict]:
        pool = [
            {"src": "10.10.66.5", "dst": "10.10.0.2", "dpt": "22", "proto": "tcp", "type": "brute-force"},
            {"src": "10.10.66.5", "dst": "10.10.20.10", "dpt": "445", "proto": "tcp", "type": "segmentation-violation"},
            {"src": "45.148.10.7", "dst": "100.92.232.122", "dpt": "443", "proto": "tcp", "type": "recon"},
            {"src": "10.10.66.5", "dst": "10.50.0.220", "dpt": "3389", "proto": "tcp", "type": "port-scan"},
        ]
        return self.rng.sample(pool, k=self.rng.randint(1, len(pool)))


# =========================================================================
# State builder — assembles the one object the page renders.
# =========================================================================
# The fixed infrastructure layout. Dynamic nodes (guests) are appended.
STATIC_NODES = [
    {"id": "wan", "label": "Internet", "type": "cloud", "tier": 0, "source": None},
    {"id": "asus", "label": "ASUS edge", "type": "router", "tier": 1, "source": "asus"},
    {"id": "hex", "label": "MikroTik hEX", "type": "firewall", "tier": 2, "source": "hex"},
    {"id": "brain", "label": "Brain Box", "type": "host", "tier": 3, "source": "brain"},
    {"id": "thisbox", "label": "This box", "type": "operator", "tier": 3, "source": "thisbox"},
    {"id": "pi", "label": "Raspberry Pi", "type": "sensor", "tier": 3, "source": "pi"},
]
STATIC_LINKS = [
    {"id": "wan-asus", "source": "wan", "target": "asus", "traffic": "wan"},
    {"id": "asus-hex", "source": "asus", "target": "hex", "traffic": "transit"},
    {"id": "hex-brain", "source": "hex", "target": "brain", "traffic": "management"},
    {"id": "hex-thisbox", "source": "hex", "target": "thisbox", "traffic": "workload"},
    {"id": "hex-pi", "source": "hex", "target": "pi", "traffic": "sensor"},
]


def _condition_for(node_id: str, source: dict | None, events: list[dict]) -> tuple[str, list[str]]:
    """A node's colour = its highest current security condition, with reasons."""
    if source is not None and source.get("status") == "unavailable":
        reasons = [e["detail"] for e in events if e["node"] == node_id] or \
            [f"{source['label']} did not answer its poll"]
        return "unavailable", reasons
    mine = [e for e in events if e["node"] == node_id]
    if not mine:
        return ("healthy", ["reporting, no current events"]) if source else ("info", [])
    top = max(mine, key=lambda e: SEVERITY_RANK.get(
        EVENT_TYPES.get(e["type"], {}).get("severity", "info"), 0))
    sev = EVENT_TYPES.get(top["type"], {}).get("severity", "info")
    cond = {"alert": "alert", "warning": "warning",
            "activity": "activity", "info": "healthy"}[sev]
    reasons = [f"{EVENT_TYPES.get(e['type'], {}).get('label', e['type'])}: {e.get('detail', '')}".rstrip(": ")
               for e in mine]
    return cond, reasons


def build_state(demo: DemoEngine | None = None) -> dict:
    """Poll every source (or drive the demo), then assemble nodes, links, and a
    newest-first event stream. Never reuses a previous reading."""
    if demo is not None:
        sources = demo.sources()
    else:
        sources = {}
        with ThreadPoolExecutor(max_workers=len(COLLECTORS)) as pool:
            futs = {sid: pool.submit(fn) for sid, fn in COLLECTORS.items()}
            for sid, fut in futs.items():
                try:
                    sources[sid] = fut.result(timeout=SOURCE_TIMEOUT + 6)
                except (FutureTimeout, Exception) as exc:  # noqa: BLE001
                    s = _source(sid, sid, "", "")
                    s["detail"] = f"collector error: {exc}"
                    s["events"].append({"type": "source-unreachable", "node": sid,
                                         "detail": f"collector raised: {exc}"})
                    sources[sid] = s

    ts = now_iso()
    # --- gather every event, newest-first, each stamped with its source time.
    events: list[dict] = []
    for sid, s in sources.items():
        for ev in s.get("events", []):
            meta = EVENT_TYPES.get(ev["type"], {"severity": "info", "label": ev["type"]})
            events.append({
                "ts": s.get("collected_at", ts), "source": sid,
                "node": ev["node"], "type": ev["type"],
                "label": meta["label"], "severity": meta["severity"],
                "detail": ev.get("detail", "")})
    events.sort(key=lambda e: (SEVERITY_RANK.get(e["severity"], 0), e["ts"]), reverse=True)

    # --- nodes: static infra + live Proxmox guests under the Brain.
    nodes = [dict(n) for n in STATIC_NODES]
    links = [dict(link) for link in STATIC_LINKS]
    brain = sources.get("brain", {})
    for i, g in enumerate(brain.get("_guests", [])):
        gid = f"guest:{g['vmid']}"
        guest_events = []
        if g.get("status") == "running":
            # running guests show live workload, not a security event.
            guest_events.append({"type": "traffic", "node": gid,
                                 "detail": f"{g['name']} running"})
        nodes.append({"id": gid, "label": g["name"], "type": "guest",
                      "tier": 4, "source": "brain",
                      "vmid": g["vmid"], "guest_status": g.get("status")})
        links.append({"id": f"brain-{gid}", "source": "brain", "target": gid,
                       "traffic": "workload" if g.get("status") == "running" else "allowed",
                       "active": g.get("status") == "running"})
        events.extend({"ts": brain.get("collected_at", ts), "source": "brain",
                       "node": gid, "type": ge["type"],
                       "label": EVENT_TYPES[ge["type"]]["label"],
                       "severity": EVENT_TYPES[ge["type"]]["severity"],
                       "detail": ge["detail"]} for ge in guest_events)

    # --- blocked flows from hEX become red overlay links + their own events.
    blocked = []
    for fl in sources.get("hex", {}).get("_flows", []):
        blocked.append({"id": f"blk:{fl['src']}->{fl['dst']}:{fl.get('dpt','')}",
                        "src": fl["src"], "dst": fl["dst"], "dpt": fl.get("dpt", ""),
                        "proto": fl.get("proto", ""), "type": fl.get("type", "recon")})

    # --- colour every node from its highest current event.
    for n in nodes:
        src = sources.get(n["source"]) if n.get("source") else None
        cond, reasons = _condition_for(n["id"], src, events)
        n["condition"], n["reasons"] = cond, reasons

    # --- per-link activity: a link is "active" when its endpoints are live, and
    #     carries the rate hint the pulse speed reads from.
    for link in links:
        if "active" in link:
            continue
        tgt = sources.get(_node_source(nodes, link["target"]))
        src = sources.get(_node_source(nodes, link["source"]))
        live = (src is None or src.get("status") == "live") and \
               (tgt is None or tgt.get("status") == "live")
        link["active"] = bool(live)

    reachable = sum(1 for s in sources.values() if s.get("status") == "live")
    return {
        "generated_at": ts,
        "mode": "demo" if demo is not None else "live",
        "summary": f"{reachable}/{len(sources)} sources live",
        "sources": {sid: _public_source(s) for sid, s in sources.items()},
        "nodes": nodes,
        "links": links,
        "blocked": blocked,
        "events": events[:60],
        "legend": {"event_types": EVENT_TYPES, "traffic_classes": list(TRAFFIC_CLASSES)},
    }


def _node_source(nodes: list[dict], node_id: str) -> str | None:
    for n in nodes:
        if n["id"] == node_id:
            return n.get("source")
    return None


def _public_source(s: dict) -> dict:
    """Strip private builder keys (prefixed '_') before sending to the page."""
    return {k: v for k, v in s.items() if not k.startswith("_")}


# =========================================================================
# HTTP server — serves the page, a fresh snapshot, and an SSE stream.
# =========================================================================
class Handler(BaseHTTPRequestHandler):
    demo: DemoEngine | None = None
    stream_interval: float = 3.0

    def log_message(self, *a):  # quiet
        pass

    def _no_cache(self):
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/", "/index.html", "/infra_dashboard.html"):
            return self._send_html()
        if path == "/api/state":
            return self._send_state()
        if path == "/api/stream":
            return self._send_stream()
        if path == "/healthz":
            return self._send_json({"ok": True, "ts": now_iso()})
        self.send_error(404, "not found")

    def _send_html(self):
        try:
            body = HTML_PATH.read_bytes()
        except OSError:
            return self.send_error(500, "page missing")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self._no_cache()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, obj: dict):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self._no_cache()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_state(self):
        self._send_json(build_state(self.demo))

    def _send_stream(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self._no_cache()
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        try:
            while True:
                payload = json.dumps(build_state(self.demo))
                self.wfile.write(f"data: {payload}\n\n".encode())
                self.wfile.flush()
                time.sleep(self.stream_interval)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return


def make_server(host: str, port: int, demo: bool = False,
                interval: float = 3.0) -> ThreadingHTTPServer:
    handler = type("BoundHandler", (Handler,),
                   {"demo": DemoEngine() if demo else None,
                    "stream_interval": interval})
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.daemon_threads = True
    return httpd


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd")
    srv = sub.add_parser("serve", help="run the dashboard HTTP server")
    srv.add_argument("--host", default="127.0.0.1")
    srv.add_argument("--port", type=int, default=8794,
                     help="TCP port (0 picks a free one, printed on start)")
    srv.add_argument("--demo", action="store_true",
                     help="synthesise telemetry (no lab access needed)")
    srv.add_argument("--interval", type=float, default=3.0,
                     help="SSE snapshot interval, seconds")
    snap = sub.add_parser("snapshot", help="print one state snapshot as JSON")
    snap.add_argument("--demo", action="store_true")
    args = ap.parse_args(argv)

    if args.cmd == "snapshot":
        print(json.dumps(build_state(DemoEngine() if args.demo else None), indent=2))
        return 0
    if args.cmd == "serve" or args.cmd is None:
        host = getattr(args, "host", "127.0.0.1")
        port = getattr(args, "port", 8794)
        demo = getattr(args, "demo", False)
        interval = getattr(args, "interval", 3.0)
        try:
            httpd = make_server(host, port, demo=demo, interval=interval)
        except OSError as exc:
            if exc.errno == errno.EADDRINUSE:
                print(f"[infra] port {port} on {host} is already in use. "
                      f"Re-run with a different --port, or --port 0 to auto-pick a free one.",
                      flush=True)
                return 2
            raise
        actual_port = httpd.server_address[1]  # real port, even when --port 0
        where = f"http://{host}:{actual_port}"
        print(f"[infra] serving {where}  (mode={'demo' if demo else 'live'})", flush=True)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[infra] stopped", flush=True)
        return 0
    ap.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
