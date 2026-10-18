#!/usr/bin/env python3
"""fleet_watcher.py — one live telemetry roll-call across every lab box.

Polls each machine over its own working path and writes two files:

  runs/live-brain/dashboard/fleet.json   the "sight" summary — per box: reachable?
      role, uptime/load, and a few telemetry counters (guests, containers,
      conntrack, fw drops, DHCP leases). The voice assistant reads this to answer
      "what boxes are up" and the dashboard can surface it as a fleet panel.

  /run/user/<uid>/fleet-poll-flows.json  hEX firewall drop flows pulled over the
      brain SSH jump, in the {src,dst,class} shape brain_watcher merges — hEX
      cannot push syslog to Parrot (attack-segment L2 is not bridged), so its
      telemetry comes through this proven poll path instead.

Each box is polled independently: one unreachable box never blanks the others.
All SSH uses BatchMode + short timeouts, so a dead box costs a few seconds, not a
hang. Read-only everywhere; no box is modified.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
from pathlib import Path

HOME = Path.home()
RUN_DIR = HOME / "Projects/keystone-range/runs/live-brain/dashboard"
FLEET_OUT = RUN_DIR / "fleet.json"
POLL_FLOWS_OUT = Path(os.environ.get(
    "FLEET_POLL_FLOWS", f"/run/user/{os.getuid()}/fleet-poll-flows.json"))
POLL_SECS = float(os.environ.get("FLEET_POLL_SECS", "20"))
FLOW_TTL = float(os.environ.get("FLEET_FLOW_TTL", "60"))

ASUS_KEY = str(HOME / ".ssh/asus-openwrt-ed25519")
ASUS_HOST = os.environ.get("ASUS_HOST", "root@100.92.232.122")
BRAIN_HOST = os.environ.get("BRAIN_HOST", "root@192.168.0.240")
HEX_HOST = os.environ.get("HEX_HOST", "root@10.10.0.1")

_KV = re.compile(r"\b(SRC|DST|PROTO|DPT)=([^\s]+)")
_PREFIX = re.compile(r"([A-Za-z][\w .:-]*?)\s*IN=")
_ATTACK_PREFIX = re.compile(r"(?i)crown|seal|vault|deny|attack|intru")
_ATTACK_DPT = {"22", "445", "3389", "88", "389", "636", "1433", "3306", "5985", "5986"}


def classify(prefix: str, dpt: str) -> str:
    if prefix and _ATTACK_PREFIX.search(prefix):
        return "attack"
    if dpt and dpt in _ATTACK_DPT:
        return "attack"
    return "recon"


def sh(args: list[str], timeout: float = 12) -> tuple[int, str]:
    """Run a local command; return (rc, stdout). Never raises."""
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout
    except (subprocess.TimeoutExpired, OSError) as exc:
        return 124, f"__error__ {exc}"


def ssh(target: str, remote_cmd: str, key: str | None = None,
        jump: str | None = None, timeout: float = 12) -> tuple[int, str]:
    args = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
            "-o", "StrictHostKeyChecking=accept-new"]
    if key:
        args += ["-i", key, "-o", "IdentitiesOnly=yes"]
    if jump:
        args += ["-J", jump]
    args += [target, remote_cmd]
    return sh(args, timeout=timeout)


def box(name: str, role: str, addr: str) -> dict:
    return {"name": name, "role": role, "address": addr,
            "reachable": False, "telemetry": {}, "detail": ""}


# --- per-box pollers; each returns a fleet entry ---------------------------

def poll_brain() -> dict:
    b = box("lab-brain", "Proxmox hypervisor (lab host)", "192.168.0.240")
    rc, out = ssh(BRAIN_HOST, "uptime; echo ---; pct list 2>/dev/null | tail -n +2 | wc -l; "
                  "qm list 2>/dev/null | tail -n +2 | wc -l; "
                  "pct list 2>/dev/null | awk '$2==\"running\"' | wc -l",
                  key=str(HOME / ".ssh/id_ed25519_labvm"))
    if rc == 0:
        parts = out.split("---")
        up = parts[0].strip()
        nums = re.findall(r"\d+", parts[1]) if len(parts) > 1 else []
        cts, vms, running = (nums + ["", "", ""])[:3]
        b.update(reachable=True, detail=up[:120])
        b["telemetry"] = {"containers": cts, "vms": vms, "cts_running": running}
    return b


def poll_lab_agent() -> dict:
    b = box("lab-agent", "lab worker (Proxmox CT 201)", "192.168.0.253")
    rc, out = ssh("root@192.168.0.253", "uptime", key=str(HOME / ".ssh/id_ed25519"))
    if rc == 0:
        b.update(reachable=True, detail=out.strip()[:120])
    return b


def poll_pi() -> dict:
    b = box("pi (drop01)", "EvilKit OS physical CORP worker", "10.50.0.220")
    # ATTACK -> CORP SSH is intentionally denied. Observe physical presence
    # from the hEX instead of weakening segmentation for a health check.
    rc, out = ssh(
        HEX_HOST,
        "ping -c 1 -W 1 10.50.0.220 >/dev/null 2>&1; rc=$?; "
        "ip neigh show 10.50.0.220; exit $rc",
        jump=BRAIN_HOST,
        timeout=10,
    )
    if rc == 0:
        neighbor = out.strip()
        mac = re.search(r"lladdr\s+([0-9a-f:]{17})", neighbor, re.I)
        b.update(reachable=True, detail="hEX sees Pi on br-keystone")
        b["telemetry"] = {
            "segment": "CORP · VLAN 50 · SG108E p3",
            "neighbor": neighbor[:120],
            "mac": mac.group(1).lower() if mac else "unknown",
            "health_path": "hEX ICMP/ARP (ATTACK→CORP SSH remains blocked)",
        }
    else:
        b["detail"] = "not visible from hEX CORP interface"
    return b


def poll_run8_vm() -> dict:
    """The staged Run 8 drop VM on will-laptop (VirtualBox, lab attacker VLAN).

    Key auth via the lab VLAN address (falls back to the laptop NAT forward).
    Reports the service state that matters to the run: desktop session,
    bootstrap service, and the implant-link address.
    """
    b = box("run8-vm", "Run 8 staged drop VM (VirtualBox on will-laptop)",
            "10.10.66.104 (lab) / 100.83.141.3:2222 (NAT)")
    key = str(HOME / ".ssh/id_ed25519_run8vm")
    target = "will@10.10.66.104"
    extra: list[str] = []
    rc, out = ssh(target,
                  "uptime; echo ---SVC---; systemctl is-active lightdm; "
                  "systemctl is-enabled evilkit-bootstrap.service; echo ---ADDR---; "
                  "ip -br addr | awk '{print $1, $3}'",
                  key=key, timeout=10)
    if rc != 0:
        rc, out = ssh("run8-vm",
                      "uptime; echo ---SVC---; systemctl is-active lightdm; "
                      "systemctl is-enabled evilkit-bootstrap.service; echo ---ADDR---; "
                      "ip -br addr | awk '{print $1, $3}'",
                      key=key, timeout=10)
        extra.append("via NAT fallback")
    if rc == 0:
        parts = out.split("---SVC---")
        seg = re.split(r"---SVC---|---ADDR---", out)
        up = seg[0].strip()
        svc = seg[1].split() if len(seg) > 1 else []
        addrs = seg[2].strip() if len(seg) > 2 else ""
        lightdm = svc[0] if svc else "?"
        bootstrap = svc[1] if len(svc) > 1 else "?"
        b.update(reachable=True, detail=(up[:100] + (" · " + " ".join(extra) if extra else "")))
        b["telemetry"] = {
            "lightdm": lightdm,
            "bootstrap_svc": bootstrap,
            "addresses": " ".join(addrs.split())[:120],
        }
    return b


def poll_asus() -> dict:
    b = box("asus (lab-edge)", "OpenWrt edge router / wifi", "100.92.232.122")
    rc, out = ssh(ASUS_HOST,
                  "uptime; echo ---; "
                  "cat /tmp/dhcp.leases 2>/dev/null | wc -l; echo ---; "
                  "logread 2>/dev/null | grep -icE 'drop|reject'",
                  key=ASUS_KEY)
    if rc == 0:
        seg = out.split("---")
        b.update(reachable=True, detail=seg[0].strip()[:120])
        b["telemetry"] = {
            "dhcp_leases": (seg[1].strip() if len(seg) > 1 else ""),
            "fw_drop_lines": (seg[2].strip() if len(seg) > 2 else ""),
            "syslog_push": "live -> collector:5514",
        }
    return b


def poll_hex() -> tuple[dict, list[dict]]:
    """Returns (fleet entry, derived drop flows) — polled via the brain jump."""
    b = box("hex (labrouter)", "OpenWrt range router / firewall", "10.10.0.1")
    flows: list[dict] = []
    rc, out = ssh(HEX_HOST,
                  "uptime; echo ---CT---; wc -l < /proc/net/nf_conntrack; "
                  "echo ---DROPS---; logread 2>/dev/null | grep -E 'IN=.*(DROP|drop|reject)|drop |reject ' | tail -40",
                  jump=BRAIN_HOST, timeout=16)
    if rc == 0:
        seg = re.split(r"---CT---|---DROPS---", out)
        b.update(reachable=True, detail=(seg[0].strip()[:120] if seg else ""))
        ct = seg[1].strip() if len(seg) > 1 else ""
        droplines = seg[2] if len(seg) > 2 else ""
        now = time.time()
        for line in droplines.splitlines():
            kv = dict(_KV.findall(line))
            if kv.get("SRC") and kv.get("DST"):
                pm = _PREFIX.search(line)
                prefix = (pm.group(1).strip() if pm else "")[:48]
                dpt = kv.get("DPT", "")
                flows.append({"src": kv["SRC"], "dst": kv["DST"],
                              "class": classify(prefix, dpt),
                              "proto": kv.get("PROTO", ""), "dpt": dpt,
                              "prefix": prefix, "router": "labrouter", "ts": now})
        b["telemetry"] = {"conntrack": ct, "fw_drops_recent": str(len(flows)),
                          "syslog_push": "blocked (attack-seg L2 split) — polled via brain"}
    return b, flows


def poll_parrot() -> dict:
    b = box("parrot (operator)", "attack workstation + local VMs/containers", "192.168.0.10")
    b["reachable"] = True
    rc_p, podman = sh(["bash", "-lc", "podman ps -q 2>/dev/null | wc -l"])
    rc_v, virsh = sh(["bash", "-lc", "virsh list --all --name 2>/dev/null | grep -vc '^$'"])
    rc_vm, vmw = sh(["bash", "-lc", "command -v vmrun >/dev/null && vmrun list 2>/dev/null | sed -n '1p' | grep -oE '[0-9]+' || echo 0"])
    rc_l, load = sh(["bash", "-lc", "cat /proc/loadavg | awk '{print $1,$2,$3}'"])
    b["telemetry"] = {
        "containers": podman.strip() or "0",
        "libvirt_vms": virsh.strip() or "0",
        "vmware_running": vmw.strip() or "0",
    }
    b["detail"] = f"load {load.strip()}"
    return b


def live_poll_flows(flows: list[dict], prev: list[dict]) -> list[dict]:
    """Keep hEX drop flows alive for FLOW_TTL so they stay visible between the
    slower fleet polls, then expire — mirrors the collector's TTL behaviour."""
    now = time.time()
    merged = {}
    for f in prev + flows:
        key = (f.get("src"), f.get("dst"), f.get("dpt"))
        if now - f.get("ts", 0) <= FLOW_TTL:
            merged[key] = f
    return list(merged.values())


def write_atomic(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(data)
    tmp.replace(path)


def main() -> int:
    prev_flows: list[dict] = []
    while True:
        boxes = []
        try:
            boxes.append(poll_brain())
        except Exception as e:
            boxes.append({**box("lab-brain", "Proxmox hypervisor", "192.168.0.240"), "detail": f"poll error: {e}"})
        for fn in (poll_lab_agent, poll_pi, poll_run8_vm, poll_asus, poll_parrot):
            try:
                boxes.append(fn())
            except Exception as e:
                boxes.append({"name": fn.__name__, "reachable": False, "detail": f"poll error: {e}", "telemetry": {}})
        hex_flows: list[dict] = []
        try:
            hb, hex_flows = poll_hex()
            boxes.append(hb)
        except Exception as e:
            boxes.append({**box("hex (labrouter)", "OpenWrt range router", "10.10.0.1"), "detail": f"poll error: {e}"})

        prev_flows = live_poll_flows(hex_flows, prev_flows)
        write_atomic(POLL_FLOWS_OUT, json.dumps({"ts": time.time(), "flows": prev_flows}))

        up = sum(1 for b in boxes if b.get("reachable"))
        fleet = {
            "ts": time.time(),
            "summary": f"{up}/{len(boxes)} boxes reachable",
            "boxes": boxes,
        }
        write_atomic(FLEET_OUT, json.dumps(fleet, indent=2))
        print(f"[fleet] {fleet['summary']} · {len(prev_flows)} hex flows live", flush=True)
        time.sleep(POLL_SECS)


if __name__ == "__main__":
    raise SystemExit(main())
