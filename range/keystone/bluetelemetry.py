"""bluetelemetry.py — project a run's ground truth into blue-observable sensors.

Keystone captures *attacker-side* truth: ``journal.jsonl`` (the operator's
declared intents), ``pcaps/``, ``fsdiff.json``, ``beacons.jsonl`` and the
dashboard event stream. A real SOC analyst never sees any of that. What a
defending estate actually has is its own telemetry: netflow, firewall drop
logs, per-host auth logs, EDR process/file events, and the alerts its canaries
and honeypots raise.

This module is the **one-way projection** between the two. It reads the run's
ground-truth evidence and emits only sensor-shaped records an estate would
legitimately produce, writing them under ``runs/<id>/telemetry/`` where the
Keystone defense MCP server (and therefore blukit) can read them.

What it deliberately does **not** do:

* It never copies the attacker's journal intent text, reasoning, action
  labels, or any free-text the operator wrote. Those are the red transcript.
* It never emits the canary token value, crown flag values, or anything from
  the private scoring key. A canary *read* becomes an alert that says a read
  happened — not what was read.

The projection is deterministic: the same evidence always yields the same
streams, so detection scoring downstream is reproducible. Where a stream needs
a fact the captures cannot prove (did an auth *succeed*?), the heuristic is
named in the record (``basis`` field) rather than hidden, so the defender —
and anyone reviewing the loop — can see it is inference, not observation.

Streams emitted (one JSONL file each, one record per line):

  ``netflow.jsonl``          per-conversation flow records (collector view)
  ``firewall-drops.jsonl``   attempts whose src->dst zone violates ZONE_POLICY
  ``auth-<host>.jsonl``      auth attempts to ssh/smb/rdp/winrm/kerberos per host
  ``host-<host>.jsonl``      EDR-style process/file events per host
  ``alerts.jsonl``           high-signal detections (canary / answer-key read)

Public API:

  ``synthesize_from_evidence(ev)``  pure: Evidence -> {filename: [records]}
  ``synthesize(run_dir)``           load evidence, write streams, return manifest
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

from . import pcap, zones
from .evidence import Evidence, load_evidence

__all__ = ["synthesize_from_evidence", "synthesize", "AUTH_SERVICES", "main"]

#: Destination ports a credential/authentication sensor cares about. Web and
#: cache ports are intentionally absent: those surface as netflow + host events,
#: not as auth-log lines.
AUTH_SERVICES: Dict[int, str] = {
    22: "ssh",
    445: "smb",
    139: "smb",
    3389: "rdp",
    5985: "winrm",
    5986: "winrm",
    88: "kerberos",
    389: "ldap",
    636: "ldaps",
}

TELEMETRY_SUBDIR = "telemetry"


def _host_label(ev: Evidence, ip: str) -> str:
    """A filename-safe host label for per-host streams: hostname if known, else IP."""
    rec = ev._by_ip.get(ip)
    if rec and rec.hostname:
        return rec.hostname
    return ip.replace(":", "_")


def _compromised_ips(ev: Evidence) -> set[str]:
    """Hosts with direct, host-level change evidence — used only to mark an auth
    attempt as a likely success. This is corroboration, not the red transcript:
    a file changed on a host or a beacon left it, both of which an estate sensor
    could independently observe."""
    out: set[str] = set()
    for host in ev.fsdiff.keys():
        out.add(ev.ip_of(str(host)))
    for b in ev.beacons:
        for field in ("host", "src", "src_ip", "source"):
            v = b.get(field)
            if v:
                out.add(ev.ip_of(str(v)))
    return {ip for ip in out if ip}


def _flows(packets: List[pcap.Packet]) -> List[Dict[str, Any]]:
    """Collapse packets into directed 5-tuple flows (a netflow collector's view)."""
    agg: Dict[Tuple[str, str, str, Optional[int]], Dict[str, Any]] = {}
    for p in packets:
        key = (p.src_ip, p.dst_ip, p.proto_name, p.dst_port)
        f = agg.get(key)
        if f is None:
            agg[key] = {
                "src": p.src_ip,
                "dst": p.dst_ip,
                "proto": p.proto_name,
                "dst_port": p.dst_port,
                "src_port": p.src_port,
                "first_ts": p.ts,
                "last_ts": p.ts,
                "packets": 1,
                "bytes": p.length,
            }
        else:
            f["last_ts"] = max(f["last_ts"], p.ts)
            f["first_ts"] = min(f["first_ts"], p.ts)
            f["packets"] += 1
            f["bytes"] += p.length
    return [agg[k] for k in sorted(agg, key=lambda k: agg[k]["first_ts"])]


def _run_epoch(packets: List[pcap.Packet]) -> Optional[float]:
    return min((p.ts for p in packets), default=None)


def synthesize_from_evidence(ev: Evidence) -> Dict[str, List[Dict[str, Any]]]:
    """Pure projection: evidence in, named sensor streams out.

    Returns a mapping of output filename -> list of records. No file IO, so it
    is trivially unit-testable with a hand-built :class:`Evidence`.
    """
    streams: Dict[str, List[Dict[str, Any]]] = {}
    flows = _flows(ev.packets)
    compromised = _compromised_ips(ev)

    # --- netflow: every flow, verbatim shape a collector would log ----------
    streams["netflow.jsonl"] = [
        {
            "ts": round(f["first_ts"], 3),
            "last_ts": round(f["last_ts"], 3),
            "src": f["src"],
            "dst": f["dst"],
            "proto": f["proto"],
            "dst_port": f["dst_port"],
            "packets": f["packets"],
            "bytes": f["bytes"],
        }
        for f in flows
    ]

    # --- firewall drops: client->server attempts that cross a denied edge ----
    # Directed: we only flag flows with a server port set (the initiating
    # direction), so established return traffic is not counted as a drop.
    drops: List[Dict[str, Any]] = []
    for f in flows:
        if f["dst_port"] is None:
            continue
        src_zone = zones.zone_of_ip(f["src"])
        dst_zone = zones.zone_of_ip(f["dst"])
        if src_zone == "unknown" or dst_zone == "unknown":
            continue
        if src_zone == dst_zone:
            continue
        if zones.reachable(src_zone, dst_zone):
            continue
        drops.append({
            "ts": round(f["first_ts"], 3),
            "src": f["src"],
            "dst": f["dst"],
            "src_zone": src_zone,
            "dst_zone": dst_zone,
            "dst_port": f["dst_port"],
            "proto": f["proto"],
            "rule": f"drop {src_zone}->{dst_zone}",
        })
    streams["firewall-drops.jsonl"] = drops

    # --- auth logs, per destination host ------------------------------------
    for f in flows:
        svc = AUTH_SERVICES.get(f["dst_port"] or -1)
        if svc is None:
            continue
        label = _host_label(ev, f["dst"])
        outcome = "accepted" if f["dst"] in compromised else "attempt"
        basis = (
            "corroborated by host-change/beacon evidence on dst"
            if outcome == "accepted"
            else "connection observed; no success evidence"
        )
        streams.setdefault(f"auth-{label}.jsonl", []).append({
            "ts": round(f["first_ts"], 3),
            "src": f["src"],
            "dst": f["dst"],
            "service": svc,
            "dst_port": f["dst_port"],
            "outcome": outcome,
            "basis": basis,
        })

    # --- host EDR events: file writes (fsdiff) + dashboard lifecycle ---------
    epoch = _run_epoch(ev.packets)
    for host, diff in ev.fsdiff.items():
        if not isinstance(diff, dict):
            continue
        ip = ev.ip_of(str(host))
        label = _host_label(ev, ip)
        bucket = streams.setdefault(f"host-{label}.jsonl", [])
        for kind, key in (("file_created", "added"), ("file_modified", "modified")):
            for path in diff.get(key, []) or []:
                bucket.append({
                    "ts": round(epoch, 3) if epoch is not None else None,
                    "host": ip,
                    "event": kind,
                    "path": str(path),
                    "basis": "fsdiff (end-of-run aggregate; ts is run epoch)",
                })
    _project_dashboard_events(ev, streams)

    # --- alerts: canary / answer-key reads ----------------------------------
    # The single highest-signal detection a SOC gets: the crown's canary token
    # surfaced in captured traffic/artifacts, or the ground-truth store was read
    # directly. We raise the alert; we never carry the token value into it.
    alerts: List[Dict[str, Any]] = []
    if ev.key.canary:
        blob = json.dumps(ev.journal) + "\n" + json.dumps(ev.fsdiff) + "\n" + json.dumps(ev.beacons)
        if ev.key.canary in blob:
            alerts.append({
                "ts": epoch,
                "severity": "critical",
                "signal": "canary_token_observed",
                "detail": "crown canary token appeared in observed artifacts/traffic",
            })
    for rec in ev.ak_access:
        alerts.append({
            "ts": rec.get("ts") or rec.get("time"),
            "severity": "critical",
            "signal": "answer_key_access",
            "detail": "ground-truth store was read",
            "source": rec.get("source") or rec.get("src") or rec.get("path"),
        })
    streams["alerts.jsonl"] = alerts

    # Drop empty per-host/auth files so the defender's directory listing is
    # not padded with zero-length noise; always keep the fixed streams.
    fixed = {"netflow.jsonl", "firewall-drops.jsonl", "alerts.jsonl"}
    return {name: recs for name, recs in streams.items() if recs or name in fixed}


def _project_dashboard_events(ev: Evidence, streams: Dict[str, List[Dict[str, Any]]]) -> None:
    """Fold host-observable dashboard lifecycle events into per-host EDR streams.

    The dashboard stream is attacker-emitted, but a subset of it describes facts
    a host sensor would independently see: a script landing on a host and a
    script executing there. We project only those, by their shape, and never the
    event's attacker-authored ``evidence``/``detail`` free-text.
    """
    path = os.path.join(ev.run_dir, "dashboard", "events.jsonl")
    if not os.path.isfile(path):
        return
    observable = {
        "script_uploaded": "process_file_written",
        "script_executed": "process_exec",
    }
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(e, dict):
                continue
            mapped = observable.get(str(e.get("event", "")))
            if mapped is None:
                continue
            host = str(e.get("host", ""))
            if not host:
                continue
            ip = ev.ip_of(host)
            label = _host_label(ev, ip)
            streams.setdefault(f"host-{label}.jsonl", []).append({
                "ts": e.get("ts"),
                "host": ip,
                "event": mapped,
                "basis": "host-observable dashboard lifecycle event",
            })


def synthesize(run_dir: str) -> Dict[str, int]:
    """Load the run's evidence, write every sensor stream, return a manifest.

    The manifest maps each written filename to its record count. The telemetry
    directory is created if absent and existing stream files are overwritten so
    re-running is idempotent.
    """
    ev = load_evidence(run_dir)
    streams = synthesize_from_evidence(ev)
    out_dir = os.path.join(os.path.abspath(run_dir), TELEMETRY_SUBDIR)
    os.makedirs(out_dir, exist_ok=True)
    manifest: Dict[str, int] = {}
    for name, records in streams.items():
        with open(os.path.join(out_dir, name), "w", encoding="utf-8") as fh:
            for rec in records:
                fh.write(json.dumps(rec, sort_keys=True) + "\n")
        manifest[name] = len(records)
    return manifest


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Project a Keystone run into blue sensor telemetry")
    ap.add_argument("--run-dir", default=os.environ.get("KEYSTONE_RUN_DIR"),
                    help="runs/<id> directory (or set KEYSTONE_RUN_DIR)")
    args = ap.parse_args(argv)
    if not args.run_dir:
        print("error: --run-dir or KEYSTONE_RUN_DIR required", file=sys.stderr)
        return 2
    manifest = synthesize(args.run_dir)
    total = sum(manifest.values())
    print(json.dumps({"run_dir": args.run_dir, "streams": manifest, "records": total},
                     indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
