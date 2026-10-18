#!/usr/bin/env python3
"""emit.py — dashboard telemetry producer for Keystone runs.

Writes the three-part telemetry contract into ``runs/<id>/dashboard/``. The
local, in-repo dashboard (``keystone.dashboard``) renders these files; they also
remain a stable contract for any external viewer:

  topology.json   nodes + edges + zones (snapshot, rewritten in place)
  events.jsonl    append-only, one JSON object per line
  status.json     current run state (rewritten in place)

Event rule: a COMPROMISE-class event (host_compromised, foothold, pivot,
flag_captured, exfil, exfil_started) or an agent_on_host assertion is only
emitted when --evidence is non-empty. Benign events (recon, discovered) may be
emitted freely.

CLI:
    python3 -m keystone.emit --run-dir runs/<id> --host 10.80.10.20 \
        --event foothold --evidence "uploaded webshell, id=... returned uid=33"
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional

RANGE = "keystone"

COMPROMISE_EVENTS = {"foothold", "host_compromised", "pivot", "flag_captured", "exfil",
                     "exfil_started", "impact", "agent_on_host"}
# Script-lifecycle events assert the agent did something script-shaped against a
# specific host. Like compromise events, they refuse to emit without --evidence
# (direct observation: a sidecar path, an upload transcript, an exit code).
SCRIPT_LIFECYCLE_EVENTS = {"script_uploaded", "script_executed"}
EVIDENCE_REQUIRED = COMPROMISE_EVENTS | SCRIPT_LIFECYCLE_EVENTS

# Blue-team events: the DEFENDER acting on the estate. These are assertions the
# responder makes about its own actions, so (unlike compromise events) the
# action record is itself the evidence and --evidence is not required. They are
# a separate dimension from the attacker progress tier: the dashboard paints
# them as a "contained"/"watched" overlay, never as another step up the
# compromise ladder. One blue event name per response action, plus a bare
# detection/alert that marks a host the SOC has merely seen.
DEFENSE_EVENTS = {
    "defense_isolate", "defense_block", "defense_disable_account",
    "defense_revoke", "defense_kill", "defense_quarantine",
    "defense_capture", "defense_preserve", "defense_detect",
}
#: response-action name (blukit.response.ACTIONS) -> dashboard blue event.
ACTION_EVENT = {
    "isolate-host": "defense_isolate",
    "block-ip": "defense_block",
    "block-host": "defense_block",
    "disable-account": "defense_disable_account",
    "revoke-creds": "defense_revoke",
    "terminate-process": "defense_kill",
    "quarantine-file": "defense_quarantine",
    "capture-packet": "defense_capture",
    "preserve-evidence": "defense_preserve",
}

KNOWN_EVENTS = EVIDENCE_REQUIRED | DEFENSE_EVENTS | {
    "recon", "discovered", "lateral", "implant",
    "persist", "c2", "crown_id", "agent_left_host",
    "exfil_stopped", "exfil_completed", "exfil_failed",
    "host_recovered", "script_authored"}


def _dashboard_dir(run_dir: str) -> str:
    d = os.path.join(run_dir, "dashboard")
    os.makedirs(d, exist_ok=True)
    return d


def emit_event(run_dir: str, host: str, event: str, evidence: str = "",
               node: Optional[str] = None, edge: Optional[Dict[str, str]] = None,
               ts: Optional[float] = None) -> Dict[str, Any]:
    """Append one correctly run-stamped event to events.jsonl. Returns the record."""
    event = event.strip().lower()
    if event in EVIDENCE_REQUIRED and not evidence.strip():
        raise ValueError(
            f"refusing to emit '{event}' without --evidence "
            "(direct evidence required)"
        )
    run_id = os.path.basename(os.path.abspath(run_dir).rstrip("/"))
    record: Dict[str, Any] = {
        "run_id": run_id,
        "ts": ts if ts is not None else time.time(),
        "host": host,
        "event": event,
        "evidence": evidence,
    }
    if node:
        record["node"] = node
    if edge:
        record["edge"] = edge
    path = os.path.join(_dashboard_dir(run_dir), "events.jsonl")
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")
    return record


def emit_defense_action(run_dir: str, subject: str, action: str, detail: str = "",
                        outcome: str = "done", actor: str = "blukit",
                        ts: Optional[float] = None) -> Dict[str, Any]:
    """Append one blue-team response action to events.jsonl for the dashboard.

    ``action`` is a response-action name (``isolate-host``, ``block-ip`` …); it
    is mapped to its blue event and carried verbatim in an ``action`` field so
    the feed can name the real action. ``outcome`` records what the enforcer
    reported (``done`` / ``refused`` / ``failed``). The defender's own action
    log is the evidence, so no attacker-evidence gate applies here.
    """
    event = ACTION_EVENT.get(action.strip().lower(), "defense_detect")
    run_id = os.path.basename(os.path.abspath(run_dir).rstrip("/"))
    record: Dict[str, Any] = {
        "run_id": run_id,
        "ts": ts if ts is not None else time.time(),
        "host": subject,
        "event": event,
        "action": action,
        "outcome": outcome,
        "actor": actor,
        "evidence": detail,
    }
    path = os.path.join(_dashboard_dir(run_dir), "events.jsonl")
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")
    return record


def write_topology(run_dir: str, nodes: List[Dict], edges: List[Dict],
                   zones: List[str], segments: Optional[List[Dict]] = None,
                   fabric: Optional[Dict] = None) -> str:
    path = os.path.join(_dashboard_dir(run_dir), "topology.json")
    topology = {"nodes": nodes, "edges": edges, "zones": zones}
    if segments:
        topology["segments"] = segments
    if fabric:
        topology["fabric"] = fabric
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(topology, fh, indent=2)
    return path


def write_status(run_dir: str, state: str = "running", model: str = "",
                 score: Optional[float] = None, flags: Optional[List[str]] = None,
                 started: Optional[str] = None,
                 current_step: Optional[Dict] = None) -> str:
    run_id = os.path.basename(os.path.abspath(run_dir).rstrip("/"))
    status = {
        "run_id": run_id,
        "range": RANGE,
        "state": state,
        "started": started or time.strftime("%Y-%m-%dT%H:%M:%S"),
        "model": model,
        "score": score,
        "flags": flags or [],
        "current_step": current_step or {},
    }
    path = os.path.join(_dashboard_dir(run_dir), "status.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(status, fh, indent=2)
    return path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Keystone dashboard event emitter")
    ap.add_argument("--run-dir", default=os.environ.get("KEYSTONE_RUN_DIR"),
                    help="runs/<id> directory (or set KEYSTONE_RUN_DIR)")
    ap.add_argument("--host", required=True)
    ap.add_argument("--event", required=True)
    ap.add_argument("--evidence", default="")
    ap.add_argument("--node", default=None)
    args = ap.parse_args(argv)

    if not args.run_dir:
        print("error: --run-dir or KEYSTONE_RUN_DIR required", file=sys.stderr)
        return 2
    if args.event.strip().lower() not in KNOWN_EVENTS:
        print(f"warning: '{args.event}' is not a known event name", file=sys.stderr)
    try:
        rec = emit_event(args.run_dir, args.host, args.event, args.evidence, node=args.node)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(rec))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
