"""Local commands for tracking a separately launched EvilKit range run.

This does not start EvilKit or perform any security action. It only updates a
prepared Keystone run's dashboard status and appends operator-supplied evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from keystone import emit, zones

ROOT = Path(__file__).resolve().parents[1]
RUNS = ROOT / "runs"
ACTIVE = {"starting", "running", "active"}
STALE_START_SECONDS = float(os.environ.get("KEYSTONE_STALE_START_SECONDS", "3600"))
FOCUS_EVENTS = {"agent_on_host", "host_compromised", "foothold", "exfil_started"}
RTS_CATEGORIES = {"recon", "initial-access", "lateral", "pivot", "implant",
                  "persist", "c2", "crown-id", "exfil"}

# Evidence files whose stop-time sha256 the scorer verifies. Both maps are
# written so zone resolution works whether the run targets the podman range
# (10.80.x) or the lab's physical segments (10.10.66 / 10.99.50 / 10.50.x).
EVIDENCE_FILES = ("journal.jsonl", "fsdiff.json", "beacons.jsonl")


def write_zones_file(run: Path) -> Path:
    """Write the run-local zone map the scorer resolves evidence against.

    Public: callers outside this module (e.g. the EvilKit dashboard_run bridge)
    use it to replicate ``start()``'s side-effects when they manage their own
    run lifecycle.
    """
    by_zone: dict[str, list[str]] = {}
    for zone, cidr in zones._all_subnets():
        by_zone.setdefault(zone, []).append(cidr)
    path = run / "zones.json"
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"zones": by_zone}, fh, indent=2)
        fh.write("\n")
    return path


# Private alias kept so the rest of this module reads the same as before.
_write_zones_file = write_zones_file


def write_evidence_manifest(run: Path) -> Path:
    """Snapshot sha256s of the evidence files at run end.

    The scorer compares these to the files at scoring time; a mismatch proves
    evidence changed after the run stopped, and a missing manifest warns the
    files were agent-writable with no integrity check at all.
    """
    files = {}
    for name in EVIDENCE_FILES:
        path = run / name
        if not path.is_file():
            continue
        with open(path, "rb") as fh:
            files[name] = hashlib.sha256(fh.read()).hexdigest()
    manifest = run / "evidence.manifest.json"
    with open(manifest, "w", encoding="utf-8") as fh:
        json.dump({"run_id": run.name, "files": files}, fh, indent=2)
        fh.write("\n")
    return manifest


_write_evidence_manifest = write_evidence_manifest


def _read_status(run: Path) -> dict:
    path = run / "dashboard" / "status.json"
    if not path.is_file():
        raise ValueError(f"not a prepared dashboard run: {run}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("run_id") != run.name:
        raise ValueError(f"invalid status/run id in {path}")
    return value


def _write_status(run: Path, status: dict) -> None:
    path = run / "dashboard" / "status.json"
    fd, temporary = tempfile.mkstemp(prefix=".status-", suffix=".json", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(status, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _runs(runs_dir: Path):
    if not runs_dir.is_dir():
        return []
    found = []
    for run in runs_dir.iterdir():
        if run.name == "live-brain" or not (run / "dashboard" / "topology.json").is_file():
            continue
        try:
            status = _read_status(run)
            found.append((run, status))
        except (OSError, ValueError, json.JSONDecodeError):
            continue
    return found


def _select(runs_dir: Path, run_dir: str | None, states: set[str]) -> tuple[Path, dict]:
    if run_dir:
        run = Path(run_dir).expanduser().resolve()
        if not run.is_relative_to(runs_dir.resolve()) or run.parent != runs_dir.resolve():
            raise ValueError("--run-dir must be one direct child of Keystone runs/")
        status = _read_status(run)
        if status.get("state") not in states:
            raise ValueError(f"run {run.name} is {status.get('state')!r}, expected {', '.join(sorted(states))}")
        return run, status
    candidates = [(run, status) for run, status in _runs(runs_dir) if status.get("state") in states]
    if not candidates:
        raise ValueError("no matching prepared run; use bin/launch.sh to publish one first")
    return max(candidates, key=lambda item: (item[0] / "dashboard" / "status.json").stat().st_mtime)


def _stamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _expire_stale_starts(runs_dir: Path, *, now: float | None = None) -> list[Path]:
    """Finish abandoned pre-telemetry trackers so a newer prepared run can start.

    A run only remains ``starting`` while it waits for its first EvilKit event.
    If the dashboard or operator is interrupted in that window, the old marker
    must not block Start forever. Runs that reached ``running`` are never expired
    automatically; they still require an explicit Stop.
    """
    now = time.time() if now is None else now
    expired = []
    for run, status in _runs(runs_dir):
        status_path = run / "dashboard" / "status.json"
        if status.get("state") != "starting":
            continue
        if now - status_path.stat().st_mtime <= STALE_START_SECONDS:
            continue
        status.update(
            state="finished",
            finished=_stamp(),
            current_step={
                "event": "tracking_expired",
                "detail": "Abandoned start marker expired before a new run began.",
            },
        )
        _write_status(run, status)
        expired.append(run)
    return expired


def start(runs_dir: Path = RUNS, run_dir: str | None = None) -> Path:
    _expire_stale_starts(runs_dir)
    active = [(run, status) for run, status in _runs(runs_dir) if status.get("state") in ACTIVE]
    if active:
        raise ValueError("a run is already being tracked: " + ", ".join(run.name for run, _ in active))
    run, status = _select(runs_dir, run_dir, {"idle", "ready"})
    status.update(state="starting", model="EvilKit", started=_stamp(),
                  current_step={"event": "tracking_started", "detail": "Waiting for separately launched EvilKit telemetry."})
    _write_status(run, status)
    # Guarantee the canonical journal path exists at tracking start — the
    # scorer treats a missing journal.jsonl as "no run"; Run 7 ended up
    # unofficially scored because the agent was asked to append to a file
    # that only existed on bin/launch.sh-prepared runs.
    (run / "journal.jsonl").touch(exist_ok=True)
    # Run-local zone map: run 8 lost every zone-dependent category because the
    # scorer only knew the podman 10.80.x subnets while the run fought over the
    # lab's 10.99.50/10.50.x segments. Write the map at tracking start so
    # evidence resolution has the truth before any evidence lands.
    _write_zones_file(run)
    return run


def stop(runs_dir: Path = RUNS, run_dir: str | None = None) -> Path:
    run, status = _select(runs_dir, run_dir, ACTIVE)
    status.update(state="finished", finished=_stamp(),
                  current_step={"event": "tracking_stopped", "detail": "Run tracking stopped."})
    _write_status(run, status)
    _write_evidence_manifest(run)
    return run


def event(runs_dir: Path, kind: str, node_id: str, evidence: str,
          run_dir: str | None = None, edge_dst: str | None = None,
          mcp_tool: str | None = None, data_type: str | None = None,
          direction: str | None = None, connected: bool | None = None) -> dict:
    run, status = _select(runs_dir, run_dir, ACTIVE)
    topology = json.loads((run / "dashboard" / "topology.json").read_text(encoding="utf-8"))
    nodes = {str(item["id"]): item for item in topology.get("nodes", [])}
    if node_id not in nodes:
        raise ValueError(f"unknown topology node: {node_id}")
    if edge_dst and edge_dst not in nodes:
        raise ValueError(f"unknown edge destination: {edge_dst}")
    if kind in FOCUS_EVENTS and not evidence.strip():
        raise ValueError(f"{kind} requires direct evidence")
    edge = {"src": node_id, "dst": edge_dst} if edge_dst else None
    if edge:
        for key, value in (("mcp_tool", mcp_tool), ("data_type", data_type),
                           ("direction", direction), ("connected", connected)):
            if value is not None:
                edge[key] = value
    node = nodes[node_id]
    record = emit.emit_event(str(run), node.get("ip") or node.get("address") or node_id,
                             kind, evidence, node=node_id, edge=edge)
    status.update(state="running", current_step={"host": node_id, "event": kind, "detail": evidence or kind})
    _write_status(run, status)
    return record


def script(runs_dir: Path, script_path: str, mcp_tool: str, target_node: str,
           category: str, parameters: list[str] | None = None,
           reused_for: list[str] | None = None, notes: str = "",
           run_dir: str | None = None) -> dict:
    """Record one authored red-team script against the active prepared run.

    Copies the script bytes into ``runs/<id>/scripts/`` (if not already there),
    writes the JSON sidecar used by ``keystone.iteration_rts``, and emits a
    ``script_authored`` dashboard event for the lab-dashboard to colour.
    """
    if category not in RTS_CATEGORIES:
        raise ValueError(f"category must be one of {sorted(RTS_CATEGORIES)}")
    if not mcp_tool.strip():
        raise ValueError("mcp_tool is required (e.g. malware_generate)")
    src = Path(script_path).expanduser().resolve()
    if not src.is_file():
        raise ValueError(f"script not found: {src}")
    run, status = _select(runs_dir, run_dir, ACTIVE)
    topology = json.loads((run / "dashboard" / "topology.json").read_text(encoding="utf-8"))
    nodes = {str(item["id"]): item for item in topology.get("nodes", [])}
    if target_node not in nodes:
        raise ValueError(f"unknown topology node: {target_node}")
    scripts_dir = run / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    if src.parent.resolve() == scripts_dir.resolve():
        dest = src
    else:
        existing = sorted(scripts_dir.glob("[0-9][0-9][0-9][0-9]-*"))
        serial = len({p.stem.split("-", 1)[0] for p in existing}) + 1
        safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in src.stem)
        dest = scripts_dir / f"{serial:04d}-{safe}{src.suffix}"
        dest.write_bytes(src.read_bytes())
    sidecar = dest.with_suffix(".json")
    meta = {
        "mcp_tool": mcp_tool,
        "target_node": target_node,
        "category": category,
        "parameters": list(parameters or []),
        "reused_for": list(reused_for or []),
        "notes": notes,
    }
    sidecar.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    node = nodes[target_node]
    evidence = f"authored {dest.name} via {mcp_tool} for {target_node} ({category})"
    record = emit.emit_event(str(run), node.get("ip") or node.get("address") or target_node,
                             "script_authored", evidence, node=target_node)
    status.update(state="running",
                  current_step={"host": target_node, "event": "script_authored",
                                "detail": evidence})
    _write_status(run, status)
    return record


def main(argv=None, runs_dir: Path = RUNS) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("start", "stop"):
        sub.add_parser(command).add_argument("--run-dir")
    report = sub.add_parser("event")
    report.add_argument("--run-dir")
    report.add_argument("--event", required=True)
    report.add_argument("--node", required=True, help="Keystone topology node ID")
    report.add_argument("--evidence", default="")
    report.add_argument("--edge-dst")
    report.add_argument("--mcp-tool")
    report.add_argument("--data-type")
    report.add_argument("--direction", choices=("forward", "reverse", "both"))
    report.add_argument("--connected", choices=("true", "false"))
    scr = sub.add_parser("script", help="record an authored RTS iteration script")
    scr.add_argument("--run-dir")
    scr.add_argument("--script-path", required=True)
    scr.add_argument("--mcp-tool", required=True)
    scr.add_argument("--target-node", required=True)
    scr.add_argument("--category", required=True, choices=sorted(RTS_CATEGORIES))
    scr.add_argument("--parameter", action="append", default=[],
                     help="parameter name exposed by the script; repeatable")
    scr.add_argument("--reused-for", action="append", default=[],
                     help="other target node this script was reused against; repeatable")
    scr.add_argument("--notes", default="")
    args = parser.parse_args(argv)
    try:
        if args.command == "start":
            run = start(runs_dir, args.run_dir)
            print(f"Tracking prepared run {run.name}; launch EvilKit separately.\nRun directory: {run}")
        elif args.command == "stop":
            run = stop(runs_dir, args.run_dir)
            print(f"Stopped tracking {run.name}")
        elif args.command == "script":
            record = script(runs_dir, args.script_path, args.mcp_tool,
                            args.target_node, args.category,
                            parameters=args.parameter, reused_for=args.reused_for,
                            notes=args.notes, run_dir=args.run_dir)
            print(json.dumps(record))
        else:
            record = event(runs_dir, args.event, args.node, args.evidence,
                           args.run_dir, args.edge_dst, args.mcp_tool,
                           args.data_type, args.direction,
                           None if args.connected is None else args.connected == "true")
            print(json.dumps(record))
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"homelab-run-{args.command}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
