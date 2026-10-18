#!/usr/bin/env python3
"""Mirror Zypheron's local audit records into a Keystone dashboard run.

This is a deliberately passive adapter: it reads an existing Zypheron JSONL audit
file and appends compact visualisation events. It never launches Zypheron, opens
network connections, changes scope, or copies audit identities/details into the
dashboard. A scan or exploit *attempt* is not represented as a compromise.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path


MAX_RECORD_BYTES = 128 * 1024
POLL_SECONDS = 0.5
IP_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")


def default_source() -> Path:
    """Zypheron's documented daily audit location for the current local date."""
    config = Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config")))
    return config / "zypheron" / "audit" / f"audit_{datetime.now().date().isoformat()}.jsonl"


def first_ipv4(value: object) -> str | None:
    """Return the first valid IPv4 in a target/address string, if any."""
    for candidate in IP_RE.findall(str(value or "")):
        try:
            return str(ipaddress.IPv4Address(candidate))
        except ipaddress.AddressValueError:
            continue
    return None


def load_nodes(run_dir: Path) -> tuple[set[str], dict[str, str]]:
    """Return topology node IDs and the lab IPv4 -> node mapping."""
    topology_path = run_dir / "dashboard" / "topology.json"
    if not topology_path.is_file():
        raise ValueError(f"No topology.json at {topology_path}")
    try:
        topology = json.loads(topology_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ValueError(f"Cannot read topology at {topology_path}: {error}") from error
    if not isinstance(topology, dict):
        raise ValueError("Topology must be a JSON object")

    ids: set[str] = set()
    by_ip: dict[str, str] = {}
    for node in topology.get("nodes", []):
        if not isinstance(node, dict) or not node.get("id"):
            continue
        node_id = str(node["id"])
        ids.add(node_id)
        for field in ("address", "ip"):
            value = node.get(field)
            for match in IP_RE.findall(str(value or "")):
                try:
                    by_ip[str(ipaddress.IPv4Address(match))] = node_id
                except ipaddress.AddressValueError:
                    continue
    return ids, by_ip


def classify_action(action: object) -> tuple[str, str] | None:
    """Map only known security-operation audit actions to dashboard activity."""
    text = str(action or "").strip().lower()
    if any(word in text for word in ("exploit", "foothold", "pivot", "lateral")):
        return "exploit", "attack"
    if any(word in text for word in ("scan", "recon", "enumerat", "discover")):
        return "recon", "recon"
    return None


def safe_label(value: object, fallback: str = "zypheron") -> str:
    """Keep an optional UI label short and free of arbitrary log content."""
    label = re.sub(r"[^A-Za-z0-9_.:/+ -]", "", str(value or "")).strip()
    return label[:64] or fallback


def audit_timestamp(value: object) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp()
        except ValueError:
            pass
    return time.time()


def translate_record(record: object, run_dir: Path, source_node: str) -> dict | None:
    """Convert one Zypheron audit record, or ignore it when it is not drawable."""
    if not isinstance(record, dict):
        return None
    activity = classify_action(record.get("action"))
    target_ip = first_ipv4(record.get("target"))
    if activity is None or target_ip is None:
        return None

    node_ids, node_by_ip = load_nodes(run_dir)
    if source_node not in node_ids:
        raise ValueError(f"Source node {source_node!r} is not in this run's topology")
    target_node = node_by_ip.get(target_ip)
    if target_node is None or target_node == source_node:
        # Do not make a dashboard claim for an address outside the selected lab map.
        return None

    event, traffic_class = activity
    outcome = "completed" if record.get("success") is True else "attempted"
    return {
        "run_id": run_dir.name,
        "ts": audit_timestamp(record.get("timestamp")),
        "host": target_ip,
        "node": target_node,
        "event": event,
        "evidence": f"Zypheron {outcome} {traffic_class} activity against {target_ip}.",
        "edge": {
            "src": source_node,
            "dst": target_node,
            "traffic_class": traffic_class,
            "tool": safe_label(record.get("tool")),
        },
    }


def append_event(run_dir: Path, event: dict) -> None:
    dashboard = run_dir / "dashboard"
    if not dashboard.is_dir():
        raise ValueError(f"No dashboard directory at {dashboard}")
    with (dashboard / "events.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, separators=(",", ":")) + "\n")


def process_line(line: str, run_dir: Path, source_node: str) -> dict | None:
    if not line.strip() or len(line.encode("utf-8")) > MAX_RECORD_BYTES:
        return None
    try:
        record = json.loads(line)
    except ValueError:
        return None
    return translate_record(record, run_dir, source_node)


def import_stream(source: Path, run_dir: Path, source_node: str, *, follow: bool, from_end: bool) -> int:
    """Read a JSONL file; follow rotation safely when requested."""
    emitted = 0
    position_at_end = from_end
    inode: tuple[int, int] | None = None
    handle = None
    try:
        while True:
            try:
                stat = source.stat()
            except FileNotFoundError:
                if not follow:
                    raise ValueError(f"Audit source does not exist: {source}")
                time.sleep(POLL_SECONDS)
                continue
            signature = (stat.st_dev, stat.st_ino)
            if handle is None or signature != inode or stat.st_size < handle.tell():
                if handle is not None:
                    handle.close()
                handle = source.open(encoding="utf-8", errors="replace")
                inode = signature
                if position_at_end:
                    handle.seek(0, os.SEEK_END)
                    position_at_end = False

            line = handle.readline()
            if not line:
                if not follow:
                    break
                time.sleep(POLL_SECONDS)
                continue
            event = process_line(line, run_dir, source_node)
            if event is not None:
                append_event(run_dir, event)
                emitted += 1
                print(json.dumps(event, separators=(",", ":")), flush=True)
    finally:
        if handle is not None:
            handle.close()
    return emitted


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, help="Keystone runs/<run_id> directory to receive events")
    parser.add_argument("--source-node", required=True, help="Topology node ID where Zypheron is operating")
    parser.add_argument("--source", type=Path, default=default_source(), help="Zypheron audit JSONL (default: today's local audit)")
    parser.add_argument("--follow", action="store_true", help="Wait for new records and handle daily-log rotation")
    parser.add_argument("--from-end", action="store_true", help="With --follow, ignore records already present at startup")
    args = parser.parse_args()
    try:
        emitted = import_stream(args.source.expanduser(), Path(args.run_dir).expanduser(), args.source_node,
                                follow=args.follow, from_end=args.from_end)
    except ValueError as error:
        parser.error(str(error))
    if not args.follow:
        print(f"Imported {emitted} eligible Zypheron audit event(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
