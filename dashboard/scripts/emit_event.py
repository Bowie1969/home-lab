#!/usr/bin/env python3
"""Append one compliant event to a keystone-range run's dashboard/events.jsonl.

This is a convenience helper for whoever writes the keystone-range producer side —
it is not imported or required by server.py, which only ever reads these files.

Usage:
  python3 emit_event.py --run-dir ~/Projects/keystone-range/runs/<run_id> \\
      --host dmz-web01 --event node_solved --node dmz-web01 \\
      --evidence "RCE achieved; webshell dropped."

  python3 emit_event.py --run-dir ... --host operator --event edge_used \\
      --edge-src dmz-router --edge-dst corp-router --evidence "Pivot traffic crossing."

  python3 emit_event.py --run-dir ... --host dmz-web01 --event flag_captured \\
      --flag dmz-foothold --evidence "FLAG dmz-foothold captured."

  python3 emit_event.py --run-dir ... --host 10.80.10.22 --node edge-upload \\
      --event agent_on_host --evidence "EvilKit action running on this host"
  python3 emit_event.py --run-dir ... --host 10.80.10.22 --node edge-upload \\
      --event host_compromised --evidence "uid=0 confirmed"
  python3 emit_event.py --run-dir ... --host 10.80.30.20 --node vault-keystone \\
      --event exfil_started --evidence "transfer started"

The three prominent EvilKit indicators use these events with --node set to the
topology node id: agent_on_host (red pulse), host_compromised (solid red),
exfil_started (yellow pulse). Emit agent_left_host and exfil_completed (or
exfil_stopped) when those activities end. Evidence should identify the
observed activity, compromise, or transfer; a scan alone is not a compromise.

Recognised --event values that move a node/edge's colour on the dashboard:
  node_discovered, node_reachable, node_in_progress, node_solved, node_data_read
  edge_discovered, edge_used
Any other --event string is still appended and shown in the live event stream,
it just won't recolour anything. --flag tallies into status.json's flags/score
if you also keep status.json's "flags" list in sync (this helper does not touch
status.json or topology.json — only events.jsonl).
"""
import argparse
import json
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run-dir", required=True, help="Path to runs/<run_id> (dashboard/ is created under it)")
    parser.add_argument("--run-id", help="Defaults to the run-dir's basename")
    parser.add_argument("--host", required=True)
    parser.add_argument("--event", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--node", help="Node id this event updates")
    parser.add_argument("--edge-src", help="Edge source node id (pairs with --edge-dst)")
    parser.add_argument("--edge-dst", help="Edge destination node id (pairs with --edge-src)")
    parser.add_argument("--flag", help="Flag id, for event=flag_captured")
    args = parser.parse_args()

    run_dir = Path(args.run_dir).expanduser()
    dashboard = run_dir / "dashboard"
    dashboard.mkdir(parents=True, exist_ok=True)

    record = {
        "run_id": args.run_id or run_dir.name,
        "ts": time.time(),
        "host": args.host,
        "event": args.event,
        "evidence": args.evidence,
    }
    if args.node:
        record["node"] = args.node
    if args.edge_src and args.edge_dst:
        record["edge"] = {"src": args.edge_src, "dst": args.edge_dst}
    if args.flag:
        record["flag"] = args.flag

    with (dashboard / "events.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")
    print(json.dumps(record))


if __name__ == "__main__":
    main()
