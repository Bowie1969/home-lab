#!/usr/bin/env python3
"""Tests for keystone_flow_events.py.

Proves the two halves of the contract:

  1. flow JSON (both 10.80.x logical and 10.50.0.x real addresses) + the run's
     topology map to edge_used events with the right node ids and traffic_class.
  2. Feeding those events through server.py's real render path (RangeWatcher
     snapshot) draws the coloured, auto-expiring edges.

Run from anywhere:
  python3 scripts/test_keystone_flow_events.py
  python3 -m unittest scripts.test_keystone_flow_events   (from lab-dashboard/)
"""
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent          # lab-dashboard/scripts
LAB_DASHBOARD = HERE.parent                      # lab-dashboard/
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(LAB_DASHBOARD))

import keystone_flow_events as kfe          # noqa: E402
import server                               # noqa: E402  (does not start a server on import)


SAMPLE_TOPOLOGY = {
    "zones": ["attacker", "dmz", "corp", "data"],
    "nodes": [
        {"id": "attacker", "label": "operator", "ip": "10.80.0.10", "real_ip": None},
        {"id": "cache-open", "label": "cache-open", "ip": "10.80.10.20", "real_ip": None},
        {"id": "ks-files01", "label": "ks-files01", "ip": "10.80.20.23",
         "real_ip": "10.50.0.12 (real, on brain bridge vmbr50)"},
        {"id": "ks-intranet01", "label": "ks-intranet01", "ip": "10.80.20.24",
         "real_ip": "10.50.0.13 (real, on brain bridge vmbr50)"},
        {"id": "vault-keystone", "label": "vault-keystone", "ip": "10.80.30.20",
         "real_ip": "10.50.0.14 (real, on brain bridge vmbr50, DATA side)"},
    ],
    "edges": [
        {"src": "attacker", "dst": "cache-open", "kind": "network", "state": "unknown"},
    ],
}

# Four distinct (src,dst) pairs, one per interesting traffic class; plus a
# ``normal`` flow and a 10.99.50.x flow that must both be skipped.
SAMPLE_FLOWS = [
    # logical podman-side recon (10.80.x)
    {"src": "10.80.0.10", "dst": "10.80.10.20", "dport": 8080, "proto": "tcp",
     "class": "recon", "pkts": 3, "bytes": 0},
    # the task's example: real brain-side attack, 10.50.0.14 -> 10.50.0.13
    {"src": "10.50.0.14", "dst": "10.50.0.13", "dport": 80, "proto": "tcp",
     "class": "attack", "pkts": 10, "bytes": 1500},
    # logical tunnel ks-intranet01 -> vault-keystone
    {"src": "10.80.20.24", "dst": "10.80.30.20", "dport": 445, "proto": "tcp",
     "class": "tunnel", "pkts": 5, "bytes": 200},
    # data exfil via real IPs ks-files01 -> vault-keystone
    {"src": "10.50.0.12", "dst": "10.50.0.14", "dport": 443, "proto": "tcp",
     "class": "data", "pkts": 4, "bytes": 900},
    # normal -> not a live edge
    {"src": "10.80.10.20", "dst": "10.80.20.23", "dport": 80, "proto": "tcp",
     "class": "normal", "pkts": 2, "bytes": 10},
    # 10.99.50.x is a brain-estate guest, not in the keystone topology -> skipped
    {"src": "10.99.50.11", "dst": "10.50.0.14", "dport": 8080, "proto": "tcp",
     "class": "recon", "pkts": 2, "bytes": 0},
]

RUN_ID = "test-run"


class TestMapping(unittest.TestCase):
    def test_ip_map_resolves_logical_and_real_to_same_node(self):
        ip2node = kfe.load_ip_map(SAMPLE_TOPOLOGY)
        # logical
        self.assertEqual(ip2node["10.80.30.20"], "vault-keystone")
        self.assertEqual(ip2node["10.80.20.24"], "ks-intranet01")
        # real (suffix stripped)
        self.assertEqual(ip2node["10.50.0.14"], "vault-keystone")
        self.assertEqual(ip2node["10.50.0.13"], "ks-intranet01")
        self.assertEqual(ip2node["10.50.0.12"], "ks-files01")

    def test_flow_to_event_node_ids_and_class(self):
        ip2node = kfe.load_ip_map(SAMPLE_TOPOLOGY)
        now = time.time()

        recon = kfe.flow_to_event(SAMPLE_FLOWS[0], ip2node, RUN_ID, now)
        self.assertEqual(recon["edge"]["src"], "attacker")
        self.assertEqual(recon["edge"]["dst"], "cache-open")
        self.assertEqual(recon["edge"]["traffic_class"], "recon")
        self.assertEqual(recon["node"], "cache-open")
        self.assertEqual(recon["event"], "recon")

        attack = kfe.flow_to_event(SAMPLE_FLOWS[1], ip2node, RUN_ID, now)
        self.assertEqual(attack["edge"]["src"], "vault-keystone")
        self.assertEqual(attack["edge"]["dst"], "ks-intranet01")
        self.assertEqual(attack["edge"]["traffic_class"], "attack")
        self.assertEqual(attack["node"], "ks-intranet01")
        self.assertEqual(attack["host"], "10.50.0.13")
        self.assertEqual(attack["event"], "exploit")

        tunnel = kfe.flow_to_event(SAMPLE_FLOWS[2], ip2node, RUN_ID, now)
        self.assertEqual((tunnel["edge"]["src"], tunnel["edge"]["dst"]),
                         ("ks-intranet01", "vault-keystone"))
        self.assertEqual(tunnel["edge"]["traffic_class"], "tunnel")
        self.assertEqual(tunnel["event"], "exploit")

        data = kfe.flow_to_event(SAMPLE_FLOWS[3], ip2node, RUN_ID, now)
        self.assertEqual((data["edge"]["src"], data["edge"]["dst"]),
                         ("ks-files01", "vault-keystone"))
        self.assertEqual(data["edge"]["traffic_class"], "data")
        self.assertEqual(data["event"], "exploit")

        for ev in (recon, attack, tunnel, data):
            self.assertEqual(ev["status"], "running")
            self.assertEqual(ev["edge"]["direction"], "forward")
            self.assertNotIn("mcp_tool", ev["edge"])  # flows carry no MCP tool

    def test_normal_and_unresolvable_skipped(self):
        ip2node = kfe.load_ip_map(SAMPLE_TOPOLOGY)
        now = time.time()
        self.assertIsNone(kfe.flow_to_event(SAMPLE_FLOWS[4], ip2node, RUN_ID, now))
        self.assertIsNone(kfe.flow_to_event(SAMPLE_FLOWS[5], ip2node, RUN_ID, now))
        self.assertIsNone(kfe.flow_to_event({}, ip2node, RUN_ID, now))


class TestBridge(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="keystone-flow-events-"))
        self.run_dir = self.tmp / RUN_ID
        dash = self.run_dir / "dashboard"
        dash.mkdir(parents=True)
        (dash / "topology.json").write_text(json.dumps(SAMPLE_TOPOLOGY), encoding="utf-8")
        self.bridge = kfe.FlowBridge(self.run_dir, "test-model", [])

    def test_emit_dedup_rate_limits_per_pair(self):
        flow = SAMPLE_FLOWS[1]   # attack, 10.50.0.14 -> 10.50.0.13
        t = time.time()
        self.assertIsNotNone(self.bridge.emit_flow(flow, t))
        self.assertIsNone(self.bridge.emit_flow(flow, t + 0.5))       # within 1s
        self.assertIsNotNone(self.bridge.emit_flow(flow, t + 1.1))    # after 1s
        lines = (self.run_dir / "dashboard" / "events.jsonl").read_text().strip().splitlines()
        self.assertEqual(len(lines), 2)

    def test_bridge_writes_status_running(self):
        self.bridge.write_status(force=True)
        status = json.loads((self.run_dir / "dashboard" / "status.json").read_text())
        self.assertEqual(status["state"], "running")
        self.assertEqual(status["range"], "keystone")
        self.assertEqual(status["run_id"], RUN_ID)

    def test_flips_finished_after_idle(self):
        from unittest import mock
        flow = SAMPLE_FLOWS[1]

        class FakeSource:
            def __init__(self):
                self.calls = 0
            def read(self):
                self.calls += 1
                return [flow] if self.calls == 1 else []

        self.bridge.sources = [FakeSource()]
        clock = {"now": 1000.0}

        with mock.patch.object(kfe.time, "time", side_effect=lambda: clock["now"]):
            self.bridge.poll_once()               # sees a flow -> running
            self.assertEqual(self.bridge._state, "running")
            clock["now"] = 1002.0
            self.bridge.poll_once()               # 2s idle, under 45s -> still running
            self.assertEqual(self.bridge._state, "running")
            clock["now"] = 1000.0 + kfe.IDLE_FINISH_SECS + 1
            self.bridge.poll_once()               # >45s idle -> finished
            self.assertEqual(self.bridge._state, "finished")

        status = json.loads((self.run_dir / "dashboard" / "status.json").read_text())
        self.assertEqual(status["state"], "finished")


class TestRenderProof(unittest.TestCase):
    def test_server_snapshot_renders_edges(self):
        now = time.time()
        ip2node = kfe.load_ip_map(SAMPLE_TOPOLOGY)
        events = [kfe.flow_to_event(f, ip2node, RUN_ID, now) for f in SAMPLE_FLOWS[:4]]
        self.assertTrue(all(events))

        # 1) The named server function reports each pair with a colour + active.
        details = server.edge_event_details(events, now=now + 1.0)
        want = {
            ("attacker", "cache-open"): "recon",
            ("vault-keystone", "ks-intranet01"): "attack",
            ("ks-intranet01", "vault-keystone"): "tunnel",
            ("ks-files01", "vault-keystone"): "data",
        }
        self.assertEqual(set(details), set(want))
        for pair, cls in want.items():
            self.assertEqual(details[pair]["kind"], cls)
            self.assertTrue(server.traffic_is_connected(details[pair]))

        # 2) Full snapshot through RangeWatcher (the real collect() path).
        runs_dir = self._write_run(events)
        old_runs = server.RUNS_DIR
        server.RUNS_DIR = runs_dir
        try:
            watcher = server.RangeWatcher()
            watcher.collect()
            sample = watcher.sample
        finally:
            server.RUNS_DIR = old_runs

        self.assertEqual(sample["mode"], "live")
        rendered = {(e["src"], e["dst"]): e for e in sample["edges"]}
        for pair, cls in want.items():
            self.assertIn(pair, rendered)
            edge = rendered[pair]
            self.assertEqual(edge.get("kind"), cls)
            self.assertTrue(server.traffic_is_connected(edge))
        # the attack victim is ringed
        under_attack = {n["id"] for n in sample["nodes"] if n.get("under_attack")}
        self.assertIn("ks-intranet01", under_attack)

        # human-readable proof for the test log
        print("\n=== server snapshot rendered edges ===")
        for pair, cls in sorted(want.items(), key=lambda kv: kv[1]):
            edge = rendered[pair]
            print(f"  {pair[0]:<15} -> {pair[1]:<15} kind={cls:<6} connected={edge.get('connected')}")

    def _write_run(self, events) -> Path:
        runs = Path(tempfile.mkdtemp(prefix="keystone-render-runs-"))
        dash = runs / RUN_ID / "dashboard"
        dash.mkdir(parents=True)
        (dash / "topology.json").write_text(json.dumps(SAMPLE_TOPOLOGY), encoding="utf-8")
        (dash / "status.json").write_text(json.dumps({
            "run_id": RUN_ID, "range": "keystone", "state": "running",
            "started": "2026-10-13T00:00:00", "model": "test", "score": None,
            "flags": [], "current_step": {"detail": "test"},
        }), encoding="utf-8")
        (dash / "events.jsonl").write_text(
            "".join(json.dumps(e, separators=(",", ":")) + "\n" for e in events),
            encoding="utf-8")
        return runs


if __name__ == "__main__":
    unittest.main(verbosity=2)
