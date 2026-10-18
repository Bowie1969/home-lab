import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


spec = importlib.util.spec_from_file_location(
    "zypheron_bridge", Path(__file__).parent / "scripts" / "zypheron_bridge.py"
)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ZypheronBridgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.run_dir = Path(self.tmp.name) / "run-1"
        dashboard = self.run_dir / "dashboard"
        dashboard.mkdir(parents=True)
        (dashboard / "topology.json").write_text(json.dumps({"nodes": [
            {"id": "g960", "address": "10.99.50.60"},
            {"id": "g911", "address": "10.99.50.11"},
        ]}), encoding="utf-8")
        (dashboard / "events.jsonl").write_text("", encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_scan_is_a_recon_edge_without_raw_audit_details(self):
        event = m.translate_record({
            "timestamp": "2026-10-12T03:04:05Z", "action": "scan_executed",
            "target": "http://10.99.50.11:8080", "tool": "nmap", "success": True,
            "user": "person@example.test", "details": {"token": "do-not-leak"},
        }, self.run_dir, "g960")
        self.assertEqual(event["event"], "recon")
        self.assertEqual(event["node"], "g911")
        self.assertEqual(event["edge"], {
            "src": "g960", "dst": "g911", "traffic_class": "recon", "tool": "nmap",
        })
        self.assertNotIn("do-not-leak", json.dumps(event))
        self.assertNotIn("person@example.test", json.dumps(event))

    def test_exploit_is_activity_not_a_compromise_claim(self):
        event = m.translate_record({
            "action": "exploit_run", "target": "10.99.50.11", "tool": "custom-tool", "success": False,
        }, self.run_dir, "g960")
        self.assertEqual(event["event"], "exploit")
        self.assertEqual(event["edge"]["traffic_class"], "attack")
        self.assertNotEqual(event["event"], "host_compromised")
        self.assertIn("attempted", event["evidence"])

    def test_out_of_topology_target_is_ignored(self):
        event = m.translate_record({
            "action": "scan_executed", "target": "10.99.50.250", "success": True,
        }, self.run_dir, "g960")
        self.assertIsNone(event)

    def test_stream_import_appends_only_eligible_records(self):
        source = Path(self.tmp.name) / "audit.jsonl"
        source.write_text("\n".join([
            json.dumps({"action": "scan_executed", "target": "10.99.50.11", "tool": "nmap", "success": True}),
            json.dumps({"action": "ai_query", "target": "10.99.50.11", "success": True}),
        ]) + "\n", encoding="utf-8")
        self.assertEqual(m.import_stream(source, self.run_dir, "g960", follow=False, from_end=False), 1)
        events = (self.run_dir / "dashboard" / "events.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(events), 1)


if __name__ == "__main__":
    unittest.main()
