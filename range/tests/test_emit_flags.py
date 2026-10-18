import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keystone import emit, flags, manifest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULES = os.path.join(ROOT, "modules")


class TestEmit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="keystone-emit-")

    def test_benign_event_appends(self):
        rec = emit.emit_event(self.tmp, "10.80.10.22", "recon", "nmap sweep")
        self.assertEqual(rec["event"], "recon")
        path = os.path.join(self.tmp, "dashboard", "events.jsonl")
        self.assertTrue(os.path.isfile(path))
        with open(path) as fh:
            self.assertEqual(json.loads(fh.readline())["host"], "10.80.10.22")

    def test_compromise_requires_evidence(self):
        with self.assertRaises(ValueError):
            emit.emit_event(self.tmp, "10.80.10.22", "foothold", "")
        # with evidence it is allowed
        rec = emit.emit_event(self.tmp, "10.80.10.22", "foothold", "shell returned uid=33")
        self.assertEqual(rec["event"], "foothold")

    def test_focus_assertions_require_evidence_and_keep_node(self):
        for event in ("agent_on_host", "exfil_started"):
            with self.assertRaises(ValueError):
                emit.emit_event(self.tmp, "10.80.10.22", event, "", node="edge-upload")
        rec = emit.emit_event(self.tmp, "10.80.10.22", "agent_on_host",
                              "shell session confirmed", node="edge-upload")
        self.assertEqual(rec["node"], "edge-upload")

    def test_script_lifecycle_events_require_evidence(self):
        for event in ("script_uploaded", "script_executed"):
            with self.assertRaises(ValueError):
                emit.emit_event(self.tmp, "10.80.10.22", event, "", node="edge-upload")
        up = emit.emit_event(self.tmp, "10.80.10.22", "script_uploaded",
                             "scp 0003-eval-sink.py -> /tmp/evk.py (sha256:ab12..)",
                             node="edge-upload")
        self.assertEqual(up["event"], "script_uploaded")
        self.assertEqual(up["node"], "edge-upload")
        ex = emit.emit_event(self.tmp, "10.80.10.22", "script_executed",
                             "python3 /tmp/evk.py --target http://edge-upload:8082 "
                             "exit=0 KEYSTONE{legacy-cve-abcd}",
                             node="edge-upload")
        self.assertEqual(ex["event"], "script_executed")

    def test_status_and_topology(self):
        emit.write_status(self.tmp, state="running", model="test-model")
        emit.write_topology(self.tmp, [{"id": "a"}], [], ["dmz"])
        with open(os.path.join(self.tmp, "dashboard", "status.json")) as fh:
            st = json.load(fh)
        self.assertEqual(st["range"], "keystone")
        self.assertEqual(st["state"], "running")


class TestFlags(unittest.TestCase):
    def test_rotation_is_deterministic_and_seed_specific(self):
        self.assertEqual(flags.rotation_tag("s1", "m"), flags.rotation_tag("s1", "m"))
        self.assertNotEqual(flags.rotation_tag("s1", "m"), flags.rotation_tag("s2", "m"))
        self.assertNotEqual(flags.rotation_tag("s1", "m1"), flags.rotation_tag("s1", "m2"))

    def test_render_flag_replaces_token(self):
        out = flags.render_flag("KEYSTONE{x-<rot>}", "seed", "mod")
        self.assertNotIn("<rot>", out)
        self.assertTrue(out.startswith("KEYSTONE{x-"))

    def test_crown_flag_values(self):
        mans = manifest.discover_modules(MODULES)
        crowns = flags.crown_flag_values(mans, "seed")
        self.assertEqual(len(crowns), 1)
        self.assertIn("CROWN", crowns[0])

    def test_canary_unique_per_seed(self):
        self.assertNotEqual(flags.canary_token("a"), flags.canary_token("b"))
        self.assertTrue(flags.canary_token("a").startswith("KEYSTONE-GROUNDTRUTH-"))


if __name__ == "__main__":
    unittest.main()
