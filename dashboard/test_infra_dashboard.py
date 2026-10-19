#!/usr/bin/env python3
"""Tests for infra_dashboard.py — the simple infrastructure truth map.

Pure stdlib, no network: live collectors are exercised only for their
degrade-to-unavailable behaviour (no lab is reachable from CI), and the rich
paths run through the deterministic demo engine.

    python3 -m unittest test_infra_dashboard -v
"""
import json
import threading
import unittest
import urllib.request
from http.client import HTTPConnection

import infra_dashboard as D


class TestClassify(unittest.TestCase):
    def test_auth_port_is_brute_force(self):
        self.assertEqual(D.classify_drop("", "22"), "brute-force")
        self.assertEqual(D.classify_drop("", "445"), "brute-force")

    def test_ids_prefix_wins(self):
        self.assertEqual(D.classify_drop("crown-exfil", "443"), "ids-alert")

    def test_plain_drop_is_recon(self):
        self.assertEqual(D.classify_drop("", "443"), "recon")

    def test_segmentation_violation(self):
        self.assertTrue(D._is_segmentation_violation("10.10.66.5", "10.10.0.2"))
        self.assertTrue(D._is_segmentation_violation("10.10.66.5", "10.50.0.220"))
        self.assertFalse(D._is_segmentation_violation("10.10.66.5", "8.8.8.8"))
        self.assertFalse(D._is_segmentation_violation("192.168.0.9", "10.10.0.2"))


class TestConditionMapping(unittest.TestCase):
    def test_unavailable_source_is_grey(self):
        src = {"status": "unavailable", "label": "X"}
        cond, reasons = D._condition_for("asus", src, [])
        self.assertEqual(cond, "unavailable")
        self.assertTrue(reasons)

    def test_highest_severity_wins(self):
        src = {"status": "live", "label": "hEX"}
        events = [
            {"node": "hex", "type": "recon"},           # warning
            {"node": "hex", "type": "brute-force"},      # alert
            {"node": "hex", "type": "guest-start"},      # activity
        ]
        cond, reasons = D._condition_for("hex", src, events)
        self.assertEqual(cond, "alert")
        self.assertEqual(len(reasons), 3)

    def test_live_no_events_is_healthy(self):
        src = {"status": "live", "label": "Brain"}
        cond, _ = D._condition_for("brain", src, [])
        self.assertEqual(cond, "healthy")


class TestLiveCollectorsDegrade(unittest.TestCase):
    """No lab is reachable here: every collector must return a well-formed
    record, never raise, and never claim 'live' it cannot prove."""

    def test_all_collectors_return_record(self):
        for sid, fn in D.COLLECTORS.items():
            rec = fn()
            self.assertEqual(rec["id"], sid)
            self.assertIn(rec["status"], ("live", "unavailable"))
            self.assertIn("collected_at", rec)
            self.assertIsInstance(rec["events"], list)

    def test_unreachable_source_raises_unreachable_event(self):
        # hEX is behind an SSH jump that cannot resolve in CI -> unavailable.
        rec = D.collect_hex()
        if rec["status"] == "unavailable":
            kinds = {e["type"] for e in rec["events"]}
            self.assertIn("source-unreachable", kinds)


class TestDemoEngine(unittest.TestCase):
    def setUp(self):
        self.engine = D.DemoEngine(seed=7)

    def test_sources_cover_all_five(self):
        s = self.engine.sources()
        self.assertEqual(set(s), {"asus", "hex", "brain", "thisbox", "pi"})

    def test_event_type_variety_over_time(self):
        """Walking the demo clock must surface many *distinct* event types,
        including at least one of each severity band."""
        import time
        seen_types, seen_sev = set(), set()
        for k in range(len(D.DemoEngine.SCRIPT) + 2):
            self.engine.t0 = time.time() - k * 4
            state = D.build_state(self.engine)
            for e in state["events"]:
                seen_types.add(e["type"])
                seen_sev.add(e["severity"])
        self.assertGreaterEqual(len(seen_types), 8, seen_types)
        self.assertTrue({"alert", "warning", "activity"} <= seen_sev, seen_sev)

    def test_pi_goes_unavailable_on_link_down_beat(self):
        import time
        # find the tick whose script beat is the Pi link-down
        idx = [i for i, b in enumerate(D.DemoEngine.SCRIPT) if b[1] == "link-down"][0]
        self.engine.t0 = time.time() - idx * 4
        state = D.build_state(self.engine)
        pi = next(n for n in state["nodes"] if n["id"] == "pi")
        self.assertEqual(pi["condition"], "unavailable")


class TestBuildState(unittest.TestCase):
    def setUp(self):
        self.state = D.build_state(D.DemoEngine(seed=1))

    def test_shape(self):
        for key in ("generated_at", "mode", "summary", "sources", "nodes",
                    "links", "blocked", "events", "legend"):
            self.assertIn(key, self.state)
        self.assertEqual(self.state["mode"], "demo")

    def test_static_infra_present(self):
        ids = {n["id"] for n in self.state["nodes"]}
        self.assertTrue({"wan", "asus", "hex", "brain", "thisbox", "pi"} <= ids)

    def test_guests_hang_off_brain(self):
        guests = [n for n in self.state["nodes"] if n["type"] == "guest"]
        self.assertTrue(guests)
        for g in guests:
            self.assertEqual(g["source"], "brain")
        glinks = [l for l in self.state["links"] if l["source"] == "brain"]
        self.assertEqual(len(glinks), len(guests))

    def test_links_carry_known_traffic_classes(self):
        for link in self.state["links"]:
            self.assertIn(link["traffic"], D.TRAFFIC_CLASSES)

    def test_every_node_has_condition_and_reasons(self):
        for n in self.state["nodes"]:
            self.assertIn(n["condition"],
                          ("healthy", "activity", "warning", "alert", "unavailable", "info"))
            self.assertIsInstance(n["reasons"], list)

    def test_public_source_hides_private_keys(self):
        for s in self.state["sources"].values():
            self.assertFalse(any(k.startswith("_") for k in s))

    def test_blocked_flows_have_endpoints(self):
        for f in self.state["blocked"]:
            self.assertIn("src", f)
            self.assertIn("dst", f)
            self.assertIn("type", f)


class TestHTTP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = D.make_server("127.0.0.1", 0, demo=True, interval=0.2)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def _get(self, path):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}", timeout=5) as r:
            return r.status, dict(r.getheaders()), r.read()

    def test_healthz(self):
        st, _, body = self._get("/healthz")
        self.assertEqual(st, 200)
        self.assertTrue(json.loads(body)["ok"])

    def test_state_is_json_and_uncached(self):
        st, hdr, body = self._get("/api/state")
        self.assertEqual(st, 200)
        self.assertIn("no-store", hdr.get("Cache-Control", ""))
        data = json.loads(body)
        self.assertEqual(data["mode"], "demo")
        self.assertTrue(data["nodes"])

    def test_index_serves_html(self):
        st, hdr, body = self._get("/")
        self.assertEqual(st, 200)
        self.assertIn("text/html", hdr.get("Content-Type", ""))
        self.assertIn(b"Infrastructure Truth Map", body)

    def test_stream_emits_a_snapshot(self):
        conn = HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/api/stream")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        chunk = resp.read(400)   # first event frame
        self.assertIn(b"data:", chunk)
        conn.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
