"""Tests for the local dashboard (keystone.dashboard). Pure stdlib."""
import json
import re
import threading
import unittest
import urllib.request
import urllib.error
from http.server import SimpleHTTPRequestHandler
from pathlib import Path
from tempfile import TemporaryDirectory

from keystone import dashboard


def _write_run(root: Path, run_id: str = "run-x", with_score: bool = False) -> Path:
    run = root / run_id
    dash = run / "dashboard"
    dash.mkdir(parents=True)
    (dash / "topology.json").write_text(json.dumps({
        "nodes": [
            {"id": "attacker", "label": "operator", "zone": "attacker", "ip": "10.80.0.10"},
            {"id": "edge-upload", "label": "edge-upload", "zone": "dmz",
             "ip": "10.80.10.22", "technique_class": "web-rce"},
            {"id": "vault", "label": "vault", "zone": "data", "ip": "10.80.30.9"},
        ],
        "edges": [
            {"src": "attacker", "dst": "edge-upload", "kind": "network", "state": "discovered"},
            {"src": "edge-upload", "dst": "vault", "kind": "network", "state": "unknown"},
        ],
        "zones": ["attacker", "dmz", "corp", "data"],
    }))
    (dash / "events.jsonl").write_text(
        json.dumps({"run_id": run_id, "ts": 1.0, "host": "10.80.10.22",
                    "event": "node_reachable", "node": "edge-upload",
                    "evidence": "service healthy"}) + "\n" +
        json.dumps({"run_id": run_id, "ts": 2.0, "host": "10.80.10.22",
                    "event": "foothold", "node": "edge-upload",
                    "evidence": "webshell uid=33"}) + "\n"
    )
    (dash / "status.json").write_text(json.dumps({
        "run_id": run_id, "range": "keystone", "state": "running",
        "model": "test-model", "started": "2026-01-01T00:00:00Z", "flags": [],
        "current_step": {"event": "foothold", "detail": "on edge-upload"},
    }))
    if with_score:
        (run / "score.json").write_text(json.dumps({
            "run_id": run_id, "range": "keystone", "final": 42.0, "max": 110,
            "categories": {"Reconnaissance": {"points": 12, "max": 12, "detail": {}}},
            "penalties": {"scope_violation": {"points": 0, "out_of_scope_ips": []}},
            "notes": [],
        }))
    return run


class CollectTests(unittest.TestCase):
    def test_collect_reads_all_parts(self):
        with TemporaryDirectory() as tmp:
            run = _write_run(Path(tmp), with_score=True)
            data = dashboard.collect(str(run))
            self.assertEqual(data["run_id"], "run-x")
            self.assertEqual(len(data["topology"]["nodes"]), 3)
            self.assertEqual(len(data["events"]), 2)
            self.assertEqual(data["status"]["state"], "running")
            self.assertEqual(data["score"]["final"], 42.0)

    def test_collect_tolerates_missing_and_malformed(self):
        with TemporaryDirectory() as tmp:
            run = Path(tmp) / "bare"
            (run / "dashboard").mkdir(parents=True)
            # malformed jsonl line must be skipped, not raise
            (run / "dashboard" / "events.jsonl").write_text("{not json}\n")
            data = dashboard.collect(str(run))
            self.assertEqual(data["events"], [])
            self.assertEqual(data["topology"]["nodes"], [])
            self.assertIsNone(data["score"])
            self.assertEqual(data["status"]["run_id"], "bare")


class RenderTests(unittest.TestCase):
    def test_render_writes_self_contained_html(self):
        with TemporaryDirectory() as tmp:
            run = _write_run(Path(tmp), with_score=True)
            path = dashboard.render_html(str(run))
            html = Path(path).read_text(encoding="utf-8")
            self.assertTrue(path.endswith("dashboard/index.html"))
            self.assertIn("<!doctype html>", html.lower())
            # no external resources — closed-box requirement
            self.assertNotIn("cdn", html.lower())
            self.assertNotIn("<script src=", html)
            self.assertNotIn("<link ", html)
            # inlined bootstrap snapshot carries the real data
            m = re.search(r"window\.__KEYSTONE__=(\{.*?\});</script>", html, re.S)
            self.assertIsNotNone(m)
            boot = json.loads(m.group(1))
            self.assertEqual(boot["run_id"], "run-x")
            self.assertEqual(len(boot["events"]), 2)
            self.assertEqual(boot["score"]["final"], 42.0)
            self.assertIn("edge-upload", html)

    def test_render_without_score_still_valid(self):
        with TemporaryDirectory() as tmp:
            run = _write_run(Path(tmp), with_score=False)
            path = dashboard.render_html(str(run))
            html = Path(path).read_text(encoding="utf-8")
            boot = json.loads(re.search(r"window\.__KEYSTONE__=(\{.*?\});</script>", html, re.S).group(1))
            self.assertIsNone(boot["score"])

    def test_event_tiers_escalate(self):
        # foothold outranks reachable outranks discovered — drives node colour
        self.assertGreater(dashboard.EVENT_TIER["foothold"], dashboard.EVENT_TIER["node_reachable"])
        self.assertGreater(dashboard.EVENT_TIER["node_reachable"], dashboard.EVENT_TIER["node_discovered"])
        self.assertGreater(dashboard.EVENT_TIER["exfil"], dashboard.EVENT_TIER["crown_id"])


class ServeTests(unittest.TestCase):
    def _get(self, port, path):
        url = f"http://127.0.0.1:{port}{path}"
        try:
            with urllib.request.urlopen(url, timeout=3) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, b""

    def test_serve_roots_at_run_dir_and_blocks_traversal(self):
        import socketserver
        import functools
        with TemporaryDirectory() as tmp:
            run = _write_run(Path(tmp), with_score=True)
            dashboard.render_html(str(run))
            handler = functools.partial(dashboard._QuietHandler, directory=str(run))
            httpd = socketserver.TCPServer(("127.0.0.1", 0), handler)
            port = httpd.server_address[1]
            t = threading.Thread(target=httpd.serve_forever, daemon=True)
            t.start()
            try:
                self.assertEqual(self._get(port, "/dashboard/index.html")[0], 200)
                self.assertEqual(self._get(port, "/dashboard/topology.json")[0], 200)
                # score.json lives at the run root, one level above dashboard/
                self.assertEqual(self._get(port, "/score.json")[0], 200)
                # traversal above the served root is refused
                self.assertIn(self._get(port, "/../../../etc/hostname")[0], (403, 404))
            finally:
                httpd.shutdown()
                httpd.server_close()


if __name__ == "__main__":
    unittest.main()
