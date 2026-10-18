import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from keystone import run_control


class RunControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.runs = Path(self.temp.name) / "runs"
        self.runs.mkdir()
        self.run = self.runs / "run-a"
        dashboard = self.run / "dashboard"
        dashboard.mkdir(parents=True)
        (dashboard / "topology.json").write_text(json.dumps({
            "nodes": [{"id": "web", "label": "web01", "ip": "10.80.10.22"}],
            "edges": [], "zones": [],
        }))
        (dashboard / "status.json").write_text(json.dumps({
            "run_id": "run-a", "state": "idle", "model": "no-attacking-operator",
            "started": "2020-01-01T00:00:00Z", "flags": [],
        }))
        (dashboard / "events.jsonl").write_text("")

    def tearDown(self):
        self.temp.cleanup()

    def status(self):
        return json.loads((self.run / "dashboard" / "status.json").read_text())

    def test_start_event_stop_without_launching_agent(self):
        self.assertEqual(run_control.start(self.runs), self.run)
        self.assertEqual(self.status()["state"], "starting")
        self.assertIn("Waiting for separately launched EvilKit", self.status()["current_step"]["detail"])
        with self.assertRaisesRegex(ValueError, "direct evidence"):
            run_control.event(self.runs, "host_compromised", "web", "")
        self.assertEqual((self.run / "dashboard" / "events.jsonl").read_text(), "")
        record = run_control.event(self.runs, "host_compromised", "web", "id command returned uid=0")
        self.assertEqual(record["node"], "web")
        self.assertEqual(record["host"], "10.80.10.22")
        self.assertEqual(self.status()["state"], "running")
        self.assertEqual(run_control.stop(self.runs), self.run)
        self.assertEqual(self.status()["state"], "finished")
        with self.assertRaisesRegex(ValueError, "no matching prepared run"):
            run_control.event(self.runs, "scan", "web", "late event")

    def test_start_touches_canonical_journal(self):
        # Regression: Run 7 ended up unofficially scored because journal.jsonl
        # only exists on bin/launch.sh-prepared runs. run_control.start must
        # guarantee the file on tracking activation so the scorer has a
        # canonical path to append to.
        journal = self.run / "journal.jsonl"
        self.assertFalse(journal.exists())
        run_control.start(self.runs)
        self.assertTrue(journal.is_file())
        self.assertEqual(journal.read_text(), "")

    def test_rejects_unknown_node_and_unprepared_run(self):
        run_control.start(self.runs)
        with self.assertRaisesRegex(ValueError, "unknown topology node"):
            run_control.event(self.runs, "agent_on_host", "ghost", "action running")
        with self.assertRaisesRegex(ValueError, "direct child"):
            run_control.stop(self.runs, str(self.runs.parent))

    def test_start_expires_an_abandoned_start_marker(self):
        run_control.start(self.runs)
        status_path = self.run / "dashboard" / "status.json"
        old = time.time() - run_control.STALE_START_SECONDS - 1
        os.utime(status_path, (old, old))
        replacement = self.runs / "run-b"
        replacement_dashboard = replacement / "dashboard"
        replacement_dashboard.mkdir(parents=True)
        (replacement_dashboard / "topology.json").write_text(
            (self.run / "dashboard" / "topology.json").read_text()
        )
        (replacement_dashboard / "events.jsonl").write_text("")
        (replacement_dashboard / "status.json").write_text(json.dumps({
            "run_id": "run-b", "state": "idle", "model": "no-attacking-operator",
            "started": "2020-01-01T00:00:00Z", "flags": [],
        }))
        self.assertEqual(run_control.start(self.runs), replacement)
        self.assertEqual(self.status()["state"], "finished")
        replacement_status = json.loads((replacement_dashboard / "status.json").read_text())
        self.assertEqual(replacement_status["state"], "starting")

    def test_start_does_not_expire_a_fresh_marker(self):
        run_control.start(self.runs)
        with self.assertRaisesRegex(ValueError, "already being tracked"):
            run_control.start(self.runs)


if __name__ == "__main__":
    unittest.main()
