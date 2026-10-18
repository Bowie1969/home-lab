import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keystone import dashboard, emit


class TestEmitDefenseAction(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="defviz-")
        self.run = os.path.join(self.dir, "runs", "r")
        os.makedirs(self.run)

    def _events(self):
        path = os.path.join(self.run, "dashboard", "events.jsonl")
        return [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]

    def test_action_maps_to_blue_event_and_keeps_action_name(self):
        rec = emit.emit_defense_action(self.run, "10.80.10.20", "isolate-host",
                                       detail="cut from corp", outcome="done")
        self.assertEqual(rec["event"], "defense_isolate")
        self.assertEqual(rec["action"], "isolate-host")
        self.assertEqual(rec["outcome"], "done")
        self.assertEqual(rec["actor"], "blukit")
        self.assertIn("defense_isolate", emit.DEFENSE_EVENTS)

    def test_defense_events_need_no_attacker_evidence(self):
        # Unlike compromise events, a defender action may omit evidence.
        rec = emit.emit_defense_action(self.run, "10.80.20.30", "disable-account")
        self.assertEqual(rec["event"], "defense_disable_account")

    def test_unknown_action_falls_back_to_detect(self):
        rec = emit.emit_defense_action(self.run, "h", "frobnicate")
        self.assertEqual(rec["event"], "defense_detect")

    def test_every_response_action_has_a_blue_event(self):
        # Keep emit.ACTION_EVENT in lockstep with blukit's response actions.
        for action in ("isolate-host", "block-ip", "block-host", "disable-account",
                       "revoke-creds", "terminate-process", "quarantine-file",
                       "capture-packet", "preserve-evidence"):
            self.assertIn(action, emit.ACTION_EVENT, action)
            self.assertIn(emit.ACTION_EVENT[action], emit.DEFENSE_EVENTS)


class TestDashboardOverlay(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="defviz-")
        self.run = os.path.join(self.dir, "runs", "r")
        os.makedirs(self.run)
        emit.write_topology(
            self.run,
            nodes=[{"id": "edge-upload", "label": "edge01", "zone": "dmz"},
                   {"id": "dc-roast", "label": "dc01", "zone": "corp"}],
            edges=[{"src": "edge-upload", "dst": "dc-roast"}],
            zones=["dmz", "corp"])
        emit.write_status(self.run, state="running")
        emit.emit_event(self.run, "edge-upload", "foothold", evidence="uid=33")
        emit.emit_defense_action(self.run, "edge-upload", "isolate-host",
                                 detail="cut from corp", outcome="done")
        emit.emit_defense_action(self.run, "dc-roast", "preserve-evidence", outcome="done")
        self.html = open(dashboard.render_html(self.run), encoding="utf-8").read()

    def test_overlay_assets_present(self):
        for token in (".def-badge", "--defended", "function defenseState",
                      "DEF_CONTAIN", "🛡 contained"):
            self.assertIn(token, self.html, token)

    def test_defense_events_embedded_with_action_and_outcome(self):
        self.assertIn("defense_isolate", self.html)
        self.assertIn('"action":"isolate-host"', self.html)
        self.assertIn('"outcome":"done"', self.html)

    def test_contain_and_watch_sets_are_disjoint_and_cover_vocab(self):
        # Mirror the JS classification against emit's vocabulary: every blue
        # event is either a containment or a watch, never both, never neither.
        contain = {"defense_isolate", "defense_block", "defense_disable_account",
                   "defense_revoke", "defense_kill", "defense_quarantine"}
        watch = {"defense_capture", "defense_preserve", "defense_detect"}
        self.assertEqual(contain & watch, set())
        self.assertEqual(contain | watch, emit.DEFENSE_EVENTS)


if __name__ == "__main__":
    unittest.main()
