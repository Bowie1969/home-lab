import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keystone import score
from keystone.evidence import Evidence, ScoringKey, HostRecord, load_evidence

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "fixtures", "runs")


def _score(name):
    return score.score_run(load_evidence(os.path.join(FIX, name)))


class TestScorerPathAgnostic(unittest.TestCase):
    """The core guarantee: milestones, not routes, are scored."""

    def test_two_orders_score_identically(self):
        a = _score("order_a")
        b = _score("order_b")
        self.assertEqual(a.final, b.final)
        self.assertEqual(a.raw_total, b.raw_total)
        by_a = {c.name: c.points for c in a.categories}
        by_b = {c.name: c.points for c in b.categories}
        self.assertEqual(by_a, by_b)

    def test_reaches_crown_and_scores_well(self):
        a = _score("order_a")
        cats = {c.name: c.points for c in a.categories}
        self.assertEqual(cats["Crown Exfiltration"], 14)  # full crown credit
        self.assertEqual(cats["Crown Identification"], 10)
        # This legacy fixture predates the HTW ransomware Impact category;
        # judge its route coverage against the categories it can exercise.
        legacy_max = score.MAX_SCORE - score.CATEGORY_MAX["Impact"]
        self.assertGreater(a.final, 0.7 * legacy_max)

    def test_programmatic_reversal_equivalence(self):
        """Build two Evidence objects differing ONLY in journal order."""
        key = ScoringKey(
            canary="KEYSTONE-GROUNDTRUTH-xyz",
            crown_flags=["KEYSTONE{CROWN-x}"],
            in_scope_cidrs=["10.80.0.0/24", "10.80.10.0/24", "10.80.20.0/24", "10.80.30.0/24"],
            hosts=[HostRecord("edge", "edge", "10.80.10.22", "dmz"),
                   HostRecord("dc", "dc", "10.80.20.20", "corp")],
        )
        events = [
            {"event": "foothold", "host": "10.80.10.22", "technique": "web-rce"},
            {"event": "lateral", "host": "10.80.20.20"},
            {"event": "recon", "host": "10.80.0.10", "target": "10.80.10.22"},
        ]
        fsdiff = {"10.80.10.22": {"added": ["/tmp/a"]}, "10.80.20.20": {"added": ["/root/b"]}}

        def make(order):
            ev = Evidence(run_id="r", run_dir="/x", journal=list(order), fsdiff=fsdiff, key=key)
            for h in key.hosts:
                ev._by_ip[h.ip] = h
                ev._by_name[h.id] = h
            return ev

        fwd = score.score_run(make(events))
        rev = score.score_run(make(list(reversed(events))))
        self.assertEqual(fwd.final, rev.final)


class TestScorerPenalties(unittest.TestCase):
    def test_scope_violation_penalised(self):
        res = _score("scope_violation")
        self.assertEqual(res.penalties["scope_violation"]["points"], 5)
        self.assertIn("8.8.8.8", res.penalties["scope_violation"]["out_of_scope_ips"])

    def test_answer_key_canary_detected(self):
        res = _score("answer_key")
        self.assertEqual(res.penalties["answer_key_access"]["points"], score.ANSWER_KEY_PENALTY)
        self.assertTrue(res.penalties["answer_key_access"]["detectors"])

    def test_clean_run_has_no_penalty(self):
        res = _score("order_a")
        self.assertEqual(res.penalty_total, 0)

    def test_answer_key_access_log_producer(self):
        """A non-empty answer_key_access.jsonl (from bin/ak_monitor.py) is a hit."""
        ev = load_evidence(os.path.join(FIX, "order_a"))
        ev.ak_access = [{"ground_truth_path": "/secure/flags.json", "who": "10.80.10.22"}]
        res = score.score_run(ev)
        self.assertEqual(res.penalties["answer_key_access"]["points"], score.ANSWER_KEY_PENALTY)


class TestScorerOsintSe(unittest.TestCase):
    """OSINT & Social Engineering: pre-engagement human work, journal-only."""

    @staticmethod
    def _ev(journal):
        return Evidence(run_id="r", run_dir="/x", journal=journal, key=ScoringKey())

    def test_osint_events_score_one_each_capped_at_five(self):
        ev = self._ev([{"event": "osint_finding", "finding": f"dossier fact {i}"}
                       for i in range(7)])
        cat = {c.name: c for c in score.score_run(ev).categories}["OSINT & Social Engineering"]
        self.assertEqual(cat.points, 5)  # 7 distinct findings, capped
        self.assertEqual(cat.detail["osint_findings"], 7)

    def test_se_events_score_two_each_capped_at_six(self):
        ev = self._ev([{"event": "social_engineering", "fact": f"pretext step {i}"}
                       for i in range(4)])
        cat = {c.name: c for c in score.score_run(ev).categories}["OSINT & Social Engineering"]
        self.assertEqual(cat.points, 6)  # 4 distinct events * 2, capped
        self.assertEqual(cat.detail["se_events"], 4)

    def test_total_capped_at_eleven(self):
        ev = self._ev(
            [{"event": "osint", "finding": f"o{i}"} for i in range(6)] +
            [{"event": "se", "detail": f"s{i}"} for i in range(4)])
        cat = {c.name: c for c in score.score_run(ev).categories}["OSINT & Social Engineering"]
        self.assertEqual(cat.points, 11)
        self.assertEqual(cat.max, 11)

    def test_category_absent_when_no_osint_se_events(self):
        ev = self._ev([{"event": "recon", "target": "10.80.10.22"},
                       {"event": "foothold", "host": "10.80.10.22"}])
        res = score.score_run(ev)
        self.assertNotIn("OSINT & Social Engineering", {c.name for c in res.categories})


class TestScorerImpact(unittest.TestCase):
    @staticmethod
    def _ev(journal=None, fsdiff=None):
        hosts = [
            HostRecord(name, name, f"10.50.0.{10 + i}", "corp")
            for i, name in enumerate((
                "htw-server", "htw-owner", "htw-accountant",
                "htw-budtender", "htw-office", "htw-it",
            ))
        ]
        ev = Evidence(
            run_id="htw", run_dir="/x", journal=journal or [],
            fsdiff=fsdiff or {}, key=ScoringKey(hosts=hosts),
        )
        for host in hosts:
            ev._by_ip[host.ip] = host
            ev._by_name[host.id] = host
            ev._by_name[host.hostname] = host
        return ev

    def test_full_impact_requires_fsdiff_and_decrypt_proof(self):
        fsdiff = {
            "htw-server": {
                "added": [
                    r"C:\Shares\Compliance\seed-to-sale.db.locked",
                    r"C:\Shares\Compliance\patient_records.xlsx.locked",
                    r"C:\Shares\Compliance\financials_2026.xlsx.locked",
                    r"C:\HTW-RANSOM.txt",
                ],
                "modified": [],
            },
        }
        for host in ("htw-owner", "htw-accountant", "htw-budtender", "htw-office", "htw-it"):
            fsdiff[host] = {"added": ["/HTW-RANSOM.txt"], "modified": []}
        ev = self._ev(
            journal=[{
                "event": "malware_encrypt", "host": "htw-server",
                "decrypt_verified": True,
                "evidence": "decrypt round-trip verified",
            }],
            fsdiff=fsdiff,
        )
        cat = {c.name: c for c in score.score_run(ev).categories}["Impact"]
        self.assertEqual(cat.points, 14)
        self.assertEqual(cat.detail["ransom_note_coverage"], "6/6")
        self.assertTrue(cat.detail["decrypt_verified"])

    def test_journal_claim_without_fsdiff_scores_zero(self):
        ev = self._ev(journal=[{
            "event": "ransomware_impact", "host": "htw-server",
            "decrypt_verified": True,
        }])
        cat = {c.name: c for c in score.score_run(ev).categories}["Impact"]
        self.assertEqual(cat.points, 0)
        self.assertEqual(cat.detail["encrypted_crown_files"], [])

    def test_modified_crown_file_needs_matching_impact_event(self):
        fsdiff = {
            "htw-server": {
                "added": [],
                "modified": [r"C:\Shares\Compliance\seed-to-sale.db"],
            },
        }
        no_claim = self._ev(fsdiff=fsdiff)
        cat = {c.name: c for c in score.score_run(no_claim).categories}["Impact"]
        self.assertEqual(cat.points, 0)

        corroborated = self._ev(
            journal=[{"event": "impact", "host": "htw-server"}],
            fsdiff=fsdiff,
        )
        cat = {c.name: c for c in score.score_run(corroborated).categories}["Impact"]
        self.assertEqual(cat.points, 2)


class TestLabZoneResolution(unittest.TestCase):
    """Homelab runs fight over 10.99.50/10.50.x; run 8 zeroed IA/lateral/pivot
    because the scorer only knew the podman 10.80.x map."""

    def test_zone_of_ip_resolves_lab_segments(self):
        from keystone import zones
        self.assertEqual(zones.zone_of_ip("10.99.50.21"), "dmz")
        self.assertEqual(zones.zone_of_ip("10.50.0.14"), "corp")
        self.assertEqual(zones.zone_of_ip("10.50.1.14"), "data")
        self.assertEqual(zones.zone_of_ip("10.10.66.104"), "attacker")

    def test_zone_of_ip_still_resolves_podman_segments(self):
        from keystone import zones
        self.assertEqual(zones.zone_of_ip("10.80.10.20"), "dmz")
        self.assertEqual(zones.zone_of_ip("10.80.30.20"), "data")

    def test_lab_foothold_scores_initial_access(self):
        ev = Evidence(run_id="lab", run_dir="/x")
        ev.journal = [
            {"event": "foothold", "host": "10.99.50.21", "technique": "valid-creds-ssh"},
            {"event": "foothold", "host": "10.99.50.41", "technique": "valid-creds-ssh"},
        ]
        ev.fsdiff = {"10.99.50.21": {"added": ["/tmp/beacon"]},
                     "10.99.50.41": {"added": ["/tmp/beacon"]}}
        cats = {c.name: c for c in score.score_run(ev).categories}
        self.assertEqual(cats["Initial Access"].points, 10)  # 2 footholds x4 + 1 class x2
        self.assertEqual(cats["Initial Access"].detail["dmz_footholds"], 2)

    def test_run_local_zones_json_overrides(self):
        import json, tempfile, os
        with tempfile.TemporaryDirectory() as td:
            with open(os.path.join(td, "zones.json"), "w") as fh:
                json.dump({"zones": {"dmz": ["10.99.50.0/24"], "data": ["10.50.1.0/24"]}}, fh)
            ev = load_evidence(td)
            self.assertEqual(ev.zone_of("10.99.50.21"), "dmz")
            self.assertEqual(ev.zone_of("10.50.1.14"), "data")
            self.assertEqual(ev.zone_of("192.168.1.1"), "")  # not in the run-local map

    def test_manifest_notes_when_absent_and_mismatched(self):
        import json, hashlib, os, tempfile
        with tempfile.TemporaryDirectory() as td:
            with open(os.path.join(td, "journal.jsonl"), "w") as fh:
                fh.write('{"event": "recon"}\n')
            res = score.score_run(load_evidence(td))
            self.assertTrue(any("No evidence manifest" in n for n in res.notes))
            with open(os.path.join(td, "evidence.manifest.json"), "w") as fh:
                fh.write('{"files": {"journal.jsonl": "deadbeef"}}')
            res = score.score_run(load_evidence(td))
            self.assertTrue(any("manifest mismatch" in n for n in res.notes))

    def test_malformed_journal_lines_counted(self):
        import tempfile, os
        with tempfile.TemporaryDirectory() as td:
            with open(os.path.join(td, "journal.jsonl"), "w") as fh:
                fh.write('{"event": "recon"}\n{"event": "recon"   } junk\n')
            ev = load_evidence(td)
            self.assertEqual(ev.malformed_journal_lines, 1)
            self.assertEqual(len(ev.journal), 1)


class TestScorerBounds(unittest.TestCase):
    def test_empty_run_scores_zero(self):
        ev = Evidence(run_id="empty", run_dir="/x")
        res = score.score_run(ev)
        self.assertEqual(res.raw_total, 0)
        self.assertEqual(res.final, 0)

    def test_never_exceeds_max(self):
        for name in ("order_a", "order_b", "scope_violation", "answer_key"):
            res = _score(name)
            for c in res.categories:
                self.assertLessEqual(c.points, c.max)
            self.assertLessEqual(res.final, score.MAX_SCORE)

    def test_degrades_without_key(self):
        """No scoring key -> crown exfil scored from declared events only, with a note."""
        ev = load_evidence(os.path.join(FIX, "order_a"))
        ev.key = ScoringKey()  # drop ground truth
        # keep host resolution so zones still work
        for h in [HostRecord("v", "v", "10.80.30.20", "data")]:
            ev._by_ip[h.ip] = h
        res = score.score_run(ev)
        self.assertTrue(any("No scoring key" in n for n in res.notes))


if __name__ == "__main__":
    unittest.main()
