import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keystone import bluetelemetry, pcap
from keystone.evidence import Evidence, HostRecord, ScoringKey

TCP = pcap.PROTO_TCP


def _pkt(ts, src, dst, dport, length=120):
    return pcap.Packet(ts=ts, src_ip=src, dst_ip=dst, proto=TCP,
                       src_port=40000, dst_port=dport, length=length)


def _evidence():
    """A small but representative run: an allowed DMZ ssh that lands a foothold,
    two policy-crossing attempts, host changes, and an answer-key read."""
    ev = Evidence(run_id="t", run_dir="/nonexistent")
    ev.packets = [
        _pkt(1000.0, "10.80.0.10", "10.80.10.20", 22),   # attacker->dmz ssh (allowed)
        _pkt(1001.0, "10.80.0.10", "10.80.10.20", 22),   # same flow, second packet
        _pkt(1100.0, "10.80.0.10", "10.80.20.30", 445),  # attacker->corp (DENIED)
        _pkt(1200.0, "10.80.10.20", "10.80.30.40", 445), # dmz->data (DENIED)
        _pkt(1300.0, "10.80.10.20", "10.80.20.30", 88),  # dmz->corp kerberos (allowed)
    ]
    ev.fsdiff = {"10.80.10.20": {"added": ["/tmp/shell.sh"], "modified": ["/etc/passwd"]}}
    ev.ak_access = [{"ts": "2026-10-16T06:00:00Z", "source": "ak_monitor"}]
    ev.key = ScoringKey(canary="KEYSTONE{do-not-leak-me}",
                        in_scope_cidrs=["10.80.0.0/16"],
                        hosts=[HostRecord(id="edge", hostname="edge01",
                                          ip="10.80.10.20", zone="dmz")])
    for h in ev.key.hosts:
        ev._by_ip[h.ip] = h
        ev._by_name[h.hostname] = h
    return ev


class TestProjection(unittest.TestCase):
    def setUp(self):
        self.streams = bluetelemetry.synthesize_from_evidence(_evidence())

    def test_netflow_collapses_packets_into_flows(self):
        flows = self.streams["netflow.jsonl"]
        ssh = [f for f in flows if f["dst"] == "10.80.10.20" and f["dst_port"] == 22]
        self.assertEqual(len(ssh), 1)
        self.assertEqual(ssh[0]["packets"], 2)          # two packets, one flow
        self.assertEqual(ssh[0]["bytes"], 240)

    def test_firewall_drops_only_denied_edges(self):
        drops = {(d["src_zone"], d["dst_zone"]) for d in self.streams["firewall-drops.jsonl"]}
        self.assertIn(("attacker", "corp"), drops)       # attacker->corp denied
        self.assertIn(("dmz", "data"), drops)            # dmz->data denied
        self.assertNotIn(("attacker", "dmz"), drops)     # allowed, no drop
        self.assertNotIn(("dmz", "corp"), drops)         # allowed, no drop

    def test_auth_marks_success_only_with_host_evidence(self):
        # edge01 has fsdiff changes, so its ssh auth is corroborated as accepted.
        auth = self.streams["auth-edge01.jsonl"]
        ssh = [a for a in auth if a["service"] == "ssh"]
        self.assertEqual(len(ssh), 1)
        self.assertEqual(ssh[0]["outcome"], "accepted")

    def test_host_stream_carries_file_events(self):
        events = {(e["event"], e["path"]) for e in self.streams["host-edge01.jsonl"]
                  if "path" in e}
        self.assertIn(("file_created", "/tmp/shell.sh"), events)
        self.assertIn(("file_modified", "/etc/passwd"), events)

    def test_answer_key_read_raises_critical_alert(self):
        alerts = self.streams["alerts.jsonl"]
        self.assertTrue(any(a["signal"] == "answer_key_access"
                            and a["severity"] == "critical" for a in alerts))

    def test_canary_token_never_leaks_into_any_stream(self):
        blob = json.dumps(self.streams)
        self.assertNotIn("do-not-leak-me", blob)
        self.assertNotIn("KEYSTONE{", blob)

    def test_canary_in_evidence_raises_alert_without_the_token(self):
        ev = _evidence()
        ev.journal = [{"action": "exfil", "loot": "KEYSTONE{do-not-leak-me}"}]
        streams = bluetelemetry.synthesize_from_evidence(ev)
        signals = {a["signal"] for a in streams["alerts.jsonl"]}
        self.assertIn("canary_token_observed", signals)
        self.assertNotIn("do-not-leak-me", json.dumps(streams))

    def test_no_attacker_journal_text_projected(self):
        # Journal intent must not appear in blue telemetry.
        ev = _evidence()
        ev.journal = [{"action": "exfil", "detail": "RED-TRANSCRIPT-SECRET-PLAN"}]
        blob = json.dumps(bluetelemetry.synthesize_from_evidence(ev))
        self.assertNotIn("RED-TRANSCRIPT-SECRET-PLAN", blob)


if __name__ == "__main__":
    unittest.main()
