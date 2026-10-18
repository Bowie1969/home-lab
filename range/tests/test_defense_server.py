import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keystone import bluetelemetry, pcap
from keystone.blue import defense_server as ds
from keystone.evidence import Evidence, HostRecord, ScoringKey

TCP = pcap.PROTO_TCP


def _pkt(ts, src, dst, dport):
    return pcap.Packet(ts=ts, src_ip=src, dst_ip=dst, proto=TCP,
                       src_port=40000, dst_port=dport, length=100)


def _build_run():
    """A run dir with synthesized blue telemetry under telemetry/."""
    d = tempfile.mkdtemp(prefix="defsrv-")
    run = os.path.join(d, "runs", "r")
    os.makedirs(run)
    ev = Evidence(run_id="r", run_dir=run)
    ev.packets = [
        _pkt(1.0, "10.80.0.10", "10.80.10.20", 22),    # attacker->dmz ssh
        _pkt(2.0, "10.80.0.10", "10.80.20.30", 445),   # attacker->corp DENIED
    ]
    ev.fsdiff = {"10.80.10.20": {"added": ["/tmp/x.sh"]}}
    ev.key = ScoringKey(in_scope_cidrs=["10.80.0.0/16"],
                        hosts=[HostRecord(id="edge", hostname="edge01",
                                          ip="10.80.10.20", zone="dmz")])
    for h in ev.key.hosts:
        ev._by_ip[h.ip] = h
    streams = bluetelemetry.synthesize_from_evidence(ev)
    tdir = os.path.join(run, "telemetry")
    os.makedirs(tdir)
    for name, recs in streams.items():
        with open(os.path.join(tdir, name), "w", encoding="utf-8") as fh:
            for r in recs:
                fh.write(json.dumps(r) + "\n")
    return run


def _env(run, *, scope="10.80.0.0/16", respond=False, deny=""):
    e = {ds.RUN_DIR_ENV_KEY: run}
    if scope is not None:
        e[ds.SCOPE_ENV_KEY] = scope
    if deny:
        e[ds.DENY_ENV_KEY] = deny
    if respond:
        e[ds.ALLOW_RESPONSE_ENV_KEY] = "1"
    return e


class TestReadTools(unittest.TestCase):
    def setUp(self):
        self.run = _build_run()

    def test_fail_closed_without_scope(self):
        with self.assertRaises(ds.Refused):
            ds.tool_netflow(_env(self.run, scope=None), {})

    def test_list_telemetry_enumerates_streams(self):
        out = ds.tool_list_telemetry(_env(self.run), {})
        self.assertIn("netflow.jsonl", out["streams"])
        self.assertIn("firewall-drops.jsonl", out["streams"])

    def test_netflow_returns_records(self):
        out = ds.tool_netflow(_env(self.run), {})
        self.assertGreater(out["count"], 0)

    def test_firewall_drops_show_denied_edge(self):
        out = ds.tool_firewall_drops(_env(self.run), {})
        self.assertTrue(any(r["dst_zone"] == "corp" for r in out["records"]))

    def test_host_events_requires_in_scope_host(self):
        with self.assertRaises(ds.Refused):
            ds.tool_host_events(_env(self.run, scope="10.99.0.0/16"), {"host": "10.80.10.20"})
        out = ds.tool_host_events(_env(self.run), {"host": "10.80.10.20"})
        self.assertEqual(out["host"], "10.80.10.20")

    def test_traversal_refused(self):
        with self.assertRaises(ds.Refused):
            ds._read_stream(_env(self.run), "../../../etc/passwd")


class TestActionTools(unittest.TestCase):
    def setUp(self):
        self.run = _build_run()

    def test_action_refused_when_response_tier_off(self):
        tool = ds.ACTION_TOOLS["isolate_host"]
        with self.assertRaises(ds.Refused):
            tool(_env(self.run, respond=False), {"subject": "10.80.10.20"})

    def test_action_refused_out_of_scope_and_journalled(self):
        tool = ds.ACTION_TOOLS["block_ip"]
        with self.assertRaises(ds.Refused):
            tool(_env(self.run, respond=True), {"subject": "10.0.0.1"})
        log = os.path.join(self.run, "defense_actions.jsonl")
        recs = [json.loads(l) for l in open(log, encoding="utf-8") if l.strip()]
        self.assertTrue(any(r["outcome"] == "refused" for r in recs))

    def test_action_records_and_paints_dashboard(self):
        tool = ds.ACTION_TOOLS["isolate_host"]
        out = tool(_env(self.run, respond=True), {"subject": "10.80.10.20", "detail": "cut"})
        self.assertEqual(out["outcome"], "done")
        # action journal
        log = os.path.join(self.run, "defense_actions.jsonl")
        self.assertTrue(any(json.loads(l)["outcome"] == "done"
                            for l in open(log, encoding="utf-8") if l.strip()))
        # dashboard paint
        ev = os.path.join(self.run, "dashboard", "events.jsonl")
        painted = [json.loads(l) for l in open(ev, encoding="utf-8") if l.strip()]
        self.assertTrue(any(r["event"] == "defense_isolate"
                            and r["action"] == "isolate-host" for r in painted))

    def test_every_response_action_is_exposed_as_a_tool(self):
        for action in ds.ACTIONS:
            self.assertIn(action.replace("-", "_"), ds.ACTION_TOOLS)


class TestDispatch(unittest.TestCase):
    def setUp(self):
        self.run = _build_run()

    def test_initialize_and_tools_list(self):
        init = ds.dispatch("initialize", {}, _env(self.run))
        self.assertEqual(init["serverInfo"]["name"], "keystone-defense")
        tools = ds.dispatch("tools/list", {}, _env(self.run))["tools"]
        names = {t["name"] for t in tools}
        self.assertIn("netflow", names)
        self.assertIn("isolate_host", names)

    def test_tools_call_wraps_result_as_mcp_content(self):
        res = ds.dispatch("tools/call",
                          {"name": "list_telemetry", "arguments": {}}, _env(self.run))
        self.assertEqual(res["content"][0]["type"], "text")
        payload = json.loads(res["content"][0]["text"])
        self.assertIn("streams", payload)

    def test_unknown_tool_refused(self):
        with self.assertRaises(ds.Refused):
            ds.dispatch("tools/call", {"name": "rm_rf", "arguments": {}}, _env(self.run))


if __name__ == "__main__":
    unittest.main()
