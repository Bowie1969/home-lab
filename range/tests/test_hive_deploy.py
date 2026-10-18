"""Tests for the deploy_hive_instance MCP tool.

Pure-function tests driven by a tempdir run dir (KEYSTONE_RUN_DIR override).
No MCP transport, no primary EvilKit, no actual network — just the policy
guards, journal/registry side effects, and the handshake payload.
"""
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path


def _load_server():
    root = Path(__file__).resolve().parent.parent
    src = root / "mcp-redteamscripting" / "server.py"
    spec = importlib.util.spec_from_file_location("rts_server", src)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class HiveBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="keystone-hive-")
        self._prev_env = os.environ.get("KEYSTONE_RUN_DIR")
        os.environ["KEYSTONE_RUN_DIR"] = self.tmp
        self.server = _load_server()

    def tearDown(self):
        if self._prev_env is None:
            os.environ.pop("KEYSTONE_RUN_DIR", None)
        else:
            os.environ["KEYSTONE_RUN_DIR"] = self._prev_env

    def _seed_compromise(self, host, event="host_compromised"):
        p = Path(self.tmp) / "journal.jsonl"
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"event": event, "host": host}) + "\n")

    def _read_journal(self):
        p = Path(self.tmp) / "journal.jsonl"
        if not p.exists():
            return []
        return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]

    def _read_registry(self):
        p = Path(self.tmp) / "hive" / "instances.jsonl"
        if not p.exists():
            return []
        return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]

    def _read_instructions(self):
        p = Path(self.tmp) / "dashboard" / "operator_instructions.jsonl"
        if not p.exists():
            return []
        return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]


class TestDeploymentPreconditions(HiveBase):
    def test_requires_host(self):
        r = self.server.deploy_hive_instance(host="")
        self.assertFalse(r["success"])
        self.assertIn("host is required", r["error"])

    def test_rejects_mac_as_infra(self):
        self._seed_compromise("mac-debian13")
        r = self.server.deploy_hive_instance(host="mac-debian13")
        self.assertFalse(r["success"])
        self.assertIn("infra", r["error"])

    def test_rejects_drop01_as_infra(self):
        self._seed_compromise("drop01")
        r = self.server.deploy_hive_instance(host="drop01")
        self.assertFalse(r["success"])
        self.assertIn("infra", r["error"])

    def test_rejects_attacker_zone(self):
        self._seed_compromise("op-kali")
        r = self.server.deploy_hive_instance(host="op-kali", zone="attacker")
        self.assertFalse(r["success"])
        self.assertIn("forbidden", r["error"])

    def test_rejects_mgmt_zone(self):
        self._seed_compromise("hex")
        r = self.server.deploy_hive_instance(host="hex", zone="mgmt")
        self.assertFalse(r["success"])

    def test_requires_journaled_compromise(self):
        r = self.server.deploy_hive_instance(host="ks-ws01", zone="corp")
        self.assertFalse(r["success"])
        self.assertIn("compromise", r["error"])

    def test_accepts_foothold_as_compromise(self):
        self._seed_compromise("edge-upload", event="foothold")
        r = self.server.deploy_hive_instance(host="edge-upload", zone="dmz")
        self.assertTrue(r["success"], r)

    def test_accepts_host_compromised(self):
        self._seed_compromise("ks-ws01")
        r = self.server.deploy_hive_instance(host="ks-ws01", zone="corp")
        self.assertTrue(r["success"], r)


class TestSideEffects(HiveBase):
    def _ok_deploy(self, host="ks-ws01", zone="corp", **kw):
        self._seed_compromise(host)
        return self.server.deploy_hive_instance(host=host, zone=zone, **kw)

    def test_journal_event_recorded(self):
        self._ok_deploy()
        evs = [e for e in self._read_journal() if e.get("event") == "hive_instance_deployed"]
        self.assertEqual(len(evs), 1)
        e = evs[0]
        self.assertEqual(e["host"], "ks-ws01")
        self.assertEqual(e["zone"], "corp")
        self.assertEqual(e["parent"], "primary")

    def test_registry_appended(self):
        self._ok_deploy()
        reg = self._read_registry()
        self.assertEqual(len(reg), 1)
        self.assertEqual(reg[0]["host"], "ks-ws01")
        self.assertEqual(reg[0]["status"], "deploy_requested")

    def test_operator_instruction_includes_payload_path(self):
        self._ok_deploy()
        ins = self._read_instructions()
        self.assertEqual(len(ins), 1)
        self.assertEqual(ins[0]["payload"], "infra/hive/worker.py")
        self.assertIn("KEYSTONE_HIVE_PRIMARY", ins[0]["env"])
        self.assertIn("KEYSTONE_HIVE_INFERENCE", ins[0]["env"])

    def test_handshake_points_at_primary_and_inference(self):
        r = self._ok_deploy()
        hs = r["handshake"]
        self.assertTrue(hs["primary_endpoint"].startswith("http"))
        self.assertTrue(hs["inference_endpoint"].startswith("http"))
        self.assertGreaterEqual(hs["beacon_interval_s"], 1)
        self.assertEqual(hs["beacon_path"], "/hive/beacon")

    def test_hive_size_grows_across_deploys(self):
        self._seed_compromise("ks-ws01")
        self._seed_compromise("ks-files01")
        r1 = self.server.deploy_hive_instance(host="ks-ws01", zone="corp")
        r2 = self.server.deploy_hive_instance(host="ks-files01", zone="corp", parent="ks-ws01")
        self.assertEqual(r1["hive_size"], 1)
        self.assertEqual(r2["hive_size"], 2)

    def test_cascading_parent_recorded(self):
        self._seed_compromise("ks-ws01")
        self._seed_compromise("ks-files01")
        self.server.deploy_hive_instance(host="ks-ws01", zone="corp")
        self.server.deploy_hive_instance(host="ks-files01", zone="corp", parent="ks-ws01")
        evs = [e for e in self._read_journal() if e.get("event") == "hive_instance_deployed"]
        self.assertEqual(evs[1]["parent"], "ks-ws01")

    def test_rationale_truncated(self):
        self._seed_compromise("ks-ws01")
        self.server.deploy_hive_instance(host="ks-ws01", zone="corp",
                                         rationale="x" * 2000)
        e = next(e for e in self._read_journal() if e.get("event") == "hive_instance_deployed")
        self.assertEqual(len(e["rationale"]), 500)

    def test_no_side_effects_on_rejection(self):
        self.server.deploy_hive_instance(host="")
        self.assertEqual(self._read_journal(), [])
        self.assertEqual(self._read_registry(), [])
        self.assertEqual(self._read_instructions(), [])


class TestOperatorOverrides(HiveBase):
    def test_config_json_overrides_endpoints(self):
        cfg = Path(self.tmp) / "hive" / "config.json"
        cfg.parent.mkdir(parents=True, exist_ok=True)
        cfg.write_text(json.dumps({
            "primary_endpoint": "http://10.10.66.99:9999",
            "inference_endpoint": "http://10.50.0.200:1234",
        }), encoding="utf-8")
        self._seed_compromise("ks-ws01")
        r = self.server.deploy_hive_instance(host="ks-ws01", zone="corp")
        hs = r["handshake"]
        self.assertEqual(hs["primary_endpoint"], "http://10.10.66.99:9999")
        self.assertEqual(hs["inference_endpoint"], "http://10.50.0.200:1234")
        self.assertEqual(hs["beacon_path"], "/hive/beacon")  # defaults still kick in


class TestRegistration(HiveBase):
    def test_tool_registered_in_TOOLS(self):
        self.assertIn("deploy_hive_instance", self.server.TOOLS)
        self.assertNotIn("plant_dropbox", self.server.TOOLS)
        self.assertIs(self.server.TOOLS["deploy_hive_instance"],
                      self.server.deploy_hive_instance)


if __name__ == "__main__":
    unittest.main()
