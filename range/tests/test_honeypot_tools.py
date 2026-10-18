"""Tests for the honeypot-derived redteamscripting tools.

Covers the three Cowrie-sensor-derived tools added to the keystone-side MCP
mirror (malware_brute, malware_ingress, malware_key_reuse) and the shell-fidelity
probe added to malware_evasion. Pure string/registry checks against the
generated scripts — no MCP transport, no network, no execution.
"""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path


def _load_server():
    root = Path(__file__).resolve().parent.parent
    src = root / "mcp-redteamscripting" / "server.py"
    spec = importlib.util.spec_from_file_location("rts_honeypot", src)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class HoneypotToolBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="keystone-honeypot-tools-")
        self._prev_cwd = os.getcwd()
        os.chdir(self.tmp)  # scripts are written under cwd/scripts

    def tearDown(self):
        os.chdir(self._prev_cwd)


class TestObservedDictionary(HoneypotToolBase):
    def setUp(self):
        super().setUp()
        self.server = _load_server()

    def test_admin_admin_is_first(self):
        self.assertEqual(self.server.OBSERVED_SSH_CREDS[0], ("admin", "admin"))

    def test_dictionary_is_field_sized_and_ordered(self):
        creds = self.server.OBSERVED_SSH_CREDS
        self.assertGreaterEqual(len(creds), 40)
        # admin:admin dominates by an order of magnitude in the capture
        self.assertIn(("oracle", "oracle"), creds)
        self.assertIn(("root", "123456"), creds)
        self.assertIn(("pi", "raspberry"), creds)

    def test_brute_tool_returns_and_embeds_the_dictionary(self):
        r = self.server.malware_brute(target="10.80.10.22")
        self.assertTrue(r["success"])
        self.assertEqual(r["category"], "initial-access")
        self.assertEqual(r["dictionary"][0], "admin:admin")
        script = Path(r["path"]).read_text(encoding="utf-8")
        self.assertIn("admin:admin", script)
        self.assertIn("oracle:oracle", script)
        self.assertIn("sshpass", script)


class TestShellFidelityProbe(HoneypotToolBase):
    def setUp(self):
        super().setUp()
        self.server = _load_server()

    def test_evasion_includes_shell_fidelity_probe(self):
        r = self.server.malware_evasion(target_ip="10.80.10.22")
        script = Path(r["path"]).read_text(encoding="utf-8")
        self.assertIn("shell-fidelity", script)
        self.assertIn("command-resolution", script)
        self.assertIn("error-behaviour", script)
        self.assertIn("MARKER=", script)


class TestIngressTool(HoneypotToolBase):
    def setUp(self):
        super().setUp()
        self.server = _load_server()

    def test_ingress_download_ladder_and_arch_selection(self):
        r = self.server.malware_ingress(target="10.80.10.22")
        self.assertTrue(r["success"])
        self.assertEqual(r["category"], "ingress-tool-transfer")
        script = Path(r["path"]).read_text(encoding="utf-8")
        self.assertIn("uname -m", script)
        self.assertIn("wget -q", script)
        self.assertIn("curl -s", script)
        self.assertIn("busybox wget", script)
        self.assertIn("tftp ", script)
        self.assertIn("ftpget ", script)

    def test_ingress_arch_list_is_used(self):
        r = self.server.malware_ingress(arches="aarch64,mips")
        self.assertEqual(r["arches"], ["aarch64", "mips"])
        script = Path(r["path"]).read_text(encoding="utf-8")
        self.assertIn("aarch64-marker", script)
        self.assertIn("mips-marker", script)


class TestKeyReuseTool(HoneypotToolBase):
    def setUp(self):
        super().setUp()
        self.server = _load_server()

    def test_key_reuse_disables_host_key_checking(self):
        r = self.server.malware_key_reuse()
        self.assertTrue(r["success"])
        self.assertEqual(r["category"], "ssh-key-reuse")
        self.assertEqual(r["hop"], "key-reuse -> corp-keyjump")
        script = Path(r["path"]).read_text(encoding="utf-8")
        self.assertIn("StrictHostKeyChecking=no", script)
        self.assertIn("UserKnownHostsFile=/dev/null", script)
        self.assertIn("/home/ci/.ssh/id_ed25519", script)


class TestRegistration(HoneypotToolBase):
    def setUp(self):
        super().setUp()
        self.server = _load_server()

    def test_new_tools_registered(self):
        for name in ("malware_brute", "malware_ingress", "malware_key_reuse"):
            self.assertIn(name, self.server.TOOLS)
            self.assertIs(self.server.TOOLS[name], getattr(self.server, name))

    def test_tools_list_exposes_new_tools(self):
        resp = self.server.handle_request({"method": "tools/list", "params": {}})
        names = {t["name"] for t in resp["result"]["tools"]}
        self.assertLessEqual({"malware_brute", "malware_ingress", "malware_key_reuse"}, names)


if __name__ == "__main__":
    unittest.main()
