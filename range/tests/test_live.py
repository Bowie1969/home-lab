"""Regressions for the live bring-up safety and partial-range contract."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from keystone import generator, live


class TestLive(unittest.TestCase):
    def test_only_reviewed_modules_are_selected(self):
        ready, skipped = live.ready_modules()
        self.assertEqual({m.id for m in ready},
                         {"bmc-super", "cache-open", "corp-keyjump", "cron-root",
                          "edge-botnet", "edge-upload", "gitleak-api", "key-reuse",
                          "legacy-cve", "meta-ssrf", "modelhub-pickle",
                          "ntlm-relay-corp", "portal-sqli", "render-ssti",
                          "runner-escape", "share-anon", "ssh-weak", "token-jwt"})
        # vault-keystone moved off Parrot onto a dedicated brain LXC (substrate
        # "lxc"); ready_modules() only ever considers substrate=="container",
        # so it never appears in the (Parrot-only) skip list at all. The whole
        # DMZ container tier is now wired, and so are the three corp expansion
        # containers from the 2026-10-16 expansion: nothing container-side is
        # skipped.
        self.assertNotIn("vault-keystone", skipped)
        self.assertEqual(skipped, {})

    def test_ssh_tunnel_exercise_provides_no_operator_helper(self):
        attacker = (live.ROOT / "infra" / "attacker" / "Containerfile").read_text()
        config = (live.ROOT / "modules" / "ssh-weak" / "Containerfile").read_text()
        exercise = (live.ROOT / "modules" / "ssh-weak" / "TUNNEL_EXERCISE.md").read_text()
        self.assertIn("openssh-client", attacker)
        self.assertNotIn("COPY", attacker)
        self.assertIn("AllowTcpForwarding local", config)
        self.assertIn("GatewayPorts no", config)
        self.assertIn("operator must author", exercise)

    def test_honeypot_targets_are_inert_and_key_reuse_is_explicit(self):
        modules = live.ROOT / "modules"
        edge = (modules / "edge-botnet" / "Containerfile").read_text()
        reuse = (modules / "key-reuse" / "Containerfile").read_text()
        jump = (modules / "corp-keyjump" / "Containerfile").read_text()
        private_key = (modules / "key-reuse" / "keys" / "id_ed25519").read_text()
        authorized_key = (
            modules / "corp-keyjump" / "keys" / "authorized_key.pub"
        ).read_text().strip()
        public_key = (
            modules / "key-reuse" / "keys" / "id_ed25519.pub"
        ).read_text().strip()

        self.assertNotIn("curl http", edge)
        self.assertNotIn("wget http", edge)
        self.assertIn("admin:admin", edge)
        self.assertIn("COPY keys/id_ed25519", reuse)
        self.assertIn("PasswordAuthentication no", jump)
        self.assertTrue(private_key.startswith("-----BEGIN OPENSSH PRIVATE KEY-----"))
        self.assertEqual(authorized_key, public_key)

    def test_live_dashboard_marks_the_verified_tunnel_as_closed(self):
        source = (live.ROOT / "keystone" / "live.py").read_text()
        self.assertIn("ssh-tunnel-corp-probe", source)
        self.assertIn("verified, closed", source)
        self.assertIn('"edge_used"', source)

    def test_compose_uses_real_contexts_and_external_networks(self):
        with tempfile.TemporaryDirectory() as tmp:
            generator.generate(str(live.ROOT / "modules"), tmp)
            compose = (Path(tmp) / "compose.yaml").read_text()
            self.assertEqual(compose.count("external: true"), 4)
            self.assertEqual(compose.count('profiles: ["needs-app"]'), 0)
            self.assertNotIn("context: ./modules", compose)
            self.assertIn("container_name: keystone-edge-upload", compose)

    def test_firewall_does_not_flush_unrelated_rules(self):
        fw = generator.build_firewall([])
        self.assertNotIn("flush ruleset", fw)
        self.assertIn("delete table inet keystone", fw)
        self.assertIn("policy drop", fw)

    def test_probe_execution_error_is_not_a_successful_denial(self):
        for result in [subprocess.CompletedProcess([], 127, "", "python missing"),
                       subprocess.CompletedProcess([], 1, "", "container absent")]:
            with patch.object(live.sp, "run", return_value=result):
                with self.assertRaises(RuntimeError):
                    live.tcp("missing", "10.80.30.250", 8200)

    def test_module_ip_comes_from_generated_topology(self):
        topology = {"nodes": [{"id": "edge-upload", "ip": "10.80.10.99"}]}
        with patch.object(live, "read", return_value=topology):
            self.assertEqual(live.module_ip("edge-upload"), "10.80.10.99")
            with self.assertRaises(RuntimeError):
                live.module_ip("missing")

    def test_live_probes_pin_mac_and_flush_stale_neighbors(self):
        source = (live.ROOT / "keystone" / "live.py").read_text()
        self.assertIn('"--mac-address", mac', source)
        self.assertIn('"ip", "neigh", "flush"', source)

    def test_socket_timeout_is_reported_as_denial(self):
        with patch.object(live.sp, "run", return_value=subprocess.CompletedProcess([], 1, "TimeoutError: timed out", "")):
            self.assertEqual(live.tcp("attacker", "10.80.30.250", 8200), (False, "TimeoutError: timed out"))

    def test_secure_directory_cannot_be_inside_project(self):
        with patch.dict(live.os.environ, {"KEYSTONE_SECURE_DIR": str(live.ROOT / "runs" / "bad")}):
            with self.assertRaises(RuntimeError):
                live.secure_dir()

    def test_publish_refuses_unverified_range(self):
        with patch.object(live, "read", return_value={"segmentation_passed": False}):
            with self.assertRaises(RuntimeError):
                live.publish("idle")


if __name__ == "__main__":
    unittest.main()
