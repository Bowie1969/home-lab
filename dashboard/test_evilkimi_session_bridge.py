import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path


spec = importlib.util.spec_from_file_location(
    "evilkimi_session_bridge",
    Path(__file__).parent / "scripts" / "evilkimi_session_bridge.py",
)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class EvilKimiSessionBridgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.run_dir = self.root / "evilkimi-live-test"
        dashboard = self.run_dir / "dashboard"
        dashboard.mkdir(parents=True)
        (dashboard / "topology.json").write_text(json.dumps({"nodes": [
            {"id": "pi-drop", "label": "Mini Evil Kit Pi", "address": "10.10.66.143"},
            {"id": "g960", "label": "drop01", "address": "10.99.50.60"},
            {"id": "g911", "label": "edge01", "address": "10.99.50.11"},
            {"id": "g912", "label": "bot01", "address": "10.99.50.21"},
        ]}), encoding="utf-8")
        (dashboard / "events.jsonl").write_text("", encoding="utf-8")
        self.bridge = m.Bridge(self.run_dir, "sid1234", "pi-drop", "evilkimi", sync_topology=False)

    def tearDown(self):
        self.tmp.cleanup()

    def _events(self):
        text = (self.run_dir / "dashboard" / "events.jsonl").read_text().strip()
        return [json.loads(line) for line in text.splitlines()] if text else []

    def test_operator_seat_is_never_a_target(self):
        self.assertNotIn("10.10.66.143", self.bridge.ip2node)
        self.assertEqual(self.bridge.ip2node["10.99.50.60"], "g960")

    def test_successful_attack_marks_the_host_compromised(self):
        self.bridge.handle({"kind": "action", "ts": 1.0, "tool": "netexec",
                            "command": "nxc smb 10.99.50.11 -u a -p b", "returncode": 0})
        kinds = [e["event"] for e in self._events()]
        self.assertIn("host_compromised", kinds)
        self.assertIn("agent_on_host", kinds)
        status = json.loads((self.run_dir / "dashboard" / "status.json").read_text())
        self.assertEqual([h["id"] for h in status["compromised_hosts"]], ["g911"])
        self.assertEqual(status["state"], "running")
        self.assertEqual(self.bridge.current_node, "g911")

    def test_failed_attack_is_only_an_edge(self):
        self.bridge.handle({"kind": "action", "ts": 1.0, "tool": "nxc",
                            "command": "nxc smb 10.99.50.11 -u a -p b", "returncode": 1})
        self.assertNotIn("host_compromised", [e["event"] for e in self._events()])

    def test_pre_records_and_unknown_targets_are_ignored(self):
        self.bridge.handle({"kind": "pre", "ts": 1.0, "tool": "Bash",
                            "command": "nmap 10.99.50.11", "decision": "allow"})
        self.bridge.handle({"kind": "action", "ts": 2.0, "tool": "Bash",
                            "command": "ping 10.99.50.250", "returncode": 0})
        self.assertEqual(self._events(), [])

    def test_stale_session_starts_finished_and_wakes_on_an_action(self):
        stale = self.root / "session_old.jsonl"
        stale.write_text("", encoding="utf-8")
        os.utime(stale, (1, 1))
        self.bridge.adopt(stale)
        self.assertEqual(self.bridge._state, "finished")
        self.bridge.handle({"kind": "action", "ts": 1.0, "tool": "Bash", "returncode": 0,
                            "command": "nxc smb 10.99.50.11 -u a -p b"})
        self.assertEqual(self.bridge._state, "running")

    def test_shell_through_the_seat_owns_the_range_host(self):
        """The live shape: everything is wrapped in `ssh <seat> '<work>'`."""
        self.bridge.handle({
            "kind": "action", "ts": 1.0, "tool": "Bash", "returncode": 0,
            "command": ("Bash ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "
                        "-i ~/.ssh/id_ed25519_evilkimi_pi root@10.99.50.11 "
                        "'echo ROOT_OK; hostname; id; cat /etc/shadow' 2>&1")})
        events = self._events()
        owned = [e for e in events if e["event"] == "host_compromised"]
        self.assertEqual([e["node"] for e in owned], ["g911"])
        self.assertIn("ssh session opened", owned[0]["evidence"])
        self.assertEqual(self.bridge.current_node, "g911")
        self.assertNotIn("10.10.66.143", [e.get("host") for e in events])

    def test_shell_login_that_failed_is_not_a_compromise(self):
        self.bridge.handle({
            "kind": "action", "ts": 1.0, "tool": "Bash", "returncode": 1,
            "command": ("Bash ssh -i ~/.ssh/id_ed25519_evilkimi_pi root@10.99.50.11 "
                        "'echo ROOT_OK' 2>&1")})
        kinds = [e["event"] for e in self._events()]
        self.assertNotIn("host_compromised", kinds)
        self.assertEqual(kinds, ["recon"])

    def test_command_execution_request_is_an_attempt_not_proof(self):
        """curl exits 0 for an HTTP error, so an accepted request is not access."""
        self.bridge.handle({
            "kind": "action", "ts": 1.0, "tool": "Bash", "returncode": 0,
            "command": ("Bash curl -s -m 5 -X POST http://10.99.50.21:9001/ "
                        "-H 'Content-Type: application/json' -d '{\"cmd\": \"id\"}'")})
        events = self._events()
        self.assertEqual([e["event"] for e in events], ["exploit"])
        self.assertEqual(events[0]["edge"]["traffic_class"], "attack")
        status = json.loads((self.run_dir / "dashboard" / "status.json").read_text())
        self.assertEqual(status["compromised_hosts"], [])

    def test_comment_wording_is_not_an_attack_tool(self):
        """The live false positive: `# exploit ...` in a comment owned a probed host."""
        self.bridge.handle({
            "kind": "action", "ts": 1.0, "tool": "Bash", "returncode": 0,
            "command": ("Bash ssh -i key pi@10.10.66.143 'sudo -n bash -c \"\n"
                        "# Exploit the fail2ban banner hint on 10.99.50.11\n"
                        "for host in 10.99.50.11 10.99.50.31; do "
                        "timeout 3 bash -c \\\"cat < /dev/tcp/$host/22\\\"; done\"'")})
        events = self._events()
        self.assertNotIn("host_compromised", [e["event"] for e in events])
        self.assertEqual(self.bridge.compromised, {})

    def test_unproven_login_inside_a_wrapper_is_not_a_compromise(self):
        """The status covers the wrapper's last statement, not every attempt in it."""
        self.bridge.handle({
            "kind": "action", "ts": 1.0, "tool": "Bash", "returncode": 0,
            "command": ("Bash ssh -i key pi@10.10.66.143 'sudo -n bash -c \"\n"
                        "sshpass -p Pr0gress\\\\!2026 -l svc_backup 10.99.50.11 hostname\n"
                        "curl -s -m 5 http://10.99.50.21:9001/ -d \\'{\"cmd\": \"id\"}\\'\"'")})
        self.assertNotIn("host_compromised", [e["event"] for e in self._events()])

    def test_recon_through_the_seat_is_only_a_coloured_edge(self):
        self.bridge.handle({
            "kind": "action", "ts": 1.0, "tool": "Bash", "returncode": 0,
            "command": ("Bash ssh -i ~/.ssh/id_ed25519_evilkimi_pi pi@10.10.66.143 "
                        "'sudo -n bash -c \"nmap -sV 10.99.50.11\"'")})
        events = self._events()
        self.assertEqual([e["event"] for e in events], ["recon"])
        self.assertEqual(events[0]["node"], "g911")
        self.assertNotIn("host_compromised", [e["event"] for e in events])
        self.assertEqual(self.bridge.current_node, "pi-drop")

    def test_action_host_is_the_statement_target(self):
        """`ssh hop ... probe <target>` still opens the session the status proves."""
        self.bridge.handle({
            "kind": "action", "ts": 1.0, "tool": "Bash", "returncode": 0,
            "command": ("Bash ssh -i key root@10.99.50.11 "
                        "'curl -s -m 5 http://10.99.50.21:9001/status'")})
        events = self._events()
        self.assertEqual(events[0]["node"], "g911")
        self.assertIn("host_compromised", [e["event"] for e in events])

    def test_discover_prefers_a_session_that_carries_actions(self):
        sessions = self.root / "state" / "sessions"
        sessions.mkdir(parents=True)
        bare = sessions / "session_bare.jsonl"
        bare.write_text(json.dumps({"kind": "session_start", "ts": 999}) + "\n", encoding="utf-8")
        live = sessions / "session_live.jsonl"
        live.write_text(json.dumps({"kind": "action", "ts": 1, "tool": "Bash",
                                    "command": "nmap 10.99.50.11", "returncode": 0}) + "\n",
                        encoding="utf-8")
        os.utime(bare, (999, 999))          # bare log is newer on disk
        os.utime(live, (1, 1))
        self.assertEqual(m.discover_session(self.root / "state").name, "session_live.jsonl")


if __name__ == "__main__":
    unittest.main()
