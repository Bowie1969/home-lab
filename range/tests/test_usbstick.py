"""USB-stick range pack tooling tests — pack, verify, tamper, load, status.

Exercises keystone.usbstick against a temporary directory standing in for a
stick mount and a temporary estates dir standing in for the repo, so no real
USB hardware or repo mutation is needed. Pure stdlib.
"""
from __future__ import annotations

import contextlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from keystone import usbstick  # noqa: E402


def run_cmd(argv):
    """Run a usbstick command with stdout+stderr captured; returns (rc, output)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = usbstick.main(argv)
    return rc, out.getvalue() + err.getvalue()


# Stand-in estates so `play` can be tested without real hardware or a real
# range. Each binds an ephemeral port, so the runner has something to report.
FAKE_SERVICES_DEFAULTS = '''import socket


class Demo:
    def __init__(self, token=None):
        self.token = token
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self.port = self._sock.getsockname()[1]
        self.running = False

    def start(self):
        self.running = True
        return self

    def stop(self):
        self.running = False
        self._sock.close()


def build_estate(tmp, token=None):
    return {"demo": Demo(token)}
'''

FAKE_SERVICES_REQUIRED = '''import socket


class Demo:
    def __init__(self, deploy_token):
        self.deploy_token = deploy_token
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self.port = self._sock.getsockname()[1]
        self.running = False

    def start(self):
        self.running = True
        return self

    def stop(self):
        self.running = False
        self._sock.close()


def build_estate(tmp, deploy_token):
    return {"demo": Demo(deploy_token)}
'''


class UsbstickToolingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        base = Path(cls._tmp.name)
        cls.sticks = base / "sticks"
        cls.estates = base / "estates"
        cls.sticks.mkdir()
        cls.estates.mkdir()
        fixture = cls.estates / "test-range"
        fixture.mkdir()
        (fixture / "topology.json").write_text(
            json.dumps({"range": "test-range", "title": "fixture"}))
        (fixture / "notes.txt").write_text("fixture notes\n")
        bad = cls.estates / "bad-range"
        bad.mkdir()
        (bad / "topology.json").write_text("{not json")

        # Two runnable fixtures for `play`: one whose build_estate params all
        # carry defaults, one with a required param the runner must synthesise.
        playable = cls.estates / "playable-range"
        playable.mkdir()
        (playable / "topology.json").write_text(
            json.dumps({"range": "playable-range", "title": "Playable Fixture Range"}))
        (playable / "services.py").write_text(FAKE_SERVICES_DEFAULTS)

        secretful = cls.estates / "secrets-range"
        secretful.mkdir()
        (secretful / "topology.json").write_text(
            json.dumps({"range": "secrets-range", "title": "Secrets Fixture Range"}))
        (secretful / "services.py").write_text(FAKE_SERVICES_REQUIRED)

        cls._orig_estates = usbstick.ESTATES_DIR
        usbstick.ESTATES_DIR = cls.estates

    @classmethod
    def tearDownClass(cls):
        usbstick.ESTATES_DIR = cls._orig_estates
        cls._tmp.cleanup()

    def _stick(self, name: str) -> Path:
        stick = self.sticks / name
        stick.mkdir(exist_ok=True)
        return stick

    def test_pack_and_verify(self):
        stick = self._stick("a")
        rc, out = run_cmd(["pack", "test-range", str(stick)])
        self.assertEqual(rc, 0, out)
        self.assertIn("packed test-range", out)
        pack_dir = stick / "keystone-ranges" / "test-range"
        self.assertTrue((pack_dir / "RANGE_ID").is_file())
        self.assertTrue((pack_dir / "manifest.sha256").is_file())
        rc, out = run_cmd(["verify", str(stick)])
        self.assertEqual(rc, 0, out)
        self.assertIn("verify test-range: OK", out)

    def test_pack_excludes_bytecode(self):
        src = self.estates / "pycache-range"
        src.mkdir()
        (src / "topology.json").write_text(
            json.dumps({"range": "pycache-range", "title": "fixture"}))
        (src / "services.py").write_text("SERVICE = True\n")
        cache = src / "__pycache__"
        cache.mkdir()
        (cache / "services.cpython-313.pyc").write_bytes(b"\x00bytecode")

        stick = self._stick("g")
        rc, out = run_cmd(["pack", "pycache-range", str(stick)])
        self.assertEqual(rc, 0, out)
        pack_dir = stick / "keystone-ranges" / "pycache-range"
        self.assertFalse((pack_dir / "__pycache__").exists())
        self.assertEqual(
            sorted(p.name for p in pack_dir.rglob("*") if p.is_file()),
            ["RANGE_ID", "manifest.sha256", "services.py", "topology.json"])
        manifest = json.loads((pack_dir / "manifest.sha256").read_text())
        self.assertIn("services.py", manifest["files"])
        self.assertFalse([f for f in manifest["files"] if f.endswith(".pyc")])
        rc, out = run_cmd(["verify", str(stick)])
        self.assertEqual(rc, 0, out)

    def test_tamper_detected(self):
        stick = self._stick("b")
        run_cmd(["pack", "test-range", str(stick)])
        notes = stick / "keystone-ranges" / "test-range" / "notes.txt"
        notes.write_text("tampered\n")
        rc, out = run_cmd(["verify", str(stick)])
        self.assertEqual(rc, 1)
        self.assertIn("hash mismatch: notes.txt", out)

    def test_status_lists_ranges(self):
        stick = self._stick("c")
        run_cmd(["pack", "test-range", str(stick)])
        rc, out = run_cmd(["status", "--mount", str(stick)])
        self.assertEqual(rc, 0, out)
        self.assertIn("range=test-range", out)

    def test_load_refuses_without_force(self):
        stick = self._stick("d")
        run_cmd(["pack", "test-range", str(stick)])
        rc, out = run_cmd(["load", str(stick)])
        self.assertEqual(rc, 4, out)
        self.assertIn("--force", out)

    def test_load_imports_stick_content(self):
        stick = self._stick("e")
        run_cmd(["pack", "test-range", str(stick)])
        (self.estates / "test-range" / "notes.txt").write_text("repo changed\n")
        rc, out = run_cmd(["load", str(stick), "--force"])
        self.assertEqual(rc, 0, out)
        loaded = (self.estates / "test-range" / "notes.txt").read_text()
        self.assertEqual(loaded, "fixture notes\n")

    def test_load_rejects_bad_topology(self):
        stick = self._stick("f")
        run_cmd(["pack", "bad-range", str(stick)])
        shutil.rmtree(self.estates / "bad-range")
        rc, out = run_cmd(["load", str(stick), "--estate", "bad-range"])
        self.assertEqual(rc, 5, out)
        self.assertIn("topology.json", out)

    # --- one range per stick ----------------------------------------------------

    def test_pack_refuses_second_range(self):
        stick = self._stick("h")
        rc, out = run_cmd(["pack", "playable-range", str(stick)])
        self.assertEqual(rc, 0, out)
        rc, out = run_cmd(["pack", "secrets-range", str(stick)])
        self.assertEqual(rc, 6, out)
        self.assertIn("one range per stick", out)
        self.assertIn("playable-range", out)
        # the refusal wrote nothing
        self.assertEqual(sorted(p.name for p in (stick / "keystone-ranges").iterdir()),
                         ["playable-range"])

    def test_pack_refuses_second_range_even_when_first_is_unverified(self):
        stick = self._stick("i")
        (stick / "keystone-ranges" / "handwritten-range").mkdir(parents=True)
        rc, out = run_cmd(["pack", "playable-range", str(stick)])
        self.assertEqual(rc, 6, out)
        self.assertIn("handwritten-range", out)

    # --- refreshing a stale pack ------------------------------------------------

    def _refresh_fixture(self) -> Path:
        src = self.estates / "refresh-range"
        src.mkdir(exist_ok=True)
        (src / "topology.json").write_text(
            json.dumps({"range": "refresh-range", "title": "fixture"}))
        (src / "notes.txt").write_text("v1\n")
        return src

    def test_pack_refuses_an_existing_range_without_force(self):
        self._refresh_fixture()
        stick = self._stick("q")
        rc, out = run_cmd(["pack", "refresh-range", str(stick)])
        self.assertEqual(rc, 0, out)
        rc, out = run_cmd(["pack", "refresh-range", str(stick)])
        self.assertEqual(rc, 2, out)
        self.assertIn("--force", out)

    def test_pack_force_replaces_rather_than_merges(self):
        src = self._refresh_fixture()
        (src / "obsolete.pyc").write_bytes(b"\x00host-specific bytecode")
        stick = self._stick("r")
        rc, out = run_cmd(["pack", "refresh-range", str(stick)])
        self.assertEqual(rc, 0, out)
        # the estate is fixed in the tree: one file dropped, another corrected
        (src / "obsolete.pyc").unlink()
        (src / "notes.txt").write_text("v2 fixed\n")
        rc, out = run_cmd(["pack", "refresh-range", str(stick), "--force"])
        self.assertEqual(rc, 0, out)
        self.assertIn("replacing stale refresh-range", out)
        pack_dir = stick / "keystone-ranges" / "refresh-range"
        self.assertFalse((pack_dir / "obsolete.pyc").exists(),
                         "a file the old pack carried must not survive a refresh")
        self.assertEqual((pack_dir / "notes.txt").read_text(), "v2 fixed\n")
        rc, out = run_cmd(["verify", str(stick)])
        self.assertEqual(rc, 0, out)
        self.assertIn("verify refresh-range: OK", out)

    def test_pack_force_never_touches_anything_else_on_the_stick(self):
        src = self._refresh_fixture()
        stick = self._stick("s")
        # stand-ins for the irreplaceable business backups the real range stick
        # carries beside keystone-ranges/ — a refresh must leave them alone
        (stick / "Quest Rockhampton.MYO").write_bytes(b"accounting data")
        (stick / "TEMPLATES").mkdir()
        (stick / "TEMPLATES" / "invoice.doc").write_text("template\n")

        def others():
            return {str(p.relative_to(stick)): usbstick._sha256(p)
                    for p in sorted(stick.rglob("*"))
                    if p.is_file() and "keystone-ranges" not in p.parts}

        before = others()
        run_cmd(["pack", "refresh-range", str(stick)])
        (src / "notes.txt").write_text("v3\n")
        rc, out = run_cmd(["pack", "refresh-range", str(stick), "--force"])
        self.assertEqual(rc, 0, out)
        self.assertEqual(others(), before, "force touched files outside the range pack")

    def test_pack_force_cannot_add_a_second_range(self):
        stick = self._stick("t")
        rc, out = run_cmd(["pack", "playable-range", str(stick)])
        self.assertEqual(rc, 0, out)
        rc, out = run_cmd(["pack", "secrets-range", str(stick), "--force"])
        self.assertEqual(rc, 6, out)
        self.assertIn("one range per stick", out)
        self.assertEqual(sorted(p.name for p in (stick / "keystone-ranges").iterdir()),
                         ["playable-range"], "force must not be a way around one-range-per-stick")
        rc, out = run_cmd(["verify", str(stick)])
        self.assertEqual(rc, 0, out)

    # --- plug and play ---------------------------------------------------------

    def test_play_runs_estate_from_stick(self):
        stick = self._stick("j")
        rc, out = run_cmd(["pack", "playable-range", str(stick)])
        self.assertEqual(rc, 0, out)
        rc, out = run_cmd(["play", str(stick), "--no-wait"])
        self.assertEqual(rc, 0, out)
        self.assertIn("verified: playable-range", out)
        self.assertIn("Playable Fixture Range", out)
        self.assertIn("demo", out)
        self.assertRegex(out, r"port=\d+")
        self.assertIn("DESIGN.md", out)
        # the estate ran off the stick and was never copied into the tree
        self.assertFalse((self.estates / "playable-range" / "notes.txt").exists())
        self.assertNotIn("KEYSTONE{", out)

    def test_play_supplies_required_build_args(self):
        stick = self._stick("k")
        run_cmd(["pack", "secrets-range", str(stick)])
        rc, out = run_cmd(["play", str(stick), "--no-wait"])
        self.assertEqual(rc, 0, out)
        self.assertIn("launch secrets", out)
        self.assertRegex(out, r"deploy_token = secrets-range-deploy_token-[0-9a-f]{8}")

    def test_play_refuses_multi_range_stick(self):
        stick = self._stick("l")
        run_cmd(["pack", "playable-range", str(stick)])
        (stick / "keystone-ranges" / "sneaked-in").mkdir()
        rc, out = run_cmd(["play", str(stick), "--no-wait"])
        self.assertEqual(rc, 6, out)
        self.assertIn("one range per stick", out)
        self.assertIn("sneaked-in", out)

    def test_play_refuses_tampered_stick(self):
        stick = self._stick("m")
        run_cmd(["pack", "playable-range", str(stick)])
        (stick / "keystone-ranges" / "playable-range" / "services.py").write_text(
            "def build_estate(tmp):\n    return {}\n")
        rc, out = run_cmd(["play", str(stick), "--no-wait"])
        self.assertEqual(rc, 3, out)
        self.assertIn("hash mismatch: services.py", out)

    def test_play_reports_live_range_estate(self):
        stick = self._stick("n")
        run_cmd(["pack", "test-range", str(stick)])  # topology + notes, no services.py
        rc, out = run_cmd(["play", str(stick), "--no-wait"])
        self.assertEqual(rc, 7, out)
        self.assertIn("no services.py", out)
        self.assertIn("launch.sh", out)

    def test_play_does_not_write_to_the_stick(self):
        """Running an estate off a stick must not mutate the stick.

        Importing services.py from the stick used to make CPython drop a
        __pycache__/services.cpython-3XX.pyc beside it, so one `play` left the
        stick failing its own manifest as an unexpected file.
        """
        stick = self._stick("p")
        rc, out = run_cmd(["pack", "playable-range", str(stick)])
        self.assertEqual(rc, 0, out)
        pack_dir = stick / "keystone-ranges" / "playable-range"
        listing = lambda: sorted(
            p.relative_to(pack_dir).as_posix() for p in pack_dir.rglob("*") if p.is_file())
        before = listing()

        # Force bytecode writing on for the duration: if the suppression in
        # _load_services_module ever regresses, this test must actually catch it.
        saved = sys.dont_write_bytecode
        sys.dont_write_bytecode = False
        try:
            rc, out = run_cmd(["play", str(stick), "--no-wait"])
        finally:
            sys.dont_write_bytecode = saved
        self.assertEqual(rc, 0, out)

        self.assertEqual(listing(), before, "play wrote to the stick")
        self.assertFalse((pack_dir / "__pycache__").exists())
        rc, out = run_cmd(["verify", str(stick)])
        self.assertEqual(rc, 0, out)
        self.assertIn("verify playable-range: OK", out)

    def test_play_errors_without_a_stick(self):
        stick = self._stick("o")
        rc, out = run_cmd(["play", str(stick), "--no-wait"])
        self.assertEqual(rc, 2, out)
        self.assertIn("no range packs", out)

    def test_scrub_redacts_flag_material(self):
        self.assertEqual(usbstick._scrub("KEYSTONE{blindforge-crown-4c91d2}"),
                         "<redacted: flag material>")
        self.assertEqual(usbstick._scrub("gc-deploy-token-9a1b"), "gc-deploy-token-9a1b")


if __name__ == "__main__":
    unittest.main()
