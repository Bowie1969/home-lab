"""SD-card range pack tooling tests — pack, verify, tamper, load, status.

Exercises keystone.sdcard against a temporary directory standing in for a
card mount and a temporary estates dir standing in for the repo, so no real
SD hardware or repo mutation is needed. Pure stdlib.
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

from keystone import sdcard  # noqa: E402


def run_cmd(argv):
    """Run a sdcard command with stdout+stderr captured; returns (rc, output)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = sdcard.main(argv)
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


class SdcardToolingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        base = Path(cls._tmp.name)
        cls.cards = base / "cards"
        cls.estates = base / "estates"
        cls.cards.mkdir()
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

        cls._orig_estates = sdcard.ESTATES_DIR
        sdcard.ESTATES_DIR = cls.estates

    @classmethod
    def tearDownClass(cls):
        sdcard.ESTATES_DIR = cls._orig_estates
        cls._tmp.cleanup()

    def _card(self, name: str) -> Path:
        card = self.cards / name
        card.mkdir(exist_ok=True)
        return card

    def test_pack_and_verify(self):
        card = self._card("a")
        rc, out = run_cmd(["pack", "test-range", str(card)])
        self.assertEqual(rc, 0, out)
        self.assertIn("packed test-range", out)
        pack_dir = card / "keystone-ranges" / "test-range"
        self.assertTrue((pack_dir / "RANGE_ID").is_file())
        self.assertTrue((pack_dir / "manifest.sha256").is_file())
        rc, out = run_cmd(["verify", str(card)])
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

        card = self._card("g")
        rc, out = run_cmd(["pack", "pycache-range", str(card)])
        self.assertEqual(rc, 0, out)
        pack_dir = card / "keystone-ranges" / "pycache-range"
        self.assertFalse((pack_dir / "__pycache__").exists())
        self.assertEqual(
            sorted(p.name for p in pack_dir.rglob("*") if p.is_file()),
            ["RANGE_ID", "manifest.sha256", "services.py", "topology.json"])
        manifest = json.loads((pack_dir / "manifest.sha256").read_text())
        self.assertIn("services.py", manifest["files"])
        self.assertFalse([f for f in manifest["files"] if f.endswith(".pyc")])
        rc, out = run_cmd(["verify", str(card)])
        self.assertEqual(rc, 0, out)

    def test_tamper_detected(self):
        card = self._card("b")
        run_cmd(["pack", "test-range", str(card)])
        notes = card / "keystone-ranges" / "test-range" / "notes.txt"
        notes.write_text("tampered\n")
        rc, out = run_cmd(["verify", str(card)])
        self.assertEqual(rc, 1)
        self.assertIn("hash mismatch: notes.txt", out)

    def test_status_lists_ranges(self):
        card = self._card("c")
        run_cmd(["pack", "test-range", str(card)])
        rc, out = run_cmd(["status", "--mount", str(card)])
        self.assertEqual(rc, 0, out)
        self.assertIn("range=test-range", out)

    def test_load_refuses_without_force(self):
        card = self._card("d")
        run_cmd(["pack", "test-range", str(card)])
        rc, out = run_cmd(["load", str(card)])
        self.assertEqual(rc, 4, out)
        self.assertIn("--force", out)

    def test_load_imports_card_content(self):
        card = self._card("e")
        run_cmd(["pack", "test-range", str(card)])
        (self.estates / "test-range" / "notes.txt").write_text("repo changed\n")
        rc, out = run_cmd(["load", str(card), "--force"])
        self.assertEqual(rc, 0, out)
        loaded = (self.estates / "test-range" / "notes.txt").read_text()
        self.assertEqual(loaded, "fixture notes\n")

    def test_load_rejects_bad_topology(self):
        card = self._card("f")
        run_cmd(["pack", "bad-range", str(card)])
        shutil.rmtree(self.estates / "bad-range")
        rc, out = run_cmd(["load", str(card), "--estate", "bad-range"])
        self.assertEqual(rc, 5, out)
        self.assertIn("topology.json", out)

    # --- one range per card ----------------------------------------------------

    def test_pack_refuses_second_range(self):
        card = self._card("h")
        rc, out = run_cmd(["pack", "playable-range", str(card)])
        self.assertEqual(rc, 0, out)
        rc, out = run_cmd(["pack", "secrets-range", str(card)])
        self.assertEqual(rc, 6, out)
        self.assertIn("one range per card", out)
        self.assertIn("playable-range", out)
        # the refusal wrote nothing
        self.assertEqual(sorted(p.name for p in (card / "keystone-ranges").iterdir()),
                         ["playable-range"])

    def test_pack_refuses_second_range_even_when_first_is_unverified(self):
        card = self._card("i")
        (card / "keystone-ranges" / "handwritten-range").mkdir(parents=True)
        rc, out = run_cmd(["pack", "playable-range", str(card)])
        self.assertEqual(rc, 6, out)
        self.assertIn("handwritten-range", out)

    # --- plug and play ---------------------------------------------------------

    def test_play_runs_estate_from_card(self):
        card = self._card("j")
        rc, out = run_cmd(["pack", "playable-range", str(card)])
        self.assertEqual(rc, 0, out)
        rc, out = run_cmd(["play", str(card), "--no-wait"])
        self.assertEqual(rc, 0, out)
        self.assertIn("verified: playable-range", out)
        self.assertIn("Playable Fixture Range", out)
        self.assertIn("demo", out)
        self.assertRegex(out, r"port=\d+")
        self.assertIn("DESIGN.md", out)
        # the estate ran off the card and was never copied into the tree
        self.assertFalse((self.estates / "playable-range" / "notes.txt").exists())
        self.assertNotIn("KEYSTONE{", out)

    def test_play_supplies_required_build_args(self):
        card = self._card("k")
        run_cmd(["pack", "secrets-range", str(card)])
        rc, out = run_cmd(["play", str(card), "--no-wait"])
        self.assertEqual(rc, 0, out)
        self.assertIn("launch secrets", out)
        self.assertRegex(out, r"deploy_token = secrets-range-deploy_token-[0-9a-f]{8}")

    def test_play_refuses_multi_range_card(self):
        card = self._card("l")
        run_cmd(["pack", "playable-range", str(card)])
        (card / "keystone-ranges" / "sneaked-in").mkdir()
        rc, out = run_cmd(["play", str(card), "--no-wait"])
        self.assertEqual(rc, 6, out)
        self.assertIn("one range per card", out)
        self.assertIn("sneaked-in", out)

    def test_play_refuses_tampered_card(self):
        card = self._card("m")
        run_cmd(["pack", "playable-range", str(card)])
        (card / "keystone-ranges" / "playable-range" / "services.py").write_text(
            "def build_estate(tmp):\n    return {}\n")
        rc, out = run_cmd(["play", str(card), "--no-wait"])
        self.assertEqual(rc, 3, out)
        self.assertIn("hash mismatch: services.py", out)

    def test_play_reports_live_range_estate(self):
        card = self._card("n")
        run_cmd(["pack", "test-range", str(card)])  # topology + notes, no services.py
        rc, out = run_cmd(["play", str(card), "--no-wait"])
        self.assertEqual(rc, 7, out)
        self.assertIn("no services.py", out)
        self.assertIn("launch.sh", out)

    def test_play_does_not_write_to_the_card(self):
        """Running an estate off a card must not mutate the card.

        Importing services.py from the card used to make CPython drop a
        __pycache__/services.cpython-3XX.pyc beside it, so one `play` left the
        card failing its own manifest as an unexpected file.
        """
        card = self._card("p")
        rc, out = run_cmd(["pack", "playable-range", str(card)])
        self.assertEqual(rc, 0, out)
        pack_dir = card / "keystone-ranges" / "playable-range"
        listing = lambda: sorted(
            p.relative_to(pack_dir).as_posix() for p in pack_dir.rglob("*") if p.is_file())
        before = listing()

        # Force bytecode writing on for the duration: if the suppression in
        # _load_services_module ever regresses, this test must actually catch it.
        saved = sys.dont_write_bytecode
        sys.dont_write_bytecode = False
        try:
            rc, out = run_cmd(["play", str(card), "--no-wait"])
        finally:
            sys.dont_write_bytecode = saved
        self.assertEqual(rc, 0, out)

        self.assertEqual(listing(), before, "play wrote to the card")
        self.assertFalse((pack_dir / "__pycache__").exists())
        rc, out = run_cmd(["verify", str(card)])
        self.assertEqual(rc, 0, out)
        self.assertIn("verify playable-range: OK", out)

    def test_play_errors_without_a_card(self):
        card = self._card("o")
        rc, out = run_cmd(["play", str(card), "--no-wait"])
        self.assertEqual(rc, 2, out)
        self.assertIn("no range packs", out)

    def test_scrub_redacts_flag_material(self):
        self.assertEqual(sdcard._scrub("KEYSTONE{blindforge-crown-4c91d2}"),
                         "<redacted: flag material>")
        self.assertEqual(sdcard._scrub("gc-deploy-token-9a1b"), "gc-deploy-token-9a1b")


if __name__ == "__main__":
    unittest.main()
