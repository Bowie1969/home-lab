import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keystone import iteration_rts


def _write_script(scripts: Path, serial: int, name: str, category: str,
                  mcp_tool: str = "malware_generate", target: str = "edge-upload",
                  parameters=(), reused_for=(), lines: int = 25,
                  include_header: bool = True, include_error: bool = True,
                  suffix: str = ".sh") -> Path:
    stem = f"{serial:04d}-{name}"
    script_path = scripts / f"{stem}{suffix}"
    body = []
    if include_header:
        body.append("#!/usr/bin/env bash")
    body.append('# RTS iteration script')
    if include_error:
        body.append("set -euo pipefail")
    for i in range(lines):
        body.append(f"echo 'step {i} on {target}'")
    script_path.write_text("\n".join(body) + "\n", encoding="utf-8")
    sidecar = scripts / f"{stem}.json"
    sidecar.write_text(json.dumps({
        "mcp_tool": mcp_tool,
        "target_node": target,
        "category": category,
        "parameters": list(parameters),
        "reused_for": list(reused_for),
        "notes": "",
    }, indent=2) + "\n", encoding="utf-8")
    return script_path


class TestIterationRTS(unittest.TestCase):
    def _run(self, populate) -> iteration_rts.OverlayResult:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "20261014-rts-fixture"
            (run_dir / "scripts").mkdir(parents=True)
            populate(run_dir / "scripts")
            return iteration_rts.score_overlay(run_dir)

    def test_empty_scripts_zero_overlay(self):
        res = self._run(lambda scripts: None)
        self.assertEqual(res.total, 0)
        self.assertEqual(res.max, iteration_rts.MAX_OVERLAY)

    def test_full_path_scores_full_overlay(self):
        def populate(scripts: Path) -> None:
            _write_script(scripts, 1, "recon", "recon", target="edge-upload",
                          parameters=["TARGET"], reused_for=["share-anon"])
            _write_script(scripts, 2, "foothold", "initial-access",
                          target="edge-upload", parameters=["WEBROOT"],
                          reused_for=["share-anon"])
            _write_script(scripts, 3, "lateral", "lateral", target="ks-ws01",
                          parameters=["CRED"], reused_for=["ks-files01"])
            _write_script(scripts, 4, "crown", "crown-id", target="vault-keystone",
                          parameters=["QUERY"], reused_for=["dc-roast"])
        res = self._run(populate)
        self.assertEqual(res.buckets["path_complete"], 4)
        self.assertEqual(res.buckets["coverage"], 8)
        self.assertEqual(res.buckets["breadth"], 3)
        self.assertEqual(res.buckets["reuse"], 6)
        self.assertEqual(res.buckets["quality"], 4)
        # Overlay max (28) requires >=6 distinct target nodes; this fixture has
        # 3 nodes exercising the full path, so breadth caps at 3 and the total
        # is 25. The ceiling is proven separately in test_full_overlay_ceiling.
        self.assertEqual(res.total, 25)

    def test_full_overlay_ceiling(self):
        """Six distinct target nodes let breadth saturate; total == MAX_OVERLAY."""
        def populate(scripts: Path) -> None:
            steps = [
                ("recon", "edge-upload"),
                ("initial-access", "share-anon"),
                ("lateral", "ks-ws01"),
                ("pivot", "ks-files01"),
                ("crown-id", "vault-keystone"),
                ("exfil", "dc-roast"),
            ]
            for idx, (cat, node) in enumerate(steps, start=1):
                _write_script(scripts, idx, cat, cat, target=node,
                              parameters=["ARG"], reused_for=["any"])
        res = self._run(populate)
        self.assertEqual(res.buckets["breadth"], 6)
        self.assertEqual(res.total, iteration_rts.MAX_OVERLAY)

    def test_missing_header_or_error_hinders_quality(self):
        def populate(scripts: Path) -> None:
            _write_script(scripts, 1, "weak", "recon", include_header=False,
                          include_error=False, parameters=[], reused_for=[])
        res = self._run(populate)
        self.assertEqual(res.buckets["quality"], 0)
        self.assertEqual(res.buckets["reuse"], 0)
        self.assertEqual(res.buckets["coverage"], 2)

    def test_unknown_category_skipped_with_note(self):
        def populate(scripts: Path) -> None:
            _write_script(scripts, 1, "bogus", "not-a-category")
        res = self._run(populate)
        self.assertEqual(res.total, 0)
        self.assertTrue(any("unknown category" in n for n in res.notes))

    def test_json_roundtrip(self):
        def populate(scripts: Path) -> None:
            _write_script(scripts, 1, "recon", "recon",
                          parameters=["T"], reused_for=["x"])
        res = self._run(populate)
        payload = json.dumps(res.to_dict())
        decoded = json.loads(payload)
        self.assertEqual(decoded["iteration"], "rts")
        self.assertEqual(decoded["max"], iteration_rts.MAX_OVERLAY)
        self.assertEqual(len(decoded["scripts"]), 1)


if __name__ == "__main__":
    unittest.main()
