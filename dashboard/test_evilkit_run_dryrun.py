"""Integration proof that EvilKit dashboard telemetry satisfies the board contract.

Runs the Cyber Operator dry-run script against an isolated runs tree and
verifies, using this dashboard's own server.py, that:

  (a) find_live_run picks the EvilKit sample run over live-brain,
  (b) run_focus reports the compromised host (g911) -> red,
  (c) the SSH tunnel edge stays connected 30s after edge_connected.
"""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path


DRYRUN = (
    Path.home()
    / "Dropbox"
    / "Shared Workspace"
    / "Cyber Operator"
    / "dryrun_dashboard_run.py"
)


class EvilKitRunDryrunTests(unittest.TestCase):
    def test_dryrun_passes_dashboard_contract(self):
        result = subprocess.run(
            [sys.executable, str(DRYRUN), "--state", "running"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        output = result.stdout
        self.assertIn("PASS (a): sample run outranks live-brain", output)
        self.assertIn("PASS (b): g911 is reported compromised (board turns red)", output)
        self.assertIn(
            "PASS (c): SSH tunnel edge still connected 30s after edge_connected",
            output,
        )


if __name__ == "__main__":
    unittest.main()
