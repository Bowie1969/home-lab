"""Regressions for the 2026-10-16 corp expansion: three new container modules
(modelhub-pickle, ntlm-relay-corp, bmc-super) and their graph/CVE/evidence
grounding. Follows tests/test_manifest.py conventions."""
import json
import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keystone import generator
from keystone import manifest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULES = os.path.join(ROOT, "modules")

SIGNAL_RE = re.compile(r"^[a-z-]+: .+$")


def _signal_text(signal):
    """Normalize a signal to "kind: text" form (miniyaml parses `- kind: text`
    list items as single-key dicts)."""
    if isinstance(signal, dict):
        assert len(signal) == 1, f"signal dict must have exactly one key: {signal!r}"
        kind, text = next(iter(signal.items()))
        return f"{kind}: {text}"
    return str(signal)


class TestExpansionGraph(unittest.TestCase):
    def setUp(self):
        self.mans = {m.id: m for m in manifest.discover_modules(MODULES)}

    def test_graph_targets_exist(self):
        for m in self.mans.values():
            for target in list(m.prereqs) + list(m.enables):
                self.assertIn(target, self.mans,
                              f"{m.id} references unknown module {target!r}")

    def test_new_modules_typed(self):
        expected = {
            "modelhub-pickle": "ai-supply-chain",
            "ntlm-relay-corp": "broadcast-cred-harvest",
            "bmc-super": "oob-management",
        }
        for module_id, technique_class in expected.items():
            self.assertIn(module_id, self.mans)
            m = self.mans[module_id]
            self.assertEqual(m.technique_class, technique_class)
            self.assertEqual(m.network_zone, "corp")
            self.assertEqual(m.substrate, "container")
            self.assertTrue(m.prereqs, f"{module_id} must have non-empty prereqs")

    def test_cve_grounding_is_real(self):
        modelhub = self.mans["modelhub-pickle"]
        self.assertEqual(modelhub.vulnerability["cves"],
                         ["CVE-2025-1716", "CVE-2026-7482"])
        self.assertTrue(modelhub.vulnerability.get("source"))

        bmc = self.mans["bmc-super"]
        self.assertEqual(bmc.vulnerability["cves"],
                         ["CVE-2025-12006", "CVE-2026-3821"])
        self.assertTrue(bmc.vulnerability.get("source"))

        # ntlm-relay-corp is a technique module, not a CVE claim: it carries no
        # vulnerability block and no fabricated CVE IDs anywhere in its manifest.
        ntlm = self.mans["ntlm-relay-corp"]
        self.assertEqual(ntlm.vulnerability, {})
        with open(os.path.join(ntlm.path, "manifest.yaml"), encoding="utf-8") as fh:
            self.assertNotIn("CVE-", fh.read())

    def test_evidence_signals_wellformed(self):
        for m in self.mans.values():
            signals = (m.evidence or {}).get("signals") or []
            for signal in signals:
                self.assertRegex(_signal_text(signal), SIGNAL_RE,
                                 f"{m.id} signal badly shaped: {signal!r}")

    def test_topology_includes_new_hostnames(self):
        with tempfile.TemporaryDirectory(prefix="keystone-expansion-") as tmp:
            generator.generate(MODULES, tmp)
            with open(os.path.join(tmp, "topology.json"), encoding="utf-8") as fh:
                topo = json.load(fh)
        corp_nodes = {n["label"] for n in topo["nodes"] if n["zone"] == "corp"}
        self.assertIn("modelhub01", corp_nodes)
        self.assertIn("workstation-noisy", corp_nodes)
        self.assertIn("bmc-super", corp_nodes)
        for label in ("modelhub01", "workstation-noisy", "bmc-super"):
            node = next(n for n in topo["nodes"] if n["label"] == label)
            self.assertEqual(node["zone"], "corp")


if __name__ == "__main__":
    unittest.main()
