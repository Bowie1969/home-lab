import json
import tempfile
import unittest
from pathlib import Path

from scripts import keystone_full_topology as topology


class FullTopologyPresentationTests(unittest.TestCase):
    def test_friendly_names_and_segments_preserve_network_model(self):
        with tempfile.TemporaryDirectory() as temp:
            build = Path(temp)
            (build / "topology.json").write_text(json.dumps({
                "zones": ["attacker", "dmz", "corp", "data"],
                "nodes": [
                    {"id": "attacker", "label": "operator", "zone": "attacker", "ip": "10.80.0.10"},
                    {"id": "drop01", "label": "drop01", "zone": "corp", "ip": "10.80.20.20"},
                    {"id": "portal-sqli", "label": "portal-sqli", "zone": "dmz", "ip": "10.80.10.20"},
                    {"id": "ks-ws01", "label": "ks-ws01", "zone": "corp", "ip": "10.80.20.21"},
                    {"id": "dc-roast", "label": "dc01", "zone": "corp", "ip": "10.80.20.22"},
                ],
                "edges": [{"src": "attacker", "dst": "portal-sqli", "kind": "network"}],
            }))
            (build / "live-state.json").write_text(json.dumps({
                "selected": ["drop01", "portal-sqli", "ks-ws01", "dc-roast"],
            }))

            result = topology.build_full_topology(build)
            nodes = {node["id"]: node for node in result["nodes"]}
            self.assertEqual(nodes["attacker"]["label"], "Red Team Control Station")
            self.assertTrue(nodes["attacker"]["operator_platform"])
            self.assertEqual(nodes["drop01"]["label"], "Guest Network Kiosk")
            self.assertEqual(nodes["drop01"]["zone"], "guest")
            self.assertEqual(nodes["portal-sqli"]["zone"], "ksdmz")
            self.assertEqual(nodes["ks-ws01"]["zone"], "privileged")
            self.assertEqual(nodes["dc-roast"]["zone"], "identity")
            self.assertEqual(nodes["drop01"]["network_zone"], "corp")
            self.assertEqual(result["edges"][0]["src"], "attacker")
            self.assertEqual(result["edges"][0]["dst"], "portal-sqli")


if __name__ == "__main__":
    unittest.main()
