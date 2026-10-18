import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keystone import zones, manifest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULES = os.path.join(ROOT, "modules")


class TestZones(unittest.TestCase):
    def test_zone_of_ip(self):
        self.assertEqual(zones.zone_of_ip("10.80.10.22"), "dmz")
        self.assertEqual(zones.zone_of_ip("10.80.30.20"), "data")
        self.assertEqual(zones.zone_of_ip("8.8.8.8"), "")

    def test_segmentation_denies_attacker_to_data(self):
        self.assertFalse(zones.reachable("attacker", "data"))
        self.assertFalse(zones.reachable("dmz", "data"))
        self.assertTrue(zones.reachable("attacker", "dmz"))
        self.assertTrue(zones.reachable("dmz", "corp"))
        self.assertTrue(zones.reachable("corp", "data"))

    def test_crown_isolated_invariant(self):
        mans = manifest.discover_modules(MODULES)
        self.assertTrue(zones.crown_is_isolated(mans))

    def test_assign_ips_is_deterministic(self):
        mans = manifest.discover_modules(MODULES)
        a1 = zones.assign_ips(mans)
        a2 = zones.assign_ips(mans)
        self.assertEqual(a1, a2)
        # every assigned IP falls inside its declared zone subnet
        for a in a1:
            self.assertEqual(zones.zone_of_ip(a.ip), a.zone)

    def test_scope_detection(self):
        self.assertTrue(zones.is_in_scope("10.80.20.5"))
        self.assertFalse(zones.is_in_scope("1.1.1.1"))


if __name__ == "__main__":
    unittest.main()
