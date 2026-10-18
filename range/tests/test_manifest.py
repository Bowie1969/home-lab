import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keystone import manifest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULES = os.path.join(ROOT, "modules")


class TestManifest(unittest.TestCase):
    def test_all_modules_load(self):
        mans = manifest.discover_modules(MODULES)
        self.assertGreaterEqual(len(mans), 15)

    def test_distinct_initial_access_vectors(self):
        # 10 original DMZ vectors + drop01 (physical-plant) + edge-botnet
        # (ingress-tool-transfer): the planted dropbox is the 11th, independent
        # way in; edge-botnet is the 12th — a neglected IoT-style box added from
        # the Cowrie honeypot capture so EvilKit's loader emulation has a target.
        mans = manifest.discover_modules(MODULES)
        ia = [m for m in mans if m.is_initial_access]
        classes = {m.technique_class for m in ia}
        self.assertEqual(len(ia), 12, "expected exactly 12 initial-access modules")
        self.assertEqual(len(classes), 12, "each initial-access vector must be a distinct class")

    def test_crown_module_present_and_in_data(self):
        mans = {m.id: m for m in manifest.discover_modules(MODULES)}
        self.assertIn("vault-keystone", mans)
        self.assertEqual(mans["vault-keystone"].network_zone, "data")
        self.assertFalse(mans["vault-keystone"].is_initial_access)

    def test_honeypot_ttp_chain_crosses_dmz_into_corp(self):
        mans = {m.id: m for m in manifest.discover_modules(MODULES)}

        edge = mans["edge-botnet"]
        self.assertTrue(edge.is_initial_access)
        self.assertEqual(edge.technique_class, "ingress-tool-transfer")
        self.assertEqual(edge.network_zone, "dmz")
        self.assertIn("key-reuse", edge.enables)

        reuse = mans["key-reuse"]
        self.assertEqual(reuse.technique_class, "ssh-key-reuse")
        self.assertEqual(reuse.network_zone, "dmz")
        self.assertEqual(set(reuse.prereqs), {"edge-botnet", "ssh-weak"})
        self.assertIn("corp-keyjump", reuse.enables)

        jump = mans["corp-keyjump"]
        self.assertEqual(jump.technique_class, "ssh-key-reuse")
        self.assertEqual(jump.network_zone, "corp")
        self.assertEqual(jump.prereqs, ["key-reuse"])
        self.assertIn("ubuntu-dirtycow", jump.enables)

    def test_at_least_one_vm(self):
        mans = manifest.discover_modules(MODULES)
        self.assertTrue(any(m.substrate == "vm" for m in mans))

    def test_known_exploit_depth_pack(self):
        mans = {m.id: m for m in manifest.discover_modules(MODULES)}
        expected = {
            "win7-eternalblue": "CVE-2017-0144",
            "samba-45": "CVE-2017-7494",
            "ubuntu-dirtycow": "CVE-2016-5195",
            "mac-debian13": "CVE-2025-32463",
        }
        for module_id, cve in expected.items():
            self.assertIn(module_id, mans)
            self.assertIn(cve, mans[module_id].vulnerability["cves"])
            self.assertFalse(mans[module_id].is_initial_access)
        self.assertEqual(mans["mac-debian13"].substrate, "physical")
        self.assertEqual(mans["mac-debian13"].hostname, "mac-debian13")

    def test_graph_referential_integrity(self):
        # discover_modules runs _check_graph; a dangling ref would raise.
        manifest.discover_modules(MODULES)

    def test_missing_required_field(self):
        with self.assertRaises(manifest.ManifestError):
            manifest.validate_manifest({"id": "x", "technique_class": "web-rce",
                                        "substrate": "container"})  # no zone

    def test_unknown_technique_class(self):
        with self.assertRaises(manifest.ManifestError):
            manifest.validate_manifest({"id": "x", "technique_class": "made-up",
                                        "substrate": "container", "network_zone": "dmz",
                                        "build": {"containerfile": "C"}})

    def test_container_requires_containerfile(self):
        with self.assertRaises(manifest.ManifestError):
            manifest.validate_manifest({"id": "x", "technique_class": "web-rce",
                                        "substrate": "container", "network_zone": "dmz"})

    def test_vm_requires_vm_spec(self):
        with self.assertRaises(manifest.ManifestError):
            manifest.validate_manifest({"id": "x", "technique_class": "kernel-privesc",
                                        "substrate": "vm", "network_zone": "corp"})

    def test_vulnerability_metadata_requires_valid_cve(self):
        with self.assertRaises(manifest.ManifestError):
            manifest.validate_manifest({
                "id": "x", "technique_class": "windows-smb-rce",
                "substrate": "vm", "network_zone": "corp",
                "build": {"vm_spec": "domain.xml"},
                "vulnerability": {
                    "cves": ["not-a-cve"],
                    "affected": "test", "verification": "test", "source": "test",
                },
            })


if __name__ == "__main__":
    unittest.main()
