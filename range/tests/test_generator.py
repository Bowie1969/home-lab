import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keystone import generator

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULES = os.path.join(ROOT, "modules")


class TestGenerator(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="keystone-gen-")
        self.written = generator.generate(MODULES, self.tmp)

    def test_all_artifacts_written(self):
        for name in ("networks.json", "compose.yaml", "firewall.nft", "vms.json", "infra.json",
                     "topology.json", "scoring_key.template.json", "reachability.md",
                     "summary.json"):
            self.assertTrue(os.path.isfile(os.path.join(self.tmp, name)), name)

    def test_compose_has_services_and_networks(self):
        with open(os.path.join(self.tmp, "compose.yaml")) as fh:
            compose = fh.read()
        self.assertIn("keystone-dmz", compose)
        self.assertIn("edge-upload:", compose)
        self.assertIn("ipv4_address:", compose)

    def test_firewall_blocks_attacker_and_dmz_to_data(self):
        with open(os.path.join(self.tmp, "firewall.nft")) as fh:
            fw = fh.read()
        self.assertIn("policy drop", fw)
        # no allow rule from attacker or dmz subnet to the data subnet
        self.assertNotIn("saddr 10.80.0.0/24 ip daddr 10.80.30.0/24 accept", fw)
        self.assertNotIn("saddr 10.80.10.0/24 ip daddr 10.80.30.0/24 accept", fw)
        # the legitimate pivot path exists
        self.assertIn("saddr 10.80.20.0/24 ip daddr 10.80.30.0/24 accept", fw)

    def test_vms_listed(self):
        with open(os.path.join(self.tmp, "vms.json")) as fh:
            vms = json.load(fh)
        ids = {v["id"] for v in vms["vms"]}
        # dc-roast is now substrate "remote-vm" (the brain's reused dc01) and
        # moved to infra.json; only Parrot-local libvirt VMs and the new
        # brain-hosted win2025-smb (from the 2026-10-15 redesign) stay here.
        self.assertNotIn("dc-roast", ids)
        self.assertIn("kiosk-kernel", ids)
        self.assertEqual(
            ids,
            {"kiosk-kernel", "samba-45", "ubuntu-dirtycow",
             "win7-eternalblue", "win2025-smb"},
        )
        by_id = {v["id"]: v for v in vms["vms"]}
        self.assertEqual(by_id["win7-eternalblue"]["vulnerability"]["cves"], ["CVE-2017-0144"])
        self.assertEqual(by_id["samba-45"]["vulnerability"]["cves"], ["CVE-2017-7494"])
        self.assertEqual(by_id["ubuntu-dirtycow"]["vulnerability"]["cves"], ["CVE-2016-5195"])
        # win2025-smb's CVE is intentionally unpinned until the owner picks
        # the specific SMB CVE + superseding KB; the vulnerability section is
        # absent from the manifest, which the generator surfaces as {}.
        self.assertEqual(by_id["win2025-smb"]["vulnerability"], {})
        self.assertFalse(any(v["ready"] for v in vms["vms"]))

    def test_infra_lists_brain_and_physical_modules(self):
        with open(os.path.join(self.tmp, "infra.json")) as fh:
            infra = json.load(fh)
        ids = {i["id"]: i for i in infra["infra"]}
        self.assertIn("dc-roast", ids)
        self.assertEqual(ids["dc-roast"]["substrate"], "remote-vm")
        self.assertIn("drop01", ids)
        self.assertEqual(ids["drop01"]["substrate"], "physical")
        self.assertIn("mac-debian13", ids)
        self.assertEqual(ids["mac-debian13"]["substrate"], "physical")
        self.assertEqual(ids["mac-debian13"]["vulnerability"]["cves"], ["CVE-2025-32463"])
        for lxc_id in ("ks-ws01", "ks-files01", "ks-intranet01", "vault-keystone"):
            self.assertIn(lxc_id, ids)
            self.assertEqual(ids[lxc_id]["substrate"], "lxc")

    def test_summary_reports_crown_isolated(self):
        with open(os.path.join(self.tmp, "summary.json")) as fh:
            summary = json.load(fh)
        self.assertTrue(summary["crown_isolated"])
        self.assertEqual(len(summary["initial_access_vectors"]), 12)

    def test_topology_has_all_nodes(self):
        with open(os.path.join(self.tmp, "topology.json")) as fh:
            topo = json.load(fh)
        # 30 modules (the existing estate plus the three 2026-10-16 honeypot-TTP
        # containers — edge-botnet, key-reuse, corp-keyjump) + attacker node + 4
        # dmz service-host VMs.
        self.assertEqual(len(topo["nodes"]), 35)
        self.assertEqual(set(topo["zones"]), {"attacker", "dmz", "corp", "data"})
        self.assertEqual(
            {segment["id"]: segment["vlan"] for segment in topo["segments"]},
            {"attacker": 66, "dmz": 9, "corp": 50, "data": 51},
        )
        fabric = {device["id"]: device for device in topo["fabric"]["devices"]}
        self.assertEqual(fabric["sg108e"]["address"], "10.10.0.5")
        self.assertEqual(fabric["evilkit"]["address"], "10.50.0.220")
        # the dropbox's C2 edge is drawn explicitly alongside the zone-policy edges
        self.assertTrue(any(e["src"] == "attacker" and e["dst"] == "drop01" for e in topo["edges"]))
        nodes = {n["id"]: n for n in topo["nodes"]}
        self.assertEqual(nodes["mac-debian13"]["cves"], ["CVE-2025-32463"])
        self.assertEqual(nodes["drop01"]["real_ip"], "10.50.0.220")
        # service-host VMs appear as dmz nodes wired to the pods they host
        for host in ("dmz-web-a", "dmz-web-b", "dmz-svc", "dmz-runner"):
            self.assertIn(host, nodes)
            self.assertEqual(nodes[host]["zone"], "dmz")
        hosts_edges = [e for e in topo["edges"] if e["kind"] == "hosts"]
        self.assertEqual(len(hosts_edges), 12)
        self.assertTrue(any(e["src"] == "dmz-web-a" and e["dst"] == "edge-upload"
                            for e in hosts_edges))


if __name__ == "__main__":
    unittest.main()
