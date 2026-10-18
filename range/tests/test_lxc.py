"""Tests for the brain (Proxmox) CORP/DATA LXC provisioning path.

These are pure-function tests: no Proxmox, no ``pct``, no network stack. They
pin the four LXC guest definitions to their manifests and assert that the
brain-side segmentation preserves the zone policy on the real ``vmbr50``
addresses — the real-layer counterpart of ``zones.crown_is_isolated``.
"""
import ipaddress
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keystone import generator, lxc, zones
from keystone.manifest import discover_modules

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULES = os.path.join(ROOT, "modules")

# The four LXC guests and the exact manifest facts they must match.
EXPECTED = {
    "ks-ws01":        dict(vmid=950, zone="corp", real_ip="10.50.0.11", port=8090,
                           flag="KEYSTONE{ws01-cached-cred-<rot>}", tech="cred-harvest"),
    "ks-files01":     dict(vmid=951, zone="corp", real_ip="10.50.0.12", port=8091,
                           flag="KEYSTONE{files01-handover-<rot>}", tech="nfs-nosquash"),
    "ks-intranet01":  dict(vmid=952, zone="corp", real_ip="10.50.0.13", port=8092,
                           flag="KEYSTONE{intranet01-admin-<rot>}", tech="ssrf-pivot"),
    "vault-keystone": dict(vmid=953, zone="data", real_ip="10.50.1.14", port=8200,
                           flag="KEYSTONE{CROWN-master-signing-key-<rot>}", tech="crown-store"),
}


class TestLxcGuests(unittest.TestCase):
    def setUp(self):
        self.guests = {g.id: g for g in lxc.lxc_guests(discover_modules(MODULES))}

    def test_exactly_the_four_lxc_guests(self):
        self.assertEqual(set(self.guests), set(EXPECTED))

    def test_guest_matches_manifest(self):
        for gid, exp in EXPECTED.items():
            g = self.guests[gid]
            self.assertEqual(g.vmid, exp["vmid"], gid)
            self.assertEqual(g.zone, exp["zone"], gid)
            self.assertEqual(g.real_ip, exp["real_ip"], gid)
            self.assertEqual(g.ports, [exp["port"]], gid)
            self.assertEqual(g.flag_value, exp["flag"], gid)
            self.assertEqual(g.technique_class, exp["tech"], gid)

    def test_guests_are_wired_and_ready(self):
        for gid, g in self.guests.items():
            self.assertTrue(lxc.guest_is_ready(g), f"{gid} should be ready (app + runtime.json)")
            self.assertTrue(os.path.isfile(os.path.join(g.path, "provision.sh")), gid)
            self.assertTrue(os.path.isfile(os.path.join(g.path, "lxc.conf")), gid)

    def test_parse_real_ip(self):
        self.assertEqual(lxc.parse_real_ip("10.50.0.11 (real, on brain bridge vmbr50)"), "10.50.0.11")
        self.assertEqual(lxc.parse_real_ip("10.50.1.14 (real, on brain bridge vmbr51 DATA VLAN 51)"), "10.50.1.14")
        self.assertIsNone(lxc.parse_real_ip("not-an-ip"))
        self.assertIsNone(lxc.parse_real_ip(None))

    def test_provision_commands_are_unprivileged_and_isolated(self):
        bridge_for = {"corp": lxc.BRAIN_BRIDGE, "data": lxc.BRAIN_DATA_BRIDGE}
        for g in self.guests.values():
            cmds = "\n".join(lxc.provision_commands(g))
            self.assertIn(f"bridge={bridge_for[g.zone]}", cmds)
            self.assertIn(f"ip={g.real_ip}/24", cmds)
            self.assertIn("--unprivileged 1", cmds)
            # The isolated bridge has no gateway; the crown must not phone home.
            self.assertNotIn("gw=", cmds)
            # pct push reads from the brain-side staging dir, not a Parrot path.
            self.assertIn(lxc.BRAIN_STAGE, cmds)


class TestBrainSegmentation(unittest.TestCase):
    def setUp(self):
        self.guests = lxc.lxc_guests(discover_modules(MODULES))
        self.corp_ips = {g.real_ip for g in self.guests if g.zone == "corp"}
        self.data_ips = {g.real_ip for g in self.guests if g.zone == "data"}

    def test_crown_sources_are_corp_only(self):
        # The real-layer analogue of zones.crown_is_isolated: every source the
        # brain firewall lets reach a DATA host is a CORP address — never the
        # dmz or attacker subnet, never an arbitrary bridge host.
        sources = lxc.crown_reachable_sources(self.guests)
        self.assertTrue(sources)  # the legitimate corp->data path must exist
        for src in sources:
            self.assertIn(src, self.corp_ips, f"{src} must be a CORP host")
            self.assertNotIn(src, self.data_ips)
            self.assertFalse(src.startswith("10.80."), f"{src} must not be dmz/attacker")

    def test_corp_to_data_only_on_vault_port(self):
        rules = lxc.brain_segmentation_rules(self.guests)
        data_rules = [r for r in rules if r["dst"] in self.data_ips and r["action"] == "accept"]
        self.assertTrue(data_rules)
        for r in data_rules:
            self.assertEqual(r.get("dport"), "8200")
            self.assertIn(r["src"], self.corp_ips)

    def test_physical_evilkit_drop_can_lateral_but_not_reach_data(self):
        rules = lxc.brain_segmentation_rules(self.guests)
        pi_ip = "10.50.0.220"
        corp_targets = {g.real_ip for g in self.guests if g.zone == "corp"}
        pi_lateral = {r["dst"] for r in rules
                      if r["src"] == pi_ip and r["action"] == "accept"}
        self.assertTrue(corp_targets.issubset(pi_lateral))
        self.assertFalse(pi_lateral & self.data_ips)

    def test_rendered_firewall_blocks_attacker_and_dmz_to_crown(self):
        fw = lxc.render_brain_firewall(self.guests)
        vault = next(g.real_ip for g in self.guests if g.zone == "data")
        self.assertIn("policy drop", fw)
        # the legitimate pivot path exists (corp -> vault on 8200)
        self.assertIn(f"ip daddr {vault} tcp dport 8200 accept", fw)
        # no accept rule grants the dmz or attacker subnet to the crown
        self.assertNotIn(f"saddr {lxc.DMZ_CIDR} ip daddr {vault} ", fw)
        self.assertNotIn(f"saddr {lxc.ATTACKER_CIDR} ip daddr {vault} ", fw)
        # attacker zone is dropped outright, and the crown has an explicit deny
        self.assertIn(f"ip saddr {lxc.ATTACKER_CIDR} drop", fw)
        self.assertIn(f"ip daddr {vault} drop", fw)
        # scoped to vmbr50 only; unrelated brain bridges are left alone
        self.assertIn('meta ibrname != "vmbr50" meta obrname != "vmbr50" accept', fw)

    def test_segmentation_matches_abstract_zone_policy(self):
        # DATA reachable only from CORP; CORP reachable only from DMZ: the brain
        # rules reuse zones.ZONE_POLICY, so no edge the abstract policy forbids
        # may appear. Here we assert the abstract policy itself is intact (the
        # brain renderer is driven by it) — a change to ZONE_POLICY that exposed
        # DATA would also flip crown_reachable_sources above.
        self.assertFalse(zones.reachable("attacker", "data"))
        self.assertFalse(zones.reachable("dmz", "data"))
        self.assertTrue(zones.reachable("corp", "data"))
        self.assertTrue(zones.reachable("dmz", "corp"))


class TestLxcLive(unittest.TestCase):
    def test_ready_modules_are_the_four_guests(self):
        from keystone import live
        ready, skipped = live.lxc_ready_modules()
        self.assertEqual({g.id for g in ready}, set(EXPECTED))
        self.assertEqual(skipped, {})

    def test_brain_actions_refuse_without_a_configured_brain(self):
        from unittest.mock import patch
        from keystone import live
        with patch.object(live, "BRAIN_SSH", None):
            with self.assertRaises(RuntimeError):
                live.brain(["pct", "status", "950"])


class TestCrownAppStaysSealed(unittest.TestCase):
    def setUp(self):
        self.vault = os.path.join(MODULES, "vault-keystone")

    def test_vault_app_requires_a_token_and_never_lists(self):
        with open(os.path.join(self.vault, "app", "server.py")) as fh:
            src = fh.read()
        self.assertIn("X-Vault-Token", src)
        self.assertIn("401", src)
        # The crown app must not be a directory-serving handler.
        self.assertNotIn("SimpleHTTPRequestHandler", src)
        self.assertNotIn("list_directory", src)
        self.assertNotIn("--directory", src)

    def test_no_container_build_remains_for_the_lxc_crown(self):
        # vault-keystone is substrate lxc now; a leftover Containerfile that
        # served /vault via http.server would list the secrets dir.
        self.assertFalse(os.path.exists(os.path.join(self.vault, "Containerfile")))


class TestGeneratorEmitsLxc(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="keystone-lxc-")
        generator.generate(MODULES, self.tmp)

    def test_lxc_and_brain_firewall_written(self):
        for name in ("lxc.json", "brain-firewall.nft"):
            self.assertTrue(os.path.isfile(os.path.join(self.tmp, name)), name)

    def test_lxc_json_lists_four_ready_guests(self):
        with open(os.path.join(self.tmp, "lxc.json")) as fh:
            plan = json.load(fh)
        self.assertEqual(plan["bridge"], "vmbr50")
        items = {i["id"]: i for i in plan["lxc"]}
        self.assertEqual(set(items), set(EXPECTED))
        for gid, exp in EXPECTED.items():
            self.assertTrue(items[gid]["ready"], gid)
            self.assertEqual(items[gid]["real_ip"], exp["real_ip"])
            self.assertEqual(items[gid]["flag"]["value"], exp["flag"])

    def test_summary_crown_sources_are_corp(self):
        with open(os.path.join(self.tmp, "summary.json")) as fh:
            summary = json.load(fh)
        self.assertEqual(summary["lxc"], 4)
        self.assertEqual(sorted(summary["brain_crown_sources"]),
                         ["10.50.0.11", "10.50.0.12", "10.50.0.13"])
        for src in summary["brain_crown_sources"]:
            self.assertTrue(ipaddress.ip_address(src) in ipaddress.ip_network("10.50.0.0/24"))


if __name__ == "__main__":
    unittest.main()
