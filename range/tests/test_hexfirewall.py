"""Tests for the hEX (OpenWrt) re-homed firewall ruleset.

These are pure-function tests: no hEX, no nftables runtime, no network stack.
They pin the ported ruleset to the same invariants the brain ruleset already
carries — crown reachable from CORP only — and assert the artifact is
fw4-includable (chain only, no table header) and that the brain ruleset
output is a separate, unchanged target.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keystone import generator, hexfirewall, lxc
from keystone.manifest import discover_modules

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULES = os.path.join(ROOT, "modules")

EXPECTED = {
    "ks-ws01": dict(vmid=950, zone="corp", real_ip="10.50.0.11", port=8090),
    "ks-files01": dict(vmid=951, zone="corp", real_ip="10.50.0.12", port=8091),
    "ks-intranet01": dict(vmid=952, zone="corp", real_ip="10.50.0.13", port=8092),
    "vault-keystone": dict(vmid=953, zone="data", real_ip="10.50.1.14", port=8200),
}
CORP_IPS = ["10.50.0.11", "10.50.0.12", "10.50.0.13"]
VAULT = "10.50.1.14"


class TestHexSegmentation(unittest.TestCase):
    def setUp(self):
        self.guests = lxc.lxc_guests(discover_modules(MODULES))
        self.fw = hexfirewall.render_hex_firewall(self.guests)
        self.rules = hexfirewall.hex_segmentation_rules(self.guests)

    def accepts(self, saddr=None, daddr=None):
        out = []
        for stmt in self.rules:
            if " accept" not in stmt:
                continue
            if saddr and f"saddr {saddr}" not in stmt:
                continue
            if daddr and f"daddr {daddr}" not in stmt:
                continue
            out.append(stmt)
        return out

    def test_crown_sources_are_corp_only(self):
        sources = hexfirewall.hex_crown_reachable_sources(self.guests)
        self.assertEqual(sources, CORP_IPS)

    def test_attacker_and_dmz_never_reach_the_vault(self):
        self.assertFalse(self.accepts(saddr=hexfirewall.HEX_ATTACK_CIDR,
                                      daddr=VAULT))
        self.assertFalse(self.accepts(saddr=hexfirewall.HEX_DMZ_CIDR,
                                      daddr=VAULT))

    def test_dmz_reaches_corp_and_attacker_reaches_dmz_only(self):
        for ip in CORP_IPS:
            self.assertTrue(self.accepts(saddr=hexfirewall.HEX_DMZ_CIDR,
                                         daddr=ip))
        self.assertTrue(self.accepts(saddr=hexfirewall.HEX_ATTACK_CIDR,
                                     daddr=hexfirewall.HEX_DMZ_CIDR))
        self.assertFalse(self.accepts(saddr=hexfirewall.HEX_ATTACK_CIDR,
                                      daddr=hexfirewall.HEX_CORP_CIDR))
        self.assertFalse(self.accepts(saddr=hexfirewall.HEX_ATTACK_CIDR,
                                      daddr=hexfirewall.HEX_DATA_CIDR))

    def test_dmz_cannot_reach_data_directly(self):
        # VLAN 51 (data) is reachable only from corp; dmz->data must be a
        # terminal drop before any zone accept gets a say.
        self.assertFalse(self.accepts(saddr=hexfirewall.HEX_DMZ_CIDR,
                                      daddr=hexfirewall.HEX_DATA_CIDR))
        self.assertFalse(self.accepts(saddr=hexfirewall.HEX_DMZ_CIDR,
                                      daddr=VAULT))
        self.assertTrue(any(
            f"saddr {hexfirewall.HEX_DMZ_CIDR}" in s
            and f"daddr {hexfirewall.HEX_DATA_CIDR}" in s
            and 'drop keystone dmz->data' in s
            for s in self.rules))

    def test_corp_to_vault_only_on_vault_port(self):
        vault_accepts = self.accepts(daddr=VAULT)
        self.assertEqual(len(vault_accepts), 3)
        for stmt in vault_accepts:
            self.assertIn("tcp dport 8200", stmt)
            self.assertTrue(any(ip in stmt for ip in CORP_IPS), stmt)

    def test_crown_seal_and_default_deny_present(self):
        self.assertIn(f'ip daddr {VAULT} log prefix "drop keystone crown-seal " counter drop',
                      self.rules)
        self.assertIn('log prefix "drop keystone default-deny " counter drop', self.rules[-1])
        self.assertTrue(any('log prefix "drop keystone attacker->subsidiary " counter drop' in s
                            for s in self.rules))

    def test_non_range_traffic_falls_through_to_fw4(self):
        # The escape rule must come before any judging rule so fw4 keeps the
        # northreach segments. All three keystone CIDRs are the chain's scope.
        idx_escape = self.rules.index(
            f"ip daddr != {{ {hexfirewall.HEX_DMZ_CIDR}, "
            f"{hexfirewall.HEX_CORP_CIDR}, "
            f"{hexfirewall.HEX_DATA_CIDR} }} counter accept")
        self.assertEqual(idx_escape, 1)  # right after ct established
        self.assertEqual(self.rules[0], "ct state established,related counter accept")

    def test_artifact_is_a_standalone_ip_table(self):
        # A dedicated ip-family table: independent of fw4's generated ruleset,
        # and the ip family is required for `log` output on the OpenWrt build
        # (the inet family's nf_log backend is nf_log_ipv6 there).
        self.assertIn("table ip keystone_hex {", self.fw)
        self.assertIn("delete table ip keystone_hex", self.fw)
        self.assertTrue(self.fw.startswith("#!/usr/sbin/nft -f"))
        self.assertIn("chain keystone_forward {", self.fw)
        self.assertIn("type filter hook forward priority -10; policy accept;",
                      self.fw)

    def test_validates_as_nft(self):
        nft = shutil.which("nft")
        if not nft:
            self.skipTest("nft binary not available")
        proc = subprocess.run([nft, "-c", "-f", "-"],
                              input=self.fw, capture_output=True, text=True)
        if proc.returncode != 0 and "Operation not permitted" in proc.stderr:
            # Unprivileged nft cannot init the netlink cache; retry inside a
            # throwaway user+net namespace, where -c (check-only) is allowed.
            unshare = shutil.which("unshare")
            if not unshare:
                self.skipTest("nft needs a namespace here and unshare is absent")
            proc = subprocess.run([unshare, "-Urn", nft, "-c", "-f", "-"],
                                  input=self.fw, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_brain_ruleset_is_a_separate_unchanged_target(self):
        brain = lxc.render_brain_firewall(self.guests)
        # The brain output remains the vmbr50 bridge table — the hEX port must
        # not leak into it (and vice versa).
        self.assertIn("table bridge keystone_brain", brain)
        self.assertNotIn("keystone_forward", brain)
        self.assertNotIn("table bridge", self.fw)
        self.assertNotIn("vmbr50", self.fw)


class TestGeneratorEmitsHex(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="keystone-hex-")
        generator.generate(MODULES, self.tmp)

    def test_hex_firewall_written_alongside_brain_firewall(self):
        for name in ("brain-firewall.nft", "hex-firewall.nft"):
            self.assertTrue(os.path.isfile(os.path.join(self.tmp, name)), name)

    def test_hex_artifact_matches_renderer(self):
        guests = lxc.lxc_guests(discover_modules(MODULES))
        with open(os.path.join(self.tmp, "hex-firewall.nft")) as fh:
            self.assertEqual(fh.read(), hexfirewall.render_hex_firewall(guests))

    def test_brain_artifact_still_matches_brain_renderer(self):
        guests = lxc.lxc_guests(discover_modules(MODULES))
        with open(os.path.join(self.tmp, "brain-firewall.nft")) as fh:
            self.assertEqual(fh.read(), lxc.render_brain_firewall(guests))


if __name__ == "__main__":
    unittest.main()
