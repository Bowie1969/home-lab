"""Tests for keystone.vm — brain Proxmox VM provisioning helpers.

Pure-function tests: no Proxmox, no qm, no network stack. They pin the plan
and the provisioning commands so a future edit cannot silently rebind a
guest to the wrong zone bridge or drop the cloud-init snippet reference.
"""
import json
import os
import sys
import unittest
from dataclasses import replace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keystone import manifest as mf
from keystone import vm


def _mk_manifest(**kw):
    """Minimal valid Manifest for VM tests. Only fields we assert on vary."""
    defaults = dict(
        id="dmz-web-a",
        technique_class="web-rce",
        substrate="vm",
        network_zone="dmz",
        hostname="dmz-web-a",
        ports=[8080],
        prereqs=[],
        enables=[],
        flag=mf.Flag(value="KEYSTONE{t}", placement="/root/flag.txt"),
        build=mf.Build(vm_spec="cloud-init"),
        evidence={"host": "brain (willshomelab, 192.168.0.240)",
                  "vmid": 971, "ip": "10.99.50.21"},
        vulnerability={},
        scoring_hint=None,
        description="",
        path="/tmp/x",
    )
    defaults.update(kw)
    return mf.Manifest(**defaults)


class TestVmGuests(unittest.TestCase):
    def test_brain_vm_included(self):
        guests = vm.vm_guests([_mk_manifest()])
        self.assertEqual([g.id for g in guests], ["dmz-web-a"])
        g = guests[0]
        self.assertEqual(g.vmid, 971)
        self.assertEqual(g.real_ip, "10.99.50.21")
        self.assertEqual(g.zone, "dmz")
        self.assertEqual(g.bridge, "vmbr9")
        self.assertEqual(g.gateway, "10.99.50.1")
        self.assertEqual(g.cidr_prefix, 24)

    def test_parrot_libvirt_vm_excluded(self):
        # kiosk-kernel-style manifest with no brain host string: Parrot libvirt
        # and MUST NOT be picked up by the brain provisioner.
        m = _mk_manifest(id="kiosk-kernel", network_zone="corp",
                         evidence={"host": "parrot (local libvirt)", "vmid": 42,
                                   "ip": "10.80.20.5"})
        self.assertEqual(vm.vm_guests([m]), [])

    def test_non_vm_substrate_excluded(self):
        m = _mk_manifest(substrate="container")
        self.assertEqual(vm.vm_guests([m]), [])
        m = _mk_manifest(substrate="lxc")
        self.assertEqual(vm.vm_guests([m]), [])

    def test_data_zone_lands_on_vmbr51(self):
        m = _mk_manifest(id="vault", network_zone="data",
                         hostname="vault",
                         evidence={"host": "brain", "vmid": 980,
                                   "ip": "10.50.1.14"})
        g = vm.vm_guests([m])[0]
        self.assertEqual(g.bridge, "vmbr51")
        self.assertEqual(g.gateway, "10.50.1.1")

    def test_corp_zone_lands_on_vmbr50(self):
        m = _mk_manifest(id="ks-ws01", network_zone="corp",
                         hostname="ks-ws01",
                         evidence={"host": "brain", "vmid": 975,
                                   "ip": "10.50.0.11"})
        g = vm.vm_guests([m])[0]
        self.assertEqual(g.bridge, "vmbr50")
        self.assertEqual(g.gateway, "10.50.0.1")

    def test_resources_override_defaults(self):
        m = _mk_manifest(evidence={"host": "brain", "vmid": 972,
                                   "ip": "10.99.50.22",
                                   "resources": {"cores": 2,
                                                 "memory_mb": 2048,
                                                 "disk_gb": 16}})
        g = vm.vm_guests([m])[0]
        self.assertEqual((g.cores, g.memory_mb, g.disk_gb), (2, 2048, 16))

    def test_defaults_when_resources_absent(self):
        g = vm.vm_guests([_mk_manifest()])[0]
        self.assertEqual(g.cores, vm.DEFAULT_CORES)
        self.assertEqual(g.memory_mb, vm.DEFAULT_MEMORY_MB)
        self.assertEqual(g.disk_gb, vm.DEFAULT_DISK_GB)


class TestProvisionCommands(unittest.TestCase):
    def setUp(self):
        self.guest = vm.vm_guests([_mk_manifest()])[0]

    def test_clone_from_template(self):
        cmds = vm.provision_commands(self.guest)
        self.assertEqual(cmds[0],
                         f"qm clone {vm.VM_TEMPLATE_VMID} 971 "
                         f"--name dmz-web-a --full true --storage local-lvm")

    def test_bridge_and_ipconfig_match_zone(self):
        cmds = "\n".join(vm.provision_commands(self.guest))
        self.assertIn("--net0 virtio,bridge=vmbr9,firewall=1", cmds)
        self.assertIn("--ipconfig0 ip=10.99.50.21/24,gw=10.99.50.1", cmds)

    def test_cicustom_references_brain_snippet(self):
        cmds = "\n".join(vm.provision_commands(self.guest))
        self.assertIn("--cicustom user=local:snippets/keystone-dmz-web-a.yaml",
                      cmds)

    def test_corp_guest_has_corp_gateway(self):
        m = _mk_manifest(id="ks-ws01", network_zone="corp",
                         hostname="ks-ws01",
                         evidence={"host": "brain", "vmid": 975,
                                   "ip": "10.50.0.11"})
        g = vm.vm_guests([m])[0]
        cmds = "\n".join(vm.provision_commands(g))
        self.assertIn("bridge=vmbr50", cmds)
        self.assertIn("ip=10.50.0.11/24,gw=10.50.0.1", cmds)

    def test_data_guest_has_data_gateway(self):
        m = _mk_manifest(id="vault", network_zone="data",
                         hostname="vault",
                         evidence={"host": "brain", "vmid": 980,
                                   "ip": "10.50.1.14"})
        g = vm.vm_guests([m])[0]
        cmds = "\n".join(vm.provision_commands(g))
        self.assertIn("bridge=vmbr51", cmds)
        self.assertIn("ip=10.50.1.14/24,gw=10.50.1.1", cmds)

    def test_unprovisionable_returns_comment_only(self):
        bad = replace(self.guest, vmid=None)
        self.assertEqual(len(vm.provision_commands(bad)), 1)
        self.assertTrue(vm.provision_commands(bad)[0].startswith("#"))


class TestCloudInit(unittest.TestCase):
    def setUp(self):
        self.guest = vm.vm_guests([_mk_manifest()])[0]

    def test_cloud_init_header(self):
        ud = vm.cloud_init_user_data(self.guest)
        self.assertTrue(ud.startswith("#cloud-config\n"))

    def test_hostname_set(self):
        ud = vm.cloud_init_user_data(self.guest)
        self.assertIn("hostname: dmz-web-a\n", ud)
        self.assertIn("fqdn: dmz-web-a.keystone.lab\n", ud)

    def test_guest_agent_enabled(self):
        ud = vm.cloud_init_user_data(self.guest)
        self.assertIn("qemu-guest-agent", ud)
        self.assertIn("systemctl enable --now qemu-guest-agent", ud)

    def test_ssh_key_only_when_provided(self):
        ud = vm.cloud_init_user_data(self.guest, admin_ssh_pubkey="")
        self.assertNotIn("ssh_authorized_keys", ud)
        ud = vm.cloud_init_user_data(self.guest,
                                     admin_ssh_pubkey="ssh-ed25519 AAAA op")
        self.assertIn("ssh_authorized_keys:", ud)
        self.assertIn("ssh-ed25519 AAAA op", ud)

    def test_offline_safe_defaults(self):
        # brain has no WAN; cloud-init must not attempt apt refresh/upgrade.
        ud = vm.cloud_init_user_data(self.guest)
        self.assertIn("package_update: false", ud)
        self.assertIn("package_upgrade: false", ud)

    def test_module_metadata_file(self):
        ud = vm.cloud_init_user_data(self.guest)
        self.assertIn("/etc/keystone-module", ud)
        self.assertIn("id=dmz-web-a", ud)
        self.assertIn("zone=dmz", ud)
        self.assertIn("technique_class=web-rce", ud)


class TestPlan(unittest.TestCase):
    def test_plan_dict_mirrors_lxc_shape(self):
        guests = vm.vm_guests([_mk_manifest()])
        plan = vm.plan_dict(guests)
        self.assertEqual(plan["template"]["vmid"], vm.VM_TEMPLATE_VMID)
        self.assertEqual(plan["vmid_range"], list(vm.VMID_RANGE))
        self.assertEqual(len(plan["guests"]), 1)
        g = plan["guests"][0]
        self.assertEqual(g["id"], "dmz-web-a")
        self.assertEqual(g["bridge"], "vmbr9")
        self.assertEqual(g["gateway"], "10.99.50.1")
        self.assertEqual(g["cidr_prefix"], 24)


if __name__ == "__main__":
    unittest.main()
