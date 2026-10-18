"""Brain-side Proxmox VM provisioning for Keystone modules.

The VM substrate on the brain, counterpart to :mod:`keystone.lxc`: pure data
+ pure functions, derived entirely from manifests, emitting the exact
``qm clone`` / ``qm set`` / ``qm start`` sequence Keystone needs to bring a
``substrate: vm`` module up on the brain's Proxmox after the 2026-10-15
redesign.

Shape mirrors :mod:`keystone.lxc` so :mod:`keystone.generator` and
:mod:`keystone.live` can treat both substrates the same way:

* ``vm_guests(manifests)`` returns a sorted list of :class:`VmGuest` for every
  ``substrate: vm`` module whose manifest declares a brain host (via
  ``evidence.host`` containing ``brain`` or ``willshomelab``). Parrot-local
  libvirt VMs (the pre-redesign kiosk-kernel/samba-45/dirtycow path) are
  excluded here and continue to be handled by their own ``domain.xml``.
* ``provision_commands(guest)`` returns the ``qm`` sequence to clone the
  Keystone Debian 13 template and bring the guest up on its zone bridge.
  Zone -> bridge is pinned in :data:`BRIDGE_FOR_ZONE` (dmz->vmbr9,
  corp->vmbr50, data->vmbr51 — the new VLAN-51 data bridge).
* ``cloud_init_user_data(guest)`` returns the per-guest cloud-init
  user-data YAML (hostname + static IP + authorized key + stdlib service
  unit). ``keystone.live`` writes it to the brain's snippets storage and
  attaches it via ``qm set --cicustom``.

No ``gw=`` is set on the NIC for corp/data: the keystone bridges are
uplink-less by design, and the hEX routes between them. DMZ guests DO get
``gw=10.99.50.1`` so the dmz->corp forward actually leaves the host.

Pure functions, unit-testable without Proxmox. Live apply is
``keystone.live vm-provision <id>``.
"""
from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .manifest import Manifest

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

# Template built by infra/brain/build-vm-template.sh. Clones derive from here.
VM_TEMPLATE_VMID = 9000
VM_TEMPLATE_NAME = "keystone-debian13"

# Reserved VMID window for brain VMs. The LXC window (950-969) stays as it is;
# the VM window starts above the Proxmox default autoid floor.
VMID_RANGE = (970, 999)

# Zone -> (bridge, cidr, gateway). All three bridges are brain-side; the hEX
# does the inter-zone routing. The gateway is set only where the hEX actually
# has a leg (dmz = hEX lan2.9, corp = hEX lan2.50, data = hEX lan2.51).
BRIDGE_FOR_ZONE: Dict[str, Dict[str, str]] = {
    "dmz":  {"bridge": "vmbr9",  "cidr": "10.99.50.0/24", "gw": "10.99.50.1"},
    "corp": {"bridge": "vmbr50", "cidr": "10.50.0.0/24",  "gw": "10.50.0.1"},
    "data": {"bridge": "vmbr51", "cidr": "10.50.1.0/24",  "gw": "10.50.1.1"},
}

# Where ``keystone.live vm`` stages each guest's cloud-init snippet on the
# brain before ``qm set --cicustom`` references it. Must be a path under a
# Proxmox storage that has the ``snippets`` content type (default: ``local``).
BRAIN_SNIPPET_STORAGE = "local"
BRAIN_SNIPPET_DIR = "/var/lib/vz/snippets"

# Default clone sizing — small enough to run many guests on a 32 GB brain.
# Per-module overrides via ``evidence.resources`` on the manifest.
DEFAULT_CORES = 1
DEFAULT_MEMORY_MB = 1024
DEFAULT_DISK_GB = 8


# --------------------------------------------------------------------------- #
# Guest model
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class VmGuest:
    """A single brain Proxmox VM, derived entirely from its manifest."""
    id: str
    hostname: str
    vmid: Optional[int]
    zone: str                      # dmz | corp | data
    real_ip: Optional[str]         # e.g. "10.50.0.21" on vmbr50
    ports: List[int] = field(default_factory=list)
    technique_class: str = ""
    cores: int = DEFAULT_CORES
    memory_mb: int = DEFAULT_MEMORY_MB
    disk_gb: int = DEFAULT_DISK_GB
    flag_value: str = ""
    flag_placement: str = ""
    path: str = ""                 # absolute module folder

    @property
    def service_port(self) -> Optional[int]:
        return self.ports[0] if self.ports else None

    @property
    def bridge(self) -> str:
        return BRIDGE_FOR_ZONE.get(self.zone, {}).get("bridge", "")

    @property
    def gateway(self) -> Optional[str]:
        return BRIDGE_FOR_ZONE.get(self.zone, {}).get("gw")

    @property
    def cidr_prefix(self) -> int:
        cidr = BRIDGE_FOR_ZONE.get(self.zone, {}).get("cidr", "0.0.0.0/0")
        return ipaddress.ip_network(cidr).prefixlen


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #

def _parse_real_ip(raw: Optional[str]) -> Optional[str]:
    """Pull a bare IP out of an ``evidence.ip`` string like ``"10.50.0.21 ..."``."""
    if not raw:
        return None
    token = str(raw).strip().split()[0].strip().rstrip(",")
    try:
        ipaddress.ip_address(token)
    except ValueError:
        return None
    return token


def _is_brain_host(raw: Optional[str]) -> bool:
    """True iff ``evidence.host`` names the brain (vs Parrot libvirt)."""
    if not raw:
        return False
    s = str(raw).lower()
    return ("brain" in s) or ("willshomelab" in s) or ("192.168.0.240" in s)


def vm_guests(manifests: List[Manifest]) -> List[VmGuest]:
    """Every brain-destined ``substrate: vm`` module as a concrete guest spec.

    Parrot-local libvirt VMs (``evidence.host`` not naming the brain) are
    excluded; those keep their own ``domain.xml``-based bring-up and never
    traverse the brain's Proxmox tooling.
    """
    guests: List[VmGuest] = []
    for man in sorted(manifests, key=lambda m: m.id):
        if man.substrate != "vm":
            continue
        evidence = man.evidence or {}
        if not _is_brain_host(evidence.get("host")):
            continue
        resources = evidence.get("resources") or {}
        guests.append(VmGuest(
            id=man.id,
            hostname=man.hostname,
            vmid=evidence.get("vmid"),
            zone=man.network_zone,
            real_ip=_parse_real_ip(evidence.get("ip")),
            ports=list(man.ports),
            technique_class=man.technique_class,
            cores=int(resources.get("cores", DEFAULT_CORES)),
            memory_mb=int(resources.get("memory_mb", DEFAULT_MEMORY_MB)),
            disk_gb=int(resources.get("disk_gb", DEFAULT_DISK_GB)),
            flag_value=man.flag.value if man.flag else "",
            flag_placement=man.flag.placement if man.flag else "",
            path=man.path,
        ))
    return guests


def guest_is_provisionable(guest: VmGuest) -> bool:
    """A guest can be provisioned once its manifest has a vmid, IP, and zone."""
    return (guest.vmid is not None
            and guest.real_ip is not None
            and guest.zone in BRIDGE_FOR_ZONE)


# --------------------------------------------------------------------------- #
# Command rendering
# --------------------------------------------------------------------------- #

def provision_commands(guest: VmGuest,
                       template_vmid: int = VM_TEMPLATE_VMID,
                       storage: str = "local-lvm",
                       snippet_storage: str = BRAIN_SNIPPET_STORAGE) -> List[str]:
    """Canonical ``qm`` sequence to bring one brain VM up from the template.

    Returned as command strings. ``keystone.live vm-provision`` runs these
    over SSH to the brain. Every destructive scope is pinned to this guest's
    VMID; cloud-init takes care of hostname/IP/users at first boot.
    """
    if not guest_is_provisionable(guest):
        return [f"# {guest.id}: cannot provision — manifest lacks vmid/ip/zone"]

    zone = BRIDGE_FOR_ZONE[guest.zone]
    net = f"virtio,bridge={zone['bridge']},firewall=1"
    ipcfg = f"ip={guest.real_ip}/{guest.cidr_prefix}"
    if guest.gateway:
        ipcfg += f",gw={guest.gateway}"
    snippet = f"{snippet_storage}:snippets/keystone-{guest.id}.yaml"

    return [
        f"qm clone {template_vmid} {guest.vmid} --name {guest.hostname} "
        f"--full true --storage {storage}",
        f"qm set {guest.vmid} --cores {guest.cores} --memory {guest.memory_mb}",
        f"qm resize {guest.vmid} scsi0 {guest.disk_gb}G",
        f"qm set {guest.vmid} --net0 {net}",
        f"qm set {guest.vmid} --ipconfig0 {ipcfg}",
        # Cloud-init user-data snippet is written to the brain's snippet
        # storage by keystone.live before this sequence runs.
        f"qm set {guest.vmid} --cicustom user={snippet}",
        f"qm start {guest.vmid}",
    ]


# --------------------------------------------------------------------------- #
# Cloud-init user-data (per-guest, written to the brain's snippets dir)
# --------------------------------------------------------------------------- #

CLOUD_INIT_HEADER = "#cloud-config\n"


def cloud_init_user_data(guest: VmGuest,
                         admin_ssh_pubkey: str = "",
                         timezone: str = "Australia/Brisbane") -> str:
    """Per-guest cloud-init user-data as a YAML string.

    Idempotent at first boot: sets hostname, installs qemu-guest-agent,
    plants the admin SSH key, writes a tiny marker so ``keystone.live`` can
    detect first-boot completion over the guest-agent, and leaves per-module
    service wiring to the module's own ``provision.sh`` (same split as the
    LXC path: generic cloud-init here, module-specific commands there).

    ``admin_ssh_pubkey`` is passed in rather than read from disk so the
    renderer stays pure (unit-testable). ``keystone.live`` reads it from
    the operator's own key when it stages the snippet.
    """
    key_line = admin_ssh_pubkey.strip() if admin_ssh_pubkey else ""
    key_block = f"      - {key_line}\n" if key_line else ""

    lines = [
        CLOUD_INIT_HEADER,
        f"hostname: {guest.hostname}\n",
        f"fqdn: {guest.hostname}.keystone.lab\n",
        f"timezone: {timezone}\n",
        "manage_etc_hosts: true\n",
        "package_update: false\n",   # offline-safe default; brain has no WAN
        "package_upgrade: false\n",
        "packages:\n",
        "  - qemu-guest-agent\n",
        "users:\n",
        "  - name: keystone\n",
        "    sudo: ALL=(ALL) NOPASSWD:ALL\n",
        "    shell: /bin/bash\n",
        "    lock_passwd: true\n",
    ]
    if key_line:
        lines.append("    ssh_authorized_keys:\n")
        lines.append(key_block)
    lines.extend([
        "write_files:\n",
        f"  - path: /etc/keystone-module\n",
        f"    permissions: '0644'\n",
        f"    content: |\n",
        f"      id={guest.id}\n",
        f"      zone={guest.zone}\n",
        f"      technique_class={guest.technique_class}\n",
        f"      vmid={guest.vmid}\n",
        "runcmd:\n",
        "  - systemctl enable --now qemu-guest-agent\n",
        "  - touch /var/lib/keystone-first-boot-done\n",
    ])
    return "".join(lines)


# --------------------------------------------------------------------------- #
# Export plan (for keystone.generator)
# --------------------------------------------------------------------------- #

def plan_dict(guests: List[VmGuest]) -> Dict:
    """A reviewable JSON plan: one entry per brain VM.

    Mirrors the shape ``keystone.lxc`` writes to ``build/lxc.json`` so the
    generator can emit a parallel ``build/vms.json`` for brain VMs.
    """
    out = []
    for g in guests:
        zone = BRIDGE_FOR_ZONE.get(g.zone, {})
        out.append({
            "id": g.id,
            "hostname": g.hostname,
            "vmid": g.vmid,
            "zone": g.zone,
            "bridge": zone.get("bridge"),
            "ip": g.real_ip,
            "cidr_prefix": g.cidr_prefix,
            "gateway": g.gateway,
            "cores": g.cores,
            "memory_mb": g.memory_mb,
            "disk_gb": g.disk_gb,
            "ports": g.ports,
            "technique_class": g.technique_class,
            "template_vmid": VM_TEMPLATE_VMID,
            "template_name": VM_TEMPLATE_NAME,
        })
    return {"template": {"vmid": VM_TEMPLATE_VMID, "name": VM_TEMPLATE_NAME},
            "vmid_range": list(VMID_RANGE), "guests": out}


def dump_plan(guests: List[VmGuest], path: str) -> None:
    """Write ``plan_dict`` to ``path`` as pretty JSON."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(plan_dict(guests), fh, indent=2, sort_keys=True)
        fh.write("\n")
