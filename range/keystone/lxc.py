"""LXC (brain/Proxmox) provisioning plan and brain-side segmentation.

The CORP and DATA tiers do not run on Parrot. They are dedicated Keystone LXCs
provisioned on the *brain* (willshomelab, a Proxmox host) on the isolated,
uplink-less bridge ``vmbr50`` (``10.50.0.0/24``). This is the deliberate physical
counterpart to the podman zone model: the crown jewel is not merely on a
different logical subnet, it is on a different host, on a bridge with no route to
the house LAN, to Parrot, or to the Pi dropbox.

This module is the LXC analogue of :mod:`keystone.zones` + the compose/firewall
builders in :mod:`keystone.generator`:

* it is **pure data + pure functions** so it unit-tests with no Proxmox, no
  network stack and no ``pct`` present; and
* it reuses :data:`keystone.zones.ZONE_POLICY` as the single source of truth for
  the reachability policy, translating it onto the brain's *real* ``vmbr50``
  addresses instead of re-deciding it.

The abstract zones stay authoritative. Parrot enforces the policy at the
synthetic ``10.80.0.0/16`` layer (``build/firewall.nft``); the brain enforces the
*same* policy at the real ``10.50.0.0/24`` layer (``build/brain-firewall.nft``).
Both are required because the two tiers live on two different hosts; neither
weakens the other.

Segmentation preserved here (identical shape to the podman side):

* **CORP reachable only from DMZ** — the only inbound accept into the CORP LXCs
  is from the DMZ pivot ingress (and intra-CORP). The attacker zone never
  reaches the brain bridge at all.
* **DATA reachable only from CORP** — the only accept into the vault (``:8200``)
  is from a known CORP host. Everything else to the vault is dropped, so even if
  the future DMZ trunk lands DMZ traffic onto ``vmbr50`` the crown stays
  unreachable from it.
"""
from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import zones
from .manifest import Manifest

# The isolated Keystone bridges on the brain. No uplink, no gateway — same
# no-route-out pattern as the existing vmbr9/vmbr43 bridges. Post-2026-10-15
# redesign, data lives on its own VLAN 51 / vmbr51 so corp and data are
# separated at L2 (not just by an hEX ACL).
BRAIN_BRIDGE = "vmbr50"            # keystone CORP zone (VLAN 50)
BRAIN_CIDR = "10.50.0.0/24"
BRAIN_DATA_BRIDGE = "vmbr51"       # keystone DATA zone (VLAN 51) — crown vault
BRAIN_DATA_CIDR = "10.50.1.0/24"
BRAIN_HOST = "willshomelab (192.168.0.240)"

# Zone -> (bridge, cidr) on the brain. Picked by provision_commands so a data
# guest lands on vmbr51 and a corp guest on vmbr50; an unknown zone falls back
# to the corp bridge (same behaviour as before this split).
BRAIN_BRIDGE_FOR_ZONE: Dict[str, Dict[str, str]] = {
    "corp": {"bridge": BRAIN_BRIDGE, "cidr": BRAIN_CIDR},
    "data": {"bridge": BRAIN_DATA_BRIDGE, "cidr": BRAIN_DATA_CIDR},
}

# Reserved VMID window for Keystone brain LXCs (see generator.build_infra note).
VMID_RANGE = (950, 969)

# The DMZ->CORP pivot ingress. Post-redesign the DMZ is real: the 12 module
# pods ride macvlan on VLAN 9 (10.99.50.0/24, shared with the estate) and
# reach CORP by hairpinning through the hEX, so dmz->corp frames arrive on
# vmbr50 with VLAN-9 source addresses. The logical ZONE_SUBNETS CIDRs are
# retained only for the legacy drop rules below.
DMZ_CIDR = zones.ZONE_SUBNETS["dmz"]
ATTACKER_CIDR = zones.ZONE_SUBNETS["attacker"]
DMZ_REAL_CIDR = "10.99.50.0/24"       # VLAN 9 (hEX lan2.9, brain vmbr9)
ATTACKER_REAL_CIDR = "10.10.66.0/24"  # VLAN 66 behind the Asus lab router
CORP_GATEWAY = "10.50.0.1"            # hEX lan2.50
DATA_GATEWAY = "10.50.1.1"            # hEX lan2.51 (VLAN 51, post-2026-10-15 split)

# A CORP host on the brain that is NOT a Keystone LXC: the reused dc01 VM
# (dc-roast, VMID 930) gains a vmbr50 NIC. Its guest-OS vmbr50 address is not
# verified yet (see modules/dc-roast/manifest.yaml), so it is listed with
# ``ip: None`` and contributes a firewall rule only once an operator fills it in
# (BRINGUP.md). Leaving it unresolved is safe: default-drop means an unlisted
# CORP member simply cannot reach the vault until it is declared.
CORP_EXTRA_HOSTS: List[Dict[str, object]] = [
    {"id": "dc-roast", "hostname": "dc01", "ip": None, "allow_data": True,
     "note": "reused DC (VMID 930), vmbr50 guest IP unverified; fill in host-side"},
    {"id": "evilkit-pi-01", "hostname": "evilkit-pi-01", "ip": "10.50.0.220",
     "allow_data": False,
     "note": "physical EvilKit OS drop on SG108E CORP access port; must lateral "
             "to an approved CORP host before reaching DATA"},
]

# Default Proxmox provisioning knobs. Overridable by the operator at bring-up
# (see BRINGUP.md); kept here so lxc.json carries a concrete, reviewable plan.
DEFAULT_OSTEMPLATE = "local:vztmpl/debian-13-standard_13.6-1_amd64.tar.zst"
DEFAULT_STORAGE = "local-lvm"
DEFAULT_ROOTFS_GB = 2
DEFAULT_MEMORY_MB = 256
DEFAULT_CORES = 1

# Where ``keystone.live lxc`` stages each guest's app + provisioner ON THE BRAIN
# before ``pct push`` copies them into the guest. ``pct push`` reads from the
# brain's own filesystem, never Parrot's, so the plan references this staging
# path rather than a Parrot-local module path.
BRAIN_STAGE = "/tmp/keystone-stage"


@dataclass(frozen=True)
class LxcGuest:
    """A single brain LXC, derived entirely from its manifest."""
    id: str
    hostname: str
    vmid: Optional[int]
    zone: str                      # corp | data
    real_ip: Optional[str]         # bare address on vmbr50, e.g. "10.50.0.11"
    synthetic_ip: str              # deterministic 10.80.x.x (scoring/dashboard)
    ports: List[int] = field(default_factory=list)
    technique_class: str = ""
    flag_value: str = ""           # template, e.g. "KEYSTONE{ws01-cached-cred-<rot>}"
    flag_placement: str = ""
    flag_mode: str = "0600"
    app: str = "app/server.py"     # module-relative path to the stdlib service
    ready: bool = False
    path: str = ""                 # absolute module folder

    @property
    def service_port(self) -> Optional[int]:
        return self.ports[0] if self.ports else None


def parse_real_ip(raw: Optional[str]) -> Optional[str]:
    """Pull the bare address out of a manifest ``evidence.ip`` string.

    Manifests annotate the real address with prose, e.g.
    ``"10.50.0.11 (real, on brain bridge vmbr50)"``. Return ``"10.50.0.11"``,
    or ``None`` if the leading token is not an IP address.
    """
    if not raw:
        return None
    token = str(raw).strip().split()[0].strip().rstrip(",")
    try:
        ipaddress.ip_address(token)
    except ValueError:
        return None
    return token


def _runtime(path: str) -> Dict:
    rt = os.path.join(path, "runtime.json")
    if os.path.isfile(rt):
        with open(rt, encoding="utf-8") as fh:
            return json.load(fh)
    return {}


def lxc_guests(manifests: List[Manifest]) -> List[LxcGuest]:
    """Every ``substrate: lxc`` module as a concrete guest spec, sorted by id."""
    assignments = {a.module_id: a for a in zones.assign_ips(manifests)}
    guests: List[LxcGuest] = []
    for man in sorted(manifests, key=lambda m: m.id):
        if man.substrate != "lxc":
            continue
        rt = _runtime(man.path)
        evidence = man.evidence or {}
        guests.append(LxcGuest(
            id=man.id,
            hostname=man.hostname,
            vmid=evidence.get("vmid"),
            zone=man.network_zone,
            real_ip=parse_real_ip(evidence.get("ip")),
            synthetic_ip=assignments[man.id].ip,
            ports=list(man.ports),
            technique_class=man.technique_class,
            flag_value=man.flag.value if man.flag else "",
            flag_placement=man.flag.placement if man.flag else "",
            flag_mode=str(rt.get("flag_mode", "0600")),
            app=str(rt.get("app", "app/server.py")),
            ready=rt.get("ready") is True,
            path=man.path,
        ))
    return guests


def guest_is_ready(guest: LxcGuest) -> bool:
    """A guest is provisionable only once its app is actually wired.

    Same contract as ``live.ready_modules`` for containers: ``runtime.json``
    must say ``ready: true`` AND the stdlib service file must exist on disk.
    """
    return guest.ready and bool(guest.path) and os.path.isfile(os.path.join(guest.path, guest.app))


def provision_commands(guest: LxcGuest,
                       ostemplate: str = DEFAULT_OSTEMPLATE,
                       storage: str = DEFAULT_STORAGE) -> List[str]:
    """Canonical ``pct`` sequence to bring one guest up on the brain.

    Returned as command strings (same convention as ``generator.build_vms``'s
    ``bringup``). ``keystone.live`` runs these over SSH to the brain; BRINGUP.md
    prints them verbatim. All destructive scope is pinned to this guest's VMID.

    No ``gw=`` is set on the NIC: ``vmbr50`` and ``vmbr51`` are both uplink-less
    by design, so the guest has no default route off its segment — the crown
    cannot phone home. The bridge is picked by zone (corp->vmbr50, data->vmbr51)
    so a DATA guest lands on the dedicated data VLAN after the 2026-10-15
    redesign.
    """
    if guest.vmid is None or guest.real_ip is None:
        return [f"# {guest.id}: cannot provision — manifest lacks evidence.vmid/evidence.ip"]
    vmid = guest.vmid
    place = BRAIN_BRIDGE_FOR_ZONE.get(
        guest.zone, {"bridge": BRAIN_BRIDGE, "cidr": BRAIN_CIDR})
    net = (f"name=eth0,bridge={place['bridge']},firewall=1,"
           f"ip={guest.real_ip}/{ipaddress.ip_network(place['cidr']).prefixlen}")
    # The app lives in its own directory, deliberately NOT the flag's directory:
    # the vault's flag is /vault/secrets/master.key, and no service may ever sit
    # in — let alone list — the secrets dir. provision.sh (authored per module)
    # creates the flag directory at the manifest placement itself.
    app_dir = f"/opt/keystone/{guest.id}"
    stage = f"{BRAIN_STAGE}/{guest.id}"
    cmds = [
        f"pct create {vmid} {ostemplate} --hostname {guest.hostname} "
        f"--unprivileged 1 --features nesting=0 --onboot 0 --ostype debian "
        f"--cores {DEFAULT_CORES} --memory {DEFAULT_MEMORY_MB} --swap {DEFAULT_MEMORY_MB} "
        f"--rootfs {storage}:{DEFAULT_ROOTFS_GB} "
        f"--net0 {net}",
        f"pct start {vmid}",
    ]
    # Inter-subnet route for the corp<->data L3 split (2026-10-15): with the crown
    # on its own VLAN 51 / 10.50.1.0/24, corp<->vault is ROUTED through the hEX
    # (which enforces corp->vault:8200 and seals the rest). No gw= is set, so only
    # this single host route is added — the crown keeps no default route and still
    # cannot phone home. ``ip route replace`` keeps the step idempotent on re-runs.
    if guest.zone == "corp":
        cmds.append(
            f"pct exec {vmid} -- ip route replace {BRAIN_DATA_CIDR} via {CORP_GATEWAY}")
    elif guest.zone == "data":
        cmds.append(
            f"pct exec {vmid} -- ip route replace {BRAIN_CIDR} via {DATA_GATEWAY}")
    cmds += [
        f"pct exec {vmid} -- install -d -m 0755 {app_dir}",
        # Push the stdlib service and the per-guest provisioner into the guest
        # from the brain-side staging dir (keystone.live lxc stages them there).
        f"pct push {vmid} {stage}/server.py {app_dir}/server.py --perms 0755",
        f"pct push {vmid} {stage}/provision.sh {app_dir}/provision.sh --perms 0755",
        # Provisioner plants dirs/users/autostart; the per-run flag is stamped
        # separately (lxc_stamp), never baked in.
        f"pct exec {vmid} -- sh {app_dir}/provision.sh",
    ]
    return cmds


def build_lxc(manifests: List[Manifest]) -> Dict:
    """The ``lxc.json`` provisioning plan (brain tier), analogous to compose.yaml."""
    items = []
    for guest in lxc_guests(manifests):
        items.append({
            "id": guest.id,
            "hostname": guest.hostname,
            "vmid": guest.vmid,
            "substrate": "lxc",
            "zone": guest.zone,
            "bridge": BRAIN_BRIDGE,
            "ip": guest.synthetic_ip,       # logical, for scoring/dashboard parity
            "real_ip": guest.real_ip,       # actual vmbr50 address on the brain
            "ports": guest.ports,
            "technique_class": guest.technique_class,
            "flag": {
                "value": guest.flag_value,
                "placement": guest.flag_placement,
                "mode": guest.flag_mode,
            },
            "app": guest.app,
            "ready": guest.ready,
            "bringup": provision_commands(guest),
        })
    return {
        "brain": BRAIN_HOST,
        "bridge": BRAIN_BRIDGE,
        "bridge_cidr": BRAIN_CIDR,
        "vmid_range": list(VMID_RANGE),
        "lxc": items,
    }


# --------------------------------------------------------------------------- #
# Brain-side segmentation (the vmbr50 firewall).
# --------------------------------------------------------------------------- #

def _corp_hosts(guests: List[LxcGuest]) -> List[Dict[str, object]]:
    """CORP members: brain LXCs plus declared VM and physical-host extras."""
    out = [{"id": g.id, "hostname": g.hostname, "ip": g.real_ip,
            "allow_data": True}
           for g in guests if g.zone == "corp"]
    out += [h for h in CORP_EXTRA_HOSTS]
    return out


def _data_hosts(guests: List[LxcGuest]) -> List[LxcGuest]:
    return [g for g in guests if g.zone == "data"]


def brain_segmentation_rules(guests: List[LxcGuest]) -> List[Dict[str, str]]:
    """Concrete accept rules for ``vmbr50``, derived from ``zones.ZONE_POLICY``.

    Only rules whose endpoints have resolved real addresses are emitted; the
    default policy is DROP, so an unresolved host (e.g. dc01 before its vmbr50
    IP is known) is simply denied until declared — never accidentally allowed.

    The returned shape mirrors ``zones.firewall_rules`` so the renderer and the
    tests can treat both firewalls the same way.
    """
    corp = [h for h in _corp_hosts(guests) if h.get("ip")]
    data = [g for g in _data_hosts(guests) if g.real_ip]
    rules: List[Dict[str, str]] = []

    # DMZ pivot ingress -> CORP (this is the "CORP reachable only from DMZ"
    # inbound edge). Post-redesign the DMZ pods are macvlan hosts on VLAN 9,
    # so the real source CIDR is 10.99.50.0/24 — frames hairpin through the
    # hEX and re-enter vmbr50 from labtrunk.50.
    for h in corp:
        rules.append({"desc": f"dmz->corp {h['id']}", "src": DMZ_REAL_CIDR,
                      "dst": h["ip"], "action": "accept"})

    # intra-CORP (cred reuse / lateral between brain CORP hosts).
    for a in corp:
        for b in corp:
            if a["ip"] != b["ip"]:
                rules.append({"desc": f"corp {a['id']}->corp {b['id']}",
                              "src": a["ip"], "dst": b["ip"], "action": "accept"})

    # CORP -> DATA (the only path to the crown; restricted to the vault ports).
    for h in corp:
        if not h.get("allow_data", True):
            continue
        for vault in data:
            port = vault.service_port
            rules.append({"desc": f"corp {h['id']}->data {vault.id}",
                          "src": h["ip"], "dst": vault.real_ip,
                          "dport": str(port) if port else "",
                          "action": "accept"})

    # Infrastructure flows the hEX-centric topology produces on vmbr50:
    # the hEX gateway itself, the chainbreaker range-gw's dual-home leg, and
    # the house-LAN management path. All are second-guessed by the hEX
    # keystone_hex table; these are defence in depth. Note there is NO
    # corp->dmz hairpin rule: ZONE_POLICY has no corp->dmz edge, so the wall
    # denies it and we mirror that denial here (dmz->corp replies still pass
    # via ct state established,related).
    rules.append({"desc": "hEX corp gateway->corp", "src": CORP_GATEWAY,
                  "dst": BRAIN_CIDR, "action": "accept"})
    rules.append({"desc": "corp->hEX corp gateway", "src": BRAIN_CIDR,
                  "dst": CORP_GATEWAY, "action": "accept"})
    rules.append({"desc": "range-gw (CT910) dual-home->corp", "src": "10.50.0.254",
                  "dst": BRAIN_CIDR, "action": "accept"})
    rules.append({"desc": "corp->range-gw (CT910) dual-home", "src": BRAIN_CIDR,
                  "dst": "10.50.0.254", "action": "accept"})
    rules.append({"desc": "house-LAN mgmt->corp (review)", "src": "192.168.0.10",
                  "dst": BRAIN_CIDR, "action": "accept"})
    rules.append({"desc": "corp->house-LAN mgmt (review)", "src": BRAIN_CIDR,
                  "dst": "192.168.0.10", "action": "accept"})
    return rules


def crown_reachable_sources(guests: List[LxcGuest]) -> List[str]:
    """Every source address the brain firewall lets reach a DATA host.

    The invariant (tested): this is a subset of CORP real addresses — never the
    DMZ subnet, never the attacker subnet, never an arbitrary bridge host.
    """
    data_ips = {g.real_ip for g in _data_hosts(guests) if g.real_ip}
    srcs = set()
    for r in brain_segmentation_rules(guests):
        if r["action"] == "accept" and r["dst"] in data_ips:
            srcs.add(r["src"])
    return sorted(srcs)


def render_brain_firewall(guests: List[LxcGuest]) -> str:
    """Render the vmbr50 policy as an nftables ``bridge`` ruleset.

    A ``bridge``-family table is used deliberately: same-bridge CT<->CT traffic
    is filtered at the bridge layer, not the IP forward layer. The table is
    scoped to ``vmbr50`` so the brain's unrelated bridges (vmbr0 house LAN,
    vmbr9/vmbr43 estates, vmbr51 data) are never touched. Default DROP for
    vmbr50; only the policy accepts below pass. Since the 2026-10-15 redesign
    DATA lives on vmbr51 — corp->data frames hairpin through the hEX and are
    seen here only on their vmbr50 leg; vmbr51 frames match the first rule
    (non-vmbr50 accept) and are governed by the hEX keystone_hex table.

    Correctness on the brain is validated host-side by ``keystone.live
    lxc-verify`` (live probes), exactly as the podman side validates
    ``firewall.nft`` with ``keystone.live verify`` — see BRINGUP.md.
    """
    rules = brain_segmentation_rules(guests)
    corp = [h for h in _corp_hosts(guests) if h.get("ip")]
    data = [g for g in _data_hosts(guests) if g.real_ip]
    prefix = ipaddress.ip_network(BRAIN_CIDR).prefixlen
    out = [
        "#!/usr/sbin/nft -f",
        "# Generated by keystone.lxc — do not edit by hand.",
        "# Brain (Proxmox) segmentation for the Keystone CORP/DATA LXC tier.",
        f"# Bridge {BRAIN_BRIDGE} ({BRAIN_CIDR}); isolated, no uplink/gateway.",
        "# Mirrors keystone.zones.ZONE_POLICY on the brain's real addresses:",
        "#   CORP reachable only from DMZ (+ intra-CORP); DATA only from CORP.",
        "# Scoped to vmbr50 only — unrelated brain bridges are left untouched.",
        "add table bridge keystone_brain",
        "delete table bridge keystone_brain",
        "table bridge keystone_brain {",
        "  chain forward {",
        "    type filter hook forward priority -10; policy drop;",
        # In the bridge family iifname/oifname are the PORT devices (veth/tap),
        # never the master bridge — that first rule accepted every frame and
        # silently disabled the whole table. ibrname/obrname carry the bridge.
        "    # Leave every non-vmbr50 bridge completely alone.",
        f"    meta ibrname != \"{BRAIN_BRIDGE}\" meta obrname != \"{BRAIN_BRIDGE}\" accept",
        "    # Non-IP (ARP etc.) within the segment must still resolve.",
        "    meta protocol arp accept",
        "    ct state established,related accept",
        f"    # The attacker zone must never touch the brain segment — neither",
        f"    # the legacy logical range nor the real VLAN 66 CIDR.",
        f"    ip saddr {ATTACKER_CIDR} drop",
        f"    ip saddr {ATTACKER_REAL_CIDR} drop",
    ]
    for g in data:
        out.append(f"    # DATA host {g.id} ({g.real_ip}) — CORP-only below; all else dropped.")
    for r in rules:
        dport = f" tcp dport {r['dport']}" if r.get("dport") else ""
        out.append(f"    ip saddr {r['src']} ip daddr {r['dst']}{dport} accept  # {r['desc']}")
    out += [
        "    # Explicit belt-and-suspenders: nothing but the CORP accepts above",
        "    # may reach a DATA host, even if the future DMZ trunk lands frames",
        "    # for the vault onto this bridge.",
    ]
    for g in data:
        out.append(f"    ip daddr {g.real_ip} drop  # deny any non-CORP source -> {g.id}")
    out += [
        f"    # Any remaining vmbr50 traffic (incl. DATA->CORP back-channel) is dropped.",
        f"    ip saddr {BRAIN_CIDR} ip daddr {BRAIN_CIDR} drop  # /{prefix} default-deny",
        "  }",
        "}",
        "",
    ]
    return "\n".join(out)
