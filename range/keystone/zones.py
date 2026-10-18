"""Software-defined network zones and reachability policy.

The range is segmented into four zones. The crown jewel lives in DATA and is
reachable ONLY by chaining a compromise: attacker -> dmz (foothold) -> corp
(pivot) -> data. No zone lets the attacker touch DATA directly; that is the
structural reason a single patch cannot close the lab.

This module is pure data + pure functions so it can be unit tested with no
network stack present. The generator turns it into podman networks + an
nftables map; the launcher verifies the live range matches it.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Dict, List, Tuple

# Zone -> subnet. Deterministic so IP assignment and the firewall map are stable.
ZONE_SUBNETS: Dict[str, str] = {
    "attacker": "10.80.0.0/24",
    "dmz": "10.80.10.0/24",
    "corp": "10.80.20.0/24",
    "data": "10.80.30.0/24",
}

# Directed allow policy between zones (source -> set of reachable destinations).
# Everything not listed is DENIED by default. Note there is NO attacker->corp,
# attacker->data, or dmz->data edge: those gaps force real pivoting.
ZONE_POLICY: Dict[str, List[str]] = {
    "attacker": ["dmz"],
    "dmz": ["dmz", "corp"],
    "corp": ["corp", "data"],
    "data": ["data"],
}

# Real-world (hEX / homelab) segment mapping of the SAME zone model. Homelab
# Keystone runs attack over the lab's physical VLANs instead of the podman
# 10.80.x subnets; the scorer must resolve zones for both worlds or every
# zone-dependent category silently zeroes (run 8 lost IA/lateral/pivot/crown
# this way). Subnets here do not overlap ZONE_SUBNETS, so both can coexist.
LAB_ZONE_SUBNETS: Dict[str, str] = {
    "attacker": "10.10.66.0/24",   # attack VLAN 66 (lab)
    "dmz": "10.99.50.0/24",        # VLAN 9 (vmbr9 estate)
    "corp": "10.50.0.0/24",        # VLAN 50 (vmbr50)
    "data": "10.50.1.0/24",        # VLAN 51 (vmbr51)
}

# A conventional operator/attacker box always sits at .10 in the attacker zone.
ATTACKER_IP = "10.80.0.10"


@dataclass(frozen=True)
class Assignment:
    module_id: str
    hostname: str
    zone: str
    ip: str
    ports: Tuple[int, ...]


def zone_of_ip(ip: str) -> str:
    """Return the zone an IP belongs to, or '' if it is out of scope.

    Consults both the podman (10.80.x) and lab (10.10.66 / 10.99.50 / 10.50.x)
    maps; a run dir's own zones.json is handled by evidence.zone_of instead.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    for zone, cidr in _all_subnets():
        if addr in ipaddress.ip_network(cidr):
            return zone
    return ""


def _all_subnets() -> List[Tuple[str, str]]:
    # The two worlds share zone NAMES but different CIDRs, so this is a
    # (zone, cidr) pair list — not a dict — or one map would clobber the other.
    return list(LAB_ZONE_SUBNETS.items()) + list(ZONE_SUBNETS.items())


def all_in_scope_cidrs() -> List[str]:
    return [cidr for _, cidr in _all_subnets()]


def is_in_scope(ip: str) -> bool:
    return zone_of_ip(ip) != ""


def reachable(src_zone: str, dst_zone: str) -> bool:
    """Is dst_zone reachable from src_zone under the segmentation policy?"""
    return dst_zone in ZONE_POLICY.get(src_zone, [])


def assign_ips(manifests) -> List[Assignment]:
    """Deterministically assign one IP per module from its zone subnet.

    Hosts are numbered from .20 upward within each zone (leaving .1 for the
    gateway and .10 for well-known boxes). Ordering is by module id so the map
    is stable across runs — reset rotates *flags*, never topology.
    """
    counters: Dict[str, int] = {z: 20 for z in ZONE_SUBNETS}
    out: List[Assignment] = []
    for man in sorted(manifests, key=lambda m: m.id):
        zone = man.network_zone
        net = ipaddress.ip_network(ZONE_SUBNETS[zone])
        host = counters[zone]
        counters[zone] += 1
        ip = str(net.network_address + host)
        out.append(
            Assignment(
                module_id=man.id,
                hostname=man.hostname,
                zone=zone,
                ip=ip,
                ports=tuple(man.ports),
            )
        )
    return out


def firewall_rules(assignments: List[Assignment]) -> List[Dict[str, str]]:
    """Expand the zone policy into concrete allow rules between subnets.

    Returned as structured dicts; ``generator`` renders them to nftables. The
    default policy is DROP, so only these allows exist.
    """
    rules: List[Dict[str, str]] = []
    for src, dsts in ZONE_POLICY.items():
        for dst in dsts:
            if src == dst:
                continue  # intra-zone traffic is allowed implicitly
            rules.append(
                {
                    "src_zone": src,
                    "dst_zone": dst,
                    "src_cidr": ZONE_SUBNETS[src],
                    "dst_cidr": ZONE_SUBNETS[dst],
                    "action": "accept",
                }
            )
    return rules


def crown_is_isolated(manifests) -> bool:
    """True iff no DATA-zone module is reachable from attacker or dmz directly.

    This is the invariant the segmentation must preserve. Unit-tested so a future
    edit to ZONE_POLICY that accidentally exposes DATA fails the self-test.
    """
    data_modules = [m for m in manifests if m.network_zone == "data"]
    if not data_modules:
        return True
    for bad_src in ("attacker", "dmz"):
        if reachable(bad_src, "data"):
            return False
    return True
