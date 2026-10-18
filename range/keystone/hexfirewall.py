"""hEX (OpenWrt) re-homed ruleset — the Keystone zone policy ported to the lab router.

The hEX becomes the router and firewall for the range, replacing the brain
(Proxmox host) as the enforcement point. The range subnets are carried as VLANs
on the brain<->hEX trunk:

* **VLAN 9**  -> estate   ``10.99.50.0/24`` (vmbr9; the keystone *dmz* zone)
* **VLAN 50** -> keystone ``10.50.0.0/24``  (vmbr50; the keystone *corp* zone)
* **VLAN 51** -> data     ``10.50.1.0/24``  (vmbr51; the keystone *data* zone;
  the crown ``vault-keystone`` at ``10.50.1.14:8200`` — separated from corp
  at both L2 and L3 by the 2026-10-15 VM redesign)
* **VLAN 1**  -> mgmt     ``10.10.0.0/24``  (native/untagged; router admin only,
  never a keystone zone)

The emitted file is a complete, self-contained nftables ruleset in a dedicated
``ip``-family table (``table ip keystone_hex``). The ``ip`` family is deliberate:
on this OpenWrt build the inet family's nf_log backend is ``nf_log_ipv6``, so a
``log`` statement in an inet chain silently drops IPv4 log output — the *ip*
family logs through ``nf_log_ipv4`` and the drop lines reach ``logread``. The
table is applied atomically (``delete``/``add``) from ``/etc/firewall.user`` on
every fw4 reload; it hooks at priority -10, *before* fw4's forward chain
(priority 0), so every accept/drop here is terminal and fw4 only ever sees
traffic this chain declines to judge.

Scope rules that keep the two firewalls from fighting:

* Traffic whose destination is **not** a range subnet is accepted (falls
  through to fw4) — the hEX's own northreach segments (attack/targets/corp on
  VLANs 66/10/20) keep their existing fw4 policy untouched.
* Everything else is judged by the exact Keystone zone policy, translated to
  the real segments: attacker (VLAN 66) -> dmz (estate) only; dmz -> corp
  only; corp -> data only on the vault port; data sealed; default drop with
  per-zone ``log prefix`` lines and counters for the SOC/dashboard.
* The deny rules that protect the crown are emitted *before* the broad zone
  accepts, exactly as in ``brain-firewall.nft``, so no accept can ever undo a
  crown denial.

The brain's own ``bridge keystone_brain`` table stays in place (defence in
depth); this ruleset is its routed-path counterpart on the hEX, derived from
the same ``lxc.brain_segmentation_rules`` source so the two cannot drift.
"""
from __future__ import annotations

from typing import List

from . import lxc

# Real segments on the hEX after the trunk conversion. The keystone zone model
# (zones.ZONE_POLICY: attacker->dmz->corp->data) maps onto them as follows;
# the hEX's own northreach segments (targets VLAN 10, corp VLAN 20) are NOT
# keystone zones and are deliberately absent from this mapping. Post-2026-10-15
# VM redesign, DATA is its own VLAN with its own /24 — corp and data are
# separated at both L2 and L3, not just by an ACL.
HEX_ATTACK_CIDR = "10.10.66.0/24"   # attack VLAN 66 — keystone attacker zone
HEX_DMZ_CIDR = "10.99.50.0/24"      # VLAN 9 (vmbr9 estate) — keystone dmz zone
HEX_CORP_CIDR = "10.50.0.0/24"      # VLAN 50 (vmbr50) — keystone corp zone
HEX_DATA_CIDR = "10.50.1.0/24"      # VLAN 51 (vmbr51) — keystone data zone (NEW)
HEX_MGMT_CIDR = "10.10.0.0/24"      # native VLAN 1 — management, not a zone

# Legacy alias: the pre-redesign code called the shared corp+data subnet
# ``HEX_CORP_DATA_CIDR``. External callers still use it to express "the brain
# keystone trunk subnet"; it keeps meaning ``10.50.0.0/24`` (the corp half).
HEX_CORP_DATA_CIDR = HEX_CORP_CIDR

# Every keystone range subnet (what this chain judges; everything else falls
# through to fw4 so the hEX's northreach segments stay untouched).
HEX_RANGE_CIDRS = (HEX_DMZ_CIDR, HEX_CORP_CIDR, HEX_DATA_CIDR)

# Trunk VLAN ids on the brain<->hEX link (matches the brain-side staging in
# the worker-a apply script; vmbr9 -> 9, vmbr50 -> 50, vmbr51 -> 51).
HEX_TRUNK_VLAN_ESTATE = 9
HEX_TRUNK_VLAN_KEYSTONE = 50
HEX_TRUNK_VLAN_DATA = 51

# Installed at /etc/keystone-hex.nft on the hEX; applied from /etc/firewall.user
# (runs on every fw4 reload, so the table survives boot and reloads).
HEX_NFT_INSTALL_PATH = "/etc/keystone-hex.nft"


def hex_segmentation_rules(guests: List[lxc.LxcGuest]) -> List[str]:
    """Concrete nftables statements for the hEX, in evaluation order.

    Reuses ``lxc.brain_segmentation_rules`` for the corp/data facts (crown
    port, corp hosts) so the hEX policy and the brain policy share one source
    of truth. Returns one statement per line, indentation excluded.
    """
    corp = [h for h in lxc._corp_hosts(guests) if h.get("ip")]
    data_capable_corp = [h for h in corp if h.get("allow_data", True)]
    data = [g for g in lxc._data_hosts(guests) if g.real_ip]
    vault_ip = data[0].real_ip if data else None
    vault_port = str(data[0].service_port) if data else "8200"

    lines: List[str] = []
    # Return traffic always passes (mirrors the brain table's ct rule).
    lines.append("ct state established,related counter accept")
    # Only the range subnets are this chain's business; fw4 keeps the rest.
    lines.append(
        f"ip daddr != {{ {HEX_DMZ_CIDR}, {HEX_CORP_CIDR}, {HEX_DATA_CIDR} }} "
        f"counter accept")
    # Attacker zone (VLAN 66): never reaches corp or data. Logged + dropped
    # BEFORE the attacker->dmz accept so the deny-side cannot be undone.
    lines.append(
        f"ip saddr {HEX_ATTACK_CIDR} "
        f"ip daddr {{ {HEX_CORP_CIDR}, {HEX_DATA_CIDR} }} "
        f'log prefix "drop keystone attacker->subsidiary " counter drop')
    # DMZ (estate) never reaches data directly; corp->data is the only edge.
    lines.append(
        f"ip saddr {HEX_DMZ_CIDR} ip daddr {HEX_DATA_CIDR} "
        f'log prefix "drop keystone dmz->data " counter drop')
    # Attacker -> dmz is the designed entry edge.
    lines.append(
        f"ip saddr {HEX_ATTACK_CIDR} ip daddr {HEX_DMZ_CIDR} counter accept")
    # DMZ (estate) -> CORP per host; the crown is denied before any accept.
    for h in corp:
        lines.append(
            f"ip saddr {HEX_DMZ_CIDR} ip daddr {h['ip']} counter accept  "
            f"# dmz->corp {h['id']}")
    # Intra-CORP parity with the brain table (same-subnet traffic stays on
    # vmbr50 L2 and never reaches this chain; kept so the ported ruleset is
    # the exact policy, not a subset).
    for a in corp:
        for b in corp:
            if a["ip"] != b["ip"]:
                lines.append(
                    f"ip saddr {a['ip']} ip daddr {b['ip']} counter accept  "
                    f"# corp {a['id']}->corp {b['id']}")
    # CORP -> DATA only on the vault port.
    if vault_ip:
        for h in data_capable_corp:
            lines.append(
                f"ip saddr {h['ip']} ip daddr {vault_ip} "
                f"tcp dport {vault_port} counter accept  "
                f"# corp {h['id']}->data vault-keystone")
        # Crown seal: nothing else reaches the vault, no matter the zone.
        lines.append(
            f"ip daddr {vault_ip} "
            f'log prefix "drop keystone crown-seal " counter drop')
    # Default deny for everything else addressed into the range.
    lines.append(
        f"ip daddr {{ {HEX_DMZ_CIDR}, {HEX_CORP_CIDR}, {HEX_DATA_CIDR} }} "
        f'log prefix "drop keystone default-deny " counter drop')
    return lines


def render_hex_firewall(guests: List[lxc.LxcGuest]) -> str:
    """Render the hEX ruleset as a complete, self-contained nftables file.

    A dedicated ``ip``-family table (atomic replace via add/delete/add, the
    same pattern as the brain ruleset) keeps the keystone policy independent of
    fw4's generated ruleset, and the ip family is required for ``log`` output
    on this OpenWrt build (the inet family's logger is nf_log_ipv6 there).
    ``nft -c -f`` on the output is the validation path.
    """
    lines = [
        "#!/usr/sbin/nft -f",
        "# Generated by keystone.hexfirewall — do not edit by hand.",
        "# hEX (labrouter) enforcement of the Keystone zone policy for the",
        "# re-homed range (brain<->hEX VLAN trunk: 9=estate/dmz, 50=keystone",
        "# corp, 51=keystone data). Hooks before fw4's forward chain;",
        "# non-range traffic falls through to fw4 untouched. Applied by",
        "# /etc/firewall.user on every fw4 reload.",
        "add table ip keystone_hex",
        "delete table ip keystone_hex",
        "add table ip keystone_hex",
        "table ip keystone_hex {",
        "  chain keystone_forward {",
        "    type filter hook forward priority -10; policy accept;",
    ]
    for stmt in hex_segmentation_rules(guests):
        lines.append(f"    {stmt}")
    lines.append("  }")
    lines.append("}")
    return "\n".join(lines) + "\n"


def hex_crown_reachable_sources(guests: List[lxc.LxcGuest]) -> List[str]:
    """Every source address the hEX chain lets reach the vault.

    The invariant (tested): CORP real addresses only — never the attacker
    VLAN, never the estate (dmz), never an arbitrary segment.
    """
    corp_ips = {h["ip"] for h in lxc._corp_hosts(guests)
                if h.get("ip") and h.get("allow_data", True)}
    vault = next(
        (g.real_ip for g in lxc._data_hosts(guests) if g.real_ip), None)
    if not vault:
        return []
    sources = set()
    for stmt in hex_segmentation_rules(guests):
        tokens = stmt.split()
        if tokens and tokens[0] == "ip" and "accept" in stmt \
                and f"daddr {vault}" in stmt:
            sources.add(tokens[tokens.index("saddr") + 1])
    return sorted(s for s in sources if s in corp_ips)
