# SG108E VLAN re-plan — Keystone VM redesign

Live state for the TL-SG108E (at `10.10.0.5/24` on the mgmt segment),
applied and verified 2026-10-17. Supersedes the earlier
VLAN 10 (targets) / VLAN 20 (corp) plan from `lab-server/lab/DESIGN.md`.

The switch has **no SSH/CLI** (RTL8370 ASIC + MCU, not Linux). All
changes are made in the web UI at `http://10.10.0.5/` from the dedicated
hEX `lan3` management link (`10.10.0.50/32` with a host route to the switch).
The TL-SG108E
V1–V6 remote-config CVE class is why mgmt stays pinned to the mgmt VLAN.

Back up the running config before touching anything:

- `System → Backup and Restore → Backup`  → save to
  `lab-configs/sg108e/bak/pre-redesign-20261015.cfg` in this repo.
- Also save the three config pages as HTML (same place):
  `802.1Q VLAN`, `802.1Q PVID Setting`, `MTU VLAN Config`.

## Target VLAN table

| VLAN | name     | role                                    | subnet (hEX)      |
|------|----------|-----------------------------------------|-------------------|
| 1    | mgmt     | switch + hEX mgmt; untagged             | 10.10.0.0/24      |
| 9    | dmz      | DMZ service hosts (ex-estate)           | 10.99.50.0/24     |
| 50   | corp     | corp VMs (ex-keystone), AD, workstations| 10.50.0.0/24      |
| 51   | data     | crown vault only (**NEW**)              | 10.50.1.0/24      |
| 66   | attacker | Parrot + attacker VMs                   | 10.10.66.0/24     |

**Retired:** VLAN 10 (targets) and VLAN 20 (corp) from the pre-redesign
layout. Any port assigned to those VLANs must be moved to 9/50 before
clearing the entry.

## Target port profile

| port | role                 | mode     | PVID | tagged VLANs       | notes |
|------|----------------------|----------|------|--------------------|-------|
| p1   | TRUNK to hEX lan5    | tagged   | 1    | 9, 50, 51, 66      | not a VLAN 1 member |
| p2   | Parrot attack        | access   | 66   | —                  | current engage port |
| p3   | CORP physical drop   | access   | 50   | —                  | EvilKit OS Pi; add fan-out for Mac |
| p4   | DMZ fan-out          | access   | 9    | —                  | physical DMZ targets |
| p5   | Parrot admin         | access   | 1    | —                  | mgmt only |
| p6   | Asus LAN2 (lab Wi-Fi)| access   | 66   | —                  | VLAN 66 extension |
| p7   | DATA access          | access   | 51   | —                  | isolated physical DATA port |
| p8   | hEX lan3 (mgmt)      | access   | 1    | —                  | dedicated switch-management link |

The brain's USB trunk NIC `enx00e04c46911b` stays directly connected to hEX
`lan2`; switch p1 connects to hEX `lan5`. The hEX bridges each matching pair
(`lan2.9`↔`lan5.9`, `lan2.50`↔`lan5.50`, `lan2.51`↔`lan5.51`) so physical
hosts and brain guests share the same real L2 zone while routing between zones
still crosses the hEX firewall.

## Click path for the VLAN add (data = 51)

1. **VLAN → 802.1Q VLAN**
   - *Add* VLAN ID `51`, Description `data`
   - Member ports: `1 (Tagged)`, `7 (Untagged)`
   - *Apply*
2. **VLAN → 802.1Q PVID Setting**
   - Port `7` → PVID `51` → *Apply*
3. **VLAN → 802.1Q VLAN** (verify trunk still carries 9, 50, 51, 66
   tagged on p1, while VLAN 1 remains untagged only on p5 and p8).

## Click path for the DMZ/CORP relabel (10/20 → 9/50)

If VLANs 10 and 20 still exist in the 802.1Q table:

1. **VLAN → 802.1Q VLAN** — *Add* `9 dmz` (p1 tagged, p4 untagged) and
   `50 corp` (p1 tagged, p3 untagged).
2. **PVID Setting** — p3 → `50`, p4 → `9`.
3. **VLAN → 802.1Q VLAN** — *Delete* VLAN 10 and VLAN 20 **last**.
4. Re-verify trunk membership for p1: `9/50/51/66 tagged`, not a VLAN 1 member.

Verified device readback after apply:

```text
vids:       [1,9,50,51,66]
tagMbrs:    [0x0,0x1,0x1,0x1,0x1]
untagMbrs:  [0x90,0x8,0x4,0x40,0x22]
pvids:      [1,66,50,9,1,66,51,1]
```

## Post-change sanity

From the hEX management link:

```bash
ping -c 2 10.10.0.5          # switch mgmt
ping -c 2 10.10.0.1          # hEX mgmt
# From any future physical DATA host on p7 after bring-up:
ping -c 2 10.50.1.1          # hEX data gateway
ping -c 2 10.50.0.<corp-ip>  # corp (expect: allowed by hEX corp→data? no — data→corp is DROP)
```

The `corp → data` edge is one-way: corp initiates to data, data cannot
initiate back. If data-side `ping 10.50.0.X` succeeds, the hEX rule
`drop keystone data-outbound` is missing — fix on the hEX, not the switch.

## Rollback

The previous table is preserved in `lab-server/lab/sg108e-fresh.sh` and can be
re-applied as VLANs `1/10/20/66`. hEX pre-change UCI and nft snapshots live in
`/root/worker-a/*pre-full-fabric*` on the router.
