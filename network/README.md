# Home-lab network

The physical and logical network that the benchmark range and dashboard run on.
Everything here is the owner's own equipment, segmented so that lab traffic can
never reach the house LAN, the self-hosted services, or the internet without
crossing the router firewall.

## Topology

```
                          internet
                             │
                   ┌─────────▼─────────┐
                   │  Asus RT-AX1800S  │  edge router + room router + lab Wi-Fi AP
                   │  (house gateway)  │
                   └─────────┬─────────┘
                             │ gated uplink (dead by default) + lab SSID = VLAN 66
                   ┌─────────▼─────────┐
                   │  MikroTik hEX     │  zone firewall (fw4 + keystone table)
                   │  lab router       │  routes + isolates every zone
                   └──┬──────┬─────┬───┘
                      │      │     └────────────── mgmt 10.10.0.0/24   (VLAN 1)
           trunk ─────┘      │
             │         brain USB trunk
      ┌──────▼─────┐   ┌─────▼──────────┐
      │ TL-SG108E  │   │  Proxmox brain │  Lenovo IdeaCentre 3 07ADA05
      │ 8p switch  │   │  (VMs + LXC)   │  lab-services · lab-ranges · lab-monitor
      └────────────┘   └────────────────┘
```

The hEX owns one gateway per zone and enforces the trust model. The brain's USB
trunk NIC carries the estate/DMZ and corp VLANs directly; the SG108E fans those
same zones out to physical hosts. Routing between zones always crosses the hEX
firewall — there is no direct zone-to-zone path that bypasses it.

## Zones and VLANs

| VLAN | Name     | Role                          | Subnet             |
|------|----------|-------------------------------|--------------------|
| 1    | `mgmt`   | switch + hEX management       | `10.10.0.0/24`     |
| 9    | `dmz`    | estate / DMZ service hosts    | `10.99.50.0/24`    |
| 50   | `corp`   | corp VMs, AD, workstations    | `10.50.0.0/24`     |
| 51   | `data`   | crown vault only              | `10.50.1.0/24`     |
| 66   | `attacker`| operator + attack VMs        | `10.10.66.0/24`    |

> `REDESIGN-VLAN-PLAN.md` is the **current** plan (9/50/51/66). `WIRING.md` and
> `DESIGN.md` predate it and still name the older 10/20 VLANs in places — treat
> the VLAN plan as the source of truth and the older docs as the physical/wiring
> reference.

## Files

| File | What it is |
|---|---|
| `WIRING.md` | Every physical cable, both ends, labelled |
| `DESIGN.md` | Zone/trust design and the firewall model |
| `REDESIGN-VLAN-PLAN.md` | Current SG108E 802.1Q VLAN + port table (applied 2026-10-17) |
| `hex-fresh.sh` | Idempotent hEX (OpenWrt) reprovisioner — VLANs, zones, `fw4` + Keystone `nft` table |
| `sg108e-fresh.sh` | SG108E config driver (web-CGI login + VLAN/PVID programming) |
| `asus-edge-fresh.sh` | Asus edge reprovisioner — lab SSID bridge, gated uplink |
| `asus-edge-runbook.md` | Flash/setup runbook for the Asus edge |

The `*-fresh.sh` scripts read credentials from environment variables
(`ROUTER_PW`, `SWITCH_PW`, `EDGE_PW`, `PPP_PASS`) — no password is committed.
They are provisioning tools for the owner's own devices, not a point-and-shoot
attack utility.
