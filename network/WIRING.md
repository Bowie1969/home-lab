# Wiring — every cable, both ends

**Layout: final, designed 2026-10-02 (night)** — VLAN backbone on the SG108E, the Asus as lab edge
*and* room router *and* lab Wi-Fi access point. `State` says what is physically true right now; the
hEX is still in its **flat** build (see §6 for the rollback), the switch is not yet configured.

One row per physical cable, both ends named. Tape the label on each cable end.

## 1. House side — 192.168.0.0/24, modem at 192.168.0.1

| # | Cable | End A | End B | Carries | Label | State |
|---|---|---|---|---|---|---|
| H1 | patch | **brain** (`willshomelab`) onboard RJ-45 | **house switch / modem** LAN port | `192.168.0.240` static — the vault's whole lifeline | `HOUSE-BRAIN` | **in place** |
| H2 | patch | **Asus `wan`** | **house uplink** (the modem's LAN, once the Sagemcom is the gateway; today the Asus *is* the gateway) | the house's internet | `HOUSE-UPLINK` | in place |
| H3 | patch *(optional)* | house switch, any port | **Windows box** `Ethernet 5` | the TAFE/legacy box | `HOUSE-WIN` | unplugged |
| H4 | USB | **archive drive** | **brain** USB | bulk storage, Proxmox backups | — | **to do** |
| H5 | *(radio)* | **Parrot** `wlp9s0` | house Wi-Fi | `192.168.0.13` — internet, tailnet, and the only way Parrot reaches the house | — | up |
| H6 | *(radio)* | **brain** `wlp2s0` | house Wi-Fi | host management only, **never bridged into a VM** | — | up |
| H7 | *(radio)* | **Z930** / Windows box / phone | house Wi-Fi | the watchdog's path, and the out-of-band internet | — | — |

## 2. Lab edge — the Asus RT-AX1800S (edge router + room router + lab AP)

| # | Cable | End A | End B | Carries | Label | State |
|---|---|---|---|---|---|---|
| E1 | patch | **Asus LAN port** | **hEX `wan`** *(the leftmost port — this box names it `wan`, there is no `lan1`)* | the lab's **gated uplink**. Unconfigured on the hEX, so it is **dead by default** — that is the air-gap | `EDGE-TO-HEX` | **to pull** |
| E2 | patch | **Asus LAN port 2** (the lab SSID's bridge) | **SG108E p6** | lab Wi-Fi injected as **VLAN 66 (attack)**, untagged on this port | `EDGE-LABWIFI` | **to pull** |
| E3 | — | **room SSID + room LAN ports** on the Asus | room phone/laptop/printer | the room network, on the Asus's own LAN | — | — |

**Two rules that make E2 safe, not a hole:**

1. The Asus's lab-SSID bridge gets **no IP, no DHCP, and no forwarding** to the Asus's WAN or to the
   room LAN. It is a pure L2 extension of VLAN 66 — the clients' gateway is still the hEX
   (`10.10.66.1`), and the hEX still decides everything.
2. **One cable only** between the Asus and the lab (E2). A second path Asus→switch is a route around
   the hEX.

**The cost, stated plainly:** the edge box now carries a lab trust domain. It faces the internet, so
a compromised or misconfigured Asus has a foot on the attack segment — the hEX stops being the *only*
thing between the lab and the internet-facing device. **Safer variant, if you want the invariant
intact: skip E2, and put the lab SSID on a dedicated AP downstream of the boundary** (the freed
Blackhawk/Netgear in AP mode, or any spare AP) cabled to **SG108E p7** — the edge router then never
touches the lab.

## 3. Lab side — hEX + SG108E, air-gapped, no WAN

| # | Cable | End A | End B | Carries | Label | State |
|---|---|---|---|---|---|---|
| L1 | patch | **hEX `lan5`** | **SG108E p1** | the **trunk**: tagged VLAN 10 / 20 / 66 | `L5-TRUNK` | **to pull** |
| L2 | patch | **hEX `lan2`** | **SG108E p8** | mgmt `10.10.0.0/24`, untagged VLAN 1 | `L2-SWMGMT` | **to pull** |
| L3 | patch | **SG108E p5** | **Parrot** `enp8s0` | mgmt `10.10.0.2` — the admin path | `SW-P5-ADMIN` | **to pull** |
| L4 | patch | **SG108E p2** | **Parrot** `enp8s0` | attack `10.10.66.5` — the same cable, moved, to engage | `SW-P2-ATTACK` | to pull |
| L5 | patch | **SG108E p3** | **flat switch 1**, port 1 | targets VLAN 10 fan-out | `SW-P3-TARGETS` | **to pull** |
| L6 | patch | **flat switch 1**, any port | **Windows box** USB-GbE adapter | the 2 vulnerable VMs | `TGT-WINBOX` | **needs the adapter** |
| L7 | patch | **flat switch 1**, any port | **brain** 2nd NIC | lab target VMs | `TGT-BRAIN` | **needs the NIC** |
| L8 | patch | **SG108E p4** | **flat switch 2**, port 1 | corp VLAN 20 fan-out | `SW-P4-CORP` | **to pull** |
| L9 | patch | **flat switch 2**, any port | corp endpoints (Windows box, workstations) | corp hosts | — | as needed |
| L10 | patch | **SG108E p6** | **Asus LAN port 2** | lab Wi-Fi, VLAN 66 (see §2) | `EDGE-LABWIFI` | **to pull** |
| L11 | patch | **SG108E p7** | *spare* — or the dedicated lab AP if you take the safer variant | VLAN 1 spare / VLAN 66 AP | `SW-P7-SPARE` | spare |
| L12 | mains | **SG108E** + smart plug | power | a wedge becomes a 30-second remote power-cycle | — | **worth buying** |
| L13 | mains | **flat switch 1, 2, hEX** | power | an unpowered switch looks exactly like an unplugged cable | — | check they are on |

**The operator's one-cable dance:** Parrot has one wired port. `L3` (p5, admin) and `L4` (p2, attack)
are the same cable in one of two ports — admin is never on the attack port. Moving it back is the same
move. A USB dongle on Parrot would end the dance (p5 and p2 at once).

## 4. Cables that must never exist

| Never | Why |
|---|---|
| **hEX ↔ house LAN**, except through the Asus (`E1`) | the `wan` port must only ever see the Asus. Any other house cable is a bypass of the gated uplink |
| **A second cable between the Asus and the lab** (beyond `E2`) | a second path is a route around the hEX |
| **An IP/DHCP/forwarding on the Asus's lab-SSID bridge** | that is the WAN→LAN hole, rebuilt on the edge box |
| **An untagged VLAN-1 member on SG108E p1** | management must never ride the trunk — that is what wedged this switch before |
| **A tagged trunk on a flat switch** | flat switches carry one segment, never tags |
| **Two cables from one flat switch into two ports** | one broadcast domain bridges two segments; seen and fixed once already |
| **Parrot's Wi-Fi and wire bridged together** | that makes Parrot a router between house and lab. One profile per segment, no bridges on the lab NIC |
| **The brain's Wi-Fi bridged into a VM** | Wi-Fi cannot carry a bridge; the lab VMs live on the wire |
| **A capsule/loop from a switch back into itself** | a dumb switch has no STP, so it storms |

## 5. Port maps

```
hEX RB750Gr3 (OpenWrt: no lan1 — the first port is "wan")
 wan   unconfigured      uplink → Asus          (dead by default = the air-gap)
 lan2  10.10.0.1         mgmt   → SG108E p8
 lan3  —                 spare  (attack in the flat rollback)
 lan4  —                 spare  (targets in the flat rollback)
 lan5  —                 TRUNK  → SG108E p1     (VLAN 10/20/66 tagged)

TL-SG108E (802.1Q backbone)                 flat switches (plumbing only)
 p1  trunk  tagged 10/20/66, NOT VLAN 1      sw1: every port = VLAN 10 (targets)
 p2  access 66  → Parrot (operator)          sw2: every port = VLAN 20 (corp)
 p3  access 10  → flat sw1 → targets hosts
 p4  access 20  → flat sw2 → corp hosts
 p5  access 1   → Parrot (admin)
 p6  access 66  → Asus lab SSID
 p7  access 1   → spare (or the dedicated lab AP)
 p8  access 1   → hEX lan2   (the switch's own management lives here, set by hand)
```

## 6. Segments, and who is on them

| Segment | VLAN | Subnet | Gateway | Occupants |
|---|---|---|---|---|
| mgmt | untagged 1 | 10.10.0.0/24 | 10.10.0.1 (hEX `lan2`) | Parrot `.2` (admin only), the SG108E's management address. **No DHCP** |
| attack | 66 | 10.10.66.0/24 | 10.10.66.1 | Parrot `.5` reserved (cable), lab Wi-Fi clients (Asus), the E7470 Kali box |
| targets | 10 | 10.10.10.0/24 | 10.10.10.1 | Windows box's 2 VMs, brain target VMs, the estate `.41–.49` |
| corp | 20 | 10.10.20.0/24 | 10.10.20.1 | the pivot tier: endpoints, workstations |
| house | — | 192.168.0.0/24 | 192.168.0.1 | brain `.240`, Parrot `.13`, Windows box, Z930, phone |
| edge/room | — | *set when the edge is configured* | the Asus | room phone/laptop/printer |

**Policy** (as the hEX enforces it): mgmt→everything allow · attack→targets only (never corp, never
mgmt) · targets→attack (return) + corp (the pivot) · corp→targets (return) only · everything→mgmt
dropped. ICMP allowed inside permitted pairs; every drop logged.

## 7. The rollback — the flat build

`hex-fresh.sh` with `MODE=flat` puts all four segments back on physical ports (`lan2` mgmt, `lan3`
attack, `lan4` targets, `lan5` corp), with the switch out of the path and the two flat switches doing
the fan-out. **The `wan` port stays unconfigured, so a rollback keeps the air-gap.** That table is the
previous version of this file in git history and in `LAB.md` §3.

The switch earns its way in through `DESIGN.md` §7: factory reset → 30-minute dumb load test → the
one scripted VLAN pass → 30 minutes through the trunk with management on its own cable. Its own
management address must be set **by hand** to a lab address on VLAN 1 (`sg108e-fresh.sh` does not set
it, and it must not stay `192.168.0.1` — that is the house modem, which has already caused one false
outage).

**Setup gotcha, verified 2026-10-02:** a factory-reset SG108E answers at `192.168.0.1` — the *same*
address as the live Asus. With Parrot's Wi-Fi up, a request to `192.168.0.1` leaves by the Wi-Fi
default route and reaches the Asus, not the switch. So run the script with Parrot's lab NIC on a
VLAN-1 port of the switch (p5) **and** either Wi-Fi off or a `/32` route to `192.168.0.1` on that
NIC. `sg108e-fresh.sh` step 0 checks which device answered and refuses to configure the wrong one —
read that message rather than retrying.

## 8. If something is unreachable

1. **Carrier first.** `cat /sys/class/net/enp8s0/carrier` on Parrot, or look at the port LEDs. No carrier means the cable, the port, or the power — not a config problem.
2. **Check the switch has mains.** An unpowered switch is indistinguishable from an unplugged cable.
3. **Check for a second path.** Two cables from one switch into two ports, or a stray Asus→lab cable, merge segments and make everything intermittent. This has happened twice.
4. **From the router, ping the target.** If the router can reach it and Parrot cannot, the fault is policy or Parrot's route, not the device.
5. **Management wedged, ARP still answering?** That is the SG108E's signature. Power-cycle it — and if it happens on a clean configuration, the box is faulty and a used managed switch with a real CLI is the money to spend.
6. **Remember the ARP trap.** A reply to ARP is not proof of life: the house modem answers ARP for stale clients, which is why two hosts looked alive for nine hours while a NIC was hung.
