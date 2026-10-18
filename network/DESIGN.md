# Lab network — from-scratch design

Written 2026-09-30. **This is now the authority for the lab's port map, addressing and policy.** It
supersedes the port tables in `northreach-network-build.md`, `segmented-switch-upgrade.md`,
`lab-build-walkthrough.md` and `tafe-vlan-lab-sg108e-steps.md` — those disagreed with each other and
with the hardware, and the memory carries a standing warning not to trust them.

**Built reality, 2026-09-30 — read this before §3.** The SG108E wedged again on a clean configuration
and had to be treated as unavailable, so the **fallback in §6 was taken deliberately**: the router now
carries all four segments itself, flat, with no VLANs anywhere — `lan2` mgmt, `lan3` attack, `lan4`
targets, `lan5` corp, each a physical port. The SG108E is unplugged, its configuration intact in
flash, and it is not part of the lab. §3's SG108E table is kept as the design of record if it ever
comes back; **`lab/WIRING.md` is the authority for what is cabled right now.**

## 1. Why four segments

The four uses decide it:

| Use | What it needs from the network | Verdict |
|---|---|---|
| **Self-hosting** (vault, files, DNS, git) | Nothing — it lives on the house LAN, reachable over the tailnet | no lab segment |
| **Red-team targets** | an attacker segment, a victim segment, and *somewhere to pivot to* | attack + targets + corp |
| **Home SOC** | to see the lab's policy decisions (the router's logs and counters) | the router is the tap |
| **Blukit operating station** | its own range is self-contained in podman; it needs no segment | no lab segment |

So: **mgmt · attack · targets · corp.** Three segments would be the minimum, but the *pivot tier* is
the whole reason to have physical segments rather than just more containers on the brain — and you
already own the second flat switch that fan-outs it. Deliberately dropped: `v25 data`, `v30`, `v40`,
`v50 hardware-targets` (the Sagemcom practice-target idea is superseded by the brain hosting ranges),
and the TAFE teaching block. All of those can be added back additively later; nothing here conflicts
with them.

## 2. Address plan

| Segment | VLAN | Subnet | Gateway | DHCP pool | Reservations | Purpose |
|---|---|---|---|---|---|---|
| **mgmt** | untagged (VLAN 1) | 10.10.0.0/24 | 10.10.0.1 (hEX `lan2`) | **none** | admin host 10.10.0.2 | admin only; unreachable from every other segment |
| **attack** | 66 | 10.10.66.0/24 | 10.10.66.1 | .100–.150 | operator 10.10.66.5 | the red-team / operator box |
| **targets** | 10 | 10.10.10.0/24 | 10.10.10.1 | .100–.150 | .21–.23 for the known target stack | victim hosts, fanned out by flat switch 1 |
| **corp** | 20 | 10.10.20.0/24 | 10.10.20.1 | .100–.150 | — | the pivot tier, fanned out by flat switch 2 |

Addressing is **DHCP from the router per segment**, with reservations for anything that must not
move. Every host then works by simply joining a segment, and there is no per-machine address book to
drift. (This is a deliberate change from the old static-everywhere scheme.)

## 3. Physical port map

### SG108E (the 8-socket switch — the 802.1Q backbone)

| Port | Mode | VLANs | PVID | Cables to |
|---|---|---|---|---|
| p1 | **trunk** | tagged 10, 20, 66 · **not** a member of VLAN 1 | 1 | hEX `lan5` |
| p2 | **access** | untagged 66 only · **not** a member of VLAN 1 | 66 | the operator box's built-in NIC |
| p3 | access | untagged 10 only | 10 | flat switch 1 → victim hosts |
| p4 | access | untagged 20 only | 20 | flat switch 2 → pivot hosts |
| p5–p7 | access | untagged 1 | 1 | spare |
| p8 | **mgmt** | untagged 1 only | 1 | the admin host, or the operator box's **USB dongle** |

### hEX (the 5-socket router)

| Interface | What it is | Address | Notes |
|---|---|---|---|
| `lan2` | management | 10.10.0.1/24 | admin only; no DHCP |
| `lan5` | trunk to SG108E p1 | — | plus `lan5.10`, `lan5.20`, `lan5.66` as the segment gateways |
| `lan3`, `lan4` | spare | — | deliberately unused, and that is the fallback path (§6) |
| `wan` | unused | — | the lab is air-gapped; each host's own Wi-Fi is its internet |

## 4. Policy

| From → To | mgmt | attack | targets | corp | internet |
|---|---|---|---|---|---|
| **mgmt** | allow | allow | allow | allow | n/a (no WAN) |
| **attack** | **drop** | — | allow | **drop** | n/a |
| **targets** | **drop** | allow (return path) | — | allow (pivot 1) | n/a |
| **corp** | **drop** | drop | allow (return path) | — | n/a |

Two deliberate departures from the old build, both fixes for problems that cost real time:

1. **ICMP is allowed within permitted pairs.** The old policy dropped it everywhere, so `ping`
   failed *by design* and every connectivity check became ambiguous. Scope is enforced by
   **destination address**, which is the actual control — not by protocol.
2. **The attack segment cannot reach the pivot tier directly.** Reaching corp must happen *through* a
   target, which is what makes a pivot a pivot and what gives the SOC something meaningful to detect.

## 5. Invariants that prevent the failures we have already paid for

- **One purpose per port.** The operator box's switch port is a *pure* access port. The old design
  put untagged management **and** tagged attack traffic on one port, and that is precisely what
  wedged the switch's management CPU, repeatedly, with a power-cycle as the only cure.
- **Admin access never rides the attack port.** Admin is p8 (with the operator box's USB dongle if it
  is also the admin host) or a separate admin machine. The old single-port arrangement is gone.
- **Flat switches only ever sit downstream of an access port.** They are plumbing; they enforce
  nothing, so they can never be given a trunk or more than one VLAN.
- **The trunk cable is the only cable between the switch and the router** (p1 ↔ `lan5`).
- **The management segment is a dead end**: no route from any other segment, on either device.
- **The lab stays air-gapped.** No WAN on the router; agents get their internet from their own Wi-Fi.
  That is also what keeps a "red team" run from being a risk to the house.

## 6. Build order, and the fallback

1. **Back up both devices** (router config tarball; the switch's config export) — even wiping, this is
   the rollback and it captures the real port map.
2. **Reset both** (switch: front-panel RESET ~10s or the web page's System Reset; router: `firstboot`
   then reboot — OpenWrt then defaults to 192.168.1.1 on `lan2`–`lan5`).
3. **Configure the router**: `hex-fresh.sh` (run on the router, cabled from the admin host to `lan2`).
4. **Configure the switch**: `sg108e-fresh.sh` (run from a host cabled to **p8**).
5. **Verify**: `verify-lab.sh` — the reachability matrix, which must match §4 exactly and must show
   `attack → corp` and everything `→ mgmt` failing.
6. **Document and back up the result**, then this file becomes the record.

**Fallback, if the switch misbehaves again:** the router alone can carry all four segments on
`lan2`–`lan5` (mgmt, attack, targets, corp), with the two flat switches fanning out the segments that
need more than one host. That design has no VLANs and no fragile switch — worth doing deliberately if
the SG108E wedges even once on a clean configuration.

## 7. Bringing the switch back with segmentation — the conditions

The flat build is what is cabled today and it works. This section does not remove it; it defines what
must be true before the SG108E returns to the path as the segment fan-out, because that box has wedged
twice and a third time is not acceptable.

### First: what actually went wrong

Four suspects, in the order of how much of the evidence they explain:

1. **A second path from the operator box.** The operator machine had a bridge (`lab-br-dmz`) and a
   VLAN sub-interface (`enp8s0.10`) live on the same NIC that was cabled into the switch. A bridge or
   a duplicate path is how a cheap switch gets a broadcast storm — and a storm presents exactly as
   "management CPU stalled, HTTP dead, ARP still answered". Both interfaces are down now and must stay
   down: **one profile per segment, never a bridge on the lab NIC.**
2. **Management riding a path it must not.** On this firmware class the switch's own management frames
   are always untagged on VLAN 1. Put management on a trunk that excludes VLAN 1, or change a serving
   port's PVID, and management stops answering — which looks identical to a wedge.
3. **Writes to flash.** Every VLAN change writes flash and stalls that CPU, and a script that retries
   after a failed write hammers exactly that path. Configure once, verify by reading the switch's own
   tables, and stop.
4. **Power.** The router beside it rebooted repeatedly in the same session. A marginal supply browns
   out a management CPU and produces the same signature as everything above.

Only after (1)–(4) are ruled out is "the switch is faulty" the right conclusion.

### The design, if it comes back

- **One trunk port** to the router's `lan5`, carrying VLANs 10/20/66 tagged, and **not a member of
  VLAN 1**. `lan5` is the port `hex-fresh.sh` builds the trunk on in `MODE=trunk`; `lan3`/`lan4` then
  go spare.
- **One management port on its own cable** to the router's `lan2` (the management segment), untagged
  VLAN 1, with a **lab** address on 10.10.0.0/24. Never `192.168.0.1` — that is the house modem and it
  has already caused one false outage.
- **Access ports**: p2 = VLAN 66 (attack), p3 = VLAN 10 (targets), p4 = VLAN 20 (corp), p5–p7 spare
  access ports whose VLAN you change when a host needs to move segment.
- **The hEX stays the only boundary.** The switch enforces nothing that anything depends on; if it
  dies, the lab loses ports, not policy.
- **A smart plug on the switch.** A wedge becomes a 30-second remote power-cycle rather than an
  evening. This is the single highest-value addition, because it removes the "no remote recovery"
  property that makes a wedge expensive.
- **The flat build stays the documented rollback** (`hex-fresh.sh` with `MODE=flat`, re-verified).

### The test that decides whether it is allowed back

1. **Factory reset, then run it dumb first.** Uplink into `lan4`, two hosts on two ports, iperf for
   30 minutes. If it wedges dumb, the box is faulty and gets replaced — no configuration work will fix
   it.
2. **Configure the design above in one scripted pass.** Verify from the switch's own tables
   (`qvlanSet.cgi` → `qvlan_ds`, `vlanPvidSet.cgi` → `pvid_ds`), not from the UI's word.
3. **Run the same 30-minute load through the trunk**, with the operator box clean and management on
   its own port. Both halves must hold: traffic keeps flowing *and* management stays reachable.
4. **Only then** make it the fan-out, with the flat build recorded as the rollback.

### If it fails again

The SG108E is a "smart" switch with a web UI bolted onto a microcontroller — no CLI, no loop
protection worth trusting, no remote recovery. A used managed switch with a real CLI (an old ProCurve,
a Cisco 2960, a Brocade ICX) costs about the same second-hand and does not have this failure mode. If
the box fails step 1 above, that is the money to spend rather than another evening on this one.
