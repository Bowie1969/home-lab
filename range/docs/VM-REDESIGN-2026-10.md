# Keystone VM Redesign — 2026-10-15

Replaces the current podman+LXC mix with real VMs, repositions hEX+switch as
the only path EvilKit must cross, and moves the Asus to the lab-router role.
No change to the module-level scoring model or the manifest schema.

## Topology

```
         Internet
            |
          [WAN]
            |
         +-----+
         |Asus |  <-- LAB ROUTER
         +-----+       - WAN NAT
         |     |       - DHCP for the attacker VLAN
         |     |       - no reach into dmz/corp/data (sealed by hEX)
         |     |
   attacker    uplink to hEX WAN
   VLAN 66           |
   10.10.66/24    +------+
       |          | hEX  |  <-- THE WALL
   +---+---+      +------+       - sole L3 path between attacker and the lab
   |       |          |          - zone firewall (keystone_hex nft, directed-allow)
Parrot  attacker      |          - no bypass: switch has no uplink to Asus/attacker
       VMs (op/C2)    |
                    trunk (802.1Q: dmz, corp, data, mgmt)
                      |
                   +--------+
                   | SWITCH |  <-- managed VLAN switch (L2 only)
                   +--------+       - 802.1Q, port-based VLANs
                     | | | |        - no routing, no inter-VLAN leak
            +--------+ | | +---------- mac-debian13 (CORP VLAN, access port)
            |          | |
         trunk       trunk access
         to brain    (CORP VLAN, drop01 Pi)
            |
       +---------+
       |  BRAIN  |  <-- Proxmox host
       +---------+       - vmbr<zone> L2-only bridges, one per VLAN
                         - VMs attach by zone; no VM holds a VLAN tag
```

Key properties:

- **The hEX is the only route across.** Attacker (Parrot + attack VMs on
  Asus-side) and defender (brain-hosted VMs behind the switch) share no L2
  and no L3 path except through the hEX.
- **The switch does segmentation, not routing.** Zones are separate L2
  broadcast domains at the switch; L3 reachability is decided entirely at
  the hEX by the `keystone_hex` nft ruleset.
- **Asus is upstream of the hEX**, not peer to it. Today's split-island
  10.10.66.0/24 (Asus-side vs hEX-side) collapses: only Asus serves that
  subnet. hEX uplinks to Asus via its WAN port and gets a static address.

## Zones and VLANs

| zone     | VLAN | CIDR            | lives on          | notes |
|----------|------|-----------------|-------------------|-------|
| attacker | 66   | 10.10.66.0/24   | Asus-side L2      | Parrot + attacker VMs; EvilKit origin |
| dmz      | 9    | 10.99.50.0/24   | switch, brain     | the 10 initial-access vectors (as service-host VMs) |
| corp     | 50   | 10.50.0.0/24    | switch, brain, Mac| AD, jump hosts, workstations |
| data     | 51*  | 10.50.1.0/24*   | switch, brain     | **NEW** — crown vault isolation at L2, not just L3 |
| mgmt     | 1    | 10.10.0.0/24    | hEX lan2 + brain mgmt NIC | out-of-band only |

`*` the data zone becomes its own VLAN. Today it shares vmbr50 with corp; this
redesign puts the vault on a separate L2 domain so a corp-side ARP/mitm cannot
observe vault traffic even hypothetically. hEX rule for `corp -> data` stays
directed-allow; everything else drops.

## VM inventory

### Brain (Proxmox) — target budget ≤ 16 GB RAM across guests

| id              | zone | VLAN | mem   | disk  | notes                                           |
|-----------------|------|------|-------|-------|-------------------------------------------------|
| dmz-web-a       | dmz  | 9    | 1 GB  | 6 GB  | hosts edge-upload, portal-sqli, render-ssti via podman |
| dmz-web-b       | dmz  | 9    | 1 GB  | 6 GB  | hosts legacy-cve, gitleak-api, meta-ssrf, token-jwt     |
| dmz-svc         | dmz  | 9    | 1 GB  | 6 GB  | hosts cache-open (Redis), ssh-weak, share-anon (SMB), cron-root |
| dmz-runner      | dmz  | 9    | 768 MB| 6 GB  | runner-escape — isolated podman-in-VM for container-escape class |
| ks-ws01         | corp | 50   | 1 GB  | 10 GB | cred-harvest workstation (ex-LXC)              |
| ks-intranet01   | corp | 50   | 1 GB  | 10 GB | ssrf-pivot intranet (ex-LXC)                    |
| ks-files01      | corp | 50   | 1 GB  | 20 GB | NFS no-root-squash share (ex-LXC)               |
| kiosk-kernel    | corp | 50   | 1 GB  | 8 GB  | pinned-kernel privesc (keep as VM)              |
| samba-45        | corp | 50   | 1 GB  | 8 GB  | CVE-2017-7494 (keep as VM)                      |
| ubuntu-dirtycow | corp | 50   | 1 GB  | 8 GB  | CVE-2016-5195 (keep as VM)                      |
| win7-eternalblue| corp | 50   | 2 GB  | 20 GB | MS17-010 (keep as VM; adjust later for Win2025) |
| dc-roast        | corp | 50   | 2 GB  | 32 GB | existing AD controller, re-NIC'd to corp VLAN   |
| vault-keystone  | data | 51   | 512 MB| 6 GB  | crown vault (ex-LXC) — own VLAN, own bridge     |

Total ≈ 14 GB RAM across 13 guests + Proxmox overhead. Thin Debian 13
cloud-init template with `qemu-guest-agent` + `cloud-initramfs-growroot`,
clone per module, cloud-init handles hostname/IP/users at first boot.

### Parrot — attacker side

| id            | zone     | mem   | notes                                   |
|---------------|----------|-------|-----------------------------------------|
| op-kali       | attacker | 2 GB  | operator box; EvilKit runs here         |
| c2-redteam    | attacker | 1 GB  | second attacker host; separate IP for noise/segmentation realism |

### Physical

- **mac-debian13** — CORP VLAN, access port on the switch, Debian 13 with the
  dedicated `/opt/keystone` sudo build exposing CVE-2025-32463.
- **drop01 (Pi)** — CORP VLAN, access port on the switch. Physical plant drop.
  (Currently offline on the tailnet; brought back as part of this wave.)

## Migration order (reversible, one wave at a time)

Each wave leaves the lab in a working state. Rollback = restore the LXC/
container from backup + revert the hEX rule set to the saved copy.

1. **Switch VLAN re-plan** — the TL-SG108E is already racked between hEX and
   brain carrying the current VLAN trunk (p1→hEX lan5, p2 attacker, p3
   targets, p4 corp, mgmt on p8). Add VLAN 51 (data), repoint p3 to dmz
   (VLAN 9), add corp access ports for Mac + Pi, keep mgmt on p8. Full
   port-by-port diff in `lab-configs/sg108e/REDESIGN-VLAN-PLAN.md`.
2. **Asus → lab router** — Asus takes WAN; hEX WAN port uplinks to Asus and
   gets a static (e.g. 10.10.0.254/24 inside a new transit VLAN). Attacker
   10.10.66/24 served by Asus only. Collapse the current split-island.
3. **Add VLAN 51 (data)** — hEX bridge, keystone_hex ruleset extended with
   DATA_CIDR 10.50.1.0/24; brain `vmbr51` L2-only; switch gets VLAN 51 in
   its 802.1Q table and a dedicated access port profile.
4. **Build the Debian 13 cloud-init template** on brain. One template, one
   build. Verifies with `qm clone`.
5. **Vault migration first** (data VLAN, smallest blast radius): LXC 950
   (vault-keystone) → VM on vmbr51, new address in 10.50.1.0/24. Confirm
   corp→data still passes, every other zone drops.
6. **Corp LXCs** → VMs (ks-ws01, ks-intranet01, ks-files01).
7. **DMZ service-host VMs** → bring up dmz-web-a/b, dmz-svc, dmz-runner;
   migrate the 10 podman modules onto them; retire the old brain-side podman.
8. **dc-roast** gets its NIC moved to the corp VLAN on the switch.
9. **Mac + drop01** cabled in on corp VLAN access ports.
10. **Windows 2025 SMB target** — build `modules/win2025-smb/`, retire
    `modules/win7-eternalblue/` to a RETIRED pointer. Resolves the task-2
    Win2025 CPU-flag/repair-loop blocker.
11. **Parrot attacker VMs** — op-kali / c2-redteam provisioned on Parrot.

## What this gets us that today does not

- **Single enforcement point.** EvilKit crosses exactly one firewall to reach
  the lab (hEX). Today the attacker-side split-island means attacker reach
  depends on which L2 you landed on. The redesign eliminates that ambiguity.
- **Real L2 isolation per zone.** The switch owns VLANs; a compromised DMZ
  host cannot ARP-spoof into corp because corp frames are not on the same
  broadcast domain. Today, intra-brain LXCs share bridges.
- **Honest per-VM attack surface.** Each VM is one MAC on one switch port, so
  the hEX's drop counters and the fleet syslog describe real network objects,
  not container-shared stacks.
- **Kernel-level realism everywhere.** The three existing kernel-privesc VMs
  no longer stand alone; corp workstations and the vault now also run their
  own kernels, so a kernel-side exploit landing in one does not pivot
  through a shared host kernel into another.
- **Clear operator model.** Asus = perimeter, hEX = wall, switch = fabric.
  Each box has one job; mental model and runbooks line up with the wiring.

## Resource / cost footprint

- Managed VLAN switch: **already racked** — existing TP-Link TL-SG108E at
  10.10.0.5/24 on the mgmt segment. No purchase; web-UI VLAN edit only.
  Switch has no SSH/CLI (RTL8370 ASIC + MCU, not Linux); its mgmt address
  stays pinned to the mgmt VLAN because of the TL-SG108E V1–V6 remote-config
  CVE class.
- Brain RAM: ≈14 GB used across 13 guests — within a 32 GB host; tune
  memory per guest if constrained.
- Parrot RAM: ≈3 GB for two attacker VMs — modest.

## Confirmed decisions (2026-10-15)

- **Switch:** existing TL-SG108E at 10.10.0.5/24. VLAN edits via web UI.
- **Asus WAN:** keeps its current internet uplink; hEX WAN uplinks to Asus.
- **Data zone:** own VLAN 51, own subnet 10.50.1.0/24.
- **Windows guest:** Server 2025 build replaces win7-eternalblue in this
  wave. Resolves the still-open task-2 Win2025 CPU-flag/repair-loop blocker.
