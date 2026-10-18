# Keystone — Full-Gear Redesign (every box earns a job)

> Implementation plan, 2026-10-17. The physical VLAN foundation (phases 1–2) is
> now live and verified; later phases remain the roadmap. Companion visual:
> `docs/topology-full-gear.md`.

## 1. Why redesign

Keystone works, but it only exercises a slice of the lab, and it carries one
architectural smell:

- **Targets run on the attacker box.** The 12 canonical DMZ vectors are rootless
  **podman containers on the Parrot desktop** (10.80.10.x), the same host the
  operator/agent runs from. `docs/` already flags the isolation risk; the live
  LXC tier on the brain is the honest version, but the podman tier is still the
  default "range." Full-gear use means **the target surface leaves the operator
  entirely** and lives on the brain / will-laptop / Mac / (E7470), reachable only
  through the hEX.
- **Idle horsepower.** The **Arc B580 GPU** does nothing for the range. The
  **arm64 Windows attacker laptop** is documented (`docs/ATTACKER_PLATFORM.md`)
  but not wired in as the second operator now that `tafe-laptop` is dead. The
  **Mac now runs Debian 13** (live, not parked) — it's a real CVE target today.
- **DATA needed physical segmentation.** This redesign moved the crown from
  `10.50.0.14` on CORP to **VLAN 51 / `10.50.1.14`**, with the hEX enforcing
  CORP→DATA only on port 8200 and DATA unable to initiate outbound.
- **Telemetry isn't scored.** Every network device already emits (hEX nft logs +
  conntrack, Asus syslog push, brain pve/guest events, Parrot collector) and
  `keystone/blue/` + `bluetelemetry.py` exist, but blue detection isn't a
  first-class scored dimension of a run.

## 2. Design principles

1. **Operator ≠ target.** Parrot and the arm64 laptop are *attacker* plane only.
   No scored target runs on them. This also fixes the answer-key-leak class for
   good: ground truth lives on the brain/scoring host, never where the agent runs.
2. **Physical segmentation is the firewall.** Zones are real VLANs on real
   copper through the SG108E and enforced by the hEX — not software bridges on one
   host. A merged zone is a broken benchmark, so isolation is proven at bring-up.
3. **Every box has one clear job**, sized to its RAM/arch. The 13 GB brain is the
   binding constraint, so heavy/Windows/VM workloads distribute off it.
4. **Path-agnostic scoring is preserved.** More gear = more realistic paths to the
   same crown, never a required order. The scorer stays a pure function of the
   evidence set.
5. **Blocks are named, not hidden.** Aspirational gear gets a role *and* the exact
   cheap unblock.
6. **One control plane, never two keyboards.** The operator (you + the agent) drives
   a single EvilKit **mesh hub** on Parrot. Every other attacker box is a *worker
   node* the hub tasks — it is never a second machine you hand-operate in parallel.
   See §5.

## 3. The gear — inventory and assigned role

| # | Box | Specs / OS | Status | Today | **Full-gear role** |
|---|-----|-----------|--------|-------|--------------------|
| 1 | **Parrot desktop** | Intel **Arc B580** dGPU, Parrot | live, daily driver | operator + podman target tier + dashboard | **Operator control plane + EvilKit mesh hub** (`evilkit mesh lead`, tailnet :8765). Primary agent host, GPU **hashcat cracking** as a real scored step, run dashboard + scoring, lab admin. Targets removed. |
| 2 | **brain** (`willshomelab`) | Lenovo IdeaCentre 3, Ryzen 3 3250U (4C), **13 GB usable**, Proxmox 9.2.2 | live | DMZ estate CTs (vmbr9) + corp/crown CTs (vmbr50) + dc01 | **Linux target core.** All lightweight CT targets (DMZ 10.99.50/24 + corp 10.50.0/24) + crown on new DATA VLAN. Holds dc01 only when RAM frees up (see §7). |
| 3 | **will-laptop** | Snapdragon X Elite **arm64**, Win 11 Pro, Hyper-V + WSL2 | live | documented attacker, not wired | **Mobile swap-in operator *or* arm64 mesh worker — not a second keyboard.** Either run the EvilKit hub *here* when away from the desk (Parrot is off), or join its Kali arm64 VM to the Parrot hub as an `evilkit mesh work` node. Adds the arm64-diversity angle. |
| 4 | **Mac** | Apple hw, now **Debian 13** | **live (newly)** | `mac-debian13` target (authored) | **`mac-debian13` CVE-2025-32463 sudo-privesc target**, physically separate, wired to corp VLAN 50. No longer aspirational. Needs: a lab-side NIC path through the p3 CORP fan-out. |
| 5 | **E7470 Latitude** | DDR4-stripped (donated to brain) | **blocked** | — | **Second Proxmox node** for the heavy/Windows VM tier (win7-eternalblue, samba-45, ubuntu-dirtycow, kiosk-kernel, AD members) — offloads the brain. **Unblock: one DDR4 SODIMM (~$20–40).** |
| 6 | **E7440 / tafe-laptop** | Latitude, DDR3 8 GB | **dead** | portable attacker | Retired. Role absorbed by will-laptop. Salvage RAM/parts only. |
| 7 | **drop01 Pi** | Raspberry Pi, **EvilKit OS** (Kali-based) | live | physical-plant vector + Kimi API + mesh worker | **The EvilKit OS appliance** — a bootable red-operator delivered onto the range. Its physical `eth0` is now the planted CORP foothold at **`10.50.0.220` on SG108E p3**. It can reach the three CORP services but is deliberately omitted from the crown allow-list, forcing lateral compromise before DATA. |
| 8 | **dc01** | Win Server VM (VMID 930) | live but flaky | AD DC for dc-roast | **Real AD DC** (Kerberos/LDAP/SMB/DCSync). Reliability fix required — unactivated-Windows 60-min self-shutdown, watchdog is a band-aid (see §7). |
| 9 | **hEX** (`labrouter`) | MikroTik RB750Gr3, OpenWrt 23.05-rc3 | live | **range router/firewall** | **The enforcement point.** Keeps `keystone_hex` zone policy + crown seal; gains the DATA VLAN 51 gateway; its nft logs + conntrack become a **scored blue sensor**. |
| 10 | **SG108E** | TP-Link TL-SG108E (no shell) | live | VLAN backbone | **The L2 fabric that makes zones physical.** Commit the clean `1/9/50/51/66` port profile incl. **p7 = DATA (VLAN 51)**. Mgmt pinned to VLAN 1 (remote-config CVE class). |
| 11 | **Asus RT-AX1800S** | OpenWrt 25.12.5 (V2) | live | lab edge + lab Wi-Fi + Tailscale subnet router | **Egress/C2 control + edge sensor.** Gates uplink (withhold = air-gapped eval). Syslog push to the collector feeds blue scoring. Lab Wi-Fi stays VLAN 66. **Not a target** (it's in the stable half). |
| 12 | **Netgear RAX9 "Blackhawk"** | AX1800, not cleanly flashable | spare | parked | **Optional SOHO-router target** on the DMZ — a genuine network-device exploitation vector (default/weak creds, dated firmware) that no container can fake. Throwaway, so safe to pwn. |
| 13 | **desktop-1mss99t** | Windows, VMware + WSL | uncertain | — | **Optional x86 Windows target host** (VMware) if RAM on the E7470 node is tight — e.g. the Windows member server / workstation that must be x86. Confirm it still exists/available. |

## 4. Zone model, physically realized

Five planes. Four are the scored zones; `mgmt` is out-of-band and never a path to
the crown.

| VLAN | zone | subnet | gateway (hEX) | SG108E port | lives on |
|------|------|--------|---------------|-------------|----------|
| 1 | **mgmt** | 10.10.0.0/24 | 10.10.0.1 | p5 (admin), p8 (hEX lan3) | switch, hEX dedicated `/32` link |
| 66 | **attacker** | 10.10.66.0/24 | 10.10.66.1 | p2 (Parrot attack), p6 (Asus Wi-Fi) | Parrot, will-laptop/Kali (Tailscale), drop01 jump |
| 9 | **dmz** | 10.99.50.0/24 | 10.99.50.1 | p4 | brain vmbr9 CTs; RAX9 target |
| 50 | **corp** | 10.50.0.0/24 | 10.50.0.1 | p3 | EvilKit OS Pi, brain vmbr50 CTs, dc01, Mac, E7470 VMs |
| 51 | **data** | **10.50.1.0/24** | **10.50.1.1 (NEW)** | **p7 (NEW)** | `vault-keystone` only |

**Directed allow (everything else DROP), enforced in `keystone_hex` on the hEX:**

```
attacker(66) -> dmz(9)          # and attacker -> corp is DROP (logged)
dmz(9)       -> corp(50)        # only to the published corp hosts
corp(50)     -> data(51):8200   # crown reachable ONLY from corp, only on 8200
data(51)     -> *               # DROP (crown cannot initiate out)
```

This policy is now live. DATA moved from an in-subnet nft seal on `10.50.0.14`
to its own VLAN 51 / `10.50.1.0/24` L2 segment. The SG108E carries
`9/50/51/66` on p1, and the hEX bridges each physical VLAN to the matching
brain-side trunk while remaining the only inter-zone router.

## 5. The attacker plane — one control plane, many workers (EvilKit OS)

**You do not operate two attacker PCs at once.** The red operator is **EvilKit**,
and EvilKit is a *mesh*: one **hub** leads, and any number of **worker nodes**
register to it, take tasks, and beacon results back. The hub is the single pane of
glass — when a worker joins, the hub **auto-pops a terminal window** streaming that
worker (`evilkit mesh watch --worker <name>`), so more attacker boxes means more
windows on *one* screen, not more keyboards.

- **Hub = Parrot** (`evilkit mesh lead` / `start`, tailnet `:8765`). This is where
  you and the agent sit. The Arc B580, the dashboard, scoring, and lab admin all
  live here. It is the only box you "drive."
- **EvilKit OS = the worker appliance.** A bootable **Kali-based Raspberry Pi**
  image (`~/Projects/evilkit-os`, `evilkit appliance build`) — the red operator
  shipped as hardware rather than a CLI run from the desk. The `drop01` Pi runs it
  as `evilkit-pi-01`; it registers to the hub (shared token at
  `/etc/evilk-mesh/token`) via `evilk-mesh-worker-pi.service` and forwards its run
  evidence to the Parrot run dir over SSH. This *is* the physical-plant vector —
  a planted Pi that is also a live operator node.
- **will-laptop is not a co-equal second attacker.** Pick one role (see §10): a
  **mobile swap-in** (run the hub there when Parrot is off — you still drive one
  box), or an **arm64 mesh worker** (`evilkit mesh work`) that the Parrot hub tasks
  like the Pi. Either way there is exactly one hub at a time.

So "all my attacking gear" scales by **adding workers to the mesh**, each a tile on
the hub — the Pi appliance today, will-laptop and future EvilKit OS boxes next —
never by splitting your attention across machines.

> Resolved: the appliance is on **SG108E p3 / CORP VLAN 50** with a reserved
> address of `10.50.0.220`. The stale `10.99.50.120` collision is gone; p7 is
> dedicated to DATA.

## 6. New capabilities this unlocks

- **Real credential cracking (Arc B580).** `ntlm-relay-corp` and `kerberoast`
  already produce NetNTLMv2 / Kerberos hashes. Today cracking is seeded. With the
  GPU, "recover the password" becomes a genuine hashcat step on the operator box —
  the **Credential Access** category scores real work, not a lookup.
- **Architecture-diversity benchmark (arm64 attacker).** Running from Kali arm64
  exposes x86-only tooling gaps (Impacket consumers, msfvenom encoders) — a real
  field-operator setup no other public pentest-agent benchmark has. The
  redteamscripting MCP already has `arch=aarch64` paths.
- **Authentic AD depth (dc01 + members).** A real Windows DC + member servers
  (on the E7470 node) make Kerberos/DCSync/BloodHound real rather than simulated —
  the biggest job-readiness lever noted across the lab memory.
- **A true data diode (VLAN 51).** The crown on its own segment means "exfil the
  key" crosses a real L2/L3 boundary that is default-deny and logged — the
  highest-weighted scoring category becomes physically honest.
- **Red + Blue in one run.** hEX nft drops/conntrack, Asus syslog, SG108E port
  counters (ESCP), brain guest events → `keystone/blue/defense_server.py` +
  `bluetelemetry.py`. Add a **Detection** dimension: did the blue sensors catch the
  chain, and did the agent evade? (`blukit` scores "did the AI catch it"; this
  scores the attacker against live sensors.)
- **A network-device vector (RAX9).** SOHO-router exploitation — a target class
  containers cannot represent — on a throwaway box, safe to brick.
- **A hardware red operator (EvilKit OS).** The attacker is a bootable Kali Pi
  appliance that joins the mesh and *is* the physical-plant drop — the only
  benchmark where the operator itself is planted hardware, and where adding
  attacker capacity means adding mesh workers under one hub (§5), not more hands.

## 7. The binding constraint: RAM, and how gear distribution solves it

The brain has **~13 GB usable**. Today it already runs VM100 lab-services (3 GB),
~15 CTs, and the keystone tier; **dc01 is 3 GB and the swing factor** — it and any
Windows member servers do not fit alongside everything at once. The distribution:

- **brain** → all **Linux CTs** (256 MB each ≈ cheap): the DMZ estate, the corp
  trio (`ks-ws01/files01/intranet01`), and the crown. This is its sweet spot.
- **E7470 (once RAM'd)** → the **VM-weight tier**: win7-eternalblue, samba-45,
  ubuntu-dirtycow, kiosk-kernel, and the **AD member servers**. A second Proxmox
  node is the clean home for everything that needs a full kernel/Windows.
- **will-laptop (Hyper-V)** → the **arm64 attacker** + optional arm64 Linux
  targets. Keeps attacker weight off Parrot and adds arch diversity.
- **Mac/Debian13** → the sudo-CVE privesc target, standalone.
- **dc01** → brain while members live on the E7470 node; or move dc01 to the
  E7470 node too and keep the brain purely CTs.

**dc01 reliability (decide):** the 60-minute self-shutdown is unactivated Windows.
Options, in order of realism-vs-effort:
- **(a)** Activate / eval-license the guest (install the guest agent so it can be
  managed) — most realistic, keeps a true Windows DC.
- **(b)** Keep the watchdog (`keystone-dc-watchdog.timer`) as-is — works, but masks
  a guest that reboots mid-run and has no agent.
- **(c)** Add a **Samba AD DC** (Linux CT, rock-solid) as the default AD, and spin
  the Windows DC only for runs that specifically need NTDS/real-DCSync realism.
  Best reliability for routine runs; (a) or hybrid (c) recommended.

## 8. Migration — phases (nothing destructive without approval)

0. **Approve this doc**; fold §3–§4 into `LAB_DESIGN.md`.
1. **DONE — Cut DATA to VLAN 51.** SG108E p7 + hEX `10.50.1.1` gateway + move
   `vault-keystone` (953) to `10.50.1.14`; rewrite the crown-seal rule as the
   corp→data(51):8200 inter-VLAN allow. Prove isolation
   (`zones.crown_is_isolated()` + live negative check) before trusting a score.
   The EvilKit appliance moved to CORP p3 at `10.50.0.220` and cannot directly
   reach the crown.
2. **DONE — Retire legacy VLAN 10/20** on the hEX `lan5`/SG108E (old targets/corp); the
   range runs entirely on `1/9/50/51/66`.
3. **Move the target surface off Parrot.** Reproduce the podman DMZ vectors as
   brain CTs on vmbr9 (most already exist as the estate). Parrot keeps only the
   offline/portable podman mirror for no-hardware dev, never as the scored range.
4. **Wire the Mac** to corp VLAN 50 and bring up `mac-debian13` for real.
5. **Stand up the mesh:** `evilkit mesh lead` hub on Parrot; the EvilKit OS Pi
   appliance (`evilkit-pi-01`) joins as a worker and streams into its own hub
   window; evidence forwards to the Parrot run dir. Add will-laptop (Kali arm64) as
   a second worker only if §10.6 chooses that role.
6. **GPU cracking** wired into the Credential Access scoring path on Parrot.
7. **Blue scoring:** promote the existing sensors to a scored Detection dimension.
8. **Blocked/optional, as parts arrive:** E7470 SODIMM → second Proxmox node →
   migrate the VM-weight tier + AD members; RAX9 SOHO-router vector; confirm/enlist
   desktop-1mss99t for x86 Windows if needed.

## 9. Costs / blocks summary

| Item | Cost | Unblocks |
|------|------|----------|
| DDR4 SODIMM for E7470 | ~$20–40 | second Proxmox node → heavy VM + AD-member tier, frees the brain |
| USB-ethernet for the Mac (if no usable built-in NIC on the lab side) | ~$15 | `mac-debian13` on corp VLAN |
| (optional) spare copper + labels for p7 DATA run | trivial | physical DATA segment |
| dc01 Windows license / eval | $0 (eval) | reliable real AD DC |

Everything else is configuration of gear already in hand.

## 10. Open decisions for you

1. **dc01:** activate the Windows DC (a), keep the watchdog (b), or add a Samba AD
   DC as the default and keep Windows for deep runs (c)?
2. **E7470:** buy the SODIMM now (unlocks the whole VM tier) or defer and keep the
   heavy VMs as authored-but-unbuilt?
3. **RAX9 as a target:** in scope as the network-device vector, or leave it as a
   spare AP?
4. **desktop-1mss99t:** still available as an x86 Windows VMware host, or drop it?
5. **Blue/Detection scoring:** add it as a scored dimension now, or keep blue as
   telemetry-only for this pass?
6. **will-laptop role:** mobile swap-in operator (run the hub there when away), an
   arm64 **mesh worker** under the Parrot hub, or leave it out of the range for now?
