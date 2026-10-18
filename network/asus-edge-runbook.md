# Asus edge runbook — house handover, flash, and the edge config

Written 2026-10-02 (night). **Nothing here has been done yet.** This is the version that survives an
internet outage: work top to bottom, and each step says how to check it before the next.

## 0. The one rule

**The rule that used to live here was based on a mistake — corrected 2026-10-03.** The box at
`192.168.0.1` is **not** the Asus: `80:82:fe:64:81:64` is an **Arcadyan** OUI (not ASUSTek), and its UI
is an Optus-branded Arcadyan router. **The RT-AX1800S is a free bench unit** (it is the disassembled
one), so there is **no house-outage gate** and §2 is **not** a prerequisite for flashing it. Keep the
spirit: never let the flash window take the house down.

## 1. Pre-flight — facts to collect before touching anything

- **Hardware rev — ✅ SETTLED 2026-10-03: this unit is a V2 (MT7981, ARM64).** So the image set is
  **`mediatek/filogic` / `asus_rt-ax57m`**, and it exists **only on the 25.12.5 branch** (24.10.x has
  no `ax57m`). For reference, the other revision is **V1 = MT7621AT** (`ramips/mt7621`, `asus_rt-ax54`,
  mipsel) — do **not** use those images here: the MT7621 image on a V2 segfaults `mtd-write` and can
  brick it (openwrt/openwrt#17198, #17119). The V1 set is quarantined in
  `~/asus-edge-flash/images/_v1-ramips-mt7621-NOT-FOR-THIS-UNIT/`. Note the trap that cost the time:
  **the `H/W Ver: A1` sticker is printed on V2 units too — it is NOT a revision indicator.**
- **The Asus's current WAN method**, from its own UI: PPPoE (with Optus credentials) or DHCP. The
  Sagemcom must be set the same way, or the house loses internet at the handover instead of after it.
- **The house SSIDs + passwords**, and the LAN subnet/DHCP scope. Recreate them on the Sagemcom so
  phones, laptops and the TV do not need touching.
- **Downloads**: the OpenWrt **initramfs-kernel** *and* **squashfs-sysupgrade** images for the rev,
  sha256-checked — the **`squashfs-factory`** image is *not* used by the documented first-flash
  routes — **plus the stock Asus image** for rollback. Keep both, not one; they are already staged in
  `~/asus-edge-flash/` (see the Verified block below).
- **No TFTP server on the desktop for the normal route.** In rescue mode the **router** is the TFTP
  server and the desktop is the client — `curl -T <initramfs-kernel.bin> tftp://192.168.1.1`. A
  desktop TFTP server is only needed for the U-Boot serial fallback (open case, solder J2).

### Verified 2026-10-03 (downloads.openwrt.org serves files directly; the wiki bot-blocks this
### machine but `r.jina.ai` renders it)

- **The two revisions are different SoCs and never share an image.** `RT-AX1800S` (V1) = MT7621AT →
  `ramips/mt7621` / `asus_rt-ax54` (profile shared with RT-AX54, RT-AX54HP, RT-AX1800HP — which is why
  grepping image names for "ax1800s" finds nothing). `RT-AX1800S V2` = MT7981 → `mediatek/filogic` /
  `asus_rt-ax57m` (titles: RT-AX57M, RT-AX54HP V2, RT-AX1800HP V2, **RT-AX1800S V2**, RT-AX3000S).
  Both revisions are on the **25.12.5** branch.
- **The kit is downloaded and sha256-verified at `~/asus-edge-flash/images/`** — V1 (25.12.5 and
  24.10.4): `initramfs-kernel.bin` + `squashfs-sysupgrade.bin` (plus a `squashfs-factory.bin` for the
  mtd-write fallback); V2 (25.12.5): `initramfs-kernel.bin`, `initramfs.trx`, `squashfs-sysupgrade.bin`.
  Rollback images: `~/asus-edge-flash/stock/`.
- **The old open question is closed**: there is **no magic recovery filename**. In the U-Boot serial
  menu the file name is typed at the prompt; in rescue-mode TFTP it is simply the file you push.
- **Architecture is the last sanity check**: `ramips/mt7621` is **mipsel**, `mediatek/filogic` is
  **aarch64**. If the file in your hand is the wrong arch, it is the wrong image.
- **Last resort for either rev — U-Boot serial**: open the case, solder a 4-pin header at **J2**
  (marked on the PCB), USB-TTL at **115200 8N1 3.3V**, interrupt the U-Boot menu → *2. Upgrade
  firmware* → TFTP (desktop `192.168.1.2`, router `192.168.1.1`, mask `255.255.255.0`).

## 2. Handover — the Sagemcom becomes the house gateway

1. Log into the Sagemcom; put it in router mode with the same WAN method as the Asus (step 1).
2. Set the house SSIDs and passwords to what the house already uses.
3. LAN `192.168.0.0/24` with DHCP on; reserve the addresses that must not move — the brain
   (`192.168.0.240`) and Parrot (`192.168.0.13`).
4. Move the wiring: the Optus feed goes to the **Sagemcom's WAN**; the Asus's WAN cable moves to a
   **Sagemcom LAN port**. The Asus is now just another client on the house LAN.
5. Verify before continuing: a phone and a laptop get internet through the Sagemcom; the brain still
   reaches the tailnet (its own path is the house cable, unaffected by this); Parrot's Wi-Fi comes
   back on the Sagemcom's SSID.
6. **The house is now independent of the Asus.** This is the point of no return for the flash.

## 3. Flash the Asus

**Revision is settled: this unit is a V2 (MT7981) — use the V2 recipe. The V1 block is kept only as
reference for other units.** Cable the desktop to the router directly (the lab NIC, never the house
one), then:

- **V2 — vendor-UI upload (this unit); no soldering, no TFTP, no case-open.**
  1. Cable the desktop to a **LAN** port and let it take a DHCP lease — the Asus's LAN will be
     `192.168.1.1` or whatever it is currently configured as; find it from the new default gateway.
  2. Log into the Asuswrt web UI, **Administration → Firmware Upgrade**, and upload
     `openwrt-25.12.5-mediatek-filogic-asus_rt-ax57m-initramfs.trx` (it is a `.trx`, *not* the
     `.bin` — the vendor UI only accepts the trx here).
  3. It reboots into OpenWrt **running in RAM** at `192.168.1.1`. Log in, then **sysupgrade** with
     `openwrt-25.12.5-mediatek-filogic-asus_rt-ax57m-squashfs-sysupgrade.bin` — that is what makes it
     persistent. Do not skip this; the RAM boot survives nothing.
  4. ⚠ **Verify the 2.5G WAN (`eth0`) actually comes up** before trusting it as the lab edge uplink —
     that port had no driver support in older builds (the wiki note singles out 25.12.4).
- **V1 (other units only) — rescue-mode TFTP, two steps, no soldering.** Cable to the router's
  **LAN1** port (exactly that one), nothing else plugged in; desktop static `192.168.1.10/24`, off
  every other network. Power off, hold RESET while powering on, keep holding until the power LED
  blinks **very slowly**. Push the kernel image:
  `curl -T openwrt-25.12.5-ramips-mt7621-asus_rt-ax54-initramfs-kernel.bin tftp://192.168.1.1`
  (Windows: the ASUS Firmware Restoration utility with the same image). It boots in RAM — browse to
  `http://192.168.1.1/cgi-bin/luci/` (root, empty password) → System → Backup/Flash firmware → flash
  the **squashfs-sysupgrade** image. Fallback: `mtd-write -i <factory.bin> -d Kernel` over SSH
  (enable SSH in the Asuswrt UI first).

Watch the LED behaviour throughout rather than trusting silence. Then on the OpenWrt side: set a root
password and add the agent's key (`/etc/dropbear/authorized_keys` on OpenWrt — not `/root/.ssh`).

## 4. Configure it — edge, room, and lab Wi-Fi

- **WAN**: DHCP (or static) off the Sagemcom's LAN. Confirm it gets an address and internet.
- **Room network**: its own LAN subnet, DHCP on, and the room SSID. This is the "range extender +
  router for the room" role.
- **Lab SSID**: bridge it to **VLAN 66**, tagged/untagged out the port that cables to **SG108E p6**
  (see `WIRING.md` §2). That bridge gets **no IP, no DHCP, and no forwarding** to the Asus's WAN or to
  the room LAN — it is a pure L2 extension, and the clients' gateway stays the hEX (`10.10.66.1`).
  If it gets an address or a route, it becomes the WAN→LAN hole the hEX exists to prevent.
- **Tailscale**: install, log in, and enable the subnet router for the lab only if you want the
  tailnet to reach lab segments — remember that reaching the lab then no longer requires being at the
  rack, and the hEX's policy is what still gates it.
- **The hEX uplink** is a separate, deliberate step: cable the Asus LAN → the hEX's **`wan`** port,
  then configure a WAN interface + a `wan` zone that **REJECTs by default**, with the gating switch
  per range. Until that is done, the uplink cable can simply be left out and the lab stays air-gapped.

## 5. Rollback

- Asus: V1 → push the stock Asus image the same way as the flash (rescue-mode TFTP, or the Firmware
  Restoration utility); V2 → install the `facinstall` package, then flash the stock Asus **trx** from
  LuCI. Then restore its saved config. ⚠ The only stock image downloaded so far is the **V2** one
  (`~/asus-edge-flash/stock/`, sha256 `01ec810463fe55eef8c9b447483425ba19af7fd1a3ff3ed5dfe7b2872b5e4054`)
  — a V1 unit's stock firmware has to come from the ASUS support page.
- House: if the Sagemcom handover goes wrong mid-way, put the Asus's WAN back where it was; that is
  the only step that restores the house.
- Lab: the edge is upstream of the hEX, so nothing here changes the hEX's config. The air-gap is
  intact whether the Asus is flashed, broken, or absent.

## 6. Notes that save an evening

- The desktop's Wi-Fi profile (`OPTUS_648160N`) will need re-pointing if the SSID changes — keep an
  iPhone hotspot available, because **the agent's own link also rides this Wi-Fi**.
- The Asus must keep its `wan` port free for the house feed and its LAN for the room + the hEX; do not
  let a lab cable land on its WAN port.
- Ownership: memory records the edge flash as a **parallel session's** job. Confirm before starting,
  so two people are not flashing one router.
