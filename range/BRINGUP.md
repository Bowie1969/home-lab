# Parrot live bring-up — 8 October 2026

> 14 October expansion: three additional known-exploit libvirt VMs and a
> physical Mac running Debian 13 are now represented in the generated plan.
> They are acceptance-gated and not claimed live; see
> `docs/KNOWN_EXPLOIT_EXPANSION.md`.

The partial range is running through `bin/launch.sh` and `bin/reset.sh`. Both
completed on this host. The dashboard API reports `mode: live`, `state: idle`,
five actual nodes, six harness events and no compromises or captured flags.
No dashboard source, configuration or systemd service was changed.

Current run: `runs/20261008-110148-1a2d3f/`. Its `bringup.json` records all live
checks and blockers. `containers.json`, `networks.json`, `firewall-active.nft`
and `dashboard-api-check.json` retain observed runtime evidence.

## Running inventory

All images are `localhost/keystone/<name>:latest`, built using `podman compose`
with the installed Docker Compose 2.26.1 provider and rootless Podman 5.4.2.

| Name (container names have `keystone-` prefix) | Address | Verified workload |
|---|---|---|
| attacker | 10.80.0.10 | Idle operator; Python, nc, iproute2, smbclient |
| edge-upload | 10.80.10.22:8080 | HTTP 200, real upload app |
| portal-sqli | 10.80.10.26:8081 | HTTP 200, real SQLite app |
| share-anon | 10.80.10.29:445 and :139 | SMB ports open; anonymous handover download succeeds |
| ssh-weak | 10.80.10.30:22 | DMZ SSH bastion; verified loopback local-forward into CORP |
| cron-root | 10.80.10.21 | PID 1 is cron; configured writable root task; no network port |

No service port is published on the host or Tailscale interface. No container is
privileged or has a host mount; NET_RAW is removed, and NET_ADMIN is not granted.
The operator has no project, module, build or secure directory mounted.

Four external Compose networks are created from `build/networks.json`:
`keystone-attacker` 10.80.0.0/24, `keystone-dmz` 10.80.10.0/24,
`keystone-corp` 10.80.20.0/24 and `keystone-data` 10.80.30.0/24. The latter
three are internal. CORP/DATA currently have no permanent containers; their
bridge interfaces disappear when the temporary verification listeners exit.

## Firewall and crown result

Host firewall applied: **no**. `sudo -n` reports that a password is required.
The exact owner command is:

```bash
sudo /sbin/nft -f /home/will_cyber/Projects/keystone-range/build/firewall.nft
```

Rootless firewall applied: **yes**. Launch installs the same rules inside the
network namespace that actually carries rootless container traffic:

```bash
podman unshare --rootless-netns /sbin/nft -f /home/will_cyber/Projects/keystone-range/build/firewall.nft
```

This is the effective isolation mechanism; applying only host nft would not
enforce the rootless bridge flows. See the official
[Podman namespace documentation](https://docs.podman.io/en/v5.7.1/markdown/podman-unshare.1.html).
The generated rules atomically replace only table `inet keystone`, preserving
unrelated rules. Keystone forwarding defaults to DROP, with only the intended
zone edges and replies allowed. Unrelated network forwarding is left unchanged.
Input from lab subnets to the network-namespace host is blocked. Explicit lab
routes and per-bridge forwarding permit the positive paths through this policy.

All 17 live checks include listener controls, HTTP responses, SMB, cron and an SSH
local-forward probe. The probe installs an ephemeral test key, reaches the CORP
listener through `ssh-weak`, and removes its key, authorization and control
socket. It does not provide the operator with a tunnel helper. The exercise
requires the operator to author an executable tunnel script; its evidence contract
is in `modules/ssh-weak/TUNNEL_EXERCISE.md`.

The live dashboard retains this verification as two solid used lines:
`attacker → ssh-weak → CORP tunnel probe (verified, closed)`. The CORP probe is
labelled as transient and is removed from the network after the check, so the
graph does not imply that it is an available challenge host or that a tunnel is
still running.

All 17 live checks passed. Network results:

| Path | Result |
|---|---|
| attacker → DMZ HTTP/SMB | PASS: connected |
| DMZ → CORP | PASS: connected to controlled listener 10.80.20.250:8200 |
| CORP → DATA | PASS: connected to controlled listener 10.80.30.250:8200 |
| attacker → DATA | PASS: blocked against that healthy DATA listener |
| DMZ → DATA | PASS: blocked against that healthy DATA listener |
| attacker → CORP | PASS: blocked |

The temporary CORP/DATA listeners are explicitly infrastructure probes, not
vulnerability modules. They were removed and excluded from the live graph.
The zone-level crown-isolation invariant passed. The actual vault is absent, so
end-to-end crown isolation/acquisition with the real vault and VMs is **not yet
validated**. No attack or exploitation run has been claimed.

## Private material and operation

`KEYSTONE_SECURE_DIR` defaults to `/home/will_cyber/.local/share/keystone-secure`.
The directory is 0700 and ground-truth/scoring-key files are 0600. Per-run private
archives are stored there, outside the project and run evidence trees. The four
running module flags were checked against the private rotated values without
printing them. No scoring key is copied into a live run.

Use the existing entry points:

```bash
cd /home/will_cyber/Projects/keystone-range
./bin/launch.sh
./bin/reset.sh
podman exec -it keystone-attacker bash
```

Reset recreates the implemented containers and rotates their flags, then checks
and publishes a fresh idle run. There are no provisioned VMs to reset yet.
Re-run launch after reboot; automatic range boot and persistent host nft
configuration were not installed. This initial operator container intentionally
has no evidence-directory mount; mount only its assigned run directory when
wiring an attacking harness, never the repository or secure directory.

The core remains stdlib. `./bin/selftest.sh` passes **57 tests** (the original 50
plus seven bring-up regressions). Shell syntax and `git diff --check` pass.

## Ordered work for the full range

1. Implement and health-check the missing vulnerability surfaces below. Add a
   reviewed `runtime.json` with `ready: true` only after the actual module works;
   extend live checks for new services. Current stubs are explicitly skipped and
   have no images built by this bring-up.
2. Resolve VM ↔ rootless CORP networking before defining either VM. The supplied
   XML references a host bridge named `keystone-corp`; no such host bridge
   exists. Rootless Podman's bridge is `ks-corp` in a different namespace, so
   simply changing the XML bridge name does not work. Implement a controlled
   system-VM to rootless-CORP link, or an isolated VM backend within that namespace,
   with the same zone policy. Re-run the positive and negative live checks across
   the actual VM connection. Do not attach these guests to the home LAN.
3. Supply and provision the two OS disks as detailed below; validate clean
   snapshots and guest-agent flag stamping before enabling VM launch/reset.
4. Wire the intended cross-module credential and escalation paths, then validate
   real CORP → vault access and attacker/DMZ → vault denial. Replace temporary
   probe evidence with checks against the real crown service as well.
5. Attach the attacking operator only to its run evidence directory; add capture
   and evidence collection and execute the first actual attack/scoring run.

| Skipped module — all “needs vuln app wired” | Missing work |
|---|---|
| vault-keystone | Real authenticated secrets app; current generic static HTTP server is a placeholder |
| ssh-weak | Seed the intended usable weak credential and verify login; current account has no usable password |

### DMZ container tier — wired 2026-10-13

All 12 DMZ container modules now build, run and verify (see
`build/live-state.json`: 13 selected incl. attacker, none skipped):

| Module | Implementation / exploit path |
|---|---|
| cache-open | stdlib RESP KV server, no auth; unauthenticated `GET flag.txt` reads /data/flag.txt |
| gitleak-api | real git history in the web root commits then “removes” config.py with a live API key; key authorises /api/internal which returns the flag |
| legacy-cve | Pillow pinned at 8.3.2 (CVE-2022-22817: ImageMath.eval builtins escape); `/eval?expr=__import__("os").popen("cat /opt/app/flag.txt").read()` returns the flag |
| meta-ssrf | /fetch?url= with a localhost/127. token blocklist only; metadata on loopback :80 — `url=http://0.0.0.0/latest/user-data` exfiltrates the flag |
| render-ssti | user input concatenated into a Jinja2 template; `{{ cycler.__init__.__globals__.os.popen('cat /app/flag.txt').read() }}` executes |
| runner-escape | root job-runner executes *.job files dropped in /jobs; planted host fs at /hostfs models the over-mount — a job reading /hostfs/root/flag.txt is the breakout |
| token-jwt | verifier trusts the JWT header alg and uses a weak HS256 secret; a forged `{"role":"admin"}` alg=none token unlocks /admin which returns the flag |

Note: runner-escape's /hostfs is an in-image simulated host filesystem; per the
original gap note, the owner's real `/` is never mounted.

### dc-roast prerequisites and provisioning

Missing disk: `/var/lib/libvirt/images/keystone/dc-roast.qcow2`.
The XML exists (4 GiB, 2 vCPUs, VirtIO disk/NIC, QEMU guest-agent channel).
Neither session nor system libvirt has a Keystone VM defined; no clean snapshot
exists. No Windows image was downloaded.

Owner must supply an appropriately licensed/evaluation Windows Server installer
and VirtIO drivers, or an already installed authorized qcow2 disk. The referenced
`provision/autounattend.xml` is absent: implement the unattended installation and
driver/guest-agent setup before unattended build can work. Set 10.80.20.20/24,
CORP gateway 10.80.20.1, and the AD DNS configuration.

Split `modules/dc-roast/provision/setup-dc.ps1` into promotion and post-reboot
stages. Its comment mentions a second pass, but the script itself does not
implement reboot/resume. After promotion to `keystone.local`, create/verify the
SPN and AS-REP accounts, the backup account, and the portal-reuse account (the
latter is currently absent). Explicitly configure the intended AD privileges:
the script grants Backup Operators membership but contains no replication ACL
provisioning; validate the documented DCSync path. Verify AD services and
guest-agent flag writing, then shut down and create
the clean baseline. Keep account secrets in provisioning/secure storage.

### kiosk-kernel prerequisites and provisioning

Missing disk: `/var/lib/libvirt/images/keystone/kiosk-kernel.qcow2`.
The XML exists (2 GiB, 2 vCPUs), but there is no installer automation, pinned
vulnerable kernel/CVE, provision hook, QEMU guest-agent channel or clean snapshot.
`~/Downloads/debian-11.2.0-amd64-netinst.iso` exists; its presence alone does not
make an unattended, correctly vulnerable VM ready.

Owner must select the intended kernel/CVE and provide/approve its OS media or
prepared disk. Build the pinned guest without silently upgrading away the target
kernel. Configure 10.80.20.21/24 and gateway 10.80.20.1, SSH, the intended
low-privilege account, and qemu-guest-agent plus its XML channel. Validate the
kernel version, service access, intended escalation and private flag stamping;
then shut down and snapshot clean.

### Known-exploit depth-pack prerequisites

The additional CORP targets are `win7-eternalblue` (MS17-010), `samba-45`
(CVE-2017-7494), `ubuntu-dirtycow` (CVE-2016-5195), and `mac-debian13`
(CVE-2025-32463). Their manifests, domain XML, guarded provisioners, CVE source
metadata, runtime gates, and tests are present. Their OS disks/vulnerable source
inputs are deliberately absent, all readiness markers are false, and the live
harness fails closed instead of defining or starting them.

The Mac target is physical Apple hardware running Debian 13. It is not a macOS
VM. Debian's packaged sudo must remain patched; only an isolated owner-built
sudo 1.9.16p2 under `/opt/keystone/vuln-sudo` is intentionally vulnerable.
Detailed build, isolation, reset, and acceptance gates are in
`docs/KNOWN_EXPLOIT_EXPANSION.md`.

After disks are installed and VM networking/provisioning is implemented and
verified, these are the final system-libvirt definition/baseline commands (not
prerequisites that can be safely run against today's missing disks):

```bash
sudo install -d -m 0755 /var/lib/libvirt/images/keystone
sudo virsh -c qemu:///system define /home/will_cyber/Projects/keystone-range/modules/dc-roast/domain.xml
sudo virsh -c qemu:///system define /home/will_cyber/Projects/keystone-range/modules/kiosk-kernel/domain.xml
sudo virsh -c qemu:///system define /home/will_cyber/Projects/keystone-range/modules/win7-eternalblue/domain.xml
sudo virsh -c qemu:///system define /home/will_cyber/Projects/keystone-range/modules/samba-45/domain.xml
sudo virsh -c qemu:///system define /home/will_cyber/Projects/keystone-range/modules/ubuntu-dirtycow/domain.xml
# With provisioning verified and each guest shut off:
sudo virsh -c qemu:///system snapshot-create-as dc-roast clean --description 'Provisioned clean Keystone baseline' --atomic
sudo virsh -c qemu:///system snapshot-create-as kiosk-kernel clean --description 'Provisioned clean Keystone baseline' --atomic
sudo virsh -c qemu:///system snapshot-create-as win7-finance clean --description 'Provisioned clean Keystone baseline' --atomic
sudo virsh -c qemu:///system snapshot-create-as files-legacy clean --description 'Provisioned clean Keystone baseline' --atomic
sudo virsh -c qemu:///system snapshot-create-as ubuntu-ops clean --description 'Provisioned clean Keystone baseline' --atomic
```

The launcher currently reports VM blockers instead of attempting arbitrary image
installation. Add the validated define/start, clean-snapshot revert and guest
flag-stamping hooks when the prerequisites exist; until then the VM tier stays
stopped. No additional sudo step is needed for the currently running partial
container range.

---

# CORP + DATA LXC tier (brain) — provisioning and verification

Added with the `dmz-wiring-20261013` follow-up. The CORP and DATA tiers do **not**
run on Parrot. They are dedicated Keystone LXCs on the **brain** (willshomelab,
Proxmox, 192.168.0.240), on the isolated, uplink-less bridge **`vmbr50`**
(`10.50.0.0/24`). This is the physical counterpart of the podman zone model: the
crown is on a different host, on a bridge with no route to the house LAN, to
Parrot, or to the Pi dropbox.

> **This was authored, not run.** The cloud build host has no podman/LXC/libvirt,
> so nothing below has been executed and nothing is claimed to "work". Everything
> that does not require a Proxmox host is validated by the test suite
> (`python3 -m unittest discover -s tests`, `./bin/selftest.sh`); the live
> `pct`/`nft` steps are validated **on the brain** by `keystone.live lxc-verify`.

## The four LXC guests (match each manifest exactly)

| module | VMID | vmbr50 IP | zone | port | technique | flag template |
|---|---|---|---|---|---|---|
| ks-ws01 | 950 | 10.50.0.11 | corp | 8090 | cred-harvest | `KEYSTONE{ws01-cached-cred-<rot>}` |
| ks-files01 | 951 | 10.50.0.12 | corp | 8091 | nfs-nosquash | `KEYSTONE{files01-handover-<rot>}` |
| ks-intranet01 | 952 | 10.50.0.13 | corp | 8092 | ssrf-pivot | `KEYSTONE{intranet01-admin-<rot>}` |
| vault-keystone | 953 | 10.50.0.14 | **data** | 8200 | crown-store | `KEYSTONE{CROWN-master-signing-key-<rot>}` |

Each module folder carries its guest definition: `lxc.conf` (canonical
`/etc/pve/lxc/<vmid>.conf`), `app/server.py` (stdlib-only service — the brain has
no apt/pip egress), `provision.sh` (in-guest service user + flag dir + systemd
unit) and `runtime.json` (the `ready` gate). The intended credential chain:
`ks-ws01` leaks `KEYSTONE\svc_desk` (reused onto files01/intranet01) →
`ks-files01` handover leaks `KEYSTONE\svc_backup` (toward dc-roast/DCSync) →
`ks-intranet01` admin panel leaks the vault service token → the vault returns the
master key only to a caller presenting that token.

## Generated artifacts (pure; emitted on any host)

`python3 -m keystone.generator` now also writes:

- `build/lxc.json` — the provisioning plan (the LXC analogue of `compose.yaml`):
  per guest its VMID, `vmbr50` address, ports, flag template and the exact `pct`
  bring-up sequence.
- `build/brain-firewall.nft` — the `vmbr50` segmentation (the analogue of
  `firewall.nft`): an nftables **bridge** table, default DROP, scoped to `vmbr50`
  only, that reproduces `keystone.zones.ZONE_POLICY` on the real addresses —
  **CORP reachable only from DMZ** (+ intra-CORP), **DATA (the vault) reachable
  only from a CORP host**. `summary.json.brain_crown_sources` lists every source
  the firewall lets reach DATA; it must be CORP addresses only.

## Exact local steps

On Parrot (operator host), with the brain reachable over SSH:

```bash
cd /home/will_cyber/Projects/keystone-range
export KEYSTONE_BRAIN_SSH=root@192.168.0.240   # the Proxmox brain

# 1) regenerate the plan (writes build/lxc.json + build/brain-firewall.nft)
python3 -m keystone.generator

# 2) full range reset: container tier, then (because KEYSTONE_BRAIN_SSH is set)
#    the brain CORP/DATA tier, then verify + publish
./bin/reset.sh
```

`reset.sh` runs the brain tier only when `KEYSTONE_BRAIN_SSH` is set; on a plain
Parrot host it brings up the container tier alone and prints a skip line. The
brain steps it runs (also runnable individually) are:

```bash
python3 -m keystone.live lxc-recreate   # pct create/start each ready guest on vmbr50 (idempotent; scope = its own VMID)
python3 -m keystone.live lxc-firewall   # apply build/brain-firewall.nft (atomically replaces only table bridge keystone_brain)
python3 -m keystone.live lxc-stamp      # stamp rotated flags into the guests (flag over stdin; chowned to the service user)
python3 -m keystone.live lxc-verify     # live segmentation + crown-gate checks (below)
```

`rotate` (run earlier by `reset.sh`) writes the shared ground truth that both
`stamp` (containers) and `lxc-stamp` (brain) consume, so the brain tier must run
after it — the ordering in `reset.sh`/`launch.sh` already reflects this.

## What `lxc-verify` proves on the brain

It is the brain analogue of `keystone.live verify`, and it finally tests what the
Parrot side could not (the real vault was absent there — `crown_service_tested:
false`):

- **CORP → DATA reachable** — a CORP guest connects to the vault `:8200`.
- **crown app sealed** — the vault returns **401** to an anonymous request and
  the rotated crown **only** with the recovered `X-Vault-Token` (the key value is
  shape-checked, never printed). A CORP foothold alone is therefore insufficient.
- **non-CORP → DATA blocked** — a transient probe CT at an unlisted `vmbr50`
  address (VMID 969, `10.50.0.200`) is DROPPED to the vault, proving "DATA only
  from CORP" at the real layer. The probe is destroyed afterwards.

The attacker/DMZ → DATA denial is additionally covered by the firewall's explicit
belt-and-suspenders drop; it becomes *live*-testable only once the DMZ→CORP trunk
below exists. The crown is never exposed or weakened to make any check pass.

## Still needs host-side artifacts (cannot be done from code)

1. **A Proxmox brain reachable over SSH.** Set `KEYSTONE_BRAIN_SSH`. The account
   must be able to run `pct` and `nft -f`.
2. **An ostemplate with `python3` + `systemd` baked in.** The brain has no
   internet egress, so the guests cannot `apt install` anything; `provision.sh`
   aborts loudly if `python3` is absent. Pre-bake a Debian 13 standard template
   accordingly, or adjust `lxc.DEFAULT_OSTEMPLATE`.
3. **Real storage volume names** in each `modules/<id>/lxc.conf` `rootfs:` line to
   match the brain's storage (`local-lvm` placeholders here).
4. **The DMZ → CORP L2 path.** `vmbr50` is currently isolated with no uplink, and
   the brain has no spare NIC/VLAN trunk to expose it to Parrot's DMZ segment (see
   `modules/drop01` and `modules/dc-roast` notes). Until a second NIC / VLAN trunk
   is wired, intra-brain CORP↔DATA is live and verifiable, but the cross-host
   `dmz→corp` pivot edge is inert (the `dmz→corp` accept in `brain-firewall.nft`
   simply never matches). This is modeled honestly, not faked.
5. **dc01's `vmbr50` guest IP.** `dc-roast` (reused VM, VMID 930) gains a `vmbr50`
   NIC but its guest-OS address on that NIC is unverified. Add it to
   `lxc.CORP_EXTRA_HOSTS` (and regenerate) so the firewall grants it the CORP→DATA
   edge; default-deny keeps it off the vault until then.

## Out of scope here (requirements only — unchanged)

- **dc-roast** (`remote-vm`, the reused dc01): see "dc-roast prerequisites and
  provisioning" above. AD domain state is unverified; this change does not touch
  it.
- **kiosk-kernel** (`vm`, missing qcow2): see "kiosk-kernel prerequisites" above.
- **drop01** (`physical`): single-homed today; the CORP-side NIC is the design
  intent, not a live path (see its manifest note).
