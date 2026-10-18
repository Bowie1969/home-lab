# Simple Range — Brain-side Runbook

Companion to `SIMPLE-RANGE-2026-10.md`. Run every step on the brain
(`willshomelab` / `192.168.0.240`) as root. Each step is idempotent — safe
to re-run. Rollback at the end.

```
VMIDs used
  9000   keystone-debian13   (existing template, from build-vm-template.sh)
   110   lab-edge01          (new, beachhead, Debian 13 on vmbr50)
   601   lab-jump01          (existing Windows VM, re-NIC'd to vmbr50)
   130   lab-crown01         (new, crown, Debian 13 on vmbr51)
```

## 0. Pre-flight — know what you have

```bash
# All existing VMs, see what 601 looks like, confirm template 9000 is present
qm list
qm config 9000 | head -20            # template present?
qm config 601 | head -20             # existing Windows VM for lab-jump01
```

If VMID 9000 is missing, build it first:

```bash
bash /root/home-lab/range/infra/brain/build-vm-template.sh
```

## 1. Snapshot everything you might touch (safety net)

```bash
for id in 110 130 601; do
  qm list | awk '$1=='"$id"' {print $1}' | while read -r vmid; do
    qm snapshot "$vmid" pre-simple-range --description "pre simple-range redesign $(date -Iseconds)" || true
  done
done
```

VM 110 and 130 do not exist yet; the `|| true` makes this harmless. 601
gets a real snapshot you can roll back to.

## 2. Make sure the bridges and VLANs exist

```bash
# Bridges on the brain — these should already exist from the earlier
# redesign. Create if missing.
for pair in "vmbr50 50" "vmbr51 51"; do
  set -- $pair
  br=$1; vlan=$2
  if ! ip link show "$br" >/dev/null 2>&1; then
    cat >>/etc/network/interfaces <<EOF

auto $br
iface $br inet manual
    bridge-ports none
    bridge-stp off
    bridge-fd 0
    bridge-vlan-aware yes
    # VLAN $vlan — L2-only, uplink via the trunk port
EOF
  fi
done
ifreload -a || systemctl restart networking
```

Switch side (TL-SG108E web UI, not SSH): add VLAN 51 if it is missing,
tag it on the brain trunk port and on the hEX trunk port.

## 3. Clone lab-edge01 (10.50.0.10) — Linux beachhead

```bash
qm clone 9000 110 --name lab-edge01 --full true
qm set 110 \
  --memory 1024 \
  --cores 1 \
  --net0 virtio,bridge=vmbr50,tag=50 \
  --ipconfig0 ip=10.50.0.10/24,gw=10.50.0.1 \
  --sshkey /root/.ssh/authorized_keys \
  --ciuser edge \
  --onboot 1
qm start 110

# Wait for cloud-init
until qm guest cmd 110 ping >/dev/null 2>&1; do sleep 2; done
qm guest exec 110 -- hostname
```

The vulnerable service for 8080 ships as a follow-up change under
`modules/simple-beachhead/`; placeholder for now:

```bash
qm guest exec 110 -- bash -c '
  apt-get -qq update
  apt-get -qq install -y python3
  mkdir -p /opt/edge
  echo "placeholder — the real vulnerable service lands under modules/simple-beachhead/" >/opt/edge/README
'
```

## 4. Re-point lab-jump01 (10.50.0.20) — existing Windows VM 601

```bash
# Inspect current NIC
qm config 601 | grep -E '^(net|ipconfig)'

# Swap bridge and VLAN; keep MAC so licensing/activation does not reset
MAC=$(qm config 601 | awk -F= '/^net0:/ {for(i=1;i<=NF;i++) if($i ~ /^[0-9A-Fa-f:]{17}$/) print $i}')
qm set 601 --net0 "virtio=$MAC,bridge=vmbr50,tag=50"
```

Inside the Windows guest (RDP via 10.50.0.20 once the NIC comes up, or use
`qm terminal 601`):

```powershell
New-NetIPAddress -InterfaceAlias Ethernet -IPAddress 10.50.0.20 -PrefixLength 24 -DefaultGateway 10.50.0.1
Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses 10.50.0.1

# Operator share — the cred leak that the beachhead implant will find
New-Item -Path C:\ops -ItemType Directory -Force
Set-Content -Path C:\ops\handover.txt -Value @"
Jump-host runbook, DO NOT COMMIT
Crown service lives at 10.50.1.30:9000.
Service account for crown deploy: svc-crown / <paste-secret-here>
"@
New-SmbShare -Name ops -Path C:\ops -ReadAccess "Everyone"

Enable-PSRemoting -Force
```

## 5. Clone lab-crown01 (10.50.1.30) — Linux crown

```bash
qm clone 9000 130 --name lab-crown01 --full true
qm set 130 \
  --memory 1024 \
  --cores 1 \
  --net0 virtio,bridge=vmbr51,tag=51 \
  --ipconfig0 ip=10.50.1.30/24 \
  --sshkey /root/.ssh/authorized_keys \
  --ciuser crown \
  --onboot 1
qm start 130

until qm guest cmd 130 ping >/dev/null 2>&1; do sleep 2; done

qm guest exec 130 -- bash -c '
  mkdir -p /vault
  umask 077
  printf "FLAG{simple-range-%s}\n" "$(date +%Y%m%d-%H%M%S)" > /vault/flag.txt
  chown root:root /vault/flag.txt
  chmod 400 /vault/flag.txt
'
```

Vulnerable service on 9000 ships under `modules/simple-crown/` as a
follow-up.

## 6. hEX firewall — the only ruleset the range needs

SSH into the hEX (`admin@192.168.0.1` or whatever the mgmt address is) and
replace `/etc/nftables/keystone_hex.nft` with the content below. Keep the
previous ruleset at `keystone_hex.nft.pre-simple-range` for rollback.

```nft
#!/usr/sbin/nft -f
flush ruleset

define ATTACKER = 10.10.66.0/24
define EDGE     = 10.50.0.10
define JUMP     = 10.50.0.20
define CROWN    = 10.50.1.30

table inet simple_range {
  chain prerouting { type filter hook prerouting priority -300; policy accept; }
  chain input      { type filter hook input      priority filter; policy accept; }

  chain forward {
    type filter hook forward priority filter; policy drop;

    ct state established,related accept

    ip saddr $ATTACKER ip daddr $EDGE   tcp dport {22, 8080}            accept
    ip saddr $EDGE     ip daddr $JUMP   tcp dport {445, 3389, 5985}     accept
    ip saddr $JUMP     ip daddr $CROWN  tcp dport 9000                  accept

    # Everything else — explicit DROP with logs so the dashboard sees it
    log prefix "simple-range-drop " drop
  }

  chain output { type filter hook output priority filter; policy accept; }
}
```

Apply:

```bash
nft -c -f /etc/nftables/keystone_hex.nft    # dry-run syntax check
nft -f /etc/nftables/keystone_hex.nft
```

## 7. Smoke test — the enforced-path invariants

```bash
# From the attacker VLAN (10.10.66.x). Replace $ATK with your Parrot IP.
nmap -Pn -p 22,8080,445,3389,5985,9000 10.50.0.10 10.50.0.20 10.50.1.30
# Expected: 10.50.0.10 shows 22+8080 open; 10.50.0.20 all filtered;
# 10.50.1.30 all filtered.

# From a shell on 10.50.0.10 (beachhead)
nmap -Pn -p 445,3389,5985,9000 10.50.0.20 10.50.1.30
# Expected: 10.50.0.20 shows 445/3389/5985 open; 10.50.1.30 all filtered.

# From a shell on 10.50.0.20 (jump)
nmap -Pn -p 9000 10.50.1.30
# Expected: 9000 open.
```

If any of those three expectations is wrong, the chain is wrong. Fix the
nft rule, do not patch around it.

## 8. Rollback

```bash
# Nuke the two new VMs
qm stop 110 || true; qm destroy 110 --purge
qm stop 130 || true; qm destroy 130 --purge

# Restore the Windows jump host NIC
qm rollback 601 pre-simple-range

# Restore the previous hEX ruleset
cp /etc/nftables/keystone_hex.nft.pre-simple-range /etc/nftables/keystone_hex.nft
nft -f /etc/nftables/keystone_hex.nft
```

The repo change is reversible with `git revert` on the commit that lands
the two docs under `docs/SIMPLE-RANGE-*.md`.

## 9. What is still a follow-up

- `modules/simple-beachhead/` — the vulnerable 8080 service source and
  manifest
- `modules/simple-crown/` — the vulnerable 9000 service source and manifest
- `keystone/score.py` — scorer that emits the six milestones in
  `SIMPLE-RANGE-2026-10.md` instead of the 11-category matrix
- `dashboard/` — simple-range topology JSON (three nodes, three edges)

Those land once this range is standing and the exploit-dev workflow has
been walked through once end-to-end.
