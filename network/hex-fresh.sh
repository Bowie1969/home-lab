#!/bin/sh
# hex-fresh.sh — build the lab router (MikroTik hEX, OpenWrt) from nothing.
#
# POSIX sh: OpenWrt has busybox ash, not bash.
#
# WHY THIS WRITES WHOLE FILES INSTEAD OF `uci set`-ing THINGS:
# this router's image turned out to have NO /etc/config/network and no /etc/config/system — not in
# the overlay and not on the read-only base either — so there is no config to edit and every
# `uci set network.…` fails with "Entry not found". Writing complete files is also simply the right
# way to build a config from scratch: it cannot half-fail on a stray section, and a re-run converges.
#
# Run it ON the router, cabled from the admin host to lan2 (a factory-default OpenWrt answers on
# 192.168.1.1 with an empty root password):
#
#   ssh root@192.168.1.1 'cat > /tmp/hex-fresh.sh' < hex-fresh.sh
#   ssh root@192.168.1.1 'sh /tmp/hex-fresh.sh'      # writes the config, then reboots
#
# The design and the reasoning are in DESIGN.md next to this file.
set -eu

# ---- the design, in one place ----------------------------------------------
# MODE decides how the segments reach the router:
#   trunk (default) — the SG108E breaks out 802.1Q tags from one trunk cable on lan5
#   flat            — one router port per segment, no VLANs at all, flat switches for fan-out.
#                     This is the fallback for when the switch wedges (it does, and a power cycle
#                     does not always clear it), so the lab never depends on that box.
MODE="${MODE:-trunk}"
MGMT_PORT=lan2  ; MGMT_IP=10.10.0.1
TRUNK=lan5
ATTACK_VLAN=66  ; ATTACK_IP=10.10.66.1
TARGETS_VLAN=10 ; TARGETS_IP=10.10.10.1
CORP_VLAN=20    ; CORP_IP=10.10.20.1
POOL_START=100  ; POOL_LIMIT=51            # .100-.150 per segment
OPERATOR_MAC=9c:6b:00:dc:9c:90             # the operator box's WIRED nic
OPERATOR_IP=10.10.66.5
AGENT_KEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKZbAMK6LHjpvec15f8xC4LIJt6Q9W0PaovFUc6bwkW1 parrot-agent->labvm 2026-09-28'

if [ "$MODE" = flat ]; then
	ATTACK_DEV=lan3 ; TARGETS_DEV=lan4 ; CORP_DEV=lan5
else
	ATTACK_DEV="${TRUNK}.${ATTACK_VLAN}" ; TARGETS_DEV="${TRUNK}.${TARGETS_VLAN}" ; CORP_DEV="${TRUNK}.${CORP_VLAN}"
fi

echo "==> building the lab router [mode: ${MODE}]"
echo "    mgmt ${MGMT_IP} on ${MGMT_PORT} / attack ${ATTACK_IP} on ${ATTACK_DEV} / targets ${TARGETS_IP} on ${TARGETS_DEV} / corp ${CORP_IP} on ${CORP_DEV}"

# ---- 0. keep a copy of whatever is there now -------------------------------
mkdir -p /tmp/config-before
cp -a /etc/config/. /tmp/config-before/ 2>/dev/null || true
tar -czf /tmp/config-before.tar.gz -C /etc config 2>/dev/null || true
echo "    saved the existing config to /tmp/config-before.tar.gz (pull it off if you want it)"

# ---- 1. identity -----------------------------------------------------------
cat > /etc/config/system <<EOF
config system
	option hostname 'labrouter'
	option timezone 'AEST-10AEDT,M10.1.0,M4.1.0/3'
	option zonename 'Australia/Melbourne'
	option ttylogin '1'
	option log_size '64'
	option urandom_seed '0'

config timeserver 'ntp'
	list server '0.openwrt.pool.ntp.org'
	list server '1.openwrt.pool.ntp.org'

config rpcd
	option socket '/var/run/ubus/ubus.sock'
	option timeout '30'
EOF

# ---- 2. network: management, the three segments, nothing else --------------
# The WAN interface simply does not exist here: the lab is air-gapped, and each host's own Wi-Fi is
# its internet. Ports the chosen mode does not use stay unreferenced, and an unreferenced DSA port is
# simply unaddressed — exactly what a spare port should be.
{
cat <<EOF
config interface 'loopback'
	option device 'lo'
	option proto 'static'
	option ipaddr '127.0.0.1'
	option netmask '255.0.0.0'

config interface 'mgmt'
	option device '${MGMT_PORT}'
	option proto 'static'
	option ipaddr '${MGMT_IP}'
	option netmask '255.255.255.0'
EOF

# In trunk mode the three segments arrive as 802.1q sub-interfaces of one cable; in flat mode each
# gets its own physical port and there is no VLAN configuration at all.
if [ "$MODE" != flat ]; then
	for pair in "${ATTACK_VLAN}:attack" "${TARGETS_VLAN}:targets" "${CORP_VLAN}:corp"; do
		vid="${pair%%:*}"
		cat <<EOF

config device
	option name '${TRUNK}.${vid}'
	option type '8021q'
	option ifname '${TRUNK}'
	option vid '${vid}'
EOF
	done
fi

cat <<EOF

config interface 'attack'
	option device '${ATTACK_DEV}'
	option proto 'static'
	option ipaddr '${ATTACK_IP}'
	option netmask '255.255.255.0'

config interface 'targets'
	option device '${TARGETS_DEV}'
	option proto 'static'
	option ipaddr '${TARGETS_IP}'
	option netmask '255.255.255.0'

config interface 'corp'
	option device '${CORP_DEV}'
	option proto 'static'
	option ipaddr '${CORP_IP}'
	option netmask '255.255.255.0'
EOF
} > /etc/config/network

# ---- 3. firewall -----------------------------------------------------------
# Anything not explicitly allowed to forward between segments is DROPPED silently: the attacker
# should learn nothing from the firewall, and the SOC reads the drops out of the log.
# Note what is absent: attack->corp (a pivot must go THROUGH a target) and everything -> mgmt.
cat > /etc/config/firewall <<EOF
config defaults
	option syn_flood '1'
	option input 'REJECT'
	option output 'ACCEPT'
	option forward 'DROP'

config zone
	option name 'mgmt'
	list network 'mgmt'
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'DROP'
	option log '1'

config zone
	option name 'attack'
	list network 'attack'
	option input 'REJECT'
	option output 'ACCEPT'
	option forward 'DROP'
	option log '1'

config zone
	option name 'targets'
	list network 'targets'
	option input 'REJECT'
	option output 'ACCEPT'
	option forward 'DROP'
	option log '1'

config zone
	option name 'corp'
	list network 'corp'
	option input 'REJECT'
	option output 'ACCEPT'
	option forward 'DROP'
	option log '1'

config rule
	option name 'ping-mgmt'
	option src 'mgmt'
	option proto 'icmp'
	option target 'ACCEPT'

config rule
	option name 'ping-attack'
	option src 'attack'
	option proto 'icmp'
	option target 'ACCEPT'

config rule
	option name 'ping-targets'
	option src 'targets'
	option proto 'icmp'
	option target 'ACCEPT'

config rule
	option name 'ping-corp'
	option src 'corp'
	option proto 'icmp'
	option target 'ACCEPT'

config rule
	option name 'dns-attack'
	option src 'attack'
	option proto 'udp'
	option dest_port '53'
	option target 'ACCEPT'

config rule
	option name 'dns-targets'
	option src 'targets'
	option proto 'udp'
	option dest_port '53'
	option target 'ACCEPT'

config rule
	option name 'dns-corp'
	option src 'corp'
	option proto 'udp'
	option dest_port '53'
	option target 'ACCEPT'

# DHCP has to be allowed IN from each segment, or every client on it is rejected before dnsmasq
# ever hears the request. This was missing in the first build and went unnoticed because every host
# had a static address; the pools were configured and unreachable at the same time.
config rule
	option name 'dhcp-attack'
	option src 'attack'
	option proto 'udp'
	option src_port '68'
	option dest_port '67'
	option target 'ACCEPT'

config rule
	option name 'dhcp-targets'
	option src 'targets'
	option proto 'udp'
	option src_port '68'
	option dest_port '67'
	option target 'ACCEPT'

config rule
	option name 'dhcp-corp'
	option src 'corp'
	option proto 'udp'
	option src_port '68'
	option dest_port '67'
	option target 'ACCEPT'

config rule
	option name 'ssh-mgmt'
	option src 'mgmt'
	option proto 'tcp'
	option dest_port '22'
	option target 'ACCEPT'

config forwarding
	option src 'mgmt'
	option dest 'attack'

config forwarding
	option src 'mgmt'
	option dest 'targets'

config forwarding
	option src 'mgmt'
	option dest 'corp'

config forwarding
	option src 'attack'
	option dest 'targets'

config forwarding
	option src 'targets'
	option dest 'attack'

config forwarding
	option src 'targets'
	option dest 'corp'
EOF

# ---- 4. DHCP + reservations ------------------------------------------------
cat > /etc/config/dhcp <<EOF
config dnsmasq
	option domainneeded '1'
	option localise_queries '1'
	option local '/lab/'
	option domain 'lab'
	option expandhosts '1'
	option authoritative '1'
	option readethers '1'
	option leasefile '/tmp/dhcp.leases'
	option resolvfile '/tmp/resolv.conf.d/resolv.conf.auto'
	option localservice '1'
	option ednspacket_max '1232'

config dhcp 'mgmt'
	option interface 'mgmt'
	option ignore '1'

config dhcp 'attack'
	option interface 'attack'
	option start '${POOL_START}'
	option limit '${POOL_LIMIT}'
	option leasetime '12h'

config dhcp 'targets'
	option interface 'targets'
	option start '${POOL_START}'
	option limit '${POOL_LIMIT}'
	option leasetime '12h'

config dhcp 'corp'
	option interface 'corp'
	option start '${POOL_START}'
	option limit '${POOL_LIMIT}'
	option leasetime '12h'

config host
	option name 'operator'
	option mac '${OPERATOR_MAC}'
	option ip '${OPERATOR_IP}'
	option leasetime 'infinite'

# The range host (Dell Latitude E7470). Reserved rather than static so it comes back on the same
# address after any re-cabling, and so the address lives in one place — the router — instead of on
# the box. Its /etc/network/interfaces is plain DHCP.
config host
	option name 'lab-victim'
	option mac '18:db:f2:4b:e3:a9'
	option ip '10.10.10.21'
	option leasetime 'infinite'
EOF

# ---- 5. access for the agent -----------------------------------------------
mkdir -p /etc/dropbear
touch /etc/dropbear/authorized_keys
grep -qF "$AGENT_KEY" /etc/dropbear/authorized_keys 2>/dev/null || echo "$AGENT_KEY" >> /etc/dropbear/authorized_keys
chmod 600 /etc/dropbear/authorized_keys
# NOTE: dropbear reads /etc/dropbear/authorized_keys, NOT /root/.ssh/authorized_keys.
if [ -n "${ROUTER_PW:-}" ]; then
	printf '%s\n%s\n' "$ROUTER_PW" "$ROUTER_PW" | passwd root >/dev/null
	echo "    root password set from ROUTER_PW"
else
	echo "    !! no ROUTER_PW given — the router still has NO root password."
	echo "    !! Set one after this:  passwd"
fi
/etc/init.d/dropbear restart >/dev/null 2>&1 || true

echo
echo "== config written (mode: ${MODE}) =="
echo "   mgmt    ${MGMT_IP}/24 on ${MGMT_PORT} (no DHCP)"
echo "   attack  ${ATTACK_IP}/24 on ${ATTACK_DEV}   pool .${POOL_START}-.$((POOL_START + POOL_LIMIT - 1)), operator reserved ${OPERATOR_IP}"
echo "   targets ${TARGETS_IP}/24 on ${TARGETS_DEV}"
echo "   corp    ${CORP_IP}/24 on ${CORP_DEV}"
echo "   no WAN at all"
if [ "$MODE" = flat ]; then
	echo "   the switch is OUT of the path: these are four physical router ports, no VLANs at all"
fi

# Verifying before rebooting is deliberate: this script can cut your own access to the router, so
# NO_REBOOT=1 lets you (or the agent) read the generated config and check it first.
if [ "${NO_REBOOT:-0}" = 1 ]; then
	echo
	echo "== NO_REBOOT=1 — not rebooting. Check the generated config, then: reboot =="
	echo "   the files written: $(ls /etc/config/network /etc/config/firewall /etc/config/dhcp /etc/config/system 2>/dev/null | tr '\n' ' ')"
	exit 0
fi

echo
echo "== rebooting so it all takes effect cleanly =="
sleep 2
reboot
