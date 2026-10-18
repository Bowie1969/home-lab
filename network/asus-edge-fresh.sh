#!/bin/sh
# asus-edge-fresh.sh — configure the ASUS RT-AX1800S (OpenWrt, ramips/mt7621, "A1" rev) as the lab
# edge, in the three roles it has to carry at once:
#
#   1. the lab's gated uplink   — its LAN feeds the hEX's `wan` port (upstream of the boundary)
#   2. the room's router + AP   — its own LAN subnet, DHCP, and the room SSID
#   3. the lab's Wi-Fi AP       — one SSID bridged to VLAN 66 and pushed OUT a port into SG108E p6
#
# The lab SSID bridge gets **no IP, no DHCP, and no forwarding** to the WAN or the room LAN. Its
# clients' gateway stays the hEX (10.10.66.1), so the hEX still decides everything — that is what
# makes this safe instead of a hole.
#
# POSIX sh: OpenWrt has busybox ash, not bash.
#
# RUN IT (dry run first — prints the plan, changes nothing):
#   ssh root@192.168.1.1 'cat > /tmp/edge.sh' < asus-edge-fresh.sh
#   ROOM_SSID='...' ROOM_KEY='...' LAB_SSID='...' LAB_KEY='...' \
#     ssh root@192.168.1.1 'sh /tmp/edge.sh'
#   ...then the same line with APPLY=1 in front to write it and reboot.
#
# Ports: WAN_PORT is the house feed. LAB_PORT is the single LAN port that cables to SG108E p6.
# Everything else is the room LAN. The preflight lists the names this router actually has.
set -u

APPLY="${APPLY:-0}"
WAN_MODE="${WAN_MODE:-dhcp}"              # dhcp | pppoe | static
PPP_USER="${PPP_USER:-}"; PPP_PASS="${PPP_PASS:-}"
WAN_IP="${WAN_IP:-}"; WAN_GW="${WAN_GW:-}"; WAN_DNS="${WAN_DNS:-}"
ROOM_SUBNET="${ROOM_SUBNET:-192.168.10.0/24}"
ROOM_SSID="${ROOM_SSID:-}"; ROOM_KEY="${ROOM_KEY:-}"
LAB_SSID="${LAB_SSID:-}";   LAB_KEY="${LAB_KEY:-}"
WAN_PORT="${WAN_PORT:-wan}"
LAB_PORT="${LAB_PORT:-lan2}"              # -> SG108E p6 (access port, VLAN 66)
ROOM_PORTS="${ROOM_PORTS:-lan1 lan3 lan4}"
HOSTNAME_EDGE="${HOSTNAME_EDGE:-lab-edge}"
EDGE_PW="${EDGE_PW:-}"
AGENT_KEY="${AGENT_KEY:-ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII2/ZMf/FF7mvT6GB07QZxQuNrgAwYobKQ0aVrXuwwM fullchecksecurity@gmail.com}"

[ -n "$ROOM_SSID" ] || { echo "set ROOM_SSID (and ROOM_KEY)" >&2; exit 1; }
[ -n "$ROOM_KEY" ]  || { echo "set ROOM_KEY" >&2; exit 1; }
if [ -n "$LAB_SSID" ] && [ -z "$LAB_KEY" ]; then echo "LAB_SSID given but no LAB_KEY" >&2; exit 1; fi

ROOM_IP="${ROOM_SUBNET%/*}"; ROOM_IP="${ROOM_IP%.*}.1"
ROOM_LIST=""; for p in $ROOM_PORTS; do ROOM_LIST="${ROOM_LIST}${ROOM_LIST:+ }${p}:u*"; done

echo "==> lab edge: ${HOSTNAME_EDGE}"
echo "    WAN       ${WAN_MODE} on ${WAN_PORT}"
echo "    room      ${ROOM_SUBNET} on ${ROOM_LIST} + SSID '${ROOM_SSID}'"
if [ -n "$LAB_SSID" ]; then
	echo "    lab wifi  SSID '${LAB_SSID}' -> br-lan.66, untagged out ${LAB_PORT} (no IP, no DHCP, no routing)"
else
	echo "    lab wifi  not configured (no LAB_SSID)"
fi

echo "==> netdevs on this router:"
for d in /sys/class/net/*; do
	n="${d##*/}"
	case "$n" in lo|eth*|br-*|wlan*|phy*|sit*|.*) continue ;; esac
	printf '    %s\n' "$n"
done
for p in "$WAN_PORT" "$LAB_PORT" $ROOM_PORTS; do
	[ -e "/sys/class/net/$p" ] || { echo "!! no netdev '$p' — fix WAN_PORT/LAB_PORT/ROOM_PORTS first" >&2; exit 1; }
done

if [ "$APPLY" != 1 ]; then
	echo
	echo "== dry run: nothing written. Re-run with APPLY=1 =="
	exit 0
fi

# ---- 0. keep what is there now ----------------------------------------------
mkdir -p /tmp/config-before-edge
cp -a /etc/config/. /tmp/config-before-edge/ 2>/dev/null || true
tar -czf /tmp/config-before-edge.tar.gz -C /etc config 2>/dev/null || true
echo "    saved the existing config to /tmp/config-before-edge.tar.gz"

# ---- 1. identity + access ---------------------------------------------------
uci -q set system.@system[0].hostname="$HOSTNAME_EDGE"
uci -q set system.@system[0].timezone='AEST-10AEDT,M10.1.0,M4.1.0/3'
uci -q set system.@system[0].zonename='Australia/Melbourne'
mkdir -p /etc/dropbear
touch /etc/dropbear/authorized_keys
grep -qF "$AGENT_KEY" /etc/dropbear/authorized_keys 2>/dev/null || echo "$AGENT_KEY" >> /etc/dropbear/authorized_keys
chmod 600 /etc/dropbear/authorized_keys
if [ -n "$EDGE_PW" ]; then
	printf '%s\n%s\n' "$EDGE_PW" "$EDGE_PW" | passwd root >/dev/null
	echo "    root password set from EDGE_PW"
else
	echo "    !! no EDGE_PW given — the router keeps whatever root password it has"
fi
/etc/init.d/dropbear restart >/dev/null 2>&1 || true

# ---- 2. network -------------------------------------------------------------
# DSA board. One bridge: VLAN 1 untagged on the room ports, VLAN 66 untagged on the single lab port.
# The bridge keeps tagged access to both, which is what lets the lab SSID attach to br-lan.66.
while uci -q delete network.@device[0]; do :; done
while uci -q delete network.@bridge-vlan[0]; do :; done
uci -q delete network.wan6 2>/dev/null || true
uci -q batch <<EOF
set network.brlan='device'
set network.brlan.name='br-lan'
set network.brlan.type='bridge'
set network.vlan1='bridge-vlan'
set network.vlan1.device='br-lan'
set network.vlan1.vlan='1'
set network.vlan66='bridge-vlan'
set network.vlan66.device='br-lan'
set network.vlan66.vlan='66'
set network.lan.device='br-lan'
set network.lan.proto='static'
set network.lan.ipaddr='${ROOM_IP}'
set network.lan.netmask='255.255.255.0'
set network.wan='interface'
set network.wan.device='${WAN_PORT}'
set network.wan.proto='${WAN_MODE}'
set network.labwifi='interface'
set network.labwifi.device='br-lan.66'
set network.labwifi.proto='none'
commit network
EOF
# every physical port is a bridge member; the VLAN sections decide the tagging. Ports are uci LIST
# elements, so they go on with add_list — `set` would store the whole line as one bogus entry.
for p in $ROOM_PORTS $LAB_PORT; do uci -q add_list network.brlan.ports="$p"; done
for p in $ROOM_PORTS; do uci -q add_list network.vlan1.ports="${p}:u*"; done
uci -q add_list network.vlan66.ports="${LAB_PORT}:u*"
uci -q commit network
if [ "$WAN_MODE" = pppoe ]; then
	uci -q set network.wan.username="$PPP_USER"
	uci -q set network.wan.password="$PPP_PASS"
	uci -q commit network
fi
if [ "$WAN_MODE" = static ] && [ -n "$WAN_IP" ]; then
	uci -q set network.wan.ipaddr="$WAN_IP"
	uci -q set network.wan.netmask='255.255.255.0'
	if [ -n "$WAN_GW" ]; then uci -q set network.wan.gateway="$WAN_GW"; fi
	if [ -n "$WAN_DNS" ]; then uci -q set network.wan.dns="$WAN_DNS"; fi
	uci -q commit network
fi

# ---- 3. DHCP: the room only. The lab bridge stays silent on purpose. ---------
uci -q set dhcp.lan.interface='lan'
uci -q set dhcp.lan.start='100'
uci -q set dhcp.lan.limit='150'
uci -q set dhcp.lan.leasetime='12h'
uci -q delete dhcp.wan 2>/dev/null || true
uci -q delete dhcp.labwifi 2>/dev/null || true
uci -q set dhcp.wan='dhcp';     uci -q set dhcp.wan.interface='wan';         uci -q set dhcp.wan.ignore='1'
uci -q set dhcp.labwifi='dhcp'; uci -q set dhcp.labwifi.interface='labwifi'; uci -q set dhcp.labwifi.ignore='1'
uci -q commit dhcp

# ---- 4. firewall: the lab SSID is a dead end --------------------------------
# No address on the bridge, no DHCP, and no forwarding here: nothing can route between the lab SSID
# and the WAN or the room LAN. The hEX remains the only thing that decides lab traffic.
while uci -q delete firewall.labwifi; do :; done
uci -q set firewall.labwifi='zone'
uci -q set firewall.labwifi.name='labwifi'
uci -q set firewall.labwifi.network='labwifi'
uci -q set firewall.labwifi.input='REJECT'
uci -q set firewall.labwifi.output='ACCEPT'
uci -q set firewall.labwifi.forward='REJECT'
uci -q set firewall.labwifi.masq='0'
uci -q commit firewall

# ---- 5. wireless ------------------------------------------------------------
# Patch whatever radios this unit has; never assume their names. psk2 on purpose: WPA3-mixed is less
# predictable across old clients, and this radio also serves the house.
RADIOS="$(uci show wireless 2>/dev/null | sed -n 's/^wireless\.\(radio[0-9]*\)=.*/\1/p')"
[ -n "$RADIOS" ] || echo "!! no radios found in /etc/config/wireless — wifi left alone" >&2
FIRST=1
for r in $RADIOS; do
	uci -q set wireless.$r.country='AU'
	if [ "$FIRST" = 1 ]; then
		sec="default_${r}"
		uci -q set wireless.$sec=wifi-iface
		uci -q set wireless.$sec.device="$r"
		uci -q set wireless.$sec.mode='ap'
		uci -q set wireless.$sec.network='lan'
		uci -q set wireless.$sec.ssid="$ROOM_SSID"
		uci -q set wireless.$sec.encryption='psk2'
		uci -q set wireless.$sec.key="$ROOM_KEY"
		uci -q set wireless.$sec.disabled='0'
		FIRST=0
	fi
	if [ -n "$LAB_SSID" ]; then
		uci -q set wireless.lab_${r}=wifi-iface
		uci -q set wireless.lab_${r}.device="$r"
		uci -q set wireless.lab_${r}.mode='ap'
		uci -q set wireless.lab_${r}.network='labwifi'
		uci -q set wireless.lab_${r}.ssid="$LAB_SSID"
		uci -q set wireless.lab_${r}.encryption='psk2'
		uci -q set wireless.lab_${r}.key="$LAB_KEY"
		uci -q set wireless.lab_${r}.disabled='0'
	fi
done
uci -q commit wireless

echo
echo "== written. Read these back on the router before trusting them =="
echo "   uci show network | grep -E 'vlan|labwifi|lan\.'      # the bridge, both VLANs, the lab iface"
echo "   uci show wireless | grep -E 'ssid|network'            # room -> lan, lab -> labwifi"
echo "   uci show firewall | grep -A4 labwifi                  # the zone with no forwardings"
echo
echo "== expected after the reboot =="
echo "   the room SSID comes up and hands out ${ROOM_IP%.*}.100+"
if [ -n "$LAB_SSID" ]; then
	echo "   the lab SSID comes up; its clients land in 10.10.66.0/24 with the hEX as gateway"
	echo "   (that is the proof the VLAN 66 port is reaching SG108E p6)"
fi
echo "   the WAN port gets an address from the Sagemcom"
echo
echo "== next, by hand =="
echo "   Tailscale, if you want the tailnet to reach the lab:"
echo "     opkg update && opkg install tailscale"
echo "     tailscale up --advertise-routes=10.10.0.0/16 --accept-dns=false"
echo "   Then the hEX uplink: cable this router's LAN -> the hEX 'wan' port, and configure that WAN"
echo "   interface + a 'wan' zone that REJECTs by default (gating off) as a separate, deliberate step."
echo
echo "== rebooting so it all takes effect =="
sleep 2
reboot
