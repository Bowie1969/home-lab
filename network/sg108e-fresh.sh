#!/usr/bin/env bash
# sg108e-fresh.sh — configure a TP-Link TL-SG108E (v6, firmware 1.0.0 build 20211209) over its CGI.
#
# This is the switch's single source of truth for the lab's VLAN table. The port map it writes is
# the final design (lab/WIRING.md §5, DESIGN.md §3). Change the table here, not in a scratch copy.
#
# TWO WAYS TO REACH THE SWITCH
#   (a) from the admin host, with a route/alias for the switch's address on the lab NIC. curl binds
#       to the NIC with --interface, which is how you talk to 192.168.0.1 without reaching the house
#       modem that shares that address. This script takes this path.
#   (b) from the hEX as a jump host — it has nc and BusyBox wget but NO curl and no python3, so this
#       curl-based script cannot run there as-is.
#
# RUN
#   SWITCH_PW='...' bash sg108e-fresh.sh                 # apply
#   DRY_RUN=1 SWITCH_PW='...' bash sg108e-fresh.sh        # print the requests, change nothing
#   REBOOT=1  SWITCH_PW='...' bash sg108e-fresh.sh        # reboot afterwards to prove persistence
#
# FIRMWARE RULES, LEARNED THE HARD WAY (2026-09-12, 2026-09-15, re-checked 2026-10-02)
#   * The config CGIs take GET with query params. A POST returns an instant EMPTY reply, and that
#     POST is what wedged this switch's management CPU twice. This script never POSTs — the only
#     exception is the documented reboot endpoint behind REBOOT=1.
#   * The Apply button's value is literally "Add/Modify" (URL-encoded Add%2FModify) on every write,
#     including for a VLAN that already exists. Sending anything else is silently ignored.
#   * Every Apply commits straight to flash. There is no separate "save config" step on this fw.
#   * Result pages embed  var tip = "Operation successful." | "Failed"  — read that, not the HTTP code.
#   * A factory-reset unit forces a password change on the first login before any other page works.
#   * The switch's OWN management address is not set by this script. Set it by hand on VLAN 1 to a
#     mgmt-segment address (10.10.0.x) and turn its DHCP client off. Never leave it at 192.168.0.1.
set -uo pipefail

SWITCH_HOST="${SWITCH_HOST:-192.168.0.1}"
SWITCH_USER="${SWITCH_USER:-admin}"
# No apostrophe in this message, deliberately: inside ${VAR:?word} an apostrophe opens a
# single-quoted string and swallows the rest of the file. Cost me a confusing syntax error once.
SWITCH_PW="${SWITCH_PW:?set SWITCH_PW to the admin password of the switch (factory default is admin)}"
DRY_RUN="${DRY_RUN:-0}"
REBOOT="${REBOOT:-0}"
IF="${IF:-enp8s0}"
JAR="$(mktemp)"
trap 'rm -f "$JAR"' EXIT
PASSWORD_STILL_DEFAULT=0   # set if we only got in with the factory default; warned about at the end

# ---------------------------------------------------------------------------
# THE DESIGN — one table. selType: 0 = untagged member, 1 = tagged member, 2 = not a member.
#
#   VLAN 1  mgmt     untagged p5,p7,p8            and NOT a member of p1..p4
#   VLAN 10 targets  tagged p1        untagged p3
#   VLAN 20 corp     tagged p1        untagged p4
#   VLAN 66 attack   tagged p1        untagged p2 (operator) + p6 (the Asus lab SSID)
#
# p1 is the trunk to hEX lan5. It carries tagged 10/20/66 and is DELIBERATELY NOT a member of VLAN 1:
# untagged management frames must never leak onto a segment port. That invariant is the whole reason
# this switch is allowed back in the path (DESIGN.md §5).
#
# If the lab SSID ends up on a dedicated AP instead of the Asus, move VLAN 66's untagged member from
# p6 to p7 in the row below — it is the only line that changes.
VLAN_TABLE=(
	"1|mgmt|2 2 2 2 0 2 0 0"
	"10|targets|1 2 0 2 2 2 2 2"
	"20|corp|1 2 2 0 2 2 2 2"
	"66|attack|1 0 2 2 2 0 2 2"
)
VLAN_ORDER=(1 10 20 66)
# p1=1 p2=66 p3=10 p4=20 p5=1 p6=66 p7=1 p8=1
PVID_EXPECT="1 66 10 20 1 66 1 1"
# ---------------------------------------------------------------------------

declare -A TAG_MASK UNTAG_MASK VLAN_NAME SELTYPES
for row in "${VLAN_TABLE[@]}"; do
	IFS='|' read -r vid name types <<<"$row"
	VLAN_NAME[$vid]="$name"
	SELTYPES[$vid]="$types"
	read -r -a t <<<"$types"
	tm=0; um=0; p=1
	for x in "${t[@]}"; do
		[ "$x" = 1 ] && tm=$((tm | (1 << (p - 1))))
		[ "$x" = 0 ] && um=$((um | (1 << (p - 1))))
		p=$((p + 1))
	done
	TAG_MASK[$vid]=$tm
	UNTAG_MASK[$vid]=$um
done

hex() { printf '0x%X' "$1"; }
to_dec() { local r; if r=$(( $1 )) 2>/dev/null; then printf '%d' "$r"; else printf -- '-1'; fi; }

# The PVID groups, derived from PVID_EXPECT so the design stays written down in exactly one place.
read -r -a pv <<<"$PVID_EXPECT"
declare -A PBM
p=1
for want in "${pv[@]}"; do
	PBM[$want]=$(( ${PBM[$want]:-0} | (1 << (p - 1)) ))
	p=$((p + 1))
done

echo "==> switch at ${SWITCH_HOST} (bound to ${IF})"

# --- 0. is anything there, and is it the switch? ------------------------------
# 192.168.0.1 is ALSO the house modem's address, so the reply has to be identified before we start
# configuring — otherwise this quietly configures the wrong device. "nothing answered" (switch
# rebooting or wedged) is NOT the same as "something else answered", so they are reported separately.
if [ "$DRY_RUN" != 1 ]; then
	probe="$(curl -fsS -m 6 --interface "$IF" "http://${SWITCH_HOST}/" 2>/dev/null || true)"
	if printf '%s' "$probe" | grep -qiE 'tp-?link|logon\.cgi|Easy Smart'; then
		echo "    looks like the switch — good"
	elif [ -z "$probe" ]; then
		echo "!! nothing answered at ${SWITCH_HOST} over ${IF}." >&2
		echo "   A wedged management CPU looks exactly like this (ARP still answers, HTTP does not)" >&2
		echo "   and only a power cycle clears it. It can also just be a missing route — check:" >&2
		echo "       ip route get ${SWITCH_HOST}      # must say dev ${IF}" >&2
		echo "       ip -4 addr show ${IF}            # must have an address in ${SWITCH_HOST%.*}.0/24" >&2
		exit 1
	else
		echo "!! ${SWITCH_HOST} answered, but not like the switch — answering page is:" >&2
		printf '%s' "$probe" | grep -oiE '<title>[^<]*</title>|tp-?link|sagemcom|optus|asus' | head -3 | sed 's/^/     /' >&2
		echo "   That is almost certainly the house modem/router, which shares this address." >&2
		echo "   Run with the switch's own address (SWITCH_HOST=...), bind to the lab NIC, or take" >&2
		echo "   your Wi-Fi down so the route cannot win." >&2
		exit 1
	fi
fi

# --- 1. log in ---------------------------------------------------------------
# The firmware answers every login attempt with the same page and reports the outcome in a JS array:
# `logonInfo = new Array(errType, ...)` where 0 = success, 1 = wrong user/password, 2 = not allowed,
# 3 = too many sessions. That array is the only reliable signal — HTTP is 200 either way.
# A factory-reset unit accepts admin/admin ONCE and then insists the password be changed; that change
# is submitted to the same endpoint with a confirm field, so this works on a virgin switch and on an
# already-configured one.
login() {
	local pw="$1" extra="$2" enc
	enc="$(printf '%s' "$pw" | python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.stdin.read(),safe=""))')"
	rm -f "$JAR"
	curl -fsS -c "$JAR" --interface "$IF" -o /dev/null "http://${SWITCH_HOST}/" || true
	printf 'username=%s&password=%s%s&logon=Login' "$SWITCH_USER" "$enc" "$extra" \
		| curl -fsS -b "$JAR" -c "$JAR" --interface "$IF" --data @- "http://${SWITCH_HOST}/logon.cgi" 2>/dev/null \
		| tr -d '\n' \
		| sed -n 's/.*logonInfo *= *new Array(\([0-9]*\).*/\1/p' | head -1
}

echo "==> logging in"
if [ "$DRY_RUN" = 1 ]; then
	echo "  + POST /logon.cgi (password hidden)" >&2
else
	rc="$(login "$SWITCH_PW" "")"
	if [ "${rc:-1}" != 0 ]; then
		echo "    the saved password did not work (errType ${rc:-?}) — trying the factory default"
		# errType 1 on a virgin switch is expected: the default is admin/admin. The firmware only
		# offers its one-time password change on the very FIRST successful login, so this tries to set
		# the password in that same request — but if anything has already logged in once (even a
		# probe), the change is silently ignored and the password stays admin/admin. Hence the honest
		# warning at the end rather than a claim that the password was set.
		enc="$(printf '%s' "$SWITCH_PW" | python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.stdin.read(),safe=""))')"
		rc2="$(login "admin" "&cpassword=${enc}")"
		if [ "${rc2:-1}" != 0 ]; then
			echo "!! could not log in at all (errType ${rc2:-?})." >&2
			echo "   errType 1 = wrong user or password, so the switch is NOT at factory defaults." >&2
			echo "   Either reset it properly (hold RESET 5+ seconds while powered on) or give this" >&2
			echo "   script the current password." >&2
			exit 1
		fi
		PASSWORD_STILL_DEFAULT=1
	else
		echo "    logged in"
	fi
fi

# Every request carries the session cookie AND Basic auth (this firmware accepts Basic on every
# request, so it costs nothing and survives a session being dropped), bound to the lab NIC.
cget() {
	if [ "$DRY_RUN" = 1 ]; then printf '  + GET %s\n' "$1" >&2; return 0; fi
	curl -fsS -m 12 -b "$JAR" -c "$JAR" --interface "$IF" -u "${SWITCH_USER}:${SWITCH_PW}" \
		-H "Referer: http://${SWITCH_HOST}/${2:-Vlan8021QRpm.htm}" "http://${SWITCH_HOST}${1}"
}

tip_ok() { grep -qi 'Operation successful'; }   # reads a result page on stdin

# --- 2. switch 802.1Q on -----------------------------------------------------
# This firmware refuses VLAN edits until 802.1Q is enabled, and the Apply is what enables it.
echo "==> enabling 802.1Q"
cget "/qvlanSet.cgi?qvlan_en=1&qvlan_mode=Apply" Vlan8021QRpm.htm >/dev/null || true

# --- 3. the VLAN table -------------------------------------------------------
# VLAN 1 already exists (it is the default) so it is modified; the rest are added. VLANs must exist
# before their PVIDs can be set — the firmware rejects a PVID with no VLAN.
vlan_query() {   # vid -> the query string for that VLAN, from the table
	local vid="$1" q p=1
	read -r -a t <<<"${SELTYPES[$vid]}"
	q="vid=${vid}&vname=${VLAN_NAME[$vid]}"
	for x in "${t[@]}"; do q="${q}&selType_${p}=${x}"; p=$((p + 1)); done
	printf '%s' "$q"
}
write_vlans() {
	local vid resp
	for vid in "${VLAN_ORDER[@]}"; do
		resp="$(cget "/qvlanSet.cgi?$(vlan_query "$vid")&qvlan_add=Add%2FModify" Vlan8021QRpm.htm)"
		if [ "$DRY_RUN" != 1 ] && ! printf '%s' "$resp" | tip_ok; then
			echo "    !! VLAN ${vid} did not report success" >&2
		fi
		[ "$DRY_RUN" != 1 ] && sleep 1
	done
}
write_pvids() {
	local want resp
	for want in $(printf '%s\n' "${pv[@]}" | awk '!seen[$0]++'); do
		resp="$(cget "/vlanPvidSet.cgi?pbm=${PBM[$want]}&pvid=${want}" Vlan8021QPvidRpm.htm)"
		if [ "$DRY_RUN" != 1 ] && ! printf '%s' "$resp" | tip_ok; then
			echo "    !! PVID ${want} did not report success" >&2
		fi
		[ "$DRY_RUN" != 1 ] && sleep 1
	done
}

echo "==> writing VLANs (tagged trunk on p1, access ports per segment)"
for vid in "${VLAN_ORDER[@]}"; do
	printf '    VLAN %s (%s)  tag=%s untag=%s\n' "$vid" "${VLAN_NAME[$vid]}" \
		"$(hex "${TAG_MASK[$vid]}")" "$(hex "${UNTAG_MASK[$vid]}")"
done
write_vlans

echo "==> setting PVIDs"
for want in $(printf '%s\n' "${pv[@]}" | awk '!seen[$0]++'); do
	echo "    pbm=${PBM[$want]} -> pvid=${want}"
done
write_pvids

# --- 4. read it back and check it, numerically --------------------------------
# Two traps this firmware taught us. (1) "tagMbrs" is a SUBSTRING of "untagMbrs", so an unanchored
# match compares the wrong mask — every pattern below is anchored on the preceding comma. (2) The
# device's float/hex formatting is inconsistent (0x0 vs 0X0), so values are compared as numbers and a
# formatting difference cannot fail a correct table. VLANs are matched by their VID, not by position.
read_field() {   # page field-name -> a space-separated list of the values in that array
	local page="$1" key="$2"
	printf '%s' "$page" | tr -d '\n\r' \
		| grep -oE "(^|,)${key}:\[[^]]*\]" | head -1 \
		| sed 's/.*\[//;s/\]//' | tr ',' ' '
}
read_vlan() { cget "/Vlan8021QRpm.htm" Vlan8021QRpm.htm; }
read_pvid() { cget "/Vlan8021QPvidRpm.htm" Vlan8021QPvidRpm.htm; }

verify() {
	local v p ok=0 vid idx i
	local -a vids tags unts pvids
	v="$(read_vlan)"; p="$(read_pvid)"
	[ -n "$v" ] && [ -n "$p" ] || { echo "    (no tables read back)"; return 1; }
	vids=($(read_field "$v" 'vids'))
	tags=($(read_field "$v" 'tagMbrs'))
	unts=($(read_field "$v" 'untagMbrs'))
	pvids=($(read_field "$p" 'pvids'))
	printf '    vids:[%s] tagMbrs:[%s] untagMbrs:[%s]\n' \
		"${vids[*]:-}" "${tags[*]:-}" "${unts[*]:-}"
	printf '    pvids:[%s]\n' "${pvids[*]:-}"
	if [ "${#vids[@]}" -eq 0 ] || [ "${#tags[@]}" -eq 0 ] || [ "${#unts[@]}" -eq 0 ]; then
		echo "    !! could not parse the VLAN table (firmware format changed?)"; return 1
	fi
	for vid in "${VLAN_ORDER[@]}"; do
		idx=-1
		for i in "${!vids[@]}"; do
			[ "$(to_dec "${vids[$i]}")" = "$vid" ] && idx=$i
		done
		if [ "$idx" -lt 0 ]; then echo "    !! VLAN ${vid} missing from the table"; ok=1; continue; fi
		if [ "$(to_dec "${tags[$idx]}")" != "${TAG_MASK[$vid]}" ]; then
			echo "    !! VLAN ${vid} tagged = $(hex "$(to_dec "${tags[$idx]}")"), wanted $(hex "${TAG_MASK[$vid]}")"; ok=1
		fi
		if [ "$(to_dec "${unts[$idx]}")" != "${UNTAG_MASK[$vid]}" ]; then
			echo "    !! VLAN ${vid} untagged = $(hex "$(to_dec "${unts[$idx]}")"), wanted $(hex "${UNTAG_MASK[$vid]}")"; ok=1
		fi
	done
	if [ "${#pvids[@]}" -lt 8 ]; then
		echo "    !! only ${#pvids[@]} PVIDs came back, expected 8"; ok=1
	else
		for i in 0 1 2 3 4 5 6 7; do
			if [ "$(to_dec "${pvids[$i]}")" != "${pv[$i]}" ]; then
				echo "    !! p$((i + 1)) PVID = $(to_dec "${pvids[$i]}"), wanted ${pv[$i]}"; ok=1
			fi
		done
	fi
	[ "$ok" = 0 ]
}

if [ "$DRY_RUN" = 1 ]; then
	echo "==> (dry run: nothing written, nothing verified)"
else
	echo "==> verifying the table on the switch"
	if ! verify; then
		echo "    does not match yet — rewriting once and checking again"
		write_vlans; write_pvids; sleep 2
		if ! verify; then
			echo "!! the table still does not match the design. Check it in the web UI." >&2
			exit 1
		fi
		echo "    matches after the retry"
	else
		echo "    matches the design exactly"
	fi
fi

# --- 5. what was written, port by port ---------------------------------------
# Printed from the same table that was applied, so this cannot drift from the design.
echo
echo "    Resulting port map:"
for p in 1 2 3 4 5 6 7 8; do
	tagged=""; untagged=""; mode="spare"
	for vid in "${VLAN_ORDER[@]}"; do
		read -r -a t <<<"${SELTYPES[$vid]}"
		case "${t[$((p - 1))]}" in
			1) tagged="${tagged} ${vid}" ;;
			0) untagged="${untagged} ${vid}" ;;
		esac
	done
	[ -n "$tagged" ] && mode="trunk (tagged)"
	[ -n "$untagged" ] && [ -z "$tagged" ] && mode="access"
	printf '      p%d  %-14s untagged:%-8s tagged:%-10s pvid %s\n' \
		"$p" "$mode" "${untagged# }" "${tagged# }" "${pv[$((p - 1))]}"
done
cat <<'NOTES'
      p1 trunk to hEX lan5 (10/20/66 tagged, NOT a member of VLAN 1)
      p2 access 66  -> the operator box
      p3 access 10  -> flat switch 1 -> targets hosts
      p4 access 20  -> flat switch 2 -> corp hosts
      p5 access 1   -> the admin host (run this script from here)
      p6 access 66  -> the Asus's lab SSID
      p7 access 1   -> spare (or the dedicated lab AP)
      p8 access 1   -> hEX lan2, the mgmt segment
NOTES

# --- 6. what is left undone, said out loud -----------------------------------
echo
echo "   NEXT, BY HAND: give the switch its own management address on VLAN 1 (10.10.0.x) and turn"
echo "   its DHCP client off. This script does not set it. It must never stay at 192.168.0.1."
if [ "$PASSWORD_STILL_DEFAULT" = 1 ]; then
	echo
	echo "   NOTE: the switch still has its factory password (admin/admin). This firmware only offers"
	echo "         the password change on the very first login after a reset, and something had already"
	echo "         logged in once. Set a real password in the web UI (System Tools -> Password), or"
	echo "         reset the switch and run this script as the first thing that touches it."
fi

# --- 7. optional proof ------------------------------------------------------
if [ "$REBOOT" = 0 ]; then
	echo
	echo "==> config written. Add REBOOT=1 next time to prove it survives a power cycle."
	exit 0
fi

echo "==> rebooting the switch to prove the config persists"
if [ "$DRY_RUN" = 1 ]; then
	echo "  + POST /reboot.cgi reboot_op=reboot&save_op=false" >&2
else
	curl -fsS -b "$JAR" -c "$JAR" --interface "$IF" --data 'reboot_op=reboot&save_op=false' \
		"http://${SWITCH_HOST}/reboot.cgi" >/dev/null 2>&1 || true
	echo "    sent. The switch drops off for ~15 seconds; re-check reachability after that."
fi
