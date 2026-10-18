#!/bin/sh
set -eu

LAB_USER=${1:-analyst}
SOURCE_DIR=${KEYSTONE_SUDO_SOURCE:-/opt/keystone/vendor/sudo-1.9.16p2}
PREFIX=/opt/keystone/vuln-sudo

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root on the isolated Debian Mac" >&2
    exit 1
fi
. /etc/os-release
if [ "${ID:-}" != debian ] || [ "${VERSION_ID:-}" != 13 ]; then
    echo "refusing ${PRETTY_NAME:-unknown OS}; expected Debian 13" >&2
    exit 1
fi

APPLE=false
if [ -r /sys/class/dmi/id/sys_vendor ] && grep -qi apple /sys/class/dmi/id/sys_vendor; then
    APPLE=true
fi
if [ -r /proc/device-tree/model ] && grep -aqi apple /proc/device-tree/model; then
    APPLE=true
fi
if [ "$APPLE" != true ]; then
    echo "refusing hardware that does not identify as Apple" >&2
    exit 1
fi
if [ ! -x "$SOURCE_DIR/configure" ]; then
    echo "missing owner-staged sudo 1.9.16p2 source at $SOURCE_DIR" >&2
    exit 1
fi
if ! id "$LAB_USER" >/dev/null 2>&1; then
    echo "create a dedicated, non-sudo lab user named $LAB_USER first" >&2
    exit 1
fi

SYSTEM_SUDO_VERSION=$(/usr/bin/sudo --version | sed -n '1s/.* //p')
echo "leaving Debian system sudo patched at version $SYSTEM_SUDO_VERSION"

cd "$SOURCE_DIR"
./configure --prefix="$PREFIX" --without-pam --without-ldap --disable-gcrypt
make -j2
make install
if ! "$PREFIX/bin/sudo" --version | sed -n '1p' | grep -q '1.9.16p2'; then
    echo "refusing unexpected lab sudo version" >&2
    exit 1
fi
chown root:root "$PREFIX/bin/sudo"
chmod 4755 "$PREFIX/bin/sudo"

install -d -m 0700 /var/lib/keystone
printf '%s\n' 'KEYSTONE{mac-debian-sudo-root-PLACEHOLDER}' > /root/keystone-flag.txt
chmod 0600 /root/keystone-flag.txt
printf '%s\n' 'ks-vault-mac-77aa09' > /var/lib/keystone/vault-recovery.token
chmod 0600 /var/lib/keystone/vault-recovery.token
install -d -o "$LAB_USER" -g "$LAB_USER" -m 0700 "/home/$LAB_USER/.ssh"
if [ -n "${KEYSTONE_MAC_PUBKEY:-}" ]; then
    printf '%s\n' "$KEYSTONE_MAC_PUBKEY" > "/home/$LAB_USER/.ssh/authorized_keys"
    chown "$LAB_USER:$LAB_USER" "/home/$LAB_USER/.ssh/authorized_keys"
    chmod 0600 "/home/$LAB_USER/.ssh/authorized_keys"
else
    echo "KEYSTONE_MAC_PUBKEY is unset; install a run-specific key before accepting the target" >&2
fi

echo "mac-debian13 prepared with isolated lab sudo $($PREFIX/bin/sudo --version | sed -n '1p')."
echo "Verify CORP-only networking and capture the clean restore image before use."
