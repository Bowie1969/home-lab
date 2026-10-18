#!/bin/sh
set -eu

# The owner stages an authorized local build of Samba 4.5.9 here. This script
# intentionally never downloads vulnerable software from the internet.
SAMBA_PREFIX=${SAMBA_PREFIX:-/opt/samba-4.5.9}
SMBD="$SAMBA_PREFIX/sbin/smbd"
SMB_CONF=/etc/keystone-samba-45.conf

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root inside the isolated guest" >&2
    exit 1
fi
if [ ! -x "$SMBD" ]; then
    echo "missing owner-staged $SMBD" >&2
    exit 1
fi
case "$($SMBD -V)" in
    *4.5.9*) ;;
    *) echo "refusing unexpected Samba version: $($SMBD -V)" >&2; exit 1 ;;
esac

install -d -m 0777 /srv/keystone/drop
install -d -m 0700 /root
printf '%s\n' 'KEYSTONE{sambacry-root-PLACEHOLDER}' > /root/flag.txt
chmod 0600 /root/flag.txt
printf '%s\n' 'ks-vault-samba-41ae92' > /root/vault-recovery.token
chmod 0600 /root/vault-recovery.token

install -m 0600 /dev/null "$SMB_CONF"
printf '%s\n' \
    '[global]' \
    '  workgroup = KEYSTONE' \
    '  server role = standalone server' \
    '  map to guest = Bad User' \
    '  nt pipe support = yes' \
    '  bind interfaces only = yes' \
    '  interfaces = lo eth0' \
    '[drop]' \
    '  path = /srv/keystone/drop' \
    '  guest ok = yes' \
    '  read only = no' \
    '  force user = root' > "$SMB_CONF"

install -m 0644 /dev/null /etc/systemd/system/keystone-samba-45.service
cat > /etc/systemd/system/keystone-samba-45.service <<EOF
[Unit]
Description=Keystone isolated Samba 4.5.9 target
After=network.target
[Service]
ExecStart=$SMBD --foreground --no-process-group --configfile=$SMB_CONF
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable keystone-samba-45.service
systemctl restart keystone-samba-45.service

echo "Samba 4.5.9 target prepared. Verify anonymous upload and guest-agent health before snapshotting."
