#!/bin/sh
# In-guest provisioner for ks-files01 (CORP nfs-nosquash stand-in LXC). Runs once
# inside the guest via `pct exec`. Offline-safe: no apt/pip. The per-run flag is
# stamped afterwards by `keystone.live lxc-stamp`.
set -eu

ID=ks-files01
APP_DIR=/opt/keystone/$ID
FLAG=/opt/ks-files01/flag.txt
SVC_USER=kssvc

command -v python3 >/dev/null 2>&1 || { echo "FATAL: python3 missing in guest template (bake it into the ostemplate)"; exit 2; }
id "$SVC_USER" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER"

install -d -m 0750 -o "$SVC_USER" -g "$SVC_USER" "$(dirname "$FLAG")"
[ -f "$FLAG" ] || printf 'KEYSTONE{files01-handover-UNSTAMPED}\n' > "$FLAG"
chown "$SVC_USER":"$SVC_USER" "$FLAG"
chmod 0600 "$FLAG"

cat > /etc/systemd/system/keystone-$ID.service <<EOF
[Unit]
Description=Keystone $ID service
After=network.target
[Service]
User=$SVC_USER
ExecStart=/usr/bin/python3 $APP_DIR/server.py
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now keystone-$ID.service
echo "provisioned $ID"
