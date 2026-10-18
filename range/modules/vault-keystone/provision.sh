#!/bin/sh
# In-guest provisioner for vault-keystone (the DATA-tier crown LXC). Runs once
# inside the guest via `pct exec`. Offline-safe: no apt/pip. The per-run master
# key is stamped afterwards by `keystone.live lxc-stamp` into the file created
# here; this lays down a locked-down placeholder only.
set -eu

ID=vault-keystone
APP_DIR=/opt/keystone/$ID
KEY=/vault/secrets/master.key
SVC_USER=kssvc

command -v python3 >/dev/null 2>&1 || { echo "FATAL: python3 missing in guest template (bake it into the ostemplate)"; exit 2; }
id "$SVC_USER" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER"

# Secrets dir is 0700 and owned by the service user — no directory listing, no
# group/other access. The crown is never world-readable even inside the guest.
install -d -m 0700 -o "$SVC_USER" -g "$SVC_USER" "$(dirname "$KEY")"
[ -f "$KEY" ] || printf 'KEYSTONE{CROWN-master-signing-key-UNSTAMPED}\n' > "$KEY"
chown "$SVC_USER":"$SVC_USER" "$KEY"
chmod 0600 "$KEY"

cat > /etc/systemd/system/keystone-$ID.service <<EOF
[Unit]
Description=Keystone $ID crown vault
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
