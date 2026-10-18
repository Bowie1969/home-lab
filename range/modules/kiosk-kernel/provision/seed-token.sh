#!/bin/sh
set -eu
# kiosk-kernel vault token seed — run once inside the isolated guest image,
# after the pinned vulnerable kernel is installed and BEFORE snapshotting.
# The token is the branch's crown credential: readable only by root, i.e.
# only after the kernel privesc that this module exists to exercise.

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root inside the isolated guest" >&2
    exit 1
fi

printf '%s\n' 'ks-vault-kernel-8b2d41' > /root/vault-recovery.token
chmod 0600 /root/vault-recovery.token

echo "kiosk-kernel vault token seeded at /root/vault-recovery.token"
