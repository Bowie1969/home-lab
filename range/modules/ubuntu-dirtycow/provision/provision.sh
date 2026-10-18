#!/bin/sh
set -eu

FIXED_VERSION=4.4.0-45.66
RUNNING_KERNEL=$(uname -r)
KERNEL_PACKAGE="linux-image-$RUNNING_KERNEL"

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root inside the isolated guest" >&2
    exit 1
fi
if ! dpkg-query -W "$KERNEL_PACKAGE" >/dev/null 2>&1; then
    echo "cannot identify package for running kernel $RUNNING_KERNEL" >&2
    exit 1
fi
PACKAGE_VERSION=$(dpkg-query -W -f='${Version}' "$KERNEL_PACKAGE")
if ! dpkg --compare-versions "$PACKAGE_VERSION" lt "$FIXED_VERSION"; then
    echo "refusing patched/non-target kernel package $PACKAGE_VERSION (fix boundary $FIXED_VERSION)" >&2
    exit 1
fi

if ! id analyst >/dev/null 2>&1; then
    useradd -m -s /bin/bash analyst
fi
passwd -l analyst >/dev/null
install -d -o analyst -g analyst -m 0700 /home/analyst/.ssh
if [ -n "${KEYSTONE_ANALYST_PUBKEY:-}" ]; then
    printf '%s\n' "$KEYSTONE_ANALYST_PUBKEY" > /home/analyst/.ssh/authorized_keys
    chown analyst:analyst /home/analyst/.ssh/authorized_keys
    chmod 0600 /home/analyst/.ssh/authorized_keys
else
    echo "KEYSTONE_ANALYST_PUBKEY is unset; the account stays locked until a run-specific key is planted" >&2
fi

install -d -m 0700 /var/lib/keystone
printf '%s\n' 'KEYSTONE{dirtycow-root-PLACEHOLDER}' > /root/flag.txt
chmod 0600 /root/flag.txt
printf '%s\n' 'ks-vault-dirtycow-d15c0' > /root/.vault-recovery.token
chmod 0600 /root/.vault-recovery.token
apt-mark hold "$KERNEL_PACKAGE" >/dev/null

echo "Dirty COW target prepared on $RUNNING_KERNEL ($PACKAGE_VERSION)."
echo "Keep the VM offline; verify low-privilege SSH and QEMU guest-agent health before snapshotting."
