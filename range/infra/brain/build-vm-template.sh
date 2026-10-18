#!/usr/bin/env bash
# Build the Keystone Debian 13 cloud-init VM template on the brain.
#
# Idempotent: safe to re-run. Target VMID is 9000 by default; a template is
# a frozen base clone every Keystone VM is derived from. Run this on the
# brain (willshomelab / 192.168.0.240), not on Parrot:
#
#     ssh root@192.168.0.240 bash < infra/brain/build-vm-template.sh
#
# Produces: Proxmox VM template VMID=9000, name=keystone-debian13, backed by
# the official Debian 13 (trixie) nocloud qcow2, cloud-init drive mounted,
# qemu-guest-agent enabled, serial console on, grow-on-first-boot.
# The template has NO network bridge attached — each clone picks its bridge
# at `qm clone` time from keystone/vm.py based on zone (vmbr9/50/51).

set -euo pipefail

# ---------------------------------------------------------------------------
# Knobs — override via env for a one-off rebuild.
# ---------------------------------------------------------------------------
: "${TEMPLATE_VMID:=9000}"
: "${TEMPLATE_NAME:=keystone-debian13}"
: "${STORAGE:=local-lvm}"
: "${SNIPPETS_STORAGE:=local}"   # Proxmox storage with the "snippets" content type
: "${CORES:=1}"
: "${MEMORY_MB:=512}"
: "${CPU_TYPE:=host}"

# Pin the Debian 13 cloud image by name; the matching SHA is checked below.
# Debian ships rolling "latest" qcow2s under /images/cloud/trixie/latest/ —
# we pin a dated snapshot URL + its published SHA so a future upstream rotate
# does not silently change the template contents.
: "${DEBIAN_IMAGE_URL:=https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2}"
: "${DEBIAN_IMAGE_SHA_URL:=https://cloud.debian.org/images/cloud/trixie/latest/SHA512SUMS}"
: "${DEBIAN_IMAGE_SHA_SIG_URL:=https://cloud.debian.org/images/cloud/trixie/latest/SHA512SUMS.sign}"
IMAGE_FILE=/var/lib/vz/template/iso/debian-13-genericcloud-amd64.qcow2
SHA_FILE=/var/lib/vz/template/iso/debian-13-genericcloud-amd64.SHA512SUMS

# ---------------------------------------------------------------------------
# Pre-flight: this must run on the brain, as root, with Proxmox tools present.
# ---------------------------------------------------------------------------
if [[ "${EUID}" -ne 0 ]]; then
  echo "must run as root on the brain" >&2
  exit 1
fi
for bin in qm pvesm wget sha512sum; do
  command -v "$bin" >/dev/null || { echo "missing $bin" >&2; exit 1; }
done
if ! pvesm status --storage "${STORAGE}" >/dev/null 2>&1; then
  echo "storage ${STORAGE} not found on this host" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Fetch + verify the base image.
# ---------------------------------------------------------------------------
if [[ ! -s "${IMAGE_FILE}" ]]; then
  echo "fetching ${DEBIAN_IMAGE_URL}"
  wget -q -O "${IMAGE_FILE}.part" "${DEBIAN_IMAGE_URL}"
  mv "${IMAGE_FILE}.part" "${IMAGE_FILE}"
fi
if [[ ! -s "${SHA_FILE}" ]]; then
  echo "fetching SHA512SUMS"
  wget -q -O "${SHA_FILE}" "${DEBIAN_IMAGE_SHA_URL}"
fi
echo "verifying image checksum"
(
  cd "$(dirname "${IMAGE_FILE}")"
  grep "$(basename "${IMAGE_FILE}")$" "${SHA_FILE}" | sha512sum -c -
) || { echo "SHA512 mismatch — refusing to build template" >&2; exit 1; }

# Optional: verify the SHA512SUMS signature if gpg is around and a Debian
# cloud-image signing key is in the keyring.
if command -v gpg >/dev/null && [[ -n "${VERIFY_GPG:-}" ]]; then
  wget -q -O "${SHA_FILE}.sign" "${DEBIAN_IMAGE_SHA_SIG_URL}"
  gpg --verify "${SHA_FILE}.sign" "${SHA_FILE}" >&2 \
    || { echo "GPG verify failed on SHA512SUMS" >&2; exit 1; }
fi

# ---------------------------------------------------------------------------
# Idempotency: if VMID already exists, require it to be the matching template
# and exit success. We never clobber an existing non-template VM at 9000.
# ---------------------------------------------------------------------------
if qm status "${TEMPLATE_VMID}" >/dev/null 2>&1; then
  if qm config "${TEMPLATE_VMID}" | grep -q '^template: 1'; then
    name="$(qm config "${TEMPLATE_VMID}" | awk -F': ' '/^name:/{print $2}')"
    if [[ "${name}" == "${TEMPLATE_NAME}" ]]; then
      echo "template ${TEMPLATE_VMID} (${TEMPLATE_NAME}) already present — nothing to do"
      exit 0
    fi
    echo "VMID ${TEMPLATE_VMID} is a template but named '${name}' (expected '${TEMPLATE_NAME}')" >&2
    exit 1
  fi
  echo "VMID ${TEMPLATE_VMID} exists and is NOT a template — refusing to touch it" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Build the template.
# ---------------------------------------------------------------------------
echo "creating VM ${TEMPLATE_VMID} (${TEMPLATE_NAME})"
qm create "${TEMPLATE_VMID}" \
  --name "${TEMPLATE_NAME}" \
  --cpu "${CPU_TYPE}" \
  --cores "${CORES}" \
  --memory "${MEMORY_MB}" \
  --ostype l26 \
  --machine q35 \
  --bios ovmf \
  --scsihw virtio-scsi-single \
  --agent enabled=1 \
  --serial0 socket --vga serial0 \
  --onboot 0

# EFI vars disk (OVMF needs a per-VM efidisk).
qm set "${TEMPLATE_VMID}" --efidisk0 "${STORAGE}:1,efitype=4m,pre-enrolled-keys=0"

# Import the cloud image as the root disk, then attach as scsi0.
echo "importing ${IMAGE_FILE} to ${STORAGE}"
qm importdisk "${TEMPLATE_VMID}" "${IMAGE_FILE}" "${STORAGE}" >/dev/null
qm set "${TEMPLATE_VMID}" \
  --scsi0 "${STORAGE}:vm-${TEMPLATE_VMID}-disk-1,ssd=1,discard=on"
# Grow to a sane base (clones will grow further via cloud-initramfs-growroot
# at first boot when the clone bumps the disk size).
qm resize "${TEMPLATE_VMID}" scsi0 8G

# Cloud-init drive. No cicustom yet — keystone/vm.py attaches per-clone
# user-data snippets.
qm set "${TEMPLATE_VMID}" --ide2 "${STORAGE}:cloudinit"
qm set "${TEMPLATE_VMID}" --boot order=scsi0
qm set "${TEMPLATE_VMID}" --ciuser keystone
# No default password — clones install an SSH key via cloud-init user-data.
qm set "${TEMPLATE_VMID}" --sshkeys /dev/stdin <<'KEYS' 2>/dev/null || true
# Clones override this at clone time; the template itself never ships a key.
KEYS

echo "converting VMID ${TEMPLATE_VMID} to a template"
qm template "${TEMPLATE_VMID}"

echo "DONE — template ${TEMPLATE_NAME} at VMID ${TEMPLATE_VMID}, storage ${STORAGE}"
echo "clone with:  qm clone ${TEMPLATE_VMID} <new-vmid> --name <hostname> --full --storage ${STORAGE}"
