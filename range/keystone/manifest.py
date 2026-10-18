"""Manifest loading and validation for Keystone modules.

Every challenge lives in ``modules/<name>/manifest.yaml`` and is fully
self-describing. Nothing about a specific challenge is hardcoded in the core:
the generator, launcher and scorer all operate purely off the parsed manifests.
Adding a challenge = dropping a folder; removing one = deleting the folder.

See ``MANIFEST_SCHEMA.md`` for the human-readable contract. This module is the
machine-readable enforcement of that contract.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from . import miniyaml

# Recognised technique classes. The crown jewel must be reachable by ~10
# INDEPENDENT initial-access vectors, each a different class drawn from here.
TECHNIQUE_CLASSES = {
    "web-rce",
    "sqli-cred",
    "ssrf-pivot",
    "smb-creddoc",
    "pinned-cve",
    "leaked-apikey",
    "deserialization-ssti",
    "jwt-authbypass",
    "writable-cron-local",
    "container-escape",
    "ad-kerberos",
    "kernel-privesc",
    "unauth-service",
    "weak-cred-ssh",
    "nfs-nosquash",
    "crown-store",
    "physical-plant",
    "cred-harvest",
    "windows-smb-rce",
    "samba-module-rce",
    "linux-cow-privesc",
    "sudo-chroot-privesc",
    "ai-supply-chain",
    "broadcast-cred-harvest",
    "oob-management",
    # Honeypot-derived surfaces (see docs/HONEYPOT_TTP_TARGETS.md): attack classes
    # observed live on the Cowrie sensor, added so EvilKit's emulation armoury has
    # valid scoped targets to exercise.
    "ingress-tool-transfer",
    "ssh-key-reuse",
}

# container/vm   = Parrot-local (podman / libvirt), as before.
# lxc            = a dedicated Keystone LXC provisioned on the brain (Proxmox).
# physical       = a planted physical implant (the Pi dropbox), not virtualized.
# remote-vm      = a VM on the brain's Proxmox (qm), reused rather than built —
#                  i.e. dc01 — distinct from a Parrot-local libvirt "vm".
SUBSTRATES = {"container", "vm", "lxc", "physical", "remote-vm"}
ZONES = {"attacker", "dmz", "corp", "data"}

# Which ATT&CK-style scoring category a module's success contributes evidence to
# by default. Purely advisory metadata for dashboards; the scorer never trusts it
# for credit (it scores observed evidence, not manifest claims).
_REQUIRED_TOP = ("id", "technique_class", "substrate", "network_zone")


class ManifestError(ValueError):
    pass


@dataclass
class Flag:
    value: str                     # literal, or template "KEYSTONE{<module>-<rot>}"
    placement: str                 # where it lives, e.g. "/root/flag.txt"
    rotate_per_run: bool = True

    @classmethod
    def from_obj(cls, obj: Dict[str, Any], mod_id: str) -> "Flag":
        if obj is None:
            raise ManifestError(f"{mod_id}: flag section missing")
        if "value" not in obj or "placement" not in obj:
            raise ManifestError(f"{mod_id}: flag needs 'value' and 'placement'")
        return cls(
            value=str(obj["value"]),
            placement=str(obj["placement"]),
            rotate_per_run=bool(obj.get("rotate_per_run", True)),
        )


@dataclass
class Build:
    containerfile: Optional[str] = None   # relative path, container substrate
    vm_spec: Optional[str] = None         # relative path, vm substrate
    context: str = "."

    @classmethod
    def from_obj(cls, obj: Optional[Dict[str, Any]]) -> "Build":
        obj = obj or {}
        return cls(
            containerfile=obj.get("containerfile"),
            vm_spec=obj.get("vm_spec"),
            context=obj.get("context", "."),
        )


@dataclass
class Manifest:
    id: str
    technique_class: str
    substrate: str
    network_zone: str
    hostname: str
    ports: List[int] = field(default_factory=list)
    prereqs: List[str] = field(default_factory=list)   # module ids that must fall first
    enables: List[str] = field(default_factory=list)   # module ids this unlocks
    flag: Optional[Flag] = None
    build: Build = field(default_factory=Build)
    evidence: Dict[str, Any] = field(default_factory=dict)
    vulnerability: Dict[str, Any] = field(default_factory=dict)
    scoring_hint: Optional[str] = None     # advisory category label
    description: str = ""
    path: str = ""                         # absolute folder path
    # A vault credential this module's compromise yields: the crown
    # (vault-keystone) accepts one token per deep CORP branch, so completing
    # any branch reaches the crown. ``value`` is the token string,
    # ``placement`` is where it lives on the target (readable only after the
    # branch's exploit succeeds), ``note`` describes the recovery condition.
    vault_token: Optional[Dict[str, str]] = None

    @property
    def is_initial_access(self) -> bool:
        """An initial-access vector has no prerequisites."""
        return len(self.prereqs) == 0

    @property
    def ip_hint(self) -> Optional[str]:
        return self.evidence.get("ip") if self.evidence else None


def _as_int_list(raw: Any, mod_id: str, field_name: str) -> List[int]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raw = [raw]
    out = []
    for item in raw:
        try:
            out.append(int(item))
        except (TypeError, ValueError):
            raise ManifestError(f"{mod_id}: {field_name} entry {item!r} is not an int")
    return out


def _as_str_list(raw: Any) -> List[str]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raw = [raw]
    return [str(x) for x in raw if x is not None]


def validate_manifest(data: Dict[str, Any], source: str = "<manifest>") -> Manifest:
    """Validate a parsed manifest mapping and return a :class:`Manifest`."""
    if not isinstance(data, dict):
        raise ManifestError(f"{source}: manifest root must be a mapping")

    for key in _REQUIRED_TOP:
        if key not in data or data[key] in (None, ""):
            raise ManifestError(f"{source}: required field '{key}' missing")

    mod_id = str(data["id"])
    tech = str(data["technique_class"])
    if tech not in TECHNIQUE_CLASSES:
        raise ManifestError(
            f"{mod_id}: unknown technique_class {tech!r}; "
            f"add it to keystone.manifest.TECHNIQUE_CLASSES if intentional"
        )
    substrate = str(data["substrate"])
    if substrate not in SUBSTRATES:
        raise ManifestError(f"{mod_id}: substrate must be one of {sorted(SUBSTRATES)}")
    zone = str(data["network_zone"])
    if zone not in ZONES:
        raise ManifestError(f"{mod_id}: network_zone must be one of {sorted(ZONES)}")

    build = Build.from_obj(data.get("build"))
    if substrate == "container" and not build.containerfile:
        raise ManifestError(f"{mod_id}: container substrate requires build.containerfile")
    if substrate == "vm" and not build.vm_spec:
        raise ManifestError(f"{mod_id}: vm substrate requires build.vm_spec")

    flag = Flag.from_obj(data.get("flag"), mod_id) if data.get("flag") is not None else None

    vulnerability = data.get("vulnerability") or {}
    if not isinstance(vulnerability, dict):
        raise ManifestError(f"{mod_id}: vulnerability must be a mapping")
    if vulnerability:
        cves = vulnerability.get("cves")
        if not isinstance(cves, list) or not cves:
            raise ManifestError(f"{mod_id}: vulnerability.cves must be a non-empty list")
        for cve in cves:
            value = str(cve)
            if not value.startswith("CVE-") or value.count("-") != 2:
                raise ManifestError(f"{mod_id}: invalid CVE identifier {value!r}")
        for required in ("affected", "verification", "source"):
            if not vulnerability.get(required):
                raise ManifestError(f"{mod_id}: vulnerability.{required} is required")

    vault_token = data.get("vault_token")
    if vault_token is not None:
        if not isinstance(vault_token, dict):
            raise ManifestError(f"{mod_id}: vault_token must be a mapping")
        value = str(vault_token.get("value") or "")
        placement = str(vault_token.get("placement") or "")
        if not value or not placement:
            raise ManifestError(f"{mod_id}: vault_token needs 'value' and 'placement'")
        vault_token = {
            "value": value,
            "placement": placement,
            "note": str(vault_token.get("note") or ""),
        }

    man = Manifest(
        id=mod_id,
        technique_class=tech,
        substrate=substrate,
        network_zone=zone,
        hostname=str(data.get("hostname", mod_id)),
        ports=_as_int_list(data.get("ports"), mod_id, "ports"),
        prereqs=_as_str_list(data.get("prereqs")),
        enables=_as_str_list(data.get("enables")),
        flag=flag,
        build=build,
        evidence=data.get("evidence") or {},
        vulnerability=vulnerability,
        scoring_hint=data.get("scoring_hint"),
        description=str(data.get("description", "")),
        vault_token=vault_token,
    )
    return man


def load_manifest_file(path: str) -> Manifest:
    data = miniyaml.load_file(path)
    man = validate_manifest(data, source=path)
    man.path = os.path.dirname(os.path.abspath(path))
    return man


def discover_modules(modules_dir: str) -> List[Manifest]:
    """Load every ``modules/<name>/manifest.yaml`` under *modules_dir*.

    This is the ONLY place module discovery happens. The set of challenges in the
    range is exactly the set of folders found here — there is no central registry.
    """
    manifests: List[Manifest] = []
    if not os.path.isdir(modules_dir):
        raise ManifestError(f"modules directory not found: {modules_dir}")
    for name in sorted(os.listdir(modules_dir)):
        folder = os.path.join(modules_dir, name)
        mf = os.path.join(folder, "manifest.yaml")
        if os.path.isfile(mf):
            manifests.append(load_manifest_file(mf))
    _check_graph(manifests)
    return manifests


def _check_graph(manifests: List[Manifest]) -> None:
    ids = {m.id for m in manifests}
    if len(ids) != len(manifests):
        seen = set()
        for m in manifests:
            if m.id in seen:
                raise ManifestError(f"duplicate module id: {m.id}")
            seen.add(m.id)
    for m in manifests:
        for dep in m.prereqs:
            if dep not in ids:
                raise ManifestError(f"{m.id}: prereq {dep!r} refers to unknown module")
        for en in m.enables:
            if en not in ids:
                raise ManifestError(f"{m.id}: enables {en!r} refers to unknown module")
    # Vault credentials are the crown's unlock keys: every branch token must be
    # unique so one leaked token can never be attributed to the wrong branch.
    seen_tokens: Dict[str, str] = {}
    for m in manifests:
        if m.vault_token:
            value = m.vault_token["value"]
            if value in seen_tokens:
                raise ManifestError(
                    f"{m.id}: vault_token value duplicated with {seen_tokens[value]}"
                )
            seen_tokens[value] = m.id
