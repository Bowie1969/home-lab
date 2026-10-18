"""Load raw post-run evidence from a ``runs/<id>/`` directory.

Evidence sources (all optional — the scorer degrades gracefully):

  journal.jsonl         agent-declared intents, one JSON object per line
  pcaps/*.pcap          network truth, parsed directly with keystone.pcap
  fsdiff.json           {host: {"added":[paths], "modified":[paths]}}
  beacons.jsonl         C2 callback logs, one object per line
  answer_key_access.jsonl  (produced by bin/ak_monitor.py) ground-truth reads
  .keystone_scoring.json   PRIVATE scorer side-channel (seed/canary/crown/hosts).
                           Placed by launch.sh OUTSIDE the agent sandbox and
                           mounted read-only for scoring. Never agent evidence.

Nothing here interprets order. Everything is reduced to unordered sets/dicts so
the scorer cannot accidentally become path-dependent.
"""
from __future__ import annotations

import glob
import hashlib
import ipaddress
import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from . import pcap, zones


def _read_jsonl(path: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    malformed = 0
    if not os.path.isfile(path):
        return out, malformed
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                malformed += 1
                continue
            if isinstance(obj, dict):
                out.append(obj)
    return out, malformed


def _read_json(path: str) -> Optional[Any]:
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return None


@dataclass
class HostRecord:
    id: str
    hostname: str
    ip: str
    zone: str


@dataclass
class ScoringKey:
    """Private ground-truth side-channel. Absent on an untrusted scoring host."""
    seed: Optional[str] = None
    canary: Optional[str] = None
    crown_flags: List[str] = field(default_factory=list)
    in_scope_cidrs: List[str] = field(default_factory=list)
    hosts: List[HostRecord] = field(default_factory=list)

    @classmethod
    def from_obj(cls, obj: Optional[Dict[str, Any]]) -> "ScoringKey":
        if not obj:
            return cls()
        hosts = [
            HostRecord(
                id=str(h.get("id", "")),
                hostname=str(h.get("hostname", "")),
                ip=str(h.get("ip", "")),
                zone=str(h.get("zone", "")),
            )
            for h in obj.get("hosts", []) or []
        ]
        return cls(
            seed=obj.get("seed"),
            canary=obj.get("canary"),
            crown_flags=list(obj.get("crown_flags", []) or []),
            in_scope_cidrs=list(obj.get("in_scope_cidrs", []) or []),
            hosts=hosts,
        )


@dataclass
class Evidence:
    run_id: str
    run_dir: str
    journal: List[Dict[str, Any]] = field(default_factory=list)
    beacons: List[Dict[str, Any]] = field(default_factory=list)
    ak_access: List[Dict[str, Any]] = field(default_factory=list)
    fsdiff: Dict[str, Any] = field(default_factory=dict)
    packets: List[pcap.Packet] = field(default_factory=list)
    key: ScoringKey = field(default_factory=ScoringKey)

    # resolution helpers built at load time
    _by_ip: Dict[str, HostRecord] = field(default_factory=dict)
    _by_name: Dict[str, HostRecord] = field(default_factory=dict)
    # run-local zone override: {zone: [cidr, ...]} from zones.json
    _zones: Dict[str, List[str]] = field(default_factory=dict)
    # evidence integrity: sha256 manifest written by run_control.stop at run end.
    # None = no manifest (evidence files were agent-writable with no check).
    manifest_ok: Optional[bool] = None
    malformed_journal_lines: int = 0

    # ---- resolution -----------------------------------------------------------
    def zone_of(self, ident: str) -> str:
        """Resolve an identifier (ip, hostname or module id) to its zone."""
        if ident in self._by_ip:
            return self._by_ip[ident].zone
        if ident in self._by_name:
            return self._by_name[ident].zone
        for zone, cidrs in self._zones.items():
            for cidr in cidrs:
                try:
                    if ipaddress.ip_address(ident) in ipaddress.ip_network(cidr):
                        return zone
                except ValueError:
                    continue
        return zones.zone_of_ip(ident)

    def ip_of(self, ident: str) -> str:
        if ident in self._by_ip:
            return ident
        if ident in self._by_name:
            return self._by_name[ident].ip
        return ident

    def in_scope(self, ip: str) -> bool:
        if self.key.in_scope_cidrs:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                return False
            for cidr in self.key.in_scope_cidrs:
                if addr in ipaddress.ip_network(cidr):
                    return True
            return False
        if self._zones:
            return self.zone_of(ip) != ""
        return zones.is_in_scope(ip)


def _read_zones(run_dir: str) -> Dict[str, List[str]]:
    """Load an optional run-local zone map (zones.json) for homelab runs.

    Format: {"zones": {"dmz": ["10.99.50.0/24"], "corp": "10.50.0.0/24"}}.
    run_control.start writes this for separately launched EvilKit runs so the
    scorer resolves the lab's real segments instead of the podman 10.80.x map.
    """
    obj = _read_json(os.path.join(run_dir, "zones.json"))
    if not isinstance(obj, dict):
        return {}
    raw = obj.get("zones", {})
    out: Dict[str, List[str]] = {}
    if isinstance(raw, dict):
        for zone, cidrs in raw.items():
            if isinstance(cidrs, str):
                cidrs = [cidrs]
            if isinstance(cidrs, list):
                out[str(zone)] = [str(c) for c in cidrs]
    return out


_EVIDENCE_FILES = ("journal.jsonl", "fsdiff.json", "beacons.jsonl")


def _read_manifest(run_dir: str) -> Optional[bool]:
    """Check the stop-time evidence manifest written by run_control.stop.

    Returns True when every evidence file's sha256 matches the manifest, False
    when at least one differs (evidence changed after the run ended), and None
    when no manifest exists (files were agent-writable with no integrity check).
    """
    manifest = _read_json(os.path.join(run_dir, "evidence.manifest.json"))
    if not isinstance(manifest, dict):
        return None
    hashes = manifest.get("files", {})
    if not isinstance(hashes, dict) or not hashes:
        return None
    ok = True
    for name in _EVIDENCE_FILES:
        path = os.path.join(run_dir, name)
        expected = hashes.get(name)
        if expected is None:
            continue
        if not os.path.isfile(path):
            ok = False
            continue
        with open(path, "rb") as fh:
            actual = hashlib.sha256(fh.read()).hexdigest()
        if actual != expected:
            ok = False
    return ok


def load_evidence(run_dir: str) -> Evidence:
    run_dir = os.path.abspath(run_dir)
    run_id = os.path.basename(run_dir.rstrip("/"))
    ev = Evidence(run_id=run_id, run_dir=run_dir)

    ev.journal, ev.malformed_journal_lines = _read_jsonl(os.path.join(run_dir, "journal.jsonl"))
    ev.beacons, _ = _read_jsonl(os.path.join(run_dir, "beacons.jsonl"))
    ev.ak_access, _ = _read_jsonl(os.path.join(run_dir, "answer_key_access.jsonl"))
    ev.fsdiff = _read_json(os.path.join(run_dir, "fsdiff.json")) or {}
    ev._zones = _read_zones(run_dir)
    ev.manifest_ok = _read_manifest(run_dir)

    for pattern in ("pcaps/*.pcap", "*.pcap"):
        for p in sorted(glob.glob(os.path.join(run_dir, pattern))):
            try:
                ev.packets.extend(pcap.read_all(p))
            except pcap.PcapError:
                continue

    ev.key = ScoringKey.from_obj(_read_json(os.path.join(run_dir, ".keystone_scoring.json")))
    for h in ev.key.hosts:
        if h.ip:
            ev._by_ip[h.ip] = h
        if h.hostname:
            ev._by_name[h.hostname] = h
        if h.id:
            ev._by_name[h.id] = h
    return ev
