"""SD-card range packs: one estate per card, swap the card to swap the range.

Card layout (on any vfat/ext4 SD card):

    <mount>/keystone-ranges/<range_id>/
        RANGE_ID            text file naming the range
        manifest.sha256     json: packed_at, range_id, per-file sha256
        <estate files...>   the estate's own files, copied verbatim

Commands (run from range/, `python3 -m keystone.sdcard ...`):

    pack <range_id> <mount>          export an estate onto a card
    play [mount] [--no-wait]         verify a card and run its estate
    load <mount> [--estate ID] [--force]   verify and import a card's estate
    status [--mount PATH]            which card holds which range
    verify <mount>                   re-hash a card and check its manifest

One range per card, enforced by `pack`: a card that already holds a different
range is refused rather than appended to. `play` is the plug-and-play path —
plug the card in, run it, and the estate comes up on ephemeral localhost ports
with its port map printed. It runs the estate straight off the card, so nothing
is copied into the git tree.

The git tree stays the source of truth; cards are disposable deployable copies.
Runs never write telemetry to the card — pack and load are the only writers.

Pure Python 3 stdlib. No third-party imports.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import inspect
import json
import secrets
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
ESTATES_DIR = ROOT / "estates"
PACK_ROOT = "keystone-ranges"

# Bytecode is regenerated per-host and would otherwise ride along on every card
# (and into every manifest), so packs are source-only. `load` deliberately does
# NOT filter: importing a card must reproduce exactly what the card holds, and
# `verify` is what reports an unexpected file.
PACK_IGNORE = shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo")


def _range_dir(mount: Path, range_id: str) -> Path:
    return mount / PACK_ROOT / range_id


def _manifest_path(mount: Path, range_id: str) -> Path:
    return _range_dir(mount, range_id) / "manifest.sha256"


def _range_id_path(mount: Path, range_id: str) -> Path:
    return _range_dir(mount, range_id) / "RANGE_ID"


def _existing_packs(mount: Path) -> List[str]:
    """Range packs already on a card, sorted."""
    packs_root = mount / PACK_ROOT
    if not packs_root.is_dir():
        return []
    return sorted(p.name for p in packs_root.iterdir() if p.is_dir())


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _file_hashes(dir_path: Path) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for path in sorted(dir_path.rglob("*")):
        if path.is_file() and path.name != "manifest.sha256":
            out[str(path.relative_to(dir_path))] = _sha256(path)
    return out


def list_mounted_cards() -> List[Tuple[str, Path]]:
    """Detected removable block devices from /proc/mounts: (device, mountpoint)."""
    cards: List[Tuple[str, Path]] = []
    try:
        lines = Path("/proc/mounts").read_text().splitlines()
    except OSError:
        return cards
    for line in lines:
        parts = line.split()
        if len(parts) < 2:
            continue
        dev, mnt = parts[0], parts[1]
        if dev.startswith("/dev/mmcblk") or dev.startswith("/dev/sd"):
            cards.append((dev, Path(mnt)))
    return cards


def cmd_pack(range_id: str, mount: Path) -> int:
    source = ESTATES_DIR / range_id
    if not source.is_dir():
        print(f"error: estate not found: {source}", file=sys.stderr)
        return 2
    if not mount.is_dir():
        print(f"error: card mount not found: {mount}", file=sys.stderr)
        return 2
    dest = _range_dir(mount, range_id)
    if dest.exists():
        print(f"error: card already holds {range_id} (remove it first)", file=sys.stderr)
        return 2
    held = [r for r in _existing_packs(mount) if r != range_id]
    if held:
        print(f"error: card already holds {', '.join(held)} — one range per card. "
              f"Use a different card, or remove {PACK_ROOT}/ from this one first.",
              file=sys.stderr)
        return 6
    dest.mkdir(parents=True)
    shutil.copytree(source, dest, dirs_exist_ok=True, ignore=PACK_IGNORE)
    (_range_id_path(mount, range_id)).write_text(range_id + "\n", encoding="utf-8")
    manifest = {
        "packed_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "range_id": range_id,
        "files": _file_hashes(dest),
    }
    _manifest_path(mount, range_id).write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"[sdcard] packed {range_id} -> {mount}/{PACK_ROOT}/{range_id} "
          f"({len(manifest['files'])} files)")
    return 0


def _verify_range(mount: Path, range_id: str) -> Tuple[bool, List[str]]:
    problems: List[str] = []
    mpath = _manifest_path(mount, range_id)
    rpath = _range_id_path(mount, range_id)
    if not mpath.is_file():
        return False, ["missing manifest.sha256"]
    if not rpath.is_file():
        return False, ["missing RANGE_ID"]
    try:
        manifest = json.loads(mpath.read_text())
    except (OSError, ValueError) as exc:
        return False, [f"unreadable manifest: {exc}"]
    stored_id = rpath.read_text().strip()
    if manifest.get("range_id") != range_id or stored_id != range_id:
        problems.append(f"RANGE_ID mismatch: file={stored_id!r} manifest={manifest.get('range_id')!r}")
    expect = manifest.get("files", {})
    actual = _file_hashes(_range_dir(mount, range_id))
    for rel, want in expect.items():
        got = actual.get(rel)
        if got is None:
            problems.append(f"missing file: {rel}")
        elif got != want:
            problems.append(f"hash mismatch: {rel}")
    for rel in actual:
        if rel not in expect:
            problems.append(f"unexpected file: {rel}")
    return (not problems), problems


def cmd_verify(mount: Path) -> int:
    if not mount.is_dir():
        print(f"error: card mount not found: {mount}", file=sys.stderr)
        return 2
    packs = sorted(p.name for p in (mount / PACK_ROOT).iterdir() if p.is_dir()) \
        if (mount / PACK_ROOT).is_dir() else []
    if not packs:
        print(f"[sdcard] no range packs on {mount}")
        return 0
    rc = 0
    for range_id in packs:
        ok, problems = _verify_range(mount, range_id)
        if ok:
            print(f"[sdcard] verify {range_id}: OK")
        else:
            rc = 1
            print(f"[sdcard] verify {range_id}: FAIL")
            for problem in problems:
                print(f"  - {problem}")
    return rc


def cmd_status(mount: Optional[Path]) -> int:
    if mount is not None:
        cards = [("given mount", mount)]
    else:
        cards = list_mounted_cards()
        if not cards:
            print("[sdcard] no SD cards detected (no /dev/mmcblk* or /dev/sd* mounts)")
            return 0
    for dev, mnt in cards:
        packs_root = mnt / PACK_ROOT
        if not packs_root.is_dir():
            print(f"[sdcard] {dev} ({mnt}): no keystone range packs")
            continue
        for pack in sorted(packs_root.iterdir()):
            if not pack.is_dir():
                continue
            rid = ""
            rid_path = pack / "RANGE_ID"
            if rid_path.is_file():
                rid = rid_path.read_text().strip()
            ok, _ = _verify_range(mnt, pack.name)
            print(f"[sdcard] {dev} ({mnt}): range={rid or pack.name} verify={'OK' if ok else 'FAIL'}")
    return 0


def cmd_load(mount: Path, estate: Optional[str], force: bool) -> int:
    if not mount.is_dir():
        print(f"error: card mount not found: {mount}", file=sys.stderr)
        return 2
    packs_root = mount / PACK_ROOT
    range_ids = [p.name for p in packs_root.iterdir() if p.is_dir()] \
        if packs_root.is_dir() else []
    if not range_ids:
        print(f"error: no range packs on {mount}", file=sys.stderr)
        return 2
    if estate is not None:
        if estate not in range_ids:
            print(f"error: card has no range {estate} (has: {', '.join(range_ids)})",
                  file=sys.stderr)
            return 2
        range_id = estate
    elif len(range_ids) == 1:
        range_id = range_ids[0]
    else:
        print(f"error: card holds multiple ranges ({', '.join(range_ids)}); "
              "pick one with --estate", file=sys.stderr)
        return 2
    ok, problems = _verify_range(mount, range_id)
    if not ok:
        print(f"error: card verification failed for {range_id}:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 3
    dest = ESTATES_DIR / range_id
    if dest.exists() and not force:
        print(f"error: {dest} already exists (use --force to overwrite)", file=sys.stderr)
        return 4
    shutil.copytree(_range_dir(mount, range_id), dest, dirs_exist_ok=True)
    topology = dest / "topology.json"
    try:
        data = json.loads(topology.read_text())
        assert data.get("range") == range_id
    except (OSError, ValueError, AssertionError) as exc:
        print(f"error: loaded estate has no valid topology.json: {exc}", file=sys.stderr)
        return 5
    print(f"[sdcard] loaded {range_id} from card into {dest}")
    print(f"[sdcard] next: python3 -m keystone.sdcard status; "
          f"cd {ROOT} && ./bin/launch.sh")
    return 0


def _detect_card() -> Tuple[Optional[Path], str]:
    """Find the one mounted card that holds a range pack."""
    holders = [mnt for _dev, mnt in list_mounted_cards() if _existing_packs(mnt)]
    if not holders:
        return None, "no mounted card holds a keystone range pack"
    if len(holders) > 1:
        return None, ("multiple cards hold range packs ("
                      + ", ".join(str(h) for h in holders)
                      + "); pass the mount explicitly")
    return holders[0], ""


def _load_services_module(range_dir: Path):
    """Import a packed estate's services.py straight off the card."""
    path = range_dir / "services.py"
    if not path.is_file():
        return None
    name = f"keystone_card_{range_dir.name.replace('-', '_')}"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _service_ports(service) -> List[Tuple[str, int]]:
    """Every int port attribute a service exposes (``port``, ``http_port``, ...)."""
    out: List[Tuple[str, int]] = []
    for attr in sorted(vars(service)):
        if attr == "port" or attr.endswith("_port"):
            value = getattr(service, attr)
            if isinstance(value, int) and not isinstance(value, bool):
                out.append((attr, value))
    return out


def _required_build_args(module, range_id: str) -> Dict[str, str]:
    """Keyword values for build_estate's required parameters.

    Estates whose extra parameters all carry defaults (blind-forge, cold-chain,
    fork-and-knife) get nothing, so their module-level rotation defaults apply.
    glass-canary requires its crown key material and deploy token up front; those
    are generated per launch and reported, because the estate seeds itself with
    them and the operator recovers them in-chain.
    """
    signature = inspect.signature(module.build_estate)
    supplied: Dict[str, str] = {}
    for param in list(signature.parameters.values())[1:]:  # drop the work dir
        if param.default is inspect.Parameter.empty:
            supplied[param.name] = f"{range_id}-{param.name}-{secrets.token_hex(4)}"
    return supplied


def _scrub(text: str) -> str:
    """Never print crown material into a launch banner."""
    return "<redacted: flag material>" if "KEYSTONE{" in text else text


def start_card_estate(range_dir: Path, workdir: Path):
    """Build and start a packed estate; returns (services_by_name, supplied_secrets)."""
    module = _load_services_module(range_dir)
    if module is None or not hasattr(module, "build_estate"):
        raise ValueError(f"{range_dir.name} has no services.py exposing build_estate()")
    supplied = _required_build_args(module, range_dir.name)
    estate = module.build_estate(workdir, **supplied)
    for service in estate.values():
        service.start()
    return estate, supplied


def describe_card_estate(range_dir: Path, estate: Dict[str, object],
                         supplied: Dict[str, str]) -> str:
    """The plug-and-play banner: what came up, where, and what to attack."""
    title = range_dir.name
    try:
        title = json.loads((range_dir / "topology.json").read_text()).get("title", title)
    except (OSError, ValueError):
        pass
    lines = ["", f"  {title}", f"  range id : {range_dir.name}",
             f"  pack     : {range_dir}", "", "  services:"]
    for name in sorted(estate):
        ports = _service_ports(estate[name])
        rendered = ", ".join(f"{attr}={port}" for attr, port in ports) or "no port"
        lines.append(f"    {name:<12} {rendered}")
    if supplied:
        lines += ["", "  launch secrets (regenerated on every start):"]
        for key in sorted(supplied):
            lines.append(f"    {key} = {_scrub(supplied[key])}")
    lines += ["", f"  objective: see {range_dir / 'DESIGN.md'}",
              "  stop with Ctrl-C", ""]
    return "\n".join(lines)


def cmd_play(mount: Optional[Path], wait: bool) -> int:
    if mount is None:
        mount, error = _detect_card()
        if mount is None:
            print(f"error: {error}", file=sys.stderr)
            return 2
    if not mount.is_dir():
        print(f"error: card mount not found: {mount}", file=sys.stderr)
        return 2
    held = _existing_packs(mount)
    if not held:
        print(f"error: no range packs on {mount}", file=sys.stderr)
        return 2
    if len(held) > 1:
        print(f"error: card holds {len(held)} ranges ({', '.join(held)}) — "
              f"one range per card", file=sys.stderr)
        return 6
    range_id = held[0]
    ok, problems = _verify_range(mount, range_id)
    if not ok:
        print(f"error: card verification failed for {range_id}:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 3
    range_dir = _range_dir(mount, range_id)
    if not (range_dir / "services.py").is_file():
        print(f"[sdcard] {range_id} verified OK but ships no services.py — it is a "
              f"live-range estate (podman/VM), not a stdlib one.", file=sys.stderr)
        print(f"[sdcard] use the live path instead: "
              f"python3 -m keystone.sdcard load {mount} && ./bin/launch.sh",
              file=sys.stderr)
        return 7
    print(f"[sdcard] card {mount} verified: {range_id}")
    with tempfile.TemporaryDirectory(prefix=f"keystone-{range_id}-") as work:
        try:
            estate, supplied = start_card_estate(range_dir, Path(work))
        except Exception as exc:  # noqa: BLE001 - report and exit, never traceback
            print(f"error: could not start {range_id}: {exc}", file=sys.stderr)
            return 8
        try:
            print(describe_card_estate(range_dir, estate, supplied))
            while wait:
                time.sleep(0.5)
        except KeyboardInterrupt:
            print(f"\n[sdcard] stopping {range_id}")
        finally:
            for service in estate.values():
                try:
                    service.stop()
                except Exception:  # noqa: BLE001 - shutdown is best-effort
                    pass
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="keystone.sdcard",
                                     description="SD-card range pack tool")
    sub = parser.add_subparsers(dest="command", required=True)
    pack = sub.add_parser("pack", help="export an estate onto a card")
    pack.add_argument("range_id")
    pack.add_argument("mount", type=Path)
    load = sub.add_parser("load", help="verify and import a card's estate")
    load.add_argument("mount", type=Path)
    load.add_argument("--estate", default=None)
    load.add_argument("--force", action="store_true")
    status = sub.add_parser("status", help="which card holds which range")
    status.add_argument("--mount", type=Path, default=None)
    verify = sub.add_parser("verify", help="re-hash a card and check its manifest")
    verify.add_argument("mount", type=Path)
    play = sub.add_parser("play", help="verify a card and run its estate (plug and play)")
    play.add_argument("mount", type=Path, nargs="?", default=None,
                      help="card mount (auto-detected when omitted)")
    play.add_argument("--no-wait", action="store_true",
                      help="start, print the port map, then stop (smoke test)")
    args = parser.parse_args(argv)
    if args.command == "pack":
        return cmd_pack(args.range_id, args.mount)
    if args.command == "load":
        return cmd_load(args.mount, args.estate, args.force)
    if args.command == "status":
        return cmd_status(args.mount)
    if args.command == "verify":
        return cmd_verify(args.mount)
    if args.command == "play":
        return cmd_play(args.mount, not args.no_wait)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
