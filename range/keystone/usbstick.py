"""USB-stick range packs: one estate per stick, swap the stick to swap the range.

Stick layout (on any vfat/ext4 USB stick):

    <mount>/keystone-ranges/<range_id>/
        RANGE_ID            text file naming the range
        manifest.sha256     json: packed_at, range_id, per-file sha256
        <estate files...>   the estate's own files, copied verbatim

Commands (run from range/, `python3 -m keystone.usbstick ...`):

    pack <range_id> <mount> [--force]  export an estate onto a stick
    play [mount] [--no-wait]         verify a stick and run its estate
    load <mount> [--estate ID] [--force]   verify and import a stick's estate
    status [--mount PATH]            which stick holds which range
    verify <mount>                   re-hash a stick and check its manifest
    diff [mount]                     check a stick's pack against the tree estate

`verify` and `diff` answer different questions. `verify` re-hashes a stick
against its own manifest, so it catches tampering and partial writes — but a
stick packed a month ago still verifies OK. `diff` compares the pack against the
estate as it stands in the tree, which is what tells you a stick has gone stale
and needs `pack --force`.

One range per stick, enforced by `pack`: a stick that already holds a different
range is refused rather than appended to, and `--force` only ever refreshes the
range already on it. `play` is the plug-and-play path — plug the stick in, run
it, and the estate comes up on ephemeral localhost ports with its port map
printed. It runs the estate straight off the stick, so nothing is copied into
the git tree.

The git tree stays the source of truth; sticks are disposable deployable copies.
Runs never write telemetry to the stick — pack and load are the only writers.

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

# Bytecode is regenerated per-host and would otherwise ride along on every stick
# (and into every manifest), so packs are source-only. `load` deliberately does
# NOT filter: importing a stick must reproduce exactly what the stick holds, and
# `verify` is what reports an unexpected file.
PACK_IGNORE = shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo")


def _range_dir(mount: Path, range_id: str) -> Path:
    return mount / PACK_ROOT / range_id


def _manifest_path(mount: Path, range_id: str) -> Path:
    return _range_dir(mount, range_id) / "manifest.sha256"


def _range_id_path(mount: Path, range_id: str) -> Path:
    return _range_dir(mount, range_id) / "RANGE_ID"


def _existing_packs(mount: Path) -> List[str]:
    """Range packs already on a stick, sorted."""
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


def list_mounted_sticks() -> List[Tuple[str, Path]]:
    """Detected removable block devices from /proc/mounts: (device, mountpoint)."""
    sticks: List[Tuple[str, Path]] = []
    try:
        lines = Path("/proc/mounts").read_text().splitlines()
    except OSError:
        return sticks
    for line in lines:
        parts = line.split()
        if len(parts) < 2:
            continue
        dev, mnt = parts[0], parts[1]
        if dev.startswith("/dev/mmcblk") or dev.startswith("/dev/sd"):
            sticks.append((dev, Path(mnt)))
    return sticks


def cmd_pack(range_id: str, mount: Path, force: bool = False) -> int:
    source = ESTATES_DIR / range_id
    if not source.is_dir():
        print(f"error: estate not found: {source}", file=sys.stderr)
        return 2
    if not mount.is_dir():
        print(f"error: stick mount not found: {mount}", file=sys.stderr)
        return 2
    # Checked before any --force deletion: refreshing one range must never be
    # the way a second range gets onto a stick.
    held = [r for r in _existing_packs(mount) if r != range_id]
    if held:
        print(f"error: stick already holds {', '.join(held)} — one range per stick. "
              f"Use a different stick, or remove {PACK_ROOT}/ from this one first.",
              file=sys.stderr)
        return 6
    dest = _range_dir(mount, range_id)
    if dest.exists():
        if not force:
            print(f"error: stick already holds {range_id} (pack --force to refresh it)",
                  file=sys.stderr)
            return 2
        # Only this range's own directory goes. A stick may hold anything else —
        # the 7.3G range stick carries irreplaceable business backups beside
        # keystone-ranges/ — so nothing outside dest is ever touched.
        shutil.rmtree(dest)
        print(f"[usbstick] replacing stale {range_id} pack on {mount}")
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
    print(f"[usbstick] packed {range_id} -> {mount}/{PACK_ROOT}/{range_id} "
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
        print(f"error: stick mount not found: {mount}", file=sys.stderr)
        return 2
    packs = sorted(p.name for p in (mount / PACK_ROOT).iterdir() if p.is_dir()) \
        if (mount / PACK_ROOT).is_dir() else []
    if not packs:
        print(f"[usbstick] no range packs on {mount}")
        return 0
    rc = 0
    for range_id in packs:
        ok, problems = _verify_range(mount, range_id)
        if ok:
            print(f"[usbstick] verify {range_id}: OK")
        else:
            rc = 1
            print(f"[usbstick] verify {range_id}: FAIL")
            for problem in problems:
                print(f"  - {problem}")
    return rc


def _is_pack_ignored(path: Path, root: Path) -> bool:
    """Whether PACK_IGNORE would have dropped this tree file from a pack.

    Mirrors the shutil pattern for the drift check: bytecode never ships, so it
    must never be reported as missing from a stick.
    """
    rel = path.relative_to(root).parts
    return "__pycache__" in rel or path.suffix in {".pyc", ".pyo"}


# Pack metadata is generated at pack time and has no counterpart in the tree,
# so it is excluded from a drift comparison.
_PACK_METADATA = {"RANGE_ID", "manifest.sha256"}


def pack_drift(mount: Path, range_id: str) -> Dict[str, List[str]]:
    """Tree-vs-stick drift for one packed range.

    ``verify`` answers "does this stick match its own manifest" — it cannot see
    that the repo has moved on since the stick was packed, so a stale stick
    still verifies OK. This is the other question: does the stick match the
    estate as it stands in the tree right now?
    """
    source = ESTATES_DIR / range_id
    pack = _range_dir(mount, range_id)
    tree: Dict[str, str] = {}
    if source.is_dir():
        for path in sorted(source.rglob("*")):
            if path.is_file() and not _is_pack_ignored(path, source):
                tree[str(path.relative_to(source))] = _sha256(path)
    stick = {rel: digest for rel, digest in _file_hashes(pack).items()
             if rel not in _PACK_METADATA}
    return {
        "changed": sorted(r for r in tree if r in stick and tree[r] != stick[r]),
        "missing": sorted(r for r in tree if r not in stick),
        "extra": sorted(r for r in stick if r not in tree),
        "no_estate": [] if source.is_dir() else [str(source)],
    }


def cmd_diff(mount: Optional[Path]) -> int:
    if mount is None:
        mount, error = _detect_stick()
        if mount is None:
            print(f"error: {error}", file=sys.stderr)
            return 2
    if not mount.is_dir():
        print(f"error: stick mount not found: {mount}", file=sys.stderr)
        return 2
    packs = _existing_packs(mount)
    if not packs:
        print(f"error: no range packs on {mount}", file=sys.stderr)
        return 2
    rc = 0
    for range_id in packs:
        drift = pack_drift(mount, range_id)
        if drift["no_estate"]:
            rc = 1
            print(f"[usbstick] diff {range_id}: NO SUCH ESTATE in the tree "
                  f"({drift['no_estate'][0]})")
            continue
        if not (drift["changed"] or drift["missing"] or drift["extra"]):
            print(f"[usbstick] diff {range_id}: in sync with the tree")
            continue
        rc = 1
        print(f"[usbstick] diff {range_id}: STALE — refresh with "
              f"./bin/packstick.sh {range_id} {mount} --force")
        for label, key in (("differs from tree", "changed"),
                           ("in tree, not on stick", "missing"),
                           ("on stick, not in tree", "extra")):
            for rel in drift[key]:
                print(f"  - {label}: {rel}")
    return rc


def cmd_status(mount: Optional[Path]) -> int:
    if mount is not None:
        sticks = [("given mount", mount)]
    else:
        sticks = list_mounted_sticks()
        if not sticks:
            print("[usbstick] no USB sticks detected (no /dev/mmcblk* or /dev/sd* mounts)")
            return 0
    for dev, mnt in sticks:
        # Pulling a stick without unmounting leaves its /proc/mounts entry
        # behind. Reporting that as "no range packs" reads as an empty stick
        # when the device is simply gone, so say which of the two it is.
        if dev.startswith("/dev/") and not Path(dev).exists():
            print(f"[usbstick] {dev} ({mnt}): STALE MOUNT — device is gone; "
                  f"umount {mnt} to clear it")
            continue
        packs_root = mnt / PACK_ROOT
        if not packs_root.is_dir():
            print(f"[usbstick] {dev} ({mnt}): no keystone range packs")
            continue
        for pack in sorted(packs_root.iterdir()):
            if not pack.is_dir():
                continue
            rid = ""
            rid_path = pack / "RANGE_ID"
            if rid_path.is_file():
                rid = rid_path.read_text().strip()
            ok, _ = _verify_range(mnt, pack.name)
            print(f"[usbstick] {dev} ({mnt}): range={rid or pack.name} verify={'OK' if ok else 'FAIL'}")
    return 0


def cmd_load(mount: Path, estate: Optional[str], force: bool) -> int:
    if not mount.is_dir():
        print(f"error: stick mount not found: {mount}", file=sys.stderr)
        return 2
    packs_root = mount / PACK_ROOT
    range_ids = [p.name for p in packs_root.iterdir() if p.is_dir()] \
        if packs_root.is_dir() else []
    if not range_ids:
        print(f"error: no range packs on {mount}", file=sys.stderr)
        return 2
    if estate is not None:
        if estate not in range_ids:
            print(f"error: stick has no range {estate} (has: {', '.join(range_ids)})",
                  file=sys.stderr)
            return 2
        range_id = estate
    elif len(range_ids) == 1:
        range_id = range_ids[0]
    else:
        print(f"error: stick holds multiple ranges ({', '.join(range_ids)}); "
              "pick one with --estate", file=sys.stderr)
        return 2
    ok, problems = _verify_range(mount, range_id)
    if not ok:
        print(f"error: stick verification failed for {range_id}:", file=sys.stderr)
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
    print(f"[usbstick] loaded {range_id} from stick into {dest}")
    print(f"[usbstick] next: python3 -m keystone.usbstick status; "
          f"cd {ROOT} && ./bin/launch.sh")
    return 0


def _detect_stick() -> Tuple[Optional[Path], str]:
    """Find the one mounted stick that holds a range pack."""
    holders = [mnt for _dev, mnt in list_mounted_sticks() if _existing_packs(mnt)]
    if not holders:
        return None, "no mounted stick holds a keystone range pack"
    if len(holders) > 1:
        return None, ("multiple sticks hold range packs ("
                      + ", ".join(str(h) for h in holders)
                      + "); pass the mount explicitly")
    return holders[0], ""


def _load_services_module(range_dir: Path):
    """Import a packed estate's services.py straight off the stick.

    Bytecode writing is suppressed for the import. Without it CPython drops a
    ``__pycache__/services.cpython-3XX.pyc`` next to the module ON THE STICK,
    which is an unexpected file as far as the manifest is concerned — a single
    `play` would leave the stick failing its own verification.
    """
    path = range_dir / "services.py"
    if not path.is_file():
        return None
    name = f"keystone_stick_{range_dir.name.replace('-', '_')}"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
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


def start_stick_estate(range_dir: Path, workdir: Path):
    """Build and start a packed estate; returns (services_by_name, supplied_secrets)."""
    module = _load_services_module(range_dir)
    if module is None or not hasattr(module, "build_estate"):
        raise ValueError(f"{range_dir.name} has no services.py exposing build_estate()")
    supplied = _required_build_args(module, range_dir.name)
    estate = module.build_estate(workdir, **supplied)
    for service in estate.values():
        service.start()
    return estate, supplied


def describe_stick_estate(range_dir: Path, estate: Dict[str, object],
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
        mount, error = _detect_stick()
        if mount is None:
            print(f"error: {error}", file=sys.stderr)
            return 2
    if not mount.is_dir():
        print(f"error: stick mount not found: {mount}", file=sys.stderr)
        return 2
    held = _existing_packs(mount)
    if not held:
        print(f"error: no range packs on {mount}", file=sys.stderr)
        return 2
    if len(held) > 1:
        print(f"error: stick holds {len(held)} ranges ({', '.join(held)}) — "
              f"one range per stick", file=sys.stderr)
        return 6
    range_id = held[0]
    ok, problems = _verify_range(mount, range_id)
    if not ok:
        print(f"error: stick verification failed for {range_id}:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 3
    range_dir = _range_dir(mount, range_id)
    if not (range_dir / "services.py").is_file():
        print(f"[usbstick] {range_id} verified OK but ships no services.py — it is a "
              f"live-range estate (podman/VM), not a stdlib one.", file=sys.stderr)
        print(f"[usbstick] use the live path instead: "
              f"python3 -m keystone.usbstick load {mount} && ./bin/launch.sh",
              file=sys.stderr)
        return 7
    print(f"[usbstick] stick {mount} verified: {range_id}")
    with tempfile.TemporaryDirectory(prefix=f"keystone-{range_id}-") as work:
        try:
            estate, supplied = start_stick_estate(range_dir, Path(work))
        except Exception as exc:  # noqa: BLE001 - report and exit, never traceback
            print(f"error: could not start {range_id}: {exc}", file=sys.stderr)
            return 8
        try:
            print(describe_stick_estate(range_dir, estate, supplied))
            while wait:
                time.sleep(0.5)
        except KeyboardInterrupt:
            print(f"\n[usbstick] stopping {range_id}")
        finally:
            for service in estate.values():
                try:
                    service.stop()
                except Exception:  # noqa: BLE001 - shutdown is best-effort
                    pass
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="keystone.usbstick",
                                     description="USB-stick range pack tool")
    sub = parser.add_subparsers(dest="command", required=True)
    pack = sub.add_parser("pack", help="export an estate onto a stick")
    pack.add_argument("range_id")
    pack.add_argument("mount", type=Path)
    pack.add_argument("--force", action="store_true",
                      help="replace this range's existing pack on the stick (refresh a stale one)")
    load = sub.add_parser("load", help="verify and import a stick's estate")
    load.add_argument("mount", type=Path)
    load.add_argument("--estate", default=None)
    load.add_argument("--force", action="store_true")
    status = sub.add_parser("status", help="which stick holds which range")
    status.add_argument("--mount", type=Path, default=None)
    verify = sub.add_parser("verify", help="re-hash a stick and check its manifest")
    verify.add_argument("mount", type=Path)
    diff = sub.add_parser("diff", help="check a stick's pack against the tree estate")
    diff.add_argument("mount", type=Path, nargs="?", default=None,
                      help="stick mount (auto-detected when omitted)")
    play = sub.add_parser("play", help="verify a stick and run its estate (plug and play)")
    play.add_argument("mount", type=Path, nargs="?", default=None,
                      help="stick mount (auto-detected when omitted)")
    play.add_argument("--no-wait", action="store_true",
                      help="start, print the port map, then stop (smoke test)")
    args = parser.parse_args(argv)
    if args.command == "pack":
        return cmd_pack(args.range_id, args.mount, args.force)
    if args.command == "load":
        return cmd_load(args.mount, args.estate, args.force)
    if args.command == "status":
        return cmd_status(args.mount)
    if args.command == "verify":
        return cmd_verify(args.mount)
    if args.command == "diff":
        return cmd_diff(args.mount)
    if args.command == "play":
        return cmd_play(args.mount, not args.no_wait)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
