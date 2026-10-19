#!/usr/bin/env python3
"""Evasion recon: pull the tripwire inventory so later steps avoid traps on purpose.

Usage: 0001-evasion-recon.py --target http://127.0.0.1:PORT [--out intel.json]
"""
import argparse
import json
import sys
import urllib.error
import urllib.request


def fetch_inventory(target: str):
    """Return the parsed tripwire inventory document."""
    with urllib.request.urlopen(target + "/inventory", timeout=10) as resp:
        return json.loads(resp.read().decode())


def main(argv=None):
    parser = argparse.ArgumentParser(description="glass-canary evasion recon")
    parser.add_argument("--target", required=True)
    parser.add_argument("--out", default=None)
    args = parser.parse_args(argv)
    try:
        inventory = fetch_inventory(args.target)
    except (urllib.error.URLError, ValueError) as exc:
        print(f"[recon] failed: {exc}", file=sys.stderr)
        return 1
    print("[recon] canary files: " + ", ".join(inventory["canary_files"]))
    print("[recon] blocklisted names: " + ", ".join(inventory["blocklisted_names"]))
    print("[recon] blocked user agents: " + ", ".join(inventory["blocked_user_agents"]))
    print("[recon] services: " + json.dumps(inventory["services"]))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(inventory, fh, indent=2)
        print(f"[recon] intel saved to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
