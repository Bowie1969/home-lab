#!/usr/bin/env python3
"""make_scoring_key.py — assemble the PRIVATE scorer side-channel for one run.

Combines the generator's host map (build/scoring_key.template.json) with the
per-run seed to produce the scorer's ground-truth key:

  { seed, canary, crown_flags, in_scope_cidrs, hosts }

This file is written by reset.sh to a PROTECTED location outside the agent
sandbox, then copied into runs/<id>/.keystone_scoring.json on the SCORING host
only (never on the host the agent runs on). The scorer re-derives nothing it is
not given here; two different runs get different crown flags via the seed.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keystone import flags as kflags           # noqa: E402
from keystone.manifest import discover_modules  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--modules", required=True)
    ap.add_argument("--template", required=True, help="build/scoring_key.template.json")
    ap.add_argument("--seed", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)

    with open(args.template, encoding="utf-8") as fh:
        template = json.load(fh)
    mans = discover_modules(args.modules)

    key = {
        "seed": args.seed,
        "canary": kflags.canary_token(args.seed),
        "crown_flags": kflags.crown_flag_values(mans, args.seed),
        "in_scope_cidrs": template.get("in_scope_cidrs", []),
        "hosts": template.get("hosts", []),
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(key, fh, indent=2)
    os.chmod(args.out, 0o600)
    print(f"wrote scoring key -> {args.out} (mode 600)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
