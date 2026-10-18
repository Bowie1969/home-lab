#!/usr/bin/env bash
# selftest.sh — validate the whole project WITHOUT podman/libvirt.
# Regenerates fixtures, runs the unittest suite, and sanity-checks the generator.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"
echo "[selftest] rebuilding fixtures"
python3 tests/make_fixtures.py
echo "[selftest] validating manifests + generating range plan"
python3 -m keystone.generator >/dev/null
echo "[selftest] running unittest suite"
python3 -m unittest discover -s tests -t .
echo "[selftest] OK"
