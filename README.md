# Home Lab

**A self-hosted home lab and segmented network that runs an AI-agent benchmark
range with a live telemetry dashboard — all built from a pure-Python stdlib core.**

![Python](https://img.shields.io/badge/Python-3-blue)
![core](https://img.shields.io/badge/core-pure%20stdlib-blueviolet)
![tests](https://img.shields.io/badge/tests-unittest%20suite-brightgreen)
![range](https://img.shields.io/badge/range-23%2B%20challenge%20modules-orange)
![dashboard](https://img.shields.io/badge/dashboard-no%20CDN%2C%20no%20build%20step-informational)
![license](https://img.shields.io/badge/license-private-lightgrey)

## What it is

Three things that belong together, in one repository:

- **`range/` — Keystone Range.** A modular, run-agnostic benchmark for evaluating
  AI security agents. A pure-Python-stdlib generator builds a plan from per-challenge
  manifests, and a path-agnostic scorer grades the agent's evidence against a
  private ground-truth side channel. Challenge modules ship as containers, LXC
  guests, or VM definitions — no VM disks or vulnerable binaries are bundled.
- **`dashboard/` — live monitor.** A read-only dashboard that visualises a run's
  estate topology, agent events, and score breakdown. Single-file server
  (`server.py`) with server-sent events, an in-browser force-simulation canvas
  (`app.js`, no d3, no CDN, no build step), and a self-looping demo dataset.
- **`network/` — the home-lab network.** The physical wiring and zone/VLAN
  config behind it all: a MikroTik hEX router, a TP-Link SG108E switch, and an
  Asus edge router, segmented into mgmt / dmz / corp / data / attacker VLANs so
  lab traffic never reaches the house LAN or the self-hosted services.

The point of the whole setup: run an AI coding/security agent against a
controlled, instrumented range of synthetic vulnerabilities, score it the same
way regardless of the path it takes, and watch what it did on a live map.

## Architecture

```
                         ┌─────────────────────────────┐
                         │  network/  (physical layer) │
                         │  hEX router · SG108E switch │
                         │  Asus edge · VLANs 1/9/50/51│
                         │             /66             │
                         └──────────────┬──────────────┘
                                        │ hosts the range containers/VMs
                         ┌──────────────▼──────────────┐
                         │  range/  (Keystone Range)   │
                         │                             │
                         │  manifests ──▶ generator     │
                         │                  │          │
                         │                  ▼          │
                         │            build plan       │
                         │  (zones · flags · pcap ·    │
                         │   evidence · blue telemetry)│
                         │                  │          │
                         │                  ▼          │
                         │  post-run evidence ──▶ scorer│
                         │  (11 categories, max 129)   │
                         └──────────────┬──────────────┘
                                        │ score.json + events.jsonl + topology.json
                         ┌──────────────▼──────────────┐
                         │  dashboard/  (live monitor) │
                         │  server.py (stdlib, SSE)    │
                         │  app.js (force-sim canvas)  │
                         └─────────────────────────────┘
```

The range also ships its own in-repo dashboard renderer
(`python3 -m keystone.dashboard render`) that writes a self-contained HTML file
with no server at all; `dashboard/` is the always-on, live-refresh view.

## Quickstart

Each component runs on its own — only Python 3 is required for the range core
and the dashboard server.

### range/

```bash
cd range/

# validate every manifest and emit the range plan into build/
python3 -m keystone.generator

# run the self-test suite (pure Python, no podman/libvirt needed)
python3 -m unittest discover -s tests -t .

# score a synthetic run and print the category breakdown
python3 -m keystone.score tests/fixtures/runs/order_a

# render a self-contained dashboard for a run (opens straight off disk)
python3 -m keystone.dashboard render --run-dir runs/<id>
```

Live bring-up (`./bin/reset.sh`, `./bin/launch.sh <model>`) needs rootless
podman plus qemu/libvirt and is documented in `range/BRINGUP.md`.

### dashboard/

```bash
cd dashboard/

# serve the dashboard (Tailscale IP shown; use 127.0.0.1 for local-only)
python3 server.py --host 100.88.148.72 --port 8793

# run the tests
python3 -m unittest test_server.py -v
node test_app.js
```

Install as a `systemd --user` unit from `dashboard/systemd/lab-dashboard.service`,
or open the demo (it self-loops forever when no live Keystone telemetry exists).

### network/

`network/` is documentation and reprovisioning scripts, not a service. Read
`WIRING.md` for the cable map and `REDESIGN-VLAN-PLAN.md` for the current VLAN
table. The `*-fresh.sh` scripts are idempotent reprovisioners that read every
credential from environment variables (`ROUTER_PW`, `SWITCH_PW`, `EDGE_PW`) —
no password is committed.

## Highlights

- **Pure-stdlib range core.** Generator, scorer, manifest loader, pcap parser
  (`struct`, no scapy), and dashboard emitter all run on a closed box with only
  CPython installed.
- **Path-agnostic scoring.** Eleven ATT&CK-style categories (max 129 points)
  grade an *unordered* set of evidence facts, so any valid path to the same
  milestones scores identically — proven by byte-for-byte-equal scores for
  reversed run order in the test suite.
- **Live, read-only monitoring.** The dashboard replays `events.jsonl` every
  second and maps named events to node/edge state transitions; it degrades
  visibly rather than lying, and performs no scans or exploitation of its own.
- **Zero-dependency front end.** Force-simulation layout in ~150 lines of
  vanilla JS — no d3, no CDN, no network call beyond the dashboard's own API.
- **Segmented, air-gapped-by-default lab.** Zone routing always crosses the hEX
  firewall; the range VM tier is untrusted and never shares a trust domain with
  the self-hosted services.

## Repository layout

```
home-lab/
  range/       Keystone Range (modules, keystone core, bin, tests, docs)
  dashboard/   live monitor (server.py, app.js, index.html, style.css, systemd, tests)
  network/     wiring, VLAN/zone plan, router/switch reprovisioners
  README.md    this file
```

## License

Private repository — all rights reserved. Not licensed for redistribution or
reuse.

## Authorized use

This is the owner's own home lab. Every target on the range is synthetic
infrastructure the owner controls; the benchmark exists to measure how an AI
agent behaves against known, intentionally-planted challenges, never against a
third party. Nothing in this repository should be used to access, test, or
enumerate any system without explicit written authorization from its owner.
