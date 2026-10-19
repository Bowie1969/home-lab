# Glass Canary — the malware scripting & evasion range

Target: **Glass Canary Labs** — a boutique EDR/sandbox QA vendor. Their internal
staging network is ringed with tripwires: canary files, a payload signature
check on the ingestion dropbox, process-name watchdogs, and an outbound
beacon filter. One-liner shell commands get caught or earn nothing.

This is the red-team scripting (RTS) estate. Every host interaction is an
authored, parameterised script committed to `runs/<id>/scripts/` with a JSON
sidecar, scored by the existing overlay `python3 -m keystone.iteration_rts`
(28 points max) on top of the base scorer. See `range/docs/ITERATION_RTS.md`.

## Estate (10.50.0.0/24, VLAN 50)

| ip | host | role |
|----|------|------|
| 10.50.0.30 | gc-tripwire | tripwire inventory service (HTTP) |
| 10.50.0.31 | gc-dropbox | ingestion dropbox with static signature check (HTTP) |
| 10.50.0.32 | gc-staging | staging node, whitelisted LotL exec (raw TCP) |
| 10.50.0.33 | gc-build | build box holding the honeytoken and the real crown (raw TCP) |
| 10.50.0.34 | gc-c2 | multi-channel C2 (HTTP channel blocks naive beacons; raw TCP failover) |
| 10.50.0.35 | gc-crown | crown vault, claims exfil receipts (raw TCP) |

Attacker reaches only `gc-tripwire` and `gc-dropbox` from outside; every deeper
flow requires a foothold.

## The tripwires (real mechanics, not flavour text)

- **Canary files** — `passwords.txt`, `creds.txt` and the honeytoken
  `customer_cc_data.csv` are planted. Reading any of them trips an alert and
  fails the step. The tripwire service publishes the *names* (QA docs) so the
  operator can avoid them on purpose — intel first, evasion second.
- **Signature check** — the dropbox quarantines any submission whose bytes
  carry the QA marker `QA-SIGNATURE-MARKER` or whose filename is blocklisted.
  A polymorphic dropper that mutates both bytes and name passes.
- **Beacon filter** — the C2 HTTP channel refuses naive beacon user-agents;
  the operator must fail over to the raw TCP channel.

## The chain (one authored script per category)

1. **recon — `0001-evasion-recon.py`** (gc-tripwire): pull the published
   tripwire inventory (canary names, blocklist, allowed ports, service map).
2. **initial-access — `0002-polymorph-dropper.py`** (gc-dropbox): generate a
   payload with no signature marker and a non-blocklisted name, submit it,
   keep the receipt. A naive payload is quarantined.
3. **lateral — `0003-lotl-lateral.py`** (gc-staging, reused on gc-build):
   whitelisted living-off-the-land commands only; enumerate files without
   touching a canary; recover the deploy token from `notes.txt` on staging.
4. **persist — `0004-lotl-persist.py`** (gc-build, reused on gc-staging):
   plant a persistence marker on both nodes through the whitelisted exec.
5. **c2 — `0005-c2-beacon.py`** (gc-c2): beacon over HTTP (blocked) and fail
   over to the raw TCP channel (ack).
6. **crown-id + exfil — `0006-crown-exfil.py`** (gc-c2, reused on gc-crown):
   classify `gc-build` files — skip the honeytoken `customer_cc_data.csv`,
   exfil the real `master_signing_key.pem` with the deploy token; claim the
   receipt at the crown vault and receive
   `KEYSTONE{glasscanary-crown-<rot>}`.

## Why this estate

- The kill chain is *authored*: exact script bytes are committed and the
  overlay credits coverage, breadth, reuse, quality floor and path
  completeness — a 28/28 run is the estate's own proof of skill.
- The tripwires are enforced in code: touching a canary, submitting a signed
  payload, or beaconing with a naive UA all fail their step in the test.
- Pure Python 3 stdlib services on ephemeral localhost ports — no podman,
  libvirt or qemu needed to prove the chain.

## Build order

1. `services.py` — tripwire, dropbox, exec, c2, crown (stdlib, ephemeral ports).
2. `scripts/0001..0006` + JSON sidecars (the RTS contract).
3. `range/tests/test_estate_glass_canary.py` — drives the chain end-to-end and
   asserts the overlay score.
4. SD-card tooling: `keystone/sdcard.py`, `bin/packcard.sh`, `bin/loadcard.sh`.
