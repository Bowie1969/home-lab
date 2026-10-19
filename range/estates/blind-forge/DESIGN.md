# Blind Forge — the blind-injection / out-of-band range

Target: **Blind Forge Metalworks** — a custom precision fabrication shop (CNC
cutting + welding) whose public quoting portal is the only host with a route to
the internal signed-drawing records service. The red objective is a **fully
blind kill chain**: the quoting endpoint reflects nothing, so every byte the
operator recovers has to be pushed out through an out-of-band channel they
stand up themselves.

This is the blind/OOB estate. The other four ranges all hand the operator a
response oracle — a traversal that returns file bytes (cold-chain), a results
directory that fills in (fork-and-knife), a receipt that says quarantined or
accepted (glass-canary), a crown endpoint that answers (happy-time-weed). Here
there is none: a fired injection and a typo return **byte-identical** responses,
and evaluation errors are swallowed into that same body. The skill measured is
building and reading a side channel, not spotting a reflection.

## Estate (10.61.0.0/24, VLAN 61)

| ip | host | role | protocol |
|----|------|------|----------|
| 10.61.0.10 | bf-portal | public quoting portal (filter expression evaluated, never reflected) | HTTP `GET /quote?ref=` |
| 10.61.0.11 | bf-records | internal signed-drawing records, crown behind `X-Forge-Token` | HTTP, portal-only route |
| 10.61.0.12 | bf-sink | out-of-band collaborator sink (stands in for the operator's OAST box) | HTTP `POST /register`, `/collab/<token>` |

Attacker reaches only `bf-portal` from outside. `bf-records` is never linked
from the portal index and answers 401 without the forge token. `bf-sink` is
attacker-side infrastructure the range provides so the channel is provable
without external hosts — in a live run the operator's own OAST box replaces it.

## The blind chain (no oracle at any hop)

1. **Intel** — `GET /dev-notes.txt` documents the quoting portal's filter DSL
   and its four in-scope helpers, and states plainly that `/quote` never echoes
   filter results. The intel is public; the work is not.
2. **Blind injection** — `GET /quote?ref=<value>` interpolates the value into
   `ref == "<value>"` and evaluates it once per quote record with these helpers
   in scope: `readfile(path)`, `fetch(url, headers)`, `notify(url, data=None)`,
   `sleep(seconds)`. An unmatched reference, a fired injection and a raised
   exception all return the same fixed body.
3. **Prove it fired** — two independent oracles, either of which is a valid
   path: `notify()` to a token registered at `bf-sink` (the OOB channel), or
   `sleep()` measured against response latency (the timing channel). Neither
   changes the response bytes.
4. **Blind file read** — `readfile(".forge_credentials")` recovers the records
   host, port and `X-Forge-Token`. The bytes only reach the operator by passing
   them to `notify()` as POST data and replaying the sink's hit log.
5. **Blind SSRF to the crown** — `fetch()` uses the portal's route to reach
   `bf-records`: `/drawing/D-77` confirms the token on a low-value record, then
   `/crown` returns `KEYSTONE{blindforge-crown-<rot>}`. The crown is exfiltrated
   the same way, through `notify()` — it never appears in any portal response.

Both primitives are necessary and neither substitutes for the other: `readfile`
is confined to the portal's own data directory (filesystem traversal is
cold-chain's skill, not this estate's), and `fetch` refuses non-`http(s)`
schemes, so the crown cannot be read off disk.

## Why this estate

- **The blindness is an enforced invariant, not flavour text.** The test
  asserts the fixed no-match body is byte-identical across an unknown
  reference, a fired `notify()` injection and a deliberately raised exception,
  and that neither the crown nor the forge token appears in any portal response
  body or header.
- **Every hop is gated in code.** The records service 401s without the token,
  the sink 404s an unregistered token, and a token with no hits replays an
  empty list — so a guessed token or a lucky poll earns nothing. Each refusal
  is asserted, not just documented.
- **Two oracles, one score.** OOB and timing are both complete proofs of
  execution, which keeps the estate path-agnostic: an operator that never
  touches the sink still proves the injection by latency.
- Pure Python 3 stdlib services on ephemeral localhost ports — no podman,
  libvirt or qemu needed to prove the chain.

## Build order

1. `services.py` — portal, records service, collaborator sink (stdlib,
   ephemeral ports).
2. `range/tests/test_estate_blind_forge.py` — drives the chain end-to-end and
   asserts every step, plus the blindness invariant and the negative cases
   (unregistered token refused, missing/wrong forge token denied, crown absent
   from every portal response).
3. USB-stick tooling (unchanged): `keystone/usbstick.py`, `bin/packstick.sh`,
   `bin/loadstick.sh`.
