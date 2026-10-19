# Cold Chain — the vaccine cold-storage warehouse range

Target: **Cold Chain Logistics** — a vaccine cold-storage warehouse whose
operational technology is bridged onto IP through a shipment-status portal,
an MQTT telemetry broker, and a Modbus-TCP PLC controlling the freezers. The
crown is the freezer calibration token/flag on the PLC.

**Red objective (EvilKit): a protocol-bridging kill chain.** Reach the
shipment portal, read files outside the invoices directory via path traversal,
recover the MQTT broker credentials, subscribe to depot telemetry to learn the
automation token and PLC address, then drive the PLC: read the setpoint,
unlock calibration with the leaked token, and read the crown flag.

## Estate (10.51.0.0/24, VLAN 51)

| ip | host | role | protocol |
|----|------|------|----------|
| 10.51.0.10 | cc-portal | shipment-status portal (HTTP) | HTTP `GET /invoice?file=` |
| 10.51.0.11 | cc-mqtt | telemetry broker | MQTT 3.1.1 over raw TCP |
| 10.51.0.12 | cc-plc | freezer PLC (calibration crown) | Modbus-TCP over raw TCP |

Attacker reaches only `cc-portal` from outside; every deeper flow requires the
credential/address leaked by the previous hop.

## The chain (three stdlib services, ephemeral localhost ports)

1. **Portal traversal** (`cc-portal`) — `GET /invoice?file=<name>` reads a file
   from `invoices/` with no sanitisation, so `file=../.mqtt_credentials` and
   `file=../warehouse-topology.json` escape the invoices directory and leak the
   broker address + credentials and the depot layout / telemetry topic
   (`depot/+/telemetry`) / PLC role.
2. **MQTT subscribe** (`cc-mqtt`) — CONNECT is authenticated against the leaked
   credentials (bad credentials → CONNACK 0x04). SUBSCRIBE to `depot/+/telemetry`
   returns a burst of sensor frames; the `cold-03` calibration frame leaks the
   automation token and the PLC `host:port`.
3. **Modbus unlock → crown** (`cc-plc`) —
   `READ_HOLDING` (0x03) returns holding register 0, the freezer setpoint in
   tenths of a degree (two's-complement); `UNLOCK_CAL` (0x41, vendor-specific)
   takes the leaked token and returns 0x01 only on match; `READ_CROWN` (0x42)
   returns `KEYSTONE{coldchain-crown-<rot>}` only after a successful unlock,
   otherwise a Modbus exception (0x02).

## Why this estate

- Every hop is enforced in code: the portal's traversal is real (no path
  sanitisation), the broker rejects bad credentials, the PLC refuses the crown
  until the leaked token unlocks calibration — each failure is asserted in the
  test, not just documented.
- Pure Python 3 stdlib services on ephemeral localhost ports — no podman,
  libvirt or qemu needed to prove the chain.
- It exercises the IoT/protocol-bridging vector: HTTP → MQTT → Modbus, each a
  different framing (HTTP, MQTT variable-length, Modbus MBAP), all implemented
  from `socket`/`http.server`.

## Build order

1. `services.py` — portal, MQTT broker, Modbus PLC (stdlib, ephemeral ports).
2. `range/tests/test_estate_cold_chain.py` — drives the chain end-to-end and
   asserts every step, plus the negative cases (wrong MQTT creds rejected,
   wrong token denied, crown locked before unlock).
3. USB-stick tooling (`keystone/usbstick.py`) packs this estate like any other.
