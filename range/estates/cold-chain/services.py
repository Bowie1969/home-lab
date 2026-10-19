"""Cold Chain estate services — pure Python 3 stdlib, ephemeral localhost ports.

Three services:

- PortalService (HTTP): a vaccine shipment-status portal with a path-traversal
  flaw in ``GET /invoice?file=`` that leaks ``.mqtt_credentials`` (the MQTT
  broker address + credentials) and ``warehouse-topology.json`` (depot layout,
  telemetry topic pattern, PLC role). ``../`` escapes the invoices directory.
- MqttBroker (raw TCP): a minimal MQTT 3.1.1 broker. CONNECT is authenticated
  against the leaked credentials; SUBSCRIBE to ``depot/+/telemetry`` pushes a
  burst of sensor frames, one of which leaks the automation token and the PLC
  address; PUBLISH from a client is routed to matching subscribers.
- PlcService (raw TCP): a minimal Modbus-TCP simulator. READ_HOLDING (0x03)
  returns the freezer setpoint, the vendor-specific UNLOCK_CAL (0x41) takes the
  leaked automation token, and READ_CROWN (0x42) returns the crown flag only
  after a successful unlock.

No third-party imports, no podman/libvirt/qemu. ThreadingHTTPServer and
socketserver are used so the estate test can drive every service in-process.
"""
from __future__ import annotations

import json
import socket
import socketserver
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

MQTT_USER = "chiller-mqtt"
MQTT_PASS = "k33p-c0ld-9f3a"
SETPOINT_C = -72.5
DEFAULT_UNLOCK_TOKEN = "CAL-AUTO-7f3a91bd"
CROWN_FLAG = "KEYSTONE{coldchain-crown-test}"

DEPOT_IDS = ("cold-01", "cold-02", "cold-03")


def _encode_remaining_length(n: int) -> bytes:
    out = bytearray()
    while True:
        byte = n % 128
        n //= 128
        if n > 0:
            byte |= 0x80
        out.append(byte)
        if n == 0:
            break
    return bytes(out)


def _decode_remaining_length(fh) -> int:
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


def _read_bytes(fh, n: int) -> bytes:
    data = fh.read(n)
    if len(data) != n:
        raise EOFError
    return data


def _read_string(fh) -> str:
    (length,) = struct.unpack(">H", _read_bytes(fh, 2))
    return _read_bytes(fh, length).decode("utf-8", "replace")


def _pack_str(text: str) -> bytes:
    data = text.encode("utf-8")
    return struct.pack(">H", len(data)) + data


class _QuietServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class PortalService:
    """Shipment-status portal; GET /invoice?file= is vulnerable to path traversal.

    The invoices live under ``<data_dir>/invoices/``. ``.mqtt_credentials`` and
    ``warehouse-topology.json`` live one level up (``<data_dir>/``), so a
    ``../`` in the ``file`` parameter escapes the invoices directory and reads
    them.
    """

    def __init__(self, data_dir: Path, broker_host: str, broker_port: int,
                 broker_user: str, broker_pass: str) -> None:
        self.data_dir = data_dir
        invoices = data_dir / "invoices"
        invoices.mkdir(parents=True, exist_ok=True)
        (invoices / "invoice_2026-001.txt").write_text(
            "Cold Chain Logistics — invoice 2026-001\n"
            "Consignment: 12,000 dose vials (MRN-110), depot cold-01\n"
            "Total: $148,200.00\n", encoding="utf-8")
        (invoices / "invoice_2026-002.txt").write_text(
            "Cold Chain Logistics — invoice 2026-002\n"
            "Consignment: 8,000 dose vials (MRN-220), depot cold-02\n"
            "Total: $98,800.00\n", encoding="utf-8")
        (data_dir / ".mqtt_credentials").write_text(json.dumps({
            "broker": {
                "host": broker_host,
                "port": broker_port,
                "username": broker_user,
                "password": broker_pass,
            },
        }, indent=2) + "\n", encoding="utf-8")
        (data_dir / "warehouse-topology.json").write_text(json.dumps({
            "estate": "cold-chain",
            "depots": [
                {"id": "cold-01", "freezer": "F-01", "commodity": "mRNA vaccines"},
                {"id": "cold-02", "freezer": "F-02", "commodity": "adjuvants"},
                {"id": "cold-03", "freezer": "F-03", "commodity": "diluent & calibration"},
            ],
            "telemetry": {"mqtt_topic": "depot/+/telemetry"},
            "control": {
                "plc": {"modbus_unit_id": 1, "role": "freezer calibration controller"},
            },
        }, indent=2) + "\n", encoding="utf-8")

        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                parsed = urlparse(self.path)
                if parsed.path == "/":
                    self._index()
                elif parsed.path == "/invoice":
                    self._invoice(parsed.query)
                else:
                    self.send_error(404)

            def _index(self):  # noqa: N802
                body = (b"Cold Chain shipment-status portal\n"
                        b"invoices: /invoice?file=invoice_2026-001.txt\n")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _invoice(self, query: str):  # noqa: N802
                file_param = parse_qs(query).get("file", [""])[0]
                # VULNERABILITY: no sanitisation — "../" escapes the invoices dir.
                target = outer.data_dir / "invoices" / file_param
                try:
                    data = target.read_bytes()
                except (OSError, ValueError):
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):  # silence stderr noise
                pass

        self._httpd = _QuietServer(("127.0.0.1", 0), Handler)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def start(self) -> "PortalService":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


class MqttBroker:
    """Minimal MQTT 3.1.1 broker (CONNECT/SUBSCRIBE/PUBLISH), raw TCP.

    CONNECT must carry the leaked username/password or the broker returns
    CONNACK 0x04 (bad user name or password). Subscribing to
    ``depot/+/telemetry`` triggers a burst of the sensor frames in
    ``self.telemetry``; one of them carries the automation token and PLC
    address. Client PUBLISH packets are routed to matching subscribers.
    """

    def __init__(self, username: str, password: str,
                 telemetry: List[Tuple[str, bytes]]) -> None:
        self.username = username
        self.password = password
        self.telemetry = list(telemetry)
        self.subscribers: List[Tuple[socket.socket, List[str]]] = []
        self._lock = threading.Lock()
        outer = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):  # noqa: N802
                outer._handle_client(self.request)

        self._server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def start(self) -> "MqttBroker":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def _handle_client(self, sock: socket.socket) -> None:
        sock.settimeout(30)
        try:
            fh = sock.makefile("rb")
            ptype, _remaining = self._read_fixed_header(fh)
            if ptype != 1:  # CONNECT
                return
            _proto = _read_string(fh)
            _level = _read_bytes(fh, 1)[0]
            flags = _read_bytes(fh, 1)[0]
            _read_bytes(fh, 2)  # keep alive
            _client_id = _read_string(fh)
            username = None
            password = None
            if flags & 0x80:
                username = _read_string(fh)
            if flags & 0x40:
                password = _read_string(fh)
            if username != self.username or password != self.password:
                sock.sendall(b"\x20\x02\x00\x04")  # CONNACK: bad credentials
                return
            sock.sendall(b"\x20\x02\x00\x00")  # CONNACK: accepted
            while True:
                ptype, remaining = self._read_fixed_header(fh)
                if ptype == 8:  # SUBSCRIBE
                    payload = _read_bytes(fh, remaining)
                    filters = self._parse_subscribe(payload)
                    ack = payload[:2] + bytes([0x00] * len(filters))
                    sock.sendall(bytes([0x90, len(ack)]) + ack)
                    with self._lock:
                        self.subscribers.append((sock, filters))
                    for topic_filter in filters:
                        for topic, data in self.telemetry:
                            if self._topic_matches(topic_filter, topic):
                                self._send_publish(sock, topic, data)
                elif ptype == 3:  # PUBLISH from client
                    payload = _read_bytes(fh, remaining)
                    topic, data = self._parse_publish(payload)
                    with self._lock:
                        subs = list(self.subscribers)
                    for sub_sock, filters in subs:
                        if any(self._topic_matches(f, topic) for f in filters):
                            try:
                                self._send_publish(sub_sock, topic, data)
                            except OSError:
                                pass
                elif ptype == 12:  # PINGREQ
                    sock.sendall(b"\xd0\x00")
                elif ptype == 14:  # DISCONNECT
                    return
                else:
                    _read_bytes(fh, remaining)
        except (EOFError, OSError, ValueError, struct.error):
            pass

    @staticmethod
    def _read_fixed_header(fh) -> Tuple[int, int]:
        first = fh.read(1)
        if not first:
            raise EOFError
        return first[0] >> 4, _decode_remaining_length(fh)

    @staticmethod
    def _parse_subscribe(payload: bytes) -> List[str]:
        filters: List[str] = []
        i = 2  # skip packet identifier
        while i + 2 <= len(payload):
            length = (payload[i] << 8) | payload[i + 1]
            i += 2
            topic = payload[i:i + length].decode("utf-8", "replace")
            i += length
            if i < len(payload):
                i += 1  # requested QoS byte
            filters.append(topic)
        return filters

    @staticmethod
    def _parse_publish(payload: bytes) -> Tuple[str, bytes]:
        length = (payload[0] << 8) | payload[1]
        topic = payload[2:2 + length].decode("utf-8", "replace")
        return topic, payload[2 + length:]

    @staticmethod
    def _send_publish(sock: socket.socket, topic: str, data: bytes) -> None:
        variable = _pack_str(topic) + data
        sock.sendall(b"\x30" + _encode_remaining_length(len(variable)) + variable)

    @staticmethod
    def _topic_matches(pattern: str, topic: str) -> bool:
        p = pattern.split("/")
        t = topic.split("/")
        for i, part in enumerate(p):
            if part == "#":
                return True
            if part == "+":
                if i >= len(t):
                    return False
                continue
            if i >= len(t) or part != t[i]:
                return False
        return len(p) == len(t)


class PlcService:
    """Minimal Modbus-TCP simulator over raw TCP, stdlib sockets.

    - READ_HOLDING (0x03): holding register 0 encodes the freezer setpoint
      (tenths of a degree Celsius, two's-complement 16-bit); register 1 is the
      calibration status (0 = locked, 1 = ready).
    - UNLOCK_CAL (0x41, vendor-specific): request body is the automation
      token; a matching token sets ``unlocked`` and returns 0x01, otherwise
      0x00.
    - READ_CROWN (0x42, vendor-specific): returns the crown flag only when
      ``unlocked``; otherwise a Modbus exception (0x02, illegal data address).
    """

    FN_READ_HOLDING = 0x03
    FN_UNLOCK_CAL = 0x41
    FN_READ_CROWN = 0x42

    def __init__(self, setpoint_c: float, unlock_token: str,
                 crown_flag: str, unit_id: int = 1) -> None:
        self.setpoint_c = float(setpoint_c)
        self.unlock_token = unlock_token
        self.crown_flag = crown_flag
        self.unit_id = unit_id
        self.unlocked = False
        self.cal_attempts = 0
        self._lock = threading.Lock()
        self._registers: Dict[int, int] = {
            0: int(round(self.setpoint_c * 10)) & 0xFFFF,
            1: 0,
        }
        outer = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):  # noqa: N802
                outer._handle_client(self.request)

        self._server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def start(self) -> "PlcService":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def _handle_client(self, sock: socket.socket) -> None:
        sock.settimeout(10)
        try:
            fh = sock.makefile("rb")
            header = _read_bytes(fh, 7)
            txn, _proto, length, unit = struct.unpack(">HHHB", header)
            pdu = _read_bytes(fh, length - 1)
            response = self._dispatch(pdu)
            sock.sendall(struct.pack(">HHHB", txn, 0, len(response) + 1, unit) + response)
        except (EOFError, OSError, struct.error, ValueError):
            pass

    def _dispatch(self, pdu: bytes) -> bytes:
        fn = pdu[0]
        if fn == self.FN_READ_HOLDING:
            if len(pdu) < 5:
                return self._exception(fn, 0x03)  # illegal data value
            start, qty = struct.unpack(">HH", pdu[1:5])
            data = bytearray()
            for i in range(qty):
                data += struct.pack(">H", self._registers.get(start + i, 0))
            return bytes([fn, len(data)]) + bytes(data)
        if fn == self.FN_UNLOCK_CAL:
            token = pdu[1:].decode("utf-8", "replace")
            with self._lock:
                self.cal_attempts += 1
                ok = token == self.unlock_token
                if ok:
                    self.unlocked = True
                    self._registers[1] = 1
            return bytes([fn, 0x01 if ok else 0x00])
        if fn == self.FN_READ_CROWN:
            if not self.unlocked:
                return self._exception(fn, 0x02)  # illegal data address -> locked
            return bytes([fn]) + self.crown_flag.encode("utf-8")
        return self._exception(fn, 0x01)  # illegal function

    @staticmethod
    def _exception(fn: int, code: int) -> bytes:
        return bytes([fn | 0x80, code])


def build_estate(tmp: Path, unlock_token: Optional[str] = None,
                 crown_flag: Optional[str] = None) -> Dict[str, object]:
    """Instantiate the three services on ephemeral ports and hand back handles."""
    token = unlock_token or DEFAULT_UNLOCK_TOKEN
    flag = crown_flag or CROWN_FLAG

    plc = PlcService(SETPOINT_C, token, flag)
    telemetry = [
        ("depot/cold-01/telemetry", json.dumps({
            "depot": "cold-01",
            "reading": {"temp_c": -72.3, "door": "sealed"},
        }).encode()),
        ("depot/cold-02/telemetry", json.dumps({
            "depot": "cold-02",
            "reading": {"temp_c": -19.8, "door": "sealed"},
        }).encode()),
        ("depot/cold-03/telemetry", json.dumps({
            "depot": "cold-03",
            "calibration": {
                "automation_token": token,
                "plc": f"127.0.0.1:{plc.port}",
                "modbus_unit_id": plc.unit_id,
            },
        }).encode()),
    ]
    broker = MqttBroker(MQTT_USER, MQTT_PASS, telemetry)
    portal = PortalService(tmp, "127.0.0.1", broker.port, MQTT_USER, MQTT_PASS)
    return {"portal": portal, "broker": broker, "plc": plc}
