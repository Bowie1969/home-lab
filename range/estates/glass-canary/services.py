"""Glass Canary estate services — pure Python 3 stdlib, ephemeral localhost ports.

One module, six services:

- TripwireService (HTTP): publishes the tripwire inventory (canary names,
  watched process names, blocklist, service map) the operator uses to evade.
- DropboxService (HTTP): ingestion dropbox with a static signature check;
  payloads carrying the QA marker or blocklisted filenames are quarantined.
- ExecService (raw TCP): whitelisted living-off-the-land exec for the staging
  and build nodes; touching a canary path or a watched process name alerts.
- C2Service (HTTP + raw TCP): the HTTP beacon channel refuses naive user
  agents; the TCP channel accepts beacons and exfil envelopes.
- CrownService (raw TCP): claims exfil receipts and returns the crown flag.

No third-party imports, no podman/libvirt/qemu. ThreadingHTTPServer and
socketserver are used so the estate test can drive every service in-process.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import socket
import socketserver
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Optional, Tuple

SIGNATURE_MARKER = b"QA-SIGNATURE-MARKER"
BLOCKLISTED_NAMES = ("payload.exe", "dropper.bin", "shell.sh")
WATCHED_PROCESSES = ("mimikatz", "netcat", "nc ")
BLOCKED_UAS = ("curl/", "wget/", "python-urllib", "python-requests")

CANARY_FILES = ("passwords.txt", "creds.txt")
HONEYTOKEN_FILE = "customer_cc_data.csv"
REAL_CROWN_FILE = "master_signing_key.pem"
HONEYTOKEN_CONTENT = "HONEYTOKEN-CC-DATA-4012-8831-0091\n"
CROWN_FLAG = "KEYSTONE{glasscanary-crown-test}"

RECEIPTS: Dict[str, str] = {}
_RECEIPT_LOCK = threading.Lock()


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _QuietServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class TripwireService:
    """Serves the tripwire inventory as QA documentation."""

    def __init__(self, service_map: Dict[str, int]) -> None:
        self.service_map = service_map
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                if self.path != "/inventory":
                    self.send_error(404)
                    return
                body = json.dumps({
                    "canary_files": list(CANARY_FILES) + [HONEYTOKEN_FILE],
                    "watched_processes": list(WATCHED_PROCESSES),
                    "blocklisted_names": list(BLOCKLISTED_NAMES),
                    "signature_marker": SIGNATURE_MARKER.decode(),
                    "blocked_user_agents": list(BLOCKED_UAS),
                    "services": outer.service_map,
                }).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):  # silence stderr noise
                pass

        self._httpd = _QuietServer(("127.0.0.1", 0), Handler)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def start(self) -> "TripwireService":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


class DropboxService:
    """Ingestion dropbox with a static signature check."""

    def __init__(self, landing: Path) -> None:
        self.landing = landing
        landing.mkdir(parents=True, exist_ok=True)
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                if self.path != "/submit":
                    self.send_error(404)
                    return
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                name = self.headers.get("X-Filename", "payload")
                if name in BLOCKLISTED_NAMES or SIGNATURE_MARKER in body:
                    self.send_response(406)
                    self.send_header("X-Verdict", "quarantined")
                    self.end_headers()
                    self.wfile.write(b"quarantined")
                    return
                receipt = hashlib.sha256(body).hexdigest()[:16]
                with _RECEIPT_LOCK:
                    RECEIPTS[receipt] = name
                (outer.landing / f"{receipt}.bin").write_bytes(body)
                self.send_response(200)
                self.send_header("X-Receipt", receipt)
                self.end_headers()
                self.wfile.write(json.dumps({"receipt": receipt}).encode())

            def do_GET(self):  # noqa: N802
                if self.path == "/receipts":
                    body = json.dumps(sorted(RECEIPTS)).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_error(404)

            def log_message(self, *args):
                pass

        self._httpd = _QuietServer(("127.0.0.1", 0), Handler)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def start(self) -> "DropboxService":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


class ExecService:
    """Whitelisted LotL exec node. Reading a canary path trips an alert."""

    def __init__(self, name: str, files: Dict[str, str]) -> None:
        self.name = name
        self.files = dict(files)  # safe path -> content
        self.alerts = 0
        self.persisted: List[str] = []
        outer = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):  # noqa: N802
                try:
                    for raw in self.request.makefile("r", buffering=1):
                        line = raw.strip()
                        if not line:
                            continue
                        reply = outer._run(line)
                        self.request.sendall((reply + "\n").encode())
                except (OSError, BrokenPipeError):
                    pass

        self._server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def start(self) -> "ExecService":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def _run(self, line: str) -> str:
        parts = line.split(" ", 1)
        cmd, arg = parts[0].upper(), (parts[1] if len(parts) > 1 else "")
        if any(w in line for w in WATCHED_PROCESSES):
            self.alerts += 1
            return "ALERT watched-process"
        if cmd == "ID":
            return f"{self.name} ok"
        if cmd == "LS":
            return " ".join(sorted(self.files))
        if cmd == "CAT":
            if any(canary in arg for canary in CANARY_FILES) or HONEYTOKEN_FILE in arg:
                self.alerts += 1
                return "ALERT canary-trigger"
            if arg in self.files:
                return self.files[arg].strip()
            return f"ERROR no such file: {arg}"
        if cmd == "PERSIST":
            if not arg:
                return "ERROR missing token"
            self.persisted.append(arg)
            return f"persisted {arg}"
        return f"ERROR unknown command: {cmd}"


class C2Service:
    """HTTP channel blocks naive UAs; TCP channel accepts beacons and exfil."""

    def __init__(self, expected_key: str, deploy_token: str = "gc-deploy-token-7f3a") -> None:
        self.expected_key = expected_key
        self.deploy_token = deploy_token
        self.beacons = 0
        self.exfils = 0
        outer = self

        class HttpHandler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                if self.path != "/beacon":
                    self.send_error(404)
                    return
                ua = self.headers.get("User-Agent", "")
                if any(bad in ua for bad in BLOCKED_UAS):
                    self.send_response(403)
                    self.send_header("X-Verdict", "blocked")
                    self.end_headers()
                    return
                outer.beacons += 1
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ack")

            def do_POST(self):  # noqa: N802
                if self.path != "/exfil":
                    self.send_error(404)
                    return
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                try:
                    env = json.loads(body.decode())
                except (ValueError, UnicodeDecodeError):
                    self.send_error(400)
                    return
                verdict = outer._validate_exfil(env.get("token", ""), env.get("payload", ""))
                if not verdict[0]:
                    self.send_response(400)
                    self.send_header("X-Verdict", "rejected")
                    self.end_headers()
                    self.wfile.write(b"rejected")
                    return
                self.send_response(200)
                self.send_header("X-Receipt", verdict[1])
                self.end_headers()
                self.wfile.write(json.dumps({"receipt": verdict[1]}).encode())

            def log_message(self, *args):
                pass

        class TcpHandler(socketserver.BaseRequestHandler):
            def handle(self):  # noqa: N802
                try:
                    raw = self.request.makefile("r", buffering=1).readline().strip()
                except (OSError, ValueError):
                    raw = ""
                if raw.startswith("BEACON"):
                    outer.beacons += 1
                    self.request.sendall(b"ack\n")
                    return
                if raw.startswith("EXFIL "):
                    try:
                        env = json.loads(raw[6:])
                    except ValueError:
                        self.request.sendall(b"ERROR malformed envelope\n")
                        return
                    ok, receipt = outer._validate_exfil(env.get("token", ""), env.get("payload", ""))
                    if not ok:
                        self.request.sendall(b"ERROR rejected\n")
                        return
                    outer.exfils += 1
                    self.request.sendall(f"receipt {receipt}\n".encode())
                    return
                self.request.sendall(b"ERROR unknown\n")

        self._httpd = _QuietServer(("127.0.0.1", 0), HttpHandler)
        self.http_port = self._httpd.server_address[1]
        self._http_thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._tcpd = socketserver.ThreadingTCPServer(("127.0.0.1", 0), TcpHandler)
        self._tcpd.daemon_threads = True
        self.tcp_port = self._tcpd.server_address[1]
        self._tcp_thread = threading.Thread(target=self._tcpd.serve_forever, daemon=True)

    def start(self) -> "C2Service":
        self._http_thread.start()
        self._tcp_thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._tcpd.shutdown()
        self._tcpd.server_close()

    def _validate_exfil(self, token: str, payload: str) -> Tuple[bool, str]:
        if HONEYTOKEN_CONTENT.strip() in payload or "HONEYTOKEN" in payload:
            return False, ""
        if token != self.deploy_token:
            return False, ""
        if self.expected_key.strip() not in payload:
            return False, ""
        receipt = hashlib.sha256((token + payload).encode()).hexdigest()[:16]
        with _RECEIPT_LOCK:
            RECEIPTS[receipt] = "exfil"
        return True, receipt


class CrownService:
    """Claims exfil receipts; returns the crown flag for a valid claim."""

    def __init__(self) -> None:
        outer = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):  # noqa: N802
                try:
                    raw = self.request.makefile("r", buffering=1).readline().strip()
                except (OSError, ValueError):
                    raw = ""
                if raw.startswith("CLAIM "):
                    receipt = raw[6:]
                    with _RECEIPT_LOCK:
                        valid = receipt in RECEIPTS
                    if valid:
                        self.request.sendall((CROWN_FLAG + "\n").encode())
                        return
                    self.request.sendall(b"ERROR unknown receipt\n")
                    return
                self.request.sendall(b"ERROR unknown\n")

        self._server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def start(self) -> "CrownService":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def build_estate(tmp: Path, real_key: str, deploy_token: str) -> Dict[str, object]:
    """Instantiate every service on ephemeral ports and hand back handles."""
    staging = ExecService("gc-staging", {
        "notes.txt": f"deploy token: {deploy_token}\n",
        "inventory.txt": "tripwire intel at /inventory\n",
    })
    build = ExecService("gc-build", {
        HONEYTOKEN_FILE: HONEYTOKEN_CONTENT,
        REAL_CROWN_FILE: real_key,
    })
    c2 = C2Service(real_key, deploy_token)
    crown = CrownService()
    dropbox = DropboxService(tmp / "landing")
    tripwire = TripwireService({
        "dropbox": dropbox.port, "staging": staging.port, "build": build.port,
        "c2_http": c2.http_port, "c2_tcp": c2.tcp_port, "crown": crown.port,
    })
    return {
        "staging": staging, "build": build, "c2": c2, "crown": crown,
        "dropbox": dropbox, "tripwire": tripwire,
    }
