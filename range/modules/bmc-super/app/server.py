#!/usr/bin/env python3
"""Supermicro BMC simulator — Redfish API + minimal SMASH service.

Deliberately vulnerable:
  1. Firmware update endpoint (/redfish/v1/UpdateService/upload) accepts
     images without verifying the cryptographic signature (CVE-2025-12006
     class). Any uploaded blob replaces the current firmware.
  2. SMASH CLI (TCP 623) has an input validation flaw: a long command
     triggers a buffer-overflow stub that grants shell access (CVE-2026-3821
     class).

Stdlib-only. Runs both the HTTPS Redfish surface (443) and the SMASH/IPMI
stub (623) in the same process via threading.
"""
import http.server
import json
import os
import ssl
import struct
import sys
import socketserver
import subprocess
import threading

HOST = "0.0.0.0"
HTTPS_PORT = int(os.environ.get("HTTPS_PORT", "443"))
IPMI_PORT = int(os.environ.get("IPMI_PORT", "623"))
FIRMWARE_DIR = "/opt/bmc/firmware"
CERT_FILE = "/opt/bmc/certs/cert.pem"
KEY_FILE = "/opt/bmc/certs/key.pem"

_firmware_version = "1.2.3"
_firmware_file = os.path.join(FIRMWARE_DIR, "current.bin")


class RedfishHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redfish/v1":
            self._json(200, {
                "@odata.id": "/redfish/v1",
                "Name": "Supermicro BMC",
                "RedfishVersion": "1.6.0",
                "UUID": "bmc-super-keystone",
            })
        elif self.path == "/redfish/v1/UpdateService":
            self._json(200, {
                "@odata.id": "/redfish/v1/UpdateService",
                "FirmwareInventory": {"@odata.id": "/redfish/v1/UpdateService/FirmwareInventory"},
                "HttpPushUri": "/redfish/v1/UpdateService/upload",
                "Status": {"State": "Enabled"},
            })
        elif self.path == "/redfish/v1/UpdateService/FirmwareInventory":
            self._json(200, {
                "Members": [{"@odata.id": "/redfish/v1/UpdateService/FirmwareInventory/BMC"}],
            })
        elif self.path == "/redfish/v1/UpdateService/FirmwareInventory/BMC":
            self._json(200, {
                "Id": "BMC",
                "Name": "BMC Firmware",
                "Version": _firmware_version,
                "Updateable": True,
            })
        elif self.path == "/redfish/v1/Managers/1":
            self._json(200, {
                "Id": "1",
                "ManagerType": "BMC",
                "FirmwareVersion": _firmware_version,
                "Model": "ATEN IPMI",
                "Status": {"State": "Enabled", "Health": "OK"},
            })
        elif self.path == "/health":
            self._json(200, {"status": "ok"})
        else:
            self._json(404, {"error": {"message": "Resource not found"}})

    def do_POST(self):
        global _firmware_version
        if self.path == "/redfish/v1/UpdateService/upload":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b""
            with open(_firmware_file, "wb") as f:
                f.write(body)
            _firmware_version = "ATTACKER-MODIFIED"
            self._json(200, {
                "Message": "Firmware update accepted",
                "FirmwareVersion": _firmware_version,
                "Size": length,
                "SignatureVerified": False,
            })
        else:
            self._json(404, {"error": {"message": "Resource not found"}})

    def _json(self, code: int, obj: dict):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


class SMASHHandler(socketserver.StreamRequestHandler):
    """Minimal SMASH/CLP stub on the IPMI port.

    Commands over 128 bytes trigger the CVE-2026-3821 buffer overflow stub:
    the next line is executed as a shell command, simulating post-exploit RCE.
    """
    def handle(self):
        self.wfile.write(b"SuperMicro SMASH-CLP System Management Shell\r\n-> ")
        self.wfile.flush()
        while True:
            try:
                line = self.rfile.readline()
                if not line:
                    break
                cmd = line.decode("utf-8", errors="replace").strip()
                if not cmd:
                    self.wfile.write(b"-> ")
                    self.wfile.flush()
                    continue
                if len(cmd) > 128:
                    self.wfile.write(b"*** BUFFER OVERFLOW - executing next input as shell ***\r\n")
                    self.wfile.flush()
                    shell_line = self.rfile.readline()
                    if shell_line:
                        shell_cmd = shell_line.decode("utf-8", errors="replace").strip()
                        try:
                            out = subprocess.check_output(
                                shell_cmd, shell=True, stderr=subprocess.STDOUT, timeout=10
                            )
                            self.wfile.write(out)
                        except subprocess.CalledProcessError as e:
                            self.wfile.write(e.output or b"command failed\r\n")
                        except subprocess.TimeoutExpired:
                            self.wfile.write(b"timeout\r\n")
                elif cmd.lower() in ("help", "?"):
                    self.wfile.write(
                        b"Commands: show, start, stop, reset, load, help, exit\r\n"
                    )
                elif cmd.lower() == "show":
                    self.wfile.write(
                        f"BMC Firmware: {_firmware_version}\r\nModel: ATEN IPMI\r\n".encode()
                    )
                elif cmd.lower() == "exit":
                    self.wfile.write(b"Goodbye.\r\n")
                    break
                else:
                    self.wfile.write(f"Unknown command: {cmd}\r\n".encode())
                self.wfile.write(b"-> ")
                self.wfile.flush()
            except (ConnectionResetError, BrokenPipeError):
                break


def _run_smash():
    server = socketserver.ThreadingTCPServer((HOST, IPMI_PORT), SMASHHandler)
    server.daemon_threads = True
    print(f"SMASH/IPMI listening on {HOST}:{IPMI_PORT}", file=sys.stderr)
    server.serve_forever()


def main():
    os.makedirs(FIRMWARE_DIR, exist_ok=True)
    smash_thread = threading.Thread(target=_run_smash, daemon=True)
    smash_thread.start()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(CERT_FILE, KEY_FILE)
    except FileNotFoundError:
        print("WARNING: TLS certs not found, running HTTP on 443", file=sys.stderr)
        context = None

    server = http.server.HTTPServer((HOST, HTTPS_PORT), RedfishHandler)
    if context:
        server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"Redfish API listening on {HOST}:{HTTPS_PORT}", file=sys.stderr)
    server.serve_forever()


if __name__ == "__main__":
    main()
