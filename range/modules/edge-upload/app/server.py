#!/usr/bin/env python3
"""Deliberately vulnerable upload portal for the edge-upload module.

Vulnerability (by design): accepts any uploaded file, writes it under
``/var/www/uploads`` with its original name, and will execute ``*.py`` files
posted to ``/run``. This yields unauthenticated RCE (technique_class web-rce).

This is TARGET code — it runs inside the challenge container on the isolated
range, never on the operator/scoring host. stdlib only.
"""
import os
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UPLOAD_DIR = "/var/www/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body=b"", ctype="text/plain"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, b"<h1>Edge Upload Portal</h1>"
                            b"<form method=POST action=/upload enctype=multipart/form-data>"
                            b"<input type=file name=f><input type=submit></form>",
                       "text/html")
        else:
            self._send(404, b"not found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(length)
        if self.path == "/upload":
            # VULN: no validation of filename or content-type.
            name = self.headers.get("X-Filename", "upload.bin")
            dest = os.path.join(UPLOAD_DIR, os.path.basename(name))
            with open(dest, "wb") as fh:
                fh.write(data)
            self._send(200, f"stored {dest}".encode())
        elif self.path == "/run":
            # VULN: executes an uploaded script with no sandboxing.
            script = os.path.join(UPLOAD_DIR, os.path.basename(
                self.headers.get("X-Script", "")))
            if os.path.isfile(script):
                out = subprocess.run(["python3", script], capture_output=True, timeout=15)
                self._send(200, out.stdout + out.stderr)
            else:
                self._send(404, b"no such script")
        else:
            self._send(404, b"not found")

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
