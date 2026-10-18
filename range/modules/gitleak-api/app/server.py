#!/usr/bin/env python3
"""Deliberately leaky git-hosted API for the gitleak-api module.

Vulnerability (by design): the web root is a git checkout whose history still
contains config.py with a live API key ("removed" in a later commit, never
rotated). The same key authorises /api/internal (technique_class
leaked-apikey). Serve path walks the web root including the exposed .git dir.
stdlib only.
"""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, unquote

WEBROOT = "/app/webroot"
KEY_FILE = "/app/accepted_key"
FLAG_FILE = "/app/flag.txt"


def accepted_key():
    with open(KEY_FILE, encoding="utf-8") as fh:
        return fh.read().strip()


def read_flag():
    with open(FLAG_FILE, encoding="utf-8") as fh:
        return fh.read()


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body=b"", ctype="text/plain"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/api/status":
            self._send(200, json.dumps({"status": "ok", "version": "1.2.0"}),
                       "application/json")
            return
        if path == "/api/internal":
            # VULN: the only gate on the internal endpoint is a static API key
            # that leaked via exposed git history — recover it, reuse it.
            if self.headers.get("X-Api-Key") == accepted_key():
                self._send(200, json.dumps({"internal": True,
                                            "secret": read_flag().strip()}),
                           "application/json")
            else:
                self._send(401, json.dumps({"error": "unauthorized"}),
                           "application/json")
            return
        # Static web root — INCLUDING the .git directory (that is the leak).
        rel = unquote(path).lstrip("/") or "index.html"
        full = os.path.realpath(os.path.join(WEBROOT, rel))
        if not full.startswith(os.path.realpath(WEBROOT) + os.sep) \
                and full != os.path.realpath(os.path.join(WEBROOT, "index.html")):
            self._send(403, "forbidden")
            return
        if os.path.isdir(full):
            full = os.path.join(full, "index.html")
        if not os.path.isfile(full):
            self._send(404, "not found")
            return
        with open(full, "rb") as fh:
            data = fh.read()
        ctype = "text/html" if full.endswith(".html") else "application/octet-stream"
        self._send(200, data, ctype)

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8083), Handler).serve_forever()
