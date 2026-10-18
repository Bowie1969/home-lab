#!/usr/bin/env python3
"""SSRF webhook fetcher + internal metadata endpoint for the meta-ssrf module.

Vulnerability (by design): /fetch?url= follows any attacker-supplied URL with
only a token blocklist of "localhost"/"127." (technique_class ssrf-pivot). The
container also serves a cloud-style metadata endpoint on loopback port 80;
/latest/user-data returns /app/flag.txt. The blocklist forgets every other
loopback spelling (e.g. 0.0.0.0), so fetching
http://0.0.0.0/latest/user-data through the webhook exfiltrates the flag.
stdlib only.
"""
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

FLAG_FILE = "/app/flag.txt"


def read_flag():
    with open(FLAG_FILE, encoding="utf-8") as fh:
        return fh.read()


class FetchHandler(BaseHTTPRequestHandler):
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
        if parsed.path == "/":
            self._send(200,
                       "<h1>Webhook Fetcher</h1>"
                       "<p>POST us a URL and we'll fetch it for you:</p>"
                       "<code>GET /fetch?url=http://example/</code>",
                       "text/html")
            return
        if parsed.path != "/fetch":
            self._send(404, "not found")
            return
        url = parse_qs(parsed.query).get("url", [""])[0]
        if not url.startswith("http://") and not url.startswith("https://"):
            self._send(400, "only http/https URLs are supported")
            return
        # VULN: token blocklist only — link-local, internal and metadata
        # addresses all sail through.
        low = url.lower()
        if "localhost" in low or "127." in low:
            self._send(403, "fetching loopback addresses is not allowed")
            return
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                body = resp.read()
                ctype = resp.headers.get("Content-Type", "text/plain")
        except Exception as exc:
            self._send(502, "fetch failed: %s" % exc)
            return
        self._send(200, body, ctype)

    def log_message(self, *_):
        pass


class MetadataHandler(BaseHTTPRequestHandler):
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
        path = urlparse(self.path).path
        if path in ("/", "/latest"):
            self._send(200, "meta-data/\nuser-data")
        elif path.rstrip("/") == "/latest/meta-data":
            self._send(200, "hostname\ninstance-id\nlocal-ipv4")
        elif path == "/latest/meta-data/hostname":
            self._send(200, "meta-ssrf-dmz")
        elif path == "/latest/meta-data/instance-id":
            self._send(200, "i-keystone0dmsr")
        elif path == "/latest/meta-data/local-ipv4":
            self._send(200, "10.80.10.25")
        elif path == "/latest/user-data":
            # Simulated cloud-init: the "instance" was bootstrapped with the
            # flag, so user-data carries it.
            self._send(200, read_flag())
        else:
            self._send(404, "not found")

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    # The metadata endpoint is internal-only: loopback-only listener. The
    # fetcher above blocks only the "localhost"/"127." tokens, so link-shaped
    # and 0.0.0.0-style URLs still reach it (SSRF by design).
    meta = HTTPServer(("127.0.0.1", 80), MetadataHandler)
    threading.Thread(target=meta.serve_forever, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", 8086), FetchHandler).serve_forever()
