#!/usr/bin/env python3
"""SSTI profile renderer for the render-ssti module.

Vulnerability (by design): the "render your profile" feature concatenates the
user-supplied name into a Jinja2 template string and renders it server-side
(technique_class deserialization-ssti). e.g.
  /render?name={{ cycler.__init__.__globals__.os.popen('cat /app/flag.txt').read() }}
yields RCE and the flag.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from jinja2 import Template

GREETING = "Hello {{ name }}! Welcome to the profile renderer."


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
        if parsed.path == "/":
            self._send(200,
                       "<h1>Profile Renderer</h1>"
                       "<form>Render your public greeting: "
                       "<input name=name><input type=submit></form>",
                       "text/html")
            return
        if parsed.path != "/render":
            self._send(404, "not found")
            return
        name = parse_qs(parsed.query).get("name", [""])[0]
        # VULN: user input goes straight into the template source.
        try:
            rendered = Template(GREETING.replace("{{ name }}", name)).render()
        except Exception as exc:
            self._send(500, "render error: %s" % exc)
            return
        self._send(200, rendered)

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8084), Handler).serve_forever()
