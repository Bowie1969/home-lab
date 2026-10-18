#!/usr/bin/env python3
"""Deliberately vulnerable image-math service for the legacy-cve module.

The service pins Pillow at 8.3.2, which predates the fix for CVE-2022-22817:
PIL.ImageMath.eval() eval()s the attacker expression with real builtins
reachable (technique_class pinned-cve). The /eval endpoint passes the raw
expression straight in, so
  /eval?expr=__import__("os").popen("cat /opt/app/flag.txt").read()
executes and returns the flag. stdlib + the pinned Pillow only.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from PIL import Image, ImageMath

FLAG_FILE = "/opt/app/flag.txt"


class Handler(BaseHTTPRequestHandler):
    server_version = "ImageCalc/1.0"

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
                       "<h1>Image Calculator</h1>"
                       "<p>Server-side image arithmetic, powered by Pillow "
                       + Image.__version__ + ".</p>"
                       "<form>Evaluate an expression: "
                       "<input name=expr><input type=submit></form>",
                       "text/html")
            return
        if parsed.path != "/eval":
            self._send(404, "not found")
            return
        expr = parse_qs(parsed.query).get("expr", [""])[0]
        if not expr:
            self._send(400, "expr parameter is required")
            return
        # VULN (pinned CVE-2022-22817): expression reaches ImageMath.eval
        # with no sandboxing; builtins are reachable inside the eval.
        try:
            result = ImageMath.eval(expr)
        except Exception as exc:
            self._send(400, "eval error: %s" % exc)
            return
        if isinstance(result, Image.Image):
            self._send(200, "image result: mode=%s size=%s"
                       % (result.mode, result.size))
        else:
            self._send(200, str(result))

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8082), Handler).serve_forever()
