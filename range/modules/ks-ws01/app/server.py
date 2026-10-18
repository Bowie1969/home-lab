#!/usr/bin/env python3
"""Employee-workstation credential-harvest listener for the ks-ws01 module.

Technique (by design, technique_class ``cred-harvest``): a workstation that
exposes its local credential cache over an unauthenticated stdlib HTTP listener.
Reading ``/cached_credentials.txt`` hands the operator a reusable domain
credential (``KEYSTONE\\svc_desk``), which is accepted onward by ks-files01 and
ks-intranet01 — the "cached creds on a shared workstation" mistake.

TARGET code; runs only inside the ks-ws01 brain LXC on the isolated CORP bridge
(vmbr50). stdlib only — the brain has no apt/pip route out (see manifest). The
per-run flag at ``/opt/ks-ws01/flag.txt`` is stamped by ``keystone.live
lxc-stamp`` and read from disk at request time, never baked into this file.
"""
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 8090
FLAG_PATH = "/opt/ks-ws01/flag.txt"

# The reusable credential a real cached-logon dump would leak. A design secret
# that lives only inside this challenge guest; it is NOT a per-run flag.
CACHED_CREDENTIALS = (
    "# C:\\Users\\jdesk\\AppData\\cached_logons.txt (roamed to the file server)\n"
    "domain=KEYSTONE realm=keystone.local\n"
    "user=KEYSTONE\\svc_desk pass=Autumn2026!Desk\n"
    "note=reused on \\\\ks-files01 and the intranet admin panel\n"
)


def _read_flag():
    try:
        with open(FLAG_PATH, encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return "KEYSTONE{ws01-cached-cred-UNSTAMPED}"


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="text/plain"):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, "<h1>ks-ws01</h1><p>Keystone employee workstation. "
                            "Local credential cache at /cached_credentials.txt</p>",
                       "text/html")
        elif self.path == "/cached_credentials.txt":
            # VULN: cached domain credential served with no authentication.
            self._send(200, CACHED_CREDENTIALS)
        elif self.path == "/flag.txt":
            # Proof-of-compromise marker for this host.
            self._send(200, _read_flag() + "\n")
        else:
            self._send(404, "not found")

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
