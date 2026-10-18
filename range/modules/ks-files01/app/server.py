#!/usr/bin/env python3
"""Open file-export stand-in for the ks-files01 module.

Technique (by design, technique_class ``nfs-nosquash``): an internal file server
exports a share with no effective access control — the "trust the network"
mistake that ``no_root_squash`` embodies. Anyone who can reach the export reads
the IT credential-handover note. Because the brain has no internet route to
apt-install ``nfs-kernel-server``/``samba`` (see manifest), this is honestly a
stdlib-HTTP stand-in for the unauthenticated export, not a real NFS daemon.

The handover note carries a reusable domain credential (``KEYSTONE\\svc_backup``,
a Backup Operator — the route toward dc-roast/DCSync) and points at the intranet
admin panel for the vault service account.

TARGET code; runs only inside the ks-files01 brain LXC on CORP (vmbr50). stdlib
only. The per-run flag at ``/opt/ks-files01/flag.txt`` is stamped at bring-up and
read from disk at request time.
"""
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 8091
FLAG_PATH = "/opt/ks-files01/flag.txt"

HANDOVER = (
    "IT HANDOVER — ks-files01:/export/it (world-readable, no_root_squash)\n"
    "domain: keystone.local (KEYSTONE)\n"
    "backup service account: KEYSTONE\\svc_backup / B@ckup-Reuse-2026\n"
    "  (member of Backup Operators on dc01 — use for the scheduled DCSync job)\n"
    "vault service account: see the intranet admin panel (ks-intranet01:/admin)\n"
)


def _read_flag():
    try:
        with open(FLAG_PATH, encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return "KEYSTONE{files01-handover-UNSTAMPED}"


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
            self._send(200, "<h1>ks-files01</h1><p>Export /export/it is open. "
                            "GET /export/it/handover.txt</p>", "text/html")
        elif self.path in ("/export/it/handover.txt", "/handover.txt"):
            # VULN: credential-handover doc readable with no authentication.
            self._send(200, HANDOVER)
        elif self.path == "/flag.txt":
            self._send(200, _read_flag() + "\n")
        else:
            self._send(404, "not found")

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
