#!/usr/bin/env python3
"""Internal-only admin panel for the ks-intranet01 module.

Technique (by design, technique_class ``ssrf-pivot``): an internal application
whose admin panel is only reachable from inside CORP. The DMZ ``meta-ssrf``
module (and the CORP foothold generally) can pivot to it; it was never meant to
be exposed. Its ``/admin`` config leaks the vault service token — the domain
service credential that authenticates to the DATA-tier crown.

Reachability is enforced by the network (the brain firewall makes this host
reachable only from CORP), not by this app — the app intentionally trusts that
"internal == safe", which is the whole point.

TARGET code; runs only inside the ks-intranet01 brain LXC on CORP (vmbr50).
stdlib only. The per-run flag at ``/opt/ks-intranet01/flag.txt`` is stamped at
bring-up and read from disk at request time.
"""
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 8092
FLAG_PATH = "/opt/ks-intranet01/flag.txt"

# The vault service token the DATA-tier crown (vault-keystone) requires. A design
# secret that lives only inside the range; recovering it here is the intended way
# to authenticate to the vault. NOT a per-run flag.
ADMIN_CONFIG = (
    "# ks-intranet01 /admin/config (internal only — do NOT expose)\n"
    "app: Keystone Intranet\n"
    "vault_url: http://vault-keystone.data:8200/secrets/master.key\n"
    "vault_service_account: svc_vault\n"
    "vault_token: ks-vault-svc-7f3c21\n"
    "usage: send header 'X-Vault-Token: ks-vault-svc-7f3c21' to the vault\n"
)


def _read_flag():
    try:
        with open(FLAG_PATH, encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return "KEYSTONE{intranet01-admin-UNSTAMPED}"


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
            self._send(200, "<h1>Keystone Intranet</h1><p>Internal admin panel at "
                            "/admin (authorized staff only).</p>", "text/html")
        elif self.path in ("/admin", "/admin/config"):
            # VULN: internal-only admin config leaks the vault service token.
            self._send(200, ADMIN_CONFIG)
        elif self.path == "/flag.txt":
            self._send(200, _read_flag() + "\n")
        else:
            self._send(404, "not found")

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
