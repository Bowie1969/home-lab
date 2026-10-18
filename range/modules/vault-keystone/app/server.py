#!/usr/bin/env python3
"""THE CROWN JEWEL — authenticated secrets store for the vault-keystone module.

Technique (by design, technique_class ``crown-store``): the DATA-tier vault that
holds the Keystone master signing key. Two independent gates protect it and this
app weakens neither:

1. **Network** — the brain firewall (``build/brain-firewall.nft``) makes
   ``:8200`` reachable ONLY from CORP hosts on vmbr50. The attacker and DMZ zones
   cannot reach it at all; the bridge has no uplink.
2. **Application** — the master key is returned ONLY to a caller presenting one
   of the branch credentials below. An unauthenticated request gets 401 and no
   key material — so a CORP foothold alone is not enough; the operator must
   complete at least one full deep branch first.

WHY A TOKEN PER BRANCH: the crown must be completable ~10 genuinely different
ways, and each deep CORP branch (AD, kernel privesc, AI supply chain, BMC,
each known-CVE VM, the physical Mac) is its own way — so each branch carries its
own break-glass/recovery credential that this vault accepts. Recovering any one
token (always post-exploitation, from a root/DA/SYSTEM-only location) completes
the range; no branch is a required stage of any other. The token VALUES are
declared in each module's manifest (``vault_token:``) and this set MUST match
the union of those declarations — ``tests/test_vault_branches.py`` pins that
parity in both directions so the two sides cannot drift.

The app never lists a directory and never serves the secrets folder; it reads the
one key file explicitly. "Winning" is reading this key and exfiltrating it back
out through the compromised pivot chain (scored on pcap of corp->data:8200 plus
the crown bytes transiting back out).

TARGET code; runs only inside the vault-keystone brain LXC on the DATA side of
vmbr50. stdlib only. The per-run master key at ``/vault/secrets/master.key`` is
stamped by ``keystone.live lxc-stamp`` and read from disk at request time.
"""
import hmac
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 8200
KEY_PATH = "/vault/secrets/master.key"

# One accepted credential per deep branch. ``value`` must equal the union of the
# ``vault_token.value`` declarations across module manifests (pinned by
# tests/test_vault_branches.py); the label is for humans/audit only and is never
# sent to the client. A design secret set, compared in constant time; NOT
# per-run flags (reset rotates the master key, not these).
VAULT_TOKENS = {
    "ks-vault-svc-7f3c21":      "service account — ks-intranet01 admin panel leak",
    "ks-vault-da-3f9a6c":       "Domain Admin break-glass — dc01 admin desktop",
    "ks-vault-kernel-8b2d41":   "kernel root recovery — kiosk-kernel",
    "ks-vault-hive-c0ffee":     "hive service token — modelhub-pickle",
    "ks-vault-bmc-5e11f0":      "BMC break-glass — bmc-super firmware dir",
    "ks-vault-dirtycow-d15c0":  "root recovery — ubuntu-dirtycow",
    "ks-vault-samba-41ae92":    "root recovery — samba-45",
    "ks-vault-eternal-6b3f7d":  "SYSTEM break-glass — win7-eternalblue",
    "ks-vault-win2025-2f8c19":  "SYSTEM break-glass — win2025-smb",
    "ks-vault-mac-77aa09":      "sudo-root recovery — mac-debian13",
}


def _valid_token(presented):
    if not presented:
        return False
    return any(hmac.compare_digest(str(presented), tok) for tok in VAULT_TOKENS)


def _read_key():
    with open(KEY_PATH, encoding="utf-8") as fh:
        return fh.read().strip()


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="text/plain", extra=None):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, "<h1>Keystone Vault</h1><p>Authenticated access only. "
                            "GET /secrets/master.key with X-Vault-Token.</p>",
                       "text/html")
            return
        if self.path == "/secrets/master.key":
            token = self.headers.get("X-Vault-Token")
            if not _valid_token(token):
                # Crown stays sealed: no key material in the unauthorized path.
                self._send(401, "unauthorized: valid X-Vault-Token required\n",
                           extra={"WWW-Authenticate": "Vault-Token"})
                return
            try:
                self._send(200, _read_key() + "\n")
            except OSError:
                self._send(503, "vault not initialized\n")
            return
        # Never list or serve any other path (no directory listing of /vault).
        self._send(404, "not found\n")

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
