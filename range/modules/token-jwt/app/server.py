#!/usr/bin/env python3
"""JWT auth-bypass API for the token-jwt module.

Vulnerability (by design): the token verifier trusts the JWT header's ``alg``
(accepting ``none`` with no signature) AND the HS256 secret is a weak,
guessable string (technique_class jwt-authbypass). Forging
{"sub":"attacker","role":"admin"} with alg=none — or re-signing with the weak
secret — passes /admin and returns /app/flag.txt. stdlib only.
"""
import base64
import hashlib
import hmac
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

FLAG_FILE = "/app/flag.txt"
WEAK_SECRET = "keystone123"


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(data):
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def sign_hs256(header, payload):
    body = b64url(header.encode()) + "." + b64url(payload.encode())
    sig = hmac.new(WEAK_SECRET.encode(), body.encode(), hashlib.sha256).digest()
    return body + "." + b64url(sig)


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
        if parsed.path == "/":
            self._send(200,
                       "<h1>Token Service</h1>"
                       "<code>GET /login?u=&amp;p=</code> for a token, then "
                       "<code>GET /admin</code> with "
                       "<code>Authorization: Bearer &lt;token&gt;</code>",
                       "text/html")
            return
        if parsed.path == "/login":
            q = parse_qs(parsed.query)
            user = q.get("u", ["guest"])[0] or "guest"
            header = json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":"))
            payload = json.dumps({"sub": user, "role": "user"},
                                 separators=(",", ":"))
            self._send(200, sign_hs256(header, payload))
            return
        if parsed.path == "/admin":
            auth = self.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                self._send(401, "missing bearer token")
                return
            token = auth[len("Bearer "):].strip()
            try:
                header_b64, payload_b64, sig_b64 = token.split(".")
                header = json.loads(b64url_decode(header_b64))
                claims = json.loads(b64url_decode(payload_b64))
            except Exception:
                self._send(401, "malformed token")
                return
            # VULN: the algorithm comes from the attacker-controlled header.
            alg = header.get("alg", "")
            if alg == "none":
                pass  # unsigned tokens are trusted as-is
            elif alg == "HS256":
                body = (header_b64 + "." + payload_b64).encode()
                expected = hmac.new(WEAK_SECRET.encode(), body,
                                    hashlib.sha256).digest()
                try:
                    supplied = b64url_decode(sig_b64)
                except Exception:
                    supplied = b""
                if not hmac.compare_digest(expected, supplied):
                    self._send(401, "bad signature")
                    return
            else:
                self._send(401, "unsupported algorithm")
                return
            if claims.get("role") == "admin":
                self._send(200, "admin panel\nflag: " + read_flag().strip())
            else:
                self._send(403, "insufficient role: %s" % claims.get("role"))
            return
        self._send(404, "not found")

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8085), Handler).serve_forever()
