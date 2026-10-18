#!/usr/bin/env python3
"""Deliberately SQL-injectable portal for the portal-sqli module.

Vulnerability (by design): the login query is built by string concatenation, so
a UNION-based injection in the ``u`` parameter dumps the users table — including
``svc_portal``, a credential reused on the corp tier (technique_class sqli-cred).

TARGET code; runs only inside the challenge container. stdlib only.
"""
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

DB = ":memory:"
_conn = sqlite3.connect(DB, check_same_thread=False)
_conn.executescript(
    """
    CREATE TABLE users (id INTEGER, username TEXT, password TEXT, role TEXT);
    INSERT INTO users VALUES (1,'admin','p0rtal-admin-9x','admin');
    INSERT INTO users VALUES (2,'svc_portal','Corp-Reuse-7!','service');
    INSERT INTO users VALUES (3,'guest','guest','user');
    """
)


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="text/plain"):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        if urlparse(self.path).path == "/login":
            user = q.get("u", [""])[0]
            pw = q.get("p", [""])[0]
            # VULN: unparameterised string concatenation.
            sql = ("SELECT username, role FROM users WHERE username = '"
                   + user + "' AND password = '" + pw + "'")
            try:
                rows = _conn.execute(sql).fetchall()
            except sqlite3.Error as exc:
                self._send(500, f"sql error: {exc}")
                return
            self._send(200, "\n".join(f"{r[0]}:{r[1]}" for r in rows) or "no match")
        else:
            self._send(200, "<h1>Portal</h1> GET /login?u=&p=", "text/html")

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8081), Handler).serve_forever()
