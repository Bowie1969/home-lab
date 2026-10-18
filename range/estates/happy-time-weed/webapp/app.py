#!/usr/bin/env python3
"""Happy Time Weed — dispensary customer site (DELIBERATELY VULNERABLE).

Stdlib-only so it runs on any of the estate hosts with python3. The site is
the realistic public face of the business and the first attack surface.

Deliberate flaws (each a real vuln class — see estates/happy-time-weed/DESIGN.md):
  1. SQLi            GET  /menu?cat=...            unsanitised string concat
  2. IDOR            GET  /orders/<id>             no authorisation
  3. Pickle RCE      session cookie (htw_session)  base64 pickle, deserialised
  4. Command inject  POST /review (JSON)           photo_name reaches os.system
  5. JWT alg=none    GET  /api/v1/patient_records  hand-rolled JWT, weak secret
  6. SSRF            GET  /track?url=...           urllib fetch, Host-gated internals
  7. Stored XSS      product reviews               rendered unescaped

Run:  python3 app.py [--port 8080] [--db path]
"""
import argparse
import base64
import hashlib
import hmac
import html
import json
import os
import pickle
import sqlite3
import sys
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

JWT_SECRET = "sativa2026"  # weak shared secret, wordlist-crackable
WEB_USER = "htw-web"       # the service account the site runs as
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "happy_time_weed.db")


# ---------------------------------------------------------------- database --
def _seed(db: sqlite3.Connection) -> None:
    db.executescript("""
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY, name TEXT, price REAL, category TEXT);
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT, role TEXT);
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY, customer TEXT, address TEXT, phone TEXT,
        items TEXT, total REAL);
    CREATE TABLE IF NOT EXISTS patient_records (
        patient_id INTEGER PRIMARY KEY, name TEXT, dob TEXT, address TEXT,
        condition TEXT, notes TEXT);
    CREATE TABLE IF NOT EXISTS reviews (
        id INTEGER PRIMARY KEY, product TEXT, author TEXT, body TEXT);
    """)
    if db.execute("SELECT COUNT(*) FROM products").fetchone()[0] == 0:
        db.executemany(
            "INSERT INTO products (name, price, category) VALUES (?,?,?)",
            [("Blue Dream", 12.50, "flower"),
             ("Sour Diesel", 13.00, "flower"),
             ("Wedding Cake", 14.50, "flower"),
             ("OG Kush", 13.75, "flower"),
             ("Grape Gummies 10mg x10", 18.00, "edible"),
             ("CBD Tincture 500mg", 35.00, "tincture"),
             ("Pre-roll 2-pack", 9.00, "preroll")])
    if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        db.executemany(
            "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
            [("d.dankworth", _sha("PurpleHaze420!"), "owner"),
             ("m.marley", _sha("BongRips2026"), "budtender"),
             ("a.ledger", _sha("JointVenture99"), "accountant"),
             ("p.paperwork", _sha("DoobieDo2026"), "office-manager"),
             ("t.tech", _sha("HashCrack!2026"), "it-contractor"),
             ("svc_web", _sha("HTW-web-svc-1"), "service"),
             ("j.customer", _sha("customerpass"), "customer"),
             ("k.shopper", _sha("shopperpass"), "customer")])
    if db.execute("SELECT COUNT(*) FROM orders").fetchone()[0] == 0:
        db.executemany(
            "INSERT INTO orders (customer, address, phone, items, total) "
            "VALUES (?,?,?,?,?)",
            [("Jane Customer", "7 Haze Lane, Stoner Creek", "0400 111 222",
              "Blue Dream x2, Pre-roll 2-pack", 34.00),
             ("Ken Shopper", "420 Green Ave, Stoner Creek", "0400 333 444",
              "Grape Gummies x3", 54.00),
             ("Dana Dankworth", "1 Kush Court, Stoner Creek", "0400 555 666",
              "Wedding Cake x1", 14.50)])
    if db.execute("SELECT COUNT(*) FROM patient_records").fetchone()[0] == 0:
        db.executemany(
            "INSERT INTO patient_records (name, dob, address, condition, notes) "
            "VALUES (?,?,?,?,?)",
            [("Jane Customer", "1988-04-20", "7 Haze Lane, Stoner Creek",
              "chronic pain", "prescribed 2g/day flower"),
             ("Ken Shopper", "1995-11-03", "420 Green Ave, Stoner Creek",
              "anxiety", "CBD tincture nightly"),
             ("Dana Dankworth", "1972-08-15", "1 Kush Court, Stoner Creek",
              "insomnia", "indica only, evenings"),
             ("Riley Stone", "2001-02-29", "99 Pipe St, Stoner Creek",
              "PTSD", "sensitive — private room for pickup")])
    if db.execute("SELECT COUNT(*) FROM reviews").fetchone()[0] == 0:
        db.executemany(
            "INSERT INTO reviews (product, author, body) VALUES (?,?,?)",
            [("Blue Dream", "j.customer", "Great daytime strain, 10/10."),
             ("Grape Gummies", "k.shopper", "Tasty but strong. Start with half.")])
    db.commit()


def _sha(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    _seed(conn)
    return conn


# -------------------------------------------------------------------- JWT --
def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def jwt_make(payload: dict, secret: str = JWT_SECRET) -> str:
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = _b64(json.dumps(payload).encode())
    sig = _b64(hmac.new(secret.encode(), f"{header}.{body}".encode(),
                        hashlib.sha256).digest())
    return f"{header}.{body}.{sig}"


def jwt_verify(token: str) -> dict:
    """Deliberately broken: accepts alg=none and a weak shared secret."""
    try:
        header_b64, body_b64, _sig = token.split(".")
    except ValueError:
        raise PermissionError("malformed token")
    header = json.loads(_b64d(header_b64))
    if header.get("alg") == "none":          # VULN 5a: alg=none accepted
        return json.loads(_b64d(body_b64))
    expected = _b64(hmac.new(JWT_SECRET.encode(),
                             f"{header_b64}.{body_b64}".encode(),
                             hashlib.sha256).digest())
    if not hmac.compare_digest(_sig, expected):  # VULN 5b: HS256, weak secret
        raise PermissionError("bad signature")
    return json.loads(_b64d(body_b64))


# --------------------------------------------------------------- sessions --
def session_make(user: str, role: str) -> str:
    """Session cookie is a base64 PICKLE — deserialised on every request."""
    blob = pickle.dumps({"user": user, "role": role})     # VULN 3
    return base64.b64encode(blob).decode()


def session_load(cookie: str) -> dict:
    try:
        blob = base64.b64decode(cookie)
        return pickle.loads(blob)                          # VULN 3: RCE here
    except Exception:
        return {}


# ------------------------------------------------------------------ views --
PAGE = """
<!doctype html><html><head><title>Happy Time Weed</title>
<style>body{{font-family:sans-serif;margin:2em;background:#123}}h1{{color:#7c5}}</style>
</head><body><h1>&#127807; Happy Time Weed</h1><p>Stoner Creek's friendliest dispensary.
<b>Open 9am-9pm, 7 days.</b></p>
<nav><a href="/menu">Menu</a> | <a href="/order">Order</a> | <a href="/intake">Patient Intake</a> |
<a href="/track">Track Order</a> | <a href="/api/v1/patient_records">Patient Portal</a></nav>
{body}</body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "HTW-Web/1.0"

    def _send(self, code, body, ctype="text/html", extra=None):
        b = body if isinstance(body, bytes) else str(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def _page(self, body, code=200):
        self._send(code, PAGE.format(body=body))

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, indent=2), "application/json")

    # -- routes ---------------------------------------------------------
    def do_GET(self):
        path = urlparse(self.path).path
        qs = parse_qs(urlparse(self.path).query)
        if path == "/" or path == "/menu":
            return self.menu(qs.get("cat", [""])[0])
        if path.startswith("/orders/"):
            return self.order_detail(path.rsplit("/", 1)[1])
        if path == "/track":
            return self.track(qs.get("url", [""])[0])
        if path == "/intake":
            return self._page("<h2>Patient Intake</h2><p>Call us or sign up in "
                              "store — your records stay between us and the "
                              "regulator. Existing patients: use the Patient "
                              "Portal link above.</p>")
        if path == "/reviews":
            conn = db()
            rows = conn.execute("SELECT * FROM reviews").fetchall()
            # VULN 7: review bodies render UNESCAPED (stored XSS).
            body = "<h2>Customer reviews</h2>" + "".join(
                f"<div><b>{r['author']}</b> on {r['product']}: {r['body']}</div>"
                for r in rows)
            return self._page(body)
        if path == "/api/v1/patient_records":
            return self.patient_records()
        if path.startswith("/internal/"):
            return self.internal(path)
        self._page("<h2>404</h2><p>that page is out of stock</p>", 404)

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/review":
            return self.review()
        if path == "/login":
            return self.login()
        if path == "/order":
            return self.order()
        self._page("<h2>404</h2>", 404)

    # -- vuln 1: SQLi ---------------------------------------------------
    def menu(self, cat):
        conn = db()
        if cat:
            # VULN 1: category interpolated straight into the query.
            rows = conn.execute(
                f"SELECT id, name, price, category FROM products "
                f"WHERE category = '{cat}'").fetchall()
        else:
            rows = conn.execute(
                "SELECT id, name, price, category FROM products").fetchall()
        if not rows:
            return self._page("<h2>Menu</h2><p>nothing in that category</p>")
        def _price(v):
            return f"${v:.2f}" if isinstance(v, (int, float)) else str(v)
        items = "".join(
            f"<li>{r['name']} — {_price(r['price'])} "
            f"<i>({html.escape(str(r['category']))})</i></li>"
            for r in rows if r["name"])
        return self._page(f"<h2>Menu</h2><ul>{items}</ul>")

    # -- vuln 2: IDOR ---------------------------------------------------
    def order_detail(self, order_id):
        conn = db()
        row = conn.execute("SELECT * FROM orders WHERE id = ?",
                           (order_id,)).fetchone()
        if not row:
            return self._page("<h2>Order not found</h2>", 404)
        # VULN 2: no session/ownership check on the order id.
        body = (f"<h2>Order #{row['id']}</h2><p><b>{row['customer']}</b><br>"
                f"{row['address']}<br>{row['phone']}<br>"
                f"items: {row['items']} — total ${row['total']:.2f}</p>")
        return self._page(body)

    # -- vuln 6: SSRF ---------------------------------------------------
    def track(self, url):
        if not url:
            return self._page("<h2>Track your order</h2><p>Enter the tracking "
                              "URL your confirmation email contained:</p>"
                              "<form action='/track'><input name='url' "
                              "size='40' placeholder='https://...'><button>"
                              "Track</button></form>")
        # VULN 6: the server fetches whatever URL the client gives it.
        try:
            with urllib.request.urlopen(url, timeout=8) as r:
                body = r.read(4000).decode("utf-8", "replace")
            return self._page(f"<h2>Tracking result</h2><pre>{html.escape(body)}</pre>")
        except Exception as e:
            return self._page(f"<h2>Tracking failed</h2><p>{html.escape(str(e))}</p>")

    # -- vuln 5: JWT ----------------------------------------------------
    def patient_records(self):
        token = self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        claims = {}
        if not token:
            # Cookie fallback: the htw_session pickle is deserialised here
            # (VULN 3 — any request with a forged cookie executes on load).
            cookie = self.headers.get("Cookie", "")
            if "htw_session=" in cookie:
                claims = session_load(
                    cookie.split("htw_session=", 1)[1].split(";")[0].strip())
            if not claims:
                self._send(401, "patient portal: Bearer <JWT> or session "
                                "cookie required\n",
                           extra={"WWW-Authenticate": "Bearer"})
                return
        else:
            try:
                claims = jwt_verify(token)
            except PermissionError as e:
                return self._json(401, {"error": str(e)})
        if claims.get("role") not in ("admin", "staff", "owner", "service"):
            return self._json(403, {"error": "insufficient role"})
        conn = db()
        rows = conn.execute("SELECT * FROM patient_records").fetchall()
        return self._json(200, {"records": [dict(r) for r in rows]})

    # -- Host-gated internal APIs (the SSRF target) ----------------------
    def internal(self, path):
        host = self.headers.get("Host", "").split(":")[0]
        if host not in ("127.0.0.1", "localhost", "htw-server"):
            return self._json(403, {"error": "internal endpoint"})
        if path == "/internal/point_of_sale":
            return self._json(200, {"pos": "online", "registers": 3,
                                    "day_till_total": 12844.50,
                                    "safe_combo_hint": "birthday of the owner's dog"})
        if path == "/internal/stock":
            conn = db()
            return self._json(200, {"stock": [dict(r) for r in conn.execute(
                "SELECT id, name, price FROM products")]})
        return self._json(404, {"error": "unknown internal path"})

    # -- vuln 4: command injection ----------------------------------------
    def review(self):
        length = int(self.headers.get("Content-Length", 0))
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self._json(400, {"error": "send JSON"})
        name = str(data.get("photo_name") or "anon.jpg")
        body = str(data.get("review") or "")
        # VULN 4: the photo name is passed to a shell command unquoted.
        os.system(f"convert uploads/{name} -resize 100x100 thumbs/{name} 2>/dev/null")
        conn = db()
        conn.execute("INSERT INTO reviews (product, author, body) VALUES (?,?,?)",
                     (data.get("product") or "menu", data.get("author") or "anon", body))
        conn.commit()
        return self._json(200, {"ok": True, "review_saved": body})

    # -- login: session cookie is a pickle (vuln 3's trigger) --------------
    def login(self):
        length = int(self.headers.get("Content-Length", 0))
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self._json(400, {"error": "send JSON"})
        conn = db()
        row = conn.execute("SELECT * FROM users WHERE username = ?",
                           (data.get("username"),)).fetchone()
        if not row or row["password_hash"] != _sha(str(data.get("password"))):
            return self._json(401, {"error": "bad credentials"})
        cookie = session_make(row["username"], row["role"])
        return self._json(200, {"ok": True, "user": row["username"],
                                "role": row["role"], "htw_session": cookie})

    # -- order placement (feeds the IDOR data) ----------------------------
    def order(self):
        length = int(self.headers.get("Content-Length", 0))
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self._json(400, {"error": "send JSON"})
        conn = db()
        cur = conn.execute(
            "INSERT INTO orders (customer, address, phone, items, total) "
            "VALUES (?,?,?,?,?)",
            (data.get("customer"), data.get("address"), data.get("phone"),
             data.get("items"), float(data.get("total") or 0)))
        conn.commit()
        return self._json(200, {"ok": True, "order_id": cur.lastrowid})

    def log_message(self, *_):
        pass


def main():
    global DB_PATH
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--db", default=DB_PATH)
    args = ap.parse_args()
    DB_PATH = args.db
    print(f"Happy Time Weed site on :{args.port} (db {args.db}) — "
          f"demo; the vulns are the point", flush=True)
    ThreadingHTTPServer(("0.0.0.0", args.port), Handler).serve_forever()


if __name__ == "__main__":
    sys.exit(main())
