"""Blind Forge estate services — pure Python 3 stdlib, ephemeral localhost ports.

Three services:

- PortalService (HTTP): the public quoting portal for Blind Forge Metalworks.
  ``GET /quote?ref=`` interpolates the caller's value into a filter expression
  that is ``eval``'d against the quote table with four helper functions in
  scope (``readfile``, ``fetch``, ``notify``, ``sleep``). The endpoint only
  ever acknowledges a lookup — it renders one fixed body for every input, so a
  real match, an unknown reference, a fired injection and a raised exception
  are all byte-identical and there is no response oracle of any kind, not even
  a boolean one. The only way a byte leaves the estate is ``notify()`` to an
  out-of-band sink, or the ``sleep()`` timing channel.
- RecordsService (HTTP): the internal signed-drawing records service. It is not
  linked from the portal index and holds the crown at ``GET /crown``, which
  requires the ``X-Forge-Token`` header. Missing or wrong token -> 401 and no
  flag bytes anywhere in the response.
- CollabSink (HTTP): the out-of-band collaborator sink. It stands in for the
  operator's own OAST box so the channel is provable without external infra.
  Tokens are registered with ``POST /register``; ``GET``/``POST
  /collab/<token>`` record an interaction and ``GET /collab/<token>/hits``
  replays them. An unregistered token is refused (404), so a guessed token
  earns nothing.

``readfile`` is deliberately confined to the portal's own data directory:
filesystem traversal is cold-chain's skill, this estate measures blind
exfiltration through a channel with no oracle. The quote table is evaluated
against but never rendered — it exists so ``ref`` means something inside the
filter, not so the caller can read it.

No third-party imports, no podman/libvirt/qemu. ThreadingHTTPServer is used so
the estate test can drive every service in-process.
"""
from __future__ import annotations

import json
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Optional

QUOTE_REF = "Q-1042"
DEFAULT_RECORDS_TOKEN = "forge-rec-4c91d2ae"
CROWN_FLAG = "KEYSTONE{blindforge-crown-test}"
CROWN_PATH = "/crown"
SLEEP_CAP = 5.0

# The one and only body /quote can return. A real match, an unknown reference,
# a fired injection and a raised exception are all indistinguishable.
QUOTE_BODY = (
    b"Blind Forge Metalworks - quoting desk\n"
    b"lookup accepted; results are queued for the estimation desk\n"
    b"this endpoint does not echo filter results\n"
)

DEV_NOTES = """Blind Forge quoting portal - estimation desk dev notes

Quote lookup
    GET /quote?ref=<reference>          e.g. /quote?ref=Q-1042

The lookup is a filter expression, not a string compare. The reference you
supply is interpolated into `ref == "<value>"` and evaluated against the quote
table, once per record, with these helpers in scope:

    readfile(path)          read a file next to the quote table (data dir only)
    fetch(url, headers)     server-side GET; http/https only; returns the body
    notify(url, data=None)  out-of-band callback. GET when data is None, POST
                            with data as the body otherwise. Returns the HTTP
                            status, or 0 when the callback could not be made.
    sleep(seconds)          pause evaluation (capped at 5s)

Read this twice: /quote NEVER echoes filter results. It renders one fixed
acknowledgement for every input — a real reference, an unknown one, a filter
that fired and a filter that raised all come back byte-identical, same status,
same body, same headers. There is no error text, no status-code difference, no
reflected value and no boolean to read, so a filter that runs is completely
invisible in the response. If you need to know whether it ran, make it call you
(notify) or make it slow (sleep).

The estimation desk keeps its service credentials in `.forge_credentials`,
next to `quotes.json`. The signed master drawing is not served from here: the
portal is the only host with a route to the internal records service, which
wants the forge token in `X-Forge-Token` and serves the drawing index at
`/drawing/D-77` and the signed master at `/crown`.
"""


class _QuietServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _http_call(url: str, headers: Optional[Dict[str, str]] = None,
               data: Optional[bytes] = None, timeout: float = 10.0):
    """One outbound HTTP call; returns (status, body_text). status 0 = unreachable."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"scheme not allowed: {parsed.scheme!r}")
    request = urllib.request.Request(url, data=data, headers=headers or {},
                                     method="POST" if data is not None else "GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, ValueError):
        return 0, ""


class RecordsService:
    """Internal signed-drawing records service; the crown lives behind a header token.

    - ``GET /``            service banner, no token needed (proves the route exists).
    - ``GET /drawing/D-77`` token required; a low-value record so the operator can
      confirm a recovered token before spending it on the crown.
    - ``GET /crown``       token required; returns the crown flag.

    A missing or wrong token is a 401 whose body contains no flag material.
    """

    def __init__(self, token: str, crown_flag: str) -> None:
        self.token = token
        self.crown_flag = crown_flag
        self.crown_reads = 0
        self.denials = 0
        self._lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path == "/":
                    self._text(200, "Blind Forge records service\n"
                                    "drawing index: /drawing/D-77 (X-Forge-Token)\n"
                                    "signed master: /crown (X-Forge-Token)\n")
                elif parsed.path.startswith("/drawing/"):
                    self._guarded(self._drawing)
                elif parsed.path == CROWN_PATH:
                    self._guarded(self._crown)
                else:
                    self._text(404, "not found\n")

            def _guarded(self, ok):  # noqa: N802
                supplied = self.headers.get("X-Forge-Token", "")
                if supplied != outer.token:
                    with outer._lock:
                        outer.denials += 1
                    self._text(401, "unauthorised: forge token required\n")
                    return
                ok()

            def _drawing(self):  # noqa: N802
                self._text(200, json.dumps({
                    "drawing": "D-77",
                    "client": "Harbourline Fabrications",
                    "scope": "316L stainless manifold, 12 mm plate",
                    "status": "signed off",
                    "note": "signed master drawing is held at /crown",
                }, indent=2) + "\n")

            def _crown(self):  # noqa: N802
                with outer._lock:
                    outer.crown_reads += 1
                self._text(200, outer.crown_flag + "\n")

            def _text(self, code: int, body: str):  # noqa: N802
                payload = body.encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):  # silence stderr noise
                pass

        self._httpd = _QuietServer(("127.0.0.1", 0), Handler)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def start(self) -> "RecordsService":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


class CollabSink:
    """Out-of-band collaborator sink: register a token, collect callbacks, replay hits.

    - ``POST /register``            mint a token; the response carries the callback URL.
    - ``GET  /collab/<token>``      record a hit (query string kept as data).
    - ``POST /collab/<token>``      record a hit whose data is the request body.
    - ``GET  /collab/<token>/hits`` replay that token's hits as JSON.

    An unregistered token is a 404 on all three, so nothing is recorded or
    replayed for a token the operator did not create.
    """

    def __init__(self) -> None:
        self.tokens: Dict[str, List[dict]] = {}
        self._lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                parts = [p for p in self.path.split("?")[0].split("/") if p]
                if len(parts) == 2 and parts[0] == "collab":
                    self._record(parts[1], "")
                elif len(parts) == 3 and parts[0] == "collab" and parts[2] == "hits":
                    self._hits(parts[1])
                else:
                    self._json(404, {"error": "not found"})

            def do_POST(self):  # noqa: N802
                parts = [p for p in self.path.split("?")[0].split("/") if p]
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
                if parts == ["register"]:
                    token = secrets.token_hex(6)
                    with outer._lock:
                        outer.tokens[token] = []
                    self._json(200, {
                        "token": token,
                        "collab": f"http://127.0.0.1:{outer.port}/collab/{token}",
                        "hits": f"http://127.0.0.1:{outer.port}/collab/{token}/hits",
                    })
                elif len(parts) == 2 and parts[0] == "collab":
                    query = self.path.split("?", 1)[1] if "?" in self.path else ""
                    self._record(parts[1], body or query)
                else:
                    self._json(404, {"error": "not found"})

            def _record(self, token: str, data: str):  # noqa: N802
                with outer._lock:
                    known = token in outer.tokens
                    if known:
                        outer.tokens[token].append({
                            "seq": len(outer.tokens[token]) + 1,
                            "at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                            "src": self.client_address[0],
                            "data": data,
                        })
                if not known:
                    self._json(404, {"error": "unknown token"})
                    return
                self._json(200, {"ok": True})

            def _hits(self, token: str):  # noqa: N802
                with outer._lock:
                    if token not in outer.tokens:
                        self._json(404, {"error": "unknown token"})
                        return
                    hits = list(outer.tokens[token])
                self._json(200, {"token": token, "count": len(hits), "hits": hits})

            def _json(self, code: int, obj):  # noqa: N802
                payload = (json.dumps(obj, indent=2) + "\n").encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):  # silence stderr noise
                pass

        self._httpd = _QuietServer(("127.0.0.1", 0), Handler)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def start(self) -> "CollabSink":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()

    def register(self) -> str:
        """In-process token mint, for the estate test."""
        token = secrets.token_hex(6)
        with self._lock:
            self.tokens[token] = []
        return token

    def hits(self, token: str) -> List[dict]:
        with self._lock:
            return list(self.tokens.get(token, []))


class PortalService:
    """Public quoting portal; the filter expression is evaluated, never reflected.

    ``GET /quote?ref=<value>`` builds ``ref == "<value>"`` and evaluates it once
    per quote record with ``readfile``/``fetch``/``notify``/``sleep`` in scope.
    The first record that makes the expression truthy wins and its summary is
    returned. Anything else — unknown reference, injected filter, raised
    exception — returns ``NO_MATCH_BODY`` unchanged, so the response carries no
    signal about what the filter did.
    """

    def __init__(self, data_dir: Path, records_host: str, records_port: int,
                 records_token: str) -> None:
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.quotes = [
            {"ref": "Q-1042", "client": "Harbourline Fabrications",
             "scope": "316L stainless manifold, 12 mm plate", "value": 18400},
            {"ref": "Q-1055", "client": "Northreach Marine",
             "scope": "aluminium deck frame, welded + anodised", "value": 9750},
            {"ref": "Q-1061", "client": "Bellbrae Dairy",
             "scope": "galvanised chute refactor, CNC-cut gussets", "value": 22300},
        ]
        (self.data_dir / "quotes.json").write_text(
            json.dumps({"quotes": self.quotes}, indent=2) + "\n", encoding="utf-8")
        (self.data_dir / ".forge_credentials").write_text(json.dumps({
            "records": {
                "host": records_host,
                "port": records_port,
                "token": records_token,
                "drawing_index": "/drawing/D-77",
                "crown_path": CROWN_PATH,
            },
        }, indent=2) + "\n", encoding="utf-8")
        (self.data_dir / "dev-notes.txt").write_text(DEV_NOTES, encoding="utf-8")

        self.read_calls = 0
        self.fetch_calls = 0
        self.notify_calls = 0
        self.sleep_calls = 0
        self.evals = 0
        self.eval_errors = 0
        self.matched_refs: List[str] = []
        self._lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path == "/":
                    self._text(200, "Blind Forge Metalworks - quoting portal\n"
                                    "quote lookup: /quote?ref=Q-1042\n"
                                    "estimation desk notes: /dev-notes.txt\n")
                elif parsed.path == "/dev-notes.txt":
                    self._text(200, DEV_NOTES)
                elif parsed.path == "/quote":
                    self._quote(urllib.parse.parse_qs(parsed.query).get("ref", [""])[0])
                else:
                    self._text(404, "not found\n")

            def _quote(self, value: str):  # noqa: N802
                outer.evaluate(value)
                # The response is a function of nothing: the acknowledgement is
                # the only body this endpoint can produce. Any variation here —
                # a rendered match, an error page, a different status — would
                # hand the operator an oracle and end the estate's premise.
                payload = QUOTE_BODY
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def _text(self, code: int, body: str):  # noqa: N802
                payload = body.encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):  # silence stderr noise
                pass

        self._httpd = _QuietServer(("127.0.0.1", 0), Handler)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def start(self) -> "PortalService":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()

    # --- the injected namespace -------------------------------------------------

    def _readfile(self, path: str) -> str:
        """Read a file inside the portal's data directory only."""
        root = self.data_dir.resolve()
        target = (self.data_dir / path).resolve()
        if not target.is_relative_to(root):
            raise ValueError("outside the quoting data directory")
        with self._lock:
            self.read_calls += 1
        return target.read_text(encoding="utf-8")

    def _fetch(self, url: str, headers: Optional[Dict[str, str]] = None) -> str:
        """Server-side request: the portal's route to the internal records service."""
        with self._lock:
            self.fetch_calls += 1
        _status, body = _http_call(url, headers=headers)
        return body

    def _notify(self, url: str, data: Optional[str] = None) -> int:
        """Out-of-band callback — the only channel that carries bytes out."""
        with self._lock:
            self.notify_calls += 1
        body = data.encode("utf-8") if data is not None else None
        headers = {"Content-Type": "text/plain"} if body is not None else {}
        status, _text = _http_call(url, headers=headers, data=body)
        return status

    def _sleep(self, seconds: float) -> None:
        """Timing oracle: a slow response is the only in-band signal available."""
        with self._lock:
            self.sleep_calls += 1
        time.sleep(max(0.0, min(float(seconds), SLEEP_CAP)))

    def evaluate(self, value: str):
        """Run the filter expression; return the matched quote or None.

        The caller never renders the result — matched references are recorded
        for estate bookkeeping only. Errors are swallowed and counted, never
        surfaced: a raised exception must be indistinguishable from an
        unmatched reference.
        """
        expression = f'ref == "{value}"'
        helpers = {
            "readfile": self._readfile,
            "fetch": self._fetch,
            "notify": self._notify,
            "sleep": self._sleep,
        }
        for record in self.quotes:
            with self._lock:
                self.evals += 1
            scope = dict(helpers)
            scope["ref"] = record["ref"]
            try:
                if eval(expression, {"__builtins__": {}}, scope):  # noqa: S307
                    with self._lock:
                        self.matched_refs.append(record["ref"])
                    return record
            except Exception:
                with self._lock:
                    self.eval_errors += 1
                return None
        return None


def build_estate(tmp: Path, records_token: Optional[str] = None,
                 crown_flag: Optional[str] = None) -> Dict[str, object]:
    """Instantiate the three services on ephemeral ports and hand back handles."""
    token = records_token or DEFAULT_RECORDS_TOKEN
    flag = crown_flag or CROWN_FLAG

    sink = CollabSink()
    records = RecordsService(token, flag)
    portal = PortalService(tmp, "127.0.0.1", records.port, token)
    return {"portal": portal, "records": records, "sink": sink}
