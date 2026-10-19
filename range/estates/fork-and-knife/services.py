"""Fork & Knife estate services — pure Python 3 stdlib, ephemeral localhost ports.

One module, four services for the ghost-kitchen supply-chain estate:

- DevPortalService (HTTP): the public developer/status web app. It also serves
  a mirror of the git repo; the commit history leaks the junior dev CI token
  and the weak webhook secret — both recoverable with a plain GET, no external
  tools.
- WebhookService (HTTP): the CI webhook. Accepts a pushed build job (JSON)
  only when the ``X-Webhook-Secret`` header matches the weak secret and the
  ``author_token`` is a known dev, then queues the job for the runner.
- RunnerService (timer thread): ticks on a timer, dequeues and executes queued
  jobs (delayed, second-order execution), and drops the job output plus the
  SSH deploy token into a per-author results directory.
- VaultService (HTTP): the prod billing vault. Returns
  ``KEYSTONE{forkknife-crown-<rot>}`` only when the SSH deploy token is
  presented as a bearer token.

No third-party imports, no podman/libvirt/qemu. ``ThreadingHTTPServer`` and
``queue.Queue`` are used so the estate test can drive everything in-process.
"""
from __future__ import annotations

import json
import queue
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Optional

# The estate's secrets. All three are "discoverable without external tools"
# from the public commit history (COMMITS, below), which is the whole point:
# the webhook secret is weak AND committed, the junior dev token is committed,
# and the SSH deploy token is the crown credential the runner leaks into
# results.

WEBHOOK_SECRET = "ghostkitchen-wh-secret"       # weak + committed to git history
JUNIOR_TOKEN = "fk-junior-dev-token-7c9d"       # junior dev CI token, committed
SSH_DEPLOY_TOKEN = "fk-ssh-deploy-key-3e1b9a"   # prod deploy credential (crown path)
CROWN_ROT = "2026-10-20"                        # current rotation of the crown secret
RESULTS_SUBDIR = "results"                      # where the runner drops per-author results


def crown_flag(rot: str) -> str:
    """The crown the prod billing vault emits for the current rotation."""
    return f"KEYSTONE{{forkknife-crown-{rot}}}"


# Commit history served by the dev portal's git mirror. Two commits leak the
# credentials: the webhook wiring commit ships the weak secret, and a junior
# dev's WIP commit ships their CI token.
COMMITS: List[Dict[str, str]] = [
    {
        "sha": "3f1a2c",
        "author": "dana <dana@ghostkitchen.dev>",
        "message": "scaffold the billing service",
        "diff": "+print('ghost-kitchen billing v0.1')\n",
    },
    {
        "sha": "b7e8d0",
        "author": "dana <dana@ghostkitchen.dev>",
        "message": "wire the CI webhook for pushes",
        "diff": (
            f'+WEBHOOK_SECRET = "{WEBHOOK_SECRET}"\n'
            "+HOOK_URL = \"http://ci.internal/push\"\n"
            "+# TODO rotate this secret — it is weak\n"
        ),
    },
    {
        "sha": "9c4f11",
        "author": "sam <sam@ghostkitchen.dev>",
        "message": "WIP: hardcode my token so local builds stop failing",
        "diff": (
            f'+DEV_TOKEN = "{JUNIOR_TOKEN}"\n'
            "+# TODO move to the secrets manager before merge\n"
        ),
    },
]

STATUS_PAGE = (
    "GhostKitchen Billing — build status\n"
    "service: billing-api      status: ok\n"
    "service: payment-ledger   status: degraded\n"
    "service: ci-runner        status: idle (timer tick)\n"
    "last deploy: 2026-10-20 03:11Z  commit 9c4f11\n"
    "public source mirror: GET /repo/log\n"
)


class _QuietServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _send_json(handler: BaseHTTPRequestHandler, obj: object, status: int = 200) -> None:
    body = json.dumps(obj).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _send_text(handler: BaseHTTPRequestHandler, text: str, status: int = 200) -> None:
    body = text.encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "text/plain; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class DevPortalService:
    """Public developer/status web app; also serves the git commit history."""

    def __init__(self) -> None:
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                if self.path == "/repo/log":
                    _send_json(self, {"repo": "ghostkitchen/billing",
                                      "ref": "refs/heads/main",
                                      "commits": COMMITS})
                    return
                if self.path == "/repo":
                    _send_json(self, {"repo": "ghostkitchen/billing",
                                      "ref": "refs/heads/main",
                                      "log": "/repo/log"})
                    return
                if self.path in ("/", "/status"):
                    _send_text(self, STATUS_PAGE)
                    return
                self.send_error(404)

            def log_message(self, *args):  # silence stderr noise
                pass

        self._httpd = _QuietServer(("127.0.0.1", 0), Handler)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def start(self) -> "DevPortalService":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


class WebhookService:
    """CI webhook: authenticates a pushed build job and queues it."""

    def __init__(self, job_queue: "queue.Queue") -> None:
        self.job_queue = job_queue
        self._seq = 0
        self._seq_lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                if self.path != "/push":
                    self.send_error(404)
                    return
                secret = self.headers.get("X-Webhook-Secret", "")
                if secret != WEBHOOK_SECRET:
                    self.send_response(401)
                    self.send_header("X-Verdict", "bad-secret")
                    self.end_headers()
                    self.wfile.write(b"unauthorized")
                    return
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length)
                try:
                    job = json.loads(raw.decode())
                except (ValueError, UnicodeDecodeError):
                    self.send_error(400)
                    return
                author = job.get("author_token", "")
                if author != JUNIOR_TOKEN:
                    self.send_response(403)
                    self.send_header("X-Verdict", "unknown-author")
                    self.end_headers()
                    self.wfile.write(b"forbidden")
                    return
                job_id = outer._next_id()
                job["job_id"] = job_id
                job.setdefault("repo", "ghostkitchen/billing")
                job.setdefault("commit", "")
                job.setdefault("command", "")
                outer.job_queue.put(job)
                _send_json(self, {"job_id": job_id, "status": "queued"})

            def do_GET(self):  # noqa: N802
                if self.path == "/queue":
                    _send_json(self, {"queued": outer.job_queue.qsize()})
                    return
                self.send_error(404)

            def log_message(self, *args):
                pass

        self._httpd = _QuietServer(("127.0.0.1", 0), Handler)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def _next_id(self) -> str:
        with self._seq_lock:
            self._seq += 1
            return f"job-{self._seq:04d}"

    def start(self) -> "WebhookService":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


class RunnerService:
    """Timer-driven CI runner: executes queued jobs and leaks the deploy token."""

    def __init__(self, job_queue: "queue.Queue", results_root: Path,
                 deploy_token: str, tick_seconds: float = 0.25) -> None:
        self.job_queue = job_queue
        self.results_root = results_root
        self.deploy_token = deploy_token
        self.tick_seconds = tick_seconds
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def start(self) -> "RunnerService":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        self.job_queue.put(None)  # wake a blocked get() so the loop exits
        self._thread.join(timeout=2)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                job = self.job_queue.get(timeout=self.tick_seconds)
            except queue.Empty:
                continue
            if job is None:  # stop() sentinel
                continue
            self._process(job)

    def _process(self, job: dict) -> None:
        author = job.get("author_token", "unknown")
        job_id = job.get("job_id", "unknown")
        out_dir = self.results_root / author / job_id
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "job.json").write_text(json.dumps(job, indent=2))
        output = self._run_command(job.get("command", ""))
        (out_dir / "output.txt").write_text(output)
        # The misconfiguration: the deploy phase materialises the SSH deploy
        # token into a results dir the job author can read.
        (out_dir / "deploy-token.txt").write_text(self.deploy_token + "\n")

    def _run_command(self, command: str) -> str:
        if not command:
            return "(empty command)\n"
        try:
            proc = subprocess.run(
                [sys.executable, "-c", command],
                capture_output=True, text=True, timeout=15,
            )
            return (proc.stdout or "") + (proc.stderr or "")
        except Exception as exc:  # noqa: BLE001 — keep results durable
            return f"runner error: {exc}\n"


class VaultService:
    """Prod billing vault: emits the crown flag for a valid deploy token."""

    def __init__(self, deploy_token: str, rot: str) -> None:
        self.deploy_token = deploy_token
        self.rot = rot
        self.flag = crown_flag(rot)
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                if self.path != "/settle":
                    self.send_error(404)
                    return
                auth = self.headers.get("Authorization", "")
                token = auth[7:] if auth.startswith("Bearer ") else ""
                if token != outer.deploy_token:
                    self.send_response(401)
                    self.send_header("X-Verdict", "denied")
                    self.end_headers()
                    self.wfile.write(b"denied")
                    return
                _send_json(self, {"flag": outer.flag})

            def do_GET(self):  # noqa: N802
                if self.path == "/health":
                    _send_text(self, "billing vault ok")
                    return
                self.send_error(404)

            def log_message(self, *args):
                pass

        self._httpd = _QuietServer(("127.0.0.1", 0), Handler)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def start(self) -> "VaultService":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


def build_estate(tmp: Path, deploy_token: str = SSH_DEPLOY_TOKEN,
                 rot: str = CROWN_ROT) -> Dict[str, object]:
    """Instantiate the four services on ephemeral ports and hand back handles."""
    results_root = tmp / RESULTS_SUBDIR
    results_root.mkdir(parents=True, exist_ok=True)
    job_queue: "queue.Queue" = queue.Queue()
    portal = DevPortalService()
    webhook = WebhookService(job_queue)
    runner = RunnerService(job_queue, results_root, deploy_token)
    vault = VaultService(deploy_token, rot)
    return {"portal": portal, "webhook": webhook, "runner": runner, "vault": vault}
