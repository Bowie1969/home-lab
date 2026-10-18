#!/usr/bin/env python3
"""keystone_flow_events.py — live flow-JSON -> Keystone dashboard edge traffic.

A passive adapter, modelled on scripts/evilkit_bridge.py: it polls classified
flow JSON (the podman monitor's output path and/or the brain's
``/run/keystone-flows.json``, the latter read as a local file or fetched with
``ssh $KEYSTONE_BRAIN_SSH cat /run/keystone-flows.json``) and appends compact
edge-traffic events to a prepared Keystone run so the live dashboard draws a
coloured, auto-expiring edge while a flow is active.

It NEVER launches anything or opens any connection beyond that single read-only
``cat`` over SSH. It only observes flow tuples already classified by the monitor
and re-colours the matching graph edge; it copies no payload, credential or flag.

Flow JSON consumed (the format written by keystone_flow_monitor.py):

    {"generated": ..., "window": 6, "flows": [
        {"src": "10.50.0.14", "dst": "10.50.0.13", "dport": 80, "proto": "tcp",
         "class": "attack", "pkts": 5, "bytes": 600, "age": 0.3}]}

Only flows whose ``class`` is one of recon/attack/tunnel/data are emitted (a
``normal`` flow stays on the baseline). IPs are mapped to node ids through the
run's dashboard/topology.json, resolving BOTH the logical ``ip`` (10.80.x) and
the ``real_ip`` (10.50.0.x, with its " (real, ...)" suffix stripped) to the same
node, so a flow between 10.50.0.14 and 10.50.0.13 lights vault-keystone /
ks-intranet01 exactly as their logical 10.80.30.20 / 10.80.20.24 would.

Each active flow re-emits an event (rate-limited to ~1/sec per src/dst/class
pair) so the server keeps the edge live inside its ~6s activity window, and lets
it lapse once the flow stops. The run stays ``running`` and flips to ``finished``
after ~45s with no flows.

Usage:
  python3 keystone_flow_events.py /path/to/podman/flows.json \\
      --run-dir ~/Projects/keystone-range/runs/<run_id>
  python3 keystone_flow_events.py brain ssh:/run/keystone-flows.json \\
      --run-dir ~/Projects/keystone-range/runs/<run_id>
  # a bare local path reads a file; ``brain`` fetches the brain's default path
  # over SSH; ``ssh:/remote/path`` fetches a specific remote path. KEYSTONE_BRAIN_SSH
  # supplies the ssh args (e.g. "-i ~/.ssh/id_ed25519_labvm root@192.168.0.240").
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import time
from pathlib import Path
from typing import Any, Optional

RANGE = "keystone"
POLL_SECS = 2.0
STATUS_HEARTBEAT_SECS = 4.0
IDLE_FINISH_SECS = 45.0       # no active flow for this long -> mark run finished
DEDUP_SECS = 1.0              # min seconds between identical pair/class re-emits
TRAFFIC_CLASSES = {"recon", "attack", "tunnel", "data"}
BRAIN_FLOWS_REMOTE = "/run/keystone-flows.json"
_IP_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")


def first_ip(text: Any) -> Optional[str]:
    """Leading IPv4 token of a field such as ``10.50.0.14 (real, on ...)``."""
    if not text:
        return None
    m = _IP_RE.search(str(text))
    return m.group(0) if m else None


def load_ip_map(topology: dict) -> dict[str, str]:
    """IP -> node id from a run's topology, for both ``ip`` and ``real_ip``."""
    out: dict[str, str] = {}
    for node in topology.get("nodes", []):
        nid = node.get("id")
        if not nid:
            continue
        for field in ("ip", "real_ip"):
            ip = first_ip(node.get(field))
            if ip:
                out[ip] = str(nid)
    return out


def event_name(cls: str) -> str:
    """Map a flow class to the operator-vocabulary event the dashboard knows."""
    return "recon" if cls == "recon" else "exploit"


def flow_to_event(flow: dict, ip2node: dict[str, str], run_id: str,
                  now: float) -> Optional[dict]:
    """Build one edge-traffic event from a classified flow, or None to skip."""
    cls = str(flow.get("class") or flow.get("traffic_class") or "")
    if cls not in TRAFFIC_CLASSES:
        return None
    src_ip = flow.get("src")
    dst_ip = flow.get("dst")
    src = ip2node.get(src_ip or "")
    dst = ip2node.get(dst_ip or "")
    if not src or not dst or src == dst:
        return None

    edge: dict[str, Any] = {
        "src": src, "dst": dst, "traffic_class": cls, "direction": "forward",
    }
    # flows have no MCP tool; the port/proto go in evidence, not on the edge.

    detail = f"{cls} flow {src_ip}->{dst_ip}"
    dport = flow.get("dport")
    proto = flow.get("proto")
    if dport is not None:
        detail += f":{dport}/{proto}" if proto else f":{dport}"

    return {
        "run_id": run_id,
        "ts": now,
        "host": dst_ip,                 # the destination host being touched
        "node": dst,                    # ...mapped to its topology node id
        "event": event_name(cls),
        "evidence": detail,
        "status": "running",
        "edge": edge,
    }


class FlowSource:
    def read(self) -> list[dict]:
        raise NotImplementedError


class LocalFlowSource(FlowSource):
    def __init__(self, path: str) -> None:
        self.path = Path(path).expanduser()

    def read(self) -> list[dict]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        if not isinstance(data, dict):
            return []
        flows = data.get("flows", [])
        return flows if isinstance(flows, list) else []


class SshFlowSource(FlowSource):
    def __init__(self, ssh_args: list[str], remote_path: str) -> None:
        self.ssh_args = ssh_args
        self.remote_path = remote_path

    def read(self) -> list[dict]:
        cmd = ["ssh", *self.ssh_args, "cat", self.remote_path]
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
        except (OSError, subprocess.TimeoutExpired):
            return []
        if out.returncode != 0:
            return []
        try:
            data = json.loads(out.stdout)
        except ValueError:
            return []
        if not isinstance(data, dict):
            return []
        flows = data.get("flows", [])
        return flows if isinstance(flows, list) else []


def default_run_dir() -> Optional[Path]:
    env = os.environ.get("KEYSTONE_DASHBOARD_RUN_DIR")
    if env:
        return Path(env).expanduser()
    runs = Path.home() / "Projects" / "keystone-range" / "runs"
    if not runs.is_dir():
        return None
    candidates = [d for d in runs.iterdir()
                  if (d / "dashboard" / "topology.json").is_file() and d.name != "live-brain"]
    if not candidates:
        return None
    return max(candidates, key=lambda d: d.stat().st_mtime)


def build_sources(specs: list[str]) -> list[FlowSource]:
    sources: list[FlowSource] = []
    for spec in specs:
        if spec == "brain":
            sources.append(SshFlowSource(shlex.split(os.environ.get("KEYSTONE_BRAIN_SSH", "")),
                                         BRAIN_FLOWS_REMOTE))
        elif spec.startswith("ssh:"):
            remote = spec[4:] or BRAIN_FLOWS_REMOTE
            sources.append(SshFlowSource(shlex.split(os.environ.get("KEYSTONE_BRAIN_SSH", "")),
                                         remote))
        else:
            sources.append(LocalFlowSource(spec))
    return sources


class FlowBridge:
    def __init__(self, run_dir: Path, model: str, sources: list[FlowSource]) -> None:
        self.run_dir = Path(run_dir)
        self.dashboard = self.run_dir / "dashboard"
        self.dashboard.mkdir(parents=True, exist_ok=True)
        self.events_path = self.dashboard / "events.jsonl"
        self.status_path = self.dashboard / "status.json"
        self.run_id = self.run_dir.name
        self.model = model
        self.sources = sources
        self.ip2node: dict[str, str] = self._load_nodes()
        self._started_iso = time.strftime("%Y-%m-%dT%H:%M:%S")
        self._last_status = 0.0
        self._last_flow_ts: Optional[float] = None
        self._state = "running"
        self._last_emit: dict[tuple[str, str, str], float] = {}
        self._last_step: dict[str, Any] = {"detail": "flow bridge attached; waiting for traffic"}

    def _load_nodes(self) -> dict[str, str]:
        try:
            topo = json.loads((self.dashboard / "topology.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return load_ip_map(topo)

    def _append(self, record: dict) -> None:
        record.setdefault("run_id", self.run_id)
        record.setdefault("ts", time.time())
        with self.events_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, separators=(",", ":")) + "\n")

    def write_status(self, force: bool = False) -> None:
        now = time.time()
        if not force and now - self._last_status < STATUS_HEARTBEAT_SECS:
            return
        self._last_status = now
        status = {
            "run_id": self.run_id, "range": RANGE, "state": self._state,
            "started": self._started_iso, "model": self.model, "score": None,
            "flags": [], "current_step": self._last_step,
        }
        tmp = self.status_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(status, indent=2), encoding="utf-8")
        os.replace(tmp, self.status_path)

    def emit_flow(self, flow: dict, now: float) -> Optional[dict]:
        event = flow_to_event(flow, self.ip2node, self.run_id, now)
        if event is None:
            return None
        edge = event["edge"]
        key = (edge["src"], edge["dst"], edge["traffic_class"])
        last = self._last_emit.get(key)
        if last is not None and now - last < DEDUP_SECS:
            return None
        self._last_emit[key] = now
        self._append(event)
        return event

    def poll_once(self) -> None:
        """One poll tick: read every source, emit active-flow events, heartbeat."""
        now = time.time()
        flows: list[dict] = []
        for source in self.sources:
            flows.extend(source.read())

        active = [f for f in flows if (f.get("class") or f.get("traffic_class")) in TRAFFIC_CLASSES]
        if active:
            self._last_flow_ts = now
            if not self.ip2node:
                self.ip2node = self._load_nodes()
            emitted = sum(1 for flow in active if self.emit_flow(flow, now) is not None)
            self._last_step = {"detail": f"{emitted} flow edge(s) live"}

        if (self._state != "finished" and self._last_flow_ts is not None
                and now - self._last_flow_ts > IDLE_FINISH_SECS and not active):
            self._state = "finished"
            self._last_step = {"detail": "no flows for 45s; engagement idle"}
            self.write_status(force=True)
        else:
            self.write_status()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("sources", nargs="*",
                    help="flow JSON sources: a local path, 'brain', or 'ssh:/remote/path' "
                         "(default: 'brain' if KEYSTONE_BRAIN_SSH is set)")
    ap.add_argument("--run-dir", default=None,
                    help="Keystone runs/<id> to receive events "
                         "(default: KEYSTONE_DASHBOARD_RUN_DIR or newest run)")
    ap.add_argument("--model", default="keystone-flow-events",
                    help="model label for status.json")
    ap.add_argument("--poll", type=float, default=POLL_SECS, help="poll interval, seconds")
    ap.add_argument("--idle", type=float, default=IDLE_FINISH_SECS,
                    help="seconds without flows before the run flips to finished")
    args = ap.parse_args(argv)

    run_dir = Path(args.run_dir).expanduser() if args.run_dir else default_run_dir()
    if run_dir is None or not (run_dir / "dashboard" / "topology.json").is_file():
        print(f"error: no usable run dir (got {run_dir}); run bin/reset.sh first or pass --run-dir",
              flush=True)
        return 2

    specs = args.sources
    if not specs:
        ssh_env = os.environ.get("KEYSTONE_BRAIN_SSH")
        specs = ["brain"] if ssh_env else [os.environ.get("KEYSTONE_FLOWS_PATH", "/run/keystone-flows.json")]
    sources = build_sources(specs)
    if not sources:
        print("error: no flow sources", flush=True)
        return 2

    bridge = FlowBridge(run_dir, args.model, sources)
    bridge.write_status(force=True)   # flip the run active so the dashboard switches
    print(f"keystone-flow-events: polling {len(sources)} source(s) -> {run_dir}", flush=True)
    try:
        while True:
            bridge.poll_once()
            time.sleep(args.poll)
    except KeyboardInterrupt:
        print("keystone-flow-events: stopped", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
