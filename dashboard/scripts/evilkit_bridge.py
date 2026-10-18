#!/usr/bin/env python3
"""evilkit_bridge.py — live EvilKit/evilqwen trace -> Keystone dashboard run.

A passive adapter, modelled on scripts/zypheron_bridge.py: it tails an evilqwen
brain trace (the JSONL written by `--trace`) and appends compact, evidence-safe
visualisation events to a prepared Keystone run so the live dashboard renders the
operator's activity. It NEVER copies command output, credentials, flags, or model
reasoning — only the action class, the target node, and the exit/verdict status.

What it produces on the run (from the trace's intention/execute/auditor events,
correlated per turn):
  * edge traffic per action — recon / attack / tunnel(SSH) — with the MCP tool
    name attached, so coloured + animated flow shows while the action is live
    (auto-expires after the server's 6s activity window when the action stops).
  * host_compromised — when an attack-class action returns rc=0 and the auditor
    did not dispute it; lights the victim node red + the incident overlay.
  * agent_on_host — follows the operator's current/pivot host.
  * a `running` status heartbeat, so find_live_run() switches the dashboard to
    this run (an idle published run otherwise loses to live-brain).

It launches nothing and opens no network connections. A missing run or trace is a
no-op. Trace tailing is by byte offset (never `tail -f`) and tolerates rotation.

Usage:
  python3 evilkit_bridge.py --trace ~/evilqwen-run.jsonl \
      --run-dir ~/Projects/keystone-range/runs/<run_id>
  # --run-dir defaults to EVILKIT_DASHBOARD_RUN_DIR or the newest keystone run.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import time
from pathlib import Path
from typing import Any, Optional

RANGE = "keystone"
POLL_SECS = 0.5
STATUS_HEARTBEAT_SECS = 4.0
IDLE_FINISH_SECS = 45.0   # no trace activity for this long -> mark run finished
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Action classification. Attack markers win over the SSH/tunnel marker so that an
# SSH *brute force* (hydra/nxc ssh) reads as an attack, while a plain SSH session
# or forward reads as a tunnel/pivot.
_ATTACK_MARKERS = ("sqlmap", "exploit", "hydra", "netexec", "nxc", "crackmap",
                   "smbclient", "metasploit", "msfconsole", "msfvenom", "impacket",
                   "hashcat", "john", "evil-winrm", "responder")
_TUNNEL_MARKERS = ("ssh", "sshpass", "socat", "chisel", "proxychains")
_RECON_MARKERS = ("nmap", "nuclei", "ffuf", "gobuster", "masscan", "ping", "curl",
                  "wget", "dig", "whatweb", "nikto", "enum4linux", "rpcclient",
                  "smbmap", "ldapsearch", "dirb", "wpscan")


def classify(text: str) -> str:
    low = text.lower()
    if any(m in low for m in _ATTACK_MARKERS):
        return "attack"
    if any(re.search(rf"\b{re.escape(m)}\b", low) for m in _TUNNEL_MARKERS):
        return "tunnel"
    if any(m in low for m in _RECON_MARKERS):
        return "recon"
    return "recon"


def first_ip(*texts: str) -> Optional[str]:
    for t in texts:
        if not t:
            continue
        m = _IP_RE.search(t)
        if m:
            return m.group(0)
    return None


def tool_label(tool: Any, command: str) -> str:
    """MCP tool name when the action was a tool call, else the command's verb."""
    if isinstance(tool, dict) and tool:
        for key in ("name", "tool", "tool_name", "function"):
            val = tool.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
        # {"function": {"name": ...}} shape
        fn = tool.get("function")
        if isinstance(fn, dict) and isinstance(fn.get("name"), str):
            return fn["name"].strip()
        first = next(iter(tool), "")
        if isinstance(first, str) and first:
            return first
    if command.strip():
        return command.strip().split()[0]
    return "action"


def default_run_dir() -> Optional[Path]:
    env = os.environ.get("EVILKIT_DASHBOARD_RUN_DIR")
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


class Bridge:
    def __init__(self, run_dir: Path, entry_node: str, model: str) -> None:
        self.run_dir = run_dir
        self.dashboard = run_dir / "dashboard"
        self.dashboard.mkdir(parents=True, exist_ok=True)
        self.events_path = self.dashboard / "events.jsonl"
        self.status_path = self.dashboard / "status.json"
        self.run_id = run_dir.name
        self.model = model
        self.entry_node = entry_node
        self.current_node = entry_node       # operator's current host; pivots on compromise
        self.compromised: set[str] = set()
        self.ip2node = self._load_nodes()
        self.pending: dict[int, dict] = {}   # turn -> intention context awaiting rc/verdict
        self._started_iso = time.strftime("%Y-%m-%dT%H:%M:%S")
        self._last_status = 0.0
        self._last_step = {"detail": "evilqwen bridge attached; waiting for first action"}
        self._last_activity = time.time()
        self._seen = False
        self._state = "running"

    def _load_nodes(self) -> dict[str, str]:
        try:
            topo = json.loads((self.dashboard / "topology.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        out: dict[str, str] = {}
        for n in topo.get("nodes", []):
            nid = n.get("id")
            if not nid:
                continue
            for field in ("ip", "address"):
                for ip in _IP_RE.findall(str(n.get(field) or "")):
                    out[ip] = str(nid)
        return out

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

    def on_tick(self) -> None:
        """Called every poll: heartbeat while active, then finish on idle so the
        dashboard releases this run back to live-brain when the engagement ends."""
        if self._state == "finished":
            return
        now = time.time()
        if self._seen and now - self._last_activity > IDLE_FINISH_SECS:
            self._state = "finished"
            self._last_step = {"detail": "evilqwen run idle; engagement ended"}
            self.write_status(force=True)
        else:
            self.write_status()

    # -- trace handlers --------------------------------------------------------
    def on_intention(self, turn: int, data: dict) -> None:
        command = str(data.get("command") or "")
        tool = data.get("tool")
        target_ip = first_ip(command, json.dumps(tool) if tool else "")
        if not self.ip2node:
            self.ip2node = self._load_nodes()
        target_node = self.ip2node.get(target_ip or "")
        activity = classify(command + " " + (json.dumps(tool) if tool else ""))
        tname = tool_label(tool, command)
        self.pending[turn] = {"target_ip": target_ip, "target_node": target_node,
                              "activity": activity, "tool": tname}
        self._last_step = {"detail": f"turn {turn}: {activity} via {tname}"
                           + (f" -> {target_node}" if target_node else "")}
        if not target_node or target_node == self.current_node:
            self.write_status()
            return
        # Live traffic edge for this action (MCP tool attached). status=running so
        # it shows connected now and the server expires it after its activity window.
        self._append({
            "host": target_ip, "node": target_node,
            "event": "recon" if activity == "recon" else "exploit",
            "evidence": f"operator {activity} action in progress ({tname})",
            "status": "running",
            "edge": {"src": self.current_node, "dst": target_node,
                     "traffic_class": activity, "mcp_tool": tname, "tool": tname,
                     "direction": "forward"},
        })
        self.write_status()

    def on_execute(self, turn: int, data: dict) -> None:
        ctx = self.pending.get(turn)
        if ctx is not None:
            ctx["returncode"] = data.get("returncode")

    def on_auditor(self, turn: int, data: dict) -> None:
        ctx = self.pending.pop(turn, None)
        if not ctx:
            return
        verdict = str(data.get("verdict") or "").upper()
        rc = ctx.get("returncode")
        node = ctx.get("target_node")
        if not node:
            return
        succeeded = (rc == 0) and verdict in ("CONTINUE", "ADVISE", "")
        if ctx["activity"] == "attack" and succeeded and node not in self.compromised:
            self.compromised.add(node)
            self._append({
                "host": ctx.get("target_ip"), "node": node, "event": "host_compromised",
                "evidence": f"attack action returned rc=0; auditor {verdict or 'n/a'}",
            })
            # operator pivots onto the freshly compromised host
            self.current_node = node
            self._append({
                "host": ctx.get("target_ip"), "node": node, "event": "agent_on_host",
                "evidence": "operator now acting from this host",
            })
        self.write_status()

    def handle(self, obj: dict) -> None:
        self._last_activity = time.time()
        self._seen = True
        if self._state != "running":   # resumed after an idle gap
            self._state = "running"
        kind = obj.get("kind")
        turn = int(obj.get("turn") or 0)
        data = obj.get("data") if isinstance(obj.get("data"), dict) else {}
        if kind == "intention":
            self.on_intention(turn, data)
        elif kind == "execute":
            self.on_execute(turn, data)
        elif kind == "auditor":
            self.on_auditor(turn, data)
        # state_delta / blocked carry no new node-level signal we can use safely.


def tail(path: Path, from_start: bool, on_line, on_tick=None) -> None:
    """Byte-offset tailer: resilient to rotation/truncation, buffers partial lines."""
    offset = 0 if from_start else (path.stat().st_size if path.is_file() else 0)
    buf = b""
    while True:
        try:
            size = path.stat().st_size if path.is_file() else 0
            if size < offset:        # rotated/truncated
                offset, buf = 0, b""
            if size > offset:
                with path.open("rb") as fh:
                    fh.seek(offset)
                    chunk = fh.read()
                    offset = fh.tell()
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        on_line(json.loads(line.decode("utf-8", "replace")))
                    except ValueError:
                        pass
        except OSError:
            pass
        if on_tick is not None:
            on_tick()
        time.sleep(POLL_SECS)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--trace", required=True, help="evilqwen --trace JSONL to tail")
    ap.add_argument("--run-dir", default=None,
                    help="Keystone runs/<id> to receive events (default: EVILKIT_DASHBOARD_RUN_DIR or newest run)")
    ap.add_argument("--entry-node", default=os.environ.get("EVILKIT_ENTRY_NODE", "attacker"),
                    help="topology node id the operator starts from (default: attacker)")
    ap.add_argument("--model", default="evilqwen", help="model label for status.json")
    ap.add_argument("--from-start", action="store_true",
                    help="replay the trace from the beginning (default: tail new lines only)")
    ap.add_argument("--no-full-topology", action="store_true",
                    help="do NOT publish the full designed range into the run on startup "
                         "(default: publish it so every labelled host shows, live or not)")
    args = ap.parse_args(argv)

    run_dir = Path(args.run_dir).expanduser() if args.run_dir else default_run_dir()
    if run_dir is None or not (run_dir / "dashboard" / "topology.json").is_file():
        print(f"error: no usable run dir (got {run_dir}); run bin/reset.sh first or pass --run-dir",
              flush=True)
        return 2
    trace = Path(args.trace).expanduser()

    # Show the whole designed range (not just the modules that came up) by
    # publishing build/topology.json into the run before we start.
    if not args.no_full_topology:
        try:
            from keystone_full_topology import publish_full
            count = publish_full(run_dir)
            if count:
                print(f"evilkit-bridge: published full topology ({count} nodes)", flush=True)
        except Exception as exc:  # best-effort; never block the run
            print(f"evilkit-bridge: full-topology publish skipped ({exc})", flush=True)

    bridge = Bridge(run_dir, args.entry_node, args.model)
    bridge.write_status(force=True)   # flip the run active immediately so the dashboard switches
    print(f"evilkit-bridge: tailing {trace} -> {run_dir} (entry={args.entry_node})", flush=True)
    try:
        tail(trace, args.from_start, bridge.handle, bridge.on_tick)
    except KeyboardInterrupt:
        print("evilkit-bridge: stopped", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
