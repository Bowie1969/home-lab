#!/usr/bin/env python3
"""evilkimi_session_bridge.py — republish a live evilkimi session onto the dashboard.

`evilkimi` writes dashboard telemetry only when it was launched with
--dashboard-run-dir, so a session already in flight has no run dir and the board
shows nothing however much the operator owns. This bridge reads the session's own
hook log — ~/.local/state/evilkimi/sessions/session_<id>.jsonl, which
evilkit.kimihook writes whether or not a dashboard run was ever configured — and
republishes it into a Keystone run:

  * one coloured edge per action (recon / attack), the tool name attached, aimed
    at the innermost range host the command acted on (the seat the operator hops
    through is never a target);
  * host_compromised only where the recorded exit status proves access was gained
    on that host — an ssh session opened onto it, or an attack tool aimed at it
    that returned 0. An exploit attempt (a command-execution request whose only
    evidence is curl's exit code) colours the edge as attack traffic but never
    repaints the host;
  * agent_on_host when the operator pivots onto a freshly owned host;
  * a `running` status heartbeat, so find_live_run() promotes this run over the
    idle live-brain view.

It follows whichever session log is live, so an operator session that restarts
mid-run (supervisor relaunch, resumed session) keeps publishing to the same run.

Like evilkit_bridge.py it carries no command output, credentials, flags or model
reasoning — only the action class, the target and the exit status.

Usage:
  python3 evilkimi_session_bridge.py                       # live session -> its run dir
  python3 evilkimi_session_bridge.py --session PATH --run-dir RUN --from-start
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evilkit_bridge import classify  # noqa: E402

RUNS_DIR = Path.home() / "Projects" / "keystone-range" / "runs"
LIVE_BRAIN_TOPO = RUNS_DIR / "live-brain" / "dashboard" / "topology.json"
POLL_SECS = 0.5
STATUS_HEARTBEAT_SECS = 4.0
TOPO_SYNC_SECS = 30.0
IDLE_FINISH_SECS = float(os.environ.get("EVILKIMI_BRIDGE_IDLE_SECS", "900"))
# Attacker-side seats: the drop, the operator box, the mesh hub. These are the
# positions the operator works FROM, never targets, so they are never marked owned.
OPERATOR_NODE_IDS = {"pi-drop", "parrot-operator", "mesh-hub"}

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# ssh-family clients open an authenticated channel on the host they are pointed
# at. The client's own arguments end where the quoted remote command begins, so
# the destination is either the `user@host` form or the last bare token.
SSH_CLIENTS = ("sshpass", "ssh", "sshuttle", "evil-winrm", "wmiexec", "psexec",
               "smbexec", "atexec", "rdesktop", "xfreerdp")
# Attack tools that name the host they hit in their own arguments. Deliberately a
# small list of tools whose exit status means something; the word "exploit" in a
# shell comment is not a tool.
ATTACK_CLIENTS = ("sqlmap", "hydra", "netexec", "nxc", "crackmapexec", "cme",
                  "smbclient", "smbmap", "msfconsole", "msfvenom", "impacket-wmiexec",
                  "impacket-psexec", "impacket-smbexec", "impacket-atexec", "responder",
                  "enum4linux", "kerbrute", "certipy", "bloodhound-python")
# A command-execution request: a POST/`-d` body carrying a command field.
_EXEC_REQUEST_RE = re.compile(
    r"(?:-X|--request)\s*POST|(?:^|\s)-d(?=\s)|--data(?:-raw|-binary|-urlencode)?(?=\s)",
    re.IGNORECASE)
_EXEC_FIELD_RE = re.compile(r"""["']?(?:cmd|command|exec|shell|run|payload)["']?\s*[:=]""",
                            re.IGNORECASE)


def _split_statements(text: str) -> list[str]:
    """Top-level shell statements: split on unquoted ; && || | and newlines."""
    parts: list[str] = []
    buf: list[str] = []
    quote = ""
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text):
            buf.append(text[index:index + 2])
            index += 2
            continue
        if quote:
            if char == quote:
                quote = ""
            buf.append(char)
            index += 1
            continue
        if char in "'\"":
            quote = char
            buf.append(char)
            index += 1
            continue
        if char == "\n" or char == ";":
            parts.append("".join(buf))
            buf = []
            index += 1
            continue
        if char in "&|" and (char == "|" or (index + 1 < len(text) and text[index + 1] == char)):
            parts.append("".join(buf))
            buf = []
            index += 2 if index + 1 < len(text) and text[index + 1] == char else 1
            continue
        buf.append(char)
        index += 1
    parts.append("".join(buf))
    return [part.strip() for part in parts if part.strip()]


def _without_comments(statement: str) -> str:
    """Drop unquoted `#` comments — a phrase in a comment is not an action."""
    out: list[str] = []
    quote = ""
    index = 0
    while index < len(statement):
        char = statement[index]
        if char == "\\" and index + 1 < len(statement):
            out.append(statement[index:index + 2])
            index += 2
            continue
        if quote:
            if char == quote:
                quote = ""
            out.append(char)
            index += 1
            continue
        if char in "'\"":
            quote = char
            out.append(char)
            index += 1
            continue
        if char == "#" and (index == 0 or statement[index - 1].isspace()):
            break
        out.append(char)
        index += 1
    return "".join(out).strip()


def final_statement(command: str) -> str:
    """The statement the recorded returncode speaks for.

    The hook records one exit status for the whole call, and a shell reports only
    its LAST top-level statement's status. Anything earlier ran, but whether it
    worked is not knowable from this record — so nothing earlier can be presented
    as proof of access.
    """
    statements = _split_statements(command)
    return statements[-1] if statements else ""


def _client_invocation(statement: str, clients: tuple[str, ...]) -> Optional[tuple[str, str]]:
    """The first client invocation in a statement: (verb, its own arguments).

    Matched on whole tokens only. Command text that merely *quotes* a client call
    — a payload inside `-d '{"cmd": "ssh ..."}'` — arrives glued to quotes and
    backslashes, so it is not an invocation of anything on this shell.
    """
    tokens = _without_comments(statement).split()
    for index, token in enumerate(tokens):
        verb = token.rsplit("/", 1)[-1]
        if verb in clients:
            return verb, _client_arguments(" ".join(tokens[index + 1:]))
    return None


def _client_arguments(invocation: str) -> str:
    """A client invocation's own arguments, up to its quoted remote command."""
    cut = len(invocation)
    for quote in ("'", '"'):
        index = invocation.find(quote)
        if index != -1:
            cut = min(cut, index)
    return invocation[:cut]


def ssh_destination(statement: str, ip: str) -> bool:
    """True when `ip` is the host an ssh-family client in this statement connects TO."""
    invocation = _client_invocation(statement, SSH_CLIENTS)
    if invocation is None:
        return False
    arguments = invocation[1].strip()
    if re.search(rf"(?<![\w.-])[\w.-]+@{re.escape(ip)}(?![\w.-])", arguments):
        return True
    tokens = arguments.split()
    return bool(tokens) and tokens[-1] == ip


def attack_aimed_at(statement: str, ip: str) -> bool:
    """True when an attack tool is invoked in this statement against `ip`."""
    invocation = _client_invocation(statement, ATTACK_CLIENTS)
    return invocation is not None and ip in invocation[1].split()


def exec_request(command: str, ip: str) -> bool:
    """True when the command sends a command-execution payload to `ip`.

    curl reports success for an HTTP error too, so this is an attempted exploit
    on the host, never proof that the host is owned.
    """
    if not (_EXEC_REQUEST_RE.search(command) and _EXEC_FIELD_RE.search(command)):
        return False
    return re.search(rf"(?<![\d.]){re.escape(ip)}(?![\d.])", command) is not None


def action_target(command: str, statement: str,
                  ip2node: dict[str, str]) -> tuple[Optional[str], Optional[str]]:
    """The range host an action acted on.

    Prefer the host the final statement is aimed at (an ssh destination, an
    attack tool's argument, a command-execution URL) — that is what the exit
    status speaks about. With no such host, fall back to the last range address
    the command mentions, so a probe through a seat still draws its edge.
    """
    for ip in _IP_RE.findall(statement):
        if ip in ip2node and (ssh_destination(statement, ip)
                              or attack_aimed_at(statement, ip)
                              or exec_request(command, ip)):
            return ip, ip2node[ip]
    mentioned = [ip for ip in _IP_RE.findall(command) if ip in ip2node]
    if not mentioned:
        return None, None
    return mentioned[-1], ip2node[mentioned[-1]]


def ownership(target_ip: str, statement: str, returncode) -> Optional[str]:
    """Why this action proves the target host is owned, or None.

    Only access actually gained counts, and only where the recorded exit status
    speaks for it: an ssh session opened onto the host, or an attack tool aimed at
    it that returned 0. A scan, an attempted exploit, and anything the status does
    not cover are never a compromise.
    """
    if returncode != 0:
        return None
    if ssh_destination(statement, target_ip):
        return "ssh session opened onto the host (exit 0)"
    if attack_aimed_at(statement, target_ip):
        return "attack tool aimed at the host succeeded (exit 0)"
    return None


def state_root() -> Path:
    override = os.environ.get("EVILKIT_STATE_DIR")
    if override:
        return Path(os.path.expanduser(override))
    return Path.home() / ".local" / "state" / "evilkimi"


def _has_actions(path: Path) -> bool:
    """True when the log carries at least one executed action (not a bare start)."""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if '"kind": "action"' in line or '"kind":"action"' in line:
                    return True
    except OSError:
        return False
    return False


def discover_session(root: Optional[Path] = None) -> Optional[Path]:
    """Newest session log that actually carries actions."""
    sessions = (root or state_root()) / "sessions"
    if not sessions.is_dir():
        return None
    files = sorted(sessions.glob("session_*.jsonl"))
    if not files:
        return None
    active = [p for p in files if _has_actions(p)]
    return max(active or files, key=lambda p: p.stat().st_mtime)


class Bridge:
    def __init__(self, run_dir: Path, session_id: str, entry_node: str, model: str,
                 sync_topology: bool = True) -> None:
        self.run_dir = Path(run_dir).expanduser()
        self.dashboard = self.run_dir / "dashboard"
        self.dashboard.mkdir(parents=True, exist_ok=True)
        self.events_path = self.dashboard / "events.jsonl"
        self.status_path = self.dashboard / "status.json"
        self.run_id = self.run_dir.name
        self.session_id = session_id
        self.model = model
        self.current_node = entry_node
        self.sync = sync_topology
        self.compromised: dict[str, dict] = {}
        self.ip2node: dict[str, str] = {}
        self.nodes: dict[str, dict] = {}
        self.actions = 0
        self._started_iso = time.strftime("%Y-%m-%dT%H:%M:%S")
        self._last_status = 0.0
        self._last_sync = 0.0
        self._last_activity = time.time()
        self._state = "running"
        self.load_topology()

    # ---------------------------------------------------------------- topology
    def load_topology(self) -> None:
        try:
            topo = json.loads((self.dashboard / "topology.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            topo = {"nodes": []}
        ip2node: dict[str, str] = {}
        nodes: dict[str, dict] = {}
        for node in topo.get("nodes", []):
            nid = node.get("id")
            if not nid:
                continue
            address = str(node.get("address") or node.get("ip") or "")
            nodes[nid] = {"id": nid, "label": node.get("label") or nid, "address": address}
            if nid in OPERATOR_NODE_IDS:
                continue                      # seats are sources, never targets
            for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", address):
                ip2node.setdefault(ip, nid)
        self.ip2node = ip2node
        self.nodes = nodes

    def sync_topology(self) -> None:
        """Keep node ids/addresses current from the live-brain view."""
        now = time.time()
        if not self.sync or now - self._last_sync < TOPO_SYNC_SECS:
            return
        self._last_sync = now
        dst = self.dashboard / "topology.json"
        try:
            if LIVE_BRAIN_TOPO.stat().st_mtime <= dst.stat().st_mtime:
                return
            data = LIVE_BRAIN_TOPO.read_text(encoding="utf-8")
            tmp = dst.with_suffix(".tmp")
            tmp.write_text(data, encoding="utf-8")
            tmp.replace(dst)
        except OSError:
            return
        self.load_topology()

    # ------------------------------------------------------------------ output
    def _append(self, payload: dict) -> dict:
        record = {"run_id": self.run_id}
        record.update(payload)
        with self.events_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return record

    def write_status(self, force: bool = False) -> None:
        now = time.time()
        if not force and now - self._last_status < STATUS_HEARTBEAT_SECS:
            return
        self._last_status = now
        status = {
            "run_id": self.run_id,
            "range": "keystone",
            "state": self._state,
            "started": self._started_iso,
            "model": self.model,
            "score": None,
            "flags": [],
            "source": "evilkimi_session_bridge",
            "session_id": self.session_id,
            "compromised_hosts": list(self.compromised.values()),
            "current_step": {
                "detail": (f"evilkimi session {self.session_id[:8]} · {self.actions} actions · "
                           f"{len(self.compromised)} host(s) owned"),
                "agent_host": self.current_node,
            },
        }
        tmp = self.status_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(status, indent=2), encoding="utf-8")
        tmp.replace(self.status_path)

    # ------------------------------------------------------------------ events
    def compromise(self, ip: str, node: str, tool: str, ts: float, why: str) -> None:
        if node in self.compromised:
            return
        self.compromised[node] = self.nodes.get(node) or {"id": node, "label": node, "address": ip}
        self._append({
            "ts": ts, "source": "evilkimi", "session_id": self.session_id,
            "host": ip, "node": node, "event": "host_compromised",
            "evidence": f"{why} via {tool or 'tool'}",
        })
        # The operator now works from the newly owned host.
        self.current_node = node
        self._append({
            "ts": ts, "source": "evilkimi", "session_id": self.session_id,
            "host": ip, "node": node, "event": "agent_on_host",
            "evidence": "operator pivoted onto the newly owned host",
        })

    def handle(self, record: dict) -> None:
        if record.get("kind") != "action":
            return                      # only PostToolUse carries the exit status
        command = str(record.get("command") or "")
        tool = str(record.get("tool") or "")
        if not command:
            return
        rc = record.get("returncode")
        statement = final_statement(command)
        target_ip, target_node = action_target(command, statement, self.ip2node)
        if not target_node:
            return
        activity = classify(f"{tool} {command}")
        attempt = exec_request(command, target_ip)
        ts = float(record.get("ts") or time.time())
        self._last_activity = time.time()
        self._state = "running"
        self.actions += 1
        owned_because = ownership(target_ip, statement, rc)
        access = bool(owned_because)
        attack = activity == "attack" or access or attempt
        payload = {
            "ts": ts, "source": "evilkimi", "session_id": self.session_id,
            "host": target_ip, "node": target_node,
            "event": "exploit" if attack else "recon",
            "evidence": (f"EvilKit {activity} action via {tool or 'tool'} (exit {rc})."
                         + (" Attempted command execution." if attempt and not access else "")),
        }
        if target_node != self.current_node:
            payload["edge"] = {
                "src": self.current_node, "dst": target_node,
                "traffic_class": "attack" if attack else "recon",
                "tool": tool or command.split(maxsplit=1)[0],
                "direction": "forward",
            }
        self._append(payload)
        if owned_because:
            self.compromise(target_ip, target_node, tool, ts, owned_because)
        self.write_status()

    def adopt(self, session_path: Path) -> None:
        """Start a session: a log that has gone quiet begins as finished, so a
        restart on an old session cannot claim the board until it acts again."""
        try:
            age = time.time() - session_path.stat().st_mtime
        except OSError:
            age = 0.0
        self._state = "running" if age < IDLE_FINISH_SECS else "finished"

    def on_tick(self) -> None:
        self.sync_topology()
        if self._state == "running":
            if time.time() - self._last_activity > IDLE_FINISH_SECS:
                self._state = "finished"
                self.write_status(force=True)
            else:
                self.write_status()
        # A finished run is NOT heartbeated: leaving its files to age is what
        # returns the board to the live lab view once the engagement is over.


def follow(bridge: Bridge, start: Path, from_start: bool) -> None:
    """Byte-offset tail that follows whichever session log is live.

    An operator session can restart mid-run, which starts a NEW session_*.jsonl;
    this switches to it so the run keeps publishing. Tolerates rotation and
    buffers partial lines.
    """
    path = start
    offset = 0 if from_start else (path.stat().st_size if path.is_file() else 0)
    buf = b""
    while True:
        newer = discover_session()
        if newer is not None and newer.resolve() != path.resolve():
            print(f"evilkimi-bridge: following {newer.name}", flush=True)
            bridge.session_id = newer.stem.replace("session_", "")
            path, offset, buf = newer, 0, b""
            bridge.adopt(newer)
            bridge.write_status(force=True)
        try:
            size = path.stat().st_size if path.is_file() else 0
            if size < offset:            # rotated/truncated
                offset, buf = 0, b""
            if size > offset:
                with path.open("rb") as handle:
                    handle.seek(offset)
                    chunk = handle.read()
                    offset = handle.tell()
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        bridge.handle(json.loads(line.decode("utf-8", "replace")))
                    except ValueError:
                        pass
        except OSError:
            pass
        bridge.on_tick()
        time.sleep(POLL_SECS)


def default_run_dir(session_id: str) -> Path:
    """One run per operator session, so a bridge restart republishes into the
    same run instead of leaving a half-empty sibling behind."""
    stamp = re.sub(r"[^A-Za-z0-9]", "", session_id)[:8] or time.strftime("%Y%m%d-%H%M%S")
    return RUNS_DIR / f"evilkimi-live-{stamp}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--session", default=None,
                    help="session_*.jsonl to start from (default: the live session)")
    ap.add_argument("--run-dir", default=None,
                    help="Keystone runs/<id> to publish into (default: evilkimi-live-<session>)")
    ap.add_argument("--entry-node", default=os.environ.get("EVILKIMI_ENTRY_NODE", "pi-drop"),
                    help="topology node the operator starts from (default: pi-drop)")
    ap.add_argument("--model", default=os.environ.get("EVILKIMI_MODEL", "evilkimi (Kimi Code CLI)"))
    ap.add_argument("--from-start", action="store_true",
                    help="replay the session from its first action (default: tail new lines only)")
    ap.add_argument("--no-sync-topology", action="store_true",
                    help="do not refresh the run topology from the live-brain view")
    args = ap.parse_args(argv)

    session = Path(args.session).expanduser() if args.session else discover_session()
    if session is None or not session.is_file():
        print(f"error: no evilkimi session log under {state_root() / 'sessions'}", flush=True)
        return 2
    session_id = session.stem.replace("session_", "")

    run_dir = Path(args.run_dir).expanduser() if args.run_dir else default_run_dir(session_id)
    dashboard = run_dir / "dashboard"
    dashboard.mkdir(parents=True, exist_ok=True)
    if not (dashboard / "topology.json").is_file():
        try:
            (dashboard / "topology.json").write_text(
                LIVE_BRAIN_TOPO.read_text(encoding="utf-8"), encoding="utf-8")
        except OSError:
            print(f"warning: no topology seed at {LIVE_BRAIN_TOPO}; nodes will not resolve",
                  flush=True)
    (dashboard / "events.jsonl").touch(exist_ok=True)
    (run_dir / "evidence").mkdir(exist_ok=True)

    bridge = Bridge(run_dir, session_id, args.entry_node, args.model,
                    sync_topology=not args.no_sync_topology)
    bridge.adopt(session)
    bridge.write_status(force=True)
    print(f"evilkimi-bridge: {session} -> {run_dir} (entry={args.entry_node})", flush=True)
    try:
        follow(bridge, session, args.from_start)
    except KeyboardInterrupt:
        bridge._state = "stopped"
        bridge.write_status(force=True)
        print("evilkimi-bridge: stopped", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
