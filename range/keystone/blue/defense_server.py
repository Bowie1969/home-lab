#!/usr/bin/env python3
"""defense_server — the blue-team tool surface for a Keystone run.

This is what a defending analyst (blukit, running Claude or gpt-Sol via Codex)
can see and do from the agent side of a Keystone engagement. It serves the
*blue-observable* telemetry that :mod:`keystone.bluetelemetry` projects into
``<run>/telemetry/`` — never the attacker's journal, pcaps or the scoring key —
and exposes a small, fixed set of response actions. Every action it takes is
written to an append-only action journal *and* painted onto the live dashboard
via :func:`keystone.emit.emit_defense_action`, so the defender's moves show up
next to the attacker's in real time.

Transport: newline-delimited JSON-RPC 2.0 over stdin/stdout (MCP stdio),
Python standard library only. The tool functions are pure (env + args in,
dict out) so the test suite drives them with no stdio and no live range.

Scope — the contract blukit writes
----------------------------------
blukit records the authorised scope into ``DEFENSE_ALLOWED_TARGETS`` (and the
deny list into ``DEFENSE_DENIED_TARGETS``). Every read and every action is gated
on it, failing closed:

  * unset/empty ``DEFENSE_ALLOWED_TARGETS``  -> everything is refused;
  * ``DEFENSE_DENIED_TARGETS`` wins over the allow list;
  * a ``host`` argument is gated the same way.

Response actions additionally require ``DEFENSE_ALLOW_RESPONSE=1`` (the same
switch blukit's own gate uses), so an observe-only engagement cannot act.
This server records and paints the action; the actual enforcement (nftables,
account disable, key revocation) is the operator's enforcer behind blukit —
the analyst that can read the estate is deliberately not the one that can be
talked into mutating it.
"""
from __future__ import annotations

import glob
import ipaddress
import json
import os
import sys
import time
from typing import Any, Callable, Dict, List, Optional

# Import keystone.emit for dashboard painting. Support running both as a module
# (python3 -m keystone.blue.defense_server) and as a bare script.
try:
    from keystone import emit
except ImportError:  # pragma: no cover - path fix for bare-script launch
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    from keystone import emit

SCOPE_ENV_KEY = "DEFENSE_ALLOWED_TARGETS"
DENY_ENV_KEY = "DEFENSE_DENIED_TARGETS"
RUN_DIR_ENV_KEY = "DEFENSE_RUN_DIR"
ALLOW_RESPONSE_ENV_KEY = "DEFENSE_ALLOW_RESPONSE"

SERVER_INFO = {"name": "keystone-defense", "version": "1.0.0"}
TELEMETRY_SUBDIR = "telemetry"
MAX_RECORDS = 2000

#: Response actions this surface exposes -> the enforcer each maps to. Kept in
#: lockstep with blukit.response.ACTIONS and keystone.emit.ACTION_EVENT.
ACTIONS = (
    "isolate-host", "block-ip", "block-host", "disable-account", "revoke-creds",
    "terminate-process", "quarantine-file", "capture-packet", "preserve-evidence",
)


class Refused(Exception):
    """A scope/switch refusal, surfaced to the caller as a tool error."""


# --- scope gate (mirrors blukit.response / chainbreaker defense_server) -------

def _parse_targets(value: Optional[str]):
    nets: list = []
    names: List[str] = []
    for token in (value or "").split(","):
        token = token.strip()
        if not token:
            continue
        try:
            nets.append(ipaddress.ip_network(token, strict=False))
        except ValueError:
            names.append(token.lower().rstrip("."))
    return nets, names


def _subject(token: str):
    token = token.strip()
    try:
        return ipaddress.ip_network(token, strict=False)
    except ValueError:
        return token.lower().rstrip(".")


def _covered(subject, nets, names) -> bool:
    if isinstance(subject, str):
        return subject in names
    return any(subject.version == n.version and subject.subnet_of(n) for n in nets)


def _touches(subject, nets, names) -> bool:
    if isinstance(subject, str):
        return subject in names
    return any(subject.version == n.version and subject.overlaps(n) for n in nets)


def check_scope(token: str, env: Dict[str, str]) -> None:
    """Raise :class:`Refused` unless ``token`` is in scope and clear of deny."""
    raw = env.get(SCOPE_ENV_KEY, "")
    if not raw.strip():
        raise Refused(f"{SCOPE_ENV_KEY} is unset: failing closed, nothing is in scope")
    allow_nets, allow_names = _parse_targets(raw)
    if not allow_nets and not allow_names:
        raise Refused(f"{SCOPE_ENV_KEY}={raw!r} names no target: failing closed")
    deny_nets, deny_names = _parse_targets(env.get(DENY_ENV_KEY, ""))
    subj = _subject(token)
    if _touches(subj, deny_nets, deny_names):
        raise Refused(f"{token} is in {DENY_ENV_KEY}: refused")
    if not _covered(subj, allow_nets, allow_names):
        raise Refused(f"{token} is outside {SCOPE_ENV_KEY}={raw}: refused")


def _require_scope_enabled(env: Dict[str, str]) -> None:
    """Fail closed before any read when no allow list is configured at all."""
    if not env.get(SCOPE_ENV_KEY, "").strip():
        raise Refused(f"{SCOPE_ENV_KEY} is unset: failing closed, nothing is observable")


def _response_enabled(env: Dict[str, str]) -> bool:
    return env.get(ALLOW_RESPONSE_ENV_KEY, "").strip() == "1"


# --- telemetry access (confined to <run>/telemetry) ---------------------------

def _run_dir(env: Dict[str, str]) -> str:
    rd = env.get(RUN_DIR_ENV_KEY, "").strip()
    if not rd:
        raise Refused(f"{RUN_DIR_ENV_KEY} is unset: no run to observe")
    return os.path.abspath(rd)


def _telemetry_dir(env: Dict[str, str]) -> str:
    return os.path.join(_run_dir(env), TELEMETRY_SUBDIR)


def _resolve(env: Dict[str, str], rel: str) -> str:
    """Map a stream name to a real file under telemetry/, or refuse.

    Only a bare filename inside telemetry/ is served: no absolute paths, no
    traversal, and the resolved real path must still sit under telemetry/.
    """
    if os.path.isabs(rel) or rel.startswith(("/", "\\")):
        raise Refused(f"{rel!r}: absolute paths are refused")
    if ".." in rel.replace("\\", "/").split("/"):
        raise Refused(f"{rel!r}: path traversal is refused")
    base = os.path.realpath(_telemetry_dir(env))
    real = os.path.realpath(os.path.join(base, rel))
    if real != base and not real.startswith(base + os.sep):
        raise Refused(f"{rel!r}: resolves outside telemetry/")
    return real


def _read_stream(env: Dict[str, str], name: str, limit: int = MAX_RECORDS) -> List[Dict[str, Any]]:
    path = _resolve(env, name)
    if not os.path.isfile(path):
        return []
    out: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                out.append(obj)
            if len(out) >= limit:
                break
    return out


def _host_match(rec: Dict[str, Any], host: Optional[str]) -> bool:
    if not host:
        return True
    return host in (rec.get("dst"), rec.get("src"), rec.get("host"))


# --- read tools ---------------------------------------------------------------

def tool_list_telemetry(env: Dict[str, str], args: Dict[str, Any]) -> Dict[str, Any]:
    _require_scope_enabled(env)
    tdir = _telemetry_dir(env)
    streams: Dict[str, int] = {}
    for p in sorted(glob.glob(os.path.join(tdir, "*.jsonl"))):
        name = os.path.basename(p)
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as fh:
                streams[name] = sum(1 for ln in fh if ln.strip())
        except OSError:
            streams[name] = 0
    return {"telemetry_dir": tdir, "streams": streams}


def _read_named(env, args, filename, host_filter=True):
    _require_scope_enabled(env)
    host = (args or {}).get("host")
    if host:
        check_scope(str(host), env)
    recs = _read_stream(env, filename)
    if host_filter and host:
        recs = [r for r in recs if _host_match(r, host)]
    return {"stream": filename, "count": len(recs), "records": recs}


def tool_netflow(env, args):        return _read_named(env, args, "netflow.jsonl")
def tool_firewall_drops(env, args): return _read_named(env, args, "firewall-drops.jsonl")
def tool_alerts(env, args):         return _read_named(env, args, "alerts.jsonl", host_filter=False)


def tool_auth_events(env, args):
    _require_scope_enabled(env)
    host = (args or {}).get("host")
    if host:
        check_scope(str(host), env)
    tdir = _telemetry_dir(env)
    recs: List[Dict[str, Any]] = []
    for p in sorted(glob.glob(os.path.join(tdir, "auth-*.jsonl"))):
        recs.extend(_read_stream(env, os.path.basename(p)))
    if host:
        recs = [r for r in recs if _host_match(r, host)]
    return {"stream": "auth-*.jsonl", "count": len(recs), "records": recs}


def tool_host_events(env, args):
    _require_scope_enabled(env)
    host = (args or {}).get("host")
    if not host:
        raise Refused("host_events needs a 'host' argument")
    check_scope(str(host), env)
    tdir = _telemetry_dir(env)
    recs: List[Dict[str, Any]] = []
    for p in sorted(glob.glob(os.path.join(tdir, "host-*.jsonl"))):
        recs.extend(r for r in _read_stream(env, os.path.basename(p)) if _host_match(r, host))
    return {"stream": "host-*.jsonl", "host": host, "count": len(recs), "records": recs}


def tool_search(env, args):
    _require_scope_enabled(env)
    needle = str((args or {}).get("query", "")).strip()
    if not needle:
        raise Refused("search needs a 'query'")
    tdir = _telemetry_dir(env)
    hits: List[Dict[str, Any]] = []
    for p in sorted(glob.glob(os.path.join(tdir, "*.jsonl"))):
        name = os.path.basename(p)
        for rec in _read_stream(env, name):
            if needle.lower() in json.dumps(rec).lower():
                hits.append({"stream": name, "record": rec})
    return {"query": needle, "count": len(hits), "hits": hits}


# --- action tools -------------------------------------------------------------

def _action_journal_path(env: Dict[str, str]) -> str:
    return os.path.join(_run_dir(env), "defense_actions.jsonl")


def _journal_action(env, record: Dict[str, Any]) -> None:
    path = _action_journal_path(env)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")


def _do_action(env: Dict[str, str], action: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Gate, record, and paint one response action.

    Order is deliberate: the switch, then the subject, then scope — the cheap
    unconditional refusals first, so a disabled tier cannot be talked into a
    decision by a malformed subject. A refusal is journalled too, so the action
    log shows attempts, not just successes.
    """
    subject = str((args or {}).get("subject", "")).strip()
    detail = str((args or {}).get("detail", ""))
    base = {"ts": time.time(), "action": action, "subject": subject,
            "actor": "blukit", "detail": detail}

    if not _response_enabled(env):
        rec = {**base, "outcome": "refused",
               "reason": f"response tier off: set {ALLOW_RESPONSE_ENV_KEY}=1"}
        _journal_action(env, rec)
        raise Refused(rec["reason"])
    if not subject:
        raise Refused("an action must name a 'subject'")
    try:
        check_scope(subject, env)
    except Refused as exc:
        _journal_action(env, {**base, "outcome": "refused", "reason": str(exc)})
        raise

    # Recorded + painted. Real enforcement is the operator's enforcer behind
    # blukit; this surface proves intent and makes the move observable.
    rec = {**base, "outcome": "done"}
    _journal_action(env, rec)
    try:
        emit.emit_defense_action(_run_dir(env), subject, action, detail=detail,
                                 outcome="done", actor="blukit")
    except (OSError, ValueError):
        pass  # painting is best-effort; the journal is the record of truth
    return {"action": action, "subject": subject, "outcome": "done",
            "painted": True, "detail": detail}


def _make_action_tool(action: str) -> Callable[[Dict[str, str], Dict[str, Any]], Dict[str, Any]]:
    def tool(env, args, _action=action):
        return _do_action(env, _action, args or {})
    return tool


# --- tool registry ------------------------------------------------------------

READ_TOOLS: Dict[str, Callable] = {
    "list_telemetry": tool_list_telemetry,
    "netflow": tool_netflow,
    "firewall_drops": tool_firewall_drops,
    "auth_events": tool_auth_events,
    "host_events": tool_host_events,
    "alerts": tool_alerts,
    "search": tool_search,
}
# Action tool names use underscores (MCP tool-name convention); they map to the
# hyphenated response-action names.
ACTION_TOOLS: Dict[str, Callable] = {
    action.replace("-", "_"): _make_action_tool(action) for action in ACTIONS
}
TOOLS: Dict[str, Callable] = {**READ_TOOLS, **ACTION_TOOLS}


def _tool_descriptors() -> List[Dict[str, Any]]:
    descs: List[Dict[str, Any]] = []
    host_arg = {"host": {"type": "string", "description": "in-scope host/IP to filter by"}}
    for name in READ_TOOLS:
        if name == "search":
            props = {"query": {"type": "string"}}
            required = ["query"]
        elif name == "host_events":
            props, required = host_arg, ["host"]
        elif name == "list_telemetry":
            props, required = {}, []
        else:
            props, required = host_arg, []
        descs.append({"name": name, "description": f"read {name} (scope-gated)",
                      "inputSchema": {"type": "object", "properties": props, "required": required}})
    for name in ACTION_TOOLS:
        descs.append({
            "name": name,
            "description": f"response action '{name.replace('_', '-')}' "
                           f"(needs {ALLOW_RESPONSE_ENV_KEY}=1; records + paints the dashboard)",
            "inputSchema": {"type": "object",
                            "properties": {"subject": {"type": "string"},
                                           "detail": {"type": "string"}},
                            "required": ["subject"]},
        })
    return descs


def dispatch(method: str, params: Dict[str, Any], env: Dict[str, str]) -> Any:
    """Handle one JSON-RPC method. Raises on protocol/tool errors."""
    if method == "initialize":
        return {"protocolVersion": "2024-11-05",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": SERVER_INFO}
    if method in ("notifications/initialized", "initialized"):
        return None
    if method == "tools/list":
        return {"tools": _tool_descriptors()}
    if method == "tools/call":
        name = params.get("name", "")
        args = params.get("arguments", {}) or {}
        fn = TOOLS.get(name)
        if fn is None:
            raise Refused(f"unknown tool {name!r}")
        result = fn(env, args)
        return {"content": [{"type": "text", "text": json.dumps(result, indent=2, sort_keys=True)}]}
    raise Refused(f"unknown method {method!r}")


def _serve(stdin, stdout, env: Dict[str, str]) -> None:
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        mid = msg.get("id")
        try:
            result = dispatch(msg.get("method", ""), msg.get("params", {}) or {}, env)
        except Refused as exc:
            if mid is not None:
                _write(stdout, {"jsonrpc": "2.0", "id": mid,
                                "error": {"code": -32000, "message": str(exc)}})
            continue
        except Exception as exc:  # pragma: no cover - defensive
            if mid is not None:
                _write(stdout, {"jsonrpc": "2.0", "id": mid,
                                "error": {"code": -32603, "message": repr(exc)}})
            continue
        if mid is not None and result is not None:
            _write(stdout, {"jsonrpc": "2.0", "id": mid, "result": result})


def _write(stdout, obj: Dict[str, Any]) -> None:
    stdout.write(json.dumps(obj) + "\n")
    stdout.flush()


def main(argv=None) -> int:
    _serve(sys.stdin, sys.stdout, dict(os.environ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
