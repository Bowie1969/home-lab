#!/usr/bin/env python3
"""Run-1 preflight — prove EVERY traffic class is recorded AND displayed accurately.

Drives the real EvilKit emitter (dashboard_run.py) public API through a full
engagement sequence into an ISOLATED temp runs tree (never touches the live
dashboard), then uses this dashboard's own server.py ingestion to assert each
class lands with the right node state / edge kind / focus / ring / persistence —
i.e. exactly what the board would paint.

Per-class checks:
  operator  drop (g960) is the operator origin at run start
  recon     recon edge (amber) + target discovered
  attack    attack edge (red)  + target in-progress + under-attack ring
  compromise host_compromised -> focus.compromised (RED node) + solved + pivot
  tunnel    sticky cyan edge that STAYS connected 30s after edge_connected
  exfil     exfil -> data-read (purple) target
  flag      KEYSTONE{...} tallied
  live      run outranks the idle live-brain view

Exit 0 = all green (go for run 1). Non-zero = at least one FAIL.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import time
from pathlib import Path

CO = Path.home() / "Dropbox" / "Shared Workspace" / "Cyber Operator"
LAB = Path.home() / "Projects" / "lab-dashboard"
REAL_LIVE_TOPO = (Path.home() / "Projects" / "keystone-range" / "runs"
                  / "live-brain" / "dashboard" / "topology.json")

sys.path.insert(0, str(CO))
from dashboard_run import RunTelemetry  # noqa: E402

RESULTS: list[tuple[bool, str]] = []


def check(ok: bool, label: str) -> None:
    RESULTS.append((bool(ok), label))
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")


def load_server(keystone_root: Path):
    os.environ["LAB_DASHBOARD_KEYSTONE_ROOT"] = str(keystone_root)
    spec = importlib.util.spec_from_file_location("server_preflight", LAB / "server.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def pick_targets(topo: dict, want: int):
    """Return [(ip, node_id), ...] of distinct attackable range hosts.

    Prefer the 10.99.50.x range estate; exclude the operator/infra nodes (the
    drop, the gateway, the services/management plane) so the preflight reads like
    a real engagement. Fall back to any addressable node if the estate is thin.
    """
    import re
    ipre = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
    infra = {"g960", "pi-drop", "g910", "g100", "g200", "g201"}
    estate, other = [], []
    for n in topo.get("nodes", []):
        nid = n.get("id")
        if nid in infra:
            continue
        m = ipre.search(str(n.get("address") or n.get("ip") or ""))
        if not m:
            continue
        (estate if m.group(0).startswith("10.99.50.") else other).append((m.group(0), nid))
    return (estate + other)[:want]


def main() -> int:
    if not REAL_LIVE_TOPO.is_file():
        print(f"FAIL: no live-brain topology at {REAL_LIVE_TOPO} (brain never polled?)")
        return 2
    live_topo = json.loads(REAL_LIVE_TOPO.read_text(encoding="utf-8"))
    targets = pick_targets(live_topo, 5)
    if len(targets) < 5:
        print(f"FAIL: need >=5 addressable non-drop nodes, found {len(targets)}")
        return 2
    (recon_ip, recon_id), (atk_ip, atk_id), (cmp_ip, cmp_id), \
        (tun_ip, tun_id), (exf_ip, exf_id) = targets
    print("targets:",
          f"recon={recon_id}({recon_ip}) attack={atk_id}({atk_ip}) "
          f"compromise={cmp_id}({cmp_ip}) tunnel={tun_id}({tun_ip}) exfil={exf_id}({exf_ip})")

    tmp = tempfile.TemporaryDirectory(prefix="run1-preflight-")
    runs_root = Path(tmp.name) / "keystone-range" / "runs"
    (runs_root / "live-brain" / "dashboard").mkdir(parents=True)
    (runs_root / "live-brain" / "dashboard" / "topology.json").write_text(
        json.dumps(live_topo), encoding="utf-8")
    os.environ["EVILKIT_DASHBOARD_STATE_DIR"] = str(runs_root.parent / "state")

    run_id = time.strftime("%Y%m%d-%H%M%S-") + "preflt"
    run_dir = runs_root / run_id
    (run_dir / "dashboard").mkdir(parents=True)
    (run_dir / "dashboard" / "topology.json").write_text(
        json.dumps(live_topo), encoding="utf-8")   # seed from live-brain

    # --- drive the full sequence via the REAL public API (LocalSink, no SSH) ---
    telem = RunTelemetry(run_dir=run_dir, autostart=False, model="run1-preflight")
    telem.start_run(detail="preflight session started")
    telem.on_tool("nmap_scan", {"target": recon_ip})                 # recon
    telem.on_tool("sqlmap", {"target": atk_ip})                      # attack (no compromise)
    telem.on_compromise("credential_spray", cmp_ip,
                        evidence="valid admin credentials returned")  # compromise + pivot
    tunnel_ts = time.time()
    telem.on_tunnel_up("ssh", tun_ip)                                # sticky tunnel
    telem.on_action("exfil", exf_ip, tool_name="scp")                # exfil
    telem.on_flag("KEYSTONE{run1-preflight-001}")                    # flag
    telem.heartbeat(detail="preflight active")                       # keep state=running

    # --- now read it back through the dashboard's OWN ingestion ---
    server = load_server(runs_root.parent)
    watcher = server.RangeWatcher()
    chosen = watcher.find_live_run()

    print("\nassertions (what the board would render):")
    check(chosen is not None and chosen.parent.name == run_id,
          "live: run outranks idle live-brain")
    if chosen is None:
        return 1

    events = server.read_jsonl(chosen / "events.jsonl")
    events.sort(key=lambda e: e.get("ts", 0.0))
    topo = json.loads((chosen / "topology.json").read_text(encoding="utf-8"))
    status = json.loads((chosen / "status.json").read_text(encoding="utf-8"))
    node_states, edge_states, flags = server.apply_events(events)
    focus = server.run_focus(topo, status, events)

    # operator origin = drop
    first_aoh = next((e for e in events if e.get("event") == "agent_on_host"), {})
    check(first_aoh.get("node") == "g960", "operator: drop g960 is the origin (agent_on_host)")

    # recon
    det_now = server.edge_event_details(events, now=time.time())
    recon_edge = det_now.get(("g960", recon_id), {})
    check(recon_edge.get("kind") == "recon" and server.traffic_is_connected(recon_edge),
          f"recon: edge g960->{recon_id} kind=recon (amber), connected")
    check(node_states.get(recon_id) == "discovered", f"recon: {recon_id} state=discovered")

    # attack
    atk_edge = det_now.get(("g960", atk_id), {})
    check(atk_edge.get("kind") == "attack" and server.traffic_is_connected(atk_edge),
          f"attack: edge g960->{atk_id} kind=attack (red), connected")
    check(node_states.get(atk_id) == "in-progress", f"attack: {atk_id} state=in-progress")
    under_attack = {e for (s, e), d in det_now.items()
                    if d.get("kind") == "attack" and server.traffic_is_connected(d)}
    check(atk_id in under_attack, f"attack: {atk_id} flagged under-attack (amber ring)")

    # compromise -> RED
    comp_ids = {h["id"] for h in focus.get("compromised", [])}
    check(cmp_id in comp_ids, f"compromise: {cmp_id} in focus.compromised (node turns RED)")
    check(node_states.get(cmp_id) == "solved", f"compromise: {cmp_id} state=solved")
    # Pivot is declared by the agent_on_host event (authoritative) and proven by
    # the tunnel edge below sourcing from cmp_id. focus.current is "host most
    # recently in play" by run_focus design, so it is NOT the pivot signal.
    pivoted = any(e.get("event") == "agent_on_host" and e.get("node") == cmp_id for e in events)
    check(pivoted, f"compromise: operator pivoted onto {cmp_id} (agent_on_host emitted)")

    # tunnel STAYS (sticky) — source is the pivoted host cmp_id
    det_late = server.edge_event_details(events, now=tunnel_ts + 30.0)
    tun_edge = det_late.get((cmp_id, tun_id)) or det_late.get((tun_id, cmp_id)) or {}
    check(tun_edge.get("kind") == "tunnel", f"tunnel: edge->{tun_id} kind=tunnel (cyan)")
    check(server.traffic_is_connected(tun_edge),
          "tunnel: STILL connected 30s after edge_connected (stays)")

    # exfil
    exf_edge = det_now.get((cmp_id, exf_id), {})
    check(exf_edge.get("kind") == "data" and server.traffic_is_connected(exf_edge),
          f"exfil: edge {cmp_id}->{exf_id} kind=data (purple), connected")
    check(node_states.get(exf_id) == "data-read", f"exfil: {exf_id} state=data-read (purple)")

    # flag
    check(any("run1-preflight-001" in str(f) for f in flags),
          "flag: KEYSTONE{run1-preflight-001} tallied")

    telem.finish(detail="preflight complete")
    passed = sum(1 for ok, _ in RESULTS if ok)
    total = len(RESULTS)
    print(f"\n{'='*52}\nPREFLIGHT: {passed}/{total} checks passed")
    if passed == total:
        print("RESULT: GO — all traffic classes recorded and displayed accurately.")
        return 0
    print("RESULT: NO-GO — see FAIL lines above.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
