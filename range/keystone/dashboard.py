#!/usr/bin/env python3
"""dashboard.py — the LOCAL Keystone run dashboard.

The telemetry contract (``topology.json``, ``events.jsonl``, ``status.json``)
used to be rendered by "an external dashboard built in parallel". This module
replaces that: it is the dashboard, in-repo and pure stdlib, so a run is
viewable on the same closed box that generates and scores it — no Node, no CDN,
no build step.

Two jobs:

  render   Read a run's ``dashboard/`` telemetry (plus ``score.json`` if the
           scoring host dropped one) and write a single self-contained
           ``dashboard/index.html``. The file inlines a snapshot of the data,
           so it renders when opened straight off disk (``file://``), and it
           also live-polls the sibling JSON when served over HTTP.

  serve    Re-render, then serve the dashboard directory with the stdlib HTTP
           server so the page refreshes itself while a run progresses.

CLI:
    python3 -m keystone.dashboard render --run-dir runs/<id>
    python3 -m keystone.dashboard serve  --run-dir runs/<id> [--port 8008]
"""
from __future__ import annotations

import argparse
import functools
import http.server
import json
import os
import socketserver
import sys
import webbrowser
from pathlib import Path
from typing import Any, Dict, List, Optional

# Zone columns, left (closest to the operator) to right (the crown).
ZONE_ORDER = ["attacker", "dmz", "corp", "data"]

# Every event name the telemetry can carry, mapped to a progress TIER. A node's
# displayed tier is the highest tier of any event that named it; higher tiers
# paint "hotter" so the estate's compromise reads at a glance. Keeping this in
# one place means an unknown/new event simply lands at tier 0 (seen) rather than
# breaking the view.
EVENT_TIER = {
    # 0 seen — telemetry mentions the node but asserts nothing about it
    "node_discovered": 1, "discovered": 1, "recon": 1,
    # 2 reachable — a service answered
    "node_reachable": 2, "node_up": 2,
    # 3 foothold — code runs on the host (or a script now sits on it)
    "foothold": 3, "agent_on_host": 3, "initial_access": 3,
    "script_uploaded": 3,
    # 4 operating — moving through / living on the host (incl. a script that ran)
    "lateral": 4, "implant": 4, "persist": 4, "script_authored": 4,
    "script_executed": 4,
    "edge_used": 2,
    # 5 pivot / C2 — the host relays or calls home
    "pivot": 5, "c2": 5,
    # 6 crown — the data-tier objective is touched
    "crown_id": 6, "host_compromised": 6,
    # 7 exfil — the crown left the estate
    "exfil_started": 7, "exfil": 7, "flag_captured": 7, "exfil_completed": 7,
    "impact": 7, "malware_encrypt": 7, "ransomware_impact": 7,
}

TIER_LABEL = {
    0: "seen", 1: "discovered", 2: "reachable", 3: "foothold",
    4: "operating", 5: "pivot/C2", 6: "crown", 7: "exfil/impact",
}


def _basename(run_dir: str) -> str:
    return os.path.basename(os.path.abspath(run_dir).rstrip("/"))


def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _read_events(path: Path) -> List[Dict]:
    out: List[Dict] = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def collect(run_dir: str) -> Dict[str, Any]:
    """Gather everything the page needs from one run directory. Pure read."""
    run = Path(run_dir)
    dash = run / "dashboard"
    topology = _read_json(dash / "topology.json", {"nodes": [], "edges": [], "zones": []})
    events = _read_events(dash / "events.jsonl")
    status = _read_json(dash / "status.json", {"run_id": _basename(run_dir), "state": "unknown"})
    # score.json is optional: the scorer runs on a separate host with the
    # private key, and only sometimes drops its result back into the run.
    score = _read_json(run / "score.json", None)
    rts = _read_json(run / "rts_score.json", None)
    return {
        "run_id": _basename(run_dir),
        "topology": topology,
        "events": events,
        "status": status,
        "score": score,
        "rts": rts,
    }


# --- HTML -------------------------------------------------------------------
# The template keeps all CSS/JS inline. %%BOOTSTRAP%% is the only substitution;
# it is a <script> assigning window.__KEYSTONE__ so the first paint needs no
# network. When served over HTTP the poller refreshes from the sibling JSON.

_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Keystone — %%RUN_ID%%</title>
<style>
:root{
  --bg:#f6f7f9; --panel:#ffffff; --ink:#1b1f24; --muted:#6b7280; --line:#e4e7eb;
  --attacker:#7c3aed; --dmz:#2563eb; --corp:#0891b2; --data:#b45309;
  --t0:#9aa4b2; --t1:#60a5fa; --t2:#22c3a6; --t3:#f6c445; --t4:#f59e0b;
  --t5:#f97316; --t6:#ef4444; --t7:#dc2626;
  --edge:#cbd2da; --edge-used:#f59e0b; --shadow:0 1px 3px rgba(16,24,40,.08);
  --defended:#0d9488; --defended-bg:rgba(13,148,136,.08);
  --fabric:#475569; --fabric-bg:#f8fafc;
}
@media (prefers-color-scheme:dark){:root{
  --bg:#0e1116; --panel:#171b21; --ink:#e7ecf2; --muted:#93a0b0; --line:#262c34;
  --edge:#333b45; --shadow:0 1px 3px rgba(0,0,0,.4);
  --defended:#2dd4bf; --defended-bg:rgba(45,212,191,.12);
  --fabric:#94a3b8; --fabric-bg:#11161d;
}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:14px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
a{color:inherit}
.wrap{max-width:1180px;margin:0 auto;padding:20px}
header.top{display:flex;flex-wrap:wrap;align-items:baseline;gap:10px 16px;margin-bottom:6px}
h1{font-size:18px;margin:0;font-weight:650;letter-spacing:.2px}
.run{color:var(--muted);font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px}
.sub{color:var(--muted);margin:2px 0 18px}
.badge{display:inline-flex;align-items:center;gap:6px;padding:2px 10px;border-radius:999px;
  font-size:12px;font-weight:600;border:1px solid var(--line);background:var(--panel)}
.badge .dot{width:8px;height:8px;border-radius:50%;background:var(--t0)}
.badge.running .dot,.badge.active .dot,.badge.starting .dot{background:var(--t2);
  box-shadow:0 0 0 0 rgba(34,195,166,.6);animation:pulse 1.8s infinite}
.badge.finished .dot{background:var(--t6)}
.badge.idle .dot,.badge.ready .dot{background:var(--t1)}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(34,195,166,.5)}70%{box-shadow:0 0 0 7px rgba(34,195,166,0)}100%{box-shadow:0 0 0 0 rgba(34,195,166,0)}}
.shell{display:grid;grid-template-columns:330px 1fr;gap:18px;align-items:start}
@media(max-width:900px){.shell{grid-template-columns:1fr}}
.rail{display:flex;flex-direction:column;gap:18px;position:sticky;top:14px}
@media(max-width:900px){.rail{position:static}}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;
  box-shadow:var(--shadow);padding:16px}
.panel h2{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);
  margin:0 0 12px;font-weight:600}
/* topology */
.topo{position:relative}
.fabric{border:1px solid var(--line);border-radius:10px;background:var(--fabric-bg);padding:11px;margin-bottom:14px}
.fabric-head{display:flex;justify-content:space-between;gap:12px;align-items:center;margin-bottom:9px}
.fabric-title{font-size:11px;font-weight:800;letter-spacing:.1em;text-transform:uppercase;color:var(--fabric)}
.fabric-mgmt{font:10px ui-monospace,Menlo,monospace;color:var(--muted);text-align:right}
.fabric-devices{display:grid;grid-template-columns:repeat(4,1fr);gap:8px}
.fabric-device{border:1px solid var(--line);border-top:3px solid var(--fabric);border-radius:8px;background:var(--panel);padding:8px}
.fabric-device.physical{border-top-color:var(--corp)}
.fabric-device .fd-name{font-weight:700;font-size:12px}
.fabric-device .fd-role{font-size:10px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}
.fabric-device .fd-address{font:11px ui-monospace,Menlo,monospace;margin-top:4px}
.fabric-device .fd-detail{font-size:10px;color:var(--muted);margin-top:2px}
.fabric-links{display:flex;flex-wrap:wrap;gap:5px;margin-top:8px}
.fabric-link{font:10px ui-monospace,Menlo,monospace;color:var(--muted);border:1px solid var(--line);border-radius:999px;padding:2px 7px;background:var(--panel)}
@media(max-width:720px){.fabric-devices{grid-template-columns:repeat(2,1fr)}.fabric-head{align-items:flex-start;flex-direction:column}.fabric-mgmt{text-align:left}}
.cols{display:grid;grid-template-columns:repeat(4,1fr);gap:0;position:relative;z-index:1}
.col{padding:0 8px}
.coltitle{text-align:center;font-size:11px;font-weight:700;letter-spacing:.1em;
  text-transform:uppercase;padding:6px 0 10px;color:var(--muted);min-height:63px}
.coltitle .vlan{display:block;font:700 10px ui-monospace,Menlo,monospace;letter-spacing:0;margin-top:3px}
.coltitle .cidr,.coltitle .ports{display:block;font:9px ui-monospace,Menlo,monospace;letter-spacing:0;text-transform:none;color:var(--muted)}
.col[data-zone=attacker] .coltitle{color:var(--attacker)}
.col[data-zone=dmz] .coltitle{color:var(--dmz)}
.col[data-zone=corp] .coltitle{color:var(--corp)}
.col[data-zone=data] .coltitle{color:var(--data)}
.node{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--t0);
  border-radius:9px;padding:8px 10px;margin:0 0 10px;cursor:default;transition:transform .08s}
.node:hover{transform:translateY(-1px)}
.node.pi-drop{border-left-color:#ef4444;background:linear-gradient(135deg,rgba(239,68,68,.06),rgba(239,68,68,.02))}
.pi-badge{display:inline-block;background:#ef4444;color:white;padding:2px 6px;border-radius:3px;font-size:11px;font-weight:600;margin-left:6px;letter-spacing:.3px}
.substrate-badge{display:inline-block;border:1px solid var(--line);color:var(--muted);padding:1px 5px;border-radius:3px;font-size:9px;font-weight:700;margin-left:4px;text-transform:uppercase;letter-spacing:.04em}
/* blue-team overlay: the defender acted on this host */
.node.contained{outline:2px solid var(--defended);outline-offset:-1px;background:var(--defended-bg)}
.node.watched{box-shadow:inset 0 0 0 1px var(--defended)}
.def-badge{display:inline-block;background:var(--defended);color:#fff;padding:1px 6px;border-radius:3px;
  font-size:10px;font-weight:700;margin-left:6px;letter-spacing:.3px;white-space:nowrap}
.ev .rail i.def{box-shadow:0 0 0 2px var(--defended-bg)}
.node .nm{font-weight:600;font-size:13px;display:flex;justify-content:space-between;gap:6px}
.node .ip{font-family:ui-monospace,Menlo,monospace;font-size:11px;color:var(--muted)}
.node .tc{font-size:11px;color:var(--muted);margin-top:2px}
.node .st{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.05em}
svg.wires{position:absolute;inset:0;width:100%;height:100%;z-index:0;pointer-events:none}
.legend{display:flex;flex-wrap:wrap;gap:4px 12px;margin-top:12px;font-size:11px;color:var(--muted)}
.legend span{display:inline-flex;align-items:center;gap:5px}
.legend i{width:10px;height:10px;border-radius:2px;display:inline-block}
/* score */
.cat{margin-bottom:9px}
.cat .lab{display:flex;justify-content:space-between;font-size:12px;margin-bottom:3px}
.cat .lab b{font-weight:600}
.track{height:7px;background:var(--line);border-radius:4px;overflow:hidden}
.track > i{display:block;height:100%;border-radius:4px;background:linear-gradient(90deg,var(--t2),var(--t4))}
.final{font-size:28px;font-weight:700;margin:2px 0 2px}
.final small{font-size:14px;color:var(--muted);font-weight:500}
.pct{color:var(--muted);font-size:12px}
.pen{color:var(--t6);font-size:12px;margin-top:6px}
.empty{color:var(--muted);font-size:12.5px;padding:8px 0}
/* feed */
.feed{max-height:520px;overflow:auto;margin:-4px -4px 0;padding:4px}
.ev{display:grid;grid-template-columns:14px 1fr;gap:9px;padding:7px 2px;border-bottom:1px solid var(--line)}
.ev:last-child{border-bottom:0}
.ev .rail{position:relative}
.ev .rail i{position:absolute;left:3px;top:5px;width:8px;height:8px;border-radius:50%;background:var(--t0)}
.ev .kind{font-weight:600;font-size:12.5px}
.ev .meta{color:var(--muted);font-size:11px;font-family:ui-monospace,Menlo,monospace}
.ev .why{font-size:12px;color:var(--ink);opacity:.86;margin-top:1px}
.foot{color:var(--muted);font-size:11px;margin-top:16px;text-align:center}
.count{font-weight:400;color:var(--muted);font-size:12px}
</style>
</head>
<body>
<div class="wrap">
  <header class="top">
    <h1>Keystone Range</h1>
    <span class="run" id="run-id"></span>
    <span id="state-badge" class="badge"><span class="dot"></span><span id="state-text">—</span></span>
    <span class="run" id="model"></span>
  </header>
  <div class="sub" id="step"></div>

  <div class="shell">
    <aside class="rail">
      <div class="panel">
        <h2>Score</h2>
        <div id="score"></div>
      </div>
      <div class="panel">
        <h2>Scripted pathfinding</h2>
        <div id="rts"></div>
      </div>
      <div class="panel">
        <h2>Event feed <span class="count" id="ev-count"></span></h2>
        <div class="feed" id="feed"></div>
      </div>
    </aside>
    <main class="panel topo">
      <h2>Estate topology <span class="count" id="node-count"></span></h2>
      <div id="topo"></div>
      <div class="legend" id="legend"></div>
    </main>
  </div>
  <div class="foot" id="foot"></div>
</div>

%%BOOTSTRAP%%
<script>
const TIER_COLOR=["--t0","--t1","--t2","--t3","--t4","--t5","--t6","--t7"];
const TIER_LABEL=["seen","discovered","reachable","foothold","operating","pivot/C2","crown","exfil"];
const EVENT_TIER=%%EVENT_TIER%%;
const ZONE_ORDER=["attacker","dmz","corp","data"];
const cssv=n=>getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const esc=s=>String(s==null?"":s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

function nodeTier(id,events){
  let t=0;
  for(const e of events){ if((e.node===id)||(e.host===id)){ const v=EVENT_TIER[e.event]; if(v>t)t=v; } }
  return t;
}
// Blue-team overlay. Containment actions cut the attacker off this host;
// forensic actions (capture/preserve) and bare detections only mark it watched.
const DEF_CONTAIN=new Set(["defense_isolate","defense_block","defense_disable_account","defense_revoke","defense_kill","defense_quarantine"]);
const DEF_WATCH=new Set(["defense_capture","defense_preserve","defense_detect"]);
const DEF_LABEL={defense_isolate:"isolated",defense_block:"blocked",defense_disable_account:"acct disabled",
  defense_revoke:"creds revoked",defense_kill:"proc killed",defense_quarantine:"quarantined",
  defense_capture:"capturing",defense_preserve:"evidence held",defense_detect:"detected"};
function isDef(ev){ return typeof ev==="string" && ev.indexOf("defense_")===0; }
function defenseState(id,events){
  // Returns {cls, label} for the newest defence action naming this host, or null.
  let contained=null, watched=null;
  for(const e of events){
    if(!isDef(e.event) || !((e.node===id)||(e.host===id))) continue;
    if(DEF_CONTAIN.has(e.event)) contained=e; else if(DEF_WATCH.has(e.event)) watched=e;
  }
  const e=contained||watched; if(!e) return null;
  return {cls: contained?"contained":"watched", label: DEF_LABEL[e.event]||"defended"};
}
function fmtTime(ts){ if(!ts)return""; const d=new Date(ts*1000); return d.toLocaleTimeString([], {hour12:false}); }

function renderFabric(topo){
  const fabric=topo.fabric; if(!fabric||!(fabric.devices||[]).length)return'';
  let h='<section class="fabric"><div class="fabric-head"><span class="fabric-title">Physical range fabric</span>'+
    '<span class="fabric-mgmt">'+esc(fabric.management||'')+'</span></div><div class="fabric-devices">';
  for(const device of fabric.devices||[]){
    h+='<div class="fabric-device'+(device.id==='evilkit'?' physical':'')+'">'+
      '<div class="fd-name">'+esc(device.label||device.id)+'</div><div class="fd-role">'+esc(device.role||'')+'</div>'+
      '<div class="fd-address">'+esc(device.address||'')+'</div><div class="fd-detail">'+esc(device.detail||'')+'</div></div>';
  }
  h+='</div><div class="fabric-links">';
  for(const link of fabric.links||[]) h+='<span class="fabric-link">'+esc(link.src)+' → '+esc(link.dst)+' · '+esc(link.label||'')+'</span>';
  return h+'</div></section>';
}

let currentTopology=null;
function render(d){
  const st=d.status||{}, events=d.events||[], topo=d.topology||{nodes:[],edges:[]};
  currentTopology=topo;
  document.getElementById('run-id').textContent=d.run_id||st.run_id||'';
  const state=(st.state||'unknown').toLowerCase();
  const badge=document.getElementById('state-badge');
  badge.className='badge '+state;
  document.getElementById('state-text').textContent=state;
  document.getElementById('model').textContent=st.model?('model: '+st.model):'';
  const step=st.current_step||{};
  document.getElementById('step').textContent=step.detail||step.event||'';

  // nodes grouped by zone column
  const nodes=topo.nodes||[];
  document.getElementById('node-count').textContent=nodes.length?('· '+nodes.length+' nodes'):'';
  const byZone={}; ZONE_ORDER.forEach(z=>byZone[z]=[]);
  for(const n of nodes){ const z=(n.zone||'dmz'); (byZone[z]=byZone[z]||[]).push(n); }
  const segments={}; for(const segment of topo.segments||[])segments[segment.id]=segment;
  const topoEl=document.getElementById('topo');
  let html=renderFabric(topo)+'<svg class="wires" id="wires"></svg><div class="cols">';
  for(const z of ZONE_ORDER){
    const segment=segments[z]||{};
    html+='<div class="col" data-zone="'+z+'"><div class="coltitle">'+esc(segment.label||z)+
      (segment.vlan?'<span class="vlan">VLAN '+esc(segment.vlan)+'</span>':'')+
      (segment.cidr?'<span class="cidr">'+esc(segment.cidr)+'</span>':'')+
      (segment.ports?'<span class="ports">'+esc(segment.ports)+'</span>':'')+'</div>';
    for(const n of (byZone[z]||[])){
      const t=nodeTier(n.id,events), col=cssv(TIER_COLOR[t]);
      const last=[...events].reverse().find(e=>e.node===n.id||e.host===n.id);
      const isPiDrop = n.id === 'drop01'||n.id === 'pi-drop';
      const def=defenseState(n.id,events);
      html+='<div class="node' + (isPiDrop ? ' pi-drop' : '') + (def?(' '+def.cls):'') + '" id="node-'+esc(n.id)+'" data-id="'+esc(n.id)+'" '+
            'style="border-left-color:'+col+'" title="'+esc((last&&last.evidence)||'')+'">'+
            '<div class="nm"><span>'+esc(n.label||n.id)+'</span>'+
            (isPiDrop ? '<span class="pi-badge">EvilKit OS</span>' : '')+
            (n.type?'<span class="substrate-badge">'+esc(n.type)+'</span>':'')+
            (def ? '<span class="def-badge">🛡 '+esc(def.label)+'</span>' : '')+
            '<span class="st" style="color:'+col+'">'+TIER_LABEL[t]+'</span></div>'+
            '<div class="ip">'+esc((n.real_ip||'').split(' ')[0]||n.address||n.ip||'')+'</div>'+
            (n.technique_class?'<div class="tc">'+esc(n.technique_class)+'</div>':'')+
            '</div>';
    }
    html+='</div>';
  }
  html+='</div>';
  topoEl.innerHTML=html;
  drawWires(topo);

  // legend
  let leg='';
  for(let i=0;i<TIER_LABEL.length;i++) leg+='<span><i style="background:'+cssv(TIER_COLOR[i])+'"></i>'+TIER_LABEL[i]+'</span>';
  leg+='<span><i style="background:'+cssv('--defended')+'"></i>🛡 contained</span>';
  document.getElementById('legend').innerHTML=leg;

  // feed (newest first)
  const feed=document.getElementById('feed');
  document.getElementById('ev-count').textContent=events.length?('· '+events.length):'';
  const rows=[...events].reverse().map(e=>{
    const def=isDef(e.event);
    const col=def?cssv('--defended'):cssv(TIER_COLOR[EVENT_TIER[e.event]||0]);
    const edge=e.edge?(esc(e.edge.src)+' → '+esc(e.edge.dst)):'';
    // Blue events read as "🛡 action (outcome)"; attacker events keep the raw name.
    const kind=def?('🛡 '+esc(e.action||e.event)+(e.outcome?(' ('+esc(e.outcome)+')'):'')):esc(e.event);
    return '<div class="ev"><div class="rail"><i class="'+(def?'def':'')+'" style="background:'+col+'"></i></div>'+
      '<div><div class="kind">'+kind+'</div>'+
      '<div class="meta">'+fmtTime(e.ts)+' · '+esc(e.node||e.host||'')+(def&&e.actor?(' · '+esc(e.actor)):'')+(edge?(' · '+edge):'')+'</div>'+
      (e.evidence?'<div class="why">'+esc(e.evidence)+'</div>':'')+'</div></div>';
  }).join('');
  feed.innerHTML=rows||'<div class="empty">No events yet.</div>';

  renderScore(d.score);
  renderRts(d.rts);
  document.getElementById('foot').textContent='Keystone local dashboard · rendered '+new Date().toLocaleString();
}

function drawWires(topo){
  const svg=document.getElementById('wires'); if(!svg)return;
  const box=svg.getBoundingClientRect();
  const used=new Set((topo.edges||[]).filter(e=>e.state&&e.state!=='unknown').map(e=>e.src+'>'+e.dst));
  const line=[];
  for(const e of (topo.edges||[])){
    const a=document.getElementById('node-'+e.src), b=document.getElementById('node-'+e.dst);
    if(!a||!b)continue;
    const ra=a.getBoundingClientRect(), rb=b.getBoundingClientRect();
    const x1=ra.right-box.left, y1=ra.top-box.top+ra.height/2;
    const x2=rb.left-box.left, y2=rb.top-box.top+rb.height/2;
    const u=(e.state&&e.state!=='unknown')||used.has(e.src+'>'+e.dst);
    const col=u?cssv('--edge-used'):cssv('--edge');
    const mx=(x1+x2)/2;
    line.push('<path d="M'+x1+' '+y1+' C'+mx+' '+y1+' '+mx+' '+y2+' '+x2+' '+y2+'" '+
      'fill="none" stroke="'+col+'" stroke-width="'+(u?2.2:1.3)+'" '+(u?'':'stroke-dasharray="4 4"')+' opacity="'+(u?0.95:0.55)+'"/>');
  }
  svg.innerHTML=line.join('');
}

function renderScore(s){
  const el=document.getElementById('score');
  if(!s){ el.innerHTML='<div class="empty">Not scored yet. Run <code>python3 -m keystone.score '+
    'runs/&lt;id&gt; --out</code> on the scoring host to drop <code>score.json</code> here.</div>'; return; }
  const max=s.max||110, final=s.final||0, pct=Math.round(final/max*100);
  let h='<div class="final">'+final.toFixed(0)+' <small>/ '+max+'</small></div>'+
        '<div class="pct">'+pct+'% of maximum</div><div style="height:12px"></div>';
  const cats=s.categories||{};
  for(const name of Object.keys(cats)){
    const c=cats[name], p=c.max?Math.round(c.points/c.max*100):0;
    h+='<div class="cat"><div class="lab"><b>'+esc(name)+'</b><span>'+c.points+' / '+c.max+'</span></div>'+
       '<div class="track"><i style="width:'+p+'%"></i></div></div>';
  }
  const pens=s.penalties||{};
  for(const k of Object.keys(pens)){ if(pens[k].points) h+='<div class="pen">− '+pens[k].points+' '+esc(k)+'</div>'; }
  (s.notes||[]).forEach(n=>h+='<div class="empty">note: '+esc(n)+'</div>');
  el.innerHTML=h;
}

function renderRts(r){
  const el=document.getElementById('rts');
  if(!r){ el.innerHTML='<div class="empty">No authored scripts recorded for this run.</div>'; return; }
  const max=r.max||28, pts=r.total!=null?r.total:(r.points||0);
  let h='<div class="final">'+Number(pts).toFixed(0)+' <small>/ '+max+'</small></div>';
  const buckets=r.buckets||r.rubric||r.categories||{};
  const rmax=r.rubric_max||{};
  for(const name of Object.keys(buckets)){
    const c=buckets[name];
    const pt=(c&&c.points!=null)?c.points:c;
    const mx=(rmax[name]!=null)?rmax[name]:((c&&c.max!=null)?c.max:'');
    const p=(mx&&typeof pt==='number')?Math.round(pt/mx*100):0;
    h+='<div class="cat"><div class="lab"><b>'+esc(name)+'</b><span>'+esc(pt)+(mx?(' / '+mx):'')+'</span></div>'+
       '<div class="track"><i style="width:'+p+'%"></i></div></div>';
  }
  const n=(r.scripts||[]).length;
  if(n) h+='<div class="pct" style="margin-top:8px">'+n+' script'+(n===1?'':'s')+' counted</div>';
  el.innerHTML=h;
}

// First paint from the inlined snapshot; then live-poll when served over HTTP.
render(window.__KEYSTONE__);
async function poll(){
  try{
    const bust='?_='+Date.now();
    const [topo,st,evtext]=await Promise.all([
      fetch('topology.json'+bust).then(r=>r.ok?r.json():null).catch(()=>null),
      fetch('status.json'+bust).then(r=>r.ok?r.json():null).catch(()=>null),
      fetch('events.jsonl'+bust).then(r=>r.ok?r.text():null).catch(()=>null),
    ]);
    // score.json / rts_score.json live one level up from dashboard/
    const [score,rts]=await Promise.all([
      fetch('../score.json'+bust).then(r=>r.ok?r.json():null).catch(()=>null),
      fetch('../rts_score.json'+bust).then(r=>r.ok?r.json():null).catch(()=>null),
    ]);
    if(topo||st||evtext){
      const events=(evtext||'').split('\n').map(l=>l.trim()).filter(Boolean).map(l=>{try{return JSON.parse(l)}catch(e){return null}}).filter(Boolean);
      render({run_id:(st&&st.run_id)||window.__KEYSTONE__.run_id,topology:topo||window.__KEYSTONE__.topology,
        status:st||window.__KEYSTONE__.status,events:events.length?events:window.__KEYSTONE__.events,
        score:score,rts:rts});
    }
  }catch(e){/* file:// or offline — keep the inlined snapshot */}
}
if(location.protocol.startsWith('http')){ setInterval(poll,2500); window.addEventListener('resize',()=>drawWires(currentTopology||window.__KEYSTONE__.topology)); }
else { window.addEventListener('resize',()=>drawWires(currentTopology||window.__KEYSTONE__.topology)); }
</script>
</body>
</html>
"""


def render_html(run_dir: str) -> str:
    """Render the dashboard snapshot to ``runs/<id>/dashboard/index.html``.

    Returns the path written. Best-effort: never raises on empty telemetry; an
    idle or freshly published run renders cleanly with whatever exists.
    """
    data = collect(run_dir)
    bootstrap = (
        "<script>window.__KEYSTONE__=" + json.dumps(data, separators=(",", ":")) + ";</script>"
    )
    html = (
        _TEMPLATE
        .replace("%%RUN_ID%%", data["run_id"])
        .replace("%%EVENT_TIER%%", json.dumps(EVENT_TIER, separators=(",", ":")))
        .replace("%%BOOTSTRAP%%", bootstrap)
    )
    out = Path(run_dir) / "dashboard"
    out.mkdir(parents=True, exist_ok=True)
    path = out / "index.html"
    path.write_text(html, encoding="utf-8")
    return str(path)


def serve(run_dir: str, port: int = 8008, open_browser: bool = False, host: str = "127.0.0.1") -> None:
    """Render, then serve the dashboard directory over HTTP with live polling."""
    render_html(run_dir)
    # Root at the run directory (not dashboard/) so the page can reach both the
    # telemetry under dashboard/ and score.json / rts_score.json that the
    # scorer drops at the run root. SimpleHTTPRequestHandler confines requests
    # to this root, so ../score.json resolves while deeper traversal is blocked.
    directory = str(Path(run_dir))
    handler = functools.partial(_QuietHandler, directory=directory)
    with socketserver.TCPServer((host, port), handler) as httpd:
        url = f"http://{host}:{port}/dashboard/index.html"
        print(f"[dashboard] serving {run_dir} at {url}  (Ctrl-C to stop)")
        if open_browser:
            try:
                webbrowser.open(url)
            except Exception:
                pass
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[dashboard] stopped")


class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):  # noqa: A003 - quiet the default access log
        pass

    def end_headers(self):
        # Live telemetry: never let the browser cache the polled JSON.
        self.send_header("Cache-Control", "no-store, max-age=0")
        super().end_headers()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Keystone local run dashboard")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("render", help="write dashboard/index.html for a run")
    r.add_argument("--run-dir", required=True)
    s = sub.add_parser("serve", help="render and serve a run with live refresh")
    s.add_argument("--run-dir", required=True)
    s.add_argument("--port", type=int, default=8008)
    s.add_argument("--host", default="127.0.0.1", help="bind address (use 0.0.0.0 or the tailnet IP to expose)")
    s.add_argument("--open", action="store_true", help="open a browser tab")
    args = ap.parse_args(argv)

    if not os.path.isdir(args.run_dir):
        print(f"error: run dir not found: {args.run_dir}", file=sys.stderr)
        return 2
    if args.cmd == "render":
        path = render_html(args.run_dir)
        print(f"[dashboard] wrote {path}")
        print(f"            open it: file://{os.path.abspath(path)}")
        return 0
    serve(args.run_dir, args.port, getattr(args, "open", False), getattr(args, "host", "127.0.0.1"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
