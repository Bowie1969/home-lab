'use strict';
/* Keystone Range Monitor — read-only live dashboard.
 * Vanilla JS throughout: a small self-contained force simulation drives node
 * positions (no d3-force, no CDN, no network call beyond same-origin /api/*).
 */
const $ = (id) => document.getElementById(id);
const SVG_NS = 'http://www.w3.org/2000/svg';

// ---------------------------------------------------------------- palettes --
const TYPE_GLYPH = { web: 'W', db: 'DB', ad: 'AD', workstation: 'PC', router: 'RT', operator: 'OP', data: 'V', switch: 'SW', server: 'HV' };
const STATUS_COLOR = {
  unknown: '#94A3B8', discovered: '#64748B', reachable: '#0284C7',
  running: '#16A34A', 'in-progress': '#F59E0B', locked: '#EA580C',
  stopped: '#475569', error: '#DC2626', solved: '#7F1D1D', 'data-read': '#7F1D1D',
};
const NODE_STATUS_LEGEND = [
  ['unknown', 'Unknown / no telemetry'],
  ['discovered', 'Discovered / not verified'],
  ['reachable', 'Reachable infrastructure'],
  ['running', 'Running host or service'],
  ['in-progress', 'Action in progress'],
  ['locked', 'Busy or locked'],
  ['stopped', 'Stopped or offline'],
  ['error', 'Error'],
  ['solved', 'Compromised / data accessed'],
];
const EDGE_KIND_COLOR = { network: '#2563EB', firewall: '#0F766E', trust: '#8B75A0', data: '#9A735B', attack: '#DC2626', recon: '#F59E0B', tunnel: '#06B6D4', implant: '#14B8A6', c2: '#C026D3' };
const DATA_TYPE_COLOR = {
  network: '#2563EB', trust: '#8B75A0', data: '#9A735B', attack: '#DC2626', recon: '#F59E0B', tunnel: '#06B6D4',
  telemetry: '#417F91', command: '#987544', file: '#729064',
  credential: '#976B8D', result: '#597DA1', text: '#6E8190',
  json: '#618A82', image: '#A47D62', audio: '#8C78A5',
};
const TOOL_PALETTE = ['#327F8C', '#7669A8', '#A16C55', '#65894D', '#9A718B', '#5D7FAD', '#9A813F'];
const assignedToolColors = new Map();
const assignedDataColors = new Map();
const colorForNode = (node) => STATUS_COLOR[node.state] || STATUS_COLOR.unknown;
const edgeTool = (edge) => String(edge.mcp_tool || edge.tool || '').trim();
const edgeDataType = (edge) => String(edge.data_type || edge.datatype || '').trim().toLowerCase();
function stableHash(value) {
  let hash = 2166136261;
  for (const char of value) hash = Math.imul(hash ^ char.charCodeAt(0), 16777619);
  return hash >>> 0;
}
function toolColor(tool) {
  if (!assignedToolColors.has(tool)) {
    const index = assignedToolColors.size;
    assignedToolColors.set(tool, TOOL_PALETTE[index] || `hsl(${Math.round(index * 137.5) % 360} 30% 42%)`);
  }
  return assignedToolColors.get(tool);
}
function dataColor(type) {
  if (DATA_TYPE_COLOR[type]) return DATA_TYPE_COLOR[type];
  if (!assignedDataColors.has(type)) {
    const index = assignedDataColors.size;
    assignedDataColors.set(type, `hsl(${Math.round(18 + index * 137.5) % 360} 31% 43%)`);
  }
  return assignedDataColors.get(type);
}
function edgeDirection(edge) {
  const value = String(edge.direction || '').toLowerCase();
  if (['reverse', 'backward', 'dst-to-src'].includes(value)) return 'reverse';
  if (['both', 'bidirectional', 'two-way'].includes(value)) return 'both';
  return edge.kind === 'trust' ? 'both' : 'forward';
}
function edgeConnection(edge) {
  if (edge.connected === true || edge.connection === 'connected') return 'connected';
  if (edge.connected === false || edge.connection === 'disconnected') return 'disconnected';
  return 'unspecified';
}

const EDGE_VISIBILITY_WINDOW_SECONDS = 20;
function edgePairKey(src, dst) { return `${src || ''}\u0000${dst || ''}`; }
function currentEventEdgePairs(snapshot) {
  const now = Number(snapshot.generated_at) || Date.now() / 1000;
  const pairs = new Set();
  for (const event of snapshot.events || []) {
    const edge = event && typeof event.edge === 'object' ? event.edge : {};
    const src = edge.src || event.src, dst = edge.dst || event.dst;
    const ts = Number(event.ts);
    if (src && dst && Number.isFinite(ts) && now - ts >= 0 && now - ts <= EDGE_VISIBILITY_WINDOW_SECONDS) {
      pairs.add(edgePairKey(src, dst));
    }
  }
  return pairs;
}
function isCurrentEdge(edge, freshPairs) {
  if (freshPairs.has(edgePairKey(edge.src, edge.dst))) return true;
  const activeTraffic = ['attack', 'recon', 'data', 'tunnel'].includes(edge.kind) || Boolean(edgeTool(edge));
  return edgeConnection(edge) === 'connected' && edge.historical !== true && activeTraffic;
}
function fabricAttachment(node, nodesById) {
  if (!node) return null;
  if (['fabric-switch', 'fabric-hex', 'fabric-brain'].includes(node.id)) return node.id;
  if (/^g\d+$/.test(node.id) || node.id.startsWith('pod-')) {
    return nodesById.has('fabric-brain') ? 'fabric-brain' : null;
  }
  return nodesById.has('fabric-switch') ? 'fabric-switch' : null;
}
function fabricRoute(source, target, nodesById) {
  const sourceAttachment = fabricAttachment(source, nodesById);
  const targetAttachment = fabricAttachment(target, nodesById);
  if (!sourceAttachment || !targetAttachment) return [source.id, target.id];
  const path = [source.id];
  if (path.at(-1) !== sourceAttachment) path.push(sourceAttachment);
  const crossesZones = source.zone && target.zone && source.zone !== target.zone;
  if (sourceAttachment === targetAttachment) {
    // Two VMs (or two physical endpoints) on different VLANs leave their
    // attachment point, traverse hEX, then return over that same trunk.
    if (crossesZones && sourceAttachment !== 'fabric-hex') path.push('fabric-hex', sourceAttachment);
  } else if (sourceAttachment === 'fabric-switch' && targetAttachment === 'fabric-brain') {
    path.push('fabric-hex', 'fabric-brain');
  } else if (sourceAttachment === 'fabric-brain' && targetAttachment === 'fabric-switch') {
    path.push('fabric-hex', 'fabric-switch');
  } else {
    if (path.at(-1) !== targetAttachment) path.push(targetAttachment);
  }
  if (path.at(-1) !== target.id) path.push(target.id);
  return path;
}
function trafficPathEdges(edge, nodesById, displayLayer = 'current') {
  const source = nodesById.get(edge.src), target = nodesById.get(edge.dst);
  if (!source || !target) return [{ ...edge, _displayLayer: displayLayer }];
  // Potential same-segment pivots describe host-to-host reachability, not a
  // physical cable route through the fabric. Draw them directly between the
  // endpoints; observed traffic still expands over the switch/hEX path.
  const path = edge.direct || edge.pivot_possible
    ? [source.id, target.id]
    : fabricRoute(source, target, nodesById);
  const segments = [];
  const segmentByLink = new Map();
  for (let index = 0; index < path.length - 1; index += 1) {
    const src = path[index], dst = path[index + 1];
    if (src === dst) continue;
    const link = [src, dst].sort().join('\u0000');
    const existing = segmentByLink.get(link);
    if (existing) {
      existing.direction = 'both';
      continue;
    }
    const segment = { ...edge, src, dst, _displayLayer: displayLayer, _pathSegment: index };
    segments.push(segment);
    segmentByLink.set(link, segment);
  }
  return segments;
}
function displayEdges(snapshot) {
  const freshPairs = currentEventEdgePairs(snapshot);
  const nodesById = new Map((snapshot.nodes || []).map((node) => [node.id, node]));
  const displayed = [];
  for (const edge of snapshot.edges || []) {
    if (!isCurrentEdge(edge, freshPairs)) {
      // Old event-only overlays are not topology. The remaining static links
      // form the neutral dotted wiring diagram beneath live traffic.
      if (!edge.historical) {
        displayed.push(...trafficPathEdges({ ...edge, connected: false }, nodesById, 'baseline'));
      }
      continue;
    }
    displayed.push(...trafficPathEdges(edge, nodesById));
  }
  return displayed;
}

// ----------------------------------------------------------- force layout --
// A wide topology plane keeps the attack -> DMZ -> CORP -> DATA path readable
// without making the 40+ live nodes tiny or pushing them under the status HUD.
const VB_W = 1800, VB_H = 760;
const simNodes = new Map();   // id -> {id, x,y, vx,vy, fx,fy(null unless pinned), zone, type}
// The topology producer already assigns zone-aware positions. Links describe
// reachability and traffic, not physical distance, so using every link as a
// spring collapses highly connected hosts into an unreadable knot. Keep nodes
// near their published anchors and use physics only to resolve collisions.
const REPULSE_K = 1800;
const MIN_NODE_GAP = 68, COLLISION_K = 0.2, ANCHOR_PULL = 0.11, DAMPING = 0.76;
// Simulation "heat": starts hot so the graph lays itself out, then cools to 0 so it
// comes to rest instead of buzzing. Reheated only on structural change or drag.
let alpha = 1;
const ALPHA_DECAY = 0.015, ALPHA_MIN = 0;
function reheat(v = 1) { alpha = Math.max(alpha, v); }

function nodePositions(nodes) {
  const positions = nodes.map((n) => n.position).filter((p) => Array.isArray(p) && p.length === 2
    && Number.isFinite(Number(p[0])) && Number.isFinite(Number(p[1])));
  const xs = positions.map((p) => Number(p[0])), ys = positions.map((p) => Number(p[1]));
  const minX = Math.min(...xs), maxX = Math.max(...xs), minY = Math.min(...ys), maxY = Math.max(...ys);
  const absolute = minX < 0 || maxX > 100 || minY < 0 || maxY > 100;
  const scale = (value, min, max) => max === min ? 50 : 10 + (Number(value) - min) * 80 / (max - min);
  const result = new Map();
  for (const node of nodes) {
    const valid = Array.isArray(node.position) && node.position.length === 2
      && Number.isFinite(Number(node.position[0])) && Number.isFinite(Number(node.position[1]));
    const [x, y] = valid ? node.position : [50, 50];
    const px = absolute ? scale(x, minX, maxX) : Number(x);
    const py = absolute ? scale(y, minY, maxY) : Number(y);
    result.set(node.id, [Math.min(96, Math.max(4, px)), Math.min(96, Math.max(4, py))]);
  }
  return result;
}

function reconcileSimNodes(nodes) {
  const seen = new Set();
  const positions = nodePositions(nodes);
  for (const n of nodes) {
    seen.add(n.id);
    if (!simNodes.has(n.id)) {
      const [px, py] = positions.get(n.id);
      simNodes.set(n.id, {
        id: n.id, zone: n.zone, type: n.type,
        x: (px / 100) * VB_W, y: (py / 100) * VB_H,
        anchorX: (px / 100) * VB_W, anchorY: (py / 100) * VB_H,
        vx: 0, vy: 0, fx: null, fy: null, dispX: 0, dispY: 0,
      });
      reheat(1);
    } else {
      const s = simNodes.get(n.id);
      s.zone = n.zone; s.type = n.type;
      if (n.position && !s.userMoved) {
        const [px, py] = positions.get(n.id);
        const ax = (px / 100) * VB_W, ay = (py / 100) * VB_H;
        if (Math.abs(ax - s.anchorX) + Math.abs(ay - s.anchorY) > 5) reheat(0.5);
        s.anchorX = ax; s.anchorY = ay;
      }
    }
  }
  for (const id of [...simNodes.keys()]) if (!seen.has(id)) simNodes.delete(id);
}
function forceTick() {
  const nodes = [...simNodes.values()];
  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) {
      const a = nodes[i], b = nodes[j];
      let dx = b.x - a.x, dy = b.y - a.y;
      let distSq = dx * dx + dy * dy;
      if (distSq < 1) {
        // Stable direction for nodes published at the same coordinate. Random
        // near-zero deltas used to create an enormous inverse-square impulse.
        const angle = (stableHash(`${a.id}|${b.id}`) % 360) * Math.PI / 180;
        dx = Math.cos(angle); dy = Math.sin(angle); distSq = 1;
      }
      const dist = Math.sqrt(distSq);
      // Same-zone nodes repel less so they can cluster; cross-zone nodes repel
      // more so the groups stay separated.
      const sameZone = a.zone === b.zone;
      const force = REPULSE_K * (sameZone ? 1.1 : 2.3)
        / Math.max(distSq, MIN_NODE_GAP * MIN_NODE_GAP);
      const fx = (force * dx) / dist, fy = (force * dy) / dist;
      if (a.fx === null) { a.vx -= fx; a.vy -= fy; }
      if (b.fx === null) { b.vx += fx; b.vy += fy; }
      // Hard minimum separation prevents dense, highly connected regions from
      // collapsing back into overlapping labels despite the spring forces.
      if (dist < MIN_NODE_GAP) {
        const push = (MIN_NODE_GAP - dist) * COLLISION_K;
        const cfx = (push * dx) / dist, cfy = (push * dy) / dist;
        if (a.fx === null) { a.vx -= cfx; a.vy -= cfy; }
        if (b.fx === null) { b.vx += cfx; b.vy += cfy; }
      }
    }
  }
  for (const n of nodes) {
    if (n.fx !== null) { n.x = n.fx; n.y = n.fy; n.vx = 0; n.vy = 0; continue; }
    n.vx += (n.anchorX - n.x) * ANCHOR_PULL;
    n.vy += (n.anchorY - n.y) * ANCHOR_PULL;
    n.vx *= DAMPING; n.vy *= DAMPING;
    const speed = Math.hypot(n.vx, n.vy);
    if (speed > 18) { n.vx *= 18 / speed; n.vy *= 18 / speed; }
    // Movement scaled by alpha so the layout eases to a stop (no perpetual jitter).
    n.x = Math.min(VB_W - 40, Math.max(40, n.x + n.vx * alpha));
    n.y = Math.min(VB_H - 40, Math.max(40, n.y + n.vy * alpha));
  }
  alpha += (ALPHA_MIN - alpha) * ALPHA_DECAY;
}

// --------------------------------------------------------------- SVG DOM --
const nodeEls = new Map();  // id -> {g, circle, glyph, label}
const edgeEls = new Map();  // edge key -> {base, flow, toolDot, edge, lane}
const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
let selectedId = null;
let current = null;
let lastRunId = '';

// --------------------------------------------------------------- sound FX --
// Web Audio keeps the dashboard self-contained. Browsers require a user gesture
// before audio starts, so the toggle is deliberately opt-in and old events are
// marked seen even while muted to prevent a noisy history replay on enable.
let soundEnabled = false;
let soundContext = null;
let soundEventsInitialised = false;
const seenSoundEvents = new Set();

function soundCategory(event) {
  const name = String(event?.event || event?.kind || event?.action || '').toLowerCase();
  if (/crown|exfil|data.read|credential/.test(name)) return 'exfil';
  if (/flag/.test(name)) return 'success';
  if (/comprom|solved|foothold|privesc|persist|lateral|implant/.test(name)) return 'attack';
  if (/recon|scan|discover|enumerat/.test(name)) return 'recon';
  if (/defen|contain|isolat|preserve|block/.test(name)) return 'defense';
  if (/error|fail|denied/.test(name)) return 'error';
  return null;
}
function soundEventKey(event) {
  return JSON.stringify([event?.ts, event?.event || event?.kind || event?.action, event?.host || event?.node,
    event?.edge?.src, event?.edge?.dst, event?.evidence]);
}
function beam(startFrequency, endFrequency, start, duration, gain = 0.028, type = 'sine') {
  if (!soundContext) return;
  const oscillator = soundContext.createOscillator();
  const filter = soundContext.createBiquadFilter();
  const volume = soundContext.createGain();
  oscillator.type = type;
  oscillator.frequency.setValueAtTime(startFrequency, start);
  oscillator.frequency.exponentialRampToValueAtTime(endFrequency, start + duration);
  filter.type = 'lowpass';
  filter.frequency.setValueAtTime(Math.max(startFrequency, endFrequency) * 1.6, start);
  filter.Q.setValueAtTime(5, start);
  volume.gain.setValueAtTime(0.0001, start);
  volume.gain.exponentialRampToValueAtTime(gain, start + 0.025);
  volume.gain.exponentialRampToValueAtTime(0.0001, start + duration);
  oscillator.connect(filter).connect(volume).connect(soundContext.destination);
  oscillator.start(start);
  oscillator.stop(start + duration + 0.02);
}
function playSound(category) {
  if (!soundEnabled || !soundContext) return;
  const start = soundContext.currentTime + 0.015;
  const patterns = {
    enabled: [[420, 980, 0, .16], [620, 1420, .11, .18, .018]],
    recon: [[380, 1250, 0, .24], [720, 1700, .12, .2, .016]],
    attack: [[980, 170, 0, .34, .035, 'sawtooth'], [620, 120, .09, .32, .018, 'square']],
    exfil: [[240, 1650, 0, .48, .032, 'triangle'], [460, 2200, .16, .4, .018]],
    defense: [[1300, 460, 0, .22, .026], [440, 920, .2, .2, .02]],
    success: [[320, 1180, 0, .3, .028, 'triangle'], [620, 2100, .18, .36, .02]],
    error: [[210, 65, 0, .42, .038, 'sawtooth']],
  };
  for (const [from, to, offset, duration, gain, type] of patterns[category] || []) {
    beam(from, to, start + offset, duration, gain, type);
  }
}
function processEventSounds(events) {
  const incoming = events || [];
  const newCategories = [];
  for (const event of incoming) {
    const key = soundEventKey(event);
    if (!seenSoundEvents.has(key) && soundEventsInitialised) {
      const category = soundCategory(event);
      if (category) newCategories.push(category);
    }
    seenSoundEvents.add(key);
  }
  soundEventsInitialised = true;
  if (!soundEnabled || !newCategories.length) return;
  const priority = ['exfil', 'success', 'attack', 'defense', 'error', 'recon'];
  playSound(priority.find((category) => newCategories.includes(category)));
}
function updateSoundButton() {
  const button = $('sound-toggle');
  button.textContent = soundEnabled ? '🔊' : '🔇';
  button.setAttribute('aria-pressed', String(soundEnabled));
  button.setAttribute('aria-label', soundEnabled ? 'Mute event sounds' : 'Enable event sounds');
  button.title = soundEnabled ? 'Mute event sounds' : 'Enable event sounds';
}
async function toggleSound() {
  soundEnabled = !soundEnabled;
  if (soundEnabled) {
    const AudioContextClass = window.AudioContext || window.webkitAudioContext;
    if (!AudioContextClass) {
      soundEnabled = false;
      updateSoundButton();
      return;
    }
    soundContext ||= new AudioContextClass();
    if (soundContext.state === 'suspended') await soundContext.resume();
    playSound('enabled');
  }
  try { window.localStorage?.setItem('keystone-sound-enabled', String(soundEnabled)); } catch (_) {}
  updateSoundButton();
}

function svgEl(tag, attrs = {}) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  return el;
}
function ensureNodeEl(node) {
  if (nodeEls.has(node.id)) return nodeEls.get(node.id);
  const g = svgEl('g', { class: 'node-group', 'data-id': node.id });
  // Blue-team "contained/watched" halo: outermost, teal, behind every other
  // ring so it reads as a defensive envelope around the host even when the host
  // is owned (solid red). See DEF_* sets and defenseStatesByNode().
  const containRing = svgEl('circle', { class: 'contain-ring', r: 38 });
  const cloneRing = svgEl('circle', { class: 'clone-ring', r: 34 });
  const currentRing = svgEl('circle', { class: 'focus-ring focus-current-ring', r: 26 });
  const exfilRing = svgEl('circle', { class: 'focus-ring focus-exfil-ring', r: 29 });
  const attackRing = svgEl('circle', { class: 'attack-ring', r: 22 });
  const circle = svgEl('circle', { class: 'node-circle', r: 18 });
  const glyph = svgEl('text', { class: 'node-glyph', dy: '0' });
  const label = svgEl('text', { class: 'node-label', y: 32 });
  const title = svgEl('title');
  g.append(title, containRing, cloneRing, currentRing, exfilRing, attackRing, circle, glyph, label);
  g.addEventListener('click', (ev) => { ev.stopPropagation(); selectNode(node.id); });
  g.addEventListener('mousedown', (ev) => startDrag(ev, node.id));
  $('node-layer').append(g);
  const rec = { g, circle, glyph, label, title };
  nodeEls.set(node.id, rec);
  return rec;
}
function edgeKey(e) { return JSON.stringify([e._displayLayer || '', e.id || '', e.src, e.dst, e.kind || '', edgeTool(e), edgeDataType(e)]); }
function pairKey(e) { return [e.src, e.dst].sort().join('|'); }
function ensureEdgeEl(e) {
  const key = edgeKey(e);
  if (edgeEls.has(key)) return edgeEls.get(key);
  const group = svgEl('g', { class: 'edge-group' });
  const base = svgEl('line', { class: 'edge-line' });
  const flow = svgEl('line', { class: 'edge-flow' });
  const toolDot = svgEl('circle', { class: 'edge-tool-dot', r: 2.3 });
  group.append(base, flow, toolDot);
  $('edge-layer').append(group);
  const hash = stableHash(key);
  const rec = { group, base, flow, toolDot, edge: e, lane: 0,
    period: 8 + hash % 5, offset: (hash >>> 8) % 13 };
  edgeEls.set(key, rec);
  return rec;
}
function pruneEls(nodeIds, edgeKeys) {
  for (const [id, rec] of [...nodeEls]) if (!nodeIds.has(id)) { rec.g.remove(); nodeEls.delete(id); }
  for (const [key, rec] of [...edgeEls]) if (!edgeKeys.has(key)) { rec.group.remove(); edgeEls.delete(key); }
}

function paintGraph(snapshot) {
  const nodes = snapshot.nodes || [];
  // The server may report several firewall events for the same visual link
  // (one per blocked port). One SVG edge represents that route; counting the
  // duplicates as parallel lanes offsets the surviving line away from its
  // endpoint. Keep the newest record for each rendered edge identity.
  const edgesByKey = new Map();
  for (const edge of displayEdges(snapshot)) edgesByKey.set(edgeKey(edge), edge);
  const edges = [...edgesByKey.values()];
  const focus = snapshot.focus || {};
  // Enter focus ("incident") view only when the run actually reports a focus host —
  // a compromise, an exfil, or a current operator host. This works for the live
  // lab too: at rest nothing is focused and the full topology stays visible.
  const hasFocus = Boolean(focus.current || (focus.compromised || []).length || focus.exfil);
  const focused = snapshot.mode === 'live' && hasFocus;
  // The "EvilKit clone on host" marker (red + purple ring) shows whenever the
  // telemetry reports a current host, even when the incident overlay is off.
  const liveCurrentId = focus.current?.id || null;
  const exfilId = focused ? focus.exfil?.id : null;
  const compromisedIds = new Set(focused ? (focus.compromised || []).map((host) => host.id) : []);
  const cloneNodeIds = new Set((snapshot.clone_fleet?.clones || []).map((clone) => clone.node_id).filter(Boolean));
  // Beaconing hosts (beacons.jsonl) count as clone-present too: a fresh C2
  // beacon is the dashboard's own proof that a clone lives on that host.
  for (const n of nodes) if (n.c2_beacon) cloneNodeIds.add(n.id);
  // Compromised hosts render red at ALL times, not only inside the incident
  // (focus) overlay. compromisedIds stays focus-scoped (it drives the dimming of
  // the rest of the board); compromisedAll drives the persistent red.
  const compromisedAll = new Set((focus.compromised || []).map((host) => host.id));
  // Never desaturate the whole map. The incident overlay used to grey every
  // non-incident node whenever a "current host" was reported, and flip back to
  // the colored map when that signal lapsed (45s activity window) — so the board
  // flickered grey<->green. Keep the full colored topology always visible and
  // show the incident as persistent overlays (red compromised, purple current
  // ring, under-attack ring) instead.
  $('graph').classList.remove('focus-view');
  reconcileSimNodes(nodes);

  const nodeIds = new Set(nodes.map((n) => n.id));
  const edgeKeys = new Set(edges.map(edgeKey));
  pruneEls(nodeIds, edgeKeys);

  const defStates = defenseStatesByNode(snapshot);

  for (const n of nodes) {
    const rec = ensureNodeEl(n);
    const def = defStates.get(n.id);
    rec.g.classList.toggle('contained', Boolean(def && def.cls === 'contained'));
    rec.g.classList.toggle('watched', Boolean(def && def.cls === 'watched'));
    // Red = compromised. Backed by the (sticky) node state as well as the focus
    // set, so a host that has been owned stays red and doesn't flick off on a
    // transient read.
    const owned = compromisedAll.has(n.id) || ['solved', 'data-read'].includes(n.state);
    const isCurrent = n.id === liveCurrentId;
    // Compromised = dark red, permanent for the rest of the run. The host
    // EvilKit is currently operating from pulses bright red on top of it.
    const baseColor = isCurrent ? '#EF4444' : owned ? '#7F1D1D' : colorForNode(n);
    rec.circle.setAttribute('fill', baseColor);
    rec.circle.setAttribute('stroke', shade(baseColor, -25));
    rec.circle.classList.toggle('busy', n.state === 'in-progress' || n.state === 'locked');
    rec.circle.classList.toggle('selected', n.id === selectedId);
    rec.g.classList.toggle('focus-current', isCurrent);
    rec.g.classList.toggle('focus-compromised', compromisedIds.has(n.id));
    // Persistent red on owned hosts, whether or not the incident overlay is on.
    rec.g.classList.toggle('compromised', owned);
    rec.g.classList.toggle('focus-exfil', n.id === exfilId);
    rec.g.classList.toggle('clone-present', cloneNodeIds.has(n.id));
    // live "under attack" ring, independent of the focus overlay: shows whenever
    // the watcher sees attack-class traffic hitting this host. Rings layer, so
    // it stays visible even on a compromised (solid red) or current (purple
    // ring) host.
    rec.g.classList.toggle('under-attack', Boolean(n.under_attack));
    // "EvilKit is working on this host" — orange pulse. Rings layer, so this
    // can stack with the purple current-host ring; only solid-red compromised
    // hosts suppress it (red fill already says owned).
    rec.g.classList.toggle('targeting', n.state === 'in-progress' && !owned);
    rec.glyph.textContent = TYPE_GLYPH[n.type] || String(n.type || '?').slice(0, 2).toUpperCase();
    rec.label.textContent = (def ? '🛡 ' : '') + (n.label || n.id);
    const highlights = [cloneNodeIds.has(n.id) ? 'EvilKit clone connected' : '', isCurrent ? 'EvilKit operating here' : '',
      n.c2_beacon ? `C2 beacon ${n.c2_beacon.bid}` : '', compromisedIds.has(n.id) ? 'compromised' : '',
      def ? `blukit: ${def.action} (${def.label})` : '',
      n.id === exfilId ? 'exfiltrating from host' : ''].filter(Boolean);
    rec.title.textContent = `${n.label || n.id}${n.host ? ' · ' + n.host : ''} · ${highlights.join(', ') || n.state || 'unknown'} · ${n.address || n.ip || 'no address'}`;
  }
  const pairCounts = new Map(), pairIndices = new Map();
  for (const e of edges) pairCounts.set(pairKey(e), (pairCounts.get(pairKey(e)) || 0) + 1);
  for (const e of edges) {
    const rec = ensureEdgeEl(e);
    rec.edge = e;
    const pair = pairKey(e), index = pairIndices.get(pair) || 0;
    pairIndices.set(pair, index + 1);
    rec.lane = (index - (pairCounts.get(pair) - 1) / 2) * 6;
    const tool = edgeTool(e), type = edgeDataType(e);
    rec.base.setAttribute('stroke', EDGE_KIND_COLOR[e.kind] || '#82909C');
    rec.base.className.baseVal = 'edge-line state-' + (e.state || 'unknown')
      + (e.kind ? ' kind-' + e.kind : '')
      + (edgeConnection(e) === 'disconnected' ? ' disconnected' : '')
      + (e.historical ? ' historical' : '');
    rec.group.classList.toggle('kind-tunnel', e.kind === 'tunnel');
    rec.group.classList.toggle('baseline', e._displayLayer === 'baseline');
    rec.group.classList.toggle('pivot-possible', Boolean(e.pivot_possible));
    rec.group.classList.toggle('current-traffic', e._displayLayer === 'current');
    rec.group.classList.toggle('fabric-segment', e.src.startsWith('fabric-') || e.dst.startsWith('fabric-'));
    // A link "flows" (marching-ants pulse) when it is carrying live activity: a
    // tool call in flight, a used edge, or classified attack/recon/tunnel
    // traffic. Each distinct tool call keeps its own colour (toolColor); edges on
    // or into an owned host — and any attack-class edge — pulse red.
    const hot = e.kind === 'attack' || compromisedAll.has(e.src) || compromisedAll.has(e.dst);
    const live = Boolean(tool) || e.state === 'used' || ['attack', 'recon', 'tunnel'].includes(e.kind);
    rec.flow.setAttribute('stroke', hot ? '#DC2626'
      : (type ? dataColor(type) : tool ? toolColor(tool) : (EDGE_KIND_COLOR[e.kind] || '#82909C')));
    rec.group.classList.toggle('flowing', live);
    rec.group.classList.toggle('hot', hot);
    if (tool) rec.toolDot.setAttribute('fill', toolColor(tool));
    rec.toolDot.style.display = tool && type ? '' : 'none';
    rec.group.setAttribute('aria-label', `${e.src} to ${e.dst}: ${e.kind || 'link'}, ${e.state || 'unknown'}, ${edgeDirection(e)}${tool ? ', MCP ' + tool : ''}${type ? ', ' + type : ''}`);
    // Keep the physical topology readable during an incident. Host rings and
    // animated flow overlays already identify the active path; dimming every
    // other link made the map look disabled and hid useful context.
    rec.group.style.opacity = '1';
  }
  buildFlowLegend(edges);
}
function positionFrame() {
  const t = performance.now();
  for (const [id, rec] of nodeEls) {
    const n = simNodes.get(id);
    if (!n) continue;
    rec.g.setAttribute('transform', `translate(${n.x.toFixed(1)},${n.y.toFixed(1)})`);
  }
  for (const rec of edgeEls.values()) {
    const e = rec.edge;
    const a = simNodes.get(e.src), b = simNodes.get(e.dst);
    if (!a || !b) continue;
    const dx = b.x - a.x, dy = b.y - a.y, length = Math.hypot(dx, dy) || 1;
    const ux = dx / length, uy = dy / length, nx = -uy, ny = ux;
    const start = { x: a.x + ux * 21 + nx * rec.lane, y: a.y + uy * 21 + ny * rec.lane };
    const end = { x: b.x - ux * 21 + nx * rec.lane, y: b.y - uy * 21 + ny * rec.lane };
    rec.base.setAttribute('x1', start.x); rec.base.setAttribute('y1', start.y);
    rec.base.setAttribute('x2', end.x); rec.base.setAttribute('y2', end.y);

    const connection = edgeConnection(e);
    const direction = edgeDirection(e);
    const cycle = (t / 1000 + rec.offset) / rec.period;
    const reverse = direction === 'reverse' || (direction === 'both' && Math.floor(cycle) % 2 === 1);
    const from = reverse ? end : start, to = reverse ? start : end;
    if (connection !== 'connected') {
      rec.flow.style.opacity = '0'; rec.toolDot.style.opacity = '0';
      continue;
    }
    const first = 0, last = 1;
    const x1 = from.x + (to.x - from.x) * first, y1 = from.y + (to.y - from.y) * first;
    const x2 = from.x + (to.x - from.x) * last, y2 = from.y + (to.y - from.y) * last;
    rec.flow.setAttribute('x1', x1); rec.flow.setAttribute('y1', y1);
    rec.flow.setAttribute('x2', x2); rec.flow.setAttribute('y2', y2);
    rec.flow.setAttribute('stroke-dashoffset', reducedMotion ? 0 : -t / 42);
    rec.flow.style.opacity = '0.9';
    if (rec.toolDot.style.display !== 'none') {
      const travel = reducedMotion ? 0.5 : (t / 1800 + rec.offset / 3) % 1;
      const dotAt = first + (last - first) * travel;
      rec.toolDot.setAttribute('cx', from.x + (to.x - from.x) * dotAt);
      rec.toolDot.setAttribute('cy', from.y + (to.y - from.y) * dotAt);
      rec.toolDot.style.opacity = '0.9';
    }
  }
}
function animate() {
  forceTick();
  positionFrame();
  requestAnimationFrame(animate);
}
function shade(hex, percent) {
  const n = parseInt(hex.slice(1), 16);
  let r = (n >> 16) + percent, g = ((n >> 8) & 0xff) + percent, b = (n & 0xff) + percent;
  r = Math.max(0, Math.min(255, r)); g = Math.max(0, Math.min(255, g)); b = Math.max(0, Math.min(255, b));
  return '#' + ((1 << 24) + (r << 16) + (g << 8) + b).toString(16).slice(1);
}

// ------------------------------------------------------------- pan / zoom --
let view = { x: 0, y: 0, k: 1 };
function applyView() { $('viewport').setAttribute('transform', `translate(${view.x},${view.y}) scale(${view.k})`); }
function toSvgPoint(evt) {
  const svg = $('graph');
  const pt = svg.createSVGPoint();
  pt.x = evt.clientX; pt.y = evt.clientY;
  return pt.matrixTransform(svg.getScreenCTM().inverse());
}
let panState = null, dragId = null;
$('graph').addEventListener('mousedown', (ev) => {
  if (ev.target.closest('.node-group')) return;
  panState = { startX: ev.clientX, startY: ev.clientY, ox: view.x, oy: view.y };
  $('graph').classList.add('panning');
});
function startDrag(ev, id) {
  ev.preventDefault();
  dragId = id;
  const n = simNodes.get(id);
  if (n) { n.fx = n.x; n.fy = n.y; }
  reheat(0.6);
}
window.addEventListener('mousemove', (ev) => {
  if (panState) {
    view.x = panState.ox + (ev.clientX - panState.startX);
    view.y = panState.oy + (ev.clientY - panState.startY);
    applyView();
  } else if (dragId) {
    const p = toSvgPointInViewport(ev);
    const n = simNodes.get(dragId);
    if (n) { n.fx = p.x; n.fy = p.y; }
    reheat(0.3);
  }
});
function toSvgPointInViewport(evt) {
  const p = toSvgPoint(evt);
  return { x: (p.x - view.x) / view.k, y: (p.y - view.y) / view.k };
}
window.addEventListener('mouseup', () => {
  panState = null;
  if (dragId) {
    const n = simNodes.get(dragId);
    if (n) { n.anchorX = n.x = n.fx; n.anchorY = n.y = n.fy; n.userMoved = true; n.fx = null; n.fy = null; }
    dragId = null; reheat(0.5);
  }
  $('graph').classList.remove('panning');
});
$('graph').addEventListener('wheel', (ev) => {
  ev.preventDefault();
  const before = toSvgPoint(ev);
  const factor = ev.deltaY < 0 ? 1.1 : 0.9;
  const newK = Math.min(3, Math.max(0.4, view.k * factor));
  view.x = before.x - ((before.x - view.x) / view.k) * newK;
  view.y = before.y - ((before.y - view.y) / view.k) * newK;
  view.k = newK;
  applyView();
}, { passive: false });

// ------------------------------------------------------------- selection --
function selectNode(id) {
  selectedId = id;
  for (const [nid, rec] of nodeEls) rec.circle.classList.toggle('selected', nid === id);
  renderInspector();
}
$('graph').addEventListener('click', (ev) => { if (ev.target === $('graph')) { selectedId = null; renderInspector(); for (const rec of nodeEls.values()) rec.circle.classList.remove('selected'); } });

// What EvilKit would plausibly care about on each host type, used as a hint when
// topology.json hasn't declared a `stores` list for that node.
const TYPE_DATA_HINT = {
  web: ['application code', 'session cookies', 'config files'],
  db: ['customer records', 'credentials table', 'audit log'],
  ad: ['user accounts', 'password hashes', 'group policy'],
  workstation: ['user documents', 'browser profile', 'cached creds'],
  router: ['routing table', 'ACLs', 'management creds'],
  data: ['exfil target: crown-jewel files'],
  operator: ['operator toolkit'],
};
// Event types that describe EvilKit *doing something* on a host (as opposed to
// passive discovery). Used to summarise the current attack in the inspector.
const EVILKIT_ACTIVE_EVENTS = new Set([
  'node_in_progress', 'exploit', 'foothold', 'credential_spray',
  'brute_force', 'enum', 'auth_attempt', 'exfil', 'data_read',
  'node_data_read', 'privesc', 'persist', 'host_compromised', 'crown_exfil',
]);

// Blue-team (blukit / gpt-Sol) response actions, emitted by keystone.emit as
// `defense_*` events. A separate dimension from the attacker tier: containment
// actions cut the intruder off a host; forensic actions only mark it watched.
const DEF_CONTAIN_EVENTS = new Set([
  'defense_isolate', 'defense_block', 'defense_disable_account',
  'defense_revoke', 'defense_kill', 'defense_quarantine',
]);
const DEF_WATCH_EVENTS = new Set(['defense_capture', 'defense_preserve', 'defense_detect']);
const DEF_LABEL = {
  defense_isolate: 'isolated', defense_block: 'blocked', defense_disable_account: 'acct disabled',
  defense_revoke: 'creds revoked', defense_kill: 'proc killed', defense_quarantine: 'quarantined',
  defense_capture: 'capturing', defense_preserve: 'evidence held', defense_detect: 'detected',
};
const isDefenseEvent = (ev) => typeof ev === 'string' && ev.indexOf('defense_') === 0;

// Resolve each defence event's subject to a topology node (by id, host, or
// address/ip, since blukit acts on IPs) and fold into {nodeId -> {cls,label,action}}.
// Containment beats watch; later events win within a class.
function defenseStatesByNode(snapshot) {
  const nodes = snapshot.nodes || [];
  const keyToId = new Map();
  for (const n of nodes) {
    for (const k of [n.id, n.host, n.address, n.ip]) if (k) keyToId.set(String(k), n.id);
    const addr = String(n.address || n.ip || '').split(' ')[0];
    if (addr) keyToId.set(addr, n.id);
  }
  const out = new Map();
  for (const e of (snapshot.events || [])) {
    if (!isDefenseEvent(e.event)) continue;
    const nid = keyToId.get(String(e.host != null ? e.host : e.node));
    if (!nid) continue;
    const contain = DEF_CONTAIN_EVENTS.has(e.event);
    const prev = out.get(nid);
    if (contain || !prev) {
      out.set(nid, { cls: contain ? 'contained' : 'watched', label: DEF_LABEL[e.event] || 'defended', action: e.action || e.event });
    }
  }
  return out;
}

function renderInspector() {
  const root = $('inspector');
  if (!selectedId || !current) { root.innerHTML = '<p class="empty">Select a node to inspect it.</p>'; return; }
  const node = (current.nodes || []).find((n) => n.id === selectedId);
  if (!node) { root.innerHTML = '<p class="empty">Node no longer present.</p>'; return; }
  const edges = (current.edges || []).filter((e) => e.src === selectedId || e.dst === selectedId);
  const events = current.events || [];
  const compromised = ['solved', 'data-read'].includes(node.state);
  const targeting = node.state === 'in-progress';
  root.replaceChildren();
  const fields = [['Name', node.label || node.id], ['Host', node.host || '—'], ['Type', node.type], ['Zone', node.zone],
    ['Status', node.state], ['Address', node.address || '—']];
  if (node.telemetry_source) fields.push(['Telemetry', node.telemetry_source]);
  if (node.telemetry_status) fields.push(['Runtime', node.telemetry_status]);
  for (const [key, value] of Object.entries(node.telemetry || {})) {
    fields.push([key.replaceAll('_', ' '), value]);
  }
  for (const [key, value] of fields) {
    const row = document.createElement('div'); row.className = 'inspector-field';
    const dt = document.createElement('dt'), dd = document.createElement('dd');
    dt.textContent = key; dd.textContent = value || '—'; row.append(dt, dd); root.append(row);
  }

  // --- EvilKit activity: what is actively being attempted on this host ---
  if (targeting || node.under_attack) {
    const section = document.createElement('section');
    section.className = 'inspector-section targeting';
    const h = document.createElement('h3'); h.textContent = 'EvilKit activity (live)'; section.append(h);
    const hostEvents = events.filter((e) => e.host === selectedId && (EVILKIT_ACTIVE_EVENTS.has(e.event) || isDefenseEvent(e.event))).slice(-5).reverse();
    if (hostEvents.length) {
      const ul = document.createElement('ul');
      for (const ev of hostEvents) {
        const li = document.createElement('li');
        const ts = document.createElement('span'); ts.className = 'ts';
        ts.textContent = ev.ts ? new Date(ev.ts * 1000).toLocaleTimeString() : '';
        const type = document.createElement('span'); type.className = 'ev-type';
        type.textContent = ' ' + (ev.event || '').replaceAll('_', ' ') + ' ';
        const detail = document.createElement('span');
        detail.textContent = ev.evidence || '';
        li.append(ts, type, detail);
        ul.append(li);
      }
      section.append(ul);
    } else {
      const p = document.createElement('p'); p.className = 'hint';
      p.textContent = 'Attack traffic observed, but no detailed events reported yet.';
      section.append(p);
    }
    root.append(section);
  }

  // --- Data stored here: shown while the host is not yet compromised ---
  if (!compromised) {
    const section = document.createElement('section');
    section.className = 'inspector-section data';
    const h = document.createElement('h3'); h.textContent = 'Data stored here'; section.append(h);
    const stores = Array.isArray(node.stores) ? node.stores
      : typeof node.stores === 'string' ? node.stores.split(',').map((s) => s.trim()).filter(Boolean)
      : TYPE_DATA_HINT[node.type] || [];
    const authored = Array.isArray(node.stores) || typeof node.stores === 'string';
    if (stores.length) {
      const row = document.createElement('div');
      for (const item of stores) {
        const chip = document.createElement('span'); chip.className = 'inspector-store-chip'; chip.textContent = item;
        row.append(chip);
      }
      section.append(row);
      if (!authored) {
        const p = document.createElement('p'); p.className = 'hint';
        p.textContent = `Inferred from device type (${node.type}). Set 'stores' in topology.json to override.`;
        section.append(p);
      }
    } else {
      const p = document.createElement('p'); p.className = 'hint';
      p.textContent = 'No data inventory declared for this host.';
      section.append(p);
    }
    root.append(section);
  }

  const links = document.createElement('div'); links.className = 'inspector-links';
  for (const e of edges) {
    const row = document.createElement('div');
    const tool = edgeTool(e), type = edgeDataType(e);
    row.textContent = `${e.src === selectedId ? '→' : '←'} ${e.src === selectedId ? e.dst : e.src} · ${e.kind || 'link'} · ${e.state || 'unknown'}`
      + `${tool ? ' · MCP ' + tool : ''}${type ? ' · ' + type : ''} · ${edgeDirection(e)}`;
    links.append(row);
  }
  if (!edges.length) links.textContent = 'No links.';
  root.append(links);
}

// ------------------------------------------------------------------ legend --
function legendSwatch(container, color, text) {
  const row = document.createElement('div');
  row.className = 'swatch-row';
  const dot = document.createElement('span'); dot.className = 'swatch-dot'; dot.style.backgroundColor = color;
  const label = document.createElement('span'); label.textContent = text;
  row.append(dot, label);
  container.append(row);
}
function legendLine(container, color, text, style) {
  const row = document.createElement('div');
  row.className = 'swatch-row';
  const line = document.createElement('span'); line.className = 'swatch-line ' + (style || ''); line.style.borderTopColor = color;
  const label = document.createElement('span'); label.textContent = text;
  row.append(line, label);
  container.append(row);
}
function buildStaticLegend() {
  const status = $('legend-status'); status.innerHTML = '';
  for (const [state, label] of NODE_STATUS_LEGEND) legendSwatch(status, STATUS_COLOR[state], label);
  const ringRow = document.createElement('div'); ringRow.className = 'swatch-row';
  const ringDot = document.createElement('span'); ringDot.className = 'swatch-dot';
  ringDot.style.backgroundColor = '#EF4444'; ringDot.style.border = '2px solid #B91C1C';
  const ringLabel = document.createElement('span'); ringLabel.textContent = 'EvilKit active here (bright red pulse)';
  ringRow.append(ringDot, ringLabel); status.append(ringRow);
  const type = $('legend-type'); type.innerHTML = '';
  for (const [k, v] of Object.entries(TYPE_GLYPH)) {
    const row = document.createElement('div'); row.className = 'swatch-row';
    const glyph = document.createElement('span'); glyph.className = 'swatch-glyph'; glyph.textContent = v;
    const label = document.createElement('span'); label.textContent = k;
    row.append(glyph, label); type.append(row);
  }
  const kind = $('legend-edge-kind'); kind.innerHTML = '';
  // Friendly labels; order and wording match the traffic colour scheme.
  const EDGE_KIND_LABEL = { network: 'normal traffic', firewall: 'firewall policy path', attack: 'attacking traffic', recon: 'recon traffic', data: 'data flow', tunnel: 'SSH tunnel / pivot', implant: 'implant / IoT link', trust: 'trust relationship', c2: 'C2 beacon / clone traffic' };
  for (const k of ['network', 'firewall', 'tunnel', 'recon', 'attack', 'data', 'implant', 'trust', 'c2']) legendLine(kind, EDGE_KIND_COLOR[k], EDGE_KIND_LABEL[k]);
  const state = $('legend-edge-state'); state.innerHTML = '';
  legendLine(state, '#444', 'unknown (faint dots)', 'dotted');
  legendLine(state, '#6D5AA6', 'direct pivot possible', 'dotted');
  legendLine(state, '#444', 'discovered (dashed)', 'dashed');
  legendLine(state, '#444', 'used (solid)', '');
}
let lastFlowLegendKey = '';
function buildFlowLegend(edges) {
  const tools = [...new Set(edges.map(edgeTool).filter(Boolean))].sort();
  const types = [...new Set(edges.map(edgeDataType).filter(Boolean))].sort();
  const key = JSON.stringify([tools, types]);
  if (key === lastFlowLegendKey) return;
  lastFlowLegendKey = key;
  const toolGroup = $('legend-tool-group'), typeGroup = $('legend-data-group');
  toolGroup.hidden = false; typeGroup.hidden = !types.length;
  const toolRoot = $('legend-tool'), typeRoot = $('legend-data');
  toolRoot.replaceChildren(); typeRoot.replaceChildren();
  if (!tools.length) {
    const empty = document.createElement('span'); empty.className = 'swatch-empty';
    empty.textContent = 'No tool names in this feed'; toolRoot.append(empty);
  }
  for (const tool of tools) legendSwatch(toolRoot, toolColor(tool), tool);
  for (const type of types) legendLine(typeRoot, dataColor(type), type);
}

// --------------------------------------------------------- run highlights --
function renderFocus(snapshot) {
  const focusRun = snapshot.mode === 'live' && snapshot.status?.run_id !== 'live-brain';
  const focus = focusRun ? (snapshot.focus || {}) : {};
  const currentHost = focus.current, exfilHost = focus.exfil;
  const compromised = focus.compromised || [];
  $('focus-current-host').textContent = currentHost?.label || 'Not reported';
  $('focus-current-detail').textContent = currentHost ? (currentHost.address || 'Current host reported by run telemetry')
    : focusRun ? 'No current host reported' : 'Waiting for an EvilKit run';
  $('focus-compromised-count').textContent = `${compromised.length} confirmed`;
  const hostList = $('focus-compromised-hosts'); hostList.replaceChildren();
  if (!compromised.length) hostList.textContent = 'No confirmed hosts';
  for (const host of compromised) {
    const chip = document.createElement('span'); chip.className = 'focus-host-chip';
    chip.textContent = host.label; chip.title = host.address || host.id; hostList.append(chip);
  }
  $('focus-exfil-host').textContent = exfilHost?.label || 'Not reported';
  $('focus-exfil-detail').textContent = exfilHost ? (exfilHost.address || 'Exfiltration in progress')
    : 'No active exfiltration reported';
  document.querySelector('.focus-current-card').classList.toggle('is-active', Boolean(currentHost));
  document.querySelector('.focus-compromised-card').classList.toggle('is-active', compromised.length > 0);
  document.querySelector('.focus-exfil-card').classList.toggle('is-active', Boolean(exfilHost));
}

function renderSegments(snapshot) {
  const root = $('segment-strip'); root.replaceChildren();
  for (const zone of snapshot.zones || []) {
    if (!zone || typeof zone !== 'object') continue;
    const card = document.createElement('article'); card.className = 'segment-card'; card.dataset.zone = zone.id || '';
    const name = document.createElement('strong'); name.className = 'segment-name'; name.textContent = zone.label || zone.id;
    const cidr = document.createElement('span'); cidr.className = 'segment-cidr'; cidr.textContent = zone.cidr || '';
    const policy = document.createElement('span'); policy.className = 'segment-policy'; policy.textContent = zone.policy || '';
    card.append(name, cidr, policy); root.append(card);
  }
}

// ---------------------------------------------------------- clone activity --
function renderClones(snapshot) {
  const fleet = snapshot.clone_fleet || {};
  const clones = fleet.clones || [];
  const running = clones.filter((clone) => ['running', 'working'].includes(clone.status)).length;
  const online = clones.filter((clone) => clone.status !== 'offline').length;
  $('clone-summary').textContent = clones.length
    ? `${online}/${clones.length} online${running ? ` · ${running} working` : ''}`
    : 'No clones detected';
  const hub = $('clone-hub-state');
  hub.textContent = fleet.connected ? 'Mesh live' : 'Mesh unavailable';
  hub.className = 'clone-hub-state' + (fleet.connected ? '' : ' is-offline');
  hub.title = fleet.error || 'Live state from the EvilKit mesh hub';

  const root = $('clone-list'); root.replaceChildren();
  if (!clones.length) {
    const empty = document.createElement('div'); empty.className = 'clone-empty';
    empty.textContent = fleet.error || 'No EvilKit clones have registered.'; root.append(empty);
    return;
  }
  for (const clone of clones) {
    const card = document.createElement('article');
    const isRunning = ['running', 'working'].includes(clone.status);
    card.className = `clone-card${isRunning ? ' is-running' : ''}${clone.status === 'offline' ? ' is-offline' : ''}`;
    const dot = document.createElement('i'); dot.className = 'clone-dot';
    const copy = document.createElement('div'); copy.className = 'clone-copy';
    const name = document.createElement('strong'); name.className = 'clone-name'; name.textContent = clone.name;
    const activity = document.createElement('span'); activity.className = 'clone-activity'; activity.textContent = clone.activity || 'Standing by for a task';
    const meta = document.createElement('span'); meta.className = 'clone-meta';
    const where = clone.node_id || clone.host || 'host not mapped';
    const seen = clone.last_seen ? ` · seen ${new Date(clone.last_seen * 1000).toLocaleTimeString()}` : '';
    meta.textContent = `${String(clone.status || 'unknown').replaceAll('_', ' ')} · ${where}${seen}`;
    copy.append(name, activity, meta);
    const terminal = document.createElement('span');
    terminal.className = 'clone-terminal' + (clone.terminal_open ? '' : ' is-closed');
    terminal.textContent = clone.terminal_open ? 'terminal open' : 'no terminal';
    card.append(dot, copy, terminal); root.append(card);
  }
}

// ----------------------------------------------------- EvilKit capabilities --
function renderAttackFeatures(snapshot) {
  const summary = snapshot.attack_features || {};
  const features = summary.features || [];
  const engine = $('attack-engine');
  engine.textContent = summary.engine ? summary.engine.toUpperCase() : 'WAITING';
  engine.className = 'pill ' + (summary.engine ? 'pill-running' : 'pill-idle');
  engine.title = summary.session_id ? `Session ${summary.session_id}` : 'No EvilKit session reported';

  const root = $('attack-feature-list'); root.replaceChildren();
  for (const feature of features) {
    const chip = document.createElement('span');
    chip.className = 'attack-feature-chip' + (feature.state === 'active' ? ' is-active' : feature.state === 'observed' ? ' is-observed' : '');
    chip.textContent = feature.label;
    const when = feature.last_seen ? new Date(feature.last_seen * 1000).toLocaleTimeString() : 'not observed';
    chip.title = feature.count ? `${feature.count} event${feature.count === 1 ? '' : 's'} · last ${when}${feature.last_tool ? ` · ${feature.last_tool}` : ''}` : 'Not observed in this run';
    root.append(chip);
  }
  const active = features.find((feature) => feature.id === summary.current);
  const latest = [...features].filter((feature) => feature.count).sort((a, b) => (b.last_seen || 0) - (a.last_seen || 0))[0];
  const result = summary.last_exit_code == null ? '' : ` · exit ${summary.last_exit_code}`;
  const host = summary.last_host ? ` on ${summary.last_host}` : '';
  $('attack-feature-detail').textContent = active
    ? `Active: ${active.label}${host}${active.last_tool ? ` · ${active.last_tool}` : ''}${result}`
    : latest ? `Last: ${latest.label}${host}${latest.last_tool ? ` · ${latest.last_tool}` : ''}${result}`
    : 'No attack activity observed';
}

// --------------------------------------------------------------- run card --
function fmtTime(iso) {
  if (!iso) return '—';
  try { return new Date(iso).toLocaleString(); } catch { return iso; }
}

// ---- run clock ----
let clockStarted = null;
let clockFinished = null;
let clockInterval = null;
function fmtElapsed(ms) {
  const s = Math.floor(ms / 1000);
  const h = String(Math.floor(s / 3600)).padStart(2, '0');
  const m = String(Math.floor((s % 3600) / 60)).padStart(2, '0');
  const sec = String(s % 60).padStart(2, '0');
  return `${h}:${m}:${sec}`;
}
function tickClock() {
  if (!clockStarted) { $('run-clock').textContent = '00:00:00'; return; }
  const end = clockFinished || Date.now();
  $('run-clock').textContent = fmtElapsed(Math.max(0, end - clockStarted));
}
function startClock(isoStarted, isFinished) {
  try { clockStarted = isoStarted ? new Date(isoStarted).getTime() : null; } catch { clockStarted = null; }
  clockFinished = isFinished ? Date.now() : null;
  if (!clockInterval) clockInterval = setInterval(tickClock, 1000);
  tickClock();
}

function renderRunCard(snapshot) {
  const status = snapshot.status || {};
  const state = status.state || 'unknown';
  const pill = $('run-state-pill');
  pill.textContent = state.toUpperCase();
  pill.className = 'pill ' + ({ running: 'pill-running', starting: 'pill-running', active: 'pill-running',
    paused: 'pill-paused', blocked: 'pill-paused', hold: 'pill-paused', holding: 'pill-paused', suspended: 'pill-paused',
    finished: 'pill-finished', complete: 'pill-finished', completed: 'pill-finished',
    error: 'pill-error', failed: 'pill-error' }[state] || 'pill-idle');
  $('run-range').textContent = status.range || '—';
  $('run-id').textContent = status.run_id || '—';
  $('run-model').textContent = status.model || '—';
  // Where the board's topology came from when no run is active. An inserted
  // range stick outranks the checked-out build plan, so the viewer can tell
  // whether they are looking at this lab or at a foreign estate on a stick.
  const sourcePill = $('run-source-pill');
  const source = status.topology_source;
  if (source === 'stick' || source === 'build') {
    sourcePill.hidden = false;
    sourcePill.textContent = source === 'stick' ? 'USB STICK' : 'BUILD PLAN';
    sourcePill.className = 'pill ' + (source === 'stick' ? 'pill-stick' : 'pill-idle');
    sourcePill.title = source === 'stick'
      ? 'Topology read from the inserted range stick'
      : 'Topology read from this lab\'s Keystone build plan';
  } else {
    sourcePill.hidden = true;
    sourcePill.className = 'pill pill-idle';
    sourcePill.title = '';
  }
  // Score widget — real Keystone scorer output (status.score / status.score_max),
  // with a per-category breakdown as a tooltip when present.
  const score = status.score;
  const scoreEl = $('run-score');
  const maxScore = (typeof status.score_max === 'number' && status.score_max > 0) ? status.score_max : 129;
  $('run-score-max').textContent = '/ ' + maxScore;
  if (score != null && score !== '') {
    scoreEl.textContent = typeof score === 'number' ? score.toFixed(1) : score;
    const pct = Math.min(100, Math.max(0, (parseFloat(score) / maxScore) * 100));
    $('score-fill').style.width = pct + '%';
    const bd = status.score_breakdown;
    scoreEl.title = (bd && typeof bd === 'object')
      ? Object.entries(bd).map(([n, c]) => `${n}: ${(+c.points).toFixed(1)}/${c.max}`).join('\n')
      : '';
  } else {
    scoreEl.textContent = '—';
    $('score-fill').style.width = '0%';
    scoreEl.title = '';
  }
  $('run-started').textContent = fmtTime(status.started);
  // Clock
  const isActive = ['running', 'starting', 'active'].includes(state);
  const isDone = ['finished', 'complete', 'completed', 'stopped'].includes(state);
  startClock(status.started, isDone);
  if (!status.started) { clockStarted = null; tickClock(); }

  const step = status.current_step || {};
  $('run-step').textContent = step.detail ? `${step.host ? step.host + ': ' : ''}${step.detail}` : 'Waiting for telemetry…';
  const flagRow = $('flag-row'); flagRow.innerHTML = '';
  for (const f of status.flags || []) {
    const chip = document.createElement('span'); chip.className = 'flag-chip'; chip.textContent = f; flagRow.append(chip);
  }
}

// ----------------------------------------------------------------- events --
let lastEventKey = '';
function renderEvents(snapshot) {
  const events = (snapshot.events || []).slice(-100).reverse();
  const key = (snapshot.status && snapshot.status.run_id) + '|' + events.length + '|' + (events[0] && events[0].ts) + '|v2';
  if (key === lastEventKey) return;
  lastEventKey = key;
  const root = $('events');
  root.innerHTML = '';
  $('event-count').textContent = String(events.length);
  if (!events.length) { root.innerHTML = '<li class="empty">No events yet.</li>'; return; }
  for (const e of events) {
    const li = document.createElement('li');
    const def = isDefenseEvent(e.event);
    if (def) li.className = 'defense';
    const time = e.ts ? new Date(e.ts * 1000).toLocaleTimeString() : '—';
    const tool = (e.tool || (e.edge && (e.edge.tool || e.edge.mcp_tool)) || '').toString().trim();
    // Blue events read as "🛡 action (outcome)"; attacker events keep their name.
    const title = def
      ? `🛡 ${(e.action || e.event).toString().replaceAll('_', ' ')}${e.outcome ? ` (${e.outcome})` : ''}`
      : (e.event || '').replaceAll('_', ' ');
    const who = def ? (e.actor || 'blukit') : (e.host || '');
    for (const [className, value] of [
      ['event-time', `${time} · ${who}`],
      ['event-title', (tool && !def) ? `${tool} · ${title}` : title],
      ['event-detail', e.evidence || ''],
    ]) {
      const span = document.createElement('span'); span.className = className; span.textContent = value; li.append(span);
    }
    root.append(li);
  }
}

// ---------------------------------------------------------------- controls --
let controlRequestPending = false;
const CONTROL_LABELS = { start: 'Start run', reset: 'Reset', stop: 'Stop' };

function renderControls(snapshot) {
  const controls = snapshot.controls || {};
  const run = snapshot.control_run || null;
  const busy = controlRequestPending || run?.status === 'running';
  $('keystone-root-path').textContent = snapshot.keystone_root || '~/Projects/keystone-range';
  for (const action of ['start', 'reset', 'stop']) {
    const btn = $('ctrl-' + action);
    const info = controls[action] || { available: false, path: '' };
    btn.disabled = !info.available || busy || Boolean(info.busy);
    btn.textContent = run?.status === 'running' && run.action === action
      ? `${CONTROL_LABELS[action]}…`
      : CONTROL_LABELS[action];
    btn.setAttribute('aria-busy', run?.status === 'running' && run.action === action ? 'true' : 'false');
    btn.title = info.available
      ? (busy ? `${run?.action || 'Control'} is already running` : `Run ${info.path}`)
      : `Not installed: ${info.path} not found or not executable. Set up keystone-range first.`;
  }
  const statusEl = $('control-status');
  statusEl.className = 'control-status' + (run ? ` is-${run.status}` : '');
  if (run?.status === 'running') {
    statusEl.textContent = `${run.message || `${run.action} is running.`} PID ${run.pid} · Log: ${run.log}`;
  } else if (run) {
    statusEl.textContent = `${run.message} Log: ${run.log}`;
  }
}
async function runControl(action) {
  const statusEl = $('control-status');
  if (controlRequestPending || current?.control_run?.status === 'running') return;
  controlRequestPending = true;
  renderControls(current || {});
  statusEl.textContent = `Requesting ${action}…`;
  try {
    const res = await fetch('/api/run/' + action, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    const body = await res.json();
    if (!res.ok) throw new Error(body.error || 'Failed');
    current = { ...(current || {}), control_run: body };
    statusEl.textContent = `${body.message || `${action} is running.`} PID ${body.pid} · Log: ${body.log}`;
  } catch (err) {
    statusEl.className = 'control-status is-failed';
    statusEl.textContent = err.message;
  } finally {
    controlRequestPending = false;
    if (current) renderControls(current);
  }
}
for (const action of ['start', 'reset', 'stop']) {
  $('ctrl-' + action).addEventListener('click', () => runControl(action));
}

// -------------------------------------------------------------- top-level --
function render(snapshot) {
  const runId = snapshot.status?.run_id || '';
  if (lastRunId && runId !== lastRunId) selectedId = null;
  lastRunId = runId;
  current = snapshot;
  processEventSounds(snapshot.events);
  const isLive = snapshot.mode === 'live';
  const isStale = snapshot.mode === 'stale';
  const isRange = snapshot.mode === 'range';
  const brainState = isLive && snapshot.status?.run_id === 'live-brain';
  const runState = snapshot.status?.state;
  $('mode-badge').textContent = isStale ? 'STALE LAB STATE'
    : isRange ? 'KEYSTONE RANGE \u2014 NO ACTIVE RUN'
    : !isLive ? 'DEMO SAMPLE DATA'
    : brainState ? 'LAB STATE'
    : runState === 'starting' ? 'AWAITING EVILKIT'
    : ['finished', 'stopped', 'complete'].includes(runState) ? 'RUN COMPLETE' : 'ACTIVE RUN';
  $('mode-badge').className = 'badge ' + (isLive ? 'badge-live' : (isStale || isRange) ? 'badge-stale' : 'badge-demo');
  $('connection').className = 'connection live';
  $('connection').innerHTML = '<i></i>Streaming';
  $('footer-updated').textContent = 'Updated ' + new Date(snapshot.generated_at * 1000).toLocaleTimeString();
  renderFocus(snapshot);
  renderSegments(snapshot);
  renderClones(snapshot);
  renderAttackFeatures(snapshot);
  paintGraph(snapshot);
  renderRunCard(snapshot);
  renderEvents(snapshot);
  renderControls(snapshot);
  renderInspector();
}

buildStaticLegend();
updateSoundButton();
$('sound-toggle').addEventListener('click', () => { toggleSound(); });
requestAnimationFrame(animate);

const stream = new EventSource('/api/events');
let lastMessageAt = 0;
stream.addEventListener('telemetry', (ev) => {
  try {
    const data = JSON.parse(ev.data);
    lastMessageAt = Date.now();
    if (data.collector_error) throw new Error(data.collector_error);
    render(data);
  } catch (err) {
    $('connection').className = 'connection lost';
    $('connection').innerHTML = '<i></i>Collector error';
  }
});
stream.onerror = () => {
  $('connection').className = 'connection lost';
  $('connection').innerHTML = '<i></i>Reconnecting…';
};
setInterval(() => {
  if (lastMessageAt && Date.now() - lastMessageAt > 15000) {
    $('connection').className = 'connection lost';
    $('connection').innerHTML = '<i></i>Stale';
  }
}, 3000);

$('fullscreen').addEventListener('click', async () => {
  try {
    if (document.fullscreenElement) await document.exitFullscreen();
    else await document.documentElement.requestFullscreen();
  } catch { /* ignore — kiosk browsers may already be fullscreen */ }
});

// ---------------------------------------------------- floating widget HUD --
// The status widgets (clock, score, run, controls, legend) are draggable glass
// panels overlaid on the map. Default layout spreads them across the bottom
// edge (using the monitor's horizontal real estate); positions persist per
// browser so a kiosk keeps its arrangement across reloads. Drag by the top
// grip; double-click a grip to reset the whole layout.
(function initFloatingWidgets() {
  const layer = $('widget-layer');
  if (!layer) return;
  const widgets = Array.from(layer.querySelectorAll('.widget'));
  const KEY = 'ks-widget-pos-v1';
  const keyOf = (w) => w.dataset.widget || w.className;
  const load = () => { try { return JSON.parse(localStorage.getItem(KEY) || '{}') || {}; } catch { return {}; } };
  const save = (o) => { try { localStorage.setItem(KEY, JSON.stringify(o)); } catch { /* private mode */ } };
  let pos = load();

  // If the responsive fallback has flattened the HUD into static flow, do nothing.
  const isFloating = () => getComputedStyle(layer).position === 'fixed';

  const place = (w, x, y) => { w.style.left = Math.round(x) + 'px'; w.style.top = Math.round(y) + 'px'; };

  // Reserve the right-hand sidebar's column so default-placed widgets don't hide under it.
  function rightBound() {
    const sb = document.querySelector('.sidebar-panels');
    if (sb && getComputedStyle(sb).position === 'fixed') {
      const r = sb.getBoundingClientRect();
      if (r.width) return Math.max(160, r.left - 12);
    }
    return window.innerWidth - 16;
  }

  // Spread across the bottom edge, using the monitor's full horizontal width:
  // when the widgets fit in one row, distribute the slack evenly between them
  // (edge-to-edge). On a narrow screen, fall back to left-packing that wraps
  // upward so nothing spills off-screen.
  function applyDefault() {
    const padX = 16, padB = 34, gap = 14;
    const right = rightBound();
    const sizes = widgets.map((w) => w.getBoundingClientRect());
    const bottom = window.innerHeight - padB;
    const totalW = sizes.reduce((a, s) => a + s.width, 0);
    const span = right - padX;
    if (widgets.length > 1 && totalW + gap * (widgets.length - 1) <= span) {
      // one row, spread edge-to-edge
      const slack = Math.max(gap, (span - totalW) / (widgets.length - 1));
      let x = padX;
      widgets.forEach((w, i) => { place(w, x, bottom - sizes[i].height); x += sizes[i].width + slack; });
      return;
    }
    // narrow: left-pack, wrap upward
    let x = padX, rowTop = bottom, rowH = 0;
    widgets.forEach((w, i) => {
      const s = sizes[i];
      if (x > padX && x + s.width > right) { x = padX; rowTop = rowTop - rowH - gap; rowH = 0; }
      place(w, x, rowTop - s.height);
      x += s.width + gap;
      rowH = Math.max(rowH, s.height);
    });
  }

  function clampAll() {
    widgets.forEach((w) => {
      const r = w.getBoundingClientRect();
      const x = Math.min(Math.max(0, parseFloat(w.style.left) || 0), Math.max(0, window.innerWidth - r.width));
      const y = Math.min(Math.max(0, parseFloat(w.style.top) || 0), Math.max(0, window.innerHeight - r.height));
      place(w, x, y);
    });
  }

  function applySaved() {
    widgets.forEach((w) => { const p = pos[keyOf(w)]; if (p) place(w, p.x, p.y); });
  }

  function layout() {
    if (!isFloating()) return;
    applyDefault();   // everyone gets a sane spot first
    applySaved();     // saved positions win
    clampAll();
  }
  requestAnimationFrame(layout);

  // --- drag by the grip handle (keeps buttons/inputs inside the widget usable) ---
  let drag = null;
  widgets.forEach((w) => {
    const grip = w.querySelector('.widget-grip') || w;
    grip.addEventListener('pointerdown', (e) => {
      if (e.button !== 0 || !isFloating()) return;
      const r = w.getBoundingClientRect();
      drag = { w, dx: e.clientX - r.left, dy: e.clientY - r.top };
      w.classList.add('dragging');
      try { grip.setPointerCapture(e.pointerId); } catch { /* older engines */ }
      e.preventDefault();
    });
    grip.addEventListener('pointermove', (e) => {
      if (!drag || drag.w !== w) return;
      const r = w.getBoundingClientRect();
      const x = Math.min(Math.max(0, e.clientX - drag.dx), window.innerWidth - r.width);
      const y = Math.min(Math.max(0, e.clientY - drag.dy), window.innerHeight - r.height);
      place(w, x, y);
    });
    const end = () => {
      if (!drag || drag.w !== w) return;
      pos[keyOf(w)] = { x: parseFloat(w.style.left) || 0, y: parseFloat(w.style.top) || 0 };
      save(pos);
      w.classList.remove('dragging');
      drag = null;
    };
    grip.addEventListener('pointerup', end);
    grip.addEventListener('pointercancel', end);
    grip.addEventListener('dblclick', () => { pos = {}; save(pos); applyDefault(); clampAll(); });
  });

  let rt = null;
  window.addEventListener('resize', () => { clearTimeout(rt); rt = setTimeout(() => { if (isFloating()) clampAll(); }, 120); });
})();
