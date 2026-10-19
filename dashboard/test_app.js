// Small DOM smoke test for the graph's observable SVG state. No browser needed.
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

class Element {
  constructor(tag = 'div') {
    this.tag = tag;
    this.children = [];
    this.attributes = {};
    this.style = {};
    this.className = { baseVal: '' };
    const classes = new Set();
    this.classList = {
      toggle(name, force) { if (force) classes.add(name); else classes.delete(name); },
      add(name) { classes.add(name); },
      remove(name) { classes.delete(name); },
      contains(name) { return classes.has(name); },
    };
    this.dataset = {};
    this.textContent = '';
  }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  querySelectorAll() { return []; }
  remove() {}
  addEventListener() {}
  setAttribute(key, value) { this.attributes[key] = String(value); }
  getAttribute(key) { return this.attributes[key]; }
}

const elements = new Map();
const getElement = (id) => {
  if (!elements.has(id)) elements.set(id, new Element());
  return elements.get(id);
};
let now = 2000;
const context = vm.createContext({
  document: {
    getElementById: getElement,
    querySelector: getElement,
    querySelectorAll: () => [],
    createElement: (tag) => new Element(tag),
    createElementNS: (_ns, tag) => new Element(tag),
  },
  window: { matchMedia: () => ({ matches: false }), addEventListener() {} },
  EventSource: class { addEventListener() {} },
  requestAnimationFrame() {},
  setInterval() {},
  performance: { now: () => now },
  fetch() {},
  console,
});
vm.runInContext(fs.readFileSync('app.js', 'utf8'), context);

assert.equal(vm.runInContext("soundCategory({event:'recon'})", context), 'recon');
assert.equal(vm.runInContext("soundCategory({event:'host_compromised'})", context), 'attack');
assert.equal(vm.runInContext("soundCategory({event:'crown_exfil'})", context), 'exfil');
assert.equal(vm.runInContext("soundCategory({event:'defense_isolate'})", context), 'defense');
assert.equal(vm.runInContext("soundCategory({event:'collector_error'})", context), 'error');

const fitted = vm.runInContext(`nodePositions([
  { id: 'left', position: [0, 0] },
  { id: 'right', position: [720, 600] },
]).get('right')`, context);
assert.deepEqual(Array.from(fitted), [90, 90], 'large topology coordinates should fit the canvas');

context.overlapNodes = [
  { id: 'overlap-a', zone: 'dmz', type: 'router', position: [20, 50] },
  { id: 'overlap-b', zone: 'dmz', type: 'workstation', position: [20, 50] },
];
const overlapLayout = vm.runInContext(`(() => {
  simNodes.clear(); alpha = 1; reconcileSimNodes(overlapNodes);
  for (let i = 0; i < 240; i++) forceTick();
  const a = simNodes.get('overlap-a'), b = simNodes.get('overlap-b');
  return { ax: a.x, ay: a.y, bx: b.x, by: b.y, distance: Math.hypot(a.x - b.x, a.y - b.y) };
})()`, context);
assert.ok(overlapLayout.distance > 20, 'overlapping nodes should separate');
for (const coordinate of [overlapLayout.ax, overlapLayout.bx]) {
  assert.ok(coordinate > 100 && coordinate < 700, 'overlap resolution should keep nodes near their x anchor');
}
for (const coordinate of [overlapLayout.ay, overlapLayout.by]) {
  assert.ok(coordinate > 200 && coordinate < 560, 'overlap resolution should keep nodes near their y anchor');
}

const nodes = [
  { id: 'a', label: 'A', type: 'web', zone: 'z', position: [20, 50], state: 'running' },
  { id: 'b', label: 'B', type: 'data', zone: 'z', position: [80, 50], state: 'stopped' },
];
const edge = { src: 'a', dst: 'b', kind: 'data', state: 'used', mcp_tool: 'mcp.filesystem', data_type: 'file', direction: 'reverse', connected: true };
context.snapshot = { nodes, edges: [edge] };
vm.runInContext('paintGraph(snapshot); for (const rec of edgeEls.values()) { rec.offset = 0; rec.period = 10; } positionFrame();', context);

const graph = vm.runInContext(`(() => {
  const a = nodeEls.get('a'), b = nodeEls.get('b'), e = [...edgeEls.values()][0];
  return { a: a.circle.getAttribute('fill'), b: b.circle.getAttribute('fill'),
    base: e.base.getAttribute('stroke'), flow: e.flow.getAttribute('stroke'),
    dot: e.toolDot.getAttribute('fill'), x1: Number(e.flow.getAttribute('x1')),
    x2: Number(e.flow.getAttribute('x2')), opacity: e.flow.style.opacity };
})()`, context);
assert.notEqual(graph.a, graph.b, 'target states need distinct circle colours');
assert.notEqual(graph.base, graph.flow, 'data type needs a distinct flow colour');
assert.ok(graph.dot, 'MCP tool marker needs a colour');
assert.ok(graph.x1 > graph.x2, 'reverse flow should start at the destination');
assert.notEqual(graph.opacity, '0', 'reported live traffic should draw the flow');

context.snapshot.edges = [edge, { ...edge, label: 'newer duplicate firewall event' }];
const alignedDuplicate = vm.runInContext(`(() => {
  paintGraph(snapshot); positionFrame();
  const rec = [...edgeEls.values()][0], target = simNodes.get('b');
  return {
    count: edgeEls.size,
    lane: rec.lane,
    endpointGap: Math.hypot(Number(rec.base.getAttribute('x2')) - target.x,
                            Number(rec.base.getAttribute('y2')) - target.y),
  };
})()`, context);
assert.equal(alignedDuplicate.count, 1, 'duplicate firewall events should render as one edge');
assert.equal(alignedDuplicate.lane, 0, 'a deduplicated edge should use the centre lane');
assert.ok(Math.abs(alignedDuplicate.endpointGap - 21) < 0.1, 'edge endpoint should meet the target node boundary');
context.snapshot.edges = [edge];

delete edge.connected;
vm.runInContext('paintGraph(snapshot); positionFrame()', context);
assert.equal(vm.runInContext('edgeEls.size', context), 1, 'unreported topology links should remain as dotted baseline wiring');
assert.equal(vm.runInContext('[...edgeEls.values()][0].group.classList.contains("baseline")', context), true);
assert.equal(vm.runInContext('[...edgeEls.values()][0].flow.style.opacity', context), '0');

edge.connected = true;
vm.runInContext('paintGraph(snapshot); positionFrame()', context);
assert.notEqual(vm.runInContext('[...edgeEls.values()][0].flow.style.opacity', context), '0', 'reported connected links should stay drawn');
edge.connected = false;
vm.runInContext('paintGraph(snapshot); positionFrame()', context);
assert.equal(vm.runInContext('edgeEls.size', context), 1, 'reported disconnected topology links should return to the baseline');
edge.historical = true;
context.snapshot.generated_at = 100;
context.snapshot.events = [{ ts: 95, edge: { src: 'a', dst: 'b' }, event: 'recon' }];
vm.runInContext('paintGraph(snapshot)', context);
assert.match(vm.runInContext('[...edgeEls.values()][0].base.className.baseVal', context), /historical/, 'historical actions should retain a visible base path');
context.snapshot.events = [{ ts: 70, edge: { src: 'a', dst: 'b' }, event: 'recon' }];
vm.runInContext('paintGraph(snapshot)', context);
assert.equal(vm.runInContext('edgeEls.size', context), 0, 'stale historical actions should not leave map lines behind');
edge.connected = true;
edge.historical = false;
context.snapshot.events = [];

context.routedSnapshot = {
  generated_at: 100,
  nodes: [
    { id: 'source', zone: 'attack' },
    { id: 'fabric-switch', zone: 'fabric' },
    { id: 'fabric-hex', zone: 'fabric' },
    { id: 'fabric-brain', zone: 'fabric' },
    { id: 'target', zone: 'dmz' },
  ],
  edges: [{ src: 'source', dst: 'target', kind: 'recon', connected: true }],
  events: [],
};
assert.deepEqual(
  Array.from(vm.runInContext('displayEdges(routedSnapshot).map(({src,dst}) => [src,dst])', context), pair => Array.from(pair)),
  [['source', 'fabric-switch'], ['fabric-switch', 'fabric-hex'], ['fabric-switch', 'target']],
  'cross-zone physical traffic should leave and return through the switch and firewall',
);
assert.equal(
  vm.runInContext('displayEdges(routedSnapshot).find(({src,dst}) => src === "fabric-switch" && dst === "fabric-hex").direction', context),
  'both',
  'the switch/firewall trunk should show outbound and return traffic',
);

context.routedSnapshot.nodes[4].id = 'g950';
context.routedSnapshot.edges[0].dst = 'g950';
assert.deepEqual(
  Array.from(vm.runInContext('displayEdges(routedSnapshot).map(({src,dst}) => [src,dst])', context), pair => Array.from(pair)),
  [['source', 'fabric-switch'], ['fabric-switch', 'fabric-hex'], ['fabric-hex', 'fabric-brain'], ['fabric-brain', 'g950']],
  'traffic to a VM should traverse switch, firewall, and Proxmox before the target',
);

context.routedSnapshot.edges[0] = { src: 'source', dst: 'g950', kind: 'network' };
assert.deepEqual(
  Array.from(vm.runInContext('displayEdges(routedSnapshot).map(({src,dst}) => [src,dst])', context), pair => Array.from(pair)),
  [['source', 'fabric-switch'], ['fabric-switch', 'fabric-hex'], ['fabric-hex', 'fabric-brain'], ['fabric-brain', 'g950']],
  'dotted topology wiring should follow the same physical switch/firewall/Proxmox route',
);
assert.equal(
  vm.runInContext('displayEdges(routedSnapshot).every(({_displayLayer}) => _displayLayer === "baseline")', context),
  true,
  'idle physical routes should remain dotted baseline wiring',
);

context.routedSnapshot.edges[0] = {
  src: 'source', dst: 'g950', kind: 'pivot-possible', direct: true,
  pivot_possible: true, connected: false,
};
assert.deepEqual(
  Array.from(vm.runInContext('displayEdges(routedSnapshot).map(({src,dst}) => [src,dst])', context), pair => Array.from(pair)),
  [['source', 'g950']],
  'potential direct pivots should connect endpoints without inventing a fabric hop',
);
vm.runInContext('paintGraph(routedSnapshot)', context);
assert.equal(
  vm.runInContext('[...edgeEls.values()][0].group.classList.contains("pivot-possible")', context),
  true,
  'potential direct pivots should receive their own dotted-line style',
);

context.snapshot = {
  ...context.snapshot, mode: 'live', status: { run_id: 'next-run', state: 'running' },
  focus: { current: { id: 'a', label: 'A' }, compromised: [{ id: 'a', label: 'A' }, { id: 'b', label: 'B' }], exfil: { id: 'b', label: 'B' } },
  clone_fleet: { connected: true, clones: [{ name: 'clone-a', node_id: 'a', status: 'running', activity: 'Enumerating A', terminal_open: true }] },
};
vm.runInContext('paintGraph(snapshot)', context);
assert.equal(getElement('graph').classList.contains('focus-view'), false, 'incident overlays should not grey the whole topology');
assert.equal(
  vm.runInContext('[...edgeEls.values()][0].group.style.opacity', context),
  '1',
  'incident focus should keep non-focus topology links bright',
);
const highlights = vm.runInContext(`({
  current: nodeEls.get('a').g.classList.contains('focus-current'),
  compromisedA: nodeEls.get('a').g.classList.contains('focus-compromised'),
  compromisedB: nodeEls.get('b').g.classList.contains('focus-compromised'),
  exfil: nodeEls.get('b').g.classList.contains('focus-exfil'),
  clone: nodeEls.get('a').g.classList.contains('clone-present'),
  currentFill: nodeEls.get('a').circle.getAttribute('fill'),
  compromisedFill: nodeEls.get('b').circle.getAttribute('fill'),
})`, context);
assert.deepEqual(JSON.parse(JSON.stringify(highlights)), {
  current: true, compromisedA: true, compromisedB: true, exfil: true, clone: true,
  currentFill: '#EF4444', compromisedFill: '#7F1D1D',
});
assert.deepEqual(
  getElement('legend-status').children.map((row) => row.children[1].textContent),
  [
    'Unknown / no telemetry', 'Discovered / not verified', 'Reachable infrastructure',
    'Running host or service', 'Action in progress', 'Busy or locked',
    'Stopped or offline', 'Error', 'Compromised / data accessed',
    'EvilKit active here (bright red pulse)',
  ],
  'node-state legend should describe the colours actually rendered',
);
vm.runInContext('renderFocus(snapshot)', context);
assert.equal(getElement('focus-current-host').textContent, 'A');
assert.equal(getElement('focus-compromised-count').textContent, '2 confirmed');
assert.equal(getElement('focus-exfil-host').textContent, 'B');
assert.equal(getElement('.focus-current-card').classList.contains('is-active'), true);
assert.equal(getElement('.focus-exfil-card').classList.contains('is-active'), true);
vm.runInContext('renderClones(snapshot)', context);
assert.equal(getElement('clone-summary').textContent, '1/1 online · 1 working');
assert.equal(getElement('clone-hub-state').textContent, 'Mesh live');
assert.equal(getElement('clone-list').children.length, 1);
context.snapshot.attack_features = {
  engine: 'evilqwen', session_id: 'session-7', current: 'c2', last_host: '10.99.50.21', last_exit_code: 0,
  features: [
    { id: 'recon', label: 'Recon', state: 'observed', count: 2, last_seen: 1900, last_tool: 'nmap_scan' },
    { id: 'c2', label: 'Command & control', state: 'active', count: 1, last_seen: 1999, last_tool: 'malware_c2' },
  ],
};
vm.runInContext('renderAttackFeatures(snapshot)', context);
assert.equal(getElement('attack-engine').textContent, 'EVILQWEN');
assert.equal(getElement('attack-feature-list').children.length, 2);
assert.match(getElement('attack-feature-detail').textContent, /Active: Command & control on 10\.99\.50\.21.*malware_c2.*exit 0/);
context.snapshot = {
  ...context.snapshot,
  controls: {
    start: { available: true, path: '/range/start.sh', busy: true },
    reset: { available: true, path: '/range/reset.sh', busy: true },
    stop: { available: true, path: '/range/stop.sh', busy: true },
  },
  control_run: { action: 'reset', status: 'running', pid: 42, log: '/tmp/reset.log', message: 'Reset is running.' },
};
vm.runInContext('renderControls(snapshot)', context);
assert.equal(getElement('ctrl-start').disabled, true);
assert.equal(getElement('ctrl-reset').textContent, 'Reset…');
assert.equal(getElement('ctrl-reset').attributes['aria-busy'], 'true');
assert.match(getElement('control-status').textContent, /Reset is running.*PID 42/);
// --- blue-team overlay: blukit/gpt-Sol actions paint on the graph + feed ---
context.snapshot = {
  mode: 'live',
  status: { run_id: 'defense-run', state: 'running' },
  nodes: [
    { id: 'edge-upload', label: 'edge01', address: '10.80.10.20' },
    { id: 'dc-roast', label: 'dc01', address: '10.80.20.30' },
    { id: 'portal', label: 'portal01', address: '10.80.10.21' },
  ],
  edges: [],
  events: [
    // containment keyed by IP (blukit acts on addresses, not node ids)
    { event: 'defense_isolate', host: '10.80.10.20', action: 'isolate-host', outcome: 'done', actor: 'blukit', ts: 10 },
    // forensic only -> watched, not contained
    { event: 'defense_preserve', host: 'dc-roast', action: 'preserve-evidence', outcome: 'done', ts: 11 },
    // attacker event -> no defence class
    { event: 'foothold', host: 'portal', evidence: 'uid=33', ts: 12 },
  ],
};
vm.runInContext('paintGraph(snapshot)', context);
const def = vm.runInContext(`(() => {
  const edge = nodeEls.get('edge-upload'), dc = nodeEls.get('dc-roast'), portal = nodeEls.get('portal');
  return {
    containedByIp: edge.g.classList.contains('contained'),
    edgeLabelShield: edge.label.textContent.startsWith('🛡'),
    watched: dc.g.classList.contains('watched'),
    dcNotContained: dc.g.classList.contains('contained'),
    portalClean: portal.g.classList.contains('contained') || portal.g.classList.contains('watched'),
  };
})()`, context);
assert.equal(def.containedByIp, true, 'isolate-host on an IP should contain the matching node');
assert.equal(def.edgeLabelShield, true, 'a defended node label should carry the shield');
assert.equal(def.watched, true, 'preserve-evidence should mark the node watched');
assert.equal(def.dcNotContained, false, 'forensic-only action must not read as contained');
assert.equal(def.portalClean, false, 'an attacker-only node must carry no defence class');

vm.runInContext('renderEvents(snapshot)', context);
const defLi = getElement('events').children.find((li) => li.className === 'defense');
assert.ok(defLi, 'defence actions should render as defence rows in the feed');

// --- run-card provenance: is the board showing a stick or this lab's build? ---
const sourcePill = getElement('run-source-pill');
vm.runInContext(`renderRunCard({status: {
  run_id: 'range-topology', range: 'blind-forge', state: 'idle', topology_source: 'stick',
  current_step: {detail: 'No active run — showing blind-forge from the inserted stick.'},
}})`, context);
assert.equal(sourcePill.hidden, false, 'an inserted range stick should badge the run card');
assert.equal(sourcePill.textContent, 'USB STICK');
assert.equal(sourcePill.className, 'pill pill-stick', 'a stick needs its own colour, not the neutral idle pill');
assert.match(sourcePill.title, /inserted range stick/);

vm.runInContext(`renderRunCard({status: {
  run_id: 'range-topology', range: 'keystone', state: 'idle', topology_source: 'build',
}})`, context);
assert.equal(sourcePill.textContent, 'BUILD PLAN');
assert.equal(sourcePill.className, 'pill pill-idle');

vm.runInContext(`renderRunCard({status: {run_id: 'run9', state: 'running', range: 'keystone'}})`, context);
assert.equal(sourcePill.hidden, true, 'a live run reports its own telemetry and needs no source badge');

vm.runInContext(`renderRunCard({status: {
  run_id: 'range-topology', range: 'keystone', state: 'idle', topology_source: null,
}})`, context);
assert.equal(sourcePill.hidden, true, 'no card and no build plan should not claim a source');

console.log('graph SVG smoke test passed');
