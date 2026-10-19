# Keystone Range Monitor

A live monitoring/visualization dashboard for the owner's own security-lab
benchmark runs. It only **reads** run telemetry files and performs no scans,
exploitation, or security actions. Its agent gateway stores status locally and
queues structured commands without executing them; the other side-effecting
endpoints shell out only to pre-registered `keystone-range` scripts after a
human clicks a button.

Generalised from the working `~/progression-demo-lab/attack-map/` visualizer
(`monitor.py` / `observatory-v2.js`): same server-sent-events shape, same
"run-scoped telemetry, degrade visibly rather than lie" philosophy, but:

- **White, Maltego/Packet-Tracer-style canvas** instead of the dark NICL theme.
- **Generic device/zone/status model** (`web/db/ad/workstation/router/operator/data`)
  instead of the NICL-specific SSH/PCAP collectors.
- **No hosted model call.** The reference's `topology.py` made one `gpt-6-astra`
  API call per run just to arrange node positions. That is gone entirely —
  positions come from a small, self-contained, in-browser force simulation
  (`app.js`, ~150 lines, no d3, no CDN, no network call of any kind beyond the
  dashboard's own same-origin `/api/*`).
- **Ships a demo dataset** (`demo/`) that self-loops forever when no live
  Keystone telemetry is available.

## Run it

```sh
cd ~/Projects/lab-dashboard
python3 server.py --host 100.88.148.72 --port 8793
```

Open **http://100.88.148.72:8793** from any device on the tailnet.

Port **8793** was picked after checking `ss -ltn` — 8787 (the reference
dashboard's own port) and 8799 (already bound to something else on this box)
were both avoided. Re-check with `ss -ltn | grep 8793` before changing it.

For local-only testing you can also bind `--host 127.0.0.1`.

## Infrastructure Truth Map (`infra_dashboard.py`)

A deliberately small sibling to the run monitor above. Where `server.py`
replays a run's telemetry files, `infra_dashboard.py` asks the five
infrastructure sources *directly*, every poll, and shows only what they report
right now:

```
Internet → ASUS edge → hEX firewall → { Brain Box (+ Proxmox guests),
                                         this operator box, Raspberry Pi }
```

```sh
# Run it by file path — works from any directory (the server finds its HTML
# relative to itself); you do not need to cd anywhere or set PYTHONPATH.
python3 dashboard/infra_dashboard.py serve --host 127.0.0.1 --port 8794   # live lab
python3 dashboard/infra_dashboard.py serve --demo                          # no lab needed
python3 dashboard/infra_dashboard.py snapshot --demo                       # print one state as JSON
```

Open **http://127.0.0.1:8794**. Port **8794** sits next to the run monitor's
8793; change it with `--port`. (`python3 -m infra_dashboard …` also works, but
only from inside the `dashboard/` directory — the path form above does not
care where you are.)

**Truth over optimism.** Each source is polled independently and in parallel
(one dead box never blanks the others). Every reading carries its own
`collected_at`, and a failed poll renders as `unavailable` (grey) with a
`source-unreachable` event — it is **never** back-filled with the last good
value. All polls are read-only and reuse the proven paths from
`scripts/fleet_watcher.py`; the attack→CORP SSH block stays intact (the Pi is
watched from the hEX by ICMP/ARP, not by weakening segmentation).

| Source | How it is reached | Telemetry |
|--------|-------------------|-----------|
| **ASUS edge** | SSH `ASUS_HOST` (key `ASUS_KEY`) | uptime, DHCP leases, edge drops → WAN probes |
| **hEX firewall** | SSH `HEX_HOST` **via the Brain jump** (`BRAIN_HOST`) | conntrack, firewall drops → scan / brute-force / segmentation / IDS events |
| **Brain Box** | SSH `BRAIN_HOST` (key `BRAIN_KEY`) | `pct`/`qm` guest counts + live guests, loadavg |
| **This box** | local counters | podman / libvirt / loadavg |
| **Raspberry Pi** | hEX ICMP/ARP via the Brain jump (`PI_IP`) | reachability + MAC on the CORP segment |

Hosts and keys come from the same environment variables as `fleet_watcher.py`,
so the two agree. Override any of them before launch, e.g.
`HEX_HOST=root@10.10.0.1 BRAIN_HOST=root@192.168.0.240 python3 -m infra_dashboard serve`.

**Event-driven colour.** Each node takes the colour of its highest *current*
security condition — `healthy` (green) · `activity` (blue) · `warning` (amber)
· `alert` (red) · `unavailable` (grey) — and the inspector explains the colour
by listing the events behind it. Security events are typed and detailed
(WAN probe, port scan, brute force, segmentation breach, IDS signature, new
device, DNS anomaly, conntrack surge, CPU pressure, guest start/stop, link
down, …). Links pulse in a pattern keyed to their traffic class — `wan`,
`transit`, `management`, `workload`, `sensor`, `allowed`, and `blocked`
(firewall drops, drawn as red deflecting arcs) — so a glance tells allowed
from denied. The `--demo` engine synthesises the full catalogue so every
colour and pulse is exercised when the live lab is out of reach.

```sh
cd dashboard && python3 -m unittest test_infra_dashboard -v
```

## Minecraft agent NPCs

`minecraft-mod/` contains a Fabric 26.3 mod that turns registered AI agents
into named villager NPCs. Their nameplates follow live state, right-clicking
shows the current task, and `/agents assign|pause|resume|cancel` appends a
structured request to `data/agent_commands.jsonl`. The dashboard never executes
these requests; an agent adapter must opt in to consuming them.

See [`minecraft-mod/README.md`](minecraft-mod/README.md) for the build,
installation, API, and command reference.

### Run the tests

```sh
cd ~/Projects/lab-dashboard
python3 -m unittest test_server.py -v
node test_app.js
```

## Serve on boot (systemd --user)

```sh
mkdir -p ~/.config/systemd/user
cp ~/Projects/lab-dashboard/systemd/lab-dashboard.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now lab-dashboard.service
systemctl --user status lab-dashboard.service
journalctl --user -u lab-dashboard.service -f
```

Lingering is already enabled for this user (`loginctl show-user $USER` shows
`Linger=yes`), so the unit starts at boot without a login session, matching
the pattern of the other `~/.config/systemd/user/*.service` units on this box
(e.g. `cyber-web.service`).

## Mac kiosk (display target: tailnet node `debian`, 100.120.171.28)

This dashboard is **not** deployed to the Mac by this change — only documented.
On the MacBook Air, once the dashboard is reachable at `100.88.148.72:8793`:

```sh
# Chromium
chromium --kiosk --incognito http://100.88.148.72:8793

# or epiphany (GNOME Web)
epiphany --kiosk http://100.88.148.72:8793
```

The page is a single responsive SSE client with no login and no local state
that matters (it keeps no browser storage), so a kiosk window can simply be
reloaded to recover from any network blip.

## Data contract it consumes

Watched at `~/Projects/keystone-range/runs/<run_id>/dashboard/` (override the
root with `LAB_DASHBOARD_KEYSTONE_ROOT` or `keystone_root` in `config.json`):

- **`topology.json`** — `{"zones":[...], "nodes":[{"id","label","type","zone","position":[x,y]}], "edges":[{"src","dst","kind","state"}]}`.
  `position` can use 0–100 percentages or a larger coordinate range; the
  browser fits either range to the canvas while separating overlaps. Dragging
  a node moves its anchor for
  the current page session. Edges may also supply `mcp_tool` (or `tool`),
  `data_type`, `direction` (`forward`, `reverse`, or `both`), and `connected`.
- **`events.jsonl`** — one JSON object per line:
  `{"run_id","ts","host","event","evidence"}` plus optional `"node"` or
  `"edge":{"src","dst"}`. The dashboard replays this file every second and
  maps specific `event` names to node/edge colour transitions:

  | event name         | moves          | to state       |
  |---------------------|----------------|----------------|
  | `node_discovered`   | `node`         | `discovered`   |
  | `node_reachable`    | `node`         | `reachable`    |
  | `node_in_progress`  | `node`         | `in-progress`  |
  | `node_solved`       | `node`         | `solved`       |
  | `node_data_read`    | `node`         | `data-read`    |
  | `edge_discovered`   | `edge`         | `discovered`   |
  | `edge_used`         | `edge`         | `used`         |
  | `edge_connected`    | `edge`         | `discovered`, `connected: true` |
  | `edge_disconnected` | `edge`         | `connected: false` |
  | `flag_captured`     | — (tallied into `status.flags`/score only; read `flag` or falls back to `evidence`) | |

  Any other `event` string is still appended to the live event stream, it
  just doesn't recolour anything. `scripts/emit_event.py` is a small stdlib
  helper for whoever writes the keystone-range producer side — it appends one
  compliant line and is not imported by `server.py` (which only ever reads).
  Edge events can carry `mcp_tool`/`tool`, `data_type`, `direction`, and
  `connected` either inside `edge` or at the top level. The latest supplied
  value for each field is shown on that topology link.

- **`status.json`** — `{"run_id","range","state","started","model","score","flags":[...],"current_step":{...}}`.
  Read fresh every tick; if a run doesn't bother tallying `flags`/`score`
  itself, the dashboard derives them from `flag_captured` events.

If no run telemetry exists, the server serves the bundled `demo/` dataset
with a **DEMO SAMPLE DATA** badge. A recent active Keystone run takes priority
over the continuously updated `live-brain` monitor. A completed run stays in
view for ten minutes, then the dashboard returns to the live lab view. A
**compromised run holds the board** for up to 30 minutes after its last
evidence (events, beacons, journal, or fsdiff) even if its emitter has already
declared it finished — hosts stay dark red through quiet thinking stretches
instead of the board resetting to the idle green range mid-engagement. Runs
whose events are still being appended always win the view, whatever their
declared state. Pressing **Reset** ends that hold on the spot: the control
records a reset epoch, every run whose activity predates it is retired, and
the board wipes immediately (then shows the freshly published idle run once
the range rebuild completes). Only activity that happens *after* a reset may
claim the board again.

## Three EvilKit run highlights

The three cards and graph highlights are independent. `agent_on_host` sets the
host EvilKit is actively operating on (pulsing red); `agent_left_host` clears it.
Recent evidence-backed activity events such as `recon`, `scan`, `exploit`, and
`pivot` also identify the active host for 45 seconds after their timestamp.
`host_compromised` or `foothold` with nonempty evidence adds a persistent red
compromised host; `host_recovered` removes it. `exfil_started` marks the source
host with a pulsing yellow ring; `exfil_completed`, `exfil_stopped`, or
`exfil_failed` clears it. Events should carry `node` with the topology node id,
or `host` with an address matching a topology node. The dashboard also accepts
`status.current_step.agent_host`, `status.current_step.exfil_source`, and
`status.compromised_hosts` as explicit snapshots. It does not infer current
access or ongoing exfiltration from reachability or a completed `exfil` event.
Reconnaissance can indicate the active operating host but never a compromise.
Once the run ends, active red/yellow pulses clear while the
confirmed compromise list remains.

Compromised hosts render **dark red** for the rest of the run; the host
EvilKit is currently operating from **pulses bright red** on top of that.

## Clone beacon traffic (C2 edges)

The run's own `beacons.jsonl` is the ground truth that a planted clone is
alive on a host. For the active run, every beacon source that maps to a
topology node gets a **magenta C2 edge** from that host to the run's operator
origin (`agent_on_host` node, else the operators-zone node). A beacon inside
the 5-minute activity window keeps the edge connected and pulsing; older ones
stay as a faint disconnected line. A beaconing host is treated as compromised
(no `host_compromised` event needed) and gets the teal clone ring.

## EvilKit clone activity

The clone strip reads the active mesh hub's `/state` endpoint and shows every
registered clone, whether it is online, idle or working, the task it is running,
and whether its Parrot terminal window is open. A clone whose name or configured
attack-segment address matches a topology node also gets a teal ring on the map.
The bearer token is read from its local file and is never included in the browser
snapshot.

The systemd unit supplies `EVILKIT_MESH_CONNECTION_FILE`,
`EVILKIT_MESH_TOKEN_FILE`, `EVILKIT_CLONE_DISPLAY_LOG`, and
`EVILKIT_CLONE_WINDOW_REGISTRY`. Set the equivalent `evilkit_mesh_connection`,
`evilkit_mesh_token`, `evilkit_clone_log`, and `evilkit_clone_windows` keys in
`config.json` when running outside that unit.

`homelab-run-start` activates tracking for the newest prepared Keystone run;
it does not launch EvilKit. A separately launched agent or operator can send
evidenced `agent_on_host`, `host_compromised`, and `exfil_started` updates with
`homelab-run-event --event EVENT --node NODE_ID --evidence TEXT`, then finish
with `homelab-run-stop`. The current `live-brain` feed and EvilKit's launch
record do not report active host, confirmed compromise, or exfiltration on
their own. `scripts/emit_event.py` is a lower-level alternative.

## EvilKit attack features

The floating **EvilKit attack features** widget reads the canonical EvilKit 1.2
telemetry already present in `dashboard/events.jsonl`. It shows the active
engine/session and tracks recon, foothold, privilege escalation, pivot, implant,
persistence, lateral movement, command-and-control, and exfiltration. Grey means
the phase has not been observed in this run, green means evidence exists, and
orange means it is the newest activity and is still inside the live activity
window. Hover a phase for its event count, last-seen time, and latest tool.

Successful EvilKit actions can use the generic `host_compromised` event name,
so the dashboard prefers the canonical tool name when choosing a phase (for
example `malware_deploy` is implant activity and `malware_c2` is C2). Producers
may instead provide an explicit `attack_feature` or `phase` field. The widget
does not claim that an available feature was used until matching telemetry is
actually present.

## Zypheron audit bridge

`scripts/zypheron_bridge.py` is an optional, passive producer for a benchmark
run. It reads Zypheron's local JSONL audit file (`~/.config/zypheron/audit/` by
default) and writes only eligible lab-target events to that run's
`dashboard/events.jsonl`. It does **not** start Zypheron, invoke a tool, change
scope, or make a network connection. It also intentionally excludes audit
identities, session/device IDs, and arbitrary detail values.

When a run has been prepared and Zypheron is actually being operated from
`g960`, attach it with:

```sh
cd ~/Projects/lab-dashboard
python3 scripts/zypheron_bridge.py \
  --run-dir ~/Projects/keystone-range/runs/<run-id> \
  --source-node g960 --follow --from-end
```

`--from-end` makes the bridge show only records produced after it starts. The
bridge maps Zypheron `scan`/`recon` actions to yellow recon traffic and
`exploit` actions to red attack traffic. An exploit record is shown only as an
attempt or completed activity; it never marks a host compromised. Targets that
do not exactly match an IPv4 address in the selected run's topology are ignored.

## EvilKimi session bridge

`scripts/evilkimi_session_bridge.py` publishes an EvilKimi operator session that
was **not** launched with `--dashboard-run-dir`. `evilkit.kimihook` writes
`~/.local/state/evilkimi/sessions/session_<id>.jsonl` for every session whether or
not a dashboard run was configured, so the bridge tails that log and republishes
it into `runs/evilkimi-live-<session>/` (one run per session). It launches
nothing, opens no network connection, and carries no command output, credentials,
flags or model reasoning — only the action class, the target, and the exit status.

What it colours:

| Session evidence | Dashboard result |
|---|---|
| any action against a range node | one edge from the operator's current host, `recon` (yellow) or attack-class (red) |
| ssh session opened onto the node, exit 0 | `host_compromised` + `agent_on_host` — solid red, listed as owned |
| attack tool (nxc/sqlmap/hydra/…) aimed at the node, exit 0 | same |
| command-execution request (`-d '{"cmd": …}'`) | attack traffic only — an attempt, never ownership |

Ownership is claimed only where the recorded exit status can prove it. The hook
records one status for the whole call, so the bridge reads only the **last**
top-level statement, and only a client invoked as a real token counts — command
text that merely quotes `ssh root@10.99.50.11 …` inside `-d '{"cmd": …}'` is a
payload, not a session. curl also reports success for an HTTP error, which is why
an accepted command-execution request is an attempt rather than a compromise.

```sh
cd ~/Projects/lab-dashboard
python3 scripts/evilkimi_session_bridge.py                  # live session -> its run
python3 scripts/evilkimi_session_bridge.py --from-start      # replay the session's history
systemctl --user status evilkimi-session-bridge              # the unit that runs it for you
```

The `evilkimi-session-bridge` user unit (installed from `systemd/`) runs the
bridge continuously, so every later session publishes on its own. A session that
has already gone quiet starts as `finished` and publishes nothing until it acts
again, so restarting the unit cannot hijack the board with an old engagement.
The run stays live while the session acts and for 15 minutes after its last
action (`EVILKIMI_BRIDGE_IDLE_SECS`), then it goes `finished` and ages out of the
live view.

## Run controls

Three buttons — **Start run / Reset / Stop** — each POST to
`/api/run/{start,reset,stop}`, which shells out to a fixed, pre-registered
script path (no path from the request body is ever used):

| action  | default path                                   |
|---------|-------------------------------------------------|
| start   | `~/Projects/keystone-range/bin/start.sh`         |
| reset   | `~/Projects/keystone-range/bin/reset.sh`         |
| stop    | `~/Projects/keystone-range/bin/stop.sh`          |

Override these with `config.json` (see below). Each button is enabled only
when its registered script exists and is executable; otherwise its tooltip
shows the missing path.

Each launch is non-blocking (`subprocess.Popen(..., start_new_session=True)`)
with output captured to `~/Projects/lab-dashboard/logs/<action>-<ts>.log`.

### `config.json` (optional)

```json
{
  "keystone_root": "/home/will_cyber/Projects/keystone-range",
  "start_script": "/home/will_cyber/Projects/keystone-range/bin/start.sh",
  "reset_script": "/home/will_cyber/Projects/keystone-range/bin/reset.sh",
  "stop_script": "/home/will_cyber/Projects/keystone-range/bin/stop.sh"
}
```

All keys optional; `LAB_DASHBOARD_CONFIG=/path/to/config.json` picks a
different file, `LAB_DASHBOARD_KEYSTONE_ROOT=...` overrides just the root.

## Colour legend

The live map uses presentation segments that separate the red-team platform,
perimeter, guest access, management, public services, users, business data,
application DMZ, privileged services, and identity. These are visual trust
boundaries only; they do not add routes, firewall gates, prerequisites, or score
requirements. The naming contract is documented in
[`docs/SEGMENTATION_AND_NAMING.md`](docs/SEGMENTATION_AND_NAMING.md).

During an active EvilKit run, the three focus states override the ordinary
target colours: active host pulses red, confirmed compromise is solid red, and
active exfiltration pulses yellow. Unrelated nodes and links are muted, while
run details, controls, legend, and events sit in a closed disclosure below the
graph. If two focus states refer to one host, both rings remain visible.

Outside an EvilKit run, node circles show target state. The letters inside
show device type; zone and address remain in the inspector. States have muted
colours:
unknown grey, discovered slate blue, reachable blue, running teal, in-progress
amber, solved green, data-read purple, stopped grey, locked ochre, error red.
The live Proxmox view uses its latest observation, so a guest can correctly
move from running back to stopped.

The thin base line shows link kind (network blue-grey, trust violet, data
brown) and telemetry state (unknown dotted, discovered dashed, used solid).
A separate moving segment appears only while the feed reports an active
connection or the live packet monitor is currently observing traffic. It
follows `direction` when supplied; trust links alternate both ways by default.
The moving line uses `data_type` colour when available, otherwise `mcp_tool`
colour, otherwise link-kind colour. When both tool and data type are present,
the moving dot uses the tool colour. Each observed tool receives a distinct
muted colour and appears in the live legend.

`connected: true` draws the traffic overlay and `connected: false` removes it.
MCP/action events are also treated as live between `started` and their terminal
status, with a short stale-activity timeout. Links with no live connection
signal remain as static topology only.

## What's wired vs stubbed

**Wired and working today, with no live data required:**
- Force-directed white-background graph (vanilla JS, pan/zoom/drag, offline).
- SSE live stream (`/api/events`) and a snapshot endpoint (`/api/status`).
- Demo dataset: a realistic 12-node, 4-zone, 6-flag run that self-loops
  forever (~84s per loop) so "Start a browser and look at it" always works.
- Automatic switch among an active Keystone run, the live lab view, and demo.
- State-coloured circles, directional links, conditional tool/data colours,
  full legend, click-to-inspect panel,
  run header (range/run id/model/score/started/current step), flag chips,
  scrolling event log.
- Live EvilKit clone cards with task text, online/idle state, terminal state,
  and teal topology rings for mapped clone hosts.
- `scripts/emit_event.py` — ready for the keystone-range side to call.
- `scripts/zypheron_bridge.py` — passive Zypheron-audit-to-dashboard adapter.
- `scripts/evilkimi_session_bridge.py` — passive EvilKimi-session-to-dashboard
  adapter (ownership is claimed only where the exit status proves it).
- `test_server.py` — unit/integration tests (event→state mapping, demo
  loop correctness, live-run discovery and most-recent-run selection,
  control-endpoint 409 when a script isn't installed yet, SSE push, static
  asset serving), following the `test_monitor.py` pattern.
- systemd --user unit.

**Conditional on the producer:**
- Each run-control button is enabled only while its registered script exists
  and is executable. Availability is refreshed with the live snapshot.
- The `live-brain` producer supplies guest state and topology, but currently
  supplies no MCP tool or data-type fields. Those colours appear as soon as a
  producer emits the optional fields documented above; the dashboard does not
  invent tool activity for the live lab.

## Files

```
lab-dashboard/
  server.py              stdlib http.server + SSE backend (RangeWatcher, DemoPlayer)
  index.html / app.js / style.css   the dashboard itself
  infra_dashboard.py     simple "truth map": direct, always-current device polls
  infra_dashboard.html   its single-file SVG page (event colours + traffic pulses)
  test_infra_dashboard.py
  demo/topology.json     12-node sample topology (attacker/dmz/corp/data)
  demo/events.jsonl      scripted 6-flag run, replayed on a loop
  scripts/emit_event.py  helper for keystone-range producers
  scripts/zypheron_bridge.py passive Zypheron-audit-to-dashboard adapter
  scripts/evilkimi_session_bridge.py  EvilKimi session-log-to-dashboard adapter
  systemd/lab-dashboard.service
  systemd/evilkimi-session-bridge.service
  test_server.py
  test_zypheron_bridge.py
  test_evilkimi_session_bridge.py
  test_app.js           SVG graph behaviour smoke test
  logs/                  created on first control-button click
```
