import importlib.util
import io
import json
import stat
import tempfile
import threading
import time
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

spec = importlib.util.spec_from_file_location("server", Path(__file__).with_name("server.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ApplyEventsTests(unittest.TestCase):
    def test_node_and_edge_event_names_map_to_states(self):
        events = [
            {"event": "node_discovered", "node": "a"},
            {"event": "node_solved", "node": "a"},
            {"event": "edge_discovered", "edge": {"src": "a", "dst": "b"}},
            {"event": "edge_used", "edge": {"src": "a", "dst": "b"}},
            {"event": "flag_captured", "flag": "f1"},
            {"event": "something_unrelated", "node": "c"},
        ]
        nodes, edges, flags = m.apply_events(events)
        self.assertEqual(nodes["a"], "solved")
        self.assertNotIn("c", nodes)
        self.assertEqual(edges[("a", "b")], "used")
        self.assertEqual(flags, ["f1"])

    def test_attack_events_leave_a_persistent_attack_path(self):
        events = [
            {"event": "recon", "node": "a", "edge": {"src": "operator", "dst": "a"}},
            {"event": "exploit", "node": "a", "edge": {"src": "operator", "dst": "a"}},
            {"event": "pivot", "node": "b", "edge": {"src": "a", "dst": "b"}},
            {"event": "exfil", "node": "b", "edge": {"src": "b", "dst": "operator"}},
        ]
        _, edges, _ = m.apply_events(events)
        self.assertEqual(edges[("operator", "a")], "used")
        self.assertEqual(edges[("a", "b")], "used")
        self.assertEqual(edges[("b", "operator")], "used")

    def test_unknown_event_names_do_not_move_state(self):
        nodes, edges, flags = m.apply_events([{"event": "log", "node": "a"}])
        self.assertEqual(nodes, {})
        self.assertEqual(edges, {})
        self.assertEqual(flags, [])

    def test_live_target_state_can_return_to_stopped(self):
        events = [
            {"node": "g950", "evidence": "pct/qm status='running' lock=''"},
            {"node": "g950", "evidence": "pct/qm status='stopped' lock=''"},
            {"node": "g911", "evidence": "pct/qm status='running' lock='mounted'"},
        ]
        self.assertEqual(m.live_target_states(events), {"g950": "stopped", "g911": "locked"})

    def test_edge_metadata_and_connection_follow_latest_event(self):
        events = [
            {"event": "edge_connected", "edge": {"src": "a", "dst": "b", "mcp_tool": "filesystem", "data_type": "file", "direction": "reverse"}},
            {"event": "edge_disconnected", "edge": {"src": "a", "dst": "b"}},
        ]
        self.assertEqual(m.edge_event_details(events)[("a", "b")], {
            "mcp_tool": "filesystem", "data_type": "file", "direction": "reverse", "connected": False,
        })

    def test_evilkit_traffic_class_colours_the_edge(self):
        events = [{
            "event": "recon", "ts": 995,
            "edge": {"src": "entry", "dst": "edge", "traffic_class": "recon", "tool": "nmap"},
        }, {
            "event": "exploit", "status": "started", "ts": 999,
            "edge": {"src": "entry", "dst": "edge", "traffic_class": "attack", "tool": "sqlmap"},
        }]
        self.assertEqual(m.edge_event_details(events, now=1000)[("entry", "edge")], {
            "tool": "sqlmap", "historical": True, "kind": "attack", "connected": True,
        })

    def test_exfil_event_renders_as_data_even_with_generic_attack_class(self):
        events = [{
            "event": "exfil", "ts": 999,
            "edge": {"src": "pivot", "dst": "target", "traffic_class": "attack", "tool": "scp"},
        }]
        self.assertEqual(m.edge_event_details(events, now=1000)[("pivot", "target")], {
            "tool": "scp", "historical": True, "kind": "data", "connected": True,
        })

    def test_completed_or_stale_traffic_is_not_connected(self):
        completed = [{"event": "mcp_action", "status": "completed", "ts": 999,
                      "edge": {"src": "a", "dst": "b", "traffic_class": "attack"}}]
        stale = [{"event": "mcp_action", "status": "started", "ts": 990,
                  "edge": {"src": "a", "dst": "b", "traffic_class": "attack"}}]
        self.assertFalse(m.edge_event_details(completed, now=1000)[("a", "b")]["connected"])
        self.assertFalse(m.edge_event_details(stale, now=1000)[("a", "b")]["connected"])

    def test_run_focus_keeps_current_compromised_and_exfil_separate(self):
        topology = {"nodes": [
            {"id": "web", "label": "web01", "ip": "10.0.0.10"},
            {"id": "db", "label": "db01", "ip": "10.0.0.20"},
        ]}
        events = [
            {"event": "node_reachable", "node": "web"},
            {"event": "host_compromised", "node": "web", "evidence": "shell proof"},
            {"event": "agent_on_host", "host": "10.0.0.20", "evidence": "session active"},
            {"event": "exfil_started", "source_node": "web", "evidence": "transfer active"},
        ]
        focus = m.run_focus(topology, {"state": "running"}, events)
        self.assertEqual(focus["current"]["id"], "db")
        self.assertEqual([h["id"] for h in focus["compromised"]], ["web"])
        self.assertEqual(focus["exfil"]["id"], "web")

        unsupported = m.run_focus(topology, {"state": "running"}, [
            {"event": "agent_on_host", "node": "web", "evidence": ""},
            {"event": "exfil_started", "node": "web", "evidence": ""},
        ])
        self.assertIsNone(unsupported["current"])
        self.assertIsNone(unsupported["exfil"])

        events.append({"event": "exfil_completed", "source_node": "web"})
        self.assertIsNone(m.run_focus(topology, {"state": "running"}, events)["exfil"])
        ended = m.run_focus(topology, {"state": "finished"}, events)
        self.assertIsNone(ended["current"])
        self.assertEqual(len(ended["compromised"]), 1)

    def test_run_focus_recent_activity_expires_and_exfil_uses_source(self):
        topology = {"nodes": [{"id": "web", "label": "web", "ip": "10.0.0.10"},
                              {"id": "db", "label": "db", "ip": "10.0.0.20"}]}
        activity = [{"event": "node_reachable", "node": "db", "evidence": "harness up", "ts": 995},
                    {"event": "scan", "node": "web", "evidence": "EvilKit scan in progress", "ts": 980}]
        self.assertEqual(m.run_focus(topology, {"state": "running"}, activity, now=1000)["current"]["id"], "web")
        self.assertIsNone(m.run_focus(topology, {"state": "running"}, activity, now=1100)["current"])
        exfil = [{"event": "exfil_started", "source_node": "web", "target_node": "db",
                  "evidence": "transfer active", "ts": 990}]
        focus = m.run_focus(topology, {"state": "running"}, exfil, now=1000)
        self.assertEqual(focus["current"]["id"], "web")
        self.assertEqual(focus["exfil"]["id"], "web")
        completed = [{"event": "exfil", "source_node": "web",
                      "evidence": "transfer complete", "ts": 990}]
        self.assertIsNone(m.run_focus(topology, {"state": "running"}, completed, now=1100)["exfil"])
        started = [{"event": "exfil_started", "source_node": "web",
                    "evidence": "stream open", "ts": 900}]
        self.assertEqual(m.run_focus(topology, {"state": "running"}, started, now=1100)["exfil"]["id"], "web")

    def test_attack_features_show_new_evilkit_phases_from_tools(self):
        status = {"state": "running", "source": "evilqwen", "session_id": "s-7",
                  "last_host": "10.99.50.21", "last_exit_code": 0}
        events = [
            {"event": "recon", "tool": "mcp__pentest__nmap_scan", "ts": 950},
            # Successful attack calls use the generic host_compromised event;
            # the tool is what identifies the new EvilKit phase.
            {"event": "host_compromised", "tool": "malware_deploy", "ts": 980},
            {"event": "host_compromised", "edge": {"tool": "malware_c2"}, "ts": 999},
        ]
        summary = m.attack_features(status, events, now=1000)
        features = {item["id"]: item for item in summary["features"]}
        self.assertEqual(summary["engine"], "evilqwen")
        self.assertEqual(summary["session_id"], "s-7")
        self.assertEqual(summary["current"], "c2")
        self.assertEqual(features["recon"]["state"], "observed")
        self.assertEqual(features["implant"]["state"], "observed")
        self.assertEqual(features["c2"]["state"], "active")
        self.assertEqual(features["foothold"]["state"], "idle")

    def test_attack_feature_activity_expires_but_history_remains(self):
        summary = m.attack_features({"state": "running"}, [
            {"event": "pivot", "tool": "ssh_tunnel", "ts": 900},
        ], now=1000)
        pivot = next(item for item in summary["features"] if item["id"] == "pivot")
        self.assertIsNone(summary["current"])
        self.assertEqual(pivot["state"], "observed")

    def test_all_evilkit_phase_events_drive_dashboard_state_and_edges(self):
        phases = [
            ("recon", "discovered", "recon"),
            ("attack", "in-progress", "attack"),
            ("host_compromised", "solved", "attack"),
            ("privesc", "solved", "attack"),
            ("pivot", "in-progress", "tunnel"),
            ("implant", "solved", "attack"),
            ("persist", "solved", "attack"),
            ("lateral", "solved", "attack"),
            ("c2", "solved", "attack"),
            ("exfil", "data-read", "data"),
        ]
        now = 1000.0
        for event_name, node_state, edge_kind in phases:
            with self.subTest(event=event_name):
                event = {"event": event_name, "node": "target", "ts": now,
                         "evidence": "phase proof", "edge": {"src": "entry", "dst": "target"}}
                nodes, edges, _ = m.apply_events([event])
                self.assertEqual(nodes.get("target"), node_state)
                self.assertEqual(edges.get(("entry", "target")),
                                 "discovered" if event_name == "recon" else "used")
                detail = m.edge_event_details([event], now=now)
                self.assertEqual(detail[("entry", "target")]["kind"], edge_kind)
                self.assertTrue(detail[("entry", "target")]["connected"])

        summary = m.attack_features({"state": "running"}, [
            {"event": event_name, "ts": now + index, "tool": tool}
            for index, (event_name, tool) in enumerate([
                ("recon", "nmap_scan"), ("host_compromised", "netexec"),
                ("privesc", "password_crack"), ("pivot", "ssh_tunnel"),
                ("implant", "malware_deploy"), ("persist", "malware_persist"),
                ("lateral", "malware_worm"), ("c2", "malware_c2"),
                ("exfil", "malware_classify"),
            ])
        ], now=now + 8)
        self.assertEqual({feature["id"] for feature in summary["features"] if feature["count"]},
                         {"recon", "foothold", "privesc", "pivot", "implant",
                          "persist", "lateral", "c2", "exfil"})

    def test_topology_merge_maps_equivalents_and_keeps_run_only_nodes(self):
        brain = {
            "zones": [{"id": "brain", "label": "Brain"}],
            "nodes": [
                {"id": "g930", "label": "Domain Controller", "host": "dc01 (930)",
                 "type": "ad", "zone": "brain", "position": [80, 50], "state": "running"},
                {"id": "pod-edge-botnet", "label": "edge-botnet",
                 "host": "edge-botnet (DMZ pod)", "type": "web", "zone": "brain",
                 "position": [70, 20], "state": "running"},
                {"id": "brain-only", "label": "Brain only", "type": "router",
                 "zone": "brain", "position": [20, 20], "state": "running"},
            ],
            "edges": [],
        }
        run = {
            "zones": [{"id": "corp", "label": "CORP"}],
            "nodes": [
                {"id": "dc-roast", "label": "dc01", "type": "remote-vm", "zone": "corp",
                 "ip": "10.80.20.22", "position": [480, 360]},
                {"id": "edge-botnet", "label": "edge-botnet", "type": "container", "zone": "corp",
                 "ip": "10.80.10.22", "position": [240, 360]},
                {"id": "run-only", "label": "Run only", "type": "workstation", "zone": "corp",
                 "ip": "10.80.20.99", "position": [480, 720]},
            ],
            "edges": [{"src": "edge-botnet", "dst": "dc-roast", "kind": "attack"}],
        }

        merged, mapping = m.merge_run_and_brain_topologies(run, brain)

        self.assertEqual(mapping["dc-roast"], "g930")
        self.assertEqual(mapping["edge-botnet"], "pod-edge-botnet")
        self.assertEqual(mapping["run-only"], "run-only")
        ids = {node["id"] for node in merged["nodes"]}
        self.assertEqual(ids, {"g930", "pod-edge-botnet", "brain-only", "run-only"})
        self.assertTrue(all(0 <= value <= 100
                            for value in next(node for node in merged["nodes"]
                                              if node["id"] == "run-only")["position"]))
        self.assertIn({"src": "pod-edge-botnet", "dst": "g930", "kind": "attack"},
                      merged["edges"])
        focus = m.run_focus(merged, {"state": "running", "compromised_hosts": [
            "dc-roast", "10.80.10.22", "run-only",
        ]}, [])
        self.assertEqual({host["id"] for host in focus["compromised"]},
                         {"g930", "pod-edge-botnet", "run-only"})

    def test_legacy_drop_origin_maps_to_portable_operator_only(self):
        events = [{
            "event": "agent_on_host", "node": "g960",
            "evidence": "EvilKit MCP toolset operating from the drop",
        }, {
            "event": "recon", "node": "g950",
            "edge": {"src": "g960", "dst": "g950"},
        }, {
            "event": "agent_on_host", "node": "g960",
            "evidence": "operator now acting from this host",
        }, {
            "event": "recon", "node": "g951",
            "edge": {"src": "g960", "dst": "g951"},
        }]
        mapped = m._map_event_nodes(events, {})
        self.assertEqual(mapped[0]["node"], "pi-drop")
        self.assertEqual(mapped[1]["edge"]["src"], "pi-drop")
        self.assertEqual(mapped[2]["node"], "g960")
        self.assertEqual(mapped[3]["edge"]["src"], "g960")

    def test_stale_topology_receives_current_names_and_segments(self):
        presented = m.apply_topology_presentation({
            "zones": [{"id": "entry", "label": "Initial Access"}],
            "nodes": [
                {"id": "pi-drop", "label": "Mini Evil Kit Pi", "zone": "entry"},
                {"id": "g960", "label": "Lobby Visitor Kiosk", "zone": "entry"},
                {"id": "g930", "label": "Domain Controller", "zone": "ad"},
            ],
            "edges": [],
        })
        nodes = {node["id"]: node for node in presented["nodes"]}
        self.assertEqual(nodes["pi-drop"]["label"], "EvilKit OS Pi · mesh worker")
        self.assertTrue(nodes["pi-drop"]["operator_platform"])
        self.assertEqual(nodes["pi-drop"]["zone"], "corp")
        self.assertIn("10.50.0.220", nodes["pi-drop"]["address"])
        self.assertEqual(nodes["g960"]["label"], "Guest Network Kiosk")
        self.assertEqual(nodes["g960"]["zone"], "dmz")
        self.assertEqual(nodes["g930"]["zone"], "corp")
        self.assertIn("fabric-switch", nodes)
        self.assertEqual(nodes["fabric-hex"]["label"], "Corporate Perimeter Firewall")
        self.assertIn("MikroTik hEX", nodes["fabric-hex"]["host"])
        firewall_pairs = {
            frozenset((edge["src"], edge["dst"]))
            for edge in presented["edges"]
            if "fabric-hex" in {edge["src"], edge["dst"]}
        }
        self.assertEqual(
            firewall_pairs,
            {frozenset(("fabric-hex", node_id)) for node_id in nodes if node_id != "fabric-hex"},
        )
        self.assertEqual(
            {zone["id"] for zone in presented["zones"]},
            {"attack", "fabric", "dmz", "corp", "data", "management"},
        )

    def test_happy_time_weed_estate_gets_roles_addresses_and_current_wiring(self):
        presented = m.apply_topology_presentation({
            "zones": [{"id": "unknown", "label": "Unassigned"}],
            "nodes": [
                {"id": "g600", "label": "htw-server (600)", "zone": "unknown",
                 "address": "—", "state": "reachable", "telemetry_status": "running"},
                {"id": "g601", "label": "htw-owner (601)", "zone": "unknown",
                 "address": "—", "state": "reachable", "telemetry_status": "running"},
                {"id": "g603", "label": "htw-budtender (603)", "zone": "unknown",
                 "address": "10.50.0.13", "state": "reachable", "telemetry_status": "running"},
            ],
            "edges": [],
        })
        nodes = {node["id"]: node for node in presented["nodes"]}
        self.assertEqual(nodes["g600"]["label"], "HTW Server · AD + Web + Crown")
        self.assertEqual(nodes["g600"]["zone"], "corp")
        self.assertEqual(nodes["g600"]["address"], "10.50.0.10")
        self.assertEqual(nodes["g600"]["type"], "ad")
        self.assertIn("guest network not observed", nodes["g600"]["telemetry"]["network"])
        self.assertEqual(nodes["g601"]["address"], "10.50.0.11")
        self.assertEqual(nodes["g603"]["label"], "HTW Budtender POS")
        self.assertEqual(nodes["g603"]["zone"], "corp")
        self.assertNotIn("telemetry", nodes["g603"])

        m.apply_provisioning_states(list(nodes.values()))
        self.assertEqual(nodes["g600"]["state"], "in-progress")
        self.assertEqual(nodes["g600"]["telemetry"]["provisioning"], "guest OS/network not ready")
        self.assertEqual(nodes["g603"]["state"], "reachable")

        physical = {(edge["src"], edge["dst"]): edge for edge in presented["edges"]
                    if edge.get("kind") == "fabric"}
        self.assertIn(("parrot-operator", "fabric-asus"), physical)
        self.assertIn("p6", physical[("fabric-asus", "fabric-switch")]["label"])
        self.assertIn("p4", physical[("fabric-switch", "pi-drop")]["label"])

        pivots = [edge for edge in presented["edges"] if edge.get("pivot_possible")]
        self.assertEqual(len(pivots), 3)  # every pair among the three HTW fixtures
        self.assertTrue(all(edge["direct"] and edge["direction"] == "both" for edge in pivots))
        self.assertIn(
            frozenset(("g600", "g603")),
            {frozenset((edge["src"], edge["dst"])) for edge in pivots},
        )

    def test_dmz_services_get_direct_pivot_paths_to_htw_entry_only(self):
        presented = m.apply_topology_presentation({
            "zones": [],
            "nodes": [
                {"id": "g600", "zone": "unknown", "address": "—"},
                {"id": "g601", "zone": "unknown", "address": "—"},
                {"id": "pod-edge-upload", "zone": "ksdmz", "address": "10.99.50.111"},
                {"id": "pod-token-jwt", "zone": "ksdmz", "address": "10.99.50.117"},
            ],
            "edges": [],
        })
        pivots = [edge for edge in presented["edges"] if edge.get("pivot_possible")]
        pairs = {(edge["src"], edge["dst"]) for edge in pivots}
        self.assertIn(("pod-edge-upload", "g600"), pairs)
        self.assertIn(("pod-token-jwt", "g600"), pairs)
        self.assertNotIn(("pod-edge-upload", "g601"), pairs)
        self.assertEqual(len(pivots), 3)  # g600<->g601 plus two service entry paths

    def test_fabric_telemetry_and_firewall_flows_attach_to_router_nodes(self):
        nodes = [
            {"id": "fabric-hex", "address": "10.10.0.1", "state": "unknown"},
            {"id": "fabric-asus", "address": "192.168.0.1", "state": "unknown"},
            {"id": "fabric-switch", "address": "10.10.0.5", "state": "reachable"},
            {"id": "pi-drop", "address": "10.50.0.220", "state": "reachable"},
        ]
        m.enrich_fabric_telemetry(nodes, {
            "hex (labrouter)": {"reachable": True, "telemetry": {"conntrack": "12"}, "detail": "up 1 day"},
        })
        self.assertEqual(nodes[0]["telemetry"]["conntrack"], "12")
        edges, events = m.firewall_overlays(nodes, [{
            "src": "10.50.0.220", "dst": "10.50.0.1", "class": "recon",
            "proto": "UDP", "dpt": "53", "prefix": "reject keystone",
            "router": "labrouter", "ts": 100,
        }])
        self.assertEqual((edges[0]["src"], edges[0]["dst"]), ("pi-drop", "fabric-hex"))
        self.assertEqual(edges[0]["tool"], "Corporate Perimeter Firewall")
        self.assertEqual(events[0]["event"], "firewall_drop")


class DemoPlayerTests(unittest.TestCase):
    def test_demo_dataset_loads_and_is_internally_consistent(self):
        player = m.DemoPlayer(m.DEMO_DIR)
        node_ids = {n["id"] for n in player.topology["nodes"]}
        for e in player.topology["edges"]:
            self.assertIn(e["src"], node_ids)
            self.assertIn(e["dst"], node_ids)
        for ev in player.script:
            if ev.get("node"):
                self.assertIn(ev["node"], node_ids)
            if ev.get("edge"):
                self.assertIn(ev["edge"]["src"], node_ids)
                self.assertIn(ev["edge"]["dst"], node_ids)

    def test_demo_progresses_and_eventually_reports_six_flags(self):
        player = m.DemoPlayer(m.DEMO_DIR)
        player.epoch = time.time() - (player.loop_duration - 0.5)  # near the end of the loop
        status, nodes, edges, events = player.sample()
        self.assertEqual(status["score"], "6/6")
        self.assertEqual(len(status["flags"]), 6)
        self.assertEqual(status["state"], "finished")

    def test_demo_loops_without_external_calls(self):
        # No hosted-model / network call of any kind: this is a pure, offline replay.
        player = m.DemoPlayer(m.DEMO_DIR)
        player.epoch = time.time() - 1.0
        status, nodes, edges, events = player.sample()
        self.assertIn(status["state"], ("running", "finished"))
        self.assertTrue(events)


class EvilKitMeshReaderTests(unittest.TestCase):
    def test_live_workers_include_task_terminal_and_topology_host(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            connection = root / "connection.json"
            token = root / "token"
            log = root / "clone-display.jsonl"
            windows = root / "clone-display-windows.json"
            connection.write_text(json.dumps({"leader": "http://100.88.148.72:8765"}))
            token.write_text("t" * 32)
            log.write_text(json.dumps({"clone": "evilkit-pi-01", "host": "10.10.66.143"}) + "\n")
            windows.write_text(json.dumps({
                "evilkit-pi-01": {"pid": __import__("os").getpid(), "host": "10.10.66.143"}
            }))
            state = {
                "workers": [{"name": "evilkit-pi-01", "seen": 995, "status": "running", "task": "t1"}],
                "tasks": [{"id": "t1", "worker": "evilkit-pi-01", "status": "running",
                           "prompt": "Enumerate the web service and report findings"}],
            }
            response = mock.MagicMock()
            response.__enter__.return_value = io.StringIO(json.dumps(state))
            reader = m.EvilKitMeshReader(connection, token, log, windows)
            nodes = [{"id": "pi-drop", "host": "evilkit-pi-01 drop node", "address": "10.10.66.143"}]
            with mock.patch.object(m, "urlopen", return_value=response):
                fleet = reader.read(nodes, now=1000)
            clone = fleet["clones"][0]
            self.assertTrue(fleet["connected"])
            self.assertEqual(clone["activity"], "Enumerate the web service and report findings")
            self.assertEqual(clone["node_id"], "pi-drop")
            self.assertTrue(clone["terminal_open"])

    def test_hub_failure_keeps_detected_clones_visible(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            log = root / "clone-display.jsonl"
            log.write_text(json.dumps({"clone": "pi-one", "host": "10.10.66.10"}) + "\n")
            reader = m.EvilKitMeshReader(None, None, log, None)
            fleet = reader.read([{"id": "drop", "address": "10.10.66.10"}])
            self.assertFalse(fleet["connected"])
            self.assertEqual(fleet["clones"][0]["node_id"], "drop")


class RangeWatcherTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.orig_root = m.KEYSTONE_ROOT
        self.orig_runs = m.RUNS_DIR
        self.orig_data_dir = m.DATA_DIR
        self.orig_stick_mounts = m.stick_mounts
        m.KEYSTONE_ROOT = self.root
        m.RUNS_DIR = self.root / "runs"
        m.DATA_DIR = self.root / "data"
        # Hermetic by default: these tests are about run selection, and a real
        # range stick plugged into the host must not change their expectations.
        # The stick path gets its own explicit test below.
        m.stick_mounts = lambda mounts_text=None: []
        self.watcher = m.RangeWatcher()
        self.watcher.control_scripts = {
            action: self.root / "bin" / f"{action}.sh"
            for action in ("start", "reset", "stop")
        }

    def tearDown(self):
        m.KEYSTONE_ROOT = self.orig_root
        m.RUNS_DIR = self.orig_runs
        m.DATA_DIR = self.orig_data_dir
        m.stick_mounts = self.orig_stick_mounts
        self.tmp.cleanup()

    def write_run(self, run_id, mtime_offset=0, status=None):
        dash = m.RUNS_DIR / run_id / "dashboard"
        dash.mkdir(parents=True)
        (dash / "topology.json").write_text(json.dumps({
            "zones": [{"id": "z1", "label": "Zone 1"}],
            "nodes": [{"id": "n1", "label": "n1", "type": "web", "zone": "z1", "position": [10, 10]}],
            "edges": [],
        }))
        (dash / "status.json").write_text(json.dumps(status or {"run_id": run_id, "state": "running"}))
        (dash / "events.jsonl").write_text("")
        if mtime_offset:
            t = time.time() + mtime_offset
            import os
            os.utime(dash / "status.json", (t, t))
        return dash

    def age_run(self, run_id, mtime_offset):
        """Back-date every file in a run so RangeWatcher.dashboard_age reports it as old."""
        import os
        t = time.time() + mtime_offset
        dash = m.RUNS_DIR / run_id / "dashboard"
        for path in dash.iterdir():
            os.utime(path, (t, t))
        return dash

    def test_falls_back_to_clean_range_when_no_runs_dir(self):
        # No demo traffic: with no runs the board shows the (here empty) range
        # topology with no events or edges — nothing moves unless it's real.
        self.watcher.collect()
        self.assertEqual(self.watcher.sample["mode"], "range")
        self.assertEqual(self.watcher.sample["events"], [])
        self.assertEqual(self.watcher.sample["edges"], [])

    def test_picks_up_live_run_over_demo(self):
        self.write_run("run-a")
        self.watcher.collect()
        self.assertEqual(self.watcher.sample["mode"], "live")
        self.assertEqual(self.watcher.sample["status"]["run_id"], "run-a")

    def test_paused_run_still_owns_the_live_view(self):
        # A held run writes no telemetry, so the active-run freshness window
        # would otherwise drop it and the board would slide back to the idle
        # range view in the middle of an engagement.
        self.write_run("live-brain", status={"run_id": "live-brain", "state": "running"})
        self.write_run("run-paused", mtime_offset=-1800,
                       status={"run_id": "run-paused", "state": "paused"})
        self.watcher.collect()
        self.assertEqual(self.watcher.sample["status"]["run_id"], "run-paused")
        self.assertEqual(self.watcher.sample["status"]["state"], "paused")

    def test_actively_running_run_outranks_a_paused_one(self):
        self.write_run("run-paused", mtime_offset=-1800,
                       status={"run_id": "run-paused", "state": "paused"})
        self.write_run("run-active", status={"run_id": "run-active", "state": "running"})
        self.watcher.collect()
        self.assertEqual(self.watcher.sample["status"]["run_id"], "run-active")

    def test_picks_most_recently_modified_run(self):
        self.write_run("run-old", mtime_offset=-100)
        self.write_run("run-new", mtime_offset=0)
        self.watcher.collect()
        self.assertEqual(self.watcher.sample["status"]["run_id"], "run-new")

    def test_active_run_takes_priority_over_live_brain_heartbeat(self):
        self.write_run("run-active", status={"run_id": "run-active", "state": "running"})
        self.write_run("live-brain", mtime_offset=10,
                       status={"run_id": "live-brain", "state": "running"})
        self.watcher.collect()
        self.assertEqual(self.watcher.sample["status"]["run_id"], "run-active")

    def test_long_active_run_stays_visible_until_stopped(self):
        self.write_run("run-active", mtime_offset=-3600,
                       status={"run_id": "run-active", "state": "starting"})
        self.write_run("live-brain", status={"run_id": "live-brain", "state": "running"})
        self.watcher.collect()
        self.assertEqual(self.watcher.sample["status"]["run_id"], "run-active")

    def test_recent_finished_run_stays_visible_for_grace_window(self):
        # README promises a completed run stays in view for ten minutes so the
        # operator can read the final board without flipping to all-green idle.
        self.write_run("run-finished", status={"run_id": "run-finished", "state": "finished"})
        self.watcher.collect()
        self.assertEqual(self.watcher.sample["status"]["run_id"], "run-finished")
        self.assertEqual(self.watcher.sample["mode"], "live")

    def test_reset_run_replaces_status_rewritten_finished_run(self):
        finished = self.write_run(
            "run-finished", status={
                "run_id": "run-finished", "state": "finished",
                "compromised_hosts": ["n1"],
            },
        )
        with (finished / "events.jsonl").open("w") as handle:
            handle.write(json.dumps({
                "run_id": "run-finished", "event": "host_compromised",
                "node": "n1", "evidence": "old shell",
            }) + "\n")
        # Age the run past the compromise hold: an explicit reset must displace
        # a released old engagement, even though its status.json still lists
        # compromised hosts.
        self.age_run("run-finished", -2000)
        # Reproduce the bridge heartbeat that made the old completed run look
        # current even though its topology and event stream were stale.
        (finished / "status.json").write_text(json.dumps({
            "run_id": "run-finished", "state": "finished",
            "compromised_hosts": ["n1"],
        }))
        # The session bridge also refreshes its copied live-brain topology on
        # every poll; neither heartbeat represents new engagement activity.
        (finished / "topology.json").touch()
        self.write_run("run-reset", status={"run_id": "run-reset", "state": "idle"})

        self.watcher.collect()

        self.assertEqual(self.watcher.sample["status"]["run_id"], "run-reset")
        self.assertEqual(self.watcher.sample["mode"], "range")
        self.assertEqual(self.watcher.sample["focus"]["compromised"], [])

    def test_finished_run_with_fresh_events_still_wins_the_view(self):
        # Self-heal: the emitter's idle timer marks a run finished while the
        # agent thinks, then keeps rewriting "finished" — but events are still
        # being appended, so the run must keep the board. A freshly published
        # idle run must not reset the view mid-engagement.
        self.write_run("run-engage", status={"run_id": "run-engage", "state": "finished"})
        self.write_run("run-reset", status={"run_id": "run-reset", "state": "idle"})
        self.watcher.collect()
        self.assertEqual(self.watcher.sample["status"]["run_id"], "run-engage")
        self.assertEqual(self.watcher.sample["mode"], "live")

    def test_beacon_overlays_draw_c2_edges_from_clone_hosts(self):
        dash = self.write_run(
            "run-beacon", status={"run_id": "run-beacon", "state": "running"},
        )
        topology = {
            "zones": [{"id": "z1", "label": "Zone 1"}],
            "nodes": [
                {"id": "op", "label": "operator", "type": "operator", "zone": "z1",
                 "position": [10, 10], "ip": "10.0.0.1"},
                {"id": "host", "label": "host", "type": "web", "zone": "z1",
                 "position": [20, 10], "ip": "10.99.50.21"},
            ],
            "edges": [],
        }
        (dash / "topology.json").write_text(json.dumps(topology))
        with (dash / "events.jsonl").open("w") as handle:
            handle.write(json.dumps({
                "run_id": "run-beacon", "event": "agent_on_host", "node": "op",
                "evidence": "operator origin", "ts": time.time(),
            }) + "\n")
        run_dir = m.RUNS_DIR / "run-beacon"
        with (run_dir / "beacons.jsonl").open("w") as handle:
            handle.write(json.dumps({
                "event": "c2", "src": "10.99.50.21", "bid": "r8-host-1",
                "ts": time.time(),
            }) + "\n")
        self.watcher.collect()
        c2_edges = [e for e in self.watcher.sample["edges"] if e.get("kind") == "c2"]
        self.assertEqual(len(c2_edges), 1)
        self.assertEqual(c2_edges[0]["src"], "host")
        self.assertEqual(c2_edges[0]["dst"], "op")
        self.assertTrue(c2_edges[0]["connected"])
        node = next(n for n in self.watcher.sample["nodes"] if n["id"] == "host")
        self.assertEqual(node.get("c2_beacon", {}).get("bid"), "r8-host-1")
        # A beaconing host is compromised: it must join the focus set and paint
        # dark red even without a host_compromised dashboard event.
        compromised = [h["id"] for h in self.watcher.sample["focus"]["compromised"]]
        self.assertIn("host", compromised)

    def test_stale_beacon_edge_renders_disconnected(self):
        dash = self.write_run(
            "run-beacon-old", status={"run_id": "run-beacon-old", "state": "running"},
        )
        topology = {
            "zones": [{"id": "z1", "label": "Zone 1"}],
            "nodes": [
                {"id": "op", "label": "operator", "type": "operator", "zone": "z1",
                 "position": [10, 10], "ip": "10.0.0.1"},
                {"id": "host", "label": "host", "type": "web", "zone": "z1",
                 "position": [20, 10], "ip": "10.99.50.21"},
            ],
            "edges": [],
        }
        (dash / "topology.json").write_text(json.dumps(topology))
        with (dash / "events.jsonl").open("w") as handle:
            handle.write(json.dumps({
                "run_id": "run-beacon-old", "event": "agent_on_host", "node": "op",
                "evidence": "operator origin", "ts": time.time(),
            }) + "\n")
        run_dir = m.RUNS_DIR / "run-beacon-old"
        with (run_dir / "beacons.jsonl").open("w") as handle:
            handle.write(json.dumps({
                "event": "c2", "src": "10.99.50.21", "bid": "r8-host-old",
                "ts": time.time() - 600,
            }) + "\n")
        self.watcher.collect()
        c2_edges = [e for e in self.watcher.sample["edges"] if e.get("kind") == "c2"]
        self.assertEqual(len(c2_edges), 1)
        self.assertFalse(c2_edges[0]["connected"])

    def test_quiet_compromised_run_holds_board_over_fresh_idle_run(self):
        # The user-facing contract: once a host is compromised it stays dark
        # red for the rest of the run. A quiet stretch (emitter already said
        # finished, events older than the 10-minute grace) must not hand the
        # view to the range's ambient idle publish.
        finished = self.write_run(
            "run-engage", status={
                "run_id": "run-engage", "state": "finished",
                "compromised_hosts": ["n1"],
            },
        )
        with (finished / "events.jsonl").open("w") as handle:
            handle.write(json.dumps({
                "run_id": "run-engage", "event": "host_compromised",
                "node": "n1", "evidence": "root shell", "ts": time.time() - 700,
            }) + "\n")
        self.age_run("run-engage", -700)
        self.write_run("run-idle", status={"run_id": "run-idle", "state": "idle"})
        self.watcher.collect()
        self.assertEqual(self.watcher.sample["status"]["run_id"], "run-engage")
        self.assertEqual(self.watcher.sample["mode"], "live")
        compromised = [h["id"] for h in self.watcher.sample["focus"]["compromised"]]
        self.assertIn("n1", compromised)

    def test_released_compromised_run_yields_to_idle_run_after_hold(self):
        finished = self.write_run(
            "run-engage", status={
                "run_id": "run-engage", "state": "finished",
                "compromised_hosts": ["n1"],
            },
        )
        with (finished / "events.jsonl").open("w") as handle:
            handle.write(json.dumps({
                "run_id": "run-engage", "event": "host_compromised",
                "node": "n1", "evidence": "root shell", "ts": time.time() - 700,
            }) + "\n")
        self.age_run("run-engage", -2000)
        self.write_run("run-idle", status={"run_id": "run-idle", "state": "idle"})
        self.watcher.collect()
        self.assertEqual(self.watcher.sample["status"]["run_id"], "run-idle")
        self.assertEqual(self.watcher.sample["mode"], "range")

    def test_explicit_reset_supersedes_compromise_hold(self):
        # The Reset button must wipe the board: even a compromised run with
        # fresh evidence loses once the operator resets.
        finished = self.write_run(
            "run-engage", status={
                "run_id": "run-engage", "state": "finished",
                "compromised_hosts": ["n1"],
            },
        )
        with (finished / "events.jsonl").open("w") as handle:
            handle.write(json.dumps({
                "run_id": "run-engage", "event": "host_compromised",
                "node": "n1", "evidence": "root shell", "ts": time.time() - 100,
            }) + "\n")
        self.age_run("run-engage", -100)
        self.watcher._reset_epoch = time.time()
        self.write_run("run-reset", status={"run_id": "run-reset", "state": "idle"})
        self.watcher.collect()
        self.assertEqual(self.watcher.sample["status"]["run_id"], "run-reset")
        self.assertEqual(self.watcher.sample["mode"], "range")
        self.assertEqual(self.watcher.sample["focus"]["compromised"], [])

    def test_post_reset_activity_reclaims_the_board(self):
        # A run whose events are appended AFTER the reset is new work, not the
        # superseded engagement: normal priority rules apply again.
        finished = self.write_run(
            "run-engage", status={
                "run_id": "run-engage", "state": "finished",
                "compromised_hosts": ["n1"],
            },
        )
        self.watcher._reset_epoch = time.time()
        # New events land after the reset: the run is alive again.
        with (finished / "events.jsonl").open("w") as handle:
            handle.write(json.dumps({
                "run_id": "run-engage", "event": "host_compromised",
                "node": "n1", "evidence": "root shell", "ts": time.time(),
            }) + "\n")
        self.write_run("run-reset", status={"run_id": "run-reset", "state": "idle"})
        self.watcher.collect()
        self.assertEqual(self.watcher.sample["status"]["run_id"], "run-engage")

    def test_reset_epoch_persists_and_loads(self):
        self.watcher._reset_epoch = 1234.5
        self.watcher._save_reset_epoch()
        self.assertEqual(self.watcher._load_reset_epoch(), 1234.5)
        self.assertEqual(m.RangeWatcher()._reset_epoch, 1234.5)

    def test_reset_run_uses_live_brain_node_states_as_baseline(self):
        brain = self.write_run(
            "live-brain", status={"run_id": "live-brain", "state": "running"},
        )
        brain_topology = json.loads((brain / "topology.json").read_text())
        brain_topology["nodes"].append({
            "id": "n2", "label": "n2", "type": "web", "zone": "z1", "position": [20, 10],
        })
        (brain / "topology.json").write_text(json.dumps(brain_topology))
        with (brain / "events.jsonl").open("w") as handle:
            handle.write(json.dumps({
                "run_id": "live-brain", "node": "n1",
                "evidence": "pct/qm status='running' lock=''",
            }) + "\n")
            handle.write(json.dumps({
                "run_id": "live-brain", "node": "n2",
                "evidence": "pct/qm status='stopped' lock=''",
            }) + "\n")
        self.write_run("run-reset", status={"run_id": "run-reset", "state": "idle"})

        self.watcher.collect()

        states = {node["id"]: node["state"] for node in self.watcher.sample["nodes"]}
        self.assertEqual(self.watcher.sample["status"]["run_id"], "run-reset")
        self.assertEqual(self.watcher.sample["mode"], "range")
        self.assertEqual(states, {"n1": "running", "n2": "stopped"})

    def test_full_run_topology_refreshes_live_telemetry_metadata(self):
        brain = self.write_run(
            "live-brain", status={"run_id": "live-brain", "state": "running"},
        )
        brain_topology = json.loads((brain / "topology.json").read_text())
        brain_topology["nodes"][0].update({
            "state": "reachable",
            "telemetry_source": "Proxmox pct",
            "telemetry_status": "running",
        })
        (brain / "topology.json").write_text(json.dumps(brain_topology))
        self.write_run("run-reset", status={"run_id": "run-reset", "state": "idle"})

        self.watcher.collect()

        node = self.watcher.sample["nodes"][0]
        self.assertEqual(node["state"], "reachable")
        self.assertEqual(node["telemetry_source"], "Proxmox pct")
        self.assertEqual(node["telemetry_status"], "running")

    def test_real_run_compromises_survive_brain_topology_merge(self):
        brain = self.write_run(
            "live-brain", status={"run_id": "live-brain", "state": "running"},
        )
        (brain / "topology.json").write_text(json.dumps({
            "zones": [{"id": "brain", "label": "Brain"}],
            "nodes": [
                {"id": "pod-edge-botnet", "label": "edge-botnet",
                 "host": "edge-botnet (DMZ pod)", "type": "web", "zone": "brain",
                 "position": [70, 20], "state": "running"},
                {"id": "g930", "label": "Domain Controller", "host": "dc01 (930)",
                 "type": "ad", "zone": "brain", "position": [80, 50], "state": "running"},
            ],
            "edges": [],
        }))
        run = self.write_run(
            "run-real", status={"run_id": "run-real", "state": "running"},
        )
        (run / "topology.json").write_text(json.dumps({
            "zones": [{"id": "corp", "label": "CORP"}],
            "nodes": [
                {"id": "edge-botnet", "label": "edge-botnet", "type": "container",
                 "zone": "corp", "ip": "10.80.10.22", "position": [240, 360]},
                {"id": "dc-roast", "label": "dc01", "type": "remote-vm",
                 "zone": "corp", "ip": "10.80.20.22", "position": [480, 360]},
                {"id": "new-target", "label": "New target", "type": "workstation",
                 "zone": "corp", "ip": "10.80.20.99", "position": [480, 720]},
            ],
            "edges": [],
        }))
        with (run / "events.jsonl").open("w") as handle:
            for node in ("edge-botnet", "dc-roast", "new-target"):
                handle.write(json.dumps({
                    "run_id": "run-real", "event": "host_compromised", "node": node,
                    "evidence": "confirmed shell", "ts": time.time(),
                }) + "\n")

        self.watcher.collect()

        nodes = {node["id"]: node for node in self.watcher.sample["nodes"]}
        self.assertTrue({"pod-edge-botnet", "g930", "new-target"}.issubset(nodes))
        self.assertEqual(nodes["pod-edge-botnet"]["state"], "solved")
        self.assertEqual(nodes["g930"]["state"], "solved")
        self.assertEqual(nodes["new-target"]["state"], "solved")
        self.assertEqual({host["id"] for host in self.watcher.sample["focus"]["compromised"]},
                         {"pod-edge-botnet", "g930", "new-target"})

    def test_node_colour_is_sticky_across_polls(self):
        # A compromise must not flicker back to grey when a later poll reads the
        # events file mid-write (transient empty) — the map should hold.
        dash = self.write_run("run-flicker", status={"run_id": "run-flicker", "state": "running"})
        with (dash / "events.jsonl").open("w") as fh:
            fh.write(json.dumps({"run_id": "run-flicker", "event": "host_compromised",
                                 "node": "n1", "ts": time.time()}) + "\n")
        self.watcher.collect()
        states = {n["id"]: n["state"] for n in self.watcher.sample["nodes"]}
        self.assertEqual(states.get("n1"), "solved")

        # transient: the events file is momentarily empty on the next poll
        (dash / "events.jsonl").write_text("")
        self.watcher.collect()
        states2 = {n["id"]: n["state"] for n in self.watcher.sample["nodes"]}
        self.assertEqual(states2.get("n1"), "solved")  # held, did not flick to unknown

        # a different run resets the sticky colouring (fresh slate)
        self.write_run("run-next", mtime_offset=5, status={"run_id": "run-next", "state": "running"})
        self.watcher.collect()
        self.assertEqual(self.watcher.sample["status"]["run_id"], "run-next")
        states3 = {n["id"]: n["state"] for n in self.watcher.sample["nodes"]}
        self.assertEqual(states3.get("n1"), "unknown")

    def test_current_operator_host_counts_as_compromised(self):
        # EvilKit operating on a host (clone/shell there) means it's compromised,
        # so it must appear in the compromised set even with no foothold event.
        dash = self.write_run("run-cur", status={"run_id": "run-cur", "state": "running"})
        with (dash / "events.jsonl").open("w") as fh:
            fh.write(json.dumps({"run_id": "run-cur", "event": "agent_on_host",
                                 "node": "n1", "evidence": "EvilKit operating from here",
                                 "ts": time.time()}) + "\n")
        self.watcher.collect()
        focus = self.watcher.sample["focus"]
        self.assertEqual((focus.get("current") or {}).get("id"), "n1")
        self.assertIn("n1", [h["id"] for h in focus.get("compromised") or []])

    def test_red_team_platform_is_current_but_never_a_compromised_target(self):
        dash = self.write_run("run-platform", status={"run_id": "run-platform", "state": "running"})
        (dash / "topology.json").write_text(json.dumps({
            "zones": [{"id": "operators", "label": "Red Team Platform"}],
            "nodes": [{
                "id": "pi-drop", "label": "Portable Red Team Node", "type": "operator",
                "zone": "operators", "operator_platform": True, "position": [10, 10],
            }],
            "edges": [],
        }))
        (dash / "events.jsonl").write_text(json.dumps({
            "run_id": "run-platform", "event": "agent_on_host", "node": "pi-drop",
            "evidence": "operator platform selected", "ts": time.time(),
        }) + "\n")
        self.watcher.collect()
        focus = self.watcher.sample["focus"]
        self.assertEqual((focus.get("current") or {}).get("id"), "pi-drop")
        self.assertNotIn("pi-drop", [h["id"] for h in focus.get("compromised") or []])

    def test_live_brain_ambient_shows_no_traffic(self):
        # The ambient live-brain view is never a live engagement: it shows the
        # topology and host health, but no edges/events read as run traffic.
        brain = m.RUNS_DIR / "live-brain" / "dashboard"
        brain.mkdir(parents=True)
        (brain / "topology.json").write_text(json.dumps({
            "zones": [{"id": "z1", "label": "Zone 1"}],
            "nodes": [
                {"id": "n1", "label": "n1", "type": "web", "zone": "z1", "position": [10, 10]},
                {"id": "n2", "label": "n2", "type": "db", "zone": "z1", "position": [20, 20]},
            ],
            # a pre-coloured attack link that must NOT show as traffic when idle
            "edges": [{"src": "n1", "dst": "n2", "kind": "attack", "state": "used"}],
        }))
        (brain / "status.json").write_text(json.dumps({"run_id": "live-brain", "state": "running"}))
        with (brain / "events.jsonl").open("w") as handle:
            handle.write(json.dumps({
                "run_id": "live-brain", "node": "n2", "event": "exploit",
                "edge": {"src": "n1", "dst": "n2", "traffic_class": "attack", "mcp_tool": "nmap"},
                "evidence": "ambient flow", "ts": time.time(),
            }) + "\n")

        self.watcher.collect()

        self.assertIn(self.watcher.sample["mode"], {"range", "stale"})
        self.assertEqual(self.watcher.sample["events"], [])
        for edge in self.watcher.sample["edges"]:
            self.assertEqual(edge["state"], "unknown")
            self.assertEqual(edge["kind"], "network")

    def test_old_finished_run_falls_back_to_clean_range(self):
        self.write_run("run-finished", status={"run_id": "run-finished", "state": "finished"})
        self.age_run("run-finished", -700)
        self.watcher.collect()
        self.assertEqual(self.watcher.sample["mode"], "range")
        self.assertEqual(self.watcher.sample["events"], [])

    def test_active_run_outranks_recently_finished_run(self):
        self.write_run("run-finished", status={"run_id": "run-finished", "state": "finished"})
        self.write_run("run-active", mtime_offset=-30,
                       status={"run_id": "run-active", "state": "running"})
        self.watcher.collect()
        self.assertEqual(self.watcher.sample["status"]["run_id"], "run-active")

    def test_stale_live_brain_snapshot_keeps_full_topology_visible(self):
        dash = self.write_run("live-brain", status={"run_id": "live-brain", "state": "running"})
        stale_time = time.time() - 120
        import os
        for path in dash.iterdir():
            os.utime(path, (stale_time, stale_time))
        self.watcher.collect()
        self.assertEqual(self.watcher.sample["mode"], "stale")
        self.assertEqual(self.watcher.sample["status"]["state"], "stale")
        self.assertEqual([node["id"] for node in self.watcher.sample["nodes"]], ["n1"])

    def test_events_drive_node_state(self):
        dash = self.write_run("run-b")
        with (dash / "events.jsonl").open("w") as f:
            f.write(json.dumps({"run_id": "run-b", "event": "node_solved", "node": "n1", "evidence": "x"}) + "\n")
        self.watcher.collect()
        node = next(n for n in self.watcher.sample["nodes"] if n["id"] == "n1")
        self.assertEqual(node["state"], "solved")

    def test_active_event_only_traffic_edge_is_rendered(self):
        dash = self.write_run("run-traffic")
        topology = json.loads((dash / "topology.json").read_text())
        topology["nodes"].append({"id": "n2", "label": "n2", "type": "web", "zone": "z1", "position": [20, 10]})
        (dash / "topology.json").write_text(json.dumps(topology))
        with (dash / "events.jsonl").open("w") as f:
            f.write(json.dumps({
                "run_id": "run-traffic", "event": "mcp_action", "status": "started", "ts": time.time(),
                "edge": {"src": "n1", "dst": "n2", "traffic_class": "recon", "tool": "nmap_scan", "source": "pentest_mcp"},
            }) + "\n")
        self.watcher.collect()
        edge = next(e for e in self.watcher.sample["edges"] if e["src"] == "n1" and e["dst"] == "n2")
        self.assertEqual(edge["kind"], "recon")
        self.assertEqual(edge["state"], "used")
        self.assertTrue(edge["connected"])

    def test_completed_event_only_traffic_edge_is_not_rendered(self):
        dash = self.write_run("run-traffic-complete")
        topology = json.loads((dash / "topology.json").read_text())
        topology["nodes"].append({"id": "n2", "label": "n2", "type": "web", "zone": "z1", "position": [20, 10]})
        (dash / "topology.json").write_text(json.dumps(topology))
        with (dash / "events.jsonl").open("w") as f:
            f.write(json.dumps({
                "run_id": "run-traffic-complete", "event": "mcp_action", "status": "completed", "ts": time.time(),
                "edge": {"src": "n1", "dst": "n2", "traffic_class": "recon", "tool": "nmap_scan"},
            }) + "\n")
        self.watcher.collect()
        self.assertFalse(any(e["src"] == "n1" and e["dst"] == "n2" for e in self.watcher.sample["edges"]))

    def test_stale_evilkit_action_edge_remains_as_history(self):
        dash = self.write_run("run-traffic-history")
        topology = json.loads((dash / "topology.json").read_text())
        topology["nodes"].append({"id": "n2", "label": "n2", "type": "web", "zone": "z1", "position": [20, 10]})
        (dash / "topology.json").write_text(json.dumps(topology))
        with (dash / "events.jsonl").open("w") as f:
            f.write(json.dumps({
                "run_id": "run-traffic-history", "event": "exploit", "status": "running",
                "ts": time.time() - 60,
                "edge": {"src": "n1", "dst": "n2", "traffic_class": "attack", "tool": "credential_spray"},
            }) + "\n")
        self.watcher.collect()
        edge = next(e for e in self.watcher.sample["edges"] if e["src"] == "n1" and e["dst"] == "n2")
        self.assertEqual(edge["kind"], "attack")
        self.assertTrue(edge["historical"])
        self.assertFalse(edge["connected"])

    def test_control_unavailable_when_script_missing(self):
        self.watcher.collect()
        with self.assertRaises(ValueError):
            self.watcher.run_control("start")
        self.assertFalse(self.watcher.sample["controls"]["start"]["available"])

    def test_control_available_and_launches_when_script_present_and_executable(self):
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        script = bin_dir / "start.sh"
        script.write_text("#!/bin/sh\necho ok\n")
        script.chmod(script.stat().st_mode | stat.S_IEXEC)
        self.watcher.control_scripts["start"] = script
        try:
            self.watcher.collect()
            self.assertTrue(self.watcher.sample["controls"]["start"]["available"])
            result = self.watcher.run_control("start")
            self.assertEqual(result["script"], str(script))
            self.assertEqual(self.watcher.sample["control_run"]["pid"], result["pid"])
            self.assertIn(self.watcher.sample["control_run"]["status"], {"running", "succeeded"})
            deadline = time.time() + 2
            while self.watcher.control_status()["status"] == "running" and time.time() < deadline:
                time.sleep(0.02)
            self.assertEqual(self.watcher.control_status()["status"], "succeeded")
            self.assertEqual(self.watcher.control_status()["returncode"], 0)
        finally:
            self.watcher.control_scripts["start"] = self.orig_root / "bin" / "start.sh"

    def test_control_failure_is_reported_after_process_exits(self):
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        script = bin_dir / "reset.sh"
        script.write_text("#!/bin/sh\necho reset failed\nexit 7\n")
        script.chmod(script.stat().st_mode | stat.S_IEXEC)
        self.watcher.control_scripts["reset"] = script
        try:
            result = self.watcher.run_control("reset")
            self.assertEqual(result["status"], "running")
            deadline = time.time() + 2
            while self.watcher.control_status()["status"] == "running" and time.time() < deadline:
                time.sleep(0.02)
            status = self.watcher.control_status()
            self.assertEqual(status["status"], "failed")
            self.assertEqual(status["returncode"], 7)
            self.assertIn("exit 7", status["message"])
            # the script's last log line (the real reason) is surfaced to the UI
            self.assertIn("reset failed", status["message"])
        finally:
            self.watcher.control_scripts["reset"] = self.orig_root / "bin" / "reset.sh"

    def test_second_control_is_rejected_while_one_is_running(self):
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        start = bin_dir / "start.sh"
        stop = bin_dir / "stop.sh"
        start.write_text("#!/bin/sh\nsleep 0.3\n")
        stop.write_text("#!/bin/sh\necho stopped\n")
        for script in (start, stop):
            script.chmod(script.stat().st_mode | stat.S_IEXEC)
        self.watcher.control_scripts.update(start=start, stop=stop)
        try:
            self.watcher.run_control("start")
            with self.assertRaisesRegex(ValueError, "start is already running"):
                self.watcher.run_control("stop")
            self.assertTrue(self.watcher.control_availability()["stop"]["busy"])
        finally:
            time.sleep(0.4)
            self.watcher.control_scripts["start"] = self.orig_root / "bin" / "start.sh"
            self.watcher.control_scripts["stop"] = self.orig_root / "bin" / "stop.sh"


class HttpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        m.KEYSTONE_ROOT = Path(self.tmp.name)
        m.RUNS_DIR = m.KEYSTONE_ROOT / "runs"
        self.watcher = m.RangeWatcher()
        self.watcher.control_scripts = {
            action: m.KEYSTONE_ROOT / "bin" / f"{action}.sh"
            for action in ("start", "reset", "stop")
        }
        self.watcher.sample = {"seq": 1, "mode": "demo"}
        self.watcher.seq = 1
        self.server = m.ThreadingHTTPServer(("127.0.0.1", 0), m.Handler)
        self.server.watcher = self.watcher
        self.server.agents = m.AgentRegistry(
            Path(self.tmp.name) / "agents.json", Path(self.tmp.name) / "commands.jsonl"
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.origin = "http://127.0.0.1:" + str(self.server.server_port)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def test_static_assets_served(self):
        for path, marker in [("/", b"Keystone Range Monitor"), ("/app.js", b"EventSource"), ("/style.css", b"--bg")]:
            with urllib.request.urlopen(self.origin + path, timeout=3) as response:
                self.assertEqual(response.status, 200)
                self.assertIn(marker, response.read())

    def test_sse_pushes_two_samples_without_polling(self):
        with urllib.request.urlopen(self.origin + "/api/events", timeout=3) as response:
            self.assertEqual(response.headers["Content-Type"], "text/event-stream")
            self.assertEqual(response.readline().decode().strip(), "event: telemetry")
            self.assertEqual(json.loads(response.readline().decode()[6:])["seq"], 1)
            response.readline()
            with self.watcher.condition:
                self.watcher.seq = 2
                self.watcher.sample = {"seq": 2, "mode": "demo"}
                self.watcher.condition.notify_all()
            self.assertEqual(response.readline().decode().strip(), "event: telemetry")
            self.assertEqual(json.loads(response.readline().decode()[6:])["seq"], 2)

    def test_control_endpoint_reports_409_when_not_installed(self):
        req = urllib.request.Request(self.origin + "/api/run/start", method="POST",
                                      data=b"{}", headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=3)
            self.fail("expected HTTPError")
        except urllib.error.HTTPError as err:
            self.assertEqual(err.code, 409)

    def post_json(self, path, payload):
        request = urllib.request.Request(
            self.origin + path,
            method="POST",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=3) as response:
            return response.status, json.loads(response.read())

    def test_agent_registration_listing_and_command_queue(self):
        status, registered = self.post_json("/api/agents/register", {
            "id": "planner-1", "name": "Planner", "status": "idle", "kind": "codex"
        })
        self.assertEqual(status, 200)
        self.assertEqual(registered["agent"]["name"], "Planner")

        with urllib.request.urlopen(self.origin + "/api/agents", timeout=3) as response:
            listing = json.loads(response.read())
        self.assertEqual([agent["id"] for agent in listing["agents"]], ["planner-1"])

        status, queued = self.post_json("/api/agents/planner-1/commands", {
            "action": "assign", "task": "Inspect the failing build"
        })
        self.assertEqual(status, 202)
        self.assertEqual(queued["command"]["agent_id"], "planner-1")
        command = json.loads((Path(self.tmp.name) / "commands.jsonl").read_text().strip())
        self.assertEqual(command["task"], "Inspect the failing build")

    def test_agent_command_rejects_unknown_agent(self):
        request = urllib.request.Request(
            self.origin + "/api/agents/missing/commands",
            method="POST",
            data=b'{"action":"pause"}',
            headers={"Content-Type": "application/json"},
        )
        with self.assertRaises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(request, timeout=3)
        self.assertEqual(raised.exception.code, 404)


class StickTopologyTests(unittest.TestCase):
    """The board follows whichever range stick is physically inserted."""

    GLASS_CANARY = {
        "range": "glass-canary",
        "title": "Glass Canary Labs - malware scripting & evasion range",
        "zones": [{"id": "operators", "label": "Red Team Platform"},
                  {"id": "staging", "label": "GC Internal Staging · VLAN 50"}],
        "nodes": [
            {"id": "operator", "label": "Red Team Control Station", "type": "operator",
             "zone": "operators", "address": "192.168.0.10", "position": [8.0, 50.0]},
            {"id": "gc-tripwire", "label": "Tripwire Inventory", "type": "web",
             "zone": "staging", "address": "10.50.0.30", "position": [40.0, 30.0]},
            {"id": "gc-build", "label": "Build Box", "type": "workstation",
             "zone": "staging", "address": "10.50.0.33", "position": [70.0, 40.0]},
        ],
        "edges": [{"src": "operator", "dst": "gc-tripwire", "kind": "network"}],
    }

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _stick(self, range_id, topology, device="/dev/sda1"):
        """Lay out a fake stick and return a /proc/mounts line pointing at it."""
        pack = self.root / "keystone-ranges" / range_id
        pack.mkdir(parents=True, exist_ok=True)
        (pack / "topology.json").write_text(json.dumps(topology), encoding="utf-8")
        return f"{device} {self.root} vfat rw,relatime 0 0\n"

    def test_stick_topology_is_read_from_the_inserted_stick(self):
        topo, note = m.load_stick_topology(self._stick("glass-canary", self.GLASS_CANARY))
        self.assertIsNotNone(topo)
        self.assertEqual(note, "stick glass-canary")
        self.assertEqual(topo["range"], "glass-canary")
        self.assertEqual({n["id"] for n in topo["nodes"]},
                         {"operator", "gc-tripwire", "gc-build"})

    def test_swapping_the_stick_swaps_the_nodes(self):
        mounts = self._stick("blind-forge", {
            "range": "blind-forge",
            "zones": [{"id": "forge", "label": "Blind Forge · VLAN 61"}],
            "nodes": [{"id": "bf-portal", "zone": "forge", "address": "10.61.0.10",
                       "position": [45.0, 35.0]}],
            "edges": [],
        })
        topo, note = m.load_stick_topology(mounts)
        self.assertEqual(note, "stick blind-forge")
        self.assertEqual([n["id"] for n in topo["nodes"]], ["bf-portal"])
        self.assertEqual(topo["zones"][0]["id"], "forge")

    def test_stick_estate_keeps_its_own_zones(self):
        """10.50.0.x on a stick must NOT be re-zoned into the lab's corp segment."""
        topo, _ = m.load_stick_topology(self._stick("glass-canary", self.GLASS_CANARY))
        self.assertEqual({z["id"] for z in topo["zones"]}, {"operators", "staging"})
        by_id = {n["id"]: n for n in topo["nodes"]}
        self.assertEqual(by_id["gc-tripwire"]["zone"], "staging")
        self.assertEqual(by_id["gc-build"]["zone"], "staging")
        self.assertNotIn("fabric-hex", by_id)

    def test_presentation_layer_leaves_a_foreign_topology_alone(self):
        presented = m.apply_topology_presentation(self.GLASS_CANARY)
        by_id = {n["id"]: n for n in presented["nodes"]}
        self.assertEqual(by_id["gc-tripwire"]["zone"], "staging")
        self.assertEqual({z["id"] for z in presented["zones"]}, {"operators", "staging"})
        self.assertNotIn("fabric-hex", by_id)

    def test_keystone_lab_topology_still_rezones_and_gets_fabric(self):
        """Regression guard: the lab's own snapshots keep their presentation."""
        presented = m.apply_topology_presentation({
            "zones": [{"id": "unknown", "label": "Unassigned"}],
            "nodes": [{"id": "g600", "label": "htw-server (600)", "zone": "unknown",
                       "address": "—", "state": "reachable"}],
            "edges": [],
        })
        by_id = {n["id"]: n for n in presented["nodes"]}
        self.assertEqual(by_id["g600"]["zone"], "corp")
        self.assertEqual(by_id["g600"]["address"], "10.50.0.10")
        self.assertIn("fabric-hex", by_id)
        self.assertEqual({z["id"] for z in presented["zones"]},
                         {"attack", "fabric", "dmz", "corp", "data", "management"})

    def test_two_packs_are_refused_rather_than_guessed(self):
        mounts = self._stick("glass-canary", self.GLASS_CANARY)
        second = self.root / "keystone-ranges" / "cold-chain"
        second.mkdir(parents=True)
        (second / "topology.json").write_text(
            json.dumps({"range": "cold-chain", "nodes": [{"id": "cc-portal"}]}))
        topo, note = m.load_stick_topology(mounts)
        self.assertIsNone(topo)
        self.assertIn("one range per stick", note)
        self.assertIn("glass-canary", note)
        self.assertIn("cold-chain", note)

    def test_unreadable_stick_topology_is_reported_not_crashed(self):
        mounts = self._stick("broken-range", {"nodes": [{"id": "x"}]})
        (self.root / "keystone-ranges" / "broken-range" / "topology.json").write_text("{not json")
        topo, note = m.load_stick_topology(mounts)
        self.assertIsNone(topo)
        self.assertIn("unreadable", note)

    def test_only_removable_devices_are_treated_as_sticks(self):
        topo, note = m.load_stick_topology(f"/dev/nvme0n1p2 {self.root} btrfs rw 0 0\n")
        self.assertIsNone(topo)
        self.assertEqual(note, "")


if __name__ == "__main__":
    unittest.main()
