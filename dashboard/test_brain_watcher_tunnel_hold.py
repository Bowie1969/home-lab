#!/usr/bin/env python3
"""Tunnel-hold persistence for brain_watcher.apply_flow_overrides.

Proves the passive flow path keeps an SSH tunnel edge lit after the session goes
quiet (the "stay" fix), lets a stronger class override it live, and expires the
hold once the window passes.
"""
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent / "scripts"))
import brain_watcher as bw  # noqa: E402


def _nodes():
    # Two range actors with routable addresses + an unrelated third node.
    return [
        {"id": "g960", "address": "10.99.50.60"},
        {"id": "g914", "address": "10.99.50.31"},
        {"id": "g911", "address": "10.99.50.11"},
    ]


def _make_add_edge(edges):
    seen = set()

    def add_edge(src, dst, kind, state="unknown"):
        key = (src, dst, kind)
        if src == dst or key in seen:
            return
        seen.add(key)
        edges.append({"src": src, "dst": dst, "kind": kind, "state": state})

    return add_edge


def _apply(edges, flows):
    nodes = _nodes()
    bw.apply_flow_overrides(nodes, edges, _make_add_edge(edges), flows)
    return nodes


def _kind(edges, a, b):
    e = next((e for e in edges if {e["src"], e["dst"]} == {a, b}), None)
    return e["kind"] if e else None


class TunnelHoldTests(unittest.TestCase):
    def setUp(self):
        bw._TUNNEL_HOLD.clear()
        self.addCleanup(bw._TUNNEL_HOLD.clear)
        # These cases describe behaviour DURING a run, when aggressive
        # colouring is licensed.
        patcher = mock.patch.object(bw, "engagement_active", return_value=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_tunnel_shows_then_stays_when_idle(self):
        edges = []
        # Poll 1: an established SSH tunnel g960 -> g914 carries data.
        _apply(edges, [{"src": "10.99.50.60", "dst": "10.99.50.31", "class": "tunnel"}])
        self.assertEqual(_kind(edges, "g960", "g914"), "tunnel")
        # Poll 2: no flows at all (tunnel idle). Edge must STAY tunnel.
        _apply(edges, [])
        self.assertEqual(_kind(edges, "g960", "g914"), "tunnel",
                         "idle tunnel dropped on the next poll")

    def test_live_attack_overrides_held_tunnel(self):
        edges = []
        _apply(edges, [{"src": "10.99.50.60", "dst": "10.99.50.31", "class": "tunnel"}])
        # Same pair now shows an attack-class flow -> attack wins over the hold.
        _apply(edges, [{"src": "10.99.50.60", "dst": "10.99.50.31", "class": "attack"}])
        self.assertEqual(_kind(edges, "g960", "g914"), "attack")

    def test_hold_expires_after_window(self):
        edges = []
        _apply(edges, [{"src": "10.99.50.60", "dst": "10.99.50.31", "class": "tunnel"}])
        # Age the hold past the window, then an idle poll should drop it.
        pair = frozenset(("g960", "g914"))
        bw._TUNNEL_HOLD[pair] = bw.time.time() - (bw.TUNNEL_HOLD_SECS + 1)
        _apply(edges, [])
        self.assertNotIn(pair, bw._TUNNEL_HOLD)
        # With the hold gone and no flow, the edge is no longer re-asserted as tunnel.
        edges2 = []
        _apply(edges2, [])
        self.assertIsNone(_kind(edges2, "g960", "g914"))

    def test_operator_nodes_start_at_distinct_positions(self):
        topology = bw.build_topology({})
        positions = {
            node["id"]: node["position"]
            for node in topology["nodes"]
            if node["id"] in {bw.PARROT_OPERATOR_ID, bw.PI_DROP_ID}
        }
        self.assertNotEqual(positions[bw.PARROT_OPERATOR_ID], positions[bw.PI_DROP_ID])
        self.assertGreaterEqual(
            abs(positions[bw.PARROT_OPERATOR_ID][1] - positions[bw.PI_DROP_ID][1]),
            20,
        )

    def test_portable_node_publishes_current_management_and_wired_paths(self):
        with mock.patch.object(bw, "load_range_dmz", return_value=([], [])), \
             mock.patch.object(bw, "_pi_drop_live", return_value=True):
            topology = bw.build_topology({})
        node = next(node for node in topology["nodes"] if node["id"] == bw.PI_DROP_ID)
        self.assertEqual(node["state"], "reachable")
        self.assertIn("10.10.66.146", node["address"])
        self.assertIn("10.99.50.120", node["address"])
        self.assertIn("switch port 7", node["address"])

    def test_topology_carries_current_guest_and_pod_telemetry(self):
        guests = {
            "910": {
                "kind": "ct", "hostname": "range-gw", "status": "running",
                "lock": "", "nets": [{"bridge": "vmbr9", "ip": "10.99.50.254"}],
            },
        }
        pods = [{"id": "edge-upload", "zone": "dmz", "ip": "10.80.10.23"}]
        with mock.patch.object(bw, "load_range_dmz", return_value=(pods, [])), \
             mock.patch.object(bw, "_pi_drop_live", return_value=True):
            topology = bw.build_topology(guests, pod_states={"edge-upload": "running"})
        by_id = {node["id"]: node for node in topology["nodes"]}
        self.assertEqual(by_id["g910"]["state"], "reachable")
        self.assertEqual(by_id["g910"]["telemetry_source"], "Proxmox pct")
        self.assertEqual(by_id["pod-edge-upload"]["state"], "reachable")
        self.assertEqual(by_id["pod-edge-upload"]["telemetry_source"], "Podman")

    def test_observed_static_windows_address_is_published_without_guest_agent(self):
        guests = {
            "600": {
                "kind": "vm", "hostname": "htw-server", "status": "running",
                "lock": "", "nets": [{"bridge": "vmbr50", "ip": None}],
                "observed_ip": "10.50.0.10", "observed_port": "5985",
            },
        }
        with mock.patch.object(bw, "load_range_dmz", return_value=([], [])), \
             mock.patch.object(bw, "_pi_drop_live", return_value=True):
            topology = bw.build_topology(guests)
        node = next(node for node in topology["nodes"] if node["id"] == "g600")
        self.assertEqual(node["address"], "10.50.0.10")
        self.assertEqual(node["state"], "reachable")
        self.assertIn("5985", node["telemetry"]["network"])

    def test_arp_verified_windows_address_is_published_without_claiming_winrm(self):
        guests = {
            "601": {
                "kind": "vm", "hostname": "htw-owner", "status": "running",
                "lock": "", "nets": [{"bridge": "vmbr50", "ip": None}],
                "observed_ip": "10.50.0.11", "observed_port": "arp",
            },
        }
        with mock.patch.object(bw, "load_range_dmz", return_value=([], [])), \
             mock.patch.object(bw, "_pi_drop_live", return_value=True):
            topology = bw.build_topology(guests)
        node = next(node for node in topology["nodes"] if node["id"] == "g601")
        self.assertEqual(node["address"], "10.50.0.11")
        self.assertEqual(node["state"], "reachable")
        self.assertEqual(node["telemetry"]["network"], "ARP/MAC verified from Proxmox")

    def test_presentation_segments_and_names_do_not_change_connectivity(self):
        guests = {
            vmid: {
                "kind": "ct", "hostname": hostname, "status": "running",
                "lock": "", "nets": [{"bridge": "vmbr9", "ip": ip}],
            }
            for vmid, hostname, ip in (
                ("910", "range-gw", "10.99.50.254"),
                ("960", "drop01", "10.99.50.60"),
                ("940", "emp01", "10.99.50.71"),
                ("920", "files01", "10.99.50.41"),
                ("930", "dc01", "10.99.50.30"),
            )
        }
        with mock.patch.object(bw, "load_range_dmz", return_value=([], [])), \
             mock.patch.object(bw, "_pi_drop_live", return_value=True):
            topology = bw.build_topology(guests)
        by_id = {node["id"]: node for node in topology["nodes"]}
        self.assertEqual(by_id["g960"]["label"], "Guest Network Kiosk")
        self.assertEqual(by_id["g960"]["zone"], "guest")
        self.assertEqual(by_id["g940"]["zone"], "users")
        self.assertEqual(by_id["g920"]["zone"], "business")
        self.assertEqual(by_id["g930"]["zone"], "identity")
        self.assertEqual(by_id[bw.PARROT_OPERATOR_ID]["label"], "Red Team Control Station")
        self.assertTrue(by_id[bw.PARROT_OPERATOR_ID]["operator_platform"])
        # Existing reachability remains represented; the redesign is visual,
        # not a new gate in the engagement path.
        self.assertTrue(any({edge["src"], edge["dst"]} == {"g920", "g930"}
                            for edge in topology["edges"]))

    def test_stopped_runtime_is_discovered_not_unknown(self):
        self.assertEqual(bw.status_to_node_state("exited", ""), "discovered")
        self.assertEqual(bw.status_to_node_state("dead", ""), "error")


class IdleGateTests(unittest.TestCase):
    """With no run publishing telemetry, severity colouring is suppressed."""

    def setUp(self):
        bw._TUNNEL_HOLD.clear()
        self.addCleanup(bw._TUNNEL_HOLD.clear)
        patcher = mock.patch.object(bw, "engagement_active", return_value=False)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_attack_flow_does_not_go_red_when_idle(self):
        edges = []
        _apply(edges, [{"src": "10.99.50.60", "dst": "10.99.50.31", "class": "attack"}])
        self.assertEqual(_kind(edges, "g960", "g914"), "network",
                         "idle range coloured an attack edge")

    def test_no_under_attack_ring_when_idle(self):
        nodes = _apply([], [{"src": "10.99.50.60", "dst": "10.99.50.31", "class": "attack"}])
        self.assertFalse(any(n.get("under_attack") for n in nodes))

    def test_idle_tunnel_is_not_held_lit(self):
        edges = []
        _apply(edges, [{"src": "10.99.50.60", "dst": "10.99.50.31", "class": "tunnel"}])
        _apply(edges, [])
        self.assertEqual(_kind(edges, "g960", "g914"), "network")


class FlowEndpointTests(unittest.TestCase):
    """A flow endpoint that is not a node is dropped, not drawn as a node."""

    def setUp(self):
        bw._TUNNEL_HOLD.clear()
        self.addCleanup(bw._TUNNEL_HOLD.clear)
        patcher = mock.patch.object(bw, "engagement_active", return_value=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_unknown_endpoint_gets_no_node_and_no_edge(self):
        edges = []
        nodes = _apply(edges, [{"src": "10.99.50.77", "dst": "10.99.50.60", "class": "recon"}])
        self.assertEqual([n["id"] for n in nodes], ["g960", "g914", "g911"])
        self.assertFalse([n for n in nodes if "Live flow" in str(n.get("label", ""))])
        self.assertEqual(edges, [])

    def test_known_endpoints_still_draw_their_edge(self):
        edges = []
        _apply(edges, [{"src": "10.99.50.60", "dst": "10.99.50.11", "class": "recon"}])
        self.assertEqual(_kind(edges, "g960", "g911"), "recon")


if __name__ == "__main__":
    unittest.main()
