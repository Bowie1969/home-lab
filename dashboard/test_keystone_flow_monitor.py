"""Unit tests for keystone_flow_monitor.py.

Feeds synthetic tcpdump lines through the real parser/classifier and asserts the
normal / recon / attack / tunnel classes, plus the configuration defaults the
brain (Proxmox) monitor relies on and the manifest+topology VULN_PORTS derivation
used by the podman launcher.
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

spec = importlib.util.spec_from_file_location(
    "kfm", Path(__file__).parent / "scripts" / "keystone_flow_monitor.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

SSH_DST = "10.99.50.31"      # crown01 :22 (not a vuln port on this host)
VULN_DST = "10.99.50.11"     # edge01 :8080 SQLi


def feed(lines):
    """Parse synthetic tcpdump lines through the real regex and ingest them,
    mirroring what _reader does with live output."""
    for line in lines:
        mm = m.LINE_RE.match(line.strip())
        assert mm, f"line did not parse: {line}"
        g = mm.groupdict()
        proto = "udp" if "UDP" in line else "tcp"
        m._ingest(g["src"], g["dst"], int(g["dport"]), proto,
                  g.get("flags") or "", int(g["length"]), float(g["ts"]))


def classify(src, dst, dport, proto="tcp", fanout=1):
    key = (src, dst, dport, proto)
    f = m._flows[key]
    return m._classify(key, f, f["last"] + 0.001, fanout)


class FlowClassTests(unittest.TestCase):
    def setUp(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            m._load_config([])          # Proxmox defaults, independent of test order
        m._flows.clear()

    def test_normal_established_service_session(self):
        feed([
            "100.0 IP 10.99.50.60.54321 > 10.99.50.11.8080: Flags [S], seq 1, length 0",
            "100.1 IP 10.99.50.11.8080 > 10.99.50.60.54321: Flags [S.], seq 1, ack 2, length 0",
            "100.2 IP 10.99.50.60.54321 > 10.99.50.11.8080: Flags [P.], seq 1:41, ack 1, length 40",
            "100.3 IP 10.99.50.60.54321 > 10.99.50.11.8080: Flags [P.], seq 41:81, ack 1, length 40",
        ])
        self.assertEqual(classify("10.99.50.60", VULN_DST, 8080), "normal")

    def test_recon_syn_probe_without_session(self):
        feed([
            "100.0 IP 10.99.50.60.54321 > 10.99.50.11.8080: Flags [S], seq 1, length 0",
        ])
        self.assertEqual(classify("10.99.50.60", VULN_DST, 8080), "recon")

    def test_recon_refused_connection_rst(self):
        # SYN goes in the client->server flow; the RST comes back in the reverse
        # flow (server->client, dport = client ephemeral port) — as on a real wire.
        feed([
            "100.0 IP 10.99.50.60.54321 > 10.99.50.11.8080: Flags [S], seq 1, length 0",
            "100.1 IP 10.99.50.11.8080 > 10.99.50.60.54321: Flags [R.], seq 0, length 0",
        ])
        self.assertEqual(classify("10.99.50.60", VULN_DST, 8080), "recon")
        self.assertEqual(classify("10.99.50.11", "10.99.50.60", 54321), "recon")

    def test_recon_host_port_fanout(self):
        targets = [("10.99.50.11", 8080), ("10.99.50.21", 9001), ("10.99.50.41", 80),
                   ("10.99.50.51", 3306), ("10.99.50.81", 80), ("10.99.50.91", 25)]
        lines = []
        for i, (dst, dport) in enumerate(targets):
            lines.append(
                f"100.{i} IP 10.99.50.60.4{i}000 > {dst}.{dport}: Flags [S], seq 1, length 0")
        feed(lines)
        # 6 distinct dst:port from one src -> fanout threshold trips
        self.assertEqual(
            classify("10.99.50.60", targets[0][0], targets[0][1], fanout=6), "recon")

    def test_attack_payload_on_vulnerable_port(self):
        feed([
            "100.0 IP 10.99.50.60.54321 > 10.99.50.11.8080: Flags [S], seq 1, length 0",
            "100.1 IP 10.99.50.11.8080 > 10.99.50.60.54321: Flags [S.], seq 1, ack 2, length 0",
            "100.2 IP 10.99.50.60.54321 > 10.99.50.11.8080: Flags [P.], seq 1:501, ack 1, length 500",
            "100.3 IP 10.99.50.60.54321 > 10.99.50.11.8080: Flags [P.], seq 501:701, ack 1, length 200",
        ])
        self.assertEqual(classify("10.99.50.60", VULN_DST, 8080), "attack")

    def test_tunnel_ssh_session_carrying_data(self):
        feed([
            "100.0 IP 10.99.50.60.54321 > 10.99.50.31.22: Flags [S], seq 1, length 0",
            "100.1 IP 10.99.50.31.22 > 10.99.50.60.54321: Flags [S.], seq 1, ack 2, length 0",
            "100.2 IP 10.99.50.60.54321 > 10.99.50.31.22: Flags [P.], seq 1:53, ack 1, length 52",
            "100.3 IP 10.99.50.60.54321 > 10.99.50.31.22: Flags [P.], seq 53:101, ack 1, length 48",
        ])
        self.assertEqual(classify("10.99.50.60", SSH_DST, 22), "tunnel")

    def test_attack_ssh_bruteforce_reconnects(self):
        # 5 short auth attempts, each closed by the client (FIN) so the next SYN
        # counts as a fresh reconnect — the brute-force signature.
        lines = []
        for i in range(5):
            t0 = 100 + i
            lines.append(f"{t0}.0 IP 10.99.50.60.54321 > 10.99.50.31.22: Flags [S], seq 1, length 0")
            lines.append(f"{t0}.1 IP 10.99.50.60.54321 > 10.99.50.31.22: Flags [P.], seq 1:41, length 40")
            lines.append(f"{t0}.2 IP 10.99.50.60.54321 > 10.99.50.31.22: Flags [F.], seq 41, length 0")
        feed(lines)
        self.assertEqual(classify("10.99.50.60", SSH_DST, 22), "attack")


class ConfigTests(unittest.TestCase):
    def test_proxmox_defaults_unchanged(self):
        """The brain monitor runs with no args/env; defaults must stay Proxmox."""
        with mock.patch.dict("os.environ", {}, clear=True):
            m._load_config([])
        self.assertEqual(m.BRIDGES, ["vmbr9", "vmbr50"])
        self.assertEqual(m.SUBNETS, ("10.99.50.", "10.50.0."))
        self.assertEqual(m.OUT_PATH, "/run/keystone-flows.json")
        self.assertEqual(m.VULN_PORTS["10.99.50.11"], {8080})
        self.assertEqual(m.BPF, "ip and (net 10.99.50.0/24 or net 10.50.0.0/24)")

    def test_env_overrides(self):
        env = {"KEYSTONE_BRIDGES": "ks-dmz,ks-attacker",
               "KEYSTONE_SUBNETS": "10.80.10.,10.80.0.",
               "KEYSTONE_FLOWS_PATH": "/run/user/1000/k.json",
               "KEYSTONE_VULN_PORTS": '{"10.80.10.26": [8081]}',
               "KEYSTONE_HOST_IPS": "10.80.10.1,10.80.0.1",
               "KEYSTONE_SERVICE_PORTS": "22,8081"}
        with mock.patch.dict("os.environ", env, clear=True):
            m._load_config([])
        self.assertEqual(m.BRIDGES, ["ks-dmz", "ks-attacker"])
        self.assertEqual(m.SUBNETS, ("10.80.10.", "10.80.0."))
        self.assertEqual(m.OUT_PATH, "/run/user/1000/k.json")
        self.assertEqual(m.VULN_PORTS, {"10.80.10.26": {8081}})
        self.assertEqual(m.HOST_BRIDGE_IPS, {"10.80.10.1", "10.80.0.1"})
        self.assertEqual(m.SERVICE_PORTS, {22, 8081})

    def test_manifest_ports_parser(self):
        text = "id: portal-sqli\nports:\n  - 8081\n  - 22  # admin\nprereqs: []\n"
        self.assertEqual(m._ports_from_manifest(text), [8081, 22])
        self.assertEqual(m._ports_from_manifest("id: cron-root\nports: []\n"), [])

    def test_vuln_ports_from_range_synthetic(self):
        def write_mod(root, name, ports):
            d = root / "modules" / name
            d.mkdir(parents=True, exist_ok=True)
            body = "".join(f"  - {p}\n" for p in ports)
            (d / "manifest.yaml").write_text(f"id: {name}\nports:\n{body}")

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "modules").mkdir()
            (root / "build").mkdir()
            (root / "build" / "topology.json").write_text(json.dumps({
                "nodes": [
                    {"id": "portal-sqli", "ip": "10.80.10.26"},
                    {"id": "edge-upload", "ip": "10.80.10.22"},
                    {"id": "cron-root", "ip": "10.80.10.21"},
                    {"id": "ks-ws01", "ip": "10.80.20.25"},   # corp zone, not local
                ]}))
            write_mod(root, "portal-sqli", [8081])
            write_mod(root, "edge-upload", [8080])
            write_mod(root, "cron-root", [])
            write_mod(root, "ks-ws01", [8090])
            vp = m._vuln_ports_from_range(td, ("10.80.10.", "10.80.0."))
        self.assertEqual(vp, {"10.80.10.26": {8081}, "10.80.10.22": {8080}})


class RealRangeTests(unittest.TestCase):
    def setUp(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            m._load_config([])
        m._flows.clear()

    def test_real_keystone_range_derivation(self):
        """Against the real checkout: DMZ services land on their 10.80.10.x IPs."""
        real = Path.home() / "Projects" / "keystone-range"
        if not (real / "build" / "topology.json").is_file():
            self.skipTest("keystone-range checkout not present")
        vp = m._vuln_ports_from_range(str(real), ("10.80.10.", "10.80.0."))
        self.assertEqual(vp.get("10.80.10.28"), {8081})   # portal-sqli
        self.assertEqual(vp.get("10.80.10.23"), {8080})   # edge-upload
        self.assertEqual(vp.get("10.80.10.33"), {8085})   # token-jwt
        self.assertEqual(vp.get("10.80.10.20"), {6379})   # cache-open
        self.assertEqual(vp.get("10.80.10.31"), {445})    # share-anon
        self.assertEqual(vp.get("10.80.10.32"), {22})     # ssh-weak
        self.assertNotIn("10.80.10.21", vp)               # cron-root: no service
        self.assertNotIn("10.80.10.30", vp)               # runner-escape: no service
        self.assertNotIn("10.80.20.25", vp)               # corp zone filtered out


if __name__ == "__main__":
    unittest.main()
