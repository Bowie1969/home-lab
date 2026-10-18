import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keystone import pcap
from tests.pcap_writer import write_pcap


class TestPcap(unittest.TestCase):
    def test_roundtrip_tcp_and_udp(self):
        tmp = tempfile.mkdtemp(prefix="keystone-pcap-")
        path = os.path.join(tmp, "t.pcap")
        write_pcap(path, [
            (1.5, "10.80.0.10", "10.80.10.22", 6, 51000, 8080, 0),
            (2.0, "10.80.10.22", "10.80.0.10", 6, 8080, 51000, 120),
            (3.0, "10.80.0.10", "8.8.8.8", 17, 51001, 53, 0),
        ])
        pkts = pcap.read_all(path)
        self.assertEqual(len(pkts), 3)
        self.assertEqual(pkts[0].src_ip, "10.80.0.10")
        self.assertEqual(pkts[0].dst_ip, "10.80.10.22")
        self.assertEqual(pkts[0].dst_port, 8080)
        self.assertEqual(pkts[0].proto_name, "tcp")
        self.assertEqual(pkts[2].proto_name, "udp")
        self.assertEqual(pkts[2].dst_port, 53)

    def test_conversations(self):
        tmp = tempfile.mkdtemp(prefix="keystone-pcap-")
        path = os.path.join(tmp, "c.pcap")
        write_pcap(path, [
            (1.0, "10.80.0.10", "10.80.10.22", 6, 1, 80, 0),
            (1.1, "10.80.0.10", "10.80.10.22", 6, 2, 443, 10),
        ])
        conv = pcap.conversations(pcap.read_all(path))
        key = ("10.80.0.10", "10.80.10.22")
        self.assertEqual(conv[key]["packets"], 2)
        self.assertEqual(conv[key]["dst_ports"], {80, 443})

    def test_rejects_non_pcap(self):
        tmp = tempfile.mkdtemp(prefix="keystone-pcap-")
        path = os.path.join(tmp, "bad.pcap")
        with open(path, "wb") as fh:
            fh.write(b"not a pcap file at all........")
        with self.assertRaises(pcap.PcapError):
            pcap.read_all(path)


if __name__ == "__main__":
    unittest.main()
