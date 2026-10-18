"""Write classic .pcap files with struct — used to build synthetic evidence.

Mirrors the format keystone.pcap reads, so the parser is exercised on bytes it
did not itself produce.
"""
from __future__ import annotations

import struct
from typing import List, Tuple

PCAP_MAGIC_LE = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1


def _ipv4(src: str, dst: str, proto: int, sport: int, dport: int, payload_len: int) -> bytes:
    def _a(ip):
        return bytes(int(x) for x in ip.split("."))
    l4 = b""
    if proto in (6, 17):
        if proto == 6:  # minimal TCP header (20 bytes)
            l4 = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, (5 << 4), 0x18, 1024, 0, 0)
        else:           # UDP header (8 bytes)
            l4 = struct.pack("!HHHH", sport, dport, 8 + payload_len, 0)
    body = l4 + (b"\x00" * payload_len)
    total = 20 + len(body)
    ver_ihl = 0x45
    ip_hdr = struct.pack("!BBHHHBBH4s4s", ver_ihl, 0, total, 0, 0, 64, proto, 0,
                         _a(src), _a(dst))
    return ip_hdr + body


def _frame(pkt_ip: bytes) -> bytes:
    eth = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + struct.pack("!H", 0x0800)
    return eth + pkt_ip


def write_pcap(path: str, packets: List[Tuple]) -> None:
    """packets: list of (ts, src, dst, proto, sport, dport, payload_len)."""
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", PCAP_MAGIC_LE, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))
        for ts, src, dst, proto, sport, dport, plen in packets:
            frame = _frame(_ipv4(src, dst, proto, sport, dport, plen))
            sec = int(ts)
            usec = int((ts - sec) * 1e6)
            fh.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            fh.write(frame)
