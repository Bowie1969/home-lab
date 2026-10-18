"""Minimal libpcap (classic .pcap) reader built on ``struct`` — no scapy.

Parses the classic pcap format directly: a 24-byte global header, then a stream
of 16-byte record headers each followed by a captured frame. Supported link type
is Ethernet (LINKTYPE_ETHERNET = 1) and raw IPv4 (LINKTYPE_RAW = 101); the parser
extracts the IPv4 5-tuple and byte counts, which is all the scorer needs to
corroborate recon / lateral movement / exfiltration / scope from the wire.

The goal is corroboration, not full dissection: we skip IPv6, VLAN tags, and
anything exotic rather than pretend to understand them.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterator, List, Optional

PCAP_MAGIC_LE = 0xA1B2C3D4          # microsecond, little-endian
PCAP_MAGIC_BE = 0xD4C3B2A1          # microsecond, big-endian
PCAP_MAGIC_NS_LE = 0xA1B23C4D       # nanosecond, little-endian
PCAP_MAGIC_NS_BE = 0x4D3CB2A1       # nanosecond, big-endian

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_RAW_ALT = 12               # some tools use 12 for raw IP

ETHERTYPE_IPV4 = 0x0800
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMP = 1


@dataclass
class Packet:
    ts: float
    src_ip: str
    dst_ip: str
    proto: int
    src_port: Optional[int]
    dst_port: Optional[int]
    length: int        # IP payload total length (bytes on wire for the IP datagram)

    @property
    def proto_name(self) -> str:
        return {PROTO_TCP: "tcp", PROTO_UDP: "udp", PROTO_ICMP: "icmp"}.get(
            self.proto, str(self.proto)
        )


class PcapError(ValueError):
    pass


def _ip_to_str(raw: bytes) -> str:
    return ".".join(str(b) for b in raw)


def _parse_ipv4(data: bytes, ts: float) -> Optional[Packet]:
    if len(data) < 20:
        return None
    version_ihl = data[0]
    if (version_ihl >> 4) != 4:
        return None
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return None
    total_length = struct.unpack("!H", data[2:4])[0]
    proto = data[9]
    src_ip = _ip_to_str(data[12:16])
    dst_ip = _ip_to_str(data[16:20])
    src_port = dst_port = None
    payload = data[ihl:]
    if proto in (PROTO_TCP, PROTO_UDP) and len(payload) >= 4:
        src_port, dst_port = struct.unpack("!HH", payload[:4])
    return Packet(
        ts=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        proto=proto,
        src_port=src_port,
        dst_port=dst_port,
        length=total_length or len(data),
    )


def iter_packets(path: str) -> Iterator[Packet]:
    """Yield IPv4 packets from a classic pcap file."""
    with open(path, "rb") as fh:
        blob = fh.read()
    yield from iter_packets_bytes(blob)


def iter_packets_bytes(blob: bytes) -> Iterator[Packet]:
    if len(blob) < 24:
        raise PcapError("file too short for a pcap global header")
    magic = struct.unpack("<I", blob[:4])[0]
    if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE):
        endian = "<"
        nanos = magic == PCAP_MAGIC_NS_LE
    elif magic in (PCAP_MAGIC_BE, PCAP_MAGIC_NS_BE):
        endian = ">"
        nanos = magic == PCAP_MAGIC_NS_BE
    else:
        raise PcapError(f"not a pcap file (magic={magic:#010x})")

    # Global header: magic, ver_major, ver_minor, thiszone, sigfigs, snaplen, network
    (_magic, _vmaj, _vmin, _tz, _sig, _snap, network) = struct.unpack(
        endian + "IHHiIII", blob[:24]
    )
    off = 24
    rec_hdr = struct.Struct(endian + "IIII")
    while off + 16 <= len(blob):
        ts_sec, ts_frac, incl_len, _orig_len = rec_hdr.unpack(blob[off:off + 16])
        off += 16
        if off + incl_len > len(blob):
            break  # truncated final record
        frame = blob[off:off + incl_len]
        off += incl_len
        ts = ts_sec + (ts_frac / 1e9 if nanos else ts_frac / 1e6)

        if network == LINKTYPE_ETHERNET:
            if len(frame) < 14:
                continue
            ethertype = struct.unpack("!H", frame[12:14])[0]
            if ethertype != ETHERTYPE_IPV4:
                continue
            pkt = _parse_ipv4(frame[14:], ts)
        elif network in (LINKTYPE_RAW, LINKTYPE_RAW_ALT):
            pkt = _parse_ipv4(frame, ts)
        else:
            continue
        if pkt is not None:
            yield pkt


def read_all(path: str) -> List[Packet]:
    return list(iter_packets(path))


# -- Convenience summaries used by the scorer ------------------------------------

def conversations(packets: List[Packet]):
    """Return {(src_ip, dst_ip): {"packets","bytes","dst_ports"}}."""
    out = {}
    for p in packets:
        key = (p.src_ip, p.dst_ip)
        slot = out.setdefault(key, {"packets": 0, "bytes": 0, "dst_ports": set()})
        slot["packets"] += 1
        slot["bytes"] += p.length
        if p.dst_port is not None:
            slot["dst_ports"].add(p.dst_port)
    return out
