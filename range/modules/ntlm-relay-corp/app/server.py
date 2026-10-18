#!/usr/bin/env python3
"""Noisy workstation — periodically attempts a mistyped UNC path, broadcasting
LLMNR/NBT-NS name queries that a Responder-class listener can poison to
harvest a NetNTLMv2 challenge-response.

Stdlib-only. Simulates the broadcast by sending UDP name-query packets on
port 5355 (LLMNR) and 137 (NBT-NS) at a configurable interval. The
challenge-response exchange is simplified for the lab: a listener that replies
gets a pre-computed NTLMv2 hash for KEYSTONE\\dreyes embedded in the response.
"""
import hashlib
import os
import socket
import struct
import sys
import time

INTERVAL = int(os.environ.get("NOISY_INTERVAL", "45"))
MISTYPED_HOST = os.environ.get("MISTYPED_HOST", "ks-filles01")
DOMAIN = "KEYSTONE"
USER = "dreyes"
NTLM_HASH = "dreyes::KEYSTONE:1122334455667788:A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6:0101000000000000"


def _llmnr_query(name: str) -> bytes:
    """Build a minimal LLMNR name query (RFC 4795)."""
    txid = os.urandom(2)
    flags = b"\x00\x00"
    counts = struct.pack(">HHHH", 1, 0, 0, 0)
    encoded = bytes([len(name)]) + name.encode("ascii") + b"\x00"
    qtype = struct.pack(">HH", 1, 1)  # A, IN
    return txid + flags + counts + encoded + qtype


def _nbtns_query(name: str) -> bytes:
    """Build a minimal NBT-NS name query (RFC 1002)."""
    txid = os.urandom(2)
    flags = b"\x01\x10"
    counts = struct.pack(">HHHH", 1, 0, 0, 0)
    padded = name.upper().ljust(15)[:15] + "\x00"
    encoded = b"\x20"
    for ch in padded.encode("ascii"):
        encoded += bytes([0x41 + (ch >> 4), 0x41 + (ch & 0x0F)])
    encoded += b"\x00"
    qtype = struct.pack(">HH", 0x0020, 1)  # NB, IN
    return txid + flags + counts + encoded + qtype


def _send_broadcast(data: bytes, port: int):
    """Send a UDP broadcast packet."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.settimeout(2)
            s.sendto(data, ("255.255.255.255", port))
            try:
                resp, addr = s.recvfrom(1024)
                print(f"[noisy] got reply from {addr[0]}:{addr[1]} ({len(resp)} bytes)",
                      file=sys.stderr)
                _send_ntlm_response(addr[0])
            except socket.timeout:
                pass
    except OSError as e:
        print(f"[noisy] broadcast error on port {port}: {e}", file=sys.stderr)


def _send_ntlm_response(responder_ip: str):
    """Send a simulated NTLMv2 challenge-response to the responder."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((responder_ip, 445))
            payload = f"NTLMSSP\x00{DOMAIN}\\{USER}\x00{NTLM_HASH}\x00".encode()
            s.sendall(payload)
    except OSError:
        pass


def main():
    print(f"[noisy] workstation stub starting — mistyped host: {MISTYPED_HOST}, "
          f"interval: {INTERVAL}s", file=sys.stderr)
    while True:
        _send_broadcast(_llmnr_query(MISTYPED_HOST), 5355)
        _send_broadcast(_nbtns_query(MISTYPED_HOST), 137)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
