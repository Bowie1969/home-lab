#!/usr/bin/env python3
"""C2 beacon with channel failover: HTTP first (blocked UA), then raw TCP.

Usage: 0005-c2-beacon.py --http-port PORT --tcp-port PORT [--host 127.0.0.1]
"""
import argparse
import socket
import sys
import urllib.error
import urllib.request

NAIVE_UA = "curl/7.68.0"


def http_beacon(host: str, port: int) -> bool:
    """Beacon over the HTTP channel with a naive user agent; True if acked."""
    req = urllib.request.Request(
        f"http://{host}:{port}/beacon", headers={"User-Agent": NAIVE_UA},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except urllib.error.HTTPError as exc:
        print(f"[c2] http beacon blocked: {exc.code}")
        return False
    except urllib.error.URLError as exc:
        print(f"[c2] http channel failed: {exc}", file=sys.stderr)
        return False


def tcp_beacon(host: str, port: int) -> bool:
    """Beacon over the raw TCP channel; True if acked."""
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            sock.sendall(b"BEACON\n")
            reply = sock.makefile("r").readline().strip()
            return reply == "ack"
    except OSError as exc:
        print(f"[c2] tcp channel failed: {exc}", file=sys.stderr)
        return False


def main(argv=None):
    parser = argparse.ArgumentParser(description="glass-canary c2 beacon")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--http-port", required=True, type=int)
    parser.add_argument("--tcp-port", required=True, type=int)
    args = parser.parse_args(argv)
    http_ok = http_beacon(args.host, args.http_port)
    tcp_ok = tcp_beacon(args.host, args.tcp_port)
    if not tcp_ok:
        print("[c2] no channel available", file=sys.stderr)
        return 1
    print(f"[c2] failover complete (http={http_ok}, tcp={tcp_ok})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
