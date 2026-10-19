#!/usr/bin/env python3
"""LotL persist: plant a persistence marker on an exec node through the whitelist.

Usage: 0004-lotl-persist.py --target 127.0.0.1 --port PORT --token MARKER
"""
import argparse
import socket
import sys


def exec_line(host: str, port: int, line: str, timeout: float = 10.0) -> str:
    """Send one command line to the exec service and return its reply."""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall((line + "\n").encode())
        reply = sock.makefile("r").readline().strip()
        return reply


def main(argv=None):
    parser = argparse.ArgumentParser(description="glass-canary LotL persist")
    parser.add_argument("--target", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--token", required=True)
    args = parser.parse_args(argv)
    try:
        ident = exec_line(args.target, args.port, "ID")
        reply = exec_line(args.target, args.port, f"PERSIST {args.token}")
    except OSError as exc:
        print(f"[persist] failed: {exc}", file=sys.stderr)
        return 1
    if not reply.startswith("persisted"):
        print(f"[persist] rejected by {ident}: {reply}", file=sys.stderr)
        return 2
    print(f"[persist] marker planted on {ident}: {reply}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
