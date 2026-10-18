#!/usr/bin/env python3
"""Deliberately unauthenticated cache for the cache-open module.

Vulnerability (by design): a Redis-compatible key/value service bound to
0.0.0.0 with NO requirepass and no bind hardening (technique_class
unauth-service). Anyone who can reach port 6379 issues commands; ``GET flag``
returns the contents of /data/flag.txt, and /data doubles as the persistence
directory, so any key that matches a file under /data is readable. stdlib only.
"""
import os
import socketserver

DATA_DIR = "/data"
store = {}


def bulk(value):
    if value is None:
        return b"$-1\r\n"
    if isinstance(value, str):
        value = value.encode()
    return b"$" + str(len(value)).encode() + b"\r\n" + value + b"\r\n"


class Handler(socketserver.StreamRequestHandler):
    def _send(self, data):
        self.wfile.write(data)
        self.wfile.flush()

    def _read_command(self):
        line = self.rfile.readline()
        if not line:
            return None
        if line.startswith(b"*"):
            try:
                count = int(line[1:].strip())
            except ValueError:
                return []
            parts = []
            for _ in range(count):
                header = self.rfile.readline()
                if not header.startswith(b"$"):
                    return []
                length = int(header[1:].strip())
                data = self.rfile.read(length)
                self.rfile.read(2)  # trailing CRLF
                parts.append(data)
            return parts
        return line.strip().split()

    def handle(self):
        while True:
            parts = self._read_command()
            if parts is None:
                return
            if not parts:
                self._send(b"-ERR unknown command\r\n")
                continue
            decoded = [p.decode("utf-8", "replace") for p in parts]
            cmd = decoded[0].upper()
            args = decoded[1:]
            if cmd == "QUIT":
                self._send(b"+OK\r\n")
                return
            elif cmd == "PING":
                self._send(bulk(args[0]) if args else b"+PONG\r\n")
            elif cmd == "ECHO" and args:
                self._send(bulk(args[0]))
            elif cmd == "SET" and len(args) >= 2:
                store[args[0]] = args[1]
                self._send(b"+OK\r\n")
            elif cmd == "GET" and args:
                key = args[0]
                if key in store:
                    self._send(bulk(store[key]))
                else:
                    # Keys fall through to the persistence dir: unauthenticated
                    # callers can read any file the daemon can read, including
                    # the flag (VULN by design — this is the intended read).
                    safe = key.replace("..", "").lstrip("/") or "_"
                    path = os.path.join(DATA_DIR, safe)
                    if os.path.isfile(path):
                        with open(path, "rb") as fh:
                            self._send(bulk(fh.read().decode("utf-8", "replace")))
                    else:
                        self._send(bulk(None))
            elif cmd == "DEL" and args:
                removed = 0
                for key in args:
                    removed += store.pop(key, None) is not None
                self._send(b":%d\r\n" % removed)
            elif cmd == "EXISTS" and args:
                present = sum(1 for k in args if k in store)
                self._send(b":%d\r\n" % present)
            elif cmd == "KEYS":
                names = sorted(store)
                out = b"*%d\r\n" % len(names)
                for name in names:
                    out += bulk(name)
                self._send(out)
            elif cmd == "CONFIG" and len(args) >= 2:
                if args[0].upper() == "GET":
                    values = {"dir": DATA_DIR, "requirepass": None,
                              "dbfilename": "dump.rdb"}
                    out = []
                    for name in values:
                        if args[1] == "*" or args[1] == name:
                            out += [name, values[name]]
                    self._send(b"*%d\r\n" % len(out) + b"".join(bulk(v) for v in out))
                else:
                    # CONFIG SET accepted silently — classic redis privesc path
                    # (dir/dbfilename) has no effect here, +OK keeps clients happy.
                    self._send(b"+OK\r\n")
            elif cmd == "INFO":
                self._send(bulk("# Server\r\nredis_version:7.0.15\r\n"))
            else:
                self._send(b"-ERR unknown command '%s'\r\n" % cmd.encode())


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with Server(("0.0.0.0", 6379), Handler) as srv:
        srv.serve_forever()
