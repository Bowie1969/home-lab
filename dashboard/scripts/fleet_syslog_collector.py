#!/usr/bin/env python3
"""fleet_syslog_collector.py — UDP syslog sink for the lab's OpenWrt routers.

The Asus lab-edge and the hEX labrouter both stream their system log (including
fw4 / nftables drop lines) to Parrot over UDP. This listener parses those
datagrams and distils them into two things the Keystone dashboard already knows
how to consume:

  * a rolling `flows` list — one entry per firewall SRC/DST pair seen in a drop
    line, classified recon (a blocked probe) or attack (a hit on a protected /
    crown segment). brain_watcher.py merges this file exactly like it merges the
    local podman flow file, so these become live, colour-classified edges that
    expire on their own when the traffic stops.
  * a `sources` heartbeat — per router hostname: last-seen, message + drop
    counts, source address. brain_watcher uses it to light the router node even
    when its SSH poll is slow or the box is only reachable on this segment.

It writes `/run/user/<uid>/fleet-syslog.json` atomically; a reader never sees a
half-written file. It opens no outbound connections and copies no payload beyond
the firewall 5-tuple and our own log prefix — no credentials, no user traffic
content. A malformed datagram is dropped silently; the collector never crashes
on bad input (the senders are trusted lab gear, but the parser is defensive).

Env:
  FLEET_SYSLOG_BIND   bind address (default 0.0.0.0 — catches attack-LAN + tailnet)
  FLEET_SYSLOG_PORT   udp port (default 5514 — unprivileged, runs as the user)
  FLEET_SYSLOG_OUT    output path (default /run/user/<uid>/fleet-syslog.json)
  FLEET_FLOW_TTL      seconds a flow stays "live" after last seen (default 20)
"""
from __future__ import annotations

import json
import os
import re
import socket
import time
from collections import OrderedDict
from pathlib import Path

BIND = os.environ.get("FLEET_SYSLOG_BIND", "0.0.0.0")
PORT = int(os.environ.get("FLEET_SYSLOG_PORT", "5514"))
OUT_PATH = Path(os.environ.get(
    "FLEET_SYSLOG_OUT", f"/run/user/{os.getuid()}/fleet-syslog.json"))
FLOW_TTL = float(os.environ.get("FLEET_FLOW_TTL", "20"))
WRITE_MIN_INTERVAL = 1.0  # don't rewrite the file more than once a second

# RFC3164-ish: <PRI>Mon DD HH:MM:SS host tag: msg  (PRI and host are optional on
# some OpenWrt builds, so everything after the optional PRI is treated loosely).
_PRI = re.compile(r"^<(\d{1,3})>")
# A firewall log line carries the netfilter 5-tuple. OpenWrt's log prefix (our
# "drop keystone crown-seal " etc.) sits just before IN=.
_KV = re.compile(r"\b(SRC|DST|PROTO|SPT|DPT)=([^\s]+)")
_PREFIX = re.compile(r"([A-Za-z][\w .:-]*?)\s*IN=")
# Host token: the word before the program tag in a standard syslog line.
_HOST = re.compile(r"^(?:<\d{1,3}>)?(?:\w{3}\s+\d+\s+[\d:]+\s+)?([A-Za-z0-9._-]+)\s")

# Prefix words that mean "this was aimed at something it must never reach" ->
# attack; anything else that got dropped is a blocked probe -> recon.
_ATTACK_PREFIX = re.compile(r"(?i)crown|seal|vault|deny|attack|intru")
# Sensitive destination ports: a drop toward these reads as an attack attempt.
_ATTACK_DPT = {"22", "445", "3389", "88", "389", "636", "1433", "3306", "5985", "5986"}


def classify(prefix: str, dpt: str) -> str:
    if prefix and _ATTACK_PREFIX.search(prefix):
        return "attack"
    if dpt and dpt in _ATTACK_DPT:
        return "attack"
    return "recon"


def source_name(msg: str, addr_ip: str) -> str:
    m = _HOST.match(msg)
    host = m.group(1) if m else ""
    # Reject the month token / our own tags masquerading as a hostname.
    if host and not re.fullmatch(r"(?i)\w{3}", host) and "=" not in host:
        return host
    return addr_ip


class Collector:
    def __init__(self) -> None:
        # flow key -> entry; OrderedDict so we can cap memory and expire oldest.
        self.flows: "OrderedDict[tuple, dict]" = OrderedDict()
        self.sources: dict[str, dict] = {}
        self._last_write = 0.0
        self._dirty = False

    def ingest(self, data: bytes, addr_ip: str) -> None:
        now = time.time()
        try:
            msg = data.decode("utf-8", errors="replace").strip()
        except Exception:
            return
        host = source_name(msg, addr_ip)
        src_rec = self.sources.setdefault(
            host, {"last_seen": 0.0, "msgs": 0, "drops": 0, "addr": addr_ip})
        src_rec["last_seen"] = now
        src_rec["addr"] = addr_ip
        src_rec["msgs"] += 1

        kv = dict(_KV.findall(msg))
        src, dst = kv.get("SRC"), kv.get("DST")
        if src and dst:
            pm = _PREFIX.search(msg)
            prefix = (pm.group(1).strip() if pm else "")[:48]
            dpt = kv.get("DPT", "")
            cls = classify(prefix, dpt)
            src_rec["drops"] += 1
            key = (src, dst, kv.get("PROTO", ""), dpt)
            self.flows[key] = {
                "src": src, "dst": dst, "class": cls,
                "proto": kv.get("PROTO", ""), "dpt": dpt,
                "prefix": prefix, "router": host, "ts": now,
            }
            self.flows.move_to_end(key)
            # Cap retained flows so a flood can't grow memory unbounded.
            while len(self.flows) > 400:
                self.flows.popitem(last=False)
        self._dirty = True
        self.maybe_write(now)

    def live_flows(self, now: float) -> list[dict]:
        cutoff = now - FLOW_TTL
        live = []
        for key in list(self.flows):
            if self.flows[key]["ts"] < cutoff:
                del self.flows[key]
            else:
                live.append(self.flows[key])
        return live

    def maybe_write(self, now: float, force: bool = False) -> None:
        if not force and (not self._dirty or now - self._last_write < WRITE_MIN_INTERVAL):
            return
        payload = {
            "ts": now,
            "flows": self.live_flows(now),
            "sources": self.sources,
        }
        tmp = OUT_PATH.with_suffix(OUT_PATH.suffix + ".tmp")
        try:
            OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(json.dumps(payload))
            tmp.replace(OUT_PATH)
        except OSError:
            return
        self._last_write = now
        self._dirty = False


def main() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((BIND, PORT))
    sock.settimeout(1.0)
    coll = Collector()
    print(f"[fleet-syslog] listening on {BIND}:{PORT} -> {OUT_PATH}", flush=True)
    coll.maybe_write(time.time(), force=True)  # write an empty file so readers find it
    while True:
        try:
            data, addr = sock.recvfrom(8192)
            coll.ingest(data, addr[0])
        except socket.timeout:
            # Idle tick: expire stale flows so the dashboard clears on its own.
            coll.maybe_write(time.time(), force=True)
        except OSError:
            continue


if __name__ == "__main__":
    raise SystemExit(main())
