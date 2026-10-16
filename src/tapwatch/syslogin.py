"""Receive the router's syslog (UniFi SIEM) and write the useful lines as JSON for the alerter.

    tapwatch syslog --listen 0.0.0.0:5514 --out <log dir>

UniFi 10.x: CyberSecure > Traffic Logging > Activity Logging (Syslog) > SIEM Server, pointed at this
machine and port, with a Contents picker for what to send. What arrives is a mix of three things
(measured on a UDM Pro, UniFi Network 10.6, see docs/setup/router-syslog.md):

* CEF events, one per UniFi event (client joins, admin activity, IPS detections, device updates):

      Oct 15 19:29:37 gateway CEF:0|Ubiquiti|UniFi Network|10.6.106|401|WiFi Client Disconnected|2|
      UNIFIcategory=Client Devices UNIFIhost=UDM Pro UNIFIclientIp=192.168.50.18 ...

  Note the missing <PRI> and the spaces inside values: the extension is split on ` key=` boundaries,
  not on spaces.

* iptables-style firewall lines, one per packet the gateway's firewall logged. With "Firewall
  Default Policy" ticked these are hundreds a minute, almost all default-policy accepts
  (`-RET-`/`-A-`) for LAN devices talking to the gateway itself (DNS, discovery):

      <13>Oct 15 19:25:16 gateway gateway [LAN_LOCAL-RET-2147483647] DESCR="no rule description" IN=br0
      OUT= MAC=... SRC=192.168.50.18 DST=192.168.50.1 ... PROTO=UDP SPT=61975 DPT=53 LEN=39 MARK=0

  Only drops and rejects are kept (as `kind: firewall` records with the chain, rule, addresses and
  ports); accepts are counted and discarded. Nothing in tapwatch alerts on them yet; they are
  evidence next to the Zeek logs.

* the gateway's own system log (systemd, earlyoom, syslog-ng, its AI daemon). Dropped.

Each kept line becomes one JSON object in <out>/udm.log, which `tapwatch run` follows like a Zeek
log. The file rotates hourly with Zeek's naming (udm.2026-10-13-14-00-00.log), so retention
pruning and evidence lookups treat it the same way.

Syslog over UDP is unauthenticated: anything on the LAN can send it. Only senders in `allow`
(by default the configured gateways) are accepted. A spoofed line can add noise but can never
suppress a real alert.
"""

from __future__ import annotations

import json
import logging
import re
import socket
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("tapwatch")
EXT_KEY = re.compile(r"(?:^|\s)([A-Za-z0-9_.]+)=")
MAX_LINE = 8192

# [LAN_LOCAL-RET-2147483647], [WAN_LOCAL-D-4000], [LAN_IN-A-2001]: <chain>-<iptables target>-<rule id>.
# The chain is <source zone>_<destination zone>; the target is A/ACCEPT, D/DROP, R/REJECT, RET/RETURN.
FW_PREFIX = re.compile(r"\[(?P<chain>[A-Z0-9_]+)-(?P<action>[A-Z]+)-(?P<rule>\d+)\] ")
FW_FIELD = re.compile(r'(?:^|\s)(?P<k>[A-Z]+)=(?:"(?P<q>[^"]*)"|(?P<v>\S*))')
FW_KEEP_ACTIONS = frozenset({"D", "DROP", "R", "REJECT"})  # accepts and chain returns are the flood
FW_FIELDS = {"DESCR": "descr", "IN": "in", "OUT": "out", "SRC": "src", "DST": "dst", "PROTO": "proto",
             "SPT": "spt", "DPT": "dpt", "LEN": "len", "TTL": "ttl"}
STATS_EVERY = 600  # seconds between "what arrived" log lines


def _unescape(v: str) -> str:
    return v.replace("\\=", "=").replace("\\n", "\n").replace("\\r", "\r").replace("\\\\", "\\").strip()


def parse_cef(text: str) -> dict | None:
    """The CEF part of a syslog line as a flat dict (header fields plus extension keys), or None."""
    i = text.find("CEF:")
    if i < 0:
        return None
    body = text[i + 4:]
    parts, cur, esc = [], [], False
    for ch in body:  # split the 7 header fields on unescaped pipes
        if len(parts) == 7:
            cur.append(ch)
            continue
        if esc:
            cur.append(ch)
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == "|":
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if len(parts) < 7:
        return None
    ext = "".join(cur)
    out = {"cef_version": parts[0], "vendor": parts[1], "product": parts[2], "product_version": parts[3],
           "class_id": parts[4], "name": parts[5], "cef_severity": parts[6]}
    keys = list(EXT_KEY.finditer(ext))
    for n, m in enumerate(keys):
        end = keys[n + 1].start() if n + 1 < len(keys) else len(ext)
        out[m.group(1)] = _unescape(ext[m.end():end])
    return out


def parse_firewall(text: str) -> dict | None:
    """An iptables-style firewall line as a flat dict, or None if the line isn't one."""
    m = FW_PREFIX.search(text)
    if m is None:
        return None
    out = {"chain": m.group("chain"), "action": m.group("action"), "rule": m.group("rule")}
    for f in FW_FIELD.finditer(text, m.end() - 1):  # from the space after "]", so DESCR counts
        key = FW_FIELDS.get(f.group("k"))
        if key and key not in out:  # LEN appears twice (IP, then UDP); the first is the packet
            out[key] = f.group("q") if f.group("q") is not None else f.group("v")
    for key in ("spt", "dpt", "len", "ttl"):
        if out.get(key, "").isdigit():
            out[key] = int(out[key])
    return out


def parse_line(text: str) -> tuple[str, dict | None]:
    """One syslog line as ("cef", rec), ("firewall", rec) or ("system", None)."""
    cef = parse_cef(text)
    if cef is not None:
        return "cef", cef
    fw = parse_firewall(text)
    if fw is not None:
        return "firewall", fw
    return "system", None


class UdmWriter:
    """Append records to <dir>/udm.log, rotating hourly to udm.<UTC open time>.log."""

    def __init__(self, out_dir: str, rotate_s: int = 3600):
        self.dir, self.rotate_s = Path(out_dir), rotate_s
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "udm.log"
        self.opened = self.path.stat().st_mtime if self.path.exists() else time.time()

    def write(self, rec: dict, now: float | None = None) -> None:
        now = time.time() if now is None else now
        if now - self.opened >= self.rotate_s and self.path.exists():
            stamp = datetime.fromtimestamp(self.opened, timezone.utc).strftime("%Y-%m-%d-%H-%M-%S")
            self.path.rename(self.dir / f"udm.{stamp}.log")
            self.opened = now
        with self.path.open("a") as fh:
            fh.write(json.dumps(rec) + "\n")


class Stats:
    """Counts per outcome, logged every STATS_EVERY seconds instead of a warning per dropped line.

    At hundreds of firewall accepts a minute, one line per drop (or per thousand) is itself noise;
    one summary line a period says what the router is sending and whether anything useful is in it.
    """

    def __init__(self, every: float = STATS_EVERY):
        self.every, self.counts, self.since = every, Counter(), None
        self.warned_refused = False  # one warning per period, not per sender: UDP sources are spoofable

    def add(self, outcome: str, now: float) -> None:
        if self.since is None:
            self.since = now
        elif now - self.since >= self.every:
            self.flush(now)
        self.counts[outcome] += 1

    def flush(self, now: float) -> None:
        minutes = max(1, round((now - (self.since if self.since is not None else now)) / 60))
        if self.counts:
            summary = ", ".join(f"{k} {v}" for k, v in sorted(self.counts.items()))
            log.info("syslog: %s in the last %d min (kept: cef, firewall_drop)", summary, minutes)
        else:  # a silent feed must look different from a quiet one: the router or the firewall rule is off
            log.info("syslog: nothing arrived in the last %d min", minutes)
        self.counts.clear()
        self.warned_refused = False
        self.since = now


def handle(data: bytes, sender: str, writer: UdmWriter, allow: set[str], now: float | None = None,
           stats: Stats | None = None) -> str | None:
    """Parse and store one datagram. Returns the kind that was kept ("cef", "firewall") or None."""
    now = time.time() if now is None else now
    stats = Stats() if stats is None else stats
    if allow and sender not in allow:
        stats.add("refused", now)
        if not stats.warned_refused:  # the count is in the summary; the warning just names one sender
            stats.warned_refused = True
            log.warning("syslog: refusing datagrams from %s (not in syslog.allow / network.gateways)", sender)
        return None
    kind, rec = parse_line(data[:MAX_LINE].decode("utf-8", errors="replace"))
    if rec is None:
        stats.add(kind, now)
        return None
    if kind == "firewall" and rec["action"] not in FW_KEEP_ACTIONS:
        stats.add("firewall_accept", now)
        return None
    stats.add("firewall_drop" if kind == "firewall" else kind, now)
    writer.write({"ts": now, "sender": sender, "kind": kind, **rec}, now)
    return kind


def serve(listen: str, out_dir: str, allow: set[str]) -> None:
    host, _, port = listen.rpartition(":")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host or "0.0.0.0", int(port)))
    writer, stats = UdmWriter(out_dir), Stats()
    sock.settimeout(stats.every)  # so a feed that stops still gets its summary line
    log.info("syslog listening on %s, writing %s (accepting from: %s)", listen, writer.path,
             ", ".join(sorted(allow)) or "anyone")
    while True:
        try:
            data, (sender, _) = sock.recvfrom(65535)
        except TimeoutError:
            stats.flush(time.time())
            continue
        try:
            handle(data, sender, writer, allow, stats=stats)
        except Exception:  # parsing can't raise; writing can (disk full, a rename race at rotation)
            log.exception("syslog: could not store a datagram from %s", sender)
