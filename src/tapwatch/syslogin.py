"""Receive the router's syslog (UniFi SIEM / CEF) and write it as JSON lines for the alerter.

    tapwatch syslog --listen 0.0.0.0:5514 --out <log dir>

UniFi: Settings > Control Plane > Integrations > Activity Logging > SIEM Server, pointed at this
machine and port. Lines are CEF, e.g.

    CEF:0|Ubiquiti|UniFi Network|9.4.19|201|Threat Detected and Blocked|7|proto=TCP src=81.181.129.172
    spt=54321 dst=192.168.0.233 dpt=443 UNIFIcategory=Security UNIFIsubCategory=Intrusion Prevention
    UNIFIrisk=medium UNIFIipsSignature=ET DROP Dshield Block Listed Source group 1 msg=A network ...

Each accepted line becomes one JSON object in <out>/udm.log, which `tapwatch run` follows like a
Zeek log. The file rotates hourly with Zeek's naming (udm.2026-10-13-14-00-00.log), so retention
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
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("tapwatch")
EXT_KEY = re.compile(r"(?:^|\s)([A-Za-z0-9_.]+)=")
MAX_LINE = 8192


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


def handle(data: bytes, sender: str, writer: UdmWriter, allow: set[str], now: float | None = None) -> bool:
    """Parse and store one datagram. Returns True if it was kept."""
    if allow and sender not in allow:
        return False
    cef = parse_cef(data[:MAX_LINE].decode("utf-8", errors="replace"))
    if cef is None:
        return False
    writer.write({"ts": time.time() if now is None else now, "sender": sender, **cef}, now)
    return True


def serve(listen: str, out_dir: str, allow: set[str]) -> None:
    host, _, port = listen.rpartition(":")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host or "0.0.0.0", int(port)))
    writer = UdmWriter(out_dir)
    log.info("syslog listening on %s, writing %s (accepting from: %s)", listen, writer.path,
             ", ".join(sorted(allow)) or "anyone")
    kept = dropped = 0
    while True:
        data, (sender, _) = sock.recvfrom(65535)
        if handle(data, sender, writer, allow):
            kept += 1
        else:
            dropped += 1
            if dropped in (1, 10, 100) or dropped % 1000 == 0:
                log.warning("dropped %d syslog datagram(s) (not CEF, or sender not allowed); last from %s",
                            dropped, sender)
