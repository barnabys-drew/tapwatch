"""Read Zeek (and Suricata eve.json) logs written as JSON lines.

Two modes:
  * replay  - read finished log files once, merged in time order (used for PCAP evals)
  * follow  - tail live log files like `tail -F`, surviving rotation
"""

from __future__ import annotations

import heapq
import json
import re
import time
from collections.abc import Iterator
from datetime import datetime, timezone
from itertools import chain
from pathlib import Path

# file name -> record type the detectors understand
LOG_TYPES = {"conn.log": "conn", "dns.log": "dns", "ssl.log": "ssl", "http.log": "http", "dhcp.log": "dhcp",
             "ftp.log": "ftp", "udm.log": "udm", "eve.json": "eve",  # udm.log: router syslog (syslogin.py)
             # The endpoint agent's osquery logs (hostrules.py): one JSON record per differential row, or
             # per snapshot. `run` follows their directories next to Zeek's (config.host_log_dirs).
             "osqueryd.results.log": "osquery", "osqueryd.snapshots.log": "osquery"}


def _parse_line(line: str, kind: str) -> dict | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None  # blank or Zeek TSV header; we require JSON output
    try:
        rec = json.loads(line)
    except json.JSONDecodeError:
        return None
    rec["_type"] = kind
    if kind == "eve":
        rec["ts"] = _eve_ts(rec.get("timestamp", ""))
    elif kind == "osquery":  # when the query ran; a Sysmon row's own time is in its `utc` column
        try:
            rec["ts"] = float(rec.get("unixTime") or 0)
        except (TypeError, ValueError):
            rec["ts"] = 0.0
    return rec


def _eve_ts(stamp: str) -> float:
    """Suricata writes ISO timestamps like 2026-10-11T12:00:00.123456+0000."""
    try:
        return datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()
    except ValueError:
        return 0.0


def _read_file(path: Path, kind: str) -> Iterator[dict]:
    with path.open(errors="replace") as fh:
        for line in fh:
            rec = _parse_line(line, kind)
            if rec is not None:
                yield rec


def _dirs(log_dirs) -> list[Path]:
    return [Path(d) for d in ([log_dirs] if isinstance(log_dirs, (str, Path)) else log_dirs)]


# Zeek's hourly rotation renames conn.log to conn.2026-10-13-14-00-00.log (UTC open time).
ROTATED = re.compile(r"^(?P<name>[a-z_]+)\.(?P<stamp>\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2})\.log$")


def rotated_ts(path: Path) -> float | None:
    """Open time (epoch) encoded in a rotated Zeek log's name, else None."""
    m = ROTATED.match(path.name)
    if not m:
        return None
    return datetime.strptime(m["stamp"], "%Y-%m-%d-%H-%M-%S").replace(tzinfo=timezone.utc).timestamp()


def log_files(d: Path, name: str) -> list[Path]:
    """Rotated files for one log, oldest first, then the live one (conn.log)."""
    stem = name.removesuffix(".log")
    rotated = sorted((p for p in d.glob(f"{stem}.*.log") if rotated_ts(p) is not None and p.name.split(".")[0] == stem),
                     key=rotated_ts)
    return rotated + ([d / name] if (d / name).exists() else [])


def replay(log_dirs) -> Iterator[dict]:
    """Yield every record from every known log file (rotated ones included), oldest first."""
    streams = []
    for d in _dirs(log_dirs):
        for name, kind in LOG_TYPES.items():
            files = log_files(d, name) if name.endswith(".log") else [d / name] if (d / name).exists() else []
            if files:
                streams.append(chain.from_iterable([_read_file(p, kind) for p in files]))  # bind kind now
    yield from heapq.merge(*streams, key=lambda r: r.get("ts", 0.0))


def prune(log_dirs, keep_days: float, now: float | None = None) -> list[Path]:
    """Delete rotated Zeek logs opened more than keep_days ago. Never touches live or other files."""
    cutoff = (time.time() if now is None else now) - keep_days * 86400
    gone = []
    for d in _dirs(log_dirs):
        for p in d.glob("*.log"):
            ts = rotated_ts(p)
            if ts is not None and ts < cutoff:
                try:
                    p.unlink()
                    gone.append(p)
                except OSError:
                    pass  # not ours to delete (read-only mount): leave it
    return gone


class _Open:
    def __init__(self, fh, inode: int, offset: int):
        self.fh, self.inode, self.offset = fh, inode, offset


class Follower:
    """Tail several log files at once, surviving Zeek's rotation.

    Each file stays open between polls. When rotation renames conn.log away, the open handle
    still points at the old file, so its last lines are read before switching to the new
    conn.log. Re-opening by path, as before, lost whatever Zeek wrote between the last poll
    and the rotation.
    """

    def __init__(self, log_dirs, from_start: bool = False):
        self.paths = [(d / name, kind) for d in _dirs(log_dirs) for name, kind in LOG_TYPES.items()]
        self.from_start = from_start
        self._open: dict[Path, _Open] = {}
        self._started = False

    def poll(self) -> list[dict]:
        out: list[dict] = []
        for path, kind in self.paths:
            try:
                st = path.stat()
            except FileNotFoundError:
                st = None
            cur = self._open.get(path)
            if cur and (st is None or st.st_ino != cur.inode):
                out += self._tag(self._drain(cur, kind, final=True), path)  # rotated or deleted: finish the old file
                cur.fh.close()
                del self._open[path]
                cur = None
            if st is None:
                continue
            if cur is None:
                # Files already there when we start: skip history and begin at the end.
                # Files that appear later (Zeek creates logs lazily, and after rotation): from the top.
                start = 0 if self.from_start or self._started else st.st_size
                cur = self._open[path] = _Open(path.open("rb"), st.st_ino, start)
            elif st.st_size < cur.offset:
                cur.offset = 0  # truncated in place
            out += self._tag(self._drain(cur, kind), path)
        self._started = True
        out.sort(key=lambda r: r.get("ts", 0.0))
        return out

    @staticmethod
    def _tag(recs: list[dict], path: Path) -> list[dict]:
        """Which directory a record came from: two endpoint agents (Windows, WSL) log under the same query names,
        so the feed-silence rule tells their feeds apart by it."""
        for r in recs:
            r["_log"] = str(path.parent)
        return recs

    @staticmethod
    def _drain(cur: _Open, kind: str, final: bool = False) -> list[dict]:
        out = []
        cur.fh.seek(cur.offset)  # binary, so offsets are exact byte counts
        while True:
            raw = cur.fh.readline()
            if not raw or (not raw.endswith(b"\n") and not final):
                break  # partial line still being written; pick it up next poll
            cur.offset += len(raw)
            rec = _parse_line(raw.decode(errors="replace"), kind)
            if rec is not None:
                out.append(rec)
        return out

    def close(self) -> None:
        for cur in self._open.values():
            cur.fh.close()
        self._open.clear()

    def follow(self, interval: float = 1.0, idle_ticks: bool = False) -> Iterator[dict | None]:
        """Yield records as they arrive. With idle_ticks, also yield None after each quiet poll,
        so the caller can run timers (the daily digest) on a network that's gone silent."""
        while True:
            batch = self.poll()
            yield from batch
            if not batch:
                time.sleep(interval)
                if idle_ticks:
                    yield None
