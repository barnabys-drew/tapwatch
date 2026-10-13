"""Find the Zeek records for one device around the time of a case.

Zeek logs can grow to several GB, so we never read a whole file. Zeek writes
lines roughly in time order, which lets us binary-search the file by byte
offset to land near the start of the time window, then read forward only until
we're past it.

"Roughly": conn.log rows are written when a connection *ends* but stamped with
when it *started*, so a row can sit a little later in the file than its time.
SLACK covers that. Connections that lasted longer than SLACK can be missed.
"""

from __future__ import annotations

import glob
import json
from pathlib import Path

from .zeek import log_files, rotated_ts

WINDOW = 300          # ±5 minutes around the case
SLACK = 900           # how far out of order a row may be written (seconds)
MAX_ROWS = 100        # per log type, to keep the page readable
MAX_SCAN_LINES = 500_000  # hard stop per file, whatever happens
EVIDENCE_LOGS = ("conn", "dns", "ssl")

# What to show for each log type: (column heading, Zeek field)
COLUMNS = {
    "conn": [("proto", "proto"), ("from", "id.orig_h"), ("from port", "id.orig_p"), ("to", "id.resp_h"),
             ("to port", "id.resp_p"), ("service", "service"), ("state", "conn_state"),
             ("duration s", "duration"), ("bytes out", "orig_bytes"), ("bytes in", "resp_bytes")],
    "dns": [("from", "id.orig_h"), ("server", "id.resp_h"), ("query", "query"), ("type", "qtype_name"),
            ("result", "rcode_name"), ("answers", "answers")],
    "ssl": [("from", "id.orig_h"), ("to", "id.resp_h"), ("to port", "id.resp_p"), ("server name", "server_name"),
            ("version", "version"), ("established", "established")],
}


def expand_dirs(patterns) -> list[Path]:
    """Config entries may be plain dirs or globs like eval/data/home-mirror-*."""
    out = []
    for p in ([patterns] if isinstance(patterns, str) else patterns or []):
        out += [Path(m) for m in sorted(glob.glob(str(p)))] or [Path(p)]
    return [d for d in out if d.is_dir()]


def _ts(line: bytes) -> float | None:
    try:
        rec = json.loads(line)
    except ValueError:
        return None  # partial line, Zeek TSV header, junk
    ts = rec.get("ts") if isinstance(rec, dict) else None
    return float(ts) if isinstance(ts, (int, float)) else None


def _first_ts_after(fh, offset: int) -> float:
    """Time of the first complete line at or after `offset` (infinity at end of file)."""
    fh.seek(offset)
    if offset:
        fh.readline()  # we probably landed mid-line; skip to the next line start
    for _ in range(1000):
        line = fh.readline()
        if not line:
            break
        ts = _ts(line)
        if ts is not None:
            return ts
    return float("inf")


def find_offset(fh, size: int, target: float) -> int:
    """Byte offset from which reading forward will reach the first line stamped >= target."""
    lo, hi = 0, size
    while hi - lo > 65536:
        mid = (lo + hi) // 2
        if _first_ts_after(fh, mid) < target:
            lo = mid
        else:
            hi = mid
    return lo


def read_window(path: Path, host: str, start: float, end: float, limit: int = MAX_ROWS) -> tuple[list[dict], bool]:
    """Rows in `path` stamped within [start, end] that involve `host`. Returns (rows, more_than_limit)."""
    rows: list[dict] = []
    with path.open("rb") as fh:
        size = path.stat().st_size
        offset = find_offset(fh, size, start - SLACK)
        fh.seek(offset)
        if offset:
            fh.readline()
        for _ in range(MAX_SCAN_LINES):
            line = fh.readline()
            if not line:
                break
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            ts = rec.get("ts") if isinstance(rec, dict) else None
            if not isinstance(ts, (int, float)):
                continue
            if ts > end + SLACK:
                break
            if start <= ts <= end and host in (rec.get("id.orig_h"), rec.get("id.resp_h")):
                if len(rows) >= limit:
                    return rows, True
                rows.append(rec)
    return rows, False


def _covering(files: list[Path], start: float, end: float) -> list[Path]:
    """The files (rotated oldest-first, then live) whose time span can overlap [start, end].
    A rotated file covers from its open time to the next file's open time."""
    opens = [rotated_ts(p) for p in files]
    out = []
    for i, p in enumerate(files):
        begin = opens[i] if opens[i] is not None else -1.0
        nxt = next((o for o in opens[i + 1:] if o is not None), None)
        if begin <= end and (nxt is None or nxt >= start):
            out.append(p)
    return out


def lookup(dirs, host: str, ts: float, window: float = WINDOW, limit: int = MAX_ROWS) -> dict:
    """{"conn": {"rows": [...], "more": bool}, "dns": ..., "ssl": ...} for `host` within ±window of `ts`."""
    out = {}
    for kind in EVIDENCE_LOGS:
        rows, more = [], False
        for d in expand_dirs(dirs):
            for path in _covering(log_files(d, f"{kind}.log"), ts - window - SLACK, ts + window + SLACK):
                found, cut = read_window(path, host, ts - window, ts + window, limit)
                rows += found
                more = more or cut
        rows.sort(key=lambda r: r["ts"])
        out[kind] = {"rows": rows[:limit], "more": more or len(rows) > limit}
    return out
