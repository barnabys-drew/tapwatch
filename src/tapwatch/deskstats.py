"""The numbers behind the case desk's Stats page: daily volume, backlog, time to a disposition, when cases
arrive and from which devices. Read-only SQL over the case store; the page (ui.render_stats) draws them.

Days and hours are local time, as the owner reads them. The owner's dispositions only (store.OWNER_DISPOSITION):
a judge auto-close (#204) is never counted as the owner's call. Log-only cases are left out of the backlog, as the
queue's "Open cases" tile leaves them out.
"""

from __future__ import annotations

import statistics
import time
from datetime import date, datetime, timedelta

from .store import DISPOSITIONS, OWNER_DISPOSITION

ROUTES = ("alert", "digest", "log")
# Time from a case's first hit to its first disposition, in hours: the histogram's buckets.
WAIT_BUCKETS = ((0, 1, "under 1 h"), (1, 6, "1–6 h"), (6, 24, "6–24 h"), (24, 72, "1–3 days"),
                (72, 168, "3–7 days"), (168, float("inf"), "over a week"))


def _days(n: int, today: date) -> list[str]:
    return [(today - timedelta(days=n - 1 - i)).isoformat() for i in range(n)]


def _day_end(day: str) -> float:
    d = date.fromisoformat(day) + timedelta(days=1)
    return datetime(d.year, d.month, d.day).timestamp()


def daily(db, days: int = 30, now: float | None = None) -> dict:
    """Per local day, the last `days` days: cases by route, decided cases, noise among them, true positives,
    and the open backlog at the end of each day."""
    now = time.time() if now is None else now
    keys = _days(days, datetime.fromtimestamp(now).date())
    start = datetime.fromisoformat(keys[0]).timestamp()
    by_route = {d: dict.fromkeys(ROUTES, 0) for d in keys}
    for r in db.execute("SELECT date(first_ts, 'unixepoch', 'localtime') AS day, COALESCE(route, 'log') AS route, "
                        "COUNT(*) AS n FROM cases WHERE first_ts >= ? GROUP BY day, route", (start,)):
        if r["day"] in by_route:
            by_route[r["day"]][r["route"] if r["route"] in ROUTES else "log"] += r["n"]
    decided = dict.fromkeys(keys, 0)
    noise = dict.fromkeys(keys, 0)
    tps = dict.fromkeys(keys, 0)
    # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query -- a constant
    for r in db.execute(f"SELECT date(first_ts, 'unixepoch', 'localtime') AS day, {OWNER_DISPOSITION} AS d "
                        f"FROM cases WHERE first_ts >= ? AND {OWNER_DISPOSITION} IS NOT NULL", (start,)):
        if r["day"] not in decided:
            continue
        decided[r["day"]] += 1
        noise[r["day"]] += r["d"] in ("false_positive", "benign_expected")
        tps[r["day"]] += r["d"] == "true_positive"
    return {"days": keys, "routes": by_route, "decided": decided, "noise": noise, "true_positives": tps,
            "backlog": backlog(db, keys, now)}


def _closed_at(db) -> dict[int, float]:
    """Each closed case's last move to closed, from the audit trail. A case closed without an audit row (older
    stores, direct updates) counts as closed at its updated_ts."""
    out = {r["case_id"]: r["ts"] for r in db.execute(
        "SELECT case_id, MAX(ts) AS ts FROM audit WHERE action = 'status' AND new = 'closed' GROUP BY case_id")}
    for r in db.execute("SELECT id, COALESCE(updated_ts, last_ts) AS ts FROM cases WHERE status = 'closed'"):
        out.setdefault(r["id"], r["ts"])
    return out


def backlog(db, days: list[str], now: float | None = None) -> dict[str, int]:
    """Cases still open (any status but closed) at the end of each day, alert and digest routes only."""
    now = time.time() if now is None else now
    closed = _closed_at(db)
    rows = db.execute("SELECT id, first_ts, status FROM cases WHERE COALESCE(route, 'log') != 'log'").fetchall()
    out = {}
    for d in days:
        end = min(_day_end(d), now)
        out[d] = sum(1 for r in rows if r["first_ts"] <= end
                     and not (r["status"] == "closed" and closed.get(r["id"], now) <= end))
    return out


def waits(db, days: int = 30, now: float | None = None) -> dict:
    """How long cases raised in the last `days` days waited for their first disposition: a histogram over
    WAIT_BUCKETS, the median in hours, and how many are still undecided."""
    now = time.time() if now is None else now
    start = now - days * 86400
    first = {r["case_id"]: r["ts"] for r in db.execute(
        "SELECT case_id, MIN(ts) AS ts FROM audit WHERE action = 'disposition' GROUP BY case_id")}
    hours, undecided = [], 0
    # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query -- a constant
    for r in db.execute(f"SELECT id, first_ts, {OWNER_DISPOSITION} AS d FROM cases WHERE first_ts >= ?", (start,)):
        if r["d"] is None:
            undecided += 1
        elif r["id"] in first:
            hours.append(max(0.0, (first[r["id"]] - r["first_ts"]) / 3600))
    hist = {name: 0 for _, _, name in WAIT_BUCKETS}
    for h in hours:
        hist[next(name for lo, hi, name in WAIT_BUCKETS if lo <= h < hi)] += 1
    return {"hist": hist, "median_h": statistics.median(hours) if hours else None, "timed": len(hours),
            "undecided": undecided}


def hour_of_day(db, days: int = 30, now: float | None = None) -> dict[str, list[int]]:
    """Cases raised in the last `days` days by local hour of day (0-23): alerts, and everything else."""
    now = time.time() if now is None else now
    out = {"alert": [0] * 24, "other": [0] * 24}
    for r in db.execute("SELECT CAST(strftime('%H', first_ts, 'unixepoch', 'localtime') AS INTEGER) AS h, "
                        "route = 'alert' AS a, COUNT(*) AS n FROM cases WHERE first_ts >= ? GROUP BY h, a",
                        (now - days * 86400,)):
        out["alert" if r["a"] else "other"][r["h"]] += r["n"]
    return out


def top(db, column: str, days: int = 30, limit: int = 8, now: float | None = None) -> list[dict]:
    """The devices (column 'host') or detectors (column 'detector') with the most cases in the last `days` days:
    cases, alerts and how many of them were decided as noise."""
    if column not in ("host", "detector"):
        raise ValueError(column)
    now = time.time() if now is None else now
    # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query -- constants only
    rows = db.execute(f"SELECT {column} AS k, COUNT(*) AS n, SUM(route = 'alert') AS alerts, "
                      f"SUM({OWNER_DISPOSITION} IN ('false_positive', 'benign_expected')) AS noise, "
                      f"SUM({OWNER_DISPOSITION} IS NOT NULL) AS decided, MAX(facts) AS facts "
                      f"FROM cases WHERE first_ts >= ? GROUP BY {column} ORDER BY n DESC, k LIMIT ?",
                      (now - days * 86400, limit)).fetchall()
    return [{"key": r["k"], "cases": r["n"], "alerts": r["alerts"] or 0, "noise": r["noise"] or 0,
             "decided": r["decided"] or 0, "facts": r["facts"]} for r in rows]


def dispositions(db, days: int = 30, now: float | None = None) -> dict[str, int]:
    """The owner's dispositions of cases raised in the last `days` days, plus '' for undecided."""
    now = time.time() if now is None else now
    out = {d: 0 for d in (*DISPOSITIONS, "")}
    # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query -- a constant
    for r in db.execute(f"SELECT COALESCE({OWNER_DISPOSITION}, '') AS d, COUNT(*) AS n FROM cases "
                        "WHERE first_ts >= ? GROUP BY d", (now - days * 86400,)):
        if r["d"] in out:
            out[r["d"]] = r["n"]
    return out
