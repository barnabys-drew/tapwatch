"""Per-device daily summaries: 30 days of history the long-horizon rules can query cheaply (#193).

The only full record of what a device did last week is the rotated Zeek logs, and rescanning a month of
conn.log per question is far too slow. `tapwatch summarize` (nightly from `run`, or on demand) closes each
finished local day into three tables (store.DAILY_TABLES):

  * device_day: per device, the day's connections, bytes each way, the local hours it was active (a 24-bit
    bitmap), and connection counts per port ("443/tcp") and per Zeek service ("ssl", "dns", "unknown")
  * device_day_dest: per device, destination and port, the same counts plus the ASN and country, and up to
    48 connection-start times at least 30 minutes apart (one a half hour fills a day), which is what R30's
    slow-beacon gaps are computed from
  * summary_days: which days were summarized, from how many records, over how many local hours with
    traffic: a quiet device and a sensor that was down both leave no device_day row, and R33's dormancy
    test must tell them apart

Only a LAN device's connections to the internet count, as for HourlyProfile: LAN-to-LAN traffic has no
ASN or country to learn, and an answer to a connection from outside is the exposure rule's. Records
between a LAN device and the house's own public address are skipped, as in `Pipeline.process`.

The device is `models.device_id` through an Identity detector seeded with the alerter's saved state and
fed the day's own records first, so each connection is credited to the MAC it carried that day (the dock
two laptops shared on 2026-10-14) and to the DHCP name that MAC announced that day, even when the lease
came after the connection. A MAC that has no name yet takes the one name it announced, on two days or more, in
the 30 days before or the day after (known_names), and once a MAC's name is learned, its earlier mac:<address> days move to the
name (rekey), so one device keeps one history. `dest` is the base domain of the server's name when one was seen (TLS SNI,
else the DNS name that resolved to it, as `Beaconing.name_for`), else the address. A connection counts in
the day it started, all of its bytes too, so totals match a direct pass over conn.log. Zeek logs a connection
when it ends, so the nightly run builds each day twice: the night after (from logs up to 3 h past midnight)
and the night after that, once a day's worth of long connections has been logged too (SETTLE).

Each day is rebuilt whole in one transaction (its old rows deleted first), so a rerun gives the same rows
and a crash leaves the day as it was. Summaries older than `summaries.retention_days` (90) are deleted.

Per-program summaries from the endpoint agents (device_day_program, for R35) are a follow-up: #320.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from itertools import chain
from zoneinfo import ZoneInfo

from . import detectors as det
from . import zeek
from .feeds import AsnTable
from .models import device_id

log = logging.getLogger("tapwatch")

READS = {"conn.log", "dns.log", "ssl.log", "dhcp.log"}
PREROLL = 2 * 3600     # s of logs read before the day: DNS answers and SNI that name its first connections
LATE = 3 * 3600        # s of logs read after it: Zeek logs a connection when it ends, stamped with its start
# s of conn logs read after it for long connections. Measured on three home days (2026-10-17/20/22): reading 3 h past
# midnight missed 0 to 31 connections a day (0.03% at most), but one was a 1.5 GB session, 3% of 2026-10-20's bytes,
# logged a day later. Each day is built again once this much has been logged (the nightly run's second look at it).
SETTLE = 24 * 3600 + LATE
CONTACTS = 48          # connection-start times kept per destination and day
CONTACT_GAP = 1800     # s between two kept start times
TOP_PORTS = 200        # per device and day; a scanning device's long tail is summed under "other"
# Unnamed destinations (a bare address:port) kept per device and day; past this, the rest are summed into one
# ("other", -1) row. A torrent client, a game or a scanner can reach a million peers in a day, and without a cap
# that day would hold ~650 bytes per peer in the alerter's memory and write a row for each (review of #321).
MAX_UNNAMED = 2000
CATCH_UP = 3           # days the nightly run looks back for a day not summarized or not settled (a stopped alerter)
BACKFILL = 30          # days `summarize --backfill` looks back
NAME_LOOKBACK = 30 * 86400   # s of DHCP logs before a day searched for the names of its MACs (known_names)
MIN_NAME_DAYS = 2            # days (UTC) a MAC must have announced its one name on, for known_names to lend it


def zone(cfg: dict):
    """The `timezone` setting, as every time-of-day rule reads it; None = this machine's local time."""
    return ZoneInfo(cfg["timezone"]) if cfg.get("timezone") else None


def bounds(day: date, tz) -> tuple[float, float]:
    """Epoch start and end of a local day (23 or 25 hours long on a daylight-saving change)."""
    start = datetime(day.year, day.month, day.day, tzinfo=tz)  # tz None: this machine's local time
    return start.timestamp(), (start + timedelta(days=1)).timestamp()  # wall-clock midnight to midnight


def local_hour(ts: float, tz) -> int:
    return datetime.fromtimestamp(ts, tz).hour


def finished(day: date, tz, now: float) -> bool:
    """A day can be summarized once its late connections have been logged and their file rotated."""
    return now >= bounds(day, tz)[1] + LATE + 3600


def settled(day: date, tz, built_ts: float) -> bool:
    """A summary built after a day's long connections were logged too: it will not change any more."""
    return built_ts >= bounds(day, tz)[1] + SETTLE


def name_for(sni: dict, dns: dict, ip: str) -> str | None:
    """TLS SNI, else the DNS name that resolved to the address: `Beaconing.name_for`."""
    return sni.get(ip) or dns.get(ip)


@dataclass
class Day:
    """One day's totals while it is being read."""

    records: int = 0
    hours: set = field(default_factory=set)     # local hours with any counted connection, any device
    devices: dict = field(default_factory=dict)  # device -> [conns, out, in, hours bitmap, ports, services]
    dests: dict = field(default_factory=dict)    # (device, dest, port) -> [conns, out, in, Counter (asn, cc), times]
    unnamed: Counter = field(default_factory=Counter)   # device -> unnamed destination rows so far (MAX_UNNAMED)
    named: dict = field(default_factory=dict)    # MAC -> the one DHCP name it announced around the day (known_names)


def known_names(log_dirs, start: float, end: float) -> tuple[dict[str, str], dict[str, str]]:
    """MAC -> DHCP name for the MACs that announced exactly one name: in the day's own window (PREROLL to LATE),
    and from NAME_LOOKBACK before the day until all that was logged after it (up to SETTLE).

    A device renews its lease about twice a day, but not every renewal carries the name, and a new sensor's
    Identity knows no names at all: summarized from an empty Identity, 12 home days put devices under
    mac:<address> on the days before their first named lease and under name:<hostname> after, two histories for
    one device. A MAC that announced two names (a dock two computers share) is left out of both: which of them
    held it before its first lease of the day is not known, and a guess could merge two computers. After that
    lease, the day's records name it as they come (Identity.feed)."""
    day: dict[str, set] = {}
    around: dict[str, set] = {}
    days: dict[str, set] = {}
    for rec in zeek.replay(log_dirs, {"dhcp.log"}, (start - NAME_LOOKBACK, end + SETTLE)):
        mac, name, ts = (rec.get("mac") or "").lower(), (rec.get("host_name") or "").strip(), rec.get("ts", 0.0)
        if name and det.mac_ok(mac) and start - NAME_LOOKBACK <= ts < end + SETTLE:
            around.setdefault(mac, set()).add(name)
            days.setdefault(mac, set()).add(int(ts // 86400))
            if start - PREROLL <= ts < end + LATE:
                day.setdefault(mac, set()).add(name)

    def one(seen: dict[str, set]) -> dict[str, str]:
        return {mac: min(n) for mac, n in seen.items() if len({x.lower() for x in n}) == 1}
    # Outside the day, the name must hold on two days or more. Measured: from an empty Identity, the shared dock's
    # first day saw one lease (one computer's) in its window and the other computer's name only the day after,
    # so one day of a single name credited the other computer's traffic to it.
    return one(day), {mac: name for mac, name in one(around).items() if len(days[mac]) >= MIN_NAME_DAYS}


def read_day(log_dirs, day: date, tz, ident: det.Identity, asn: AsnTable | None = None) -> Day:
    """Read one local day's connections out of the rotated logs into per-device and per-destination totals."""
    start, end = bounds(day, tz)
    window = (start - PREROLL, end + LATE)
    out, sni, dns = Day(), {}, {}
    # The day's DHCP names first: a laptop that renewed its lease at noon is name:<hostname> all day, not
    # mac:<address> in the morning and name:<hostname> after. Then, for a MAC still unnamed, the one name it
    # announced in the weeks around the day.
    todays, out.named = known_names(log_dirs, start, end)
    ident.hostname.update(todays)
    for mac, name in out.named.items():
        ident.hostname.setdefault(mac, name)
    # Then the day with its names, and after it the next day's conn logs for long connections (only the files the
    # first pass did not read: the two windows share a file at the seam, and the live file).
    first = {p for files, _ in zeek.replay_files(log_dirs, READS, window) for p in files}
    late = zeek.replay(log_dirs, {"conn.log"}, (end + LATE, end + SETTLE), skip=first)
    for rec in chain(zeek.replay(log_dirs, READS, window), late):
        kind = rec["_type"]
        if kind == "dns":
            for answer in rec.get("answers") or ():
                dns[answer] = rec.get("query") or ""
            continue
        if kind == "ssl":
            if rec.get("server_name"):
                sni[rec.get("id.resp_h", "")] = rec["server_name"]
            continue
        ident.feed(rec)  # conn and dhcp: this record's own MAC decides the device
        if kind != "conn" or not start <= rec.get("ts", 0.0) < end or det.hairpin(rec):
            continue
        src, dst = rec.get("id.orig_h", ""), rec.get("id.resp_h", "")
        if not det.is_unicast_lan(src) or det.is_internal(dst):
            continue
        out.records += 1
        dev = device_id(src, ident.facts_for(src))
        port, proto = rec.get("id.resp_p"), rec.get("proto") or "?"
        up, down = int(rec.get("orig_bytes") or 0), int(rec.get("resp_bytes") or 0)
        hour = local_hour(rec["ts"], tz)
        out.hours.add(hour)
        d = out.devices.get(dev)
        if d is None:
            d = out.devices[dev] = [0, 0, 0, 0, Counter(), Counter()]
        d[0] += 1
        d[1] += up
        d[2] += down
        d[3] |= 1 << hour
        d[4][f"{port}/{proto}"] += 1
        d[5][rec.get("service") or "unknown"] += 1
        name = name_for(sni, dns, dst)
        key = (dev, det.base_domain(name) if name else dst, port if isinstance(port, int) else -1)
        row = out.dests.get(key)
        if row is None and not name:
            if out.unnamed[dev] >= MAX_UNNAMED:
                key = (dev, "other", -1)
                row = out.dests.get(key)
            else:
                out.unnamed[dev] += 1
        if row is None:
            row = out.dests[key] = [0, 0, 0, Counter(), []]
        row[0] += 1
        row[1] += up
        row[2] += down
        row[3][asn.lookup(dst) if asn else None] += 1
        times = row[4]   # kept as contact_times would keep them, so a busy destination holds 48, not every start
        if len(times) < CONTACTS and (not times or rec["ts"] - times[-1] >= CONTACT_GAP):
            times.append(rec["ts"])
    return out


def contact_times(times: list[float]) -> list[int]:
    """Up to CONTACTS start times, each at least CONTACT_GAP after the one kept before it."""
    kept: list[int] = []
    for t in sorted(times):
        if not kept or t - kept[-1] >= CONTACT_GAP:
            kept.append(int(t))
            if len(kept) == CONTACTS:
                break
    return kept


def top_ports(ports: Counter) -> dict[str, int]:
    out = dict(ports.most_common(TOP_PORTS))
    rest = sum(ports.values()) - sum(out.values())
    return {**out, "other": rest} if rest else out


def rows(day: date, d: Day) -> tuple[list[tuple], list[tuple]]:
    """device_day and device_day_dest rows for one day, in a fixed order so a rerun writes the same rows."""
    iso = day.isoformat()
    days = [(dev, iso, c, up, down, bits, json.dumps(top_ports(ports), sort_keys=True),
             json.dumps(dict(services), sort_keys=True))
            for dev, (c, up, down, bits, ports, services) in sorted(d.devices.items())]
    dests = []
    for (dev, dest, port), (c, up, down, asns, times) in sorted(d.dests.items()):
        known = [(n, a) for a, n in asns.items() if a is not None]
        asn, cc = max(known)[1] if known else (None, None)  # the network most of its connections went to
        dests.append((dev, iso, dest, port, asn, cc, c, up, down, json.dumps(contact_times(times))))
    return days, dests


def write_day(db, day: date, d: Day, seconds: float) -> None:
    """Replace one day's summaries in a single transaction."""
    iso = day.isoformat()
    days, dests = rows(day, d)
    with db:
        db.execute("DELETE FROM device_day WHERE day=?", (iso,))
        db.execute("DELETE FROM device_day_dest WHERE day=?", (iso,))
        db.executemany("INSERT INTO device_day VALUES (?,?,?,?,?,?,?,?)", days)
        db.executemany("INSERT INTO device_day_dest VALUES (?,?,?,?,?,?,?,?,?,?)", dests)
        db.execute("INSERT OR REPLACE INTO summary_days VALUES (?,?,?,?,?,?)",
                   (iso, len(days), d.records, len(d.hours), time.time(), round(seconds, 2)))


def rekey(db, named: dict[str, str], before: date) -> int:
    """Move earlier days summarized under mac:<address> to the name that MAC has announced since (known_names), so a
    device keeps one history once its name is learned. A day that already has a row under the name keeps both
    (`summarize --day` rebuilds it as one). Returns how many device-days moved."""
    moved = 0
    with db:
        for mac, name in sorted(named.items()):
            old, new = device_id("", {"device_mac": mac}), device_id("", {"device_name": name})
            days = [r[0] for r in db.execute(
                "SELECT day FROM device_day WHERE device=? AND day<? AND day NOT IN"
                " (SELECT day FROM device_day WHERE device=?)", (old, before.isoformat(), new))]
            for day in days:
                db.execute("UPDATE device_day SET device=? WHERE device=? AND day=?", (new, old, day))
                db.execute("UPDATE device_day_dest SET device=? WHERE device=? AND day=?", (new, old, day))
            moved += len(days)
    return moved


def prune(db, today: date, keep_days: int) -> int:
    """Delete summaries older than keep_days. Returns how many device-days went."""
    if not keep_days:
        return 0
    cutoff = (today - timedelta(days=keep_days)).isoformat()
    with db:
        gone = db.execute("DELETE FROM device_day WHERE day<?", (cutoff,)).rowcount
        db.execute("DELETE FROM device_day_dest WHERE day<?", (cutoff,))
        db.execute("DELETE FROM summary_days WHERE day<?", (cutoff,))
    return gone


def has_logs(log_dirs, day: date, tz) -> bool:
    """A conn log opened during the day, or a live one written to since it began whose first record is from before
    it ended. Days before the oldest log left are skipped, not summarized as days without traffic."""
    start, end = bounds(day, tz)
    for d in zeek._dirs(log_dirs):
        for p in zeek.log_files(d, "conn.log"):
            if zeek.rotated_ts(p) is None and _live_covers(p, start, end):
                return True
    # A log rotated during the day, and the day's first hour still on disk: the oldest log left must have opened by
    # then. On the oldest day left, prune has already deleted its morning, and a first --backfill would build it
    # from the rest and mark it settled (review of #321). A sensor's first, partial day is skipped the same way.
    stamps = list(_rotated(log_dirs))
    return any(start <= ts < end for ts in stamps) and min(stamps) <= start + 3600


def _rotated(log_dirs):
    for d in zeek._dirs(log_dirs):
        for p in zeek.log_files(d, "conn.log"):
            ts = zeek.rotated_ts(p)
            if ts is not None:
                yield ts


def _live_covers(path, start: float, end: float) -> bool:
    try:
        if path.stat().st_mtime < start:
            return False
        with path.open(errors="replace") as fh:
            for line in fh:
                rec = zeek._parse_line(line, "conn")
                if rec is not None:
                    return float(rec.get("ts") or 0) < end
    except (OSError, ValueError):
        pass
    return False


def summarized(db) -> dict[str, float]:
    """Day -> when its summary was built."""
    return {r[0]: r[1] for r in db.execute("SELECT day, built_ts FROM summary_days")}


def due_days(db, log_dirs, tz, now: float, look_back: int) -> list[date]:
    """Days in the last `look_back` with logs to read, oldest first: finished ones never summarized, and ones built
    before their long connections were logged, once those have been."""
    today = datetime.fromtimestamp(now, tz).date()
    built = summarized(db)
    out = []
    for d in (today - timedelta(days=n) for n in range(look_back, 0, -1)):
        when = built.get(d.isoformat())
        due = finished(d, tz, now) if when is None else not settled(d, tz, when) and settled(d, tz, now)
        if due and has_logs(log_dirs, d, tz):
            out.append(d)
    return out


def identity_state(store) -> dict:
    """The alerter's saved Identity (IP -> MAC, MAC -> DHCP name), or an empty one. Only that row is decoded: the
    nightly thread runs inside the alerter, and every detector's state would cost memory it rarely gives back."""
    row = store.db.execute("SELECT data FROM detector_state WHERE name='identity'").fetchone()
    try:
        return json.loads(row[0]) if row else {}
    except ValueError:
        return {}


@dataclass
class Result:
    day: date
    devices: int
    dests: int
    records: int
    seconds: float


def summarize(store, cfg: dict, log_dirs, days: list[date], asn: AsnTable | None = None,
              configure: bool = True) -> list[Result]:
    """Summarize each day (oldest first), then apply retention. Detector globals the reading depends on (the
    LAN's IPv6 prefix, the house's public address, the public suffix list) are set from cfg, as build() does,
    unless configure is False: inside `run`, build() set them already, and resetting them from this thread
    would empty them for a moment under the live detectors."""
    if configure:
        net = cfg.get("network") or {}
        det.set_local_nets(net.get("local_nets") or ())
        det.set_house_ips(net.get("public_ips"))
        det.set_public_suffixes(cfg.get("public_suffix_file"))
    if asn is None:
        asn = AsnTable.load(cfg.get("asn_file"))
    tz, saved, out = zone(cfg), identity_state(store), []
    for day in sorted(days):
        t0 = time.monotonic()
        ident = det.Identity()
        ident.restore(saved)
        d = read_day(log_dirs, day, tz, ident, asn)
        seconds = time.monotonic() - t0
        before = store.db.execute("SELECT records FROM summary_days WHERE day=?", (day.isoformat(),)).fetchone()
        if before and d.records < before[0]:
            # fewer records than the summary already there: the day's oldest logs were pruned since, so rebuilding
            # would replace a complete day with part of one (review of #321)
            log.warning("kept %s's summary: it was built from %d records, its logs now hold %d", day, before[0],
                        d.records)
        elif d.records:  # nothing counted: the logs only touch the day (an edge of what is left), not a quiet day
            write_day(store.db, day, d, seconds)
        if moved := rekey(store.db, d.named, day):
            log.info("moved %d earlier device-day(s) from a MAC to the DHCP name it announced", moved)
        out.append(Result(day, len(d.devices), len(d.dests), d.records, seconds))
    keep = int((cfg.get("summaries") or {}).get("retention_days", 90))
    prune(store.db, datetime.now(tz).date(), keep)
    return out


def parse_day(text: str) -> date:
    return date.fromisoformat(text)


def day_range(first: date, last: date) -> list[date]:
    return [first + timedelta(days=n) for n in range((last - first).days + 1)]


class NightlyClock:
    """Once per local day, at or after `hour` (default 4: a day's last connections are logged up to LATE after
    midnight, and their file rotates on the hour). Like DigestClock, a start after the hour counts as that day's run."""

    def __init__(self, hour: int, tz):
        if hour < LATE // 3600:   # before then the day isn't finished, so each summary would wait a night
            log.warning("summaries.hour %d is before %d: using %d", hour, LATE // 3600, LATE // 3600)
            hour = LATE // 3600
        self.hour, self.tz, self.last_day = hour, tz, None

    def due(self, now: float) -> bool:
        t = datetime.fromtimestamp(now, self.tz)
        if t.hour < self.hour or self.last_day == t.date():
            return False
        self.last_day = t.date()
        return True


def nightly(cfg: dict, log_dirs, store_factory, now: float | None = None,
            asn: AsnTable | None = None) -> threading.Thread:
    """Summarize the finished days not done yet, in a background thread so the alerter keeps reading meanwhile.
    The thread opens its own database connection (store_factory); each day is written in one short transaction,
    which the alerter's writes wait for (Store's 10 s timeout) rather than fail."""
    def work():
        try:
            store = store_factory()
            days = due_days(store.db, log_dirs, zone(cfg), time.time() if now is None else now, CATCH_UP)
            for r in summarize(store, cfg, log_dirs, days, asn=asn, configure=False):
                log.info("summarized %s: %d device(s), %d destination row(s) from %d connection(s) in %.0f s",
                         r.day, r.devices, r.dests, r.records, r.seconds)
        except Exception:  # a failed summary must never take the alerter down
            log.exception("daily summaries failed")

    t = threading.Thread(target=work, name="summarize", daemon=True)
    t.start()
    return t
