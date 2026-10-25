"""Long-horizon rules over the daily summaries (#52): R30 slow beacon (#194) and R31 low-and-slow upload (#195).

The windowed detectors decide within minutes to an hour. Beaconing needs ten beats in a window it holds in memory,
so a heartbeat every 6 or 24 hours is invisible to it, and upload_spike needs 500 MB in one hour, so 20 MB a day
never reaches it. These rules read the per-device daily summaries (history.py, store.DAILY_TABLES) instead of raw
logs, once a day:

  * R30 `slow_beacon`: one destination contacted at a steady interval of 2 to 72 hours for 4+ days (slow_beacons)
  * R31 `slow_upload`: 100+ MB uploaded to one destination over 14 days, a little on most days, never a spike,
    lopsided, and to a destination this device had not uploaded to in the 30 days before (slow_uploads)

A device's profile is mature after 14 watched days: summarized days on which the sensor saw traffic in at least 12
local hours (summary_days.hours), counted from the device's first summarized day. A quiet device keeps maturing; a
day the sensor was down does not count, since it says nothing about the device.

**How they run inside `run`.** The nightly summary thread (history.nightly) calls `then` once its days are written;
`queue_into` evaluates the rules there, on the thread's own database connection, and puts the cases on a queue.
The run loop drains the queue on the main thread and hands each case to `Pipeline.handle` (`admit`), so dedupe,
suppressions, routing, the shadow judge and notifications are the ones every other case goes through, and nothing
touches the pipeline (one SQLite connection, detector state, the notifier) from the summary thread. What the rules
need from the live detectors (the popular list, the benign beacon classes, the dev profile, Beaconing's reported
destinations, the identity table) is copied on the main thread before the thread starts (Context.from_pipeline).
`tapwatch longhaul` runs the same evaluation on demand and prints what it would raise, storing nothing.

**Routing (router.long_horizon).** Digest, unless another signal on the same device backs the case up within 7 days:
a threat-list hit, a host case at digest or louder, or a short-window case at digest or louder to the same
destination (or, for a destination with no name, the same network). Then it is an alert. A suppression, a code
ceiling (a managed device) and the learning period still win, and the learned judge never takes a backed case.
"""

from __future__ import annotations

import json
import logging
import re
import statistics
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field, fields
from datetime import date, datetime, timedelta
from itertools import pairwise

from . import detectors as det
from . import history, hostrules
from .models import Case, device_id
from .router import LONG_HORIZON

log = logging.getLogger("tapwatch")

DAY = 86400
MATURE_DAYS = 14        # watched days before a device's long-horizon rules may fire (#193)
WATCHED_HOURS = 12      # a summarized day counts towards maturity when the sensor saw traffic in this many hours
ONCE_DAYS = 30          # one case per (device, destination) and rule this often
BACKING_DAYS = 7        # another case on the device this recent backs a long-horizon case up (router.long_horizon)


@dataclass
class BeaconRule:
    """R30 thresholds (config `detectors.slow_beacon`), from #194."""

    days: int = 30                 # contact times read
    spacing_s: float = 3600        # first contacts at least this far apart are the beats
    min_gaps: int = 6
    min_span_days: float = 4
    min_interval_h: float = 2      # median gap
    max_interval_h: float = 72
    max_cv: float = 0.2            # coefficient of variation of the gaps
    day_slack_s: float = 1800      # or every gap a whole number of days, this close


@dataclass
class UploadRule:
    """R31 thresholds (config `detectors.slow_upload`), from #195."""

    window_days: int = 14
    min_mb: float = 100            # uploaded in the window
    min_days: int = 7              # days in the window with an upload of at least day_mb
    day_mb: float = 1
    min_ratio: float = 5           # upload / download over the window
    prior_days: int = 30           # before the window ...
    prior_mb: float = 5            # ... this device sent it less than this: a new upload target
    baseline_days: int = 7         # watched days before the window the "new" test needs
    # upload_spike's floor: a day below it can't have had a spike hour, so the destination was never upload_spike's
    spike_bytes: int = 500_000_000


def _rule(cls, cfg: dict, name: str):
    """A rule's thresholds from `detectors.<name>`; unknown keys are ignored with a warning, not fatal."""
    given = dict(((cfg.get("detectors") or {}).get(name)) or {})
    known = {f.name for f in fields(cls)}
    for k in set(given) - known:
        log.warning("detectors.%s.%s is not a setting: ignored", name, k)
    return cls(**{k: v for k, v in given.items() if k in known})


def is_name(dest: str) -> bool:
    """A summary's dest is a base domain when a name was seen, else an address."""
    return "." in dest and any(c.isalpha() for c in dest) and ":" not in dest


def _role(entry: dict | None, words) -> str:
    role = str((entry or {}).get("role", "")).lower()
    return role if any(re.search(rf"\b{re.escape(w)}\b", role) for w in words) else ""


@dataclass
class Context:
    """What the rules borrow from the alerter: copies, so the summary thread never reads live detector state."""

    popular: set = field(default_factory=set)
    classes: dict = field(default_factory=dict)          # benign beacon class -> domains (Beaconing.classes)
    dev: det.DevProfile = field(default_factory=det.DevProfile)
    expected: dict = field(default_factory=dict)         # host -> services it polls on purpose (takeover.expected)
    beacon_reported: dict = field(default_factory=dict)  # (device, port, dest) -> when Beaconing reported it
    ident: det.Identity = field(default_factory=det.Identity)
    assets: object = None                                # summarizer.Assets
    asn: object = None                                   # feeds.AsnTable, to place a backing case's addresses

    @classmethod
    def from_pipeline(cls, p, cfg: dict) -> Context:
        """Call on the main thread, before the summary thread starts."""
        beacon = next((d for d in p.detectors if isinstance(d, det.Beaconing)), None)
        ident = det.Identity()
        if p.identity is not None:
            ident.restore(json.loads(json.dumps(p.identity.snapshot())))
        if beacon is None:
            return cls(ident=ident, assets=p.assets)
        return cls(popular=beacon.popular, classes={k: set(v) for k, v in beacon.classes.items()},
                   dev=det.DevProfile(set(beacon.dev.hosts), beacon.dev.domains),
                   expected={k: set(v) for k, v in beacon.expected.items()}, beacon_reported=dict(beacon.reported),
                   ident=ident, assets=p.assets, asn=next((d.asn for d in p.detectors if getattr(d, "asn", None)), None))

    @classmethod
    def from_config(cls, cfg: dict, store) -> Context:
        """For `tapwatch longhaul`: the same inputs, from the config and the alerter's saved state."""
        # function-level: config pulls in the notifiers and the triage client
        from . import config, history
        from .feeds import AsnTable

        b = (cfg.get("detectors") or {}).get("beaconing") or {}
        classes = {k: set(v) for k, v in det.BEACON_CLASSES.items()}
        for k, v in (b.get("benign_classes") or {}).items():
            classes.setdefault(k, set()).update(v or ())
        devp = cfg.get("dev_profile") or {}
        ident = det.Identity()
        ident.restore(history.identity_state(store))
        reported: dict = {}
        row = store.db.execute("SELECT data FROM detector_state WHERE name='beaconing'").fetchone()
        if row:
            try:
                reported = det.decode(json.loads(row[0]).get("reported") or {})
            except (ValueError, AttributeError):
                reported = {}
        return cls(popular=config.popular_domains(cfg), classes=classes,
                   dev=det.DevProfile(devp.get("hosts") or (), devp.get("domains") or ()),
                   expected=det._expected_services((cfg.get("detectors") or {}).get("takeover") or {}),
                   beacon_reported=reported if isinstance(reported, dict) else {}, ident=ident,
                   assets=config.assets(cfg), asn=AsnTable.load(cfg.get("asn_file")))

    def device(self, device: str) -> tuple[str, list[str], dict]:
        """(address for the case, every address known for it, identity facts) for a summary's device key."""
        ips = [device] if not device.startswith(("name:", "mac:")) else self.ident.ips_for(device)
        host = self.ident.ip_for(device) if device.startswith(("name:", "mac:")) else device
        facts: dict = {}
        mac = device[4:] if device.startswith("mac:") else next((m for ip in ips if (m := self.ident.mac_for(ip))), "")
        if mac:
            facts["device_mac"] = mac
        if device.startswith("name:"):
            facts["device_name"] = next((n for ip in ips if (n := self.ident.hostname_for(ip))), device[5:])
        return host, ips, facts

    def class_for(self, dest: str) -> str | None:
        return next((c for c, doms in self.classes.items() if det.suffix_match(dest, doms)), None)

    def entry(self, host: str, facts: dict) -> dict | None:
        return self.assets.entry(host, facts) if self.assets is not None else None


@dataclass
class Result:
    cases: list = field(default_factory=list)
    skipped: Counter = field(default_factory=Counter)     # why candidates were not raised (the measurement)
    devices: int = 0
    mature: int = 0
    days: int = 0


# ------------------------------------------------------------------ history


def watched(db) -> list[str]:
    """Summarized days on which the sensor saw traffic in WATCHED_HOURS or more local hours, oldest first."""
    return [r[0] for r in db.execute("SELECT day FROM summary_days WHERE hours >= ? ORDER BY day", (WATCHED_HOURS,))]


def maturity(db, days: list[str]) -> dict[str, int]:
    """Device -> watched days since its first summarized day."""
    out = {}
    for dev, first in db.execute("SELECT device, MIN(day) FROM device_day GROUP BY device"):
        out[dev] = sum(1 for d in days if d >= first)
    return out


def raised(db, detector: str, device: str, dest: str, ts: float) -> bool:
    """This rule already raised this (device, destination) in the last ONCE_DAYS."""
    return db.execute("SELECT 1 FROM cases WHERE detector=? AND first_ts>=? AND json_extract(facts, '$.device')=?"
                      " AND json_extract(facts, '$.dest')=? LIMIT 1",
                      (detector, ts - ONCE_DAYS * DAY, device, dest)).fetchone() is not None


@dataclass
class Recent:
    id: int
    detector: str
    host: str
    device: str
    route: str
    reason: str
    names: set
    addrs: set


def recent_cases(db, ts: float) -> list[Recent]:
    """Cases first raised in the BACKING_DAYS before ts: what can back a long-horizon case up."""
    out = []
    for r in db.execute("SELECT id, detector, host, route, reason, facts, indicators FROM cases"
                        " WHERE first_ts BETWEEN ? AND ?", (ts - BACKING_DAYS * DAY, ts)):
        try:
            facts, inds = json.loads(r[5] or "{}"), json.loads(r[6] or "[]")
        except ValueError:
            continue
        names = {det.base_domain(i.split(":")[0]) for i in inds if isinstance(i, str) and is_name(i.split(":")[0])}
        out.append(Recent(r[0], r[1], r[2], device_id(r[2], facts), r[3] or "", r[4] or "", names,
                          set(facts.get("dests") or ())))
    return out


def backers(recent: list[Recent], device: str, ips: list[str], dest: str, asn: int | None, ctx: Context) -> list[dict]:
    """Other cases on the same device that back a long-horizon case up (#194's routing), loudest first."""
    out = []
    for r in recent:
        # The address only for a case keyed by a bare address (no MAC or name then): the address map is today's, and a
        # case from days ago on an address DHCP has since handed to this device is another device's (review of #324)
        same = r.device == device or (r.device == r.host and r.host in ips)
        if r.detector in LONG_HORIZON or r.reason.startswith("suppressed:") or not same:
            continue
        if r.detector == "ioc_match":
            why = "a threat-list hit"
        elif r.route not in ("digest", "alert"):
            continue
        elif r.detector in hostrules.NAMES and r.detector != "vuln_kev":
            # digest or louder only: on the dev PC a logged host case (the owner's agent work) comes every few hours
            why = "a case from the PC's own agent"
        elif dest in r.names or dest in r.addrs:
            # the same name or the same address. Not the same network: R31's unnamed targets are whole networks
            # ("AS16509"), and AWS, Google and Cloudflare host everyone (review of #324)
            why = "a case to the same destination"
        else:
            continue
        out.append({"id": r.id, "detector": r.detector, "route": r.route, "why": why})
    out.sort(key=lambda b: (b["route"] == "alert", b["id"]), reverse=True)
    return out[:3]


# ------------------------------------------------------------------ R30


def beats(times: list[float], spacing: float) -> list[float]:
    """First contacts at least `spacing` apart."""
    out: list[float] = []
    for t in sorted(times):
        if not out or t - out[-1] >= spacing:
            out.append(t)
    return out


def beacon_shape(gaps: list[float], rule: BeaconRule) -> dict | None:
    """R30's timing test: enough gaps over enough days, a median of 2 to 72 hours, and either steady (CV <= 0.2) or
    every gap a whole number of days apart within half an hour (a daily job whose clock drifts a little, or a day the
    device or the sensor was off), with no more missed days than beats."""
    if len(gaps) < rule.min_gaps or sum(gaps) < rule.min_span_days * DAY:
        return None
    med = statistics.median(gaps)
    if not rule.min_interval_h * 3600 <= med <= rule.max_interval_h * 3600:
        return None
    cv = statistics.pstdev(gaps) / statistics.mean(gaps)
    if cv <= rule.max_cv:
        return {"interval_s": round(med), "cv": round(cv, 3), "regularity": "steady"}
    days = [round(g / DAY) for g in gaps]
    if all(k >= 1 and abs(g - k * DAY) <= rule.day_slack_s for g, k in zip(gaps, days)) and sum(days) <= 2 * len(gaps):
        return {"interval_s": round(med), "cv": round(cv, 3), "regularity": "daily at the same time",
                "missed_days": sum(days) - len(gaps)}
    return None


def watched_gaps(kept: list[float], watched_days: set[str] | None, tz) -> list[float]:
    """Gaps between beats, leaving out any that spans a day the sensor didn't watch: one day the sensor was down
    adds a gap that breaks a 6-hour beat's steadiness for the month it stays in the window (review of #324)."""
    out = []
    for a, b in pairwise(kept):
        if watched_days is not None:
            d, last = datetime.fromtimestamp(a, tz).date(), datetime.fromtimestamp(b, tz).date()
            gap_days = []
            while d <= last:
                gap_days.append(d.isoformat())
                d += timedelta(days=1)
            if any(x not in watched_days for x in gap_days):
                continue
        out.append(b - a)
    return out


def slow_beacons(groups: dict, ctx: Context, rule: BeaconRule, res: Result,
                 watched_days: set[str] | None = None, tz=None) -> list[dict]:
    """Candidates per (device, dest): the best port's beat, after the benign skips."""
    best: dict[tuple, dict] = {}
    for (dev, dest, port), rows in groups.items():
        if len({r[0] for r in rows}) < 3 or dest == "other" or port < 0 or port in det.HOUSEKEEPING_UDP_PORTS:
            continue   # 4 days at 72 h gaps needs 3 days with contacts at least
        times = [t for r in rows for t in json.loads(r[5] or "[]")]
        kept = beats(times, rule.spacing_s)
        shape = beacon_shape(watched_gaps(kept, watched_days, tz), rule)
        if shape is None:
            continue
        host, ips, _ = ctx.device(dev)
        why = None
        if is_name(dest) and (cls := ctx.class_for(dest)):
            why = f"known class: {cls}"
        elif is_name(dest) and dest in ctx.popular:
            why = "popular destination"
        elif is_name(dest) and any(ctx.dev.covers(ip, dest) for ip in ips + [host]):
            why = "dev service on a dev host"
        elif is_name(dest) and any(det.suffix_match(dest, ctx.expected.get(ip, frozenset())) for ip in ips + [host]):
            why = "expected service (takeover.expected)"
        elif (dev, port, dest) in ctx.beacon_reported:
            why = "already reported by beaconing"
        if why:
            res.skipped[f"R30 {why}"] += 1
            continue
        asns = Counter(r[1] for r in rows if r[1] is not None)
        cand = {**shape, "dev": dev, "dest": dest, "port": port, "beats": len(kept),
                "span_days": round((kept[-1] - kept[0]) / DAY, 1), "days_seen": len({r[0] for r in rows}),
                "first_day": min(r[0] for r in rows), "last_day": max(r[0] for r in rows),
                "asn": asns.most_common(1)[0][0] if asns else None,
                "country": next((r[2] for r in rows if r[2]), None)}
        if (dev, dest) not in best or cand["beats"] > best[(dev, dest)]["beats"]:
            best[(dev, dest)] = cand
    return list(best.values())


# ------------------------------------------------------------------ R31


def target(dest: str, asn) -> str:
    """What R31 sums over: the base domain when named, else the network (rotating cloud addresses), else the address."""
    return dest if is_name(dest) or asn is None else f"AS{asn}"


def slow_uploads(rows: list, days: list[str], ctx: Context, rule: UploadRule, end: date, res: Result,
                 firsts: dict[str, str] | None = None) -> list[dict]:
    w0 = end - timedelta(days=rule.window_days - 1)
    p0 = w0 - timedelta(days=rule.prior_days)
    w0s, p0s, ends = w0.isoformat(), p0.isoformat(), end.isoformat()
    window_days = [(w0 + timedelta(days=i)).isoformat() for i in range(rule.window_days)]
    firsts = firsts or {}

    def baseline(dev: str) -> int:
        """Watched days before the window since this device was first summarized: a device that only appeared
        inside the window has never been seen sending anywhere, which isn't the same as "new" (review of #324)."""
        since = max(p0s, firsts.get(dev, p0s))
        return sum(1 for d in days if since <= d < w0s)

    daily: dict[tuple, Counter] = defaultdict(Counter)
    down: Counter = Counter()
    prior: Counter = Counter()
    users: dict[str, set] = defaultdict(set)
    nets: dict[tuple, Counter] = defaultdict(Counter)
    addrs: dict[tuple, set] = defaultdict(set)
    for dev, day, dest, port, asn, cc, out, inb, _ in rows:
        if dest == "other":
            continue
        key = (dev, target(dest, asn))
        if w0s <= day <= ends:
            daily[key][day] += out
            down[key] += inb
            users[key[1]].add(dev)
            nets[key][(asn, cc)] += out
            if not is_name(dest):
                addrs[key].add(dest)
        elif p0s <= day < w0s:
            prior[key] += out
    found = []
    for key, per_day in daily.items():
        dev, tgt = key
        up = sum(per_day.values())
        if up < rule.min_mb * 1e6:
            continue
        up_days = sorted(d for d, b in per_day.items() if b >= rule.day_mb * 1e6)
        ratio = up / max(down[key], 1)
        if len(up_days) < rule.min_days or max(per_day.values()) >= rule.spike_bytes or ratio < rule.min_ratio:
            continue
        if prior[key] >= rule.prior_mb * 1e6:
            res.skipped["R31 uploaded there before the window"] += 1
            continue
        if baseline(dev) < rule.baseline_days:
            res.skipped["R31 no baseline before the window to call it new"] += 1
            continue
        host, ips, _ = ctx.device(dev)
        asn, cc = nets[key].most_common(1)[0][0]
        why = None
        if is_name(tgt) and (det.sync_service(tgt) or det.suffix_match(tgt, det.SECURITY_TELEMETRY)):
            why = "sync service or security vendor"
        elif asn in det.HourlyProfile.SYNC_ASNS:
            why = "sync network (Apple, Microsoft, Dropbox, Backblaze)"
        elif is_name(tgt) and any(ctx.dev.covers(ip, tgt) for ip in ips + [host]):
            why = "dev service on a dev host"
        elif is_name(tgt) and tgt in ctx.popular and len(users[tgt] - {dev}) >= 1:
            why = "popular and used by other devices"
        if why:
            res.skipped[f"R31 {why}"] += 1
            continue
        found.append({"dev": dev, "dest": tgt, "asn": asn, "country": cc, "up": up, "down": down[key],
                      "ratio": round(ratio, 1), "up_days": len(up_days), "first_day": up_days[0],
                      "daily_mb": [round(per_day.get(d, 0) / 1e6, 1) for d in window_days],
                      "prior_mb": round(prior[key] / 1e6, 1), "peers": len(users[tgt] - {dev}),
                      "popular": tgt in ctx.popular, "addrs": sorted(addrs[key])[:8]})
    return found


# ------------------------------------------------------------------ cases


def evaluate(store, cfg: dict, ctx: Context, now: float | None = None, mature_days: int | None = None) -> Result:
    """Both rules over the summary tables as they stand. Reads only; the caller decides what to do with the cases."""
    db, now = store.db, time.time() if now is None else now
    sums = cfg.get("summaries") or {}
    need = int(mature_days if mature_days is not None else sums.get("mature_days", MATURE_DAYS))
    beacon, upload = _rule(BeaconRule, cfg, "slow_beacon"), _rule(UploadRule, cfg, "slow_upload")
    res = Result()
    days = watched(db)
    last = db.execute("SELECT MAX(day) FROM summary_days").fetchone()[0]
    if not last:
        return res
    end = date.fromisoformat(last)
    grown = maturity(db, days)
    res.days, res.devices = len(days), len(grown)
    mature = {d for d, n in grown.items() if n >= need}
    res.mature = len(mature)
    start = min(end - timedelta(days=beacon.days - 1), end - timedelta(days=upload.window_days + upload.prior_days - 1))
    rows = [r for r in db.execute("SELECT device, day, dest, port, asn, country, bytes_out, bytes_in, contact_times"
                                  " FROM device_day_dest WHERE day >= ? AND day <= ?", (start.isoformat(), last))
            if r[0] in mature]
    b0 = (end - timedelta(days=beacon.days - 1)).isoformat()
    groups: dict[tuple, list] = defaultdict(list)
    for dev, day, dest, port, asn, cc, _, _, times in rows:
        if day >= b0:
            groups[(dev, dest, port)].append((day, asn, cc, None, None, times))
    recent = recent_cases(db, now)
    firsts = dict(db.execute("SELECT device, MIN(day) FROM device_day GROUP BY device").fetchall())
    for c in slow_beacons(groups, ctx, beacon, res, set(days), history.zone(cfg)):
        case = beacon_case(c, ctx, now, grown[c["dev"]], recent)
        if raised(db, case.detector, c["dev"], c["dest"], now):
            res.skipped["R30 raised in the last 30 days"] += 1
        else:
            res.cases.append(case)
    for c in slow_uploads(rows, days, ctx, upload, end, res, firsts):
        case = upload_case(c, ctx, now, grown[c["dev"]], upload, recent)
        if raised(db, case.detector, c["dev"], c["dest"], now):
            res.skipped["R31 raised in the last 30 days"] += 1
        else:
            res.cases.append(case)
    return res


def _base_facts(c: dict, ctx: Context, matured: int, recent: list[Recent]) -> tuple[str, dict]:
    host, ips, ident = ctx.device(c["dev"])
    facts = {"source": "history", "device": c["dev"], "dest": c["dest"], "asn": c["asn"], "country": c["country"],
             "mature_days": matured, **ident}
    backed = backers(recent, c["dev"], ips + [host], c["dest"], c["asn"], ctx)
    if backed:
        facts["backed_by"] = backed
    return host, facts


def beacon_case(c: dict, ctx: Context, now: float, matured: int, recent: list[Recent]) -> Case:
    host, facts = _base_facts(c, ctx, matured, recent)
    facts.update({"port": c["port"], "interval_s": c["interval_s"], "cv": c["cv"], "regularity": c["regularity"],
                  "beats": c["beats"], "span_days": c["span_days"], "days_seen": c["days_seen"],
                  "first_day": c["first_day"], "last_day": c["last_day"], "dedupe": f"{c['dest']}:{c['port']}",
                  **({"missed_days": c["missed_days"]} if "missed_days" in c else {}),
                  **det.dests(c["dest"])})
    named = is_name(c["dest"])
    return Case("slow_beacon", host, now, "Steady check-ins to one outside host, hours apart, for days",
                facts, [c["dest"]] if named else [], base_severity=3)


def upload_case(c: dict, ctx: Context, now: float, matured: int, rule: UploadRule, recent: list[Recent]) -> Case:
    host, facts = _base_facts(c, ctx, matured, recent)
    entry = ctx.entry(host, facts)
    facts.update({"mb": round(c["up"] / 1e6), "down_mb": round(c["down"] / 1e6, 1), "ratio": c["ratio"],
                  "upload_days": c["up_days"], "window_days": rule.window_days, "first_day": c["first_day"],
                  "daily_mb": c["daily_mb"], "prior_mb": c["prior_mb"], "prior_days": rule.prior_days,
                  "peers": c["peers"], "popular": c["popular"], "dedupe": c["dest"], **det.dests(*c["addrs"])})
    severity = 3
    if fixed := _role(entry, det.FIXED_ROLE_WORDS):
        facts["fixed_function"] = fixed
        severity = 4
    if managed := _role(entry, det.MANAGED_ROLE_WORDS):
        facts["managed_device"] = managed   # its employer's tooling watches it: digest at most, as upload_spike
        facts["max_route"] = "digest"
    return Case("slow_upload", host, now, "Slow, steady upload to a new destination over two weeks", facts,
                [c["dest"]] if is_name(c["dest"]) else [], base_severity=severity)


# ------------------------------------------------------------------ the run loop


def queue_into(q, cfg: dict, ctx: Context):
    """history.nightly's `then`: evaluate on the summary thread, queue the cases for the run loop (admit)."""
    def then(store):
        res = evaluate(store, cfg, ctx)
        log.info("long-horizon rules: %d case(s) from %d watched day(s), %d of %d device(s) mature",
                 len(res.cases), res.days, res.mature, res.devices)
        for case in res.cases:
            q.put(case)
    return then


def admit(p, case: Case):
    """On the main thread: the device's address now (a lease may have moved since the summary), then the pipeline."""
    dev = str(case.facts.get("device", ""))
    if p.identity is not None and dev.startswith(("name:", "mac:")) and (ip := p.identity.ip_for(dev)) != dev:
        case.host = ip
    return p.handle(case)


def describe(case: Case) -> str:
    """One line for `tapwatch longhaul` (the terminal only: it names the device and the destination)."""
    f = case.facts
    if case.detector == "slow_beacon":
        what = (f"every {f['interval_s'] / 3600:.1f} h ({f['regularity']}, cv {f['cv']}), {f['beats']} beats over "
                f"{f['span_days']} days, port {f['port']}")
    else:
        what = (f"{f['mb']} MB up over {f['upload_days']} days, ratio {f['ratio']}, peers {f['peers']}"
                + (f", {f['fixed_function']}" if f.get("fixed_function") else ""))
    backed = f" backed by #{f['backed_by'][0]['id']}" if f.get("backed_by") else ""
    return f"{case.detector:11} {f['device']:28} {f['dest']:32} {what}{backed}"
