"""Long-horizon rules over the daily summaries (#52): R30 slow beacon (#194), R31 low-and-slow upload (#195), R32
rare nameless destination (#196), R33 dormant device waking up (#197) and R34 routine shift (#198).

The windowed detectors decide within minutes to an hour. Beaconing needs ten beats in a window it holds in memory,
so a heartbeat every 6 or 24 hours is invisible to it, and upload_spike needs 500 MB in one hour, so 20 MB a day
never reaches it. These rules read the per-device daily summaries (history.py, store.DAILY_TABLES) instead of raw
logs, once a day:

  * R30 `slow_beacon`: one destination contacted at a steady interval of 2 to 72 hours for 4+ days (slow_beacons)
  * R31 `slow_upload`: 100+ MB uploaded to one destination over 14 days, a little on most days, never a spike,
    lopsided, and to a destination this device had not uploaded to in the 30 days before (slow_uploads)
  * R32 `rare_dest`: a network reached with no name that no other device in the house touched in 30 days, new to
    this device; or a fixed-function device reaching a country none of its same-role peers reached (rare_dests)
  * R33 `dormant_wake`: a device with 14+ active days goes 14+ watched days without a connection, then comes back
    talking to 3+ networks or a non-web port it never used before (dormant_wakes)
  * R34 `routine_shift`: a device's active hours, new-port share or daily bytes beyond its own 30-day normal on 3
    days in a row (routine_shifts)

A device's profile is mature after 14 watched days: summarized days on which the sensor saw traffic in at least 12
local hours (summary_days.hours), counted from the device's first summarized day. A quiet device keeps maturing; a
day the sensor was down does not count, since it says nothing about the device.

**Device keys change.** A device's key can move (`mac:` to `name:` once its DHCP name is learned, or a fix to how
connections are attributed), so R32 to R34 read a device's history under every key today's identity table ties to
the same MAC (`aliases`), and look for an earlier case under any of them. A key no alias reaches starts a new
history: it is not mature, so it can't fire, and in particular it can't look dormant or new.

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
destination (the same name or the same address, never just the same network). Then it is an alert. A suppression, a code
ceiling (a managed device) and the learning period still win, and the learned judge never takes a backed case.
"""

from __future__ import annotations

import json
import logging
import math
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
WEB_PORTS = frozenset({53, 80, 123, 443})   # R33, R34: a port outside these, new to the device, is a finding
RECENT_DAYS = 2        # R32, R33: days judged each night, the newest and the one before (rebuilt once settled)
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


# Voice, video and game traffic with no name (#196's expected false positives, `tls_odd`'s WebRTC addresses): Zoom's
# media ports, Teams/Skype media, Xbox Live, PlayStation, Steam's game and voice range, Discord RTC, WhatsApp/
# Messenger calls, FaceTime. R32 counts it under a skip reason instead of a case (measured: a long call on
# FaceTime's 16393/udp to a home ISP address was one of its two cases on the home data before this).
MEDIA_PORTS = frozenset({*range(8801, 8811), *range(3478, 3498), 3074, 3075, 3659, *range(9295, 9305),
                         *range(16384, 16404), *range(27000, 27101), *range(50000, 50101)})


@dataclass
class RareRule:
    """R32 thresholds (config `detectors.rare_dest`), from #196."""

    window_days: int = 30          # household prevalence and "new to this device" look back this far
    min_contacts: int = 3          # connections that day to the network, or ...
    min_mb: float = 1              # ... this much either way
    max_devices: int = 1           # devices that touched the network in the window (this one only)
    min_peers: int = 2             # the peer variant needs this many same-role fixed-function peers
    media: bool = True             # skip MEDIA_PORTS
    p2p_ports: int = 5             # this many remote ports above 1023 to the network in a day: a P2P peer, skipped


@dataclass
class WakeRule:
    """R33 thresholds (config `detectors.dormant_wake`), from #197."""

    history_days: int = 90         # summaries read for the profile before the quiet spell
    active_days: int = 14          # days with connections before the quiet spell: a profile to compare against
    quiet_days: int = 14           # watched days in a row with no connection (days the sensor didn't watch skipped)
    new_asns: int = 3              # networks never used before, or ...
    new_ports: int = 1             # ... ports never used before, off WEB_PORTS: TCP, or UDP under 1024 (_telling_key)
    house_devices: int = 2         # a name this many other devices used in the last 30 days is the house's, not new


@dataclass
class ShiftRule:
    """R34 thresholds (config `detectors.routine_shift`), from #198. The floors are from the home run's per-device
    score distributions (eval/RESULTS.md); each device's own leave-one-out maximum over its baseline raises them."""

    baseline_days: int = 30        # the normal: this many days before the last run_days
    run_days: int = 3              # a score beyond its threshold this many days in a row
    min_baseline_days: int = 7     # days with connections in the baseline
    hour_share: float = 0.25       # an hour is normal when the device was active in it on this share of baseline days
    hours_distance: float = 0.6    # Jaccard distance floor between a day's active hours and the normal ones
    new_share: float = 0.2         # floor on the share of a day's connections on ports/protocols new to the device
    bytes_z: float = 3.0           # floor on the z-score of log10(daily bytes), upward only
    z_std_floor: float = 0.1       # log10 std floor: a very steady device's 10% wobble is not 3 sigma
    once_days: int = 14


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
    seen: Counter = field(default_factory=Counter)        # what the rules looked at (R33's dormancy returns)
    wakes: set = field(default_factory=set)               # R33's (device, wake day) pairs, for a replay to count once
    scores: dict = field(default_factory=lambda: defaultdict(list))   # R34's daily scores, for --stats


@dataclass
class Device:
    """One device's history for R32 to R34, under every key it has had (aliases)."""

    canon: str
    keys: list            # the key seen last first: the one a case names
    first: str            # its first summarized day under any key
    matured: int          # watched days since then

    @property
    def key(self) -> str:
        return self.keys[0]


# ------------------------------------------------------------------ history


def watched(db, last: str = "9999-12-31") -> list[str]:
    """Summarized days on which the sensor saw traffic in WATCHED_HOURS or more local hours, oldest first."""
    return [r[0] for r in db.execute("SELECT day FROM summary_days WHERE hours >= ? AND day <= ? ORDER BY day",
                                     (WATCHED_HOURS, last))]


def firsts(db, last: str = "9999-12-31") -> dict[str, str]:
    """Device -> its first summarized day."""
    return dict(db.execute("SELECT device, MIN(day) FROM device_day WHERE day <= ? GROUP BY device", (last,)).fetchall())


def maturity(db, days: list[str], last: str = "9999-12-31") -> dict[str, int]:
    """Device -> watched days since its first summarized day."""
    return {dev: sum(1 for d in days if d >= first) for dev, first in firsts(db, last).items()}


def aliases(devices, ctx: Context) -> dict[str, str]:
    """Device key -> the key its history is read under: `mac:<address>` for a `name:` key whose DHCP name today's
    identity table gives to exactly one MAC, so the days a device spent as `mac:` before its name was learned (or
    before attribution changed) are its own history, not a new device's. Every other key is its own."""
    macs: dict[str, set] = defaultdict(set)
    for mac, name in ctx.ident.hostname.items():
        if name:
            macs[str(name).lower()].add(str(mac).lower())
    out = {}
    for dev in devices:
        one = macs.get(dev[5:], set()) if dev.startswith("name:") else set()
        out[dev] = f"mac:{next(iter(one))}" if len(one) == 1 else dev
    return out


def _span(day: str, back: int) -> str:
    return (date.fromisoformat(day) - timedelta(days=back)).isoformat()


def raised(db, detector: str, device, dest: str, ts: float, days: int = ONCE_DAYS) -> bool:
    """This rule already raised this (device, destination) in the last `days`. `device` is a key, or the keys one
    device has had (aliases), so a key that changed since doesn't raise the same thing again."""
    keys = [device] if isinstance(device, str) else list(device)
    # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query -- only '?' placeholders are joined; every value is bound
    return db.execute("SELECT 1 FROM cases WHERE detector=? AND first_ts>=? AND json_extract(facts, '$.device') IN"
                      f" ({','.join('?' * len(keys))}) AND json_extract(facts, '$.dest')=? LIMIT 1",
                      (detector, ts - days * DAY, *keys, dest)).fetchone() is not None


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


def backers(recent: list[Recent], device, ips: list[str], dest, asn: int | None, ctx: Context) -> list[dict]:
    """Other cases on the same device that back a long-horizon case up (#194's routing), loudest first. `device` is
    a key or the keys the device has had; `dest` one destination or several (R32's addresses, R33's new ones)."""
    out = []
    keys = {device} if isinstance(device, str) else set(device)
    wanted = {dest} if isinstance(dest, str) else set(dest or ())
    for r in recent:
        # The address only for a case keyed by a bare address (no MAC or name then): the address map is today's, and a
        # case from days ago on an address DHCP has since handed to this device is another device's (review of #324)
        same = r.device in keys or (r.device == r.host and r.host in ips)
        if r.detector in LONG_HORIZON or r.reason.startswith("suppressed:") or not same:
            continue
        if r.detector == "ioc_match":
            why = "a threat-list hit"
        elif r.route not in ("digest", "alert"):
            continue
        elif r.detector in hostrules.NAMES and r.detector != "vuln_kev":
            # digest or louder only: on the dev PC a logged host case (the owner's agent work) comes every few hours
            why = "a case from the PC's own agent"
        elif wanted & (r.names | r.addrs):
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
    for dev, day, dest, port, asn, cc, out, inb, *_ in rows:
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


# ------------------------------------------------------------------ R32


def role_word(entry: dict | None) -> str:
    """The FIXED_ROLE_WORDS word an assets.yaml role carries ("front camera" -> "camera"): R32's peer group."""
    role = str((entry or {}).get("role", "")).lower()
    return next((w for w in det.FIXED_ROLE_WORDS if re.search(rf"\b{re.escape(w)}\b", role)), "")


def _since(days: set, lo: str, hi: str) -> bool:
    """Any of `days` in [lo, hi)."""
    return any(lo <= d < hi for d in days)


def rare_dests(rows: list, devices: dict[str, Device], canon: dict[str, str], judged: list[str], mature: set,
               ctx: Context, rule: RareRule, res: Result) -> list[dict]:
    """R32 over the destination rows: per (device, network) reached with no name on a judged day, and per (fixed-
    function device, country) for the peer variant. "Used" means any connection, named or not, by any key the device
    has had; the media ports are left out of the volume, not out of "used"."""
    touched: dict = defaultdict(lambda: defaultdict(set))   # asn -> device -> days
    places: dict = defaultdict(lambda: defaultdict(set))    # device -> country -> days
    named: set = set()                                      # (device, day, asn) reached by a name that day
    nets: dict = {}                                         # (device, day, asn) -> volume with no name
    lands: dict = {}                                        # (device, day, country) -> volume, any name

    def add(table, key, conns, size, media, addr, port, cc, asn):
        v = table.setdefault(key, {"conns": 0, "bytes": 0, "media_conns": 0, "media_bytes": 0, "addrs": set(),
                                   "ports": Counter(), "cc": Counter(), "asn": Counter()})
        v["media_conns" if media else "conns"] += conns
        v["media_bytes" if media else "bytes"] += size
        if addr:
            v["addrs"].add(addr)
        v["ports"][port] += conns
        if cc:
            v["cc"][cc] += conns
        if asn is not None:
            v["asn"][asn] += conns

    for dev, day, dest, port, asn, cc, out, inb, _, conns in rows:
        c = canon.get(dev, dev)
        if asn is not None:
            touched[asn][c].add(day)
        if cc:
            places[c][cc].add(day)
        if day not in judged or dest == "other" or port in det.HOUSEKEEPING_UDP_PORTS:
            continue
        media = rule.media and port in MEDIA_PORTS
        name = is_name(dest)
        if cc:
            add(lands, (c, day, cc), conns, out + inb, media, None if name else dest, port, cc, asn)
        if asn is None:
            continue
        if name:
            named.add((c, day, asn))
        else:
            add(nets, (c, day, asn), conns, out + inb, media, dest, port, cc, asn)

    def loud(v) -> str:
        """'' when the volume passes, else why not."""
        if v["conns"] >= rule.min_contacts or v["bytes"] >= rule.min_mb * 1e6:
            return ""
        if v["media_conns"] >= rule.min_contacts or v["media_bytes"] >= rule.min_mb * 1e6:
            return "R32 voice, video or game ports"
        return f"R32 under {rule.min_contacts} connections and {rule.min_mb:g} MB"

    found = []
    for (c, day, asn), v in sorted(nets.items(), key=lambda kv: (kv[0][0], kv[0][1], kv[0][2])):
        lo = _span(day, rule.window_days)
        if c not in mature or _since(touched[asn][c], lo, day):
            continue   # immature, or this device used the network in the window: not new to it
        if (c, day, asn) in named:
            res.skipped["R32 reached by name the same day"] += 1
            continue
        users = {o for o, ds in touched[asn].items() if _since(ds, lo, _span(day, -1))}
        if len(users) > rule.max_devices:
            res.skipped["R32 other devices use the network"] += 1
            continue
        if why := loud(v):
            res.skipped[why] += 1
            continue
        if len({p for p in v["ports"] if p >= 1024}) >= rule.p2p_ports:
            # a peer-to-peer game or VPN peer: one home address reached on a new port each session. A C2 server
            # listens on one or two ports (measured: 470 connections on scattered ports to one ISP address)
            res.skipped[f"R32 peer-to-peer shape ({rule.p2p_ports}+ ports above 1023)"] += 1
            continue
        found.append({"rule": "R32", "detector": "rare_dest", "canon": c, "variant": "network", "day": day,
                      "dest": f"AS{asn}", "asn": asn, "country": v["cc"].most_common(1)[0][0] if v["cc"] else None,
                      "conns": v["conns"], "bytes": v["bytes"], "ports": [p for p, _ in v["ports"].most_common(5)],
                      "addrs": sorted(v["addrs"])[:8], "devices": len(users)})

    roles = {}
    for c, d in devices.items():
        host, _, facts = ctx.device(d.key)
        roles[c] = role_word(ctx.entry(host, facts))
    for (c, day, cc), v in sorted(lands.items(), key=lambda kv: (kv[0][0], kv[0][1], kv[0][2])):
        word = roles.get(c)
        if not word or c not in mature:
            continue
        lo = _span(day, rule.window_days)
        if _since(places[c][cc], lo, day):
            continue
        peers = [o for o, w in roles.items() if w == word and o != c]
        if len(peers) < rule.min_peers:
            res.skipped["R32 peer variant: fewer than 2 same-role peers"] += 1
            continue
        if any(_since(places[o][cc], lo, _span(day, -1)) for o in peers):
            res.skipped["R32 peer variant: a peer reached the country"] += 1
            continue
        if why := loud(v):
            res.skipped[why] += 1
            continue
        found.append({"rule": "R32", "detector": "rare_dest", "canon": c, "variant": "peer", "day": day,
                      "dest": f"country:{cc}", "asn": v["asn"].most_common(1)[0][0] if v["asn"] else None,
                      "country": cc, "conns": v["conns"], "bytes": v["bytes"],
                      "ports": [p for p, _ in v["ports"].most_common(5)], "addrs": sorted(v["addrs"])[:8],
                      "peers": len(peers), "role_word": word})
    return found


# ------------------------------------------------------------------ R33


def dormant_wakes(db, daily: dict, rows: list, devices: dict[str, Device], canon: dict[str, str], days: list[str],
                  judged: list[str], last: str, ctx: Context, rule: WakeRule, res: Result) -> list[dict]:
    """R33: a device's first active day after `quiet_days` watched days without a connection, on a judged day.
    Quiet is counted in watched days only: a day the sensor was down or half-blind neither counts towards the quiet
    spell nor breaks it, so an outage never makes a device dormant. A device's first appearance has no day before it,
    so it is never a return. Its first 24 hours back (the wake day and the next, when summarized) are compared with
    everything it did before the quiet spell, under every key it has had."""
    found = []
    hist0 = _span(last, rule.history_days)
    for c, dev in devices.items():
        active = sorted(daily.get(c, {}))
        for w in (d for d in active if d in judged):
            prev = max((d for d in active if d < w), default=None)
            if prev is None:
                continue   # its first day (or first under any key): new, not back
            quiet = [d for d in days if prev < d < w]
            if len(quiet) < rule.quiet_days:
                continue
            res.seen["R33 dormancy returns"] += 1
            res.wakes.add((c, w))
            before = [d for d in active if hist0 <= d <= prev]
            if len(before) < rule.active_days:
                res.skipped[f"R33 fewer than {rule.active_days} active days before the quiet spell"] += 1
                continue
            back = {w, _span(w, -1)}
            # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query -- only '?' placeholders are joined; every value is bound
            mine = db.execute("SELECT day, dest, port, asn, country FROM device_day_dest WHERE day >= ? AND day <= ?"
                              f" AND device IN ({','.join('?' * len(dev.keys))})", (hist0, last, *dev.keys)).fetchall()
            pre = [r for r in mine if r[0] <= prev]
            pre_asns = {r[3] for r in pre if r[3] is not None}
            pre_names = {r[1] for r in pre if is_name(r[1])}
            pre_ports = {r[2] for r in pre}
            lo = _span(w, 30)
            house: dict[str, set] = defaultdict(set)
            for o, day, dest, *_ in rows:
                if day >= lo and is_name(dest) and canon.get(o, o) != c:
                    house[dest].add(canon.get(o, o))
            new_asns, new_ports, names, addrs, dropped = set(), set(), set(), set(), Counter()
            for day, dest, port, asn, cc in mine:
                if day not in back or dest == "other":
                    continue
                if is_name(dest):
                    if dest in pre_names:
                        continue
                    if dest in ctx.popular or ctx.class_for(dest):
                        dropped["popular or a known service"] += 1
                        continue
                    if len(house[dest]) >= rule.house_devices:
                        dropped["used by other devices in the house"] += 1
                        continue
                if asn is not None and asn not in pre_asns:
                    new_asns.add(asn)
                # the destination rows carry no protocol; the day's port counts do ("22/tcp")
                tcp = f"{port}/tcp" in daily.get(c, {}).get(day, [0, 0, 0, 0, {}])[4]
                if port >= 0 and port not in pre_ports and _telling_key(f"{port}/{'tcp' if tcp else 'udp'}"):
                    new_ports.add(port)
                if (asn is not None and asn not in pre_asns) or port in new_ports:
                    (names if is_name(dest) else addrs).add(dest)
            if len(new_asns) < rule.new_asns and len(new_ports) < rule.new_ports:
                res.skipped["R33 back, but nothing new enough"] += 1
                continue
            found.append({"rule": "R33", "detector": "dormant_wake", "canon": c, "dest": f"wake:{w}", "day": w,
                          "last_active": prev, "quiet_days": len(quiet),
                          "quiet_calendar_days": (date.fromisoformat(w) - date.fromisoformat(prev)).days - 1,
                          "active_before": len(before), "new_asns": sorted(new_asns)[:8], "new_ports": sorted(new_ports)[:8],
                          "names": sorted(names)[:8], "addrs": sorted(addrs)[:8], "dropped": dict(dropped)})
    return found


# ------------------------------------------------------------------ R34


def _hours(bits: int) -> set:
    return {h for h in range(24) if bits >> h & 1}


def normal_hours(base: list[list], share: float) -> set:
    """Hours the device was active in on at least `share` of its baseline days."""
    counts = Counter(h for row in base for h in _hours(row[3]))
    return {h for h, n in counts.items() if n >= share * len(base)}


def hours_distance(bits: int, normal: set) -> float:
    a = _hours(bits)
    union = a | normal
    return round(1 - len(a & normal) / len(union), 3) if union else 0.0


def new_share(row: list, base: list[list]) -> tuple[float, list[str]]:
    """Share of the day's connections on ports, or Zeek protocols, the device used on no baseline day; and those."""
    ports = {k for b in base for k in b[4]}
    protos = {p for b in base for k in b[5] for p in k.split(",")}   # Zeek writes "quic,ssl" and "ssl,quic" alike
    new_p = {k: n for k, n in row[4].items() if k != "other" and k not in ports}
    new_s: Counter = Counter()
    for k, n in row[5].items():
        for p in set(k.split(",")) - protos:
            new_s[p] += n
    total = max(row[0], 1)
    share = max(sum(new_p.values()), max(new_s.values(), default=0)) / total
    keys = sorted(new_p, key=lambda k: -new_p[k]) + sorted(new_s, key=lambda k: -new_s[k])
    return round(min(share, 1.0), 3), keys


def bytes_z(row: list, base: list[list], floor: float) -> float:
    xs = [math.log10(b[1] + b[2] + 1) for b in base]
    sd = max(statistics.pstdev(xs), floor)
    return round((math.log10(row[1] + row[2] + 1) - statistics.mean(xs)) / sd, 2)


def _scores(row: list, base: list[list], rule: ShiftRule) -> dict[str, float]:
    return {"hours": hours_distance(row[3], normal_hours(base, rule.hour_share)),
            "new_ports": new_share(row, base)[0], "bytes": bytes_z(row, base, rule.z_std_floor)}


def routine_shifts(daily: dict, devices: dict[str, Device], days: list[str], end: date, mature: set, ctx: Context,
                   rule: ShiftRule, res: Result) -> list[dict]:
    """R34: per mature device, its last `run_days` days each scored against the `baseline_days` before them (watched
    days with connections only). A score's threshold is its floor, or the device's own highest leave-one-out score
    over the baseline when that is higher (each baseline day against the others), so a device whose hours always
    wander needs a bigger move than a camera's. Fires when one score is beyond its threshold on every run day. A
    fixed-function device also fires when one port or protocol it never used appears on every run day (a TV
    starting to speak SSH is a handful of connections among thousands, never a share)."""
    watched_set = set(days)
    run = [(end - timedelta(days=n)).isoformat() for n in range(rule.run_days - 1, -1, -1)]
    b_lo = (end - timedelta(days=rule.run_days + rule.baseline_days - 1)).isoformat()
    floors = {"hours": rule.hours_distance, "new_ports": rule.new_share, "bytes": rule.bytes_z}
    found = []
    for c, dev in devices.items():
        if c not in mature:
            continue
        mine = daily.get(c, {})
        if not all(d in mine and d in watched_set for d in run):
            res.skipped["R34 not active on every run day"] += 1
            continue
        base_days = sorted(d for d in mine if b_lo <= d < run[0] and d in watched_set)
        if len(base_days) < rule.min_baseline_days:
            res.skipped[f"R34 fewer than {rule.min_baseline_days} baseline days"] += 1
            continue
        base = [mine[d] for d in base_days]
        loo: dict[str, float] = defaultdict(float)
        for i, row in enumerate(base):
            for k, v in _scores(row, base[:i] + base[i + 1:], rule).items():
                loo[k] = max(loo[k], v)
        thresholds = {k: round(max(floors[k], loo[k]), 3) for k in floors}
        per_day = [_scores(mine[d], base, rule) for d in run]
        for k in floors:
            res.scores[k].append(per_day[-1][k])
        res.scores["thresholds"].append(thresholds)
        shifts = [{"score": k, "values": [s[k] for s in per_day], "threshold": thresholds[k]}
                  for k in floors if all(s[k] > thresholds[k] for s in per_day)]
        host, _, facts = ctx.device(dev.key)
        fixed = _role(ctx.entry(host, facts), det.FIXED_ROLE_WORDS)
        news = [set(new_share(mine[d], base)[1]) for d in run]
        steady_new = sorted(k for k in set.intersection(*news) if _telling_key(k))
        if fixed and steady_new and not any(s["score"] == "new_ports" for s in shifts):
            shifts.append({"score": "new_port_every_day", "keys": steady_new[:5]})
        if not shifts:
            continue
        normal = normal_hours(base, rule.hour_share)
        found.append({"rule": "R34", "detector": "routine_shift", "canon": c, "dest": "routine", "day": run[-1],
                      "once_days": rule.once_days, "shifts": shifts, "run": run, "baseline_days": len(base),
                      "normal_hours": sorted(normal), "run_hours": sorted(set().union(*(_hours(mine[d][3]) for d in run))),
                      "new_keys": sorted(set().union(*news))[:8],
                      "daily_mb": [round((mine[d][1] + mine[d][2]) / 1e6, 1) for d in run],
                      "baseline_mb": round(statistics.median(b[1] + b[2] for b in base) / 1e6, 1)})
    return found


def _telling_key(key: str) -> bool:
    """A new port or protocol worth a case on a fixed-function device: a Zeek protocol other than the web's ("ssh"),
    or a TCP port, or a UDP port under 1024, off the web ports. As IotDrift: a UDP port above 1023 is peer-to-peer
    and media traffic's, a new one every session (measured: a busy device's P2P peer on a new high UDP port for
    three days running)."""
    port, _, proto = key.partition("/")
    if not port.isdigit():
        # web, time, address and "no idea" protocols; ayiya is Zeek misreading QUIC (common in the home data)
        return key not in ("ssl", "http", "dns", "quic", "ntp", "dhcp", "unknown", "dtls", "stun", "ayiya")
    n = int(port)
    return n not in WEB_PORTS and (proto == "tcp" or n < 1024) and n not in det.HOUSEKEEPING_UDP_PORTS


# ------------------------------------------------------------------ cases


def devices_from(db, days: list[str], last: str, ctx: Context) -> tuple[dict[str, Device], dict[str, str]]:
    """Canonical device -> its history's keys, first day and maturity; and key -> canonical device (aliases)."""
    spans = {r[0]: (r[1], r[2]) for r in db.execute("SELECT device, MIN(day), MAX(day) FROM device_day WHERE day <= ?"
                                                     " GROUP BY device", (last,))}
    canon = aliases(spans, ctx)
    members: dict[str, list] = defaultdict(list)
    for key, c in canon.items():
        members[c].append(key)
    out = {}
    for c, keys in members.items():
        keys.sort(key=lambda k: (spans[k][1], k.startswith("name:"), k), reverse=True)   # the key seen last first
        first = min(spans[k][0] for k in keys)
        out[c] = Device(c, keys, first, sum(1 for d in days if d >= first))
    return out, canon


def daily_rows(db, canon: dict[str, str], since: str, last: str) -> dict[str, dict[str, list]]:
    """Canonical device -> day -> [conns, bytes out, bytes in, hours bitmap, ports Counter, protocols Counter], the
    device's keys summed (one device seen under two keys on its renaming day)."""
    out: dict[str, dict[str, list]] = defaultdict(dict)
    for dev, day, conns, up, down, bits, ports, protos in db.execute(
            "SELECT device, day, conns, bytes_out, bytes_in, active_hours_bitmap, ports, protocols FROM device_day"
            " WHERE day >= ? AND day <= ?", (since, last)):
        if not conns:
            continue
        row = out[canon.get(dev, dev)].setdefault(day, [0, 0, 0, 0, Counter(), Counter()])
        row[0] += conns
        row[1] += up
        row[2] += down
        row[3] |= bits
        try:
            row[4].update(json.loads(ports or "{}"))
            row[5].update(json.loads(protos or "{}"))
        except (ValueError, TypeError):
            pass
    return out


def evaluate(store, cfg: dict, ctx: Context, now: float | None = None, mature_days: int | None = None,
             as_of: str | None = None) -> Result:
    """Every long-horizon rule over the summary tables as they stand (up to `as_of`, a day, for a replay). Reads only;
    the caller decides what to do with the cases."""
    db = store.db
    sums = cfg.get("summaries") or {}
    need = int(mature_days if mature_days is not None else sums.get("mature_days", MATURE_DAYS))
    beacon, upload = _rule(BeaconRule, cfg, "slow_beacon"), _rule(UploadRule, cfg, "slow_upload")
    rare, wake = _rule(RareRule, cfg, "rare_dest"), _rule(WakeRule, cfg, "dormant_wake")
    shift = _rule(ShiftRule, cfg, "routine_shift")
    res = Result()
    last = db.execute("SELECT MAX(day) FROM summary_days WHERE day <= ?", (as_of or "9999-12-31",)).fetchone()[0]
    if not last:
        return res
    end, tz = date.fromisoformat(last), history.zone(cfg)
    if now is None:   # a replay is judged the night after its last day, as the nightly run would have
        now = time.time() if as_of is None else history.bounds(end + timedelta(days=1), tz)[0] + 4 * 3600
    days = watched(db, last)
    grown = maturity(db, days, last)
    res.days, res.devices = len(days), len(grown)
    mature = {d for d, n in grown.items() if n >= need}
    res.mature = len(mature)
    start = end - timedelta(days=max(beacon.days - 1, upload.window_days + upload.prior_days - 1,
                                     rare.window_days + RECENT_DAYS, 31))
    every = db.execute("SELECT device, day, dest, port, asn, country, bytes_out, bytes_in, contact_times, conns"
                       " FROM device_day_dest WHERE day >= ? AND day <= ?", (start.isoformat(), last)).fetchall()
    rows = [r for r in every if r[0] in mature]
    b0 = (end - timedelta(days=beacon.days - 1)).isoformat()
    groups: dict[tuple, list] = defaultdict(list)
    for dev, day, dest, port, asn, cc, _, _, times, _ in rows:
        if day >= b0:
            groups[(dev, dest, port)].append((day, asn, cc, None, None, times))
    recent = recent_cases(db, now)
    for c in slow_beacons(groups, ctx, beacon, res, set(days), tz):
        case = beacon_case(c, ctx, now, grown[c["dev"]], recent)
        if raised(db, case.detector, c["dev"], c["dest"], now):
            res.skipped["R30 raised in the last 30 days"] += 1
        else:
            res.cases.append(case)
    for c in slow_uploads(rows, days, ctx, upload, end, res, firsts(db, last)):
        case = upload_case(c, ctx, now, grown[c["dev"]], upload, recent)
        if raised(db, case.detector, c["dev"], c["dest"], now):
            res.skipped["R31 raised in the last 30 days"] += 1
        else:
            res.cases.append(case)

    devices, canon = devices_from(db, days, last, ctx)
    grown_up = {c for c, d in devices.items() if d.matured >= need}
    judged = [(end - timedelta(days=n)).isoformat() for n in range(RECENT_DAYS - 1, -1, -1)]
    found = rare_dests(every, devices, canon, judged, grown_up, ctx, rare, res)
    since = (end - timedelta(days=max(wake.history_days, shift.baseline_days + shift.run_days))).isoformat()
    daily = daily_rows(db, canon, since, last)
    found += dormant_wakes(db, daily, every, devices, canon, days, judged, last, ctx, wake, res)
    found += routine_shifts(daily, devices, days, end, grown_up, ctx, shift, res)
    for c in found:
        dev = devices[c["canon"]]
        case = history_case(c, dev, ctx, now, recent)
        if raised(db, case.detector, dev.keys, c["dest"], now, c.get("once_days", ONCE_DAYS)):
            res.skipped[f"{c['rule']} raised in the last {c.get('once_days', ONCE_DAYS)} days"] += 1
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


def history_case(c: dict, dev: Device, ctx: Context, now: float, recent: list[Recent]) -> Case:
    """An R32, R33 or R34 case. Severity 2, 3 on a fixed-function device (and for R32's peer variant); a managed
    device is capped at digest, as R31: its employer's tooling makes new networks, ports and hours on its own."""
    host, ips, ident = ctx.device(dev.key)
    facts = {"source": "history", "device": dev.key, "dest": c["dest"], "day": c["day"], "mature_days": dev.matured,
             **ident}
    if len(dev.keys) > 1:
        facts["device_keys"] = dev.keys[:5]
    entry = ctx.entry(host, facts)
    severity = 2
    if fixed := _role(entry, det.FIXED_ROLE_WORDS):
        facts["fixed_function"] = fixed
        severity = 3
    if managed := _role(entry, det.MANAGED_ROLE_WORDS):
        facts["managed_device"] = managed
        facts["max_route"] = "digest"
    names = c.get("names") or []
    backed = backers(recent, dev.keys, ips + [host], set(c.get("addrs") or ()) | set(names), None, ctx)
    if backed:
        facts["backed_by"] = backed
    if c["detector"] == "rare_dest":
        facts.update({"variant": c["variant"], "asn": c["asn"], "country": c["country"], "conns": c["conns"],
                      "mb": round(c["bytes"] / 1e6, 1), "ports": c["ports"], "household_devices": c.get("devices"),
                      "peers": c.get("peers"), "role_word": c.get("role_word"), "dedupe": c["dest"],
                      **det.dests(*c["addrs"])})
        if c["variant"] == "peer":
            return Case("rare_dest", host, now, "A fixed-function device reached a country none of its peers use",
                        facts, [], base_severity=3)
        return Case("rare_dest", host, now, "A network no other device in the house uses, reached with no name",
                    facts, [], base_severity=severity)
    if c["detector"] == "dormant_wake":
        facts.update({k: c[k] for k in ("last_active", "quiet_days", "quiet_calendar_days", "active_before",
                                        "new_asns", "new_ports", "dropped")})
        facts.update({"new_names": names, "dedupe": c["dest"], **det.dests(*c["addrs"])})
        return Case("dormant_wake", host, now, "A device quiet for weeks came back talking somewhere new", facts,
                    list(names), base_severity=severity)
    facts.update({k: c[k] for k in ("shifts", "run", "baseline_days", "normal_hours", "run_hours", "new_keys",
                                    "daily_mb", "baseline_mb")})
    facts["dedupe"] = c["dest"]
    return Case("routine_shift", host, now, "A device's daily routine moved off its own 30-day normal", facts, [],
                base_severity=severity)


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
    elif case.detector == "slow_upload":
        what = (f"{f['mb']} MB up over {f['upload_days']} days, ratio {f['ratio']}, peers {f['peers']}"
                + (f", {f['fixed_function']}" if f.get("fixed_function") else ""))
    elif case.detector == "rare_dest":
        what = (f"{f['variant']} on {f['day']}: {f['conns']} conns, {f['mb']} MB, ports {f['ports']}, "
                + (f"{f['peers']} {f['role_word']} peers" if f["variant"] == "peer" else f"AS{f['asn']} {f['country']}"))
    elif case.detector == "dormant_wake":
        what = (f"back {f['day']} after {f['quiet_days']} watched quiet days ({f['active_before']} active before): "
                f"{len(f['new_asns'])} new networks, new ports {f['new_ports']}")
    else:
        what = "; ".join(f"{s['score']} {s.get('values', s.get('keys'))} > {s.get('threshold', '-')}"
                         for s in f["shifts"])
    backed = f" backed by #{f['backed_by'][0]['id']}" if f.get("backed_by") else ""
    return f"{case.detector:13} {f['device']:28} {f['dest']:32} {what}{backed}"
