"""Long-horizon rules over the daily summaries (#52): R30 slow beacon (#194), R31 low-and-slow upload (#195),
their routing (router.long_horizon), the judge guardrail (#201) and the nightly hook."""

import json
import queue
import random
from datetime import UTC, date, datetime, timedelta

import pytest

from tapwatch import cli, detectors, history, judge, longhaul
from tapwatch.models import Case, Route
from tapwatch.pipeline import Pipeline
from tapwatch.router import route
from tapwatch.store import Store
from tapwatch.summarizer import Assets

END = date(2026, 9, 30)
IP, MAC = "192.168.50.10", "02:00:00:00:00:0a"
DEV = f"mac:{MAC}"
PEER, PEER_MAC = "192.168.50.11", "02:00:00:00:00:0b"
H, DAY, MB = 3600, 86400, 1_000_000
NOW = datetime(END.year, END.month, END.day, tzinfo=UTC).timestamp() + 2 * DAY   # the night after END


def day(n_back: int) -> str:
    return (END - timedelta(days=n_back)).isoformat()


def midnight(d: str) -> float:
    return datetime.fromisoformat(d).replace(tzinfo=UTC).timestamp()


def summaries(store, days=30, hours=24, devices=(DEV,), low=()):
    """summary_days for the last `days` days to END (`low`: days the sensor saw only 4 hours), each device present."""
    for n in range(days):
        d = day(n)
        store.db.execute("INSERT INTO summary_days VALUES (?,?,?,?,?,?)", (d, len(devices), 100, 4 if d in low else hours,
                                                                            NOW, 1.0))
        for dev in devices:
            store.db.execute("INSERT OR REPLACE INTO device_day VALUES (?,?,?,?,?,?,?,?)",
                             (dev, d, 1, 0, 0, 1, "{}", "{}"))
    store.db.commit()


def put(store, d, dest, port=443, out=0, inb=0, times=(), dev=DEV, asn=None, cc=None):
    store.db.execute("INSERT OR REPLACE INTO device_day_dest VALUES (?,?,?,?,?,?,?,?,?,?)",
                     (dev, d, dest, port, asn, cc, max(1, len(times)), out, inb, json.dumps([int(t) for t in times])))
    store.db.commit()


def heartbeat(store, dest, every_h, days, port=443, dev=DEV, jitter=0.0, seed=1):
    """Contacts every `every_h` hours over the last `days` days, filed under the day each started."""
    rnd = random.Random(seed)
    t, stop = midnight(day(days - 1)) + 600, midnight(END.isoformat()) + DAY
    per_day: dict[str, list] = {}
    while t < stop:
        s = t + rnd.uniform(-jitter, jitter)
        per_day.setdefault(datetime.fromtimestamp(s, UTC).date().isoformat(), []).append(s)
        t += every_h * H
    for d, times in per_day.items():
        put(store, d, dest, port, out=2000, inb=4000, times=history.contact_times(times), dev=dev)


def ctx(**kw):
    ident = detectors.Identity()
    ident.mac.update({IP: MAC, PEER: PEER_MAC})
    ident.last_ip.update({DEV: IP, f"mac:{PEER_MAC}": PEER})
    return longhaul.Context(ident=ident, assets=kw.pop("assets", Assets()), **kw)


@pytest.fixture
def store():
    s = Store(":memory:")
    summaries(s)
    return s


def run(store, c=None, cfg=None, **kw):
    return longhaul.evaluate(store, cfg or {}, c or ctx(), now=NOW, **kw)


# --------------------------------------------------------------- R30


def test_a_six_hour_heartbeat_raises_one_slow_beacon_and_random_contacts_none(store):
    heartbeat(store, "c2.example.com", 6, 20)
    rnd = random.Random(7)
    for n in range(20):   # a site visited at random times of day, a few times a day
        put(store, day(n), "news.example.org", times=sorted(midnight(day(n)) + rnd.uniform(0, DAY) for _ in range(3)))
    res = run(store)
    [case] = res.cases
    f = case.facts
    assert case.detector == "slow_beacon" and case.host == IP and case.indicators == ["c2.example.com"]
    assert f["regularity"] == "steady" and abs(f["interval_s"] - 6 * H) < 60 and f["port"] == 443
    assert f["device"] == DEV and f["device_mac"] == MAC and f["source"] == "history" and f["span_days"] >= 19
    assert case.base_severity == 3 and "backed_by" not in f


def test_through_the_pipeline_it_is_a_digest_item_raised_once_a_month(store):
    heartbeat(store, "c2.example.com", 6, 20)
    p = Pipeline([detectors.Identity()], Assets(), store)
    [case] = run(store).cases
    case_id, _, verdict, r = longhaul.admit(p, case)
    row = store.get(case_id)
    assert r is Route.DIGEST and verdict is None and row["reason"].startswith("long-horizon")
    assert run(store).cases == []                              # once per (device, destination) per 30 days
    assert run(store).skipped["R30 raised in the last 30 days"] == 1


def test_a_daily_job_with_missed_days_and_clock_drift_counts_as_daily(store):
    rnd = random.Random(3)
    for n in (20, 19, 18, 16, 15, 14, 13, 11, 10, 9, 8, 6, 5):   # 03:00 +- 12 min, a day missed now and then
        put(store, day(n), "updates.example.net", times=[midnight(day(n)) + 3 * H + rnd.uniform(-720, 720)])
    [case] = run(store).cases
    assert case.facts["regularity"] == "daily at the same time" and case.facts["cv"] > 0.2
    assert case.facts["missed_days"] == 3


def test_beacon_shape_limits():
    rule = longhaul.BeaconRule()
    steady = [6 * H] * 20
    assert longhaul.beacon_shape(steady, rule)["regularity"] == "steady"
    assert longhaul.beacon_shape([6 * H] * 5, rule) is None                  # fewer than 6 gaps
    assert longhaul.beacon_shape([3 * H] * 10, rule) is None                 # 30 hours: under 4 days
    assert longhaul.beacon_shape([1.5 * H] * 80, rule) is None               # 90 minutes: Beaconing's
    assert longhaul.beacon_shape([96 * H] * 8, rule) is None                 # every 4 days: over 72 h
    assert longhaul.beacon_shape([4 * H, 8 * H] * 10, rule) is None          # cv 0.33, not whole days
    assert longhaul.beacon_shape([DAY, 4 * DAY] * 4, rule) is None           # more missed days than beats
    assert longhaul.beats([0, 1800, 3600, 3700, 7300], 3600) == [0, 3600, 7300]


def test_a_device_matures_after_14_watched_days_and_a_sensor_outage_does_not_count():
    young = Store(":memory:")
    summaries(young, days=10)
    heartbeat(young, "c2.example.com", 6, 10)
    assert run(young).cases == [] and run(young).mature == 0
    assert len(run(young, mature_days=5).cases) == 1                       # the measurement flag
    down = Store(":memory:")   # 20 days of summaries, but the sensor saw only 4 hours on 8 of them: 12 watched
    summaries(down, days=20, low={day(n) for n in range(3, 11)})
    heartbeat(down, "c2.example.com", 6, 20)
    assert run(down).cases == []
    quiet = Store(":memory:")  # the sensor watched all 20 days; the device was simply quiet on most of them
    summaries(quiet, days=20, devices=())
    summaries(quiet, days=0)
    quiet.db.execute("INSERT INTO device_day VALUES (?,?,?,?,?,?,?,?)", (DEV, day(19), 1, 0, 0, 1, "{}", "{}"))
    heartbeat(quiet, "c2.example.com", 12, 6)
    assert len(run(quiet).cases) == 1


def test_benign_destinations_are_skipped(store):
    heartbeat(store, "popular.example.com", 6, 20)
    heartbeat(store, "tailscale.com", 6, 20)                    # a benign beacon class
    heartbeat(store, "github.com", 6, 20)                       # a dev service, from a dev host
    heartbeat(store, "support.example.net", 6, 20)              # takeover.expected for this host
    heartbeat(store, "seen.example.net", 6, 20)                 # Beaconing already reported it
    heartbeat(store, "198.51.100.30", 6, 20, port=123)          # time sync: a housekeeping port
    c = ctx(popular={"popular.example.com"}, classes=detectors.BEACON_CLASSES,
            dev=detectors.DevProfile([IP]), expected={IP: {"support.example.net"}},
            beacon_reported={(DEV, 443, "seen.example.net"): NOW - DAY})
    res = run(store, c)
    assert res.cases == []
    assert {k: v for k, v in res.skipped.items()} == {
        "R30 popular destination": 1, "R30 known class: NAT traversal / VPN relay": 1,
        "R30 dev service on a dev host": 1, "R30 expected service (takeover.expected)": 1,
        "R30 already reported by beaconing": 1}


# --------------------------------------------------------------- R31


def upload(store, dest, mb_per_day, days, inb_mb=1.0, dev=DEV, asn=None, start=0):
    for n in range(start, start + days):
        put(store, day(n), dest, out=int(mb_per_day * MB), inb=int(inb_mb * MB), times=(), dev=dev,
            asn=asn, cc="ZZ" if asn else None)


def test_fifteen_mb_a_day_for_eight_days_to_a_new_destination_raises_slow_upload(store):
    upload(store, "198.51.100.20", 15, 8, asn=64500)           # the issue's safe test, by address: summed by network
    [case] = run(store).cases
    f = case.facts
    assert case.detector == "slow_upload" and case.base_severity == 3 and case.indicators == []
    assert f["dest"] == "AS64500" and f["mb"] == 120 and f["upload_days"] == 8 and f["ratio"] == 15.0
    assert f["dests"] == ["198.51.100.20"] and len(f["daily_mb"]) == 14 and f["daily_mb"][-1] == 15.0
    assert f["prior_mb"] == 0 and f["first_day"] == day(7)


@pytest.mark.parametrize("shape,why", [
    ({"prior": 10}, "R31 uploaded there before the window"),
    ({"inb_mb": 4}, None),                                     # ratio under 5: a two-way service
    ({"spike": 600}, None),                                    # a day that big may have been upload_spike's
    ({"days": 6, "mb": 20}, None),                             # 6 upload days, not 7
    ({"mb": 10}, None),                                        # 80 MB, under 100
    ({"asn": 714}, "R31 sync network (Apple, Microsoft, Dropbox, Backblaze)"),
])
def test_slow_upload_needs_steady_lopsided_uploads_to_a_new_destination(store, shape, why):
    upload(store, "198.51.100.20", shape.get("mb", 15), shape.get("days", 8), inb_mb=shape.get("inb_mb", 1),
           asn=shape.get("asn", 64500))
    if "prior" in shape:
        upload(store, "198.51.100.20", shape["prior"], 1, asn=64500, start=20)
    if "spike" in shape:
        put(store, day(0), "198.51.100.20", out=shape["spike"] * MB, inb=MB, asn=64500, times=[midnight(day(0))])
    res = run(store)
    assert res.cases == []
    assert (why is None and not res.skipped) or res.skipped[why] == 1


def test_a_popular_destination_other_devices_use_is_skipped_but_not_one_only_this_device_uses():
    s = Store(":memory:")
    summaries(s, devices=(DEV, f"mac:{PEER_MAC}"))
    upload(s, "files.example.com", 15, 8)
    assert len(run(s, ctx(popular={"files.example.com"})).cases) == 1    # popular, but only this device: digest
    put(s, day(2), "files.example.com", out=1000, inb=5000, times=[midnight(day(2))], dev=f"mac:{PEER_MAC}")
    res = run(s, ctx(popular={"files.example.com"}))
    assert res.cases == [] and res.skipped["R31 popular and used by other devices"] == 1
    sync = Store(":memory:")
    summaries(sync)
    upload(sync, "icloud.com", 15, 8)                                    # a known sync service
    assert run(sync).skipped["R31 sync service or security vendor"] == 1


def test_no_baseline_before_the_window_means_nothing_can_be_called_new():
    s = Store(":memory:")
    summaries(s, days=16)
    upload(s, "198.51.100.20", 15, 8, asn=64500)
    res = run(s)
    assert res.cases == [] and res.skipped["R31 no baseline before the window to call it new"] == 1


def test_a_fixed_function_device_is_severity_4_and_a_managed_one_is_capped(store):
    upload(store, "198.51.100.20", 15, 8, asn=64500)
    [cam] = run(store, ctx(assets=Assets({IP: {"name": "porch camera", "role": "camera"}}))).cases
    assert cam.base_severity == 4 and cam.facts["fixed_function"] == "camera"
    assert route(cam, None)[0] is Route.DIGEST                  # severity 4, but long-horizon: digest unbacked
    [work] = run(store, ctx(assets=Assets({DEV: {"name": "work laptop", "role": "work laptop"}}))).cases
    assert work.facts["max_route"] == "digest" and work.facts["managed_device"] == "work laptop"


# --------------------------------------------------------------- routing


def other(store, detector, route_=Route.DIGEST, host=IP, ts=NOW - DAY, indicators=(), facts=None, reason="rules-only"):
    case = Case(detector, host, ts, "other", dict(facts or {}), list(indicators), detector == "ioc_match", 3)
    return store.add(case, "state", None, route_, reason)


@pytest.mark.parametrize("detector,route_,indicators,facts,ts,backed", [
    ("host_temp_exec", Route.DIGEST, (), {"source": "endpoint"}, NOW - DAY, True),
    ("host_temp_exec", Route.LOG, (), {"source": "endpoint"}, NOW - DAY, False),     # the owner's agent work logs
    ("host_temp_exec", Route.DIGEST, (), {"source": "endpoint"}, NOW - 8 * DAY, False),   # over 7 days ago
    ("ioc_match", Route.ALERT, ("bad.example.com",), {}, NOW - DAY, True),
    ("beaconing", Route.DIGEST, ("api.example.net",), {}, NOW - DAY, True),     # short window, same base domain
    ("beaconing", Route.DIGEST, ("cdn.example.org",), {}, NOW - DAY, False),       # another destination
    ("vuln_kev", Route.DIGEST, (), {"source": "endpoint"}, NOW - DAY, False),      # a standing condition, not a signal
])
def test_another_signal_on_the_device_within_7_days_backs_it_up_to_an_alert(store, detector, route_, indicators,
                                                                             facts, ts, backed):
    heartbeat(store, "example.net", 6, 20)   # summaries keep base domains
    oid = other(store, detector, route_, ts=ts, indicators=indicators, facts=facts)
    [case] = run(store).cases
    assert bool(case.facts.get("backed_by")) is backed
    r, reason = route(case, None)
    assert r is (Route.ALERT if backed else Route.DIGEST)
    if backed:
        assert case.facts["backed_by"][0]["id"] == oid and f"#{oid}" in reason


def test_a_backing_case_on_another_device_or_one_the_owner_suppressed_does_not_count(store):
    heartbeat(store, "c2.example.com", 6, 20)
    other(store, "host_temp_exec", host=PEER, facts={"source": "endpoint"})
    other(store, "host_lolbin", facts={"source": "endpoint"}, reason="suppressed: a rule", route_=Route.LOG)
    [case] = run(store).cases
    assert "backed_by" not in case.facts


def test_routing_never_raises_a_suppressed_capped_or_learning_case():
    backed = Case("slow_upload", IP, NOW, "t", {"backed_by": [{"id": 9, "detector": "ioc_match", "why": "x"}]}, [], False, 3)
    assert route(backed, None)[0] is Route.ALERT
    assert route(backed, None, suppression="a rule")[0] is Route.LOG
    assert route(backed, None, learning="learning period (day 1 of 3)")[0] is Route.DIGEST
    capped = Case("slow_upload", IP, NOW, "t", {**backed.facts, "max_route": "digest"}, [], False, 3)
    assert route(capped, None)[0] is Route.DIGEST
    loud = Case("slow_upload", IP, NOW, "t", {}, [], False, 4)
    r, reason = route(loud, None)
    assert r is Route.DIGEST and "unless another signal" in reason


# --------------------------------------------------------------- judge (#201)


def test_the_judge_never_takes_a_long_horizon_case_with_another_case_on_the_device(store):
    heartbeat(store, "c2.example.com", 6, 20)
    p = Pipeline([detectors.Identity()], Assets(), store)
    [case] = run(store).cases
    lone = longhaul.admit(p, case)[0]
    ok, reason, _ = judge.eligible(store.db, store.get(lone))
    assert not ok and reason.startswith("no owner precedent")       # nothing else on the device: the usual checks
    other(store, "new_domain", Route.LOG, indicators=("cdn.example.org",), ts=NOW - 3 * DAY)   # recent, closed
    store.db.execute("UPDATE cases SET status='closed' WHERE detector='new_domain'")
    ok, reason, _ = judge.eligible(store.db, store.get(lone))
    assert not ok and "long-horizon case backed by another case on this device" in reason and "recent" in reason
    store.db.execute("UPDATE cases SET first_ts=? WHERE detector='new_domain'", (NOW - 20 * DAY,))
    assert judge.eligible(store.db, store.get(lone))[1].startswith("no owner precedent")   # old and closed: no
    store.db.execute("UPDATE cases SET status='new' WHERE detector='new_domain'")
    assert "open" in judge.eligible(store.db, store.get(lone))[1]                           # old but still open


# --------------------------------------------------------------- the nightly hook and the command


def test_the_summary_thread_queues_cases_and_the_run_loop_raises_them_on_its_own_thread(tmp_path):
    path = str(tmp_path / "t.db")
    s = Store(path)
    summaries(s)
    heartbeat(s, "c2.example.com", 6, 20)
    q: queue.Queue = queue.Queue()
    p = Pipeline([detectors.Identity()], Assets(), s)
    t = history.nightly({"timezone": "UTC"}, [str(tmp_path)], lambda: Store(path), now=NOW,
                        then=longhaul.queue_into(q, {}, longhaul.Context.from_pipeline(p, {})))
    t.join(timeout=30)
    assert s.db.execute("SELECT COUNT(*) FROM cases").fetchone()[0] == 0     # nothing written from the thread
    case = q.get_nowait()
    assert case.detector == "slow_beacon"
    case_id, *_ = longhaul.admit(p, case)
    assert s.get(case_id)["route"] == "digest"


def test_longhaul_command_prints_what_it_would_raise_and_stores_nothing(tmp_path, capsys):
    path = str(tmp_path / "t.db")
    s = Store(path)
    summaries(s, days=10)
    heartbeat(s, "c2.example.com", 6, 10)
    upload(s, "198.51.100.20", 15, 8, asn=64500)
    cfg = tmp_path / "config.yaml"
    cfg.write_text(f"db_path: {path}\n")
    assert cli.main(["-c", str(cfg), "longhaul", "--stats"]) == 0
    assert "0 case(s) would be raised" in capsys.readouterr().out           # 10 days: not mature
    assert cli.main(["-c", str(cfg), "longhaul", "--mature-days", "5", "--stats"]) == 0
    out = capsys.readouterr().out
    assert "slow_beacon: 1 digest" in out and "c2.example.com" in out
    assert "no baseline before the window" in out                          # 10 days: nothing before R31's window
    assert s.db.execute("SELECT COUNT(*) FROM cases").fetchone()[0] == 0


def test_the_case_summary_states_the_weeks_in_words(store):
    from tapwatch.summarizer import summarize

    heartbeat(store, "c2.example.com", 6, 20)
    upload(store, "198.51.100.20", 15, 8, asn=64500)
    texts = {c.detector: summarize(c, Assets()) for c in run(store).cases}
    assert "about every 6 hours, at a steady interval" in texts["slow_beacon"]
    assert "uploaded 120 MB to one destination, a little on 8 different days" in texts["slow_upload"]
    assert "192.168.50" not in "".join(texts.values())


def test_a_device_that_appeared_inside_the_window_has_no_baseline_to_call_anything_new():
    """A new camera uploading steadily to its cloud from its first day: the sensor has a month of history, the
    device two weeks, so 'it never sent there before' means nothing yet (review of #324)."""
    s = Store(":memory:")
    newdev = "mac:02:00:00:00:00:0c"
    summaries(s)
    for n in range(14):
        s.db.execute("INSERT OR REPLACE INTO device_day VALUES (?,?,?,?,?,?,?,?)", (newdev, day(n), 1, 0, 0, 1, "{}", "{}"))
    s.db.commit()
    upload(s, "198.51.100.20", 15, 8, asn=64500, dev=newdev)
    res = run(s)
    assert res.cases == [] and res.skipped["R31 no baseline before the window to call it new"] == 1


def test_a_day_the_sensor_did_not_watch_does_not_hide_a_six_hour_beacon():
    """One unwatched day used to add a gap that broke the beat's steadiness for a month (review of #324)."""
    s = Store(":memory:")
    summaries(s, low={day(10)})
    heartbeat(s, "c2.example.com", 6, 20)
    s.db.execute("DELETE FROM device_day_dest WHERE day=?", (day(10),))   # the sensor saw nothing that day
    s.db.commit()
    assert [c.detector for c in run(s).cases] == ["slow_beacon"]


def test_backing_follows_the_device_not_an_address_dhcp_reassigned():
    other = longhaul.Recent(1, "beaconing", IP, "name:other-laptop", "digest", "rules-only", {"c2.example.com"}, set())
    bare = longhaul.Recent(2, "beaconing", IP, IP, "digest", "rules-only", {"c2.example.com"}, set())
    assert longhaul.backers([other], DEV, [IP], "c2.example.com", None, ctx()) == []
    assert [b["id"] for b in longhaul.backers([bare], DEV, [IP], "c2.example.com", None, ctx())] == [2]
    # the same network is not the same destination: AWS hosts everyone
    aws = longhaul.Recent(3, "upload_spike", IP, DEV, "digest", "rules-only", set(), {"198.51.100.99"})
    assert longhaul.backers([aws], DEV, [IP], "AS16509", 16509, ctx()) == []
