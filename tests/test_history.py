"""Per-device daily summaries (#193): history.py, `tapwatch summarize` and the zeek.py helpers it reads with."""

import json
from datetime import date
from itertools import pairwise

import pytest
from conftest import conn, dhcp, dns, ssl, write_logs

from tapwatch import cli, detectors, history, zeek
from tapwatch.store import Store

DAY = date(2026, 9, 21)
CFG = {"timezone": "UTC"}
START, END = history.bounds(DAY, history.zone(CFG))
LAPTOP, PHONE = "02:00:00:00:00:0a", "02:00:00:00:00:0b"


def with_mac(rec, mac):
    return {**rec, "orig_l2_addr": mac, "resp_bytes": 2000}


def fixture_day():
    """A day of traffic, plus what must not count: the evening before, LAN to LAN, an answer to an inbound
    connection, and a hairpin through the house's public address."""
    recs = {"dns": [], "ssl": [], "conn": [], "dhcp": []}
    recs["dns"].append({**dns(START - 600, "api.example.com"), "answers": ["203.0.113.5"]})
    recs["dhcp"].append({**dhcp(START + 7200, mac=LAPTOP), "host_name": "Study-Laptop"})
    for i in range(60):   # the laptop polls a named API every 20 minutes
        recs["conn"].append(with_mac(conn(START + 300 + i * 1200, orig_bytes=500 + i), LAPTOP))
    for i in range(10):   # the phone, by SNI, on IPv4 and on its second address
        t = START + 40000 + i * 60
        recs["ssl"].append(ssl(t - 1, "edge.cdn.example.net", src="192.168.50.11", dst="198.51.100.20"))
        recs["conn"].append(with_mac(conn(t, src="192.168.50.11" if i % 2 else "192.168.50.12",
                                          dst="198.51.100.20", orig_bytes=10_000), PHONE))
    recs["conn"].append(with_mac(conn(START + 50000, src="192.168.50.11", dst="198.51.100.99", port=51820,
                                      orig_bytes=77), PHONE))   # no name: the address
    recs["conn"] += [
        with_mac(conn(START - 60, orig_bytes=999), LAPTOP),                        # the day before
        with_mac(conn(START + 1000, dst="192.168.50.1", port=53), LAPTOP),         # LAN to LAN
        with_mac(conn(START + 2000, src="203.0.113.77", dst="192.168.50.10"), LAPTOP),   # inbound
        with_mac(conn(START + 3000, dst="198.51.100.1", port=41641), LAPTOP),      # hairpin
        with_mac(conn(END + 30, orig_bytes=999), LAPTOP),                          # the day after
    ]
    for rows in recs.values():
        rows.sort(key=lambda r: r["ts"])
    return recs


def direct_pass(conns):
    """What the totals must equal: LAN device -> internet connections started in the day, hairpins excluded."""
    keep = [r for r in conns if START <= r["ts"] < END and detectors.is_unicast_lan(r["id.orig_h"])
            and not detectors.is_internal(r["id.resp_h"]) and r["id.resp_h"] != "198.51.100.1"]
    return len(keep), sum(r["orig_bytes"] for r in keep), sum(r.get("resp_bytes", 0) for r in keep)


@pytest.fixture
def setup(tmp_path):
    recs = fixture_day()
    write_logs(tmp_path, **recs)
    cfg = {**CFG, "network": {"public_ips": ["198.51.100.1"]}}
    yield tmp_path, Store(str(tmp_path / "t.db")), cfg, recs
    detectors.set_house_ips(None)


def table(store, name):
    return [tuple(r) for r in store.db.execute(f"SELECT * FROM {name} ORDER BY 1, 2, 3, 4")]


def test_totals_match_a_direct_pass_and_a_rerun_gives_identical_rows(setup):
    d, store, cfg, recs = setup
    [res] = history.summarize(store, cfg, [d], [DAY])
    conns, up, down = direct_pass(recs["conn"])
    got = store.db.execute("SELECT sum(conns), sum(bytes_out), sum(bytes_in) FROM device_day").fetchone()
    assert tuple(got) == (conns, up, down) == (71, sum(500 + i for i in range(60)) + 100_077, 71 * 2000)
    dest = store.db.execute("SELECT sum(conns), sum(bytes_out), sum(bytes_in) FROM device_day_dest").fetchone()
    assert tuple(dest) == tuple(got)
    assert res.records == 71 and res.devices == 2
    before = table(store, "device_day"), table(store, "device_day_dest")
    history.summarize(store, cfg, [d], [DAY])
    assert (table(store, "device_day"), table(store, "device_day_dest")) == before
    [done] = store.db.execute("SELECT day, devices, records FROM summary_days").fetchall()
    assert tuple(done) == ("2026-09-21", 2, 71)


def test_devices_are_keyed_by_identity_all_day(setup):
    d, store, cfg, _ = setup
    history.summarize(store, cfg, [d], [DAY])
    rows = {r["device"]: r for r in store.db.execute("SELECT * FROM device_day")}
    # The laptop's lease (with its name) came two hours in: its earlier polls still count under the name.
    # The phone's two addresses are one device by MAC.
    assert set(rows) == {"name:study-laptop", f"mac:{PHONE}"}
    assert rows["name:study-laptop"]["conns"] == 60 and rows[f"mac:{PHONE}"]["conns"] == 11
    laptop = rows["name:study-laptop"]
    assert laptop["active_hours_bitmap"] == (1 << 20) - 1   # every hour from 00 to 19
    assert json.loads(laptop["ports"]) == {"443/tcp": 60} and json.loads(laptop["protocols"]) == {"ssl": 60}


def test_destinations_are_base_domains_when_named_else_the_address(setup):
    d, store, cfg, _ = setup
    history.summarize(store, cfg, [d], [DAY])
    dests = {(r["device"], r["dest"], r["port"]): r for r in store.db.execute("SELECT * FROM device_day_dest")}
    assert set(dests) == {("name:study-laptop", "example.com", 443), (f"mac:{PHONE}", "example.net", 443),
                          (f"mac:{PHONE}", "198.51.100.99", 51820)}
    times = json.loads(dests[("name:study-laptop", "example.com", 443)]["contact_times"])
    assert len(times) == 30 and {b - a for a, b in pairwise(times)} == {2400}   # polls every 20 min
    assert dests[("name:study-laptop", "example.com", 443)]["asn"] is None   # no ASN table configured


def test_asn_and_country_come_from_the_table(setup):
    d, store, cfg, _ = setup
    from tapwatch.feeds import AsnTable

    asn = AsnTable([int.from_bytes(bytes([203, 0, 113, 0]), "big")], [int.from_bytes(bytes([203, 0, 113, 255]), "big")],
                   [64500], ["ZZ"])
    history.summarize(store, cfg, [d], [DAY], asn=asn)
    row = store.db.execute("SELECT asn, country FROM device_day_dest WHERE dest='example.com'").fetchone()
    assert tuple(row) == (64500, "ZZ")


def test_contact_times_keep_48_starts_half_an_hour_apart():
    times = [1000.0 + 60 * i for i in range(2000)]
    kept = history.contact_times(list(reversed(times)))
    assert kept[0] == 1000 and len(kept) == 48 and {b - a for a, b in pairwise(kept)} == {1800}


def test_a_scanning_device_keeps_its_top_ports_and_sums_the_rest():
    from collections import Counter

    ports = Counter({f"{p}/tcp": 1 for p in range(1, 1001)})
    ports["443/tcp"] = 50
    out = history.top_ports(ports)
    assert len(out) == history.TOP_PORTS + 1 and out["443/tcp"] == 50 and sum(out.values()) == sum(ports.values())


def test_old_summaries_are_deleted_after_the_retention(setup):
    d, store, cfg, _ = setup
    history.summarize(store, cfg, [d], [DAY])
    assert history.prune(store.db, date(2026, 12, 20), 90) == 0
    assert history.prune(store.db, date(2026, 12, 21), 90) == 2
    assert not table(store, "device_day_dest") and not table(store, "summary_days")


def test_due_days_skips_done_unfinished_and_logless_days(setup):
    d, store, cfg, _ = setup
    tz = history.zone(cfg)
    before, after = date(2026, 9, 20), date(2026, 9, 22)   # one connection each in the fixture
    now = END + 86400 + 12 * 3600   # noon the day after `after`
    assert history.due_days(store.db, [d], tz, now, 4) == [before, DAY, after]   # 09-19: no logs reach back to it
    assert history.due_days(store.db, [d], tz, END + 3600, 3) == [before]   # DAY's late connections still coming
    history.summarize(store, cfg, [d], [before, DAY, after])
    assert history.due_days(store.db, [d], tz, now, 4) == []


def test_nightly_clock_runs_once_a_local_day_after_its_hour():
    clock = history.NightlyClock(4, history.zone(CFG))
    assert not clock.due(START + 3 * 3600)
    assert clock.due(START + 5 * 3600) and not clock.due(START + 6 * 3600)
    assert clock.due(START + 86400 + 4 * 3600)


def test_nightly_summarizes_in_the_background(setup):
    d, store, cfg, _ = setup
    history.nightly(cfg, [d], lambda: Store(str(d / "t.db")), now=END + 86400 + 12 * 3600).join(10)
    assert [r[0] for r in table(store, "summary_days")] == ["2026-09-20", "2026-09-21", "2026-09-22"]


def test_summarize_command_rebuilds_a_named_day(setup, capsys):
    d = setup[0]
    (d / "config.yaml").write_text(f"db_path: {d / 't.db'}\ntimezone: UTC\n")
    assert cli.main(["-c", str(d / "config.yaml"), "summarize", "--zeek-dir", str(d), "--day", "2026-09-21"]) == 0
    assert "2026-09-21     2 devices" in capsys.readouterr().out
    assert cli.main(["-c", str(d / "config.yaml"), "summarize", "--zeek-dir", str(d), "--day", "2026-09-19"]) == 0
    assert "no conn logs" in capsys.readouterr().err


def test_the_day_reads_rotated_files_that_can_hold_it(tmp_path):
    """Files opened from the preroll to LATE after midnight; the one opened before (still open then) too."""
    def rotated(ts):
        return tmp_path / f"conn.{zeek.datetime.fromtimestamp(ts, zeek.timezone.utc):%Y-%m-%d-%H-%M-%S}.log"

    for h in range(-5, 30):
        rotated(START + h * 3600).write_text("")
    picked = zeek.opened_between(zeek.log_files(tmp_path, "conn.log"), START - history.PREROLL, END + history.LATE)
    assert [zeek.rotated_ts(p) for p in picked] == [START + h * 3600 for h in range(-3, 27)]
    (tmp_path / "conn.log").write_text("")
    assert zeek.opened_between(zeek.log_files(tmp_path, "conn.log"), START, END)[-1].name == "conn.2026-09-21-23-00-00.log"
    assert zeek.opened_between(zeek.log_files(tmp_path, "conn.log"), END + 30 * 3600, END + 40 * 3600)[-1].name == "conn.log"


def test_rotated_names_with_the_close_time_repeated_still_count(tmp_path):
    name = "conn.2026-10-13-22-04-34.2026-10-13-22-41-11.2026-10-13-22-41-11.2026-10-13-22-41-11.2026-10-13-22-41-11.log"
    (tmp_path / name).write_text(json.dumps({"ts": 1.0}) + "\n")
    assert zeek.rotated_ts(tmp_path / name) == zeek.rotated_ts(tmp_path / "conn.2026-10-13-22-04-34.log")
    assert zeek.log_files(tmp_path, "conn.log") == [tmp_path / name]
    assert [r["_type"] for r in zeek.replay(tmp_path, {"conn.log"})] == ["conn"]


def test_long_connections_logged_the_next_day_count_once(tmp_path):
    """A connection is logged when it ends: one started in the day and logged 10 h after midnight still counts, and
    a file both passes read (the seam at LATE) counts once."""
    def rotated(ts, recs):
        name = f"conn.{zeek.datetime.fromtimestamp(ts, zeek.timezone.utc):%Y-%m-%d-%H-%M-%S}.log"
        (tmp_path / name).write_text("".join(json.dumps({**r, "uid": f"C{r['ts']}"}) + "\n" for r in recs))

    rotated(START + 3600, [with_mac(conn(START + 3700), LAPTOP)])
    rotated(END + 2 * 3600, [with_mac(conn(START + 5000, orig_bytes=7), LAPTOP)])   # read by both passes
    rotated(END + 10 * 3600, [{**with_mac(conn(START + 200, orig_bytes=5_000_000), LAPTOP), "duration": 80000}])
    store = Store(str(tmp_path / "t.db"))
    [res] = history.summarize(store, CFG, [tmp_path], [DAY])
    assert res.records == 3
    assert store.db.execute("SELECT sum(bytes_out) FROM device_day").fetchone()[0] == 500 + 7 + 5_000_000


def test_a_day_is_built_again_once_its_long_connections_are_logged(setup):
    d, store, cfg, _ = setup
    tz = history.zone(cfg)
    history.summarize(store, cfg, [d], [DAY])
    store.db.execute("UPDATE summary_days SET built_ts=?", (END + 5 * 3600,))   # the first nightly build
    store.db.commit()
    assert DAY not in history.due_days(store.db, [d], tz, END + 20 * 3600, 3)   # not settled yet: wait
    assert DAY in history.due_days(store.db, [d], tz, END + history.SETTLE + 60, 3)
    store.db.execute("UPDATE summary_days SET built_ts=?", (END + history.SETTLE + 60,))
    store.db.commit()
    assert DAY not in history.due_days(store.db, [d], tz, END + 3 * 86400, 4)


def test_a_device_with_huge_fan_out_is_bounded(tmp_path, monkeypatch):
    """A torrent client or a scanner reaching thousands of unnamed peers: the rows past MAX_UNNAMED fold into one
    ("other", -1) row, totals still match, and a busy destination keeps at most CONTACTS start times while read."""
    monkeypatch.setattr(history, "MAX_UNNAMED", 3)
    peers = [with_mac(conn(START + 600 + i, dst=f"198.51.100.{i + 10}", port=6881), LAPTOP) for i in range(10)]
    busy = [with_mac(conn(START + 3600 + i * 60, dst="203.0.113.9", port=443), LAPTOP) for i in range(500)]
    write_logs(tmp_path, conn=sorted(peers + busy, key=lambda r: r["ts"]))
    d = history.read_day([tmp_path], DAY, history.zone(CFG), detectors.Identity())
    keys = sorted(k[1] for k in d.dests)
    assert len(keys) == 4 and "other" in keys and "203.0.113.9" not in keys   # 3 peers kept, the rest in "other"
    assert sum(r[0] for r in d.dests.values()) == 510
    assert max(len(r[4]) for r in d.dests.values()) <= history.CONTACTS


def test_a_rebuild_with_fewer_records_keeps_the_complete_summary(setup):
    d, store, cfg, recs = setup
    history.summarize(store, cfg, [d], [DAY])
    before = table(store, "device_day")
    write_logs(d, **{**recs, "conn": recs["conn"][len(recs["conn"]) // 2:]})   # the morning's logs pruned since
    history.summarize(store, cfg, [d], [DAY])
    assert table(store, "device_day") == before


def test_the_oldest_day_left_is_skipped_once_its_morning_is_pruned(tmp_path):
    def rotated(ts):
        (tmp_path / f"conn.{zeek.datetime.fromtimestamp(ts, zeek.timezone.utc):%Y-%m-%d-%H-%M-%S}.log").write_text("")

    tz = history.zone(CFG)
    for h in range(6, 30):   # the day's first six hours already pruned
        rotated(START + h * 3600)
    assert not history.has_logs([tmp_path], DAY, tz)
    assert history.has_logs([tmp_path], date(2026, 9, 22), tz)
    rotated(START - 3600 + 1234)   # an irregular rotation the evening before still holds the morning
    assert history.has_logs([tmp_path], DAY, tz)


def test_an_hour_before_the_day_is_finished_is_moved_to_when_it_is():
    clock = history.NightlyClock(1, history.zone(CFG))
    assert clock.hour == history.LATE // 3600


TABLET, DOCK = "02:00:00:00:00:41", "02:00:00:00:00:42"


def two_name_logs(tmp_path, *tablet_named_at):
    """The tablet's named leases at `tablet_named_at` only; a dock two computers share announces both their names."""
    write_logs(tmp_path, conn=sorted([with_mac(conn(START + 600, src="192.168.50.41"), TABLET),
                                      with_mac(conn(START + 700, src="192.168.50.42"), DOCK),
                                      with_mac(conn(START + 2 * 86400 + 600, src="192.168.50.41"), TABLET)],
                                     key=lambda r: r["ts"]),
               dhcp=sorted([*({**dhcp(t, mac=TABLET), "host_name": "Den-Tablet"} for t in tablet_named_at),
                            {**dhcp(START + 3600, mac=DOCK), "host_name": "Desk-PC"},
                            {**dhcp(START + 7200, mac=DOCK), "host_name": "Work-Laptop"}], key=lambda r: r["ts"]))


def devices(store, day=DAY):
    return {r[0] for r in store.db.execute("SELECT device FROM device_day WHERE day=?", (day.isoformat(),))}


def test_a_mac_takes_the_one_name_it_announced_around_the_day_but_a_shared_dock_does_not(tmp_path):
    """Measured on 12 home days from an empty Identity: devices sat under mac:<address> until their first named lease,
    two histories for one device. A dock that announced two names stays its MAC: which computer it was is unknown.
    One day of one name outside the day is not enough (that dock's first day showed only one computer's lease)."""
    two_name_logs(tmp_path, END + 3600, END + 26 * 3600)      # named on the next two days, before the second build
    store = Store(str(tmp_path / "t.db"))
    history.summarize(store, CFG, [tmp_path], [DAY])
    assert devices(store) == {"name:den-tablet", f"mac:{DOCK}"}
    (tmp_path / "once").mkdir()
    two_name_logs(tmp_path / "once", END + 5 * 3600)          # after the day's own window, on one day
    store = Store(str(tmp_path / "once" / "t.db"))
    history.summarize(store, CFG, [tmp_path / "once"], [DAY])
    assert devices(store) == {f"mac:{TABLET}", f"mac:{DOCK}"}


def test_once_a_mac_announces_its_name_its_earlier_days_move_to_it(tmp_path):
    two_name_logs(tmp_path, END + 1.5 * 86400, END + 2.5 * 86400)    # named on the third and fourth days only
    store = Store(str(tmp_path / "t.db"))
    history.summarize(store, CFG, [tmp_path], [DAY])
    assert devices(store) == {f"mac:{TABLET}", f"mac:{DOCK}"}
    with store.db:   # an earlier day that has a row under the name already
        store.db.execute("INSERT INTO device_day VALUES ('name:den-tablet', '2026-09-20', 1, 1, 1, 1, '{}', '{}')")
        store.db.execute("INSERT INTO device_day VALUES (?, '2026-09-20', 2, 2, 2, 2, '{}', '{}')", (f"mac:{TABLET}",))
    later = date(2026, 9, 23)
    history.summarize(store, CFG, [tmp_path], [later])
    assert devices(store, later) == {"name:den-tablet"}
    assert devices(store) == {"name:den-tablet", f"mac:{DOCK}"}           # one history from the first day
    assert [r[0] for r in store.db.execute("SELECT DISTINCT device FROM device_day_dest WHERE day=? AND device != ?",
                                           (DAY.isoformat(), f"mac:{DOCK}"))] == ["name:den-tablet"]
    # that day keeps both rows (`summarize --day` merges them), rather than one overwriting the other
    assert devices(store, date(2026, 9, 20)) == {"name:den-tablet", f"mac:{TABLET}"}


def test_an_older_run_of_mac_days_another_computer_made_is_never_renamed(tmp_path):
    """Review of #326: weeks of a dock's mac:<address> days from one computer, then another computer docks and
    announces its name. Only the days next to its first named leases move; the older run keeps the MAC."""
    two_name_logs(tmp_path, END + 1.5 * 86400, END + 2.5 * 86400)    # the tablet named on 9-23 and 9-24 only
    store = Store(str(tmp_path / "t.db"))
    old = [date(2026, 8, 1), date(2026, 9, 5), date(2026, 9, 18)]    # past the lookback; inside it but weeks off; 5 days
    with store.db:
        for d in old:
            store.db.execute("INSERT INTO device_day VALUES (?, ?, 1, 1, 1, 1, '{}', '{}')", (f"mac:{TABLET}", d.isoformat()))
            store.db.execute("INSERT INTO device_day_dest VALUES (?, ?, 'example.com', 443, NULL, NULL, 1, 1, 1, '[]')",
                             (f"mac:{TABLET}", d.isoformat()))
    history.summarize(store, {**CFG, "summaries": {"retention_days": 0}}, [tmp_path], [DAY, date(2026, 9, 23)])
    assert devices(store) == {"name:den-tablet", f"mac:{DOCK}"}           # two days before the first named lease
    for d in old:
        assert devices(store, d) == {f"mac:{TABLET}"}
        assert store.db.execute("SELECT device FROM device_day_dest WHERE day=?", (d.isoformat(),)).fetchone()[0] \
            == f"mac:{TABLET}"
    assert history.rekey(store.db, {TABLET: "Den-Tablet"}, date(2026, 9, 23), {}) == 0   # no announced days: no move
