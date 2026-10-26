"""The Stats page's numbers (deskstats) and its new charts, on a small store with known times."""

import html
from datetime import datetime, timedelta

from tapwatch import deskstats, ui
from tapwatch.models import Case, Route
from tapwatch.store import Store
from tapwatch.summarizer import Assets

NOW = datetime(2026, 10, 20, 12, 0).timestamp()   # local noon
DAY, HOUR = 86400, 3600


def add(store, ts, route=Route.ALERT, detector="beaconing", host="192.168.50.10"):
    cid = store.add(Case(detector, host, ts, "Regular repeating connection", {"dedupe": f"x{ts}"}, []),
                    "state", None, route, "test")
    store.db.execute("UPDATE cases SET first_ts = ?, last_ts = ? WHERE id = ?", (ts, ts, cid))
    store.db.commit()
    return cid


def close(store, cid, at, disposition="benign_expected"):
    store.update_case(cid, actor="owner", status="closed", disposition=disposition)
    store.db.execute("UPDATE audit SET ts = ? WHERE case_id = ?", (at, cid))   # as if decided at `at`
    store.db.commit()


def test_daily_counts_routes_and_the_backlog_at_each_days_end(tmp_path):
    store = Store(str(tmp_path / "t.db"))
    a = add(store, NOW - 2 * DAY)                      # alert two days ago, closed yesterday
    add(store, NOW - 2 * DAY + 60, Route.LOG)          # log-only: counted as a case, never in the backlog
    b = add(store, NOW - DAY, Route.DIGEST)            # digest yesterday, still open
    close(store, a, NOW - DAY + HOUR)
    d = deskstats.daily(store.db, days=3, now=NOW)
    day2, day1, today = d["days"]
    assert d["routes"][day2] == {"alert": 1, "digest": 0, "log": 1}
    assert d["routes"][day1] == {"alert": 0, "digest": 1, "log": 0}
    assert d["backlog"] == {day2: 1, day1: 1, today: 1}   # a was open at day2's end, closed in day1; b opened day1
    assert d["decided"][day2] == 1 and d["noise"][day2] == 1 and sum(d["true_positives"].values()) == 0
    assert b


def test_waits_histogram_median_and_undecided(tmp_path):
    store = Store(str(tmp_path / "t.db"))
    for hours in (0.5, 3, 30):
        cid = add(store, NOW - 3 * DAY)
        close(store, cid, NOW - 3 * DAY + hours * HOUR)
    add(store, NOW - DAY)                                # undecided
    w = deskstats.waits(store.db, now=NOW)
    assert w["hist"]["under 1 h"] == 1 and w["hist"]["1–6 h"] == 1 and w["hist"]["1–3 days"] == 1
    assert w["median_h"] == 3 and w["timed"] == 3 and w["undecided"] == 1


def test_hour_of_day_and_the_busiest(tmp_path):
    store = Store(str(tmp_path / "t.db"))
    nine = datetime(2026, 10, 19, 9, 15).timestamp()
    add(store, nine)
    add(store, nine + 60, Route.DIGEST, host="192.168.50.11", detector="new_domain")
    add(store, nine + 120, Route.DIGEST, host="192.168.50.11", detector="new_domain")
    hod = deskstats.hour_of_day(store.db, now=NOW)
    assert hod["alert"][9] == 1 and hod["other"][9] == 2 and sum(hod["alert"]) == 1
    devs = deskstats.top(store.db, "host", now=NOW)
    assert [(r["key"], r["cases"], r["alerts"]) for r in devs] == [("192.168.50.11", 2, 0), ("192.168.50.10", 1, 1)]
    assert deskstats.top(store.db, "detector", now=NOW)[0]["key"] == "new_domain"


def test_stats_page_draws_the_new_charts_and_stays_inert(tmp_path):
    store = Store(str(tmp_path / "t.db"))
    cid = add(store, NOW - DAY, host="192.168.50.12")
    close(store, cid, NOW - DAY + HOUR, "false_positive")
    page = ui.render_stats(store, None, Assets({"192.168.50.12": {"name": "<b>printer</b>"}}))[1]
    for heading in ("Cases a day", "Open backlog at the end of each day", "Time to a disposition",
                    "When cases arrive", "Busiest devices", "Busiest detectors", "All time", "Judge scorecard (shadow)"):
        assert heading in page, heading
    assert "&lt;b&gt;printer&lt;/b&gt;" in page and "<b>printer</b>" not in page   # names are escaped
    assert f'href="{html.escape("/?status=all&route=all&device=192.168.50.12")}"' in page
    assert '<details class="more">' in page and "<script" not in page


def test_an_empty_store_renders():
    store = Store(":memory:")
    page = ui.render_stats(store)[1]
    assert "Cases a day" in page and "Nothing yet." in page


def test_week_old_installs_show_at_least_a_week():
    days = deskstats._days(7, datetime.fromtimestamp(NOW).date())
    assert days[-1] == "2026-10-20" and days[0] == (datetime(2026, 10, 20) - timedelta(days=6)).date().isoformat()


def test_machine_dispositions_dont_time_the_wait(tmp_path):
    # review of #340: a judge close or tapwatch's own close at arrival made the median look like minutes
    store = Store(str(tmp_path / "t.db"))
    from tapwatch import judge
    a = add(store, NOW - 3 * DAY)
    store.update_case(a, actor=judge.ACTOR, status="closed", disposition="benign_expected")
    store.update_case(a, actor="ui owner", disposition="false_positive")   # the owner overrides, two days later
    rows = store.db.execute("SELECT id, actor FROM audit WHERE case_id = ? AND action = 'disposition' ORDER BY id",
                            (a,)).fetchall()
    store.db.execute("UPDATE audit SET ts = ? WHERE id = ?", (NOW - 3 * DAY + 300, rows[0]["id"]))
    store.db.execute("UPDATE audit SET ts = ? WHERE id = ?", (NOW - DAY, rows[1]["id"]))
    b = add(store, NOW - 2 * DAY)
    store.update_case(b, actor="tapwatch", status="closed", disposition="benign_expected")   # suppressed on arrival
    store.db.commit()
    w = deskstats.waits(store.db, now=NOW)
    assert w["timed"] == 1 and w["median_h"] == 48 and w["undecided"] == 0


def test_a_reopened_case_is_open_again_only_from_the_reopen(tmp_path):
    store = Store(str(tmp_path / "t.db"))
    cid = add(store, NOW - 5 * DAY)
    store.update_case(cid, actor="ui owner", status="closed", disposition="benign_expected")
    store.update_case(cid, actor="ui owner", status="investigating")   # reopened
    ts = [NOW - 4 * DAY, NOW - DAY]   # closed four days ago, reopened yesterday
    for row, t in zip(store.db.execute("SELECT id FROM audit WHERE case_id = ? AND action = 'status' ORDER BY id",
                                       (cid,)).fetchall(), ts):
        store.db.execute("UPDATE audit SET ts = ? WHERE id = ?", (t, row["id"]))
    store.db.commit()
    d = deskstats.daily(store.db, days=6, now=NOW)
    assert [d["backlog"][k] for k in d["days"]] == [1, 0, 0, 0, 1, 1]


def test_judge_closes_are_their_own_bucket_not_undecided(tmp_path):
    store = Store(str(tmp_path / "t.db"))
    from tapwatch import judge
    cid = add(store, NOW - DAY)
    store.update_case(cid, actor=judge.ACTOR, status="closed", disposition="benign_expected")
    store.db.execute("INSERT INTO judge_closures (case_id, ts, detector, width, model_version, precedent_ids, explanation)"
                     " VALUES (?, ?, ?, ?, ?, ?, ?)", (cid, NOW, "beaconing", "device", "test", "[]", "closed like earlier"))
    store.db.commit()
    disp = deskstats.dispositions(store.db, now=NOW)
    assert disp["judge"] == 1 and disp[""] == 0 and disp["benign_expected"] == 0
    assert deskstats.waits(store.db, now=NOW)["undecided"] == 0
    assert "closed by the judge" in ui.render_stats(store)[1]
