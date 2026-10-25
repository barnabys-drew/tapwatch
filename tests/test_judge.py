import json
import time

from tapwatch import judge
from tapwatch.detectors import IOCMatch
from tapwatch.models import Case, Route
from tapwatch.pipeline import Pipeline
from tapwatch.store import Store
from tapwatch.summarizer import Assets

DAY = 86400
NOW = time.time()


def add(store, detector="new_domain", host="192.168.50.10", ts=NOW, indicators=("cdn.example.com",), facts=None,
        must_alert=False, route=Route.DIGEST, severity=2):
    case = Case(detector, host, ts, "test case", dict(facts or {}), list(indicators), must_alert, severity)
    return store.add(case, "state", None, route, "rules-only")


def close(store, case_id, actor="ui owner", disposition="benign_expected", label_ts=None):
    """Close as the owner would: by default an hour after the case happened (update_case stamps the wall clock)."""
    store.update_case(case_id, actor, status="closed", disposition=disposition)
    when = label_ts if label_ts is not None else store.get(case_id)["first_ts"] + 3600
    store.db.execute("UPDATE judge_examples SET labelled_ts=? WHERE case_id=?", (when, case_id))
    store.db.commit()


def row(store, case_id):
    return store.get(case_id)


def history(store, days_ago, actor="ui owner", host="192.168.50.10", **kw):
    """One closed case per day in `days_ago`, each happening that many days before NOW."""
    for d in days_ago:
        close(store, add(store, host=host, ts=NOW - d * DAY, **kw), actor)


def test_label_source_reads_who_decided():
    assert judge.label_source("ui owner") == judge.label_source("cli") == "owner"
    assert judge.label_source("cli (requested by the user)") == "owner_request"
    assert judge.label_source("tapwatch explain") == "explain"
    assert judge.label_source("tapwatch") == "tapwatch"
    assert judge.label_source("claude") == judge.label_source("cli (triage handoff)") == "ai"
    assert judge.label_source("claude (requested by the user)") == "ai"   # only a cli actor carries the request
    for actor in ("judge precedent-1", "Judge", "tapwatch judge"):
        assert judge.label_source(actor) is None
    assert {"owner", "owner_request", "explain"} == judge.COUNTED


def test_every_disposition_writes_one_example_and_the_judge_never_does():
    s = Store(":memory:")
    a, b, c = add(s), add(s, indicators=("other.example.org",)), add(s, indicators=("third.example.net",))
    close(s, a, "ui owner")
    close(s, b, "judge precedent-1")
    close(s, c, "tapwatch")
    ex = {r["case_id"]: r for r in s.db.execute("SELECT * FROM judge_examples")}
    assert set(ex) == {a, c}
    assert ex[a]["label_source"] == "owner" and ex[a]["key"] == "domain:cdn.example.com"
    assert ex[c]["label_source"] == "tapwatch"
    # reopen and re-close: the newer label supersedes
    s.update_case(a, "ui owner", status="investigating")
    s.update_case(a, "ui owner", status="closed", disposition="true_positive")
    assert s.db.execute("SELECT label FROM judge_examples WHERE case_id=?", (a,)).fetchone()[0] == "true_positive"


def test_features_keep_no_network_strings():
    s = Store(":memory:")
    cid = add(s, indicators=("evil-looking.cdn.example.com",), facts={"port": 443, "device_mac": "02:00:00:00:00:01"})
    f = judge.features(row(s, cid))
    assert f["key"] == "domain:evil-looking.cdn.example.com" and f["device"] == "mac:02:00:00:00:00:01"
    assert f["port"] == 443 and json.dumps(f).count("evil-looking") == 1   # only in the normalised key


def test_keys_are_as_narrow_as_the_facts_allow():
    assert judge.key_for("host_encoded_cmd", {}, ["powershell.exe"]) == "program:powershell.exe"
    assert judge.key_for("beaconing", {"host_program_path": "C:\\Program Files\\App\\Chrome.exe"}, ["a.example.com"]) \
        == "program:c:/program files/app/chrome.exe"   # the full path: a look-alike elsewhere is another program
    # one tenant of a shared platform is not another (the registrable domain would merge them)
    assert judge.key_for("beaconing", {}, ["x1.trycloudflare.com:443"]) != judge.key_for(
        "beaconing", {}, ["evil-c2.trycloudflare.com:443"])
    assert judge.key_for("scan", {"dedupe": "192.168.50.20"}, []) == "ind:192.168.50.20"


def test_guardrails_say_why_not():
    s = Store(":memory:")
    history(s, [20, 12, 4])
    cases = {
        "always-alert rule": add(s, detector="ioc", must_alert=True, route=Route.ALERT),
        "code floor": add(s, facts={"min_route": "alert"}),
        "a coding agent": add(s, facts={"host_who": "agent_misused"}),
        "critical code-only alert": add(s, detector="mgmt_access", route=Route.ALERT, severity=4),
        "paired with an alert": add(s, facts={"correlated_best": "alert"}),
        "no owner precedent": add(s, indicators=("never-seen.example.net",)),
    }
    for want, cid in cases.items():
        ok, reason, _ = judge.eligible(s.db, row(s, cid), before=NOW + 60)
        assert not ok and want in reason, (want, reason)


def test_owner_precedent_over_days_and_weeks_is_eligible():
    s = Store(":memory:")
    history(s, [20, 12, 4])                     # three days, three different weeks
    ok, reason, prec = judge.eligible(s.db, row(s, add(s)), before=NOW + 60)
    assert ok and len(prec) == 3, reason


def test_closes_the_owner_didnt_make_are_not_precedent():
    s = Store(":memory:")
    history(s, [20, 12, 4], actor="claude")
    history(s, [19, 11, 3], actor="tapwatch")
    ok, reason, _ = judge.eligible(s.db, row(s, add(s)), before=NOW + 60)
    assert not ok and "only closes the owner didn't make" in reason


def test_one_burst_or_one_week_cannot_train_a_habit():
    s = Store(":memory:")
    for _ in range(10):                          # ten closes of one day's flood
        close(s, add(s, ts=NOW - 2 * DAY))
    ok, reason, _ = judge.eligible(s.db, row(s, add(s)), before=NOW + 60)
    assert not ok and "1 day(s)" in reason
    s3 = Store(":memory:")
    for d in (20, 12, 5, 4):                     # four days of activity, all closed in one sitting
        close(s3, add(s3, ts=NOW - d * DAY), label_ts=NOW - 3600)
    ok, reason, _ = judge.eligible(s3.db, row(s3, add(s3)), before=NOW + 60)
    assert not ok and "all on one day" in reason
    s2 = Store(":memory:")
    monday = NOW - (time.localtime(NOW).tm_wday + 7) * DAY + 3600 * 12   # last week's Monday, midday
    for d in (0, 1, 2):                          # three days, all in last week
        close(s2, add(s2, ts=monday + d * DAY))
    ok, reason, _ = judge.eligible(s2.db, row(s2, add(s2)), before=NOW + 60)
    assert not ok and "one week" in reason


def test_a_true_positive_keeps_the_judge_off():
    s = Store(":memory:")
    history(s, [20, 12, 4])
    close(s, add(s, detector="beaconing", indicators=("c2.example.net",), ts=NOW - DAY), disposition="true_positive")
    ok, reason, _ = judge.eligible(s.db, row(s, add(s)), before=NOW + 60)
    assert not ok and "true positive on this device" in reason
    s2 = Store(":memory:")
    history(s2, [20, 12], host="192.168.50.11")
    close(s2, add(s2, host="192.168.50.11", ts=NOW - 50 * DAY), disposition="true_positive")  # same key
    history(s2, [5], host="192.168.50.11")
    # judged 40 days on, so the true positive's label is outside the 30-day device lookback
    ok, reason, _ = judge.eligible(s2.db, row(s2, add(s2, host="192.168.50.11")), before=NOW + 40 * DAY)
    assert not ok and "true positive before" in reason
    # the same from a source that isn't precedent: a true-positive label only ever makes the judge careful
    s3 = Store(":memory:")
    close(s3, add(s3, ts=NOW - 50 * DAY), actor="claude", disposition="true_positive", label_ts=NOW - 49 * DAY)
    history(s3, [20, 12, 4])
    ok, reason, _ = judge.eligible(s3.db, row(s3, add(s3)), before=NOW + 60)
    assert not ok and "true positive before" in reason


def test_any_device_needs_more_than_one_device():
    s = Store(":memory:")
    history(s, [20, 12, 4], host="192.168.50.10")
    new_device_case = row(s, add(s, host="192.168.50.30"))
    assert not judge.eligible(s.db, new_device_case, before=NOW + 60)[0]
    ok, reason, _ = judge.eligible(s.db, new_device_case, before=NOW + 60, width="any_device")
    assert not ok and "one device" in reason
    history(s, [19, 11, 3], host="192.168.50.20")
    ok, reason, prec = judge.eligible(s.db, new_device_case, before=NOW + 60, width="any_device")
    assert ok and len(prec) == 6, reason


def test_decide_records_both_widths_and_never_acts():
    s = Store(":memory:")
    history(s, [20, 12, 4])
    cid = add(s, ts=NOW + 60)
    d = judge.decide(s.db, cid)
    assert d["suggestion"] == "close_noise" and d["eligible"] == 1
    assert "same device" in d["explanation"] and "cdn" not in d["explanation"]
    widths = json.loads(s.judge_decision(cid)["widths"])
    assert set(widths) == {"device", "any_device"} and widths["any_device"]["eligible"] is False
    r = row(s, cid)
    assert r["status"] == "new" and r["disposition"] is None and r["route"] == "digest"
    assert not s.db.execute("SELECT 1 FROM suppressions").fetchone()


def test_pipeline_records_a_shadow_decision_for_every_new_case():
    s = Store(":memory:")
    p = Pipeline([IOCMatch(set(), {"bad.example"})], Assets(), s)
    out = p.handle(Case("ioc", "192.168.50.10", NOW, "IOC", {}, ["bad.example"], True, 5))
    d = s.judge_decision(out[0])
    assert d is not None and d["suggestion"] == "leave" and d["ineligible_reason"] == "always-alert rule"


def test_backfill_and_replay_on_a_small_history():
    s = Store(":memory:")
    history(s, [20, 12, 4])
    tp = add(s, detector="beaconing", indicators=("c2.example.net",), ts=NOW - DAY)
    s.update_case(tp, "cli (requested by the user)", status="closed", disposition="true_positive")
    s.db.execute("DELETE FROM judge_examples")
    s.db.commit()
    assert judge.backfill(s.db) == {"owner": 3, "owner_request": 1}
    assert s.db.execute("SELECT COUNT(*) FROM judge_examples WHERE feature_version=0").fetchone()[0] == 4
    # a live snapshot survives a second backfill
    live = add(s, indicators=("live.example.org",))
    close(s, live)
    assert judge.backfill(s.db) == {}
    assert s.db.execute("SELECT feature_version FROM judge_examples WHERE case_id=?", (live,)).fetchone()[0] == 1
    r = judge.replay(s.db)
    assert r["true_positives_eligible"] == {"device": [], "any_device": []}
    assert r["detectors"]["new_domain"]["cases"] == 4


def test_case_page_shows_the_shadow_answer_with_precedent_links():
    from tapwatch import ui

    s = Store(":memory:")
    history(s, [20, 12, 4])
    cid = add(s, ts=NOW + 60)
    judge.decide(s.db, cid)
    _title, body = ui.render_case(s, Assets(), cid, [], "token")
    assert "Judge (shadow)" in body and "would close as noise" in body and "nothing is closed" in body
    first = json.loads(s.judge_decision(cid)["precedent_ids"])[0]
    assert f'<a href="/case/{first}">#{first}</a>' in body


def test_a_sensor_health_true_positive_does_not_keep_the_judge_off_the_device():
    s = Store(":memory:")
    history(s, [20, 12, 4])
    close(s, add(s, detector="feed_silence", indicators=("conn",), ts=NOW - DAY), disposition="true_positive")
    ok, reason, _ = judge.eligible(s.db, row(s, add(s)), before=NOW + 60)
    assert ok, reason
    # it still blocks its own key
    ok, reason, _ = judge.eligible(s.db, row(s, add(s, detector="feed_silence", indicators=("conn",))), before=NOW + 60)
    assert not ok and "true positive before" in reason


def test_precedent_from_before_the_device_was_named_counts_unless_the_mac_had_another_name():
    s = Store(":memory:")
    mac = "02:00:00:00:00:0d"
    history(s, [20, 12, 4], facts={"device_mac": mac})                      # closed while still mac:-keyed
    named = {"device_mac": mac, "device_name": "Den-Tablet"}
    ok, reason, prec = judge.eligible(s.db, row(s, add(s, facts=named)), before=NOW + 60)
    assert ok and len(prec) == 3, reason
    # the same MAC once carried another name (a dock): its mac:-keyed closes may be the other computer's
    add(s, facts={"device_mac": mac, "device_name": "Work-Laptop"}, indicators=("other.example.net",))
    ok, reason, _ = judge.eligible(s.db, row(s, add(s, facts=named)), before=NOW + 60)
    assert not ok and "no owner precedent" in reason
