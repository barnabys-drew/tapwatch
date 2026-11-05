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
    assert set(widths) == set(judge.WIDTHS) and widths["any_device"]["eligible"] is False   # new_domain: all apply
    assert widths["site"]["eligible"] is True
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
    assert s.db.execute("SELECT feature_version FROM judge_examples WHERE case_id=?", (live,)).fetchone()[0] == judge.FEATURE_VERSION
    r = judge.replay(s.db)
    assert r["true_positives_eligible"] == {w: [] for w in judge.WIDTHS}
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


# ---------------------------------------------------------------- wider keys (#353)

def test_site_of_widens_a_host_to_its_site_but_never_a_shared_platform_tenant():
    assert judge.site_of("domain:a.cdn.example.com") == judge.site_of("domain:example.com") == "example.com"
    assert judge.site_of("domain:x1.github.io") == "x1.github.io"            # a tenant is its own site
    assert judge.site_of("domain:evil.trycloudflare.com") == "evil.trycloudflare.com"
    assert judge.site_of("program:c:/windows/system32/cmd.exe") is None
    assert judge.site_of("ind:192.168.50.20") is None


def test_shared_platform_reads_the_private_section_of_the_list(tmp_path):
    from tapwatch import detectors

    psl = tmp_path / "psl.dat"
    psl.write_text("// ===BEGIN ICANN DOMAINS===\ncom\n// ===END ICANN DOMAINS===\n"
                   "// ===BEGIN PRIVATE DOMAINS===\ntenants.example\n*.zone.example\n// ===END PRIVATE DOMAINS===\n")
    try:
        assert detectors.set_public_suffixes(str(psl)) == 1
        assert detectors.shared_platform("a.tenants.example") == "tenants.example"
        assert detectors.shared_platform("b.x.zone.example") == "x.zone.example"
        assert detectors.shared_platform("tenants.example") is None             # the platform itself is no tenant
        assert detectors.base_domain("a.tenants.example") == "tenants.example"  # ICANN-only registrable domains
    finally:
        detectors.set_public_suffixes(None)
    assert detectors.shared_platform("a.tenants.example") is None
    assert detectors.shared_platform("x.github.io") == "github.io"            # built in, list or not


def test_site_width_matches_other_names_of_the_same_site():
    s = Store(":memory:")
    for d, name in zip([20, 12, 4], ["a.example.com", "b.example.com", "c.example.com"]):
        close(s, add(s, ts=NOW - d * DAY, indicators=(name,)))
    new = row(s, add(s, indicators=("d.example.com",)))
    ok, reason, _ = judge.eligible(s.db, new, before=NOW + 60)
    assert not ok and "no owner precedent" in reason                          # the exact name is new
    ok, reason, prec = judge.eligible(s.db, new, before=NOW + 60, width="site")
    assert ok and len(prec) == 3, reason
    # an unrelated site that ends the same way is not this one
    assert not judge.eligible(s.db, row(s, add(s, indicators=("d.notexample.com",))), before=NOW + 60,
                              width="site")[0]


def test_tenants_of_a_shared_platform_never_widen():
    s = Store(":memory:")
    for d, name in zip([20, 12, 4], ["a.github.io", "b.github.io", "c.github.io"]):
        close(s, add(s, ts=NOW - d * DAY, indicators=(name,)))
    new = row(s, add(s, indicators=("evil.github.io",)))
    for width in judge.WIDTHS[:4]:
        ok, reason, _ = judge.eligible(s.db, new, before=NOW + 60, width=width)
        assert not ok, (width, reason)


def test_a_true_positive_on_a_site_blocks_its_site_widths_from_any_detector():
    s = Store(":memory:")
    for d, name in zip([20, 12, 4], ["a.example.com", "b.example.com", "c.example.com"]):
        close(s, add(s, ts=NOW - d * DAY, indicators=(name,)))
    # another detector, another device, another name of the same site: called a true positive
    close(s, add(s, detector="beaconing", host="192.168.50.99", ts=NOW - 60 * DAY, indicators=("c2.example.com",)),
          disposition="true_positive", label_ts=NOW - 59 * DAY)
    new = row(s, add(s, indicators=("d.example.com",)))
    ok, reason, _ = judge.eligible(s.db, new, before=NOW + 60, width="site")
    assert not ok and "site was called a true positive" in reason
    # the narrow key is unaffected: c2.example.com is not cdn.example.com
    history(s, [21, 13, 5])
    assert judge.eligible(s.db, row(s, add(s)), before=NOW + 60)[0]


def test_category_width_matches_the_kind_of_site_across_devices_only_when_nothing_is_odd():
    s = Store(":memory:")
    ads = {"categories": ["advertising"], "popular": 1, "count": 1}
    for d, host, name in zip([20, 12, 4, 19, 11, 3], ["192.168.50.10"] * 3 + ["192.168.50.20"] * 3,
                             ["a.ads1.example", "b.ads2.example", "c.ads3.example", "d.ads4.example",
                              "e.ads5.example", "f.ads6.example"]):
        close(s, add(s, host=host, ts=NOW - d * DAY, indicators=(name,), facts=ads))
    new = row(s, add(s, host="192.168.50.30", indicators=("x.ads9.example",), facts=ads))
    ok, reason, prec = judge.eligible(s.db, new, before=NOW + 60, width="category")
    assert ok and len(prec) == 6, reason
    assert "kind of site" in judge.decide(s.db, new["id"])["widths"]
    # an unranked name, a random-looking one, another category: never matched by it
    for facts in ({**ads, "popular": 0}, {**ads, "random": 1}, {**ads, "newly_registered": 1},
                  {"categories": ["file_hosting"], "popular": 1, "count": 1}):
        ok, reason, _ = judge.eligible(s.db, row(s, add(s, indicators=("y.ads9.example",), facts=facts)),
                                       before=NOW + 60, width="category")
        assert not ok, (facts, reason)
    # other detectors don't opt in: the width isn't recorded for them
    other = add(s, detector="beaconing", indicators=("z.ads9.example",), facts=ads)
    assert "category" not in json.loads(judge.decide(s.db, other)["widths"])


def test_widths_that_dont_apply_are_left_out_of_the_shadow_answer():
    s = Store(":memory:")
    cid = add(s, detector="host_lolbin", indicators=("rundll32.exe",))
    assert set(json.loads(judge.decide(s.db, cid)["widths"])) == {"device", "any_device"}


def test_benchmark_says_which_detectors_suit_a_judge():
    from tapwatch import benchmark

    s = Store(":memory:")
    history(s, [20, 12, 4])
    judge.decide(s.db, add(s, ts=NOW + 60))                                         # eligible
    for name in ("n1.example.net", "n2.example.org"):
        judge.decide(s.db, add(s, detector="beaconing", indicators=(name,), ts=NOW + 60))   # never repeats
    fit = {r["detector"]: r for r in benchmark.judge_fit(s.db)}
    assert fit["new_domain"]["eligible"] == 1 and fit["new_domain"]["reading"] == "eligible"
    assert fit["beaconing"]["reading"] == "rare" and "no owner precedent" in fit["beaconing"]["top_reason"]
    judge.decide(s.db, add(s, indicators=("uncategorised.example.info",), ts=NOW + 60))   # widest: category
    fit = {r["detector"]: r for r in benchmark.judge_fit(s.db)}
    assert fit["new_domain"]["cases"] == 2 and fit["new_domain"]["reading"] == "eligible"   # one of two
    s.db.execute("DELETE FROM judge_decisions WHERE eligible=1")
    assert {r["detector"]: r for r in benchmark.judge_fit(s.db)}["new_domain"]["reading"] == "context"
    md = benchmark.judge_markdown(s.db)
    assert "Which detectors suit the judge" in md and "rarely repeat" in md
