"""Judge auto-close (#204) and drift back-off with the digest section (#205). Both ship off."""

import http.client
import json
import re
import threading
import time
from pathlib import Path
from urllib.parse import urlencode

import pytest
import yaml

from tapwatch import benchmark, config, judge, ui
from tapwatch.models import Case, Route
from tapwatch.pipeline import Pipeline
from tapwatch.store import Store, WorkflowError
from tapwatch.summarizer import Assets

DAY = 86400
NOW = time.time()
HOST = "192.168.50.10"
LOW = benchmark.Qualify(min_decided=0, min_weeks=0)   # qualifies on any shadow decision without a true positive
ON = {"new_domain": ("device",)}


class Recorder:
    def __init__(self):
        self.sent = []

    def send(self, title, items):
        self.sent.append((title, items))
        return ["fake"]


def add(store, detector="new_domain", host=HOST, ts=NOW, indicators=("cdn.example.com",), facts=None,
        must_alert=False, route=Route.DIGEST, severity=2):
    case = Case(detector, host, ts, "test case", dict(facts or {}), list(indicators), must_alert, severity)
    return store.add(case, "state", None, route, "rules-only")


def close(store, case_id, actor="ui owner", disposition="benign_expected"):
    store.update_case(case_id, actor, status="closed", disposition=disposition)
    store.db.execute("UPDATE judge_examples SET labelled_ts=? WHERE case_id=?",
                     (store.get(case_id)["first_ts"] + 3600, case_id))
    store.db.commit()


def seeded(path=":memory:", host=HOST, days=(20, 12, 4), detector="new_domain"):
    """Owner precedent for new_domain / cdn.example.com on three days in three weeks: the next one is eligible."""
    s = Store(path)
    for d in days:
        close(s, add(s, detector=detector, host=host, ts=NOW - d * DAY))
    s.mark_digested([r[0] for r in s.db.execute("SELECT id FROM cases")])   # earlier digests listed them
    return s


def settings(**kw):
    return judge.Settings(**{"auto_close": True, "detectors": ON, "qualify": LOW, **kw})


def pipe(store, notifier=None, base_url=None, **kw):
    return Pipeline([], Assets(), store, notifier=notifier, base_url=base_url,
                    autoclose=judge.AutoClose(settings(**kw)))


def raise_case(p, ts=NOW + 60, host=HOST, indicators=("cdn.example.com",), facts=None, must_alert=False, severity=2,
               detector="new_domain"):
    facts = {"count": 1, "via": "DNS", "random": False, "shared": False, "popular_known": False, **(facts or {})}
    return p.handle(Case(detector, host, ts, "New domain", facts, list(indicators), must_alert, severity))[0]


def stored(store, route=Route.DIGEST, **kw):
    """A case stored and shadow-judged without the pipeline, for consider() on its own."""
    cid = add(store, ts=NOW + 60, route=route, **kw)
    judge.decide(store.db, cid)
    return cid


# ---------------------------------------------------------------- off by default

def test_config_defaults_are_off_and_the_example_config_says_so():
    d = judge.Settings.from_config({})
    assert (d.auto_close, d.detectors, d.alerts) == (False, {}, False)
    assert d.qualify == benchmark.Qualify() == benchmark.Qualify(50, 4, 0.98, 0)
    assert (d.backoff_days, d.max_undo_rate, d.min_confidence) == (14, 0.02, 0.8)
    example = yaml.safe_load((Path(__file__).parent.parent / "config.example.yaml").read_text())
    ex = config.judge_settings(example)
    assert (ex.auto_close, ex.detectors, ex.alerts) == (False, {}, False)
    assert ex.qualify == benchmark.Qualify() and ex.backoff_days == 14 and ex.max_undo_rate == 0.02
    assert "auto-close is off" in ex.summary()
    # "true" as a string, or any truthy junk, is not a yes
    assert judge.Settings.from_config({"judge": {"auto_close": "yes", "auto_close_alerts": 1}}).auto_close is False
    q = benchmark.Qualify.from_config({"judge": {"qualify": {"min_decided": 80, "max_true_positives": 0}}})
    assert (q.min_decided, q.min_weeks, q.min_agreement) == (80, 4, 0.98)


def test_allow_list_shapes():
    assert judge.allow_list(["new_domain", "beaconing"]) == {"new_domain": ("device",), "beaconing": ("device",)}
    assert judge.allow_list({"new_domain": ["any_device", "device"]}) == {"new_domain": ("device", "any_device")}
    assert judge.allow_list({"new_domain": ["everywhere"]}) == {}          # an unknown width allows nothing
    assert judge.allow_list("new_domain") == {"new_domain": ("device",)}
    for junk in (None, True, 3, []):
        assert judge.allow_list(junk) == {}


def test_off_by_default_nothing_ever_closes():
    for ac in (None,                                                       # the pipeline's own default
               judge.AutoClose(),                                          # Settings() defaults
               judge.AutoClose(settings(auto_close=False)),                # listed and qualifying, but off
               judge.AutoClose(settings(detectors={})),                    # on, but nothing listed
               judge.AutoClose(config.judge_settings({"judge": {"auto_close_detectors": ["new_domain"]}}))):
        s = seeded()
        p = Pipeline([], Assets(), s, autoclose=ac)
        cid = raise_case(p)
        assert s.judge_decision(cid)["suggestion"] == "close_noise"       # the judge would, in shadow
        assert (s.get(cid)["status"], s.get(cid)["disposition"]) == ("new", None)
        assert not s.db.execute("SELECT 1 FROM judge_closures").fetchone()
        assert not s.db.execute("SELECT 1 FROM audit WHERE actor LIKE '%judge%'").fetchone()


# ---------------------------------------------------------------- closing, and the guardrails when on

def test_on_it_closes_with_the_precedent_named_and_audited():
    s = seeded()
    cid = raise_case(pipe(s))
    r = s.get(cid)
    assert (r["status"], r["disposition"], r["route"]) == ("closed", "benign_expected", "digest")   # route kept
    trail = s.audit_trail(cid)
    assert {a["action"] for a in trail if a["actor"] == judge.ACTOR} == {"status", "disposition", "note"}
    assert judge.ACTOR == "judge precedent-1" and judge.label_source(judge.ACTOR) is None
    precedent = json.loads(s.judge_decision(cid)["precedent_ids"])
    note = s.notes(cid)[0]["text"]
    assert note.startswith("Closed by the judge (auto-close, same device width)")
    assert all(f"#{i}" in note for i in precedent) and len(precedent) == 3
    c = judge.closure(s.db, cid)
    assert (c["width"], json.loads(c["precedent_ids"]), c["undone_ts"]) == ("device", precedent, None)
    assert not s.db.execute("SELECT 1 FROM suppressions").fetchone()      # never suppresses
    assert not s.db.execute("SELECT 1 FROM judge_examples WHERE case_id=?", (cid,)).fetchone()


def test_the_guardrails_hold_when_it_is_on():
    def check(cid, s, ac, want, now=None):
        before = s.get(cid)["status"]
        closed, why = ac.consider(s, cid, now)
        assert not closed and want in why, (want, why)
        assert s.get(cid)["status"] == before and not judge.closure(s.db, cid)

    ac = judge.AutoClose(settings())
    s = seeded()
    check(stored(s, must_alert=True, route=Route.ALERT), s, ac, "always-alert")
    check(stored(s, facts={"min_route": "alert"}), s, ac, "would leave it")          # code floor
    check(stored(s, facts={"correlated_best": "alert"}), s, ac, "would leave it")    # paired with an alert
    check(stored(s, facts={"host_who": "agent_misused"}), s, ac, "would leave it")
    check(stored(s, indicators=("never-seen.example.net",)), s, ac, "would leave it")
    check(stored(s, route=Route.ALERT), s, ac, "alert-routed")                       # the owner's default: never
    check(stored(s, detector="beaconing"), s, ac, "not in judge.auto_close_detectors")
    check(stored(s), s, judge.AutoClose(settings(qualify=None)), "does not qualify")  # the real bar: 50 in 4 weeks
    check(stored(s), s, judge.AutoClose(settings(min_confidence=0.95)), "confidence below")
    done = stored(s)
    s.update_case(done, "ui owner", status="investigating")                          # the owner already has it
    check(done, s, ac, "case is investigating")
    # the guardrails are re-checked when it acts: a true positive marked on the device after the case arrived (and
    # after its shadow decision) blocks it
    late = stored(s)
    close(s, add(s, detector="scan", indicators=("192.168.50.99",), ts=NOW), disposition="true_positive")  # NOW+1h
    assert s.judge_decision(late)["suggestion"] == "close_noise"
    check(late, s, ac, "not eligible: a true positive on this device", now=NOW + 7200)


def test_alert_routed_cases_close_only_when_allowed_and_after_the_alert_is_sent():
    # A rule Jev would judge (not code-only), so a rules-only severity-4 alert is not a critical code-only one, which
    # the guardrails refuse at any setting (a new_domain alert, below).
    allow = {"test_rule": ("device",)}

    def sent_order(note, s, cid):
        return [t for t, _ in note.sent], s.get(cid)["status"]

    s, note = seeded(detector="test_rule"), Recorder()
    cid = raise_case(pipe(s, note, alerts=True, detectors=allow), detector="test_rule", severity=4)
    assert s.get(cid)["route"] == "alert" and sent_order(note, s, cid) == (["tapwatch alert: New domain"], "closed")
    alert_audit = [a["actor"] for a in s.audit_trail(cid)]
    assert alert_audit and set(alert_audit) == {judge.ACTOR}                     # closed after; the alert went out
    s2, note2 = seeded(detector="test_rule"), Recorder()
    cid2 = raise_case(pipe(s2, note2, detectors=allow), detector="test_rule", severity=4)   # the default: never
    assert s2.get(cid2)["route"] == "alert" and note2.sent and s2.get(cid2)["status"] == "new"
    s3 = seeded()
    cid3 = raise_case(pipe(s3, alerts=True), severity=4)
    assert s3.get(cid3)["route"] == "alert" and s3.get(cid3)["status"] == "new"
    assert "critical code-only alert" in s3.judge_decision(cid3)["ineligible_reason"]


def test_the_wider_key_closes_only_when_listed_for_it():
    s = seeded()
    for d in (19, 11, 3):
        close(s, add(s, host="192.168.50.30", ts=NOW - d * DAY))
    other = "192.168.50.20"   # a device with no precedent of its own: only the any-device width says close
    cid = raise_case(pipe(s), host=other)
    assert s.get(cid)["status"] == "new"
    cid = raise_case(pipe(s, detectors={"new_domain": ("device", "any_device")}), host=other, ts=NOW + 7200)
    assert s.get(cid)["status"] == "closed" and judge.closure(s.db, cid)["width"] == "any_device"
    assert "any device width" in s.notes(cid)[0]["text"]


def test_a_crashing_judge_never_loses_the_case_or_its_alert(monkeypatch):
    s, note = seeded(), Recorder()
    p = pipe(s, note)
    monkeypatch.setattr(judge.AutoClose, "consider", lambda *a, **k: 1 / 0)
    cid = raise_case(p, severity=4)
    assert note.sent and s.get(cid)["status"] == "new"


# ---------------------------------------------------------------- never training, never agreement

def test_judge_closes_never_become_training_examples_or_scorecard_agreement():
    s = seeded()
    p = pipe(s)
    first = raise_case(p)
    assert s.get(first)["status"] == "closed"
    assert s.db.execute("SELECT COUNT(*) FROM judge_examples").fetchone()[0] == 3     # only the owner's three
    nd = next(d for d in benchmark.judge(s.db)["detectors"] if d["width"] == "device")
    assert (nd["would_close"], nd["decided"], nd["agree"]) == (1, 0, 0)             # closed, but not "agreed"
    # the next case still rests on the owner's three closes, not on the judge's own
    nxt = raise_case(p, ts=NOW + 7200)
    assert len(json.loads(s.judge_decision(nxt)["precedent_ids"])) == 3 and first not in json.loads(
        s.judge_decision(nxt)["precedent_ids"])
    assert judge.backfill(s.db) == {}                                                 # nothing to add from the judge
    # once the owner undoes it and closes it themselves, it is the owner's label like any other
    s.undo_judge_close(first, "ui owner")
    close(s, first)
    assert s.db.execute("SELECT label_source FROM judge_examples WHERE case_id=?", (first,)).fetchone()[0] == "owner"


# ---------------------------------------------------------------- undo

def test_undo_reopens_clears_the_disposition_and_is_audited():
    s = seeded()
    cid = raise_case(pipe(s))
    page = ui.render_case(s, Assets(), cid, [], "tok")[1]
    assert "Closed by the judge" in page and f'action="/case/{cid}/undo-judge"' in page
    s.undo_judge_close(cid, "ui owner")
    r = s.get(cid)
    assert (r["status"], r["disposition"], r["feedback"]) == ("investigating", None, None)
    mine = [(a["action"], a["old"], a["new"]) for a in s.audit_trail(cid) if a["actor"] == "ui owner"]
    assert ("status", "closed", "investigating") in mine and ("disposition cleared", "benign_expected", None) in mine
    c = judge.closure(s.db, cid)
    assert (c["undone_how"], c["undone_by"]) == ("undo", "ui owner")
    with pytest.raises(WorkflowError, match="already undone"):
        s.undo_judge_close(cid, "ui owner")
    with pytest.raises(WorkflowError, match="did not close"):
        s.undo_judge_close(1, "ui owner")                                             # the owner's own close
    page = ui.render_case(s, Assets(), cid, [], "tok")[1]
    assert "undone by ui owner" in page and "undo-judge" not in page
    # the scorecard and backfill read the empty label as no label
    assert judge.backfill(s.db) == {}
    assert next(d for d in benchmark.judge(s.db)["detectors"] if d["width"] == "device")["decided"] == 0


def test_a_case_changed_since_the_judge_closed_it_is_not_undone_over_the_owner():
    s = seeded()
    cid = raise_case(pipe(s))
    s.update_case(cid, "ui owner", disposition="false_positive")
    with pytest.raises(WorkflowError, match="changed since"):
        s.undo_judge_close(cid, "ui owner")
    assert judge.closure(s.db, cid)["undone_ts"] is None                             # fp vs benign: still agreeing


@pytest.fixture
def desk(tmp_path):
    started = []

    def start(db):
        app = ui.App(db, Assets(), port=0, judge_settings=settings())
        srv = ui.make_server(app)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        started.append(srv)
        return app

    yield start
    for srv in started:
        srv.shutdown()
        srv.server_close()


def _req(app, method, path, body=None, cookie=None):
    c = http.client.HTTPConnection("127.0.0.1", app.port, timeout=5)
    headers = {"Host": f"127.0.0.1:{app.port}"}
    if cookie:
        headers["Cookie"] = f"{ui.COOKIE}={cookie}"
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    c.request(method, path, body=urlencode(body) if body is not None else None, headers=headers)
    r = c.getresponse()
    text = r.read().decode()
    c.close()
    return r, text


def test_undo_through_the_desk_one_case_and_one_day(desk, tmp_path):
    db = str(tmp_path / "t.db")
    s = seeded(db)
    p = pipe(s)
    a, b, c = (raise_case(p, ts=NOW + 60 + i * 7200) for i in range(3))
    app = desk(db)
    r, text = _req(app, "GET", "/judge")
    assert r.status == 200 and "What the judge closed" in text and all(f'href="/case/{i}"' in text for i in (a, b, c))
    sid = re.search(rf"{ui.COOKIE}=([^;]+)", r.getheader("Set-Cookie")).group(1)
    csrf = re.search(r'name="csrf" value="([^"]+)"', text).group(1)
    assert _req(app, "POST", f"/case/{a}/undo-judge", {})[0].status == 403            # CSRF still applies
    r, _ = _req(app, "POST", f"/case/{a}/undo-judge", {"csrf": csrf}, sid)
    assert r.status == 303 and Store(db).get(a)["status"] == "investigating"
    r, text = _req(app, "POST", f"/case/{a}/undo-judge", {"csrf": csrf}, sid)
    assert r.status == 400 and "already undone" in text
    day = time.strftime("%Y-%m-%d", time.localtime(judge.closure(s.db, b)["ts"]))
    r, _ = _req(app, "POST", "/judge/undo-day", {"csrf": csrf, "day": day}, sid)
    assert r.status == 303
    assert {Store(db).get(i)["status"] for i in (a, b, c)} == {"investigating"}
    assert _req(app, "POST", "/judge/undo-day", {"csrf": csrf, "day": "junk"}, sid)[0].status == 400


# ---------------------------------------------------------------- back-off (#205)

def test_an_undo_backs_the_detector_off_and_the_digest_says_so():
    s, note = seeded(), Recorder()
    p = pipe(s, note)
    cid = raise_case(p)
    s.undo_judge_close(cid, "ui owner")
    nxt = raise_case(p, ts=NOW + 7200)
    assert s.get(nxt)["status"] == "new"                                             # stopped: back to the owner
    b = judge.backoff_active(s.db, "new_domain")
    assert b is not None and "undid 1 of its 1 close(s) in the last 14 days" in b["reason"]
    assert s.db.execute("SELECT new FROM audit WHERE action='judge back-off'").fetchone()[0].startswith("new_domain:")
    assert p.autoclose.consider(s, nxt) == (False, "backed off")
    p.send_digest()
    title, items = note.sent[-1]
    assert "judge back-off" in title
    assert any(i["heading"] == "The judge stopped auto-closing new_domain" for i in items)
    assert p.send_digest() == 0                                                       # said once
    assert "backed off" not in judge.Settings().summary()


def test_reopening_and_marking_true_positive_backs_off_without_the_undo_button():
    s = seeded()
    p = pipe(s)
    cid = raise_case(p)
    s.update_case(cid, "ui owner", status="investigating")
    s.update_case(cid, "ui owner", status="closed", disposition="true_positive")
    assert judge.closure(s.db, cid)["undone_how"] == "true_positive"
    p.autoclose.review(s.db)
    assert "called a case it closed a true positive" in judge.backoff_active(s.db, "new_domain")["reason"]


def test_a_true_positive_among_the_cases_it_only_suggested_backs_it_off():
    s = seeded()
    ac = judge.AutoClose(settings(qualify=None))     # listed, not yet qualifying: it only suggests
    cid = stored(s)
    assert s.judge_decision(cid)["suggestion"] == "close_noise" and not ac.consider(s, cid)[0]
    close(s, cid, disposition="true_positive")
    ac.review(s.db)
    assert f"would have closed was called a true positive (#{cid})" in judge.backoff_active(s.db, "new_domain")["reason"]


def test_one_undo_in_many_closes_stays_under_the_rate():
    s = seeded()
    ac = judge.AutoClose(settings(max_undo_rate=0.5))
    p = Pipeline([], Assets(), s, autoclose=ac)
    ids = [raise_case(p, ts=NOW + 60 + i * 7200) for i in range(3)]
    assert all(s.get(i)["status"] == "closed" for i in ids)
    s.undo_judge_close(ids[0], "ui owner")
    assert ac.drift(s.db, "new_domain", time.time()) is None                         # 1 of 3 is under 50%
    s.undo_judge_close(ids[1], "ui owner")
    assert "undid 2 of its 3" in ac.drift(s.db, "new_domain", time.time())


def test_back_off_lifts_only_after_a_fresh_qualification_window():
    s, note = seeded(), Recorder()
    ac = judge.AutoClose(settings(qualify=benchmark.Qualify(min_decided=1, min_weeks=1)))
    ac._qualified, ac._qualified_ts = {("new_domain", "device")}, time.time()       # qualified on its history
    p = Pipeline([], Assets(), s, notifier=note, autoclose=ac)
    s.undo_judge_close(raise_case(p), "ui owner")
    held = raise_case(p, ts=NOW + 7200)
    assert s.get(held)["status"] == "new" and judge.backoff_active(s.db, "new_domain")
    ac.review(s.db)                                  # nothing decided since the back-off: still off
    assert judge.backoff_active(s.db, "new_domain")
    close(s, held)                                   # the owner decides a would-close case raised since: agreement
    ac.review(s.db)
    assert judge.backoff_active(s.db, "new_domain") is None
    assert s.db.execute("SELECT 1 FROM audit WHERE action='judge back-off lifted'").fetchone()
    assert ac.drift(s.db, "new_domain", time.time()) is None                         # the old undo is spent
    p.send_digest()
    assert any(i["heading"] == "The judge resumed auto-closing new_domain" for i in note.sent[-1][1])
    ac._qualified, ac._qualified_ts = {("new_domain", "device")}, time.time()
    assert s.get(raise_case(p, ts=NOW + 4 * 7200))["status"] == "closed"


# ---------------------------------------------------------------- the digest section (#205)

def test_digest_lists_what_the_judge_closed_per_detector_with_links():
    s, note = seeded(), Recorder()
    p = pipe(s, note, base_url="https://desk.example.com")
    ids = [raise_case(p, ts=NOW + 60 + i * 7200) for i in range(2)]
    assert all(s.get(i)["status"] == "closed" for i in ids)
    p.send_digest()
    title, items = note.sent[-1]
    assert "2 closed by the judge" in title and "item(s) to review" not in title    # not listed to read as well
    sec = next(i for i in items if i["heading"] == "What the judge closed: 2 case(s)")
    assert sec["facts"]["new_domain"] == "2: " + ", ".join(f"https://desk.example.com/case/{i}" for i in ids)
    assert "Undo" in sec["facts"] and "new_domain 2 closed, 0 undone" in sec["facts"]["Last 7 days"]
    assert not [i for i in items if i["heading"] == "New domain"]                     # the closed digest cases
    assert p.send_digest() == 0                                                       # each close is listed once
    assert s.db.execute("SELECT COUNT(*) FROM cases WHERE digested=0 AND route='digest'").fetchone()[0] == 0


def test_digest_without_the_judge_is_unchanged():
    s, note = seeded(), Recorder()
    p = Pipeline([], Assets(), s, notifier=note)
    raise_case(p)
    p.send_digest()
    title, items = note.sent[-1]
    assert title == "tapwatch daily digest: 1 item(s) to review"
    assert not [i for i in items if "judge" in i["heading"].lower()]


# ---------------------------------------------------------------- the CLI

def test_cli_lists_and_undoes(tmp_path, capsys):
    from tapwatch.cli import main

    db = str(tmp_path / "t.db")
    s = seeded(db)
    cid = raise_case(pipe(s))
    (tmp_path / "config.yaml").write_text(f"db_path: {db}\n")
    cfg = ["-c", str(tmp_path / "config.yaml")]
    assert main(cfg + ["judge", "closed"]) == 0
    out = capsys.readouterr().out
    assert "auto-close is off" in out and f"#{cid}" in out and "new_domain" in out
    assert main(cfg + ["judge", "undo", str(cid)]) == 0
    assert Store(db).get(cid)["status"] == "investigating"
    assert main(cfg + ["judge", "undo", str(cid)]) == 1
    assert main(cfg + ["judge", "undo"]) == 2
