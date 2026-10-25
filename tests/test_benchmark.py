"""benchmark.py: week-by-week noise rate and Jev agreement, and host-context accuracy, from the case desk."""

import json

from conftest import T0

from tapwatch import benchmark, ui
from tapwatch.cli import main
from tapwatch.models import Case
from tapwatch.router import Route
from tapwatch.store import Store

WEEK = 7 * 86400


def seed(store: Store):
    """Two weeks of cases: week one noisy and Jev wrong twice; week two cleaner, Jev right, one true positive."""
    rows = [  # (first_ts, route, disposition, jev category, host_who, host_jev_who, corroborated)
        (T0, "alert", "false_positive", "c2_beaconing", "owner_using_agent", "owner_using_agent", True),
        (T0 + 100, "digest", "benign_expected", "c2_beaconing", "other_program", "agent_misused", False),
        (T0 + 200, "digest", "benign_expected", "benign", None, None, False),
        (T0 + 300, "log", None, None, "agent_unconfirmed", None, False),
        (T0 + WEEK, "alert", "true_positive", "c2_beaconing", "agent_misused", "agent_misused", False),
        (T0 + WEEK + 100, "digest", "benign_expected", "benign", "other_program", "other_program", False),
        (T0 + WEEK + 200, "digest", "false_positive", "unknown", None, None, False),
    ]
    for i, (ts, route, disp, cat, who, jev_who, corr) in enumerate(rows):
        facts = {"port": 3478, "dedupe": f"port:{i}"}
        if who:
            facts.update(host_who=who, host_corroborated=corr)
            if jev_who:
                facts["host_jev_who"] = jev_who
        case = Case("beaconing", "192.168.50.10", ts, "Regular repeating connection", facts, [f"dest{i}.example"])
        cid = store.add(case, "summary", None, Route(route), "rules")
        verdict = json.dumps({"category": cat, "category_confidence": 0.9}) if cat else None
        store.db.execute("UPDATE cases SET verdict = ?, disposition = ?, status = ? WHERE id = ?",
                         (verdict, disp, "closed" if disp else "new", cid))
    store.db.commit()


def test_weekly_noise_rate_and_jev_agreement(tmp_path):
    store = Store(str(tmp_path / "t.db"))
    seed(store)
    w1, w2 = benchmark.weekly(store.db)
    assert (w1["cases"], w1["alerts"], w1["decided"], w1["noise"], w1["true_positives"]) == (4, 1, 3, 3, 0)
    assert w1["noise_rate"] == 1.0
    # Jev called the first two C2 (owner said noise: disagree) and the third benign (agree): 1 of 3
    assert (w1["jev_decided"], w1["jev_agree"]) == (3, 1) and abs(w1["jev_agreement"] - 1 / 3) < 1e-9
    assert (w2["cases"], w2["decided"], w2["noise"], w2["true_positives"]) == (3, 3, 2, 1)
    # week two: C2 on the true positive (agree), benign on the benign (agree); "unknown" is not a category: 2 of 2
    assert (w2["jev_decided"], w2["jev_agree"], w2["jev_agreement"]) == (2, 2, 1.0)
    assert w1["week"] < w2["week"]


def test_host_context_accuracy_counts_only_claims(tmp_path):
    store = Store(str(tmp_path / "t.db"))
    seed(store)
    h = benchmark.host_context(store.db)
    assert h["cases"] == 5 and h["corroborated"] == 1
    assert h["who"] == {"owner_using_agent": 1, "other_program": 2, "agent_unconfirmed": 1, "agent_misused": 1}
    # Jev's who was recorded four times and matched code's three times
    assert (h["jev_asked"], h["jev_agree"]) == (4, 3) and h["jev_agreement"] == 0.75
    # claims: the owner's agent (closed FP: right) and a misused agent (closed TP: right); other_program names who
    # held the connection and claims nothing about intent, agent_unconfirmed claims nothing, the undecided case is out
    assert (h["claims"], h["claims_right"], h["accuracy"]) == (2, 2, 1.0)


def test_benchmark_markdown_stats_page_and_command(tmp_path, capsys):
    store = Store(str(tmp_path / "t.db"))
    seed(store)
    md = benchmark.markdown(store.db, now=T0 + 2 * WEEK)
    assert "| week | cases | alerts | decided | noise rate | true positives | Jev agreement |" in md
    assert "| 100% | 0 | 33% (3) |" in md and "| 67% | 1 | 100% (2) |" in md
    assert "5 cases on the PC, 1 corroborated" in md and "matched the owner's disposition on 100% of 2" in md
    page = ui.render_stats(store)[1]
    assert "Week by week" in page and "Host context: code, Jev and you" in page and "agent misused" in page
    assert "Jev agreed with code on 75% of the 4 it was asked" in page and "agreed 100% of 2 times" in page
    (tmp_path / "config.yaml").write_text("db_path: " + str(tmp_path / "t.db") + "\n")
    assert main(["-c", str(tmp_path / "config.yaml"), "benchmark"]) == 0
    assert "### Benchmark" in capsys.readouterr().out
    assert benchmark.weekly(Store(str(tmp_path / "empty.db")).db) == []
    assert benchmark.host_context(Store(str(tmp_path / "empty.db")).db)["accuracy"] is None


# ---------------------------------------------------------------- the judge's scorecard (#203)

def judged(store: Store, detector: str, ts: float, device: bool, any_device: bool | None, disposition=None,
           actor="ui owner") -> int:
    """One case with a shadow decision recorded at both widths, closed by `actor` when a disposition is given.
    any_device None is a row from before per-width answers: top-level columns only."""
    n = store.db.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
    case = Case(detector, "192.168.50.10", ts, "test case", {"dedupe": f"j{n}"}, [f"host{n}.example.com"])
    cid = store.add(case, "summary", None, Route.DIGEST, "rules-only")
    widths = {} if any_device is None else {
        w: {"eligible": c, "suggestion": "close_noise" if c else "leave"}
        for w, c in (("device", device), ("any_device", any_device))}
    store.db.execute("INSERT OR REPLACE INTO judge_decisions (case_id, ts, model_version, eligible, suggestion,"
                     " confidence, precedent_ids, explanation, widths) VALUES (?,?,?,?,?,?,?,?,?)",
                     (cid, ts, "test", int(device), "close_noise" if device else "leave", 0.8, "[]", "test",
                      json.dumps(widths)))
    store.db.commit()
    if disposition:
        store.update_case(cid, actor, status="closed", disposition=disposition)
    return cid


def judge_history(store: Store) -> int:
    """Two weeks of shadow decisions. new_domain: three owner-agreed would-closes at the device width, and a true
    positive only the any-device width would have closed. Returns that true positive's case id."""
    w0, w1 = T0, T0 + WEEK
    judged(store, "new_domain", w0, True, True, "benign_expected")                                     # owner
    judged(store, "new_domain", w0 + 60, True, True, "false_positive", "cli (requested by the user)")  # counted
    judged(store, "new_domain", w1, True, True, "benign_expected", "tapwatch explain")                 # counted
    tp = judged(store, "new_domain", w1 + 60, False, True, "true_positive")                            # any device
    judged(store, "new_domain", w1 + 120, True, True, "benign_expected", "claude")                     # an AI's own
    judged(store, "new_domain", w1 + 180, True, True)                                                  # undecided
    judged(store, "new_domain", w0 + 120, False, False, "benign_expected")                             # leave
    judged(store, "beaconing", w0, True, True, "benign_expected")
    judged(store, "beaconing", w1, True, False, "benign_expected")
    return tp


def _det(card, detector, width):
    return next(d for d in card["detectors"] if d["detector"] == detector and d["width"] == width)


def test_judge_agreement_counts_only_the_owners_would_close_dispositions(tmp_path):
    store = Store(str(tmp_path / "t.db"))
    judge_history(store)
    nd = _det(benchmark.judge(store.db), "new_domain", "device")
    # 7 judged, 5 would close; of those the owner decided 3 (owner, owner_request, explain): the AI's own close and
    # the undecided case are out, and the "leave" claims nothing even though the owner decided it
    assert (nd["cases"], nd["would_close"], nd["decided"], nd["agree"]) == (7, 5, 3, 3)
    assert nd["agreement"] == 1.0 and abs(nd["saved"] - 5 / 7) < 1e-9 and nd["weeks"] == 2
    # the latest disposition's actor is the one that counts: an AI's close the owner later redid becomes the owner's
    cid = judged(store, "beaconing", T0 + WEEK + 60, True, True, "benign_expected", "claude")
    assert _det(benchmark.judge(store.db), "beaconing", "device")["decided"] == 2
    store.update_case(cid, "ui owner", status="investigating")
    store.update_case(cid, "ui owner", status="closed", disposition="true_positive")
    b = _det(benchmark.judge(store.db), "beaconing", "device")
    assert (b["decided"], b["agree"], b["tp_closed"], b["tp_ids"]) == (3, 2, 1, [cid])
    assert abs(b["agreement"] - 2 / 3) < 1e-9


def test_judge_scores_each_width_on_its_own_answers(tmp_path):
    store = Store(str(tmp_path / "t.db"))
    tp = judge_history(store)
    card = benchmark.judge(store.db)
    dev, anyd = _det(card, "new_domain", "device"), _det(card, "new_domain", "any_device")
    assert (dev["would_close"], dev["tp_closed"]) == (5, 0)
    assert (anyd["would_close"], anyd["tp_closed"], anyd["tp_ids"]) == (6, 1, [tp])
    assert (anyd["decided"], anyd["agree"]) == (4, 3)   # the true positive is the owner's, and a disagreement
    assert _det(card, "beaconing", "device")["would_close"] == 2
    assert _det(card, "beaconing", "any_device")["would_close"] == 1
    # week rows: per detector, and one for all detectors, at each width
    w1_all_any = next(w for w in card["weeks"] if w["week"] == benchmark._week(T0 + WEEK) and w["detector"] is None
                      and w["width"] == "any_device")
    assert (w1_all_any["cases"], w1_all_any["would_close"], w1_all_any["tp_closed"]) == (5, 4, 1)
    # a decision recorded before per-width answers scores at the device width only
    judged(store, "port_scan", T0, True, None, "benign_expected")
    card = benchmark.judge(store.db)
    assert _det(card, "port_scan", "device")["would_close"] == 1
    assert not [d for d in card["detectors"] if d["detector"] == "port_scan" and d["width"] == "any_device"]


def test_a_would_closed_true_positive_shows_in_red_and_disqualifies(tmp_path, capsys):
    store = Store(str(tmp_path / "t.db"))
    tp = judge_history(store)
    assert not any(d["qualifies"] for d in benchmark.judge(store.db)["detectors"])   # far short of the volume bars
    # with the volume bars lowered to this fixture, only the true positive (and thin evidence) stands in the way
    low = benchmark.Qualify(min_decided=2, min_weeks=2)
    card = benchmark.judge(store.db, qualify=low)
    assert _det(card, "new_domain", "device")["qualifies"] is True
    anyd = _det(card, "new_domain", "any_device")
    assert anyd["qualifies"] is False and "would have closed 1 true positive(s)" in anyd["why"]
    assert "agreement 75%, needs 98%" in anyd["why"]
    assert _det(card, "beaconing", "device")["qualifies"] is True
    assert "1 week(s) of them, needs 2" in _det(card, "beaconing", "any_device")["why"]
    md = benchmark.judge_markdown(store.db, qualify=low)
    assert f"| new_domain | any device | 7 | 6 | 75% (3/4) | 86% (6/7) | **1** (#{tp}) | 2 | no: would have closed" in md
    assert "| new_domain | same device | 7 | 5 | 100% (3/3) | 71% (5/7) | 0 | 2 | **yes** |" in md
    assert "| **all** | any device |" in md
    page = ui.render_stats(store, low)[1]
    assert "Judge scorecard (shadow)" in page and f'<b class="err">1</b> <a href="/case/{tp}">#{tp}</a>' in page
    assert '<tr class="r-alert"><td class="mono">new_domain</td><td>any device</td>' in page
    assert "qualifies</span>" in page
    # and `tapwatch benchmark` carries it
    (tmp_path / "config.yaml").write_text("db_path: " + str(tmp_path / "t.db") + "\n")
    assert main(["-c", str(tmp_path / "config.yaml"), "benchmark"]) == 0
    out = capsys.readouterr().out
    assert "#### Judge scorecard (shadow decisions)" in out and f"**1** (#{tp})" in out


def test_judge_replay_scores_history_before_any_shadow_data(tmp_path, capsys):
    from tapwatch import judge

    store = Store(str(tmp_path / "t.db"))
    for days in (20, 12, 4):   # owner precedent on three days in three weeks: the next case is eligible
        cid = store.add(Case("new_domain", "192.168.50.10", T0 - days * 86400, "test", {}, ["cdn.example.com"]),
                        "summary", None, Route.DIGEST, "rules-only")
        store.update_case(cid, "ui owner", status="closed", disposition="benign_expected")
        store.db.execute("UPDATE judge_examples SET labelled_ts=? WHERE case_id=?", (T0 - days * 86400 + 3600, cid))
    tp = store.add(Case("new_domain", "192.168.50.10", T0, "test", {}, ["cdn.example.com"]), "summary", None,
                   Route.DIGEST, "rules-only")
    store.update_case(tp, "ui owner", status="closed", disposition="true_positive")
    store.db.commit()
    assert not store.db.execute("SELECT 1 FROM judge_decisions").fetchone()
    assert benchmark.judge(store.db)["detectors"] == []
    assert "No judge decisions yet (`tapwatch benchmark --judge-replay`" in benchmark.judge_markdown(store.db)
    card = benchmark.judge(store.db, replay=True)
    dev = _det(card, "new_domain", "device")
    assert (dev["cases"], dev["would_close"], dev["tp_closed"], dev["tp_ids"]) == (4, 1, 1, [tp])
    assert dev["qualifies"] is False and judge.WIDTHS == card["widths"]
    assert not store.db.execute("SELECT 1 FROM judge_decisions").fetchone()   # read-only
    (tmp_path / "config.yaml").write_text("db_path: " + str(tmp_path / "t.db") + "\n")
    assert main(["-c", str(tmp_path / "config.yaml"), "benchmark", "--judge-replay"]) == 0
    assert f"**1** (#{tp})" in capsys.readouterr().out
