"""benchmark.py: week-by-week noise rate and Jev agreement, and host-context accuracy, from the case desk."""

import json

from conftest import T0

from tapwatch import benchmark, ui
from tapwatch.cli import main
from tapwatch.models import Case
from tapwatch.store import Store
from tapwatch.summarizer import Assets

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
        verdict = json.dumps({"category": cat, "category_confidence": 0.9}) if cat else None
        store.db.execute(
            "INSERT INTO cases (key, first_ts, last_ts, hits, detector, host, title, facts, indicators, must_alert, state, "
            "verdict, route, reason, disposition, status) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, 0, 'open', ?, ?, 'rules', ?, ?)",
            (case.key, ts, ts, case.detector, case.host, case.title, json.dumps(facts), json.dumps(case.indicators),
             verdict, route, disp, "closed" if disp else "new"))
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
    # claims: owner (FP: right), other_program (benign: right), misused (TP: right), other_program (benign: right);
    # agent_unconfirmed makes no claim and the undecided case does not count
    assert (h["claims"], h["claims_right"], h["accuracy"]) == (4, 4, 1.0)


def test_benchmark_markdown_stats_page_and_command(tmp_path, capsys):
    store = Store(str(tmp_path / "t.db"))
    seed(store)
    md = benchmark.markdown(store.db, now=T0 + 2 * WEEK)
    assert "| week | cases | alerts | decided | noise rate | true positives | Jev agreement |" in md
    assert "| 100% | 0 | 33% (3) |" in md and "| 67% | 1 | 100% (2) |" in md
    assert "5 cases on the PC, 1 corroborated" in md and "matched the owner's disposition on 100% of 4" in md
    page = ui.render_stats(store)[1]
    assert "Week by week" in page and "Host context: code, Jev and you" in page and "agent misused" in page
    assert "Jev agreed with code on 75% of the 4 it was asked" in page
    (tmp_path / "config.yaml").write_text("db_path: " + str(tmp_path / "t.db") + "\n")
    assert main(["-c", str(tmp_path / "config.yaml"), "benchmark"]) == 0
    assert "### Benchmark" in capsys.readouterr().out
    assert benchmark.weekly(Store(str(tmp_path / "empty.db")).db) == []
    assert benchmark.host_context(Store(str(tmp_path / "empty.db")).db)["accuracy"] is None
    Assets()  # the stats page needs none; imported to keep the module's surface in one place
