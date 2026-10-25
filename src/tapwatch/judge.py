"""The learned judge (v0.4, #37): learn tier-1 triage from the owner's own closed cases, in shadow mode first.

Three parts, in order:

- **Training set (#200).** Every disposition writes a `judge_examples` row: the label, who decided it and the case's
  code facts as they were at that moment (`cases.facts` changes later, when a correlation partner arrives). Who
  decided is read from the audit actor (`label_source`). Only the owner's decisions count as precedent: closes made
  in the case desk, `tapwatch mark`, `tapwatch explain`'s Apply, and closes a triage session made at the owner's
  request (actor "cli (requested by ...)"). An AI that closed cases on its own (actor "claude") and tapwatch's own
  closes on arrival (a suppression matched) are recorded for the record but never count: learning them would teach
  the judge an AI's triage, then automate it. The judge's own actor never writes an example at all.
- **Guardrails (#201).** `eligible` says "not yours" before any scoring: always-alert, a code floor, a misused
  agent, a critical code-only alert, a correlated alert, a recent true positive on the device, and any case without
  enough owner precedent for the same (detector, device, key). Precedent counts the distinct days its cases
  happened on, and one ISO week can give at most half of them, so one burst of activity can't train a habit.
- **Shadow judge (#202).** After a case is stored, `decide` records what the judge *would* do and why, with the
  precedent case ids. It never changes a route, status or disposition, and never adds a suppression.

Precedent before models (roadmap, 2026-10-25): with 9 true positives in 1,198 labels a trained model adds risk and
hides its reasons, so the judge matches exact keys. Wider keys (a domain on any device) are earned per detector
through the scorecard (#203), never assumed. Nothing here touches the network.
"""

from __future__ import annotations

import json
import sqlite3
import time
from datetime import datetime

from .detectors import base_domain
from .models import Case, Route, Verdict, device_id, main_indicator
from .router import CODE_ONLY, agent_misused, critical

FEATURE_VERSION = 1
MODEL_VERSION = "precedent-1"
NOISE = ("false_positive", "benign_expected")
# Who decided, from the audit actor. Only COUNTED sources are precedent.
COUNTED = {"owner", "owner_request", "explain"}
# Distinct local days on which the precedent cases *happened*, not when they were closed: the owner closes in
# batches (on the live history the median close came 12 hours after the case, and one program's 130 closes fell on
# 2 labelling days), while what the cap is for, one burst of activity training a habit, is about occurrence.
MIN_PRECEDENT_DAYS = 3
MAX_WEEK_SHARE = 0.5          # one ISO week gives at most this share of those days
MAX_DEVICE_SHARE = 0.5        # at the "any_device" width, one device gives at most this share of the precedents
TP_LOOKBACK = 30 * 86400      # a true positive on the device this recently keeps the judge off it
KEY_WORDS = {"domain": "destination", "program": "program", "ind": "indicator", "detector": "case type"}
WIDTHS = ("device", "any_device")   # precedent key widths shadow mode records (see eligible)
PRECEDENT_LINKS = 5           # case ids named in an explanation


def label_source(actor: str) -> str | None:
    """Who made a disposition, from its audit actor. None: never an example (the judge itself)."""
    a = (actor or "").strip()
    if a.startswith("judge"):
        return None
    if a.startswith("ui ") or a == "cli":
        return "owner"           # the case desk, or `tapwatch mark` typed by the owner
    if a == "tapwatch explain":
        return "explain"         # the owner applied an explain suggestion (desk button or `explain --apply`)
    if "(requested by" in a:
        return "owner_request"   # a triage session closing what the owner asked it to
    if a == "tapwatch":
        return "suppression"     # closed on arrival by an owner's rule: the rule is the decision, not this case
    return "ai"                  # an AI session deciding on its own ("claude", "cli (triage handoff)")


def key_for(detector: str, facts: dict, indicators: list[str]) -> str:
    """The normalised "same thing" for precedent: a program's file name when host context named one, else the
    main indicator's registrable domain, else the indicator itself (an address, "ip:port", a dedupe fact)."""
    program = facts.get("host_program_path") or facts.get("program_path") or ""
    ind = main_indicator(indicators, facts)
    if not program and detector.startswith("host_"):
        program = ind   # the endpoint rules' indicator is the program itself (cmd.exe, rundll32.exe, pip)
    if program:
        return "program:" + str(program).replace("\\", "/").rsplit("/", 1)[-1].lower()
    if ind and any(c.isalpha() for c in ind.split(":")[0]):
        return "domain:" + base_domain(ind.lower())
    return f"ind:{ind}" if ind else f"detector:{detector}"


def features(row: sqlite3.Row) -> dict:
    """Code facts only, as the case stands now. No indicator text beyond the normalised key, no network strings."""
    facts = json.loads(row["facts"] or "{}")
    indicators = json.loads(row["indicators"] or "[]")
    verdict = json.loads(row["verdict"]) if row["verdict"] else {}
    return {
        "detector": row["detector"],
        "device": device_id(row["host"], facts),
        "key": key_for(row["detector"], facts, indicators),
        "port": facts.get("port") if isinstance(facts.get("port"), int) else None,
        "base_severity": row["base_severity"],
        "route": row["route"],
        "reason_class": (row["reason"] or "").split(":")[0][:40],
        "must_alert": bool(row["must_alert"]),
        "popular": facts.get("popular"),
        "host_who": facts.get("host_who"),
        "host_assessment": facts.get("host_assessment"),
        "correlated_best": facts.get("correlated_best"),
        "jev_category": verdict.get("category"),
        "jev_confidence": verdict.get("category_confidence"),
    }


def record_example(db: sqlite3.Connection, row: sqlite3.Row, disposition: str, actor: str, ts: float) -> bool:
    """Write (or supersede) the case's training example. Called inside the disposition's transaction."""
    source = label_source(actor)
    if source is None:
        return False
    f = features(row)
    db.execute("INSERT OR REPLACE INTO judge_examples (case_id, labelled_ts, label, label_source, actor, detector,"
               " device, key, features, feature_version) VALUES (?,?,?,?,?,?,?,?,?,?)",
               (row["id"], ts, disposition, source, actor, f["detector"], f["device"], f["key"], json.dumps(f),
                FEATURE_VERSION))
    return True


def backfill(db: sqlite3.Connection) -> dict[str, int]:
    """Build examples for cases decided before the judge existed, from each case's latest disposition in the audit
    trail. Facts are as stored now (correlations may have been added since): approximate, and marked as version 0."""
    db.row_factory = sqlite3.Row
    latest = db.execute("SELECT a.case_id, a.ts, a.actor, a.new FROM audit a JOIN (SELECT case_id, MAX(id) AS id FROM"
                        " audit WHERE action='disposition' GROUP BY case_id) m ON a.id = m.id").fetchall()
    counts: dict[str, int] = {}
    with db:
        for a in latest:
            row = db.execute("SELECT * FROM cases WHERE id=?", (a["case_id"],)).fetchone()
            if row is None or row["disposition"] != a["new"]:
                continue   # changed outside the audit trail (an old `mark` label): no actor to trust
            if record_example(db, row, a["new"], a["actor"], a["ts"]):
                db.execute("UPDATE judge_examples SET feature_version=0 WHERE case_id=?", (a["case_id"],))
                src = label_source(a["actor"])
                counts[src] = counts.get(src, 0) + 1
    return counts


def _case(row: sqlite3.Row) -> Case:
    facts = json.loads(row["facts"] or "{}")
    return Case(row["detector"], row["host"], row["first_ts"], row["title"], facts,
                json.loads(row["indicators"] or "[]"), bool(row["must_alert"]), row["base_severity"] or 2)


def _verdict(row: sqlite3.Row) -> Verdict | None:
    try:
        v = json.loads(row["verdict"]) if row["verdict"] else None
        return Verdict(**v) if v else None
    except (TypeError, ValueError):
        return None


def _day(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d")


def _week(ts: float) -> str:
    y, w, _ = datetime.fromtimestamp(ts).isocalendar()
    return f"{y}-W{w:02d}"


def eligible(db: sqlite3.Connection, row: sqlite3.Row, before: float | None = None,
             width: str = "device") -> tuple[bool, str, list]:
    """May the judge suggest closing this case? (allowed, reason, precedent rows). Only examples labelled before
    `before` count (default: the case's first time), so a replay sees what the judge would have seen then.

    `width` is how wide the precedent key is: "device" (same detector, device and key: what the judge acts on first)
    or "any_device" (the same detector and key on any device, which the roadmap says real savings need, and where a
    real case hides: FluBot used www.facebook.com). A wider key is earned per detector through the scorecard (#203);
    until then shadow mode records both. "any_device" needs precedent from two devices, none giving over half."""
    case, verdict = _case(row), _verdict(row)
    before = row["first_ts"] if before is None else before
    if case.must_alert:
        return False, "always-alert rule", []
    if case.facts.get("min_route") == "alert":
        return False, "code floor: suspicious process on the PC", []
    if agent_misused(case):
        return False, "a coding agent acted without the owner", []
    if row["route"] == Route.ALERT.value and case.detector in CODE_ONLY and critical(case, verdict, Route.ALERT):
        return False, "critical code-only alert", []
    if case.facts.get("correlated_best") == "alert":
        return False, "paired with an alert on the same device", []
    f = features(row)
    if db.execute("SELECT 1 FROM judge_examples WHERE device=? AND label='true_positive' AND labelled_ts BETWEEN ? AND ?"
                  " LIMIT 1", (f["device"], before - TP_LOOKBACK, before)).fetchone():
        return False, "a true positive on this device in the last 30 days", []
    if width == "device":
        same = db.execute("SELECT * FROM judge_examples WHERE detector=? AND device=? AND key=? AND labelled_ts < ?"
                          " AND case_id != ? ORDER BY labelled_ts DESC",
                          (f["detector"], f["device"], f["key"], before, row["id"])).fetchall()
    else:
        same = db.execute("SELECT * FROM judge_examples WHERE detector=? AND key=? AND labelled_ts < ?"
                          " AND case_id != ? ORDER BY labelled_ts DESC",
                          (f["detector"], f["key"], before, row["id"])).fetchall()
    counted = [p for p in same if p["label_source"] in COUNTED]
    if any(p["label"] == "true_positive" for p in counted):
        return False, "the owner called this same thing a true positive before", counted
    where = "this device" if width == "device" else "any device"
    if not counted:
        ai_only = " (only closes the owner didn't make)" if same else ""
        what = KEY_WORDS.get(f["key"].split(":")[0], "indicator")
        return False, f"no owner precedent on {where} for this {what}{ai_only}", []
    firsts = {r["id"]: r["first_ts"] for r in db.execute(
        # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query -- only '?' placeholders are joined; every value is bound
        f"SELECT id, first_ts FROM cases WHERE id IN ({','.join('?' * len(counted))})", [p["case_id"] for p in counted])}
    days = {_day(firsts.get(p["case_id"], p["labelled_ts"])) for p in counted}
    if len(days) < MIN_PRECEDENT_DAYS:
        return False, f"owner precedent on {len(days)} day(s), needs {MIN_PRECEDENT_DAYS}", counted
    weeks: dict[str, int] = {}
    for d in days:
        w = _week(datetime.strptime(d, "%Y-%m-%d").timestamp())
        weeks[w] = weeks.get(w, 0) + 1
    if max(weeks.values()) / len(days) > MAX_WEEK_SHARE:
        return False, "owner precedent comes mostly from one week", counted
    if width != "device":
        devices: dict[str, int] = {}
        for p in counted:
            devices[p["device"]] = devices.get(p["device"], 0) + 1
        if len(devices) < 2 or max(devices.values()) / len(counted) > MAX_DEVICE_SHARE:
            return False, "owner precedent comes mostly from one device", counted
    return True, "eligible", counted


def _explain(ok: bool, reason: str, precedents: list, width: str) -> tuple[str, list[int], float]:
    noise = sum(p["label"] in NOISE for p in precedents)
    confidence = round((noise + 1) / (len(precedents) + 2), 3)   # Laplace: 3 of 3 is 0.8, 10 of 10 is 0.92
    ids = [p["case_id"] for p in precedents[:PRECEDENT_LINKS]]
    if not ok:
        return f"not eligible: {reason}", ids, confidence
    labels = sorted({p["label"] for p in precedents})
    what = "program" if precedents[0]["key"].startswith("program:") else "destination" \
        if precedents[0]["key"].startswith("domain:") else "indicator"
    where = "same device" if width == "device" else "any device"
    return (f"like {len(precedents)} earlier cases the owner closed: {where}, same {what}, all "
            f"{' or '.join(labels)} (" + ", ".join(f"#{i}" for i in ids) + ")"), ids, confidence


def decide(db: sqlite3.Connection, case_id: int, now: float | None = None) -> dict | None:
    """Shadow mode: record what the judge would do with a stored case, and why, at each key width. Never acts on
    it. The top-level columns are the "device" width, the one it would act on first; `widths` holds both."""
    db.row_factory = sqlite3.Row
    row = db.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    if row is None:
        return None
    widths = {}
    for width in WIDTHS:
        ok, reason, precedents = eligible(db, row, width=width)
        explanation, ids, confidence = _explain(ok, reason, precedents, width)
        widths[width] = {"eligible": ok, "reason": None if ok else reason,
                         "suggestion": "close_noise" if ok else "leave", "confidence": confidence,
                         "precedent_ids": ids, "explanation": explanation}
    d = widths["device"]
    decision = {"case_id": case_id, "ts": now or time.time(), "model_version": MODEL_VERSION,
                "eligible": int(d["eligible"]), "ineligible_reason": d["reason"], "suggestion": d["suggestion"],
                "confidence": d["confidence"], "precedent_ids": json.dumps(d["precedent_ids"]),
                "explanation": d["explanation"], "widths": json.dumps(widths)}
    with db:
        db.execute("INSERT OR REPLACE INTO judge_decisions (case_id, ts, model_version, eligible, ineligible_reason,"
                   " suggestion, confidence, precedent_ids, explanation, widths) VALUES (:case_id, :ts,"
                   " :model_version, :eligible, :ineligible_reason, :suggestion, :confidence, :precedent_ids,"
                   " :explanation, :widths)", decision)
    return decision


def replay(db: sqlite3.Connection) -> dict:
    """#201's measure: run every stored case through `eligible` at each key width with only the examples labelled
    before it, and count per detector. Facts are as stored now, so this is an estimate. Read-only."""
    db.row_factory = sqlite3.Row
    out: dict[str, dict] = {}
    reasons: dict[str, dict[str, int]] = {w: {} for w in WIDTHS}
    tp_eligible: dict[str, list[int]] = {w: [] for w in WIDTHS}
    for row in db.execute("SELECT * FROM cases ORDER BY first_ts").fetchall():
        d = out.setdefault(row["detector"], {"cases": 0, **{w: 0 for w in WIDTHS}, "eligible_tp": 0})
        d["cases"] += 1
        for width in WIDTHS:
            ok, reason, _ = eligible(db, row, width=width)
            reasons[width][reason] = reasons[width].get(reason, 0) + 1
            if ok:
                d[width] += 1
                if row["disposition"] == "true_positive":
                    d["eligible_tp"] += 1
                    tp_eligible[width].append(row["id"])
    return {"detectors": out, "reasons": reasons, "true_positives_eligible": tp_eligible}
