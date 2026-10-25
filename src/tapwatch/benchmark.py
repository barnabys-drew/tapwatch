"""Benchmark: how the system is doing over time, from what the case desk already records.

Every case carries its route, Jev's verdict when asked, the owner's disposition once triaged, and for cases on the
tapwatch PC the host-context verdicts (`host_who` from code, `host_jev_who` from Jev). Those are enough for three
numbers worth tracking week by week: the share of decided cases that were noise (false positive or expected
benign), how often Jev agreed with the owner, and how often code's "who did it" matched the owner's disposition.
The judge's scorecard (#203) grades the shadow judge's recorded answers the same way, per detector and key width,
and says which detectors have earned auto-close. The stats page shows the tables; `tapwatch benchmark` prints
them as Markdown for eval/RESULTS.md.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime

from .store import DISPOSITIONS

NOISE = ("false_positive", "benign_expected")
# Code's host-context answer against the owner's disposition. Only two answers claim anything about intent: the
# owner's agent at work (benign) and a misused agent (hostile). "other_program" names who held the connection and
# says nothing about whether it was wanted (review of #130: on live data every claim was other_program, so the
# accuracy would have measured "non-agent traffic was noise"); "unconfirmed" and "unknown" make no claim either.
BENIGN_WHO = {"owner_using_agent"}
HOSTILE_WHO = {"agent_misused"}


def _rows(db: sqlite3.Connection) -> list[sqlite3.Row]:
    cur = db.cursor()
    cur.row_factory = sqlite3.Row  # on the cursor, not the caller's connection
    return cur.execute("SELECT first_ts, route, disposition, verdict, facts FROM cases").fetchall()


def _week(ts: float) -> str:
    y, w, _ = datetime.fromtimestamp(ts).isocalendar()
    return f"{y}-W{w:02d}"


def _jev_benign(verdict: str | None) -> bool | None:
    """Jev's call as benign (True) or not (False); None when Jev was not asked or gave no category."""
    if not verdict:
        return None
    try:
        cat = json.loads(verdict).get("category")
    except (ValueError, AttributeError):
        return None
    return None if cat in (None, "", "unknown") else cat == "benign"


def weekly(db: sqlite3.Connection) -> list[dict]:
    """Per ISO week, oldest first: cases, alerts, decided, noise (FP + benign), true positives, and Jev's agreement
    with the disposition over the decided cases Jev had a category for."""
    weeks: dict[str, dict] = {}
    for r in _rows(db):
        w = weeks.setdefault(_week(r["first_ts"]), {"week": _week(r["first_ts"]), "cases": 0, "alerts": 0, "decided": 0,
                                                     "noise": 0, "true_positives": 0, "jev_decided": 0, "jev_agree": 0})
        w["cases"] += 1
        w["alerts"] += r["route"] == "alert"
        d = r["disposition"]
        if d in DISPOSITIONS:
            w["decided"] += 1
            w["noise"] += d in NOISE
            w["true_positives"] += d == "true_positive"
            jev = _jev_benign(r["verdict"])
            if jev is not None:
                w["jev_decided"] += 1
                w["jev_agree"] += jev == (d in NOISE)
    for w in weeks.values():
        w["noise_rate"] = w["noise"] / w["decided"] if w["decided"] else None
        w["jev_agreement"] = w["jev_agree"] / w["jev_decided"] if w["jev_decided"] else None
    return [weeks[k] for k in sorted(weeks)]


def host_context(db: sqlite3.Connection) -> dict:
    """Code's host-context verdicts: how many of each, how many corroborated, how often Jev's `who` agreed with
    code's, and how often code's claim matched the owner's disposition (benign answers against noise dispositions,
    the hostile answer against true positives)."""
    out = {"cases": 0, "who": {}, "corroborated": 0, "jev_asked": 0, "jev_agree": 0, "claims": 0, "claims_right": 0}
    for r in _rows(db):
        try:
            f = json.loads(r["facts"] or "{}")
        except ValueError:
            continue
        who = f.get("host_who")
        if not who:
            continue
        out["cases"] += 1
        out["who"][who] = out["who"].get(who, 0) + 1
        out["corroborated"] += bool(f.get("host_corroborated"))
        if f.get("host_jev_who"):
            out["jev_asked"] += 1
            out["jev_agree"] += f["host_jev_who"] == who
        d = r["disposition"]
        if d in DISPOSITIONS and (who in BENIGN_WHO or who in HOSTILE_WHO):
            out["claims"] += 1
            out["claims_right"] += (who in BENIGN_WHO) == (d in NOISE)
    out["jev_agreement"] = out["jev_agree"] / out["jev_asked"] if out["jev_asked"] else None
    out["accuracy"] = out["claims_right"] / out["claims"] if out["claims"] else None
    return out


def kev_what_if(db: sqlite3.Connection) -> dict:
    """#227: how past cases would have routed had their device carried an open R48 case (base severity + 1).

    Only rules-routed cases can move: with no AI verdict the route follows severity (2-3 digest, 4+ alert, 1 log),
    so a 3 becomes an alert (a 2 stays a digest item, and log-level cases are not raised). Cases Jev routed, suppressed, capped, always-alert or routed by host
    context keep their route (the +1 changes none of those paths). Cases stored before `base_severity` was recorded
    (2026-10-20) are told apart by their reason where it says the level ("high/low severity"); a plain "rules-only"
    digest from then is 2 or 3 (the rules emit both) and counts as `maybe`. The "program is the vulnerable product" alert floor depends
    on which product a device runs and is not counted."""
    cur = db.cursor()
    cur.row_factory = sqlite3.Row
    out = {"cases": 0, "rules_routed": 0, "up": 0, "maybe": 0, "by_detector": {}}
    rows = cur.execute("SELECT * FROM cases")
    has_sev = "base_severity" in {d[0] for d in rows.description}
    for r in rows:
        out["cases"] += 1
        if r["verdict"] or r["must_alert"]:
            continue
        reason, sev = r["reason"] or "", (r["base_severity"] if has_sev else None)
        if not reason.startswith("rules-only"):
            continue
        out["rules_routed"] += 1
        moved = None
        if sev is not None:
            moved = sev == 3
        elif reason == "rules-only":
            moved = "maybe"     # a 2 or a 3
        if moved is True:
            out["up"] += 1
            out["by_detector"][r["detector"]] = out["by_detector"].get(r["detector"], 0) + 1
        elif moved == "maybe":
            out["maybe"] += 1
    return out


def _pct(v) -> str:
    return f"{v:.0%}" if isinstance(v, (int, float)) else "–"


def markdown(db: sqlite3.Connection, now: float | None = None, judge_replay: bool = False) -> str:
    stamp = datetime.fromtimestamp(now).strftime("%Y-%m-%d") if now else datetime.now().strftime("%Y-%m-%d")
    lines = [f"### Benchmark {stamp}", "",
             "| week | cases | alerts | decided | noise rate | true positives | Jev agreement |", "|---|---|---|---|---|---|---|"]
    for w in weekly(db):
        lines.append(f"| {w['week']} | {w['cases']} | {w['alerts']} | {w['decided']} | {_pct(w['noise_rate'])} | "
                     f"{w['true_positives']} | {_pct(w['jev_agreement'])} ({w['jev_decided']}) |")
    h = host_context(db)
    lines += ["", f"Host context: {h['cases']} cases on the PC, {h['corroborated']} corroborated. Code said "
              + (", ".join(f"{k} {v}" for k, v in sorted(h["who"].items())) or "nothing") + ". "
              f"Jev agreed with code on {_pct(h['jev_agreement'])} of {h['jev_asked']} it was asked; code's benign-or-hostile "
              f"claims matched the owner's disposition on {_pct(h['accuracy'])} of {h['claims']}."]
    k = kev_what_if(db)
    top = ", ".join(f"{d} {n}" for d, n in sorted(k["by_detector"].items(), key=lambda x: -x[1])[:5])
    lines += ["", f"Known-exploited what-if (#227): had every device carried an open R48 case, {k['up']} of "
              f"{k['cases']} cases would have routed one step louder" + (f" ({top})" if top else "")
              + (f", and up to {k['maybe']} more stored before their rule's severity was recorded" if k["maybe"] else "")
              + f"; the other {k['cases'] - k['rules_routed']} were routed by Jev, a suppression or a fixed rule."]
    lines += ["", judge_markdown(db, judge_replay)]
    return "\n".join(lines)


def judge_examples_markdown(db: sqlite3.Connection) -> str:
    """#200: the judge's training set, examples per label source and per detector. Only owner, owner_request and
    explain count as precedent (judge.COUNTED); the rest are kept for the record."""
    cur = db.cursor()
    cur.row_factory = sqlite3.Row
    try:
        rows = cur.execute("SELECT detector, label_source, label, COUNT(*) AS n FROM judge_examples"
                           " GROUP BY detector, label_source, label").fetchall()
    except sqlite3.OperationalError:   # an older database, before the judge's tables
        return "No judge examples yet."
    if not rows:
        return "No judge examples yet (`tapwatch judge backfill` builds them from the audit trail)."
    sources = sorted({r["label_source"] for r in rows})
    by_det: dict[str, dict[str, int]] = {}
    tps: dict[str, int] = {}
    for r in rows:
        by_det.setdefault(r["detector"], {}).setdefault(r["label_source"], 0)
        by_det[r["detector"]][r["label_source"]] += r["n"]
        if r["label"] == "true_positive":
            tps[r["detector"]] = tps.get(r["detector"], 0) + r["n"]
    out = ["| Detector | " + " | ".join(sources) + " | True positives |", "|---" * (len(sources) + 2) + "|"]
    for det, counts in sorted(by_det.items(), key=lambda kv: -sum(kv[1].values())):
        out.append(f"| {det} | " + " | ".join(str(counts.get(s, 0)) for s in sources) + f" | {tps.get(det, 0)} |")
    total = {s: sum(c.get(s, 0) for c in by_det.values()) for s in sources}
    out.append("| **all** | " + " | ".join(str(total[s]) for s in sources) + f" | {sum(tps.values())} |")
    return "\n".join(out)


# ---------------------------------------------------------------- the judge's scorecard (#203)

# When a detector qualifies for auto-close at one key width (#204 reads this). Provisional: the owner decides the
# real thresholds on #204. These are the numbers #203 itself proposed, the strictest on the table, because a judge
# closing a real case is the failure the whole gate exists for: the live history had 9 true positives in 1,198
# labels, so "0 true positives would-closed" over a few dozen cases is weak evidence on its own.
QUALIFY_MIN_DECIDED = 50       # would-close cases the owner decided (counted sources only)
QUALIFY_MIN_WEEKS = 4          # distinct ISO weeks those decided would-close cases fall in
QUALIFY_MIN_AGREEMENT = 0.98   # share of them the owner also called noise
QUALIFY_MAX_TP = 0             # true positives it would have closed: one is enough to disqualify
WIDTH_WORDS = {"device": "same device", "any_device": "any device"}


def _judge_rows(db: sqlite3.Connection, replay: bool) -> list[tuple]:
    """(case id, first_ts, detector, disposition, label source, {width: would close?}) for every judged case.

    The label source is the latest disposition's audit actor through `judge.label_source`. When the audit trail
    has no row for the current disposition (one set outside it), the case's training example says who decided."""
    from . import judge

    cur = db.cursor()
    cur.row_factory = sqlite3.Row
    actors = {r["case_id"]: (r["new"], r["actor"]) for r in cur.execute(
        "SELECT a.case_id, a.new, a.actor FROM audit a JOIN (SELECT case_id, MAX(id) AS id FROM audit"
        " WHERE action='disposition' GROUP BY case_id) m ON a.id = m.id").fetchall()}
    examples = {r["case_id"]: (r["label"], r["label_source"])
                for r in cur.execute("SELECT case_id, label, label_source FROM judge_examples").fetchall()}
    answers: dict[int, dict] = {}
    if replay:   # what the judge would have said at the time: eligible() only sees examples labelled before the case
        db.row_factory = sqlite3.Row   # eligible() reads rows by name, as judge.replay does
        for row in cur.execute("SELECT * FROM cases ORDER BY first_ts").fetchall():
            answers[row["id"]] = {w: judge.eligible(db, row, width=w)[0] for w in judge.WIDTHS}
    else:
        for r in cur.execute("SELECT case_id, suggestion, widths FROM judge_decisions").fetchall():
            try:
                widths = json.loads(r["widths"] or "{}")
            except ValueError:
                widths = {}
            # a row without per-width answers: its top-level columns are the "device" width, the other is unknown
            answers[r["case_id"]] = {
                w: widths[w].get("suggestion") == "close_noise" if isinstance(widths.get(w), dict)
                else (r["suggestion"] == "close_noise" if w == "device" else None) for w in judge.WIDTHS}
    out = []
    for r in cur.execute("SELECT id, first_ts, detector, disposition FROM cases ORDER BY first_ts").fetchall():
        if r["id"] not in answers:
            continue   # stored before the judge existed (a replay judges every case)
        d, source = r["disposition"], None
        if d in DISPOSITIONS:
            new, actor = actors.get(r["id"], (None, None))
            if new == d:
                source = judge.label_source(actor)
            elif examples.get(r["id"], (None,))[0] == d:
                source = examples[r["id"]][1]
        out.append((r["id"], r["first_ts"], r["detector"], d, source, answers[r["id"]]))
    return out


def _tally() -> dict:
    return {"cases": 0, "would_close": 0, "decided": 0, "agree": 0, "tp_closed": 0, "tp_ids": [], "weeks": set()}


def _finish(t: dict) -> dict:
    t["agreement"] = t["agree"] / t["decided"] if t["decided"] else None
    t["saved"] = t["would_close"] / t["cases"] if t["cases"] else None
    t["weeks"] = len(t["weeks"])
    return t


def _verdict(t: dict) -> list[str]:
    """Why a detector does not qualify at one width; empty when it does."""
    why = []
    if t["tp_closed"] > QUALIFY_MAX_TP:
        why.append(f"would have closed {t['tp_closed']} true positive(s)")
    if t["decided"] < QUALIFY_MIN_DECIDED:
        why.append(f"{t['decided']} decided would-close cases, needs {QUALIFY_MIN_DECIDED}")
    if t["weeks"] < QUALIFY_MIN_WEEKS:
        why.append(f"{t['weeks']} week(s) of them, needs {QUALIFY_MIN_WEEKS}")
    if t["agreement"] is not None and t["agreement"] < QUALIFY_MIN_AGREEMENT:
        why.append(f"agreement {_pct(t['agreement'])}, needs {QUALIFY_MIN_AGREEMENT:.0%}")
    return why


def judge(db: sqlite3.Connection, replay: bool = False) -> dict:
    """#203: how the shadow judge would have done, at each precedent key width (judge.WIDTHS).

    Rows per ISO week (of the case's first time) and detector, a row per week for all detectors (detector None),
    and a row per detector over all weeks, each with:

    - `cases`: cases the judge answered for; `would_close`: how many it would have closed as noise. Shadow mode
      suggests close_noise exactly when a case is eligible, so this is also the eligible count.
    - `agreement`: of the would-close cases the owner decided, the share the owner also called noise (`agree` of
      `decided`). Only the owner's own dispositions count (judge.COUNTED: owner, owner_request, explain): grading
      the judge against an AI's closes would reward it for copying an AI's triage. A "leave" claims nothing about
      the case, so it is not scored.
    - `saved`: the owner's reading load it would have removed, would-close over all judged cases.
    - `tp_closed` / `tp_ids`: true positives it would have closed, whoever marked them: a true positive an AI found
      is still one the judge would have hidden.

    Per detector, `qualifies` and `why` are the auto-close verdict at that width (#204 reads them): at least
    QUALIFY_MIN_DECIDED decided would-close cases in at least QUALIFY_MIN_WEEKS ISO weeks, agreement of at least
    QUALIFY_MIN_AGREEMENT, and no true positive it would have closed. The thresholds are provisional until the
    owner settles them on #204.

    `replay` judges every stored case afresh (judge.eligible, seeing only the examples labelled before the case)
    instead of reading `judge_decisions`, so the numbers exist before weeks of shadow data. Facts are as stored
    now, so a replay is an estimate. Read-only either way."""
    from . import judge as judge_mod

    try:
        rows = _judge_rows(db, replay)
    except sqlite3.OperationalError:   # an older database, before the judge's tables
        rows = []
    weeks: dict[tuple, dict] = {}
    dets: dict[tuple, dict] = {}
    for cid, ts, det, disp, source, answers in rows:
        wk = _week(ts)
        for width, closes in answers.items():
            if closes is None:
                continue
            for t in (weeks.setdefault((width, wk, det), _tally()), weeks.setdefault((width, wk, None), _tally()),
                      dets.setdefault((width, det), _tally())):
                t["cases"] += 1
                if not closes:
                    continue
                t["would_close"] += 1
                if disp == "true_positive":
                    t["tp_closed"] += 1
                    t["tp_ids"].append(cid)
                if disp in DISPOSITIONS and source in judge_mod.COUNTED:
                    t["decided"] += 1
                    t["agree"] += disp in NOISE
                    t["weeks"].add(wk)
    order = {w: i for i, w in enumerate(judge_mod.WIDTHS)}   # same device first: the width it would act on first
    week_rows = [{"width": w, "week": wk, "detector": det, **_finish(t)}
                 for (w, wk, det), t in sorted(weeks.items(), key=lambda kv: (order[kv[0][0]], kv[0][1], kv[0][2] or ""))]
    det_rows = []
    for (w, det), t in sorted(dets.items(), key=lambda kv: (order[kv[0][0]], -kv[1]["cases"], kv[0][1])):
        why = _verdict(_finish(t))
        det_rows.append({"width": w, "detector": det, **t, "qualifies": not why, "why": "; ".join(why) or "qualifies"})
    return {"replay": replay, "widths": judge_mod.WIDTHS, "weeks": week_rows, "detectors": det_rows}


def _agree(t: dict) -> str:
    return f"{_pct(t['agreement'])} ({t['agree']}/{t['decided']})" if t["decided"] else "– (0)"


def _saved(t: dict) -> str:
    return f"{_pct(t['saved'])} ({t['would_close']}/{t['cases']})"


def _tps(t: dict) -> str:
    """True positives it would have closed: bold, with case ids, so a non-zero never reads as a routine cell."""
    if not t["tp_closed"]:
        return "0"
    return f"**{t['tp_closed']}** (" + ", ".join(f"#{i}" for i in t["tp_ids"][:10]) + ")"


def judge_markdown(db: sqlite3.Connection, replay: bool = False) -> str:
    """The scorecard as Markdown: per detector with its auto-close verdict, then week by week, at each width."""
    s = judge(db, replay)
    head = "#### Judge scorecard " + ("(replay: every case judged afresh from the examples before it)" if replay
                                     else "(shadow decisions)")
    if not s["detectors"]:
        return head + "\n\nNo judge decisions yet" + ("." if replay else
                                                       " (`tapwatch benchmark --judge-replay` estimates them).")
    rule = (f"Qualifies for auto-close (provisional until #204): at least {QUALIFY_MIN_DECIDED} would-close cases the "
            f"owner decided, in at least {QUALIFY_MIN_WEEKS} ISO weeks, agreement at least "
            f"{QUALIFY_MIN_AGREEMENT:.0%}, and no true positive it would have closed. Agreement counts only the "
            "owner's own dispositions; load saved is would-close over all cases judged.")
    cols = "| cases | would close | agreement | load saved | true positives it would have closed |"
    lines = [head, "", rule, "", "| detector | width " + cols + " weeks | qualifies |", "|---" * 9 + "|"]
    for d in s["detectors"]:
        lines.append(f"| {d['detector']} | {WIDTH_WORDS.get(d['width'], d['width'])} | {d['cases']} | "
                     f"{d['would_close']} | {_agree(d)} | {_saved(d)} | {_tps(d)} | {d['weeks']} | "
                     + ("**yes**" if d["qualifies"] else f"no: {d['why']}") + " |")
    lines += ["", "| week | detector | width " + cols, "|---" * 8 + "|"]
    for w in s["weeks"]:
        lines.append(f"| {w['week']} | {w['detector'] or '**all**'} | {WIDTH_WORDS.get(w['width'], w['width'])} | "
                     f"{w['cases']} | {w['would_close']} | {_agree(w)} | {_saved(w)} | {_tps(w)} |")
    return "\n".join(lines)
