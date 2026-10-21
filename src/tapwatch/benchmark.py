"""Benchmark: how the system is doing over time, from what the case desk already records.

Every case carries its route, Jev's verdict when asked, the owner's disposition once triaged, and for cases on the
tapwatch PC the host-context verdicts (`host_who` from code, `host_jev_who` from Jev). Those are enough for three
numbers worth tracking week by week: the share of decided cases that were noise (false positive or expected
benign), how often Jev agreed with the owner, and how often code's "who did it" matched the owner's disposition.
The stats page shows the tables; `tapwatch benchmark` prints them as Markdown for eval/RESULTS.md.
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


def markdown(db: sqlite3.Connection, now: float | None = None) -> str:
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
    return "\n".join(lines)
