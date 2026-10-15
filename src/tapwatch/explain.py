"""`tapwatch explain`: find why rules keep firing on PCs with host context, and propose (or apply)
suppressions with that reason, closing the explained cases with a valid disposition.

Cases are grouped by (detector, device, program path, destination). A group becomes a suggestion
only when it repeats (`min_cases`, default 3) and **every** case in it was assessed likely benign
by host context (an installed program, nothing suspicious). One suspicious or unclear case and the
group is left for a human.

--apply creates one `device_program` suppression per group (detector + device + program: a
different program talking to the same place still alerts), expiring after `days` (default 30),
and closes the group's open cases as benign_expected with the explanation as the note. Everything
goes through the audit trail as actor "tapwatch explain". Always-alert cases are never touched.
"""

from __future__ import annotations

import json
import time
from collections import defaultdict

from .detectors import base_domain
from .models import device_id
from .store import Store, WorkflowError

ACTOR = "tapwatch explain"


def _destination(facts: dict, indicators: list[str]) -> str:
    return base_domain(indicators[0]) if indicators else str(facts.get("port", "?"))


def groups(store: Store, since: float) -> list[dict]:
    rows = store.db.execute("SELECT * FROM cases WHERE last_ts >= ? AND must_alert = 0 ORDER BY id", (since,)).fetchall()
    out: dict[tuple, dict] = defaultdict(lambda: {"cases": [], "assessments": defaultdict(int), "signals": set()})
    for r in rows:
        facts = json.loads(r["facts"])
        if "host_assessment" not in facts:
            continue
        # Grouped by device identity, not address: the PC and a docked laptop shared .215 (2026-10-15).
        key = (r["detector"], device_id(r["host"], facts), facts.get("host_program_path") or "",
               _destination(facts, json.loads(r["indicators"])))
        g = out[key]
        g["cases"].append(r)
        g["assessments"][facts["host_assessment"]] += 1
        g["signals"].update(facts.get("host_signals", []))
        g["parent"] = facts.get("host_parent", "")
    result = []
    for (detector, host, program, dest), g in out.items():
        n = len(g["cases"])
        explained = bool(program) and g["assessments"].get("likely_benign", 0) == n
        result.append({"detector": detector, "host": host, "program": program, "destination": dest, "cases": n,
                       "open": [c["id"] for c in g["cases"] if c["status"] != "closed"],
                       "assessments": dict(g["assessments"]), "signals": sorted(g["signals"])[:3],
                       "parent": g.get("parent", ""), "explained": explained,
                       "first": min(c["first_ts"] for c in g["cases"]), "last": max(c["last_ts"] for c in g["cases"]),
                       "latest_id": max(c["id"] for c in g["cases"])})
    return sorted(result, key=lambda g: (-g["explained"], -g["cases"]))


def reason(g: dict) -> str:
    days = max(1, round((g["last"] - g["first"]) / 86400))
    why = "; ".join(g["signals"][:2])
    return (f"Explained by {g['program']}" + (f" (started by {g['parent']})" if g["parent"] else "")
            + f" talking to {g['destination']}: {g['cases']} cases over {days} day(s), all assessed likely "
              f"benign on the PC ({why}).")


def apply(store: Store, g: dict, days: float = 30, now: float | None = None) -> tuple[int, list[int]]:
    """Create the suppression and close the group's open cases. Returns (rule id, closed case ids)."""
    now = time.time() if now is None else now
    text = reason(g)
    rule = store.add_suppression(g["latest_id"], "device_program", text, ACTOR, expires_ts=now + days * 86400)
    closed = []
    for cid in g["open"]:
        try:
            store.update_case(cid, ACTOR, status="closed", disposition="benign_expected",
                              note=f"{text} Suppression rule #{rule}, expires in {days:g} days.")
            closed.append(cid)
        except WorkflowError:
            continue
    return rule, closed


def report(gs: list[dict], min_cases: int) -> str:
    lines = []
    total = sum(g["cases"] for g in gs)
    counts: dict[str, int] = defaultdict(int)
    for g in gs:
        for a, n in g["assessments"].items():
            counts[a] += n
    lines.append(f"cases with host context: {total}  " + ", ".join(f"{a}={n}" for a, n in sorted(counts.items())))
    sugg = [g for g in gs if g["explained"] and g["cases"] >= min_cases]
    lines.append(f"suggested suppressions (>= {min_cases} cases, all likely benign): {len(sugg)}")
    for g in gs:
        tag = "SUGGEST" if g in sugg else ("explained" if g["explained"] else "review")
        lines.append(f"  [{tag:9s}] {g['detector']:13s} {g['host']:22s} {g['program'] or '(no single program)':35s} "
                     f"-> {g['destination']:25s} {g['cases']} case(s) {dict(g['assessments'])}")
        if tag == "SUGGEST":
            lines.append(f"      reason: {reason(g)}")
    return "\n".join(lines)
