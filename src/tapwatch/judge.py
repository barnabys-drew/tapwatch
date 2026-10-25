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
- **Auto-close (#204), off by default.** `AutoClose.consider` closes a case only when all of these hold:
  `judge.auto_close` is on; the detector is on the owner's `judge.auto_close_detectors` list at that key width; the
  scorecard (#203) says the detector qualifies at that width; the detector is not backed off; the case is new, not
  always-alert and (unless `judge.auto_close_alerts`) not alert-routed; and the shadow decision at that width,
  re-checked through `eligible` at the moment it acts, says close_noise. It closes as `benign_expected` with actor
  "judge precedent-1" and a note naming the precedent cases, and records the close in `judge_closures`. It never
  suppresses, adds a rule or changes a route, and an alert has already been sent by then. The owner's undo
  (`undo_close`) reopens the case to investigating and clears the judge's disposition, audited. The judge's closes
  never become training examples (`label_source`) or scorecard agreement.
- **Back-off (#205).** Per detector, over the last `judge.backoff.window_days`: a judge close the owner then called a
  true positive, an undo rate above `judge.backoff.max_undo_rate`, or a true positive among the cases it only
  suggested closing (the only label that disagrees with "noise") stops auto-close for that detector
  (`judge_backoff`, audited, announced in the digest). It resumes only once the detector qualifies again on the cases
  raised after the back-off alone.

Precedent before models (roadmap, 2026-10-25): with 9 true positives in 1,198 labels a trained model adds risk and
hides its reasons, so the judge matches exact keys. Wider keys (a domain on any device) are earned per detector
through the scorecard (#203), never assumed. Nothing here touches the network.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime

from .models import Case, Route, Verdict, device_id, main_indicator
from .router import CODE_ONLY, LONG_HORIZON, agent_misused, critical

log = logging.getLogger("tapwatch")

FEATURE_VERSION = 1
MODEL_VERSION = "precedent-1"
NOISE = ("false_positive", "benign_expected")
# Who decided, from the audit actor. Only COUNTED sources are precedent.
COUNTED = {"owner", "owner_request", "explain"}
# Two separate caps. Precedent cases must have *happened* on 3 distinct local days, so one burst of activity can't
# train a habit, and the owner must have *closed* them on 2 distinct days, so one sitting can't either: the case
# times are the attacker's to choose (a slow beacon once a day), and a single bulk close, explain Apply or triage
# session would otherwise teach the judge in one go (review of #318). Labelling days alone made the live history
# useless (the owner closes in batches: the median close came 12 hours after the case).
MIN_PRECEDENT_DAYS = 3
MIN_LABEL_DAYS = 2
MAX_WEEK_SHARE = 0.5          # one ISO week gives at most this share of those days
MAX_DEVICE_SHARE = 0.5        # at the "any_device" width, one device gives at most this share of the precedents
TP_LOOKBACK = 30 * 86400      # a true positive on the device this recently keeps the judge off it
# True positives about tapwatch itself, not a threat on the device they're filed under: a feed that went silent is
# real (and labelled so), but it says nothing about the PC, and six of them kept the judge off the main PC for a month
# (2026-10-25). They still block their own key like any true positive.
SENSOR_HEALTH = ("feed_silence",)
BACKED_WINDOW = 7 * 86400     # another case on the device this recent keeps the judge off a long-horizon case
KEY_WORDS = {"domain": "destination", "program": "program", "ind": "indicator", "detector": "case type"}
WIDTHS = ("device", "any_device")   # precedent key widths shadow mode records (see eligible)
PRECEDENT_LINKS = 5           # case ids named in an explanation


def label_source(actor: str) -> str | None:
    """Who made a disposition, from its audit actor. None: never an example (the judge itself)."""
    a = (actor or "").strip()
    if "judge" in a.lower():
        return None
    if a.startswith("ui ") or a == "cli":
        return "owner"           # the case desk, or `tapwatch mark` typed by the owner
    if a == "tapwatch explain":
        return "explain"         # the owner applied an explain suggestion (desk button or `explain --apply`)
    if a.startswith("cli (requested by"):
        return "owner_request"   # a triage session closing what the owner asked it to
    if a == "tapwatch":
        return "tapwatch"        # tapwatch's own closes: a suppression matched on arrival, R48 resolved by a patch
    return "ai"                  # an AI session deciding on its own ("claude", "cli (triage handoff)")


def key_for(detector: str, facts: dict, indicators: list[str]) -> str:
    """The normalised "same thing" for precedent, as narrow as the facts allow: a program's full path when host
    context named one, else the endpoint rule's program name, else the main indicator's full host name, else the
    indicator itself (an address, "ip:port", a dedupe fact). Not the registrable domain: every tenant of
    trycloudflare.com, ngrok or github.io would share one key (review of #318). Wider keys are #203's to earn."""
    program = facts.get("host_program_path") or facts.get("program_path") or ""
    ind = main_indicator(indicators, facts)
    if program:   # the full path: a svchost.exe in a temp folder is not the one in System32
        return "program:" + str(program).replace("\\", "/").lower()
    if detector.startswith("host_") and ind:
        return "program:" + str(ind).replace("\\", "/").rsplit("/", 1)[-1].lower()   # cmd.exe, rundll32.exe, pip
    host = ind.split(":")[0].rstrip(".").lower() if ind else ""
    if "." in host and any(c.isalpha() for c in host):
        return "domain:" + host
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
    trail. Facts are as stored now (correlations may have been added since): approximate, and marked as version 0.
    A case that already has an example keeps it: rerunning must not replace a live snapshot with today's facts."""
    db.row_factory = sqlite3.Row
    latest = db.execute("SELECT a.case_id, a.ts, a.actor, a.new FROM audit a JOIN (SELECT case_id, MAX(id) AS id FROM"
                        " audit WHERE action='disposition' GROUP BY case_id) m ON a.id = m.id").fetchall()
    counts: dict[str, int] = {}
    with db:
        for a in latest:
            row = db.execute("SELECT * FROM cases WHERE id=?", (a["case_id"],)).fetchone()
            if row is None or row["disposition"] != a["new"]:
                continue   # changed outside the audit trail (an old `mark` label): no actor to trust
            if db.execute("SELECT 1 FROM judge_examples WHERE case_id=?", (a["case_id"],)).fetchone():
                continue
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


def backed_long_horizon(db: sqlite3.Connection, row: sqlite3.Row, case: Case, before: float) -> str:
    """#201's "a long-horizon rule backed by another signal": the rule's own backing (`backed_by`, longhaul.backers),
    or any other case on the same device raised before it that is still open or was raised in the BACKED_WINDOW
    before (never one raised after it, so a replay doesn't see the future: review of #324). Wider
    than the router's backing on purpose: the router decides how loud, this only keeps the judge's hands off, and a
    weeks-long lead next to anything else on the device is for the owner to read. "" when there is none."""
    backed = (case.facts.get("backed_by") or [None])[0]
    if isinstance(backed, dict):
        return f"#{backed.get('id')}"
    mac = case.facts.get("device_mac")
    # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query -- only fixed text and '?' placeholders are joined; every value is bound
    lh = sorted(LONG_HORIZON)
    other = db.execute("SELECT id, status FROM cases WHERE id != ? AND detector NOT IN (" + ",".join("?" * len(lh)) + ")"
                       " AND (host = ?" + (" OR json_extract(facts, '$.device_mac') = ?" if mac else "") + ")"
                       " AND first_ts <= ? AND (status != 'closed' OR first_ts >= ?) ORDER BY id DESC LIMIT 1",
                       [row["id"], *lh, row["host"]] + ([mac] if mac else []) + [before, before - BACKED_WINDOW]).fetchone()
    return f"#{other['id']}, {'open' if other['status'] != 'closed' else 'recent'}" if other else ""


def device_keys(db: sqlite3.Connection, device: str, facts: dict) -> list[str]:
    """The device's key, plus the `mac:` key its cases had before its DHCP name was learned, the same alias the
    suppressions and daily summaries follow (#326). Only while that MAC has never carried another name: a dock's or
    adapter's MAC is not always one machine, and another computer's closes must never count as this one's."""
    mac, name = str(facts.get("device_mac") or "").lower(), str(facts.get("device_name") or "").lower()
    if not (mac and name and device == f"name:{name}"):
        return [device]
    other = db.execute("SELECT 1 FROM cases WHERE json_extract(facts, '$.device_mac') = ? AND json_extract(facts,"
                       " '$.device_name') IS NOT NULL AND lower(json_extract(facts, '$.device_name')) != ? LIMIT 1",
                       (facts.get("device_mac"), name)).fetchone()
    return [device] if other else [device, f"mac:{mac}"]


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
    if case.detector in LONG_HORIZON and (other := backed_long_horizon(db, row, case, before)):
        return False, f"a long-horizon case backed by another case on this device ({other})", []
    f = features(row)
    devices = device_keys(db, f["device"], case.facts)
    marks = ",".join("?" * len(devices))
    # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query -- only '?' placeholders are joined; every value is bound
    if db.execute(f"SELECT 1 FROM judge_examples WHERE device IN ({marks}) AND label='true_positive' AND labelled_ts"
                  f" BETWEEN ? AND ? AND detector NOT IN ({','.join('?' * len(SENSOR_HEALTH))}) LIMIT 1",
                  (*devices, before - TP_LOOKBACK, before, *SENSOR_HEALTH)).fetchone():
        return False, "a true positive on this device in the last 30 days", []
    if width == "device":
        # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query -- only '?' placeholders are joined; every value is bound
        same = db.execute(f"SELECT * FROM judge_examples WHERE detector=? AND device IN ({marks}) AND key=?"
                          " AND labelled_ts < ? AND case_id != ? ORDER BY labelled_ts DESC",
                          (f["detector"], *devices, f["key"], before, row["id"])).fetchall()
    else:
        same = db.execute("SELECT * FROM judge_examples WHERE detector=? AND key=? AND labelled_ts < ?"
                          " AND case_id != ? ORDER BY labelled_ts DESC",
                          (f["detector"], f["key"], before, row["id"])).fetchall()
    if any(p["label"] == "true_positive" for p in same):   # from any source: a TP label only makes the judge careful
        return False, "this same thing was called a true positive before", []
    counted = [p for p in same if p["label_source"] in COUNTED]
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
    label_days = {_day(p["labelled_ts"]) for p in counted}
    if len(label_days) < MIN_LABEL_DAYS:
        return False, f"the owner closed them all on one day, needs {MIN_LABEL_DAYS}", counted
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


# ---------------------------------------------------------------- auto-close (#204) and back-off (#205)

ACTOR = f"judge {MODEL_VERSION}"   # contains "judge": label_source makes sure its closes never become examples
QUALIFY_CACHE_S = 3600        # the scorecard reads every judged case: recomputed at most this often while closing
DIGEST_LINKS = 10             # case links per detector in the digest's "what the judge closed" section


def _widths_of(value) -> tuple[str, ...]:
    widths = [value] if isinstance(value, str) else list(value or ["device"])
    bad = [w for w in widths if w not in WIDTHS]
    if bad:
        log.warning("judge.auto_close_detectors: unknown width(s) %s ignored (known: %s)", bad, ", ".join(WIDTHS))
    return tuple(w for w in WIDTHS if w in widths)   # "device" first: the narrowest key is tried first


def allow_list(value) -> dict[str, tuple[str, ...]]:
    """`judge.auto_close_detectors`: a list of detectors (same-device width only), or a mapping of detector to the
    widths it may close at (`{new_domain: [device, any_device]}`). Anything else is an empty list: nothing closes."""
    if isinstance(value, str):
        value = [value]
    if isinstance(value, dict):
        out = {str(d): _widths_of(w) for d, w in value.items()}
    elif isinstance(value, (list, tuple)):
        out = {str(d): ("device",) for d in value if d}
    else:
        out = {}
    return {d: w for d, w in out.items() if w}


@dataclass(frozen=True)
class Settings:
    """`judge:` in config.yaml. Every default is the safe one: auto-close off, no detector allowed, no alerts."""
    auto_close: bool = False
    detectors: dict = field(default_factory=dict)   # detector -> widths it may close at (allow_list)
    alerts: bool = False                            # may an alert-routed case be closed (after its alert was sent)
    min_confidence: float = 0.8                     # the shadow decision's confidence (3 of 3 noise is 0.8)
    qualify: object = None                          # benchmark.Qualify; None: the owner's defaults
    backoff_days: float = 14
    max_undo_rate: float = 0.02                     # undone closes over closes: one undo in fewer than 50 trips it

    @classmethod
    def from_config(cls, cfg: dict | None) -> Settings:
        from .benchmark import Qualify

        j = (cfg or {}).get("judge") or {}
        b = j.get("backoff") or {}
        qualify = Qualify.from_config(cfg)
        return cls(auto_close=j.get("auto_close") is True, detectors=allow_list(j.get("auto_close_detectors")),
                   alerts=j.get("auto_close_alerts") is True,
                   min_confidence=float(j.get("min_confidence", cls.min_confidence)), qualify=qualify,
                   backoff_days=float(b.get("window_days", cls.backoff_days)),
                   max_undo_rate=float(b.get("max_undo_rate", cls.max_undo_rate)))

    def summary(self) -> str:
        """One line for the log and the case desk: what auto-close will do."""
        if not self.auto_close:
            return "auto-close is off (judge.auto_close: false): the judge only records what it would do"
        if not self.detectors:
            return "auto-close is on, but no detector is in judge.auto_close_detectors: nothing closes"
        allowed = ", ".join(f"{d} ({', '.join(w).replace('_', ' ')})" for d, w in sorted(self.detectors.items()))
        return (f"auto-close is on for {allowed}, each only while it qualifies and isn't backed off"
                + ("; alert-routed cases too" if self.alerts else "; never alert-routed cases"))


def _rows(db: sqlite3.Connection, sql: str, args=()) -> list[sqlite3.Row]:
    cur = db.cursor()
    cur.row_factory = sqlite3.Row   # on the cursor, not the caller's connection
    return cur.execute(sql, args).fetchall()


def backoff_active(db: sqlite3.Connection, detector: str) -> sqlite3.Row | None:
    found = _rows(db, "SELECT * FROM judge_backoff WHERE detector=? AND lifted_ts IS NULL ORDER BY id DESC LIMIT 1",
                  (detector,))
    return found[0] if found else None


def _audit(db: sqlite3.Connection, case_id, actor: str, action: str, old, new, now: float) -> None:
    db.execute("INSERT INTO audit (case_id, ts, actor, action, old, new) VALUES (?,?,?,?,?,?)",
               (case_id, now, actor, action, old, new))


def closure(db: sqlite3.Connection, case_id: int) -> sqlite3.Row | None:
    found = _rows(db, "SELECT * FROM judge_closures WHERE case_id=?", (case_id,))
    return found[0] if found else None


def note_owner_change(db: sqlite3.Connection, case_id: int, actor: str, status: str | None,
                      disposition: str | None, now: float) -> None:
    """Called inside `Store.update_case`'s transaction: someone other than the judge reopened a case the judge
    closed, or called it a true positive. Either is the owner disagreeing, which back-off counts (#205). A note, or
    relabelling false_positive vs benign_expected (both noise), is not."""
    if "judge" in (actor or "").lower():
        return
    how = "true_positive" if disposition == "true_positive" else "reopened" if status and status != "closed" else None
    if how is None:
        return
    db.execute("UPDATE judge_closures SET undone_ts=?, undone_by=?, undone_how=? WHERE case_id=? AND undone_ts IS NULL",
               (now, actor, how, case_id))
    if how == "true_positive":   # reopened or undone first, then marked: the true positive is the stronger signal
        db.execute("UPDATE judge_closures SET undone_how='true_positive' WHERE case_id=?", (case_id,))


class AutoClose:
    """#204 and #205 for one pipeline. With the default Settings it never reads the database and never closes."""

    def __init__(self, settings: Settings | None = None):
        self.s = settings or Settings()
        self._qualified: set[tuple[str, str]] = set()
        self._qualified_ts = float("-inf")

    @property
    def qualify(self):
        from .benchmark import Qualify

        return self.s.qualify or Qualify()

    def qualified(self, db: sqlite3.Connection, now: float) -> set[tuple[str, str]]:
        """(detector, width) pairs the scorecard qualifies right now, recomputed at most every QUALIFY_CACHE_S."""
        if now - self._qualified_ts >= QUALIFY_CACHE_S:
            from . import benchmark

            card = benchmark.judge(db, qualify=self.qualify)
            self._qualified = {(d["detector"], d["width"]) for d in card["detectors"] if d["qualifies"]}
            self._qualified_ts = now
        return self._qualified

    def consider(self, store, case_id: int, now: float | None = None) -> tuple[bool, str]:
        """Close the stored case if every condition holds (module docstring). Returns (closed?, why or why not).

        `store` is the pipeline's Store: the close goes through `update_case`, so it is audited like any other."""
        if not self.s.auto_close:
            return False, "auto-close is off"
        now = time.time() if now is None else now
        db = store.db
        row = store.get(case_id)
        if row is None:
            return False, "no such case"
        widths = self.s.detectors.get(row["detector"])
        if not widths:
            return False, "detector not in judge.auto_close_detectors"
        if row["must_alert"]:
            return False, "always-alert rule"
        if row["status"] != "new":
            return False, f"case is {row['status']}"   # closed on arrival by a suppression, or already being worked
        if row["route"] == Route.ALERT.value and not self.s.alerts:
            return False, "alert-routed (judge.auto_close_alerts: false)"
        if backoff_active(db, row["detector"]):
            return False, "backed off"
        if (reason := self.drift(db, row["detector"], now)) is not None:
            self.back_off(db, row["detector"], reason, now)
            return False, f"backed off: {reason}"
        decision = store.judge_decision(case_id)
        if decision is None:
            return False, "no shadow decision"
        try:
            answers = json.loads(decision["widths"] or "{}")
        except ValueError:
            return False, "unreadable shadow decision"
        qualified = self.qualified(db, now)
        why = "no allowed width qualifies"
        for width in widths:
            words = width.replace("_", " ")
            a = answers.get(width)
            if not isinstance(a, dict) or a.get("suggestion") != "close_noise":
                why = f"the judge would leave it ({words} width)"
                continue
            if float(a.get("confidence") or 0) < self.s.min_confidence:
                why = f"confidence below {self.s.min_confidence} ({words} width)"
                continue
            if (row["detector"], width) not in qualified:
                why = f"{row['detector']} does not qualify at {words} width"
                continue
            # The guardrails again, at the moment it acts and with every label made since the case arrived: a true
            # positive marked in between keeps its hands off.
            ok, reason, precedents = eligible(db, row, before=now, width=width)
            if not ok:
                why = f"not eligible: {reason}"
                continue
            explanation, ids, _ = _explain(ok, reason, precedents, width)
            self.close(store, row, width, explanation, ids, now)
            return True, explanation
        return False, why

    def close(self, store, row: sqlite3.Row, width: str, explanation: str, ids: list[int], now: float) -> None:
        where = "same device" if width == "device" else "any device"
        store.update_case(row["id"], ACTOR, status="closed", disposition="benign_expected",
                          note=f"Closed by the judge (auto-close, {where} width): {explanation}. Undo on this page "
                               "puts it back to investigating with no disposition.")
        with store.db:
            store.db.execute("INSERT OR REPLACE INTO judge_closures (case_id, ts, detector, width, model_version,"
                             " precedent_ids, explanation) VALUES (?,?,?,?,?,?,?)",
                             (row["id"], now, row["detector"], width, MODEL_VERSION, json.dumps(ids), explanation))
        log.info("judge closed #%s (%s, %s): %s", row["id"], row["detector"], where, explanation)

    # ------------------------------------------------------------ back-off (#205)

    def drift(self, db: sqlite3.Connection, detector: str, now: float) -> str | None:
        """Why auto-close should stop for this detector now, or None. Only what happened in the window and since the
        last back-off lifted counts, so the evidence for one back-off never trips the next."""
        lifted = db.execute("SELECT MAX(lifted_ts) FROM judge_backoff WHERE detector=?", (detector,)).fetchone()[0]
        start = max(now - self.s.backoff_days * 86400, lifted or 0.0)
        days = f"{self.s.backoff_days:g} days"
        closed = _rows(db, "SELECT j.case_id, j.undone_ts, j.undone_how, c.disposition FROM judge_closures j"
                           " JOIN cases c ON c.id = j.case_id WHERE j.detector=? AND j.ts >= ?", (detector, start))
        tp = [r["case_id"] for r in closed if r["undone_how"] == "true_positive" or r["disposition"] == "true_positive"]
        if tp:
            return f"the owner called a case it closed a true positive (#{tp[0]})"
        undone = sum(r["undone_ts"] is not None for r in closed)
        if undone and undone / len(closed) > self.s.max_undo_rate:
            return f"the owner undid {undone} of its {len(closed)} close(s) in the last {days}"
        # The cases it only suggested closing (not allowed at that width, not qualifying, alert-routed): the owner's
        # own decisions on them are the drift signal while it closes the rest. The only disposition that is not noise
        # is true_positive, so "agreement fell below the bar" is exactly "the owner called one a true positive", and
        # one is enough, as one is enough to disqualify a detector in the scorecard. Whoever marked it: a true
        # positive an AI found is still one the judge would have hidden.
        allowed = self.s.detectors.get(detector) or ("device",)
        for r in _rows(db, "SELECT d.case_id, d.widths FROM judge_decisions d JOIN cases c ON c.id = d.case_id"
                           " WHERE c.detector=? AND c.first_ts >= ? AND c.disposition='true_positive'"
                           " ORDER BY c.first_ts", (detector, start)):
            try:
                answers = json.loads(r["widths"] or "{}")
            except ValueError:
                continue
            if any(isinstance(answers.get(w), dict) and answers[w].get("suggestion") == "close_noise" for w in allowed):
                return f"a case it would have closed was called a true positive (#{r['case_id']})"
        return None

    def back_off(self, db: sqlite3.Connection, detector: str, reason: str, now: float) -> bool:
        """Stop auto-closing `detector`, audited. False when it was already backed off."""
        if backoff_active(db, detector):
            return False
        with db:
            db.execute("INSERT INTO judge_backoff (detector, since_ts, reason) VALUES (?,?,?)", (detector, now, reason))
            _audit(db, None, "judge back-off", "judge back-off", None, f"{detector}: {reason}", now)
        log.warning("judge auto-close backed off for %s: %s", detector, reason)
        return True

    def review(self, db: sqlite3.Connection, now: float | None = None) -> None:
        """Before each digest: check every allowed detector for drift, and lift a back-off once the detector
        qualifies again on the cases raised since it began, alone (a fresh qualification window, #205)."""
        if not self.s.auto_close:
            return
        from . import benchmark

        now = time.time() if now is None else now
        for detector, widths in sorted(self.s.detectors.items()):
            active = backoff_active(db, detector)
            if active is None:
                if (reason := self.drift(db, detector, now)) is not None:
                    self.back_off(db, detector, reason, now)
                continue
            card = benchmark.judge(db, qualify=self.qualify, since=active["since_ts"])
            fresh = [d["width"] for d in card["detectors"]
                     if d["detector"] == detector and d["qualifies"] and d["width"] in widths]
            if not fresh:
                continue
            why = f"it qualifies again at {fresh[0].replace('_', ' ')} width on the cases raised since it stopped"
            with db:
                db.execute("UPDATE judge_backoff SET lifted_ts=?, lifted_reason=? WHERE id=?", (now, why, active["id"]))
                _audit(db, None, "judge back-off", "judge back-off lifted", active["reason"], f"{detector}: {why}", now)
            self._qualified_ts = float("-inf")
            log.info("judge auto-close resumed for %s: %s", detector, why)


def undo_close(store, case_id: int, actor: str) -> None:
    """The owner's one-click undo: reopen a case the judge closed to investigating and clear the judge's
    disposition, in one audited transaction. Refuses a case the judge didn't close, or one changed since."""
    from .store import WorkflowError

    c, row = closure(store.db, case_id), store.get(case_id)
    if c is None or row is None:
        raise WorkflowError(f"the judge did not close case #{case_id}")
    if c["undone_ts"] is not None:
        raise WorkflowError(f"the judge's close of #{case_id} was already undone by {c['undone_by']}")
    if row["status"] != "closed" or row["disposition"] != "benign_expected":
        raise WorkflowError(f"#{case_id} has changed since the judge closed it: use the form to change it")
    now, db = time.time(), store.db
    note = "Undid the judge's close: back to investigating, disposition cleared."
    with db:
        db.execute("UPDATE cases SET status='investigating', disposition=NULL, feedback=NULL, updated_ts=? WHERE id=?",
                   (now, case_id))
        _audit(db, case_id, actor, "status", "closed", "investigating", now)
        # Its own action name, not "disposition": the scorecard and backfill read the latest "disposition" row as the
        # case's label, and an empty label is not one.
        _audit(db, case_id, actor, "disposition cleared", "benign_expected", None, now)
        db.execute("INSERT INTO notes (case_id, ts, actor, text) VALUES (?,?,?,?)", (case_id, now, actor, note))
        _audit(db, case_id, actor, "note", None, note, now)
        db.execute("UPDATE judge_closures SET undone_ts=?, undone_by=?, undone_how='undo' WHERE case_id=?",
                   (now, actor, case_id))


def closures(db: sqlite3.Connection, limit: int = 500) -> list[sqlite3.Row]:
    """Everything the judge closed, newest first, with each case's status and disposition now."""
    return _rows(db, "SELECT j.*, c.title, c.host, c.status, c.disposition, c.route FROM judge_closures j"
                     " JOIN cases c ON c.id = j.case_id ORDER BY j.ts DESC, j.case_id DESC LIMIT ?", (limit,))


def digest_section(db: sqlite3.Connection, link, now: float | None = None) -> tuple[list[dict], dict]:
    """#205's digest section: what the judge closed since the last digest, per detector with links, and back-offs
    begun or lifted since. Returns (items, what to mark reported once sent). `link(case_id)` makes a case link."""
    now = time.time() if now is None else now
    try:
        new = _rows(db, "SELECT case_id, detector, undone_ts FROM judge_closures WHERE digested=0"
                        " ORDER BY detector, case_id")
        offs = _rows(db, "SELECT * FROM judge_backoff WHERE announced_on=0 ORDER BY id")
        ons = _rows(db, "SELECT * FROM judge_backoff WHERE lifted_ts IS NOT NULL AND announced_off=0 ORDER BY id")
        week = _rows(db, "SELECT detector, COUNT(*) AS n, SUM(undone_ts IS NOT NULL) AS u FROM judge_closures"
                         " WHERE ts >= ? GROUP BY detector ORDER BY detector", (now - 7 * 86400,))
    except sqlite3.OperationalError:   # an older database, before these tables
        return [], {}
    items = []
    for b in offs:
        items.append({"heading": f"The judge stopped auto-closing {b['detector']}",
                      "facts": {"Why": b["reason"],
                                "Now": "its cases come to you as before; it resumes only once it qualifies again on "
                                       "cases raised since"}, "untrusted": []})
    for b in ons:
        items.append({"heading": f"The judge resumed auto-closing {b['detector']}",
                      "facts": {"Why": b["lifted_reason"] or ""}, "untrusted": []})
    if new:
        by_det: dict[str, list] = {}
        for r in new:
            by_det.setdefault(r["detector"], []).append(r)
        facts = {}
        for det, rs in by_det.items():
            shown = ", ".join(link(r["case_id"]) + (" (undone)" if r["undone_ts"] else "") for r in rs[:DIGEST_LINKS])
            more = f" and {len(rs) - DIGEST_LINKS} more" if len(rs) > DIGEST_LINKS else ""
            facts[det] = f"{len(rs)}: {shown}{more}"
        facts["Undo"] = "open a case and press Undo on its judge card; the desk's Judge page lists every close"
        facts["Last 7 days"] = "; ".join(f"{w['detector']} {w['n']} closed, {w['u'] or 0} undone" for w in week)
        items.append({"heading": f"What the judge closed: {len(new)} case(s)", "facts": facts, "untrusted": []})
    return items, {"closures": [r["case_id"] for r in new], "off": [b["id"] for b in offs],
                   "on": [b["id"] for b in ons]}


def mark_reported(db: sqlite3.Connection, done: dict) -> None:
    if not done:
        return
    with db:
        db.executemany("UPDATE judge_closures SET digested=1 WHERE case_id=?", [(i,) for i in done["closures"]])
        db.executemany("UPDATE judge_backoff SET announced_on=1 WHERE id=?", [(i,) for i in done["off"]])
        db.executemany("UPDATE judge_backoff SET announced_off=1 WHERE id=?", [(i,) for i in done["on"]])
