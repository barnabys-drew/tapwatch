"""SQLite storage for cases, AI verdicts, the case workflow and suppressions.

The schema only ever grows (new columns, new tables), so an older `tapwatch run`
can keep writing to a database that a newer version has already migrated.
"""

from __future__ import annotations

import json
import re
import sqlite3
import time
from dataclasses import asdict

from . import inventory, judge
from .detectors import base_domain, suffix_match
from .models import Case, Route, Verdict, device_id, main_indicator

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY,
    key TEXT NOT NULL,
    first_ts REAL NOT NULL,
    last_ts REAL NOT NULL,
    hits INTEGER NOT NULL DEFAULT 1,
    detector TEXT NOT NULL,
    host TEXT NOT NULL,
    title TEXT NOT NULL,
    facts TEXT NOT NULL,
    indicators TEXT NOT NULL,
    must_alert INTEGER NOT NULL,
    state TEXT NOT NULL,
    verdict TEXT,
    route TEXT NOT NULL,
    reason TEXT NOT NULL,
    digested INTEGER NOT NULL DEFAULT 0,
    feedback TEXT
);
CREATE INDEX IF NOT EXISTS cases_key ON cases(key, last_ts);
"""

# Case workflow (added 2026-10-12). Every statement is additive and safe to run while
# `tapwatch run` is writing: each one is its own short transaction.
NEW_CASE_COLUMNS = {
    "status": "TEXT NOT NULL DEFAULT 'new'",
    "disposition": "TEXT",
    "updated_ts": "REAL",
    "base_severity": "INTEGER",   # the rule's own 1..5 (added 2026-10-20 for #227's benchmark); NULL before
}
NEW_TABLES = """
CREATE TABLE IF NOT EXISTS detector_state (  -- learned baselines, so a restart doesn't start from zero
    name TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    saved_ts REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY,
    case_id INTEGER NOT NULL,
    ts REAL NOT NULL,
    actor TEXT NOT NULL,
    text TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY,
    case_id INTEGER,            -- NULL for changes that aren't about one case (suppression rules)
    ts REAL NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    old TEXT,
    new TEXT
);
CREATE TABLE IF NOT EXISTS suppressions (
    id INTEGER PRIMARY KEY,
    scope TEXT NOT NULL,        -- device_indicator | indicator | port | device_program
    detector TEXT NOT NULL,
    host TEXT,
    indicator TEXT,
    port INTEGER,
    reason TEXT NOT NULL,
    created_ts REAL NOT NULL,
    expires_ts REAL,
    hits INTEGER NOT NULL DEFAULT 0,
    last_hit_ts REAL
);
CREATE TABLE IF NOT EXISTS software (     -- each agent's latest software snapshot (#224), replaced on each one
    agent TEXT NOT NULL,        -- osquery hostIdentifier: the WSL distro and the Windows host are two agents
    kind TEXT NOT NULL,         -- windows | deb | rpm | brew
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    source TEXT NOT NULL,       -- deb/rpm source package (what OSV names); '' for Windows
    product TEXT NOT NULL,      -- inventory.WINDOWS_PRODUCTS key, '' when not one the vulnerability check knows
    seen_ts REAL NOT NULL,
    PRIMARY KEY (agent, kind, name, version)
);
CREATE TABLE IF NOT EXISTS agents (       -- what each agent says it runs (os_version), for the ecosystem
    agent TEXT PRIMARY KEY,
    os_name TEXT NOT NULL,
    os_version TEXT NOT NULL,
    platform TEXT NOT NULL,
    seen_ts REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS judge_examples (  -- the judge's training set (#200): one per decided case, newest label wins
    case_id INTEGER PRIMARY KEY,
    labelled_ts REAL NOT NULL,
    label TEXT NOT NULL,        -- the disposition
    label_source TEXT NOT NULL, -- judge.label_source: owner | owner_request | explain count; ai | suppression don't
    actor TEXT NOT NULL,
    detector TEXT NOT NULL,
    device TEXT NOT NULL,
    key TEXT NOT NULL,          -- judge.key_for: program file name, registrable domain or indicator
    features TEXT NOT NULL,     -- code facts at labelling time (JSON)
    feature_version INTEGER NOT NULL   -- 0: backfilled from the audit trail with today's facts
);
CREATE INDEX IF NOT EXISTS judge_examples_key ON judge_examples(detector, device, key);
CREATE TABLE IF NOT EXISTS judge_decisions (  -- shadow mode (#202): what the judge would do, never done
    case_id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    model_version TEXT NOT NULL,
    eligible INTEGER NOT NULL,
    ineligible_reason TEXT,
    suggestion TEXT NOT NULL,   -- close_noise | leave
    confidence REAL NOT NULL,
    precedent_ids TEXT NOT NULL,   -- JSON list of case ids
    explanation TEXT NOT NULL,
    widths TEXT NOT NULL DEFAULT '{}'   -- JSON: the same answer at each precedent key width (judge.WIDTHS)
);
CREATE INDEX IF NOT EXISTS notes_case ON notes(case_id);
CREATE INDEX IF NOT EXISTS audit_case ON audit(case_id);
"""

STATUSES = ("new", "investigating", "closed")
# Where each status may go next. Closed cases can be reopened into investigating.
TRANSITIONS = {"new": {"investigating", "closed"}, "investigating": {"closed"}, "closed": {"investigating"}}
DISPOSITIONS = ("true_positive", "false_positive", "benign_expected")
# device_program needs host context; the domain scopes match any host under the indicator's registrable
# domain (ch-tanzone-02 after ch-tanzone-01 was suppressed: a sibling host alerted again, 2026-10-15).
SCOPES = ("device_indicator", "indicator", "device_domain", "domain", "port", "device_program")

# `tapwatch mark` labels and the old feedback column, mapped onto dispositions.
FEEDBACK_TO_DISPOSITION = {"fp": "false_positive", "tp": "true_positive"}
# benign_expected means "not malicious", which is what the eval's fp label means too.
DISPOSITION_TO_FEEDBACK = {"true_positive": "tp", "false_positive": "fp", "benign_expected": "fp"}


class WorkflowError(ValueError):
    """An update that the case workflow doesn't allow (bad status move, closing without a disposition...)."""


def describe_rule(rule) -> str:
    """Short label for a suppression rule, used in the case's route reason and in the UI."""
    if rule["scope"] == "port":
        what = f"any device, port {rule['port']}"
    elif rule["scope"] == "indicator":
        what = f"any device, {rule['indicator']}"
    elif rule["scope"] == "domain":
        what = f"any device, any host under {rule['indicator']}"
    elif rule["scope"] == "device_domain":
        what = f"{rule['host']}, any host under {rule['indicator']}"
    elif rule["scope"] == "device_program":
        name = str(rule["indicator"]).replace("\\", "/").rsplit("/", 1)[-1]  # the path names the user: the name only
        what = f"{rule['host']}, program {name}"
    else:
        what = f"{rule['host']}, {rule['indicator']}"
    return f"#{rule['id']} {rule['detector']} ({what})"


class Store:
    def __init__(self, path: str = "tapwatch.db", migrate: bool = True):
        # timeout: wait up to 10 s for the live alerter's short writes instead of failing.
        self.db = sqlite3.connect(path, timeout=10)
        self.db.row_factory = sqlite3.Row
        if migrate:
            self.db.executescript(SCHEMA)
            self.migrate()

    def migrate(self) -> None:
        have = {r["name"] for r in self.db.execute("PRAGMA table_info(cases)")}
        for name, decl in NEW_CASE_COLUMNS.items():
            if name not in have:
                try:  # SQLite can't bind identifiers; name and decl are NEW_CASE_COLUMNS' own constants
                    # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query
                    self.db.execute(f"ALTER TABLE cases ADD COLUMN {name} {decl}")
                except sqlite3.OperationalError as e:
                    if "duplicate column" not in str(e):  # another process migrated first: fine
                        raise
        self.db.executescript(NEW_TABLES)
        if "disposition" not in have:  # first migration: carry over earlier `tapwatch mark` labels
            for label, disposition in FEEDBACK_TO_DISPOSITION.items():
                self.db.execute("UPDATE cases SET disposition=? WHERE feedback=? AND disposition IS NULL",
                                (disposition, label))
            self.db.commit()

    # ------------------------------------------------------- software inventory (#224)

    def replace_software(self, agent: str, kind: str, rows: list[dict], ts: float) -> int:
        """One agent's snapshot of one kind replaces its previous one (a snapshot is the full list). An empty
        snapshot is ignored: osquery returns no rows when the table read failed, which is not 'uninstalled all'."""
        if not agent or not rows:
            return 0
        with self.db:
            self.db.execute("DELETE FROM software WHERE agent=? AND kind=?", (agent, kind))
            self.db.executemany("INSERT OR REPLACE INTO software VALUES (?,?,?,?,?,?,?)",
                                [(agent, kind, r["name"], r["version"], r["source"], r["product"], ts) for r in rows])
        return len(rows)

    def set_agent_os(self, agent: str, row: dict, ts: float) -> None:
        if not agent:
            return
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO agents VALUES (?,?,?,?,?)",
                            (agent, str(row.get("name") or ""), str(row.get("version") or ""),
                             str(row.get("platform") or ""), ts))

    def agents(self) -> dict[str, dict]:
        return {r["agent"]: dict(r) for r in self.db.execute("SELECT * FROM agents")}

    def software(self, agent: str | None = None) -> list[sqlite3.Row]:
        if agent:
            return self.db.execute("SELECT * FROM software WHERE agent=? ORDER BY kind, name", (agent,)).fetchall()
        return self.db.execute("SELECT * FROM software ORDER BY agent, kind, name").fetchall()

    def ecosystems(self) -> dict[str, set[str]]:
        """Ecosystem -> the source packages installed in it, across agents: what update-feeds fetches for."""
        agents = self.agents()
        out: dict[str, set[str]] = {}
        for r in self.db.execute("SELECT agent, kind, name, source, product FROM software"):
            os_row = agents.get(r["agent"])
            eco = inventory.ecosystem(r["kind"], {"name": os_row["os_name"], "version": os_row["os_version"]}
                                      if os_row else None)
            key = r["product"] if eco == "windows" else (r["source"] or r["name"])
            if eco and key:   # a Windows program no product maps has nothing to fetch for
                out.setdefault(eco, set()).add(key)
        return out

    # ------------------------------------------------------- detector state

    def save_state(self, states: dict[str, dict]) -> None:
        now = time.time()
        with self.db:  # all detectors or none, so a crash mid-save can't mix old and new
            self.db.executemany("INSERT OR REPLACE INTO detector_state (name, data, saved_ts) VALUES (?, ?, ?)",
                                [(n, json.dumps(d), now) for n, d in states.items()])

    def load_state(self) -> dict[str, dict]:
        out = {}
        for r in self.db.execute("SELECT name, data FROM detector_state"):
            try:
                out[r["name"]] = json.loads(r["data"])
            except ValueError:
                continue
        return out

    # ------------------------------------------------------------ pipeline

    def recent(self, case: Case, window: float) -> int | None:
        """If the same case (same key) was recorded within `window` seconds, bump it and return its id."""
        row = self.db.execute("SELECT id FROM cases WHERE key=? AND last_ts>=? ORDER BY id DESC LIMIT 1",
                              (case.key, case.ts - window)).fetchone()
        if row is None:
            return None
        # max(): a repeat read out of order (a replayed log) must not move last_ts backwards, or the next
        # in-order repeat falls outside the window and opens a fresh case instead of counting as a hit.
        self.db.execute("UPDATE cases SET hits=hits+1, last_ts=max(last_ts, ?) WHERE id=?", (case.ts, row["id"]))
        self.db.commit()
        return row["id"]

    def add(self, case: Case, state: str, verdict: Verdict | None, route: Route, reason: str) -> int:
        cur = self.db.execute(
            "INSERT INTO cases (key, first_ts, last_ts, detector, host, title, facts, indicators, must_alert,"
            " state, verdict, route, reason, base_severity) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (case.key, case.ts, case.ts, case.detector, case.host, case.title, json.dumps(case.facts),
             json.dumps(case.indicators), int(case.must_alert), state,
             json.dumps(asdict(verdict)) if verdict else None, route.value, reason, case.base_severity))
        self.db.commit()
        return cur.lastrowid

    def nearby(self, case: Case, window: float, detectors: set[str] | None = None) -> list[sqlite3.Row]:
        """Cases first raised on the same device within `window` seconds of `case`, newest first, other keys only,
        and only from `detectors` when given. The device is its MAC when both sides know it (identity facts), else
        the address. The window is on a case's first time: a long-running case's later repeats do not pair again.
        The device and the detectors are in the query, before the limit: the limit covers a replay flood
        (measured 2026-10-17: 337 host cases in one hour), and filtering after it could leave the real partner
        out in one."""
        if detectors is not None and not detectors:
            return []
        mac = case.facts.get("device_mac")
        sql = ("SELECT * FROM cases WHERE first_ts BETWEEN ? AND ? AND key != ? AND (host = ?"
               + (" OR json_extract(facts, '$.device_mac') = ?" if mac else "") + ")")
        args: list = [case.ts - window, case.ts + window, case.key, case.host] + ([mac] if mac else [])
        if detectors:
            sql += f" AND detector IN ({','.join('?' * len(detectors))})"
            args += sorted(detectors)
        # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query -- only fixed text and '?' placeholders are joined; every value is bound
        return self.db.execute(sql + " ORDER BY id DESC LIMIT 400", args).fetchall()

    def link_cases(self, case_id: int, other_id: int, entry: dict, note: str, actor: str = "tapwatch") -> None:
        """Record on an existing case that a later one pairs with it: a `correlated` fact entry and a note."""
        row = self.get(case_id)
        if row is None:
            return
        facts = json.loads(row["facts"] or "{}")
        linked = [e for e in facts.get("correlated", []) if isinstance(e, dict)]
        if any(e.get("id") == other_id for e in linked):
            return
        facts["correlated"] = (linked + [entry])[-3:]  # the newest three, as pipeline.correlate keeps on the other side
        now = time.time()
        with self.db:
            self.db.execute("UPDATE cases SET facts=?, updated_ts=? WHERE id=?", (json.dumps(facts), now, case_id))
            self.db.execute("INSERT INTO notes (case_id, ts, actor, text) VALUES (?,?,?,?)", (case_id, now, actor, note))
            self._audit(case_id, actor, "note", None, note, now)

    def add_fact(self, case_id: int, key: str, value, note: str, actor: str) -> bool:
        """Set one fact on an existing case (an on-demand check's result) with a note, audited."""
        row = self.get(case_id)
        if row is None:
            return False
        facts = json.loads(row["facts"] or "{}")
        facts[key] = value
        now = time.time()
        with self.db:
            self.db.execute("UPDATE cases SET facts=?, updated_ts=? WHERE id=?", (json.dumps(facts), now, case_id))
            self.db.execute("INSERT INTO notes (case_id, ts, actor, text) VALUES (?,?,?,?)", (case_id, now, actor, note))
            self._audit(case_id, actor, "note", None, note, now)
        return True

    def pending_digest(self) -> list[sqlite3.Row]:
        return self.db.execute("SELECT * FROM cases WHERE route='digest' AND digested=0 ORDER BY first_ts").fetchall()

    def mark_digested(self, ids: list[int]) -> None:
        self.db.executemany("UPDATE cases SET digested=1 WHERE id=?", [(i,) for i in ids])
        self.db.commit()

    def get(self, case_id: int) -> sqlite3.Row | None:
        return self.db.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()

    # ------------------------------------------------------------ workflow

    def set_feedback(self, case_id: int, label: str) -> bool:
        """`tapwatch mark`: fp/tp becomes the disposition and closes the case."""
        row = self.get(case_id)
        if row is None:
            return False
        self.update_case(case_id, actor="cli", disposition=FEEDBACK_TO_DISPOSITION[label],
                         status=None if row["status"] == "closed" else "closed")
        return True

    def update_case(self, case_id: int, actor: str, status: str | None = None, disposition: str | None = None,
                    note: str | None = None) -> list[str]:
        """Apply a status change, disposition and/or note in one transaction, auditing each change.

        Returns what changed. Raises WorkflowError if the change isn't allowed."""
        row = self.get(case_id)
        if row is None:
            raise WorkflowError(f"no case #{case_id}")
        status = status if status and status != row["status"] else None
        disposition = disposition if disposition and disposition != row["disposition"] else None
        note = (note or "").strip()
        if status and status not in STATUSES:
            raise WorkflowError(f"unknown status {status!r}")
        if status and status not in TRANSITIONS[row["status"]]:
            raise WorkflowError(f"can't move a case from {row['status']} to {status}")
        if disposition and disposition not in DISPOSITIONS:
            raise WorkflowError(f"unknown disposition {disposition!r}")
        if status == "closed" and not (disposition or row["disposition"]):
            raise WorkflowError("pick a disposition before closing the case")
        now = time.time()
        changed = []
        with self.db:  # one transaction: all of it or none of it
            if disposition:
                self.db.execute("UPDATE cases SET disposition=?, feedback=?, updated_ts=? WHERE id=?",
                                (disposition, DISPOSITION_TO_FEEDBACK[disposition], now, case_id))
                self._audit(case_id, actor, "disposition", row["disposition"], disposition, now)
                judge.record_example(self.db, row, disposition, actor, now)   # the judge's training set (#200)
                changed.append("disposition")
            if status:
                self.db.execute("UPDATE cases SET status=?, updated_ts=? WHERE id=?", (status, now, case_id))
                self._audit(case_id, actor, "status", row["status"], status, now)
                changed.append("status")
            if note:
                self.db.execute("INSERT INTO notes (case_id, ts, actor, text) VALUES (?,?,?,?)",
                                (case_id, now, actor, note))
                self.db.execute("UPDATE cases SET updated_ts=? WHERE id=?", (now, case_id))
                self._audit(case_id, actor, "note", None, note, now)
                changed.append("note")
        return changed

    def _audit(self, case_id: int | None, actor: str, action: str, old, new, now: float) -> None:
        self.db.execute("INSERT INTO audit (case_id, ts, actor, action, old, new) VALUES (?,?,?,?,?,?)",
                        (case_id, now, actor, action, old, new))

    def judge_decision(self, case_id: int) -> sqlite3.Row | None:
        return self.db.execute("SELECT * FROM judge_decisions WHERE case_id=?", (case_id,)).fetchone()

    def notes(self, case_id: int) -> list[sqlite3.Row]:
        return self.db.execute("SELECT * FROM notes WHERE case_id=? ORDER BY ts, id", (case_id,)).fetchall()

    def audit_trail(self, case_id: int | None = None) -> list[sqlite3.Row]:
        if case_id is None:
            return self.db.execute("SELECT * FROM audit ORDER BY ts DESC, id DESC LIMIT 200").fetchall()
        return self.db.execute("SELECT * FROM audit WHERE case_id=? ORDER BY ts, id", (case_id,)).fetchall()

    # ------------------------------------------------------------ suppressions

    def add_suppression(self, case_id: int, scope: str, reason: str, actor: str,
                        expires_ts: float | None = None) -> int:
        """Create a rule from a case. must_alert cases (IOC hits, IDS severity 1) can't be suppressed."""
        row = self.get(case_id)
        if row is None:
            raise WorkflowError(f"no case #{case_id}")
        if row["must_alert"]:
            raise WorkflowError("always-alert cases (threat-list hits, IDS severity 1) can't be suppressed")
        if scope not in SCOPES:
            raise WorkflowError(f"unknown scope {scope!r}")
        reason = (reason or "").strip()
        if not reason:
            raise WorkflowError("a suppression needs a reason")
        facts = json.loads(row["facts"])
        indicator = main_indicator(json.loads(row["indicators"]), facts)
        port = facts.get("port")
        if scope == "port" and not isinstance(port, int):
            raise WorkflowError("this case has no port to suppress on")
        program = facts.get("host_program_path") or ""
        if scope == "device_program" and not program:
            raise WorkflowError("no single program on the device explains this case (needs host context)")
        if scope not in ("port", "device_program") and not indicator:
            raise WorkflowError("this case has no indicator to suppress on")
        if scope in ("device_domain", "domain") and "." not in indicator:
            raise WorkflowError("this case's indicator isn't a domain name")
        dom = base_domain(indicator) if indicator else ""
        dev = device_id(row["host"], facts)  # the rule follows the device, not the address it had that day
        values = {"device_indicator": (dev, indicator, None), "indicator": (None, indicator, None),
                  "device_domain": (dev, dom, None), "domain": (None, dom, None),
                  "port": (None, None, port), "device_program": (dev, program, None)}[scope]
        now = time.time()
        with self.db:
            cur = self.db.execute(
                "INSERT INTO suppressions (scope, detector, host, indicator, port, reason, created_ts, expires_ts)"
                " VALUES (?,?,?,?,?,?,?,?)", (scope, row["detector"], *values, reason, now, expires_ts))
            rule = self.db.execute("SELECT * FROM suppressions WHERE id=?", (cur.lastrowid,)).fetchone()
            self._audit(case_id, actor, "suppression added", None, f"{describe_rule(rule)}: {reason}", now)
        return cur.lastrowid

    def suppressions(self) -> list[sqlite3.Row]:
        return self.db.execute("SELECT * FROM suppressions ORDER BY id DESC").fetchall()

    def delete_suppression(self, rule_id: int, actor: str) -> bool:
        rule = self.db.execute("SELECT * FROM suppressions WHERE id=?", (rule_id,)).fetchone()
        if rule is None:
            return False
        with self.db:
            self.db.execute("DELETE FROM suppressions WHERE id=?", (rule_id,))
            self._audit(None, actor, "suppression deleted", f"{describe_rule(rule)}: {rule['reason']}", None,
                        time.time())
        return True

    def match_suppression(self, case: Case, now: float | None = None) -> str | None:
        """Return the label of the first live rule matching this case (and count the hit), else None.

        Never matches must_alert cases; the router double-checks this too."""
        if case.must_alert:
            return None
        now = time.time() if now is None else now
        port, program = case.facts.get("port"), case.facts.get("host_program_path") or ""
        live = self.db.execute("SELECT * FROM suppressions WHERE detector=? AND (expires_ts IS NULL OR expires_ts>?)"
                               " ORDER BY id", (case.detector, now)).fetchall()
        rule = None
        mine = {device_id(case.host, case.facts), case.host}  # rules made before identities were keyed by IP
        for r in live:
            same_device = r["host"] in mine
            scope = r["scope"]
            # Beaconing cases carried the indicator "port:N" when the destination had no name until
            # 2026-10-15 (now "<address>:N"); rules made from those keep matching by port.
            legacy = re.fullmatch(r"port:(\d+)", r["indicator"] or "")
            same_ind = r["indicator"] == case.indicator or bool(legacy and isinstance(port, int) and int(legacy[1]) == port)
            if (scope == "device_indicator" and same_device and same_ind) \
                    or (scope == "indicator" and same_ind) \
                    or (scope == "device_domain" and same_device and suffix_match(case.indicator, {r["indicator"]})) \
                    or (scope == "domain" and suffix_match(case.indicator, {r["indicator"]})) \
                    or (scope == "port" and isinstance(port, int) and r["port"] == port) \
                    or (scope == "device_program" and same_device and program and r["indicator"] == program):
                rule = r
                break
        if rule is None:
            return None
        self.db.execute("UPDATE suppressions SET hits=hits+1, last_hit_ts=? WHERE id=?", (now, rule["id"]))
        self.db.commit()
        return describe_rule(rule)
