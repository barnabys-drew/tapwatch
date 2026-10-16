"""Wire it together: record -> detectors -> summarize -> Jev -> route -> store/notify."""

from __future__ import annotations

import json
import logging
import math
import time
from datetime import datetime, timezone

from . import detectors as det
from . import evidence
from .hostctx import HostContext
from .models import Case, Route, Verdict
from .notifiers import HerdrNotifier, Notifier
from .router import Thresholds, critical, route, wants_ai
from .store import Store
from .summarizer import Assets, summarize
from .triage import JevClient, TriageError

log = logging.getLogger("tapwatch")


def case_link(base_url: str | None, case_id: int) -> str:
    return f"{base_url.rstrip('/')}/case/{case_id}" if base_url else f"#{case_id}"


def alert_item(case: Case, verdict: Verdict | None, reason: str, assets: Assets, case_id: int,
               base_url: str | None = None) -> dict:
    facts = {
        "Device": f"{assets.name(case.host, case.facts)} ({case.host})",
        "When": datetime.fromtimestamp(case.ts, timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "Why": reason,
    }
    if verdict:
        facts["AI read"] = (f"{verdict.category} (confidence {verdict.category_confidence:.0%}), "
                            f"routine {verdict.routine:.0%}")
    facts["Case"] = f"#{case_id}  (mark with: tapwatch mark {case_id} fp|tp)"
    if base_url:
        facts["Open"] = case_link(base_url, case_id)
    return {"heading": case.title, "facts": facts, "untrusted": case.indicators}


class Pipeline:
    def __init__(self, detectors: list[det.Detector], assets: Assets, store: Store,
                 client: JevClient | None = None, notifier: Notifier | None = None,
                 thresholds: Thresholds | None = None, dedupe_seconds: float = 3600,
                 base_url: str | None = None, herdr: HerdrNotifier | None = None, herdr_ai_severity: float = 3.5,
                 hostctx: HostContext | None = None, zeek_dirs=None, learning_seconds: float = 0):
        self.detectors, self.assets, self.store, self.base_url = detectors, assets, store, base_url
        self.client, self.notifier = client, notifier
        self.herdr, self.herdr_ai_severity = herdr, herdr_ai_severity  # critical cases pop up in the terminal
        self.hostctx, self.zeek_dirs = hostctx, zeek_dirs  # "who on the PC did this", for the tapwatch PC
        self.thresholds, self.dedupe_seconds = thresholds or Thresholds(), dedupe_seconds
        self.learning_seconds = learning_seconds  # AI alerts go to the digest while the install is this young
        self.identity = next((d for d in detectors if isinstance(d, det.Identity)), None)
        self._first_ts: float | None = None       # learning clock when no detector carries a Warmup
        self.input_tokens = 0
        self._pc_base: dict[int, set] = {}   # "this PC" address sets as configured, before follow_this_pc
        self._pc_warned: str | None = None

    def process(self, rec: dict) -> list[tuple[int, Case, Verdict | None, Route]]:
        out = []
        for d in self.detectors:
            for case in d.feed(rec):
                handled = self.handle(case)
                if handled:
                    out.append(handled)
        return out

    def flush(self) -> list[tuple[int, Case, Verdict | None, Route]]:
        """Handle cases detectors were still buffering (call at the end of a replay)."""
        out = []
        for d in self.detectors:
            for case in d.flush():
                handled = self.handle(case)
                if handled:
                    out.append(handled)
        return out

    def handle(self, case: Case) -> tuple[int, Case, Verdict | None, Route] | None:
        if self.store.recent(case, self.dedupe_seconds) is not None:
            return None  # same thing already reported recently: count it, don't re-ask or re-alert
        if self.identity is not None:
            case.facts.update(self.identity.facts_for(case.host))  # device_mac, device_name
        self.add_host_context(case)
        state = summarize(case, self.assets)
        if "host_who" in case.facts and self.client and hasattr(self.client, "who"):
            try:  # Jev judges what the PC facts add up to; the router decides how far to trust it
                case.facts["host_jev_who"], case.facts["host_jev_conf"] = self.client.who(state)
            except TriageError as e:
                log.warning("AI 'who' question failed: %s", e)
        suppression = self.store.match_suppression(case)  # always None for must_alert cases
        verdict = None
        if self.client and wants_ai(case) and not suppression:  # skip always-alert, code-routed and suppressed
            try:
                verdict = self.client.triage(state)
                self.input_tokens += verdict.input_tokens
            except TriageError as e:
                log.warning("AI triage failed, using rules only: %s", e)
        r, reason = route(case, verdict, self.thresholds, suppression, self.learning_label(case.ts))
        case_id = self.store.add(case, state, verdict, r, reason)
        if suppression and r is not Route.ALERT:
            # The owner already said this is expected: the case is kept for the stats and the audit
            # trail, but arrives closed rather than as another "new" item to triage by hand.
            self.store.update_case(case_id, "tapwatch", status="closed", disposition="benign_expected",
                                   note=f"closed on arrival: matched suppression {suppression}")
        if self.herdr and critical(case, verdict, r, self.herdr_ai_severity):
            where = case_link(self.base_url, case_id) if self.base_url else f"case #{case_id}"
            try:
                self.herdr.show(f"tapwatch CRITICAL: {case.title}",
                                f"{self.assets.name(case.host, case.facts)} - {reason} - {where}")
            except RuntimeError as e:
                log.error("could not show Herdr notification for #%s: %s", case_id, e)
        if r is Route.ALERT and self.notifier:
            try:
                self.notifier.send(f"tapwatch alert: {case.title}",
                                   [alert_item(case, verdict, reason, self.assets, case_id, self.base_url)])
            except RuntimeError as e:
                log.error("could not deliver alert #%s: %s", case_id, e)
        return case_id, case, verdict, r

    def _warmup(self) -> det.Warmup | None:
        return next((d.warmup for d in self.detectors if isinstance(getattr(d, "warmup", None), det.Warmup)), None)

    def learning_label(self, ts: float) -> str | None:
        """"learning period (day 1 of 3)" while the install is younger than learning_seconds, else None.

        The clock is the first-seen detectors' warm-up start, which save_state persists, so a
        restart doesn't start a new learning period."""
        if not self.learning_seconds:
            return None
        w = self._warmup()
        start = w.start if w is not None and w.start is not None else self._first_ts
        if start is None:
            self._first_ts = start = ts
        if ts - start >= self.learning_seconds:
            return None
        days = max(1, math.ceil(self.learning_seconds / 86400))
        return f"learning period (day {min(days, int((ts - start) // 86400) + 1)} of {days})"

    def save_state(self) -> int:
        """Persist what the detectors have learned. Returns how many detectors were saved."""
        states = {d.name: d.snapshot() for d in self.detectors if d.PERSIST}
        w = self._warmup()
        if w is not None and w.start is not None:
            states["warmup"] = {"start": w.start}
        self.store.save_state(states)
        return len(states)

    def restore_state(self) -> int:
        """Load saved detector state (call once, before processing). A detector whose saved shape
        no longer fits (an upgrade changed it) starts fresh instead of crashing the alerter."""
        saved, n = self.store.load_state(), 0
        for d in self.detectors:
            if d.PERSIST and d.name in saved:
                try:
                    d.restore(saved[d.name])
                    n += 1
                except Exception as e:  # noqa: BLE001
                    log.warning("discarding saved state for %s: %s", d.name, e)
        w = self._warmup()
        if w is not None and w.start is None and isinstance(saved.get("warmup", {}).get("start"), (int, float)):
            w.start = saved["warmup"]["start"]
        return n

    def add_host_context(self, case: Case) -> None:
        """For a case on the tapwatch PC: which program, and was it the owner's coding agent (hostctx.py)."""
        if case.facts.get("source") == "endpoint":
            return  # a host rule's case already says what ran; the network programs around it would only confuse it
        if not (self.hostctx and self.zeek_dirs and self.hostctx.is_this_pc(case.host, case.ts)):
            return
        try:
            ev = evidence.lookup(self.zeek_dirs, case.host, case.ts, window=180)
            case.facts.update(self.hostctx.collect(case, ev["conn"]["rows"], ev["dns"]["rows"]))
        except Exception as e:  # noqa: BLE001 - context is a bonus; never lose the case over it
            log.warning("host context failed for %s: %s", case.detector, e)

    def follow_this_pc(self, now: float | None = None) -> set[str] | None:
        """Keep rules that name the tapwatch PC by its configured IP (admin_devices, dev_profile.hosts) on the
        addresses its agents report now, since DHCP moves it. Returns those addresses (None: no reports)."""
        if not self.hostctx:
            return None
        now = now or time.time()
        current = self.hostctx.addresses_near(now)
        warning = self.hostctx.config_mismatch(now)
        if warning and warning != self._pc_warned:
            log.warning("%s", warning)
        self._pc_warned = warning
        if current is None:
            return None
        sets = [d.dev.hosts for d in self.detectors if isinstance(getattr(d, "dev", None), det.DevProfile)]
        sets += [d.admins for d in self.detectors if isinstance(d, det.ManagementAccess)]
        for s in {id(s): s for s in sets}.values():
            base = self._pc_base.setdefault(id(s), set(s))
            if self.hostctx.host in base:
                s.clear()
                s |= base | current
        return current

    def send_digest(self) -> int:
        rows = self.store.pending_digest()
        if not rows or not self.notifier:
            return 0
        items = []
        for row in rows[:40]:  # keep the card readable; the rest go in the next digest
            facts = {"Device": f"{self.assets.name(row['host'], json.loads(row['facts']))} ({row['host']})",
                     "Why": row["reason"],
                     "Seen": f"{row['hits']} time(s)", "Case": case_link(self.base_url, row["id"])}
            items.append({"heading": row["title"], "facts": facts, "untrusted": json.loads(row["indicators"])})
        self.notifier.send(f"tapwatch daily digest: {len(rows)} item(s) to review", items)
        self.store.mark_digested([r["id"] for r in rows[:40]])
        return len(items)
