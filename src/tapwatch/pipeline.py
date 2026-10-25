"""Wire it together: record -> detectors -> summarize -> Jev -> route -> store/notify."""

from __future__ import annotations

import json
import logging
import math
import time
from datetime import datetime, timezone

from . import detectors as det
from . import evidence, hostrules, inventory, vulnkev, zeek
from .hostctx import HostContext
from .models import Case, Route, Verdict
from .notifiers import HerdrNotifier, Notifier
from .router import RANK, Thresholds, critical, route, wants_ai
from .store import Store
from .summarizer import Assets, clean_untrusted, summarize
from .triage import JevClient, TriageError

log = logging.getLogger("tapwatch")


def case_link(base_url: str | None, case_id: int) -> str:
    return f"{base_url.rstrip('/')}/case/{case_id}" if base_url else f"#{case_id}"


CORRELATE_WINDOW = 300  # seconds either side of a case within which a host and a network case on one device pair


def alert_item(case: Case, verdict: Verdict | None, reason: str, assets: Assets, case_id: int,
               base_url: str | None = None) -> dict:
    facts = {
        "Device": f"{assets.name(case.host, case.facts)} ({case.host})",
        "When": datetime.fromtimestamp(case.ts, timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "Why": reason,
    }
    if case.facts.get("src") and "network" in case.facts:   # where a router login from outside came from (R11)
        net = clean_untrusted(case.facts["network"]) or "unknown network"
        facts["From"] = f"{case.facts['src']} ({net}" + (f", {case.facts['country']}" if case.facts.get("country") else "") + ")"
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
        self.vuln = next((d for d in detectors if isinstance(d, vulnkev.VulnKev)), None)
        self.fleet = [d for d in detectors if isinstance(d, hostrules.FleetAgents)]
        self.device_kev = vulnkev.DeviceKev(store)   # #227

    def process(self, rec: dict) -> list[tuple[int, Case, Verdict | None, Route]]:
        """One record through every detector; a `{"_type": "tick", "ts": now}` record is the minute tick instead."""
        out = []
        tick = rec.get("_type") == "tick"
        if not tick and det.hairpin(rec):
            return out   # a LAN device and the house's own public address: traffic that never left the house
        if not tick and rec.get("_type") in ("osquery", zeek.FLEET_OSQUERY) and rec.get("action") == "snapshot":
            self.record_inventory(rec)
        for d in self.detectors:
            for case in (d.tick(rec["ts"]) if tick else d.feed(rec)):
                handled = self.handle(case)
                if handled:
                    out.append(handled)
        for v in self._vulns():
            if v.resolved:
                vulnkev.close_resolved(self.store, v)   # R48: patched since its case, so the case closes
        return out

    def _vulns(self) -> list[vulnkev.VulnKev]:
        """R48 for this PC, and for every computer enrolled in Fleet."""
        out = [self.vuln] if self.vuln is not None else []
        return out + [v for f in self.fleet for v in f.vulns()]

    def record_inventory(self, rec: dict) -> None:
        """Software and OS snapshots from the endpoint agents go to the inventory tables (#224); the detectors
        still see the record."""
        name, agent = rec.get("name"), str(rec.get("hostIdentifier") or "")
        rows = [r for r in rec.get("snapshot") or () if isinstance(r, dict)]
        if name == inventory.OS_QUERY and rows:
            self.store.set_agent_os(agent, rows[0], rec.get("ts") or time.time())
        elif name in inventory.QUERIES:
            self.store.replace_software(agent, inventory.QUERIES[name], inventory.normalise(name, rows),
                                        rec.get("ts") or time.time())

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
        self.name_partner(case)
        self.device_kev.apply(case)   # #227: an open R48 case on the device raises this one
        partners = self.correlate(case)
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
        if "partner_in_house" in case.facts:
            self.note_partner(case, case_id, r)
        for other in partners:  # the other case learns about this one too, with a note on its page
            minutes = round((case.ts - other["first_ts"]) / 60)
            when = "in the same minute" if not minutes else f"{abs(minutes)} min {'later' if minutes > 0 else 'earlier'}"
            self.store.link_cases(other["id"], case_id,
                                  {"id": case_id, "detector": case.detector, "title": case.title, "route": r.value,
                                   "minutes": minutes},
                                  f"paired with #{case_id} ({case.detector}, {when} on the same device)")
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

    def name_partner(self, case: Case) -> None:
        """R16 found the likely other end of a remote-control session on another house device: name it from
        assets.yaml. When both ends are labelled devices, the session is someone in the house helping, so the case
        is held to the digest; an unlabelled partner or none at all keeps the alert."""
        p = case.facts.get("partner")
        if case.detector != "takeover" or not isinstance(p, dict) or not p.get("ip"):
            return
        ident = self.identity.facts_for(p["ip"]) if self.identity is not None else {}
        p["device"] = self.assets.describe(p["ip"], ident)
        if self.assets.entry(case.host, case.facts) and self.assets.entry(p["ip"], ident):
            p["known"] = True
            case.facts.setdefault("max_route", "digest")  # never loosen a stricter ceiling

    def note_partner(self, case: Case, case_id: int, r: Route) -> None:
        """The long-connection (odd_port) case for the same session learns what R16 found about the other end."""
        relays = set(case.facts.get("dests") or ())
        p = case.facts.get("partner")
        found = (f"the other end is likely {p.get('device', 'another device in the house')}" if isinstance(p, dict)
                 else "no other device in the house was on the same relay so far")
        for row in self.store.nearby(case, det.TakeoverChannel.SESSION_WINDOW, {"odd_port"}):
            if relays & set(json.loads(row["facts"] or "{}").get("dests") or ()):
                self.store.link_cases(row["id"], case_id,
                                      {"id": case_id, "detector": case.detector, "title": case.title, "route": r.value,
                                       "minutes": round((case.ts - row["first_ts"]) / 60)},
                                      f"#{case_id} (takeover) checked this session: {found}")

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

    def correlate(self, case: Case) -> list:
        """A host case and a network case on the same device within CORRELATE_WINDOW become one story.

        The sides must differ: a program the agent saw (`source: endpoint`) and something the wire saw, never two
        network cases or two host cases (those pair through host context and dedupe already). Measured 2026-10-17
        on the live case history, the 06:00 replay flood excluded: the pairs that were one story sat 0.0, 0.2,
        2.5, 3.7 and 4.4 minutes apart (a temp-folder curl and its new domain, a tampered binary and its new
        domain, a LOLBin and a new domain, a tls_odd item and the encoded command after it), and the nearest
        unrelated cases 6.2 and 11 minutes away, so the window is five minutes. The facts carry up to three
        partners, loudest first then newest, so the first is the one that sets `correlated_best`, which the
        router turns into a floor (router.route). A monitor case (R22) pairs with nothing, nor does a case the
        owner suppressed."""
        if not self.store or case.facts.get("source") == "monitor":
            return []
        mine = case.facts.get("source") == "endpoint"
        partners = []
        partners_of = hostrules.PAIRS.get(case.detector, frozenset()) if mine \
            else {h for h, nets in hostrules.PAIRS.items() if case.detector in nets}
        for r in self.store.nearby(case, CORRELATE_WINDOW, set(partners_of)):
            # The side and the pairing come from the rule names alone (no facts to parse): a host rule is one of
            # hostrules.NAMES, and a monitor case (R22) is in no host rule's PAIRS.
            if (r["detector"] in hostrules.NAMES) == mine:
                continue
            host_rule, net_rule = (case.detector, r["detector"]) if mine else (r["detector"], case.detector)
            if not hostrules.pairs_with(host_rule, net_rule):
                continue  # not the same story, just the same PC within five minutes (hostrules.PAIRS)
            if str(r["reason"] or "").startswith("suppressed:"):
                continue  # the owner said that side is expected: it is not half of a story (review of #139: #786)
            partners.append(r)
        if not partners:
            return []
        partners.sort(key=lambda r: (RANK[Route(r["route"])], r["id"]), reverse=True)  # loudest first, then newest
        partners = partners[:3]
        case.facts["correlated"] = [{"id": r["id"], "detector": r["detector"], "title": r["title"], "route": r["route"],
                                     "minutes": round((r["first_ts"] - case.ts) / 60)} for r in partners]
        case.facts["correlated_best"] = partners[0]["route"]
        return partners

    def add_host_context(self, case: Case) -> None:
        """For a case on the tapwatch PC: which program, and was it the owner's coding agent (hostctx.py)."""
        if case.facts.get("source") in ("endpoint", "monitor"):
            # a host rule's case already says what ran, and a monitor case (R22) is about tapwatch itself: the
            # PC's programs around it would only confuse it. Measured 2026-10-17, case #427: the first live
            # feed_silence alert was attributed to every connection on the PC in the window, judged likely
            # benign and capped at digest.
            return
        if not (self.hostctx and self.zeek_dirs
                and self.hostctx.is_this_pc(case.host, case.ts, case.facts.get("device_name"))):
            return  # not this PC's address, or another device (a shared dock) holds it now
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
        from . import explain
        rows = self.store.pending_digest()
        sugg = explain.suggestions(self.store)
        if not (rows or sugg) or not self.notifier:
            return 0
        items = []
        if sugg:  # #12: what host context explained, waiting for one press on the case desk
            items.append({"heading": f"{len(sugg)} suppression suggestion(s) from host context",
                          "facts": {"What": "repeated cases the PC checked and found benign, one program each",
                                    "Open": (self.base_url.rstrip("/") + "/suppressions#explained") if self.base_url
                                    else "tapwatch explain"},
                          "untrusted": []})
        for row in rows[:40]:  # keep the card readable; the rest go in the next digest
            facts = {"Device": f"{self.assets.name(row['host'], json.loads(row['facts']))} ({row['host']})",
                     "Why": row["reason"],
                     "Seen": f"{row['hits']} time(s)", "Case": case_link(self.base_url, row["id"])}
            items.append({"heading": row["title"], "facts": facts, "untrusted": json.loads(row["indicators"])})
        # A digest of suggestions alone repeats daily while they wait (the digest clock): a reminder, on purpose.
        parts = ([f"{len(rows)} item(s) to review"] if rows else []) + ([f"{len(sugg)} suggestion(s)"] if sugg else [])
        self.notifier.send("tapwatch daily digest: " + ", ".join(parts), items)
        self.store.mark_digested([r["id"] for r in rows[:40]])
        return len(items)
