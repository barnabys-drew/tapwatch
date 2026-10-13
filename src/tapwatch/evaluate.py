"""Phase 0 go/no-go: does Jev triage beat rules-only on labelled traffic?

Feed Zeek logs from a replayed PCAP through the detectors once, then route every
case two ways: rules-only, and with Jev. Ground truth is a labels file listing
which internal hosts were infected/malicious in the capture.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from . import zeek
from .detectors import Detector
from .models import Case, Route, Verdict
from .router import Thresholds, route, wants_ai
from .summarizer import Assets, summarize
from .triage import JevClient, TriageError, cost_usd


@dataclass
class ModeResult:
    routes: Counter = field(default_factory=Counter)        # (route, truth) -> count
    surfaced_bad_hosts: set = field(default_factory=set)    # malicious hosts with an alert or digest case
    alerted_bad_hosts: set = field(default_factory=set)


def _tally(res: ModeResult, case: Case, r: Route, bad: bool) -> None:
    res.routes[(r.value, "bad" if bad else "ok")] += 1
    if bad and r is not Route.LOG:
        res.surfaced_bad_hosts.add(case.host)
    if bad and r is Route.ALERT:
        res.alerted_bad_hosts.add(case.host)


def run(log_dir, labels: dict, detectors: list[Detector], assets: Assets,
        client: JevClient | None, thresholds: Thresholds | None = None) -> dict:
    bad_hosts = set(labels.get("malicious_hosts", []))
    cases: list[Case] = []
    seen_keys = set()
    def all_cases():
        for rec in zeek.replay(log_dir):
            for d in detectors:
                yield from d.feed(rec)
        for d in detectors:
            yield from d.flush()

    for c in all_cases():
        if c.key not in seen_keys:  # same dedupe the live pipeline does
            seen_keys.add(c.key)
            cases.append(c)

    rules, ai = ModeResult(), ModeResult()
    calib: Counter = Counter()  # (bucket, correct?) -> n
    tokens, failures = 0, 0
    for c in cases:
        bad = c.host in bad_hosts
        _tally(rules, c, route(c, None, thresholds)[0], bad)
        verdict: Verdict | None = None
        if client and wants_ai(c):
            try:
                verdict = client.triage(summarize(c, assets))
                tokens += verdict.input_tokens
            except TriageError:
                failures += 1
        if client:
            _tally(ai, c, route(c, verdict, thresholds)[0], bad)
        if verdict and verdict.category != "unknown":
            bucket = min(int(verdict.category_confidence * 10) // 2 * 2, 8)  # 0,2,4,6,8 -> tenths
            calib[(bucket, (verdict.category != "benign") == bad)] += 1

    return {"cases": len(cases), "by_detector": Counter(c.detector for c in cases),
            "bad_hosts": bad_hosts, "hosts_with_cases": {c.host for c in cases},
            "rules": rules, "ai": ai if client else None, "calibration": calib,
            "tokens": tokens, "cost": cost_usd(tokens), "failures": failures,
            "model": getattr(client, "model", "ai")}


def _mode_lines(name: str, m: ModeResult, bad_hosts: set) -> list[str]:
    r = m.routes
    noise = r[("alert", "ok")] + r[("digest", "ok")]
    lines = [f"  {name}:",
             f"    alert : {r[('alert', 'bad')]:4d} malicious  {r[('alert', 'ok')]:4d} benign",
             f"    digest: {r[('digest', 'bad')]:4d} malicious  {r[('digest', 'ok')]:4d} benign",
             f"    log   : {r[('log', 'bad')]:4d} malicious  {r[('log', 'ok')]:4d} benign",
             f"    benign items the admin must read (alert+digest): {noise}",
             (f"    malicious hosts surfaced: {len(m.surfaced_bad_hosts)}/{len(bad_hosts)}"
             f"   alerted: {len(m.alerted_bad_hosts)}/{len(bad_hosts)}")]
    return lines


def report(res: dict) -> str:
    out = [f"cases: {res['cases']}  " + ", ".join(f"{k}={v}" for k, v in sorted(res["by_detector"].items())),
           (f"labelled malicious hosts: {len(res['bad_hosts'])}; "
           f"detected by any rule: {len(res['bad_hosts'] & res['hosts_with_cases'])}")]
    out += _mode_lines("rules-only", res["rules"], res["bad_hosts"])
    if res["ai"] is None:
        out.append("  ai: skipped (no TYPESAFE_API_KEY or AI_GATEWAY_API_KEY set)")
        return "\n".join(out)
    out += _mode_lines(f"with {res['model']}", res["ai"], res["bad_hosts"])
    out.append(f"    API failures: {res['failures']}  input tokens: {res['tokens']}  cost: ${res['cost']:.5f}")
    out.append("  calibration (category confidence -> how often the malicious/benign call was right):")
    for b in range(0, 10, 2):
        right, wrong = res["calibration"][(b, True)], res["calibration"][(b, False)]
        if right + wrong:
            out.append(f"    {b / 10:.1f}-{(b + 2) / 10:.1f}: {right}/{right + wrong} = {right / (right + wrong):.0%}")
    rn = res["rules"].routes
    an = res["ai"].routes
    rules_noise = rn[("alert", "ok")] + rn[("digest", "ok")]
    ai_noise = an[("alert", "ok")] + an[("digest", "ok")]
    lost = res["rules"].surfaced_bad_hosts - res["ai"].surfaced_bad_hosts
    # Jev earns its place by cutting noise OR by promoting real threats to alerts, as long as it
    # adds no false alerts and loses no malicious host. (The old rule only counted noise cuts; the
    # 2026-10-13 eval showed Jev's value is promotion: FluBot and HtBot went digest -> alert.)
    more_alerted = len(res["ai"].alerted_bad_hosts) > len(res["rules"].alerted_bad_hosts)
    extra_false_alerts = an[("alert", "ok")] > rn[("alert", "ok")]
    helped = ai_noise < rules_noise or more_alerted
    verdict = "GO" if helped and not extra_false_alerts and not lost else "NO-GO"
    out.append(f"  verdict: {verdict}  (noise {rules_noise} -> {ai_noise}; malicious hosts alerted "
               f"{len(res['rules'].alerted_bad_hosts)} -> {len(res['ai'].alerted_bad_hosts)}; false alerts "
               f"{rn[('alert', 'ok')]} -> {an[('alert', 'ok')]}; "
               f"malicious hosts lost vs rules-only: {sorted(lost) or 'none'})")
    return "\n".join(out)
