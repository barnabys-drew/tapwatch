"""Decide what happens to a case: alert now, daily digest, or log only.

Safety rule: the AI (and the admin's suppression rules) can raise or lower
priority for ordinary cases, but can never silence a `must_alert` case (threat-intel hit, critical IDS alert). Those
fields are set by deterministic code, so text an attacker puts in a domain name
cannot talk its way out of an alert.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import Case, Route, Verdict

# Detectors whose cases are routed by code only. Measured 2026-10-11/12: Jev 1.13
# called ordinary new domains (www.example.com, herdr.dev, bleepingcomputer.com)
# c2_beaconing at 0.5-0.95 confidence across several prompt wordings, while code
# facts (random-looking? widely used?) already separate them. Re-test before removing.
CODE_ONLY = {"new_domain",
             # Home rules where the fact is the verdict (docs/detections/DESIGN.md R03, R13).
             # R01 exposure and R14 rogue_dhcp are must_alert, so they skip the AI anyway.
             "mgmt_access", "cleartext_auth",
             # R16: the service's identity is the verdict, and judging whether a domain is
             # normal is Jev's measured weak spot.
             "takeover",
             # R07: which resolver a device uses is a fact; whether that's normal for the device is
             # the kind of "is this destination OK" call Jev is measured weak at.
             "dns_bypass",
             # A steady uploader going quiet is a fact about the device; nothing for Jev to weigh.
             "upload_stopped",
             # R22: a feed that stopped is a fact about tapwatch itself; nothing for Jev to weigh.
             "feed_silence",
             # R11: whether the owner logged in is a fact only the owner knows.
             "udm_admin",
             # R10 has no names to judge; Jev called a camera's vendor TLS "c2 0.95" (home eval).
             "tls_odd",
             # R17-R21, the endpoint rules (hostrules.NAMES): what ran on the PC is a fact the agent saw, and
             # "is this program normal?" is the same question as "is this domain normal?", never asked.
             "host_encoded_cmd", "host_app_shell", "host_temp_exec", "host_lolbin", "host_bad_sig", "host_persist"}


def wants_ai(case: Case) -> bool:
    return not case.must_alert and case.detector not in CODE_ONLY


@dataclass
class Thresholds:
    min_confidence: float = 0.6   # below this, a human should look (digest, flagged)
    page_prob: float = 0.7        # P(page_admin) needed to interrupt
    page_severity: float = 2.5    # and at least this severity (0..4 scale)
    routine_prob: float = 0.8     # P(routine) needed to drop to log-only
    # Category confidence Jev needs before it alone can interrupt. M5 eval (2026-10-13): true C2
    # beacons scored 0.78-0.99 over 3 runs each (FluBot, HtBot); a game launcher's update check
    # scored 0.60-0.61 and flipped into an alert at the old 0.6. Margin above FluBot is thin.
    alert_confidence: float = 0.75


RANK = {Route.LOG: 0, Route.DIGEST: 1, Route.ALERT: 2}


def route(case: Case, verdict: Verdict | None, t: Thresholds | None = None,
          suppression: str | None = None, learning: str | None = None) -> tuple[Route, str]:
    """`learning` is the pipeline's label ("learning period (day 1 of 3)") while the install is new."""
    r, reason = _route(case, verdict, t, suppression)
    if case.facts.get("min_route") == "alert" and not case.must_alert and r is not Route.ALERT:
        # Code saw something suspicious on the PC itself (a program in /tmp, a deleted binary, a
        # download-and-run command line). That floor beats suppressions and AI.
        signals = "; ".join(case.facts.get("host_signals", [])[:2])
        return Route.ALERT, f"on the PC: suspicious process ({signals})"
    caps = [c for c in (case.facts.get("max_route"), case.facts.get("host_max_route")) if c in ("log", "digest")]
    cap = min(caps, key=lambda c: RANK[Route(c)]) if caps else None
    if cap and not case.must_alert and not agent_misused(case) and RANK[r] > RANK[Route(cap)]:
        # A ceiling proven in code (household prevalence, a known sync service, a likely-benign program
        # on the PC). Jev can lower a case further but not raise it past this. Never for always-alert.
        return Route(cap), f"{reason}; capped at {cap} by code facts"
    if r is Route.ALERT and not case.must_alert and owner_likely(case):
        return Route.DIGEST, "on the PC: probably the owner's agent work (not confirmed), " + reason
    if learning and r is Route.ALERT and not case.must_alert and not agent_misused(case) \
            and case.facts.get("min_route") != "alert":
        # A fresh install. The windowed detectors (beaconing, dns_anomaly, scan) have no warm-up and
        # the prevalence caps need days of history, so day one of a home install produced 50 alerts
        # (2026-10-12), then 5, then 3. Until the learning period ends, the AI's alerts go to the
        # digest. Always-alert rules, agent misuse and a suspicious program on the PC still interrupt.
        return Route.DIGEST, f"{learning}: {reason}"
    return r, reason


def _route(case: Case, verdict: Verdict | None, t: Thresholds | None = None,
           suppression: str | None = None) -> tuple[Route, str]:
    """Return (route, reason). `verdict` is None when AI triage is off or failed.
    `suppression` is the label of an admin suppression rule that matched the case, if any."""
    t = t or Thresholds()
    if case.must_alert:
        return Route.ALERT, "always-alert rule"  # checked first: a suppression rule can't silence it either
    if agent_misused(case):  # before suppressions: an attacker could hide behind a pattern the owner muted
        return Route.ALERT, "on the PC: a coding agent did this without the owner asking"
    if suppression:
        return Route.LOG, f"suppressed: {suppression}"
    if owner_confirmed(case):
        return Route.LOG, "on the PC: the owner's own agent work"
    if verdict is None:
        if case.base_severity >= 4:
            return Route.ALERT, "rules-only: high severity"
        if case.base_severity >= 2:
            return Route.DIGEST, "rules-only"
        return Route.LOG, "rules-only: low severity"
    if verdict.category == "unknown" or verdict.category_confidence < t.min_confidence:
        return Route.DIGEST, "needs a human look: AI unsure"
    if verdict.page_admin >= t.page_prob and verdict.severity >= t.page_severity:
        if verdict.category_confidence >= t.alert_confidence:
            return Route.ALERT, f"AI: {verdict.category}, severity {verdict.severity:.1f}/4"
        return Route.DIGEST, f"AI leaning {verdict.category} ({verdict.category_confidence:.2f}), not sure enough to interrupt"
    if (verdict.category == "benign" and verdict.routine >= t.routine_prob
            and verdict.category_confidence >= 0.8 and case.base_severity < 4):
        return Route.LOG, "AI: routine activity"
    return Route.DIGEST, f"AI: {verdict.category}"


STALE_PROMPT_MIN = 30


def agent_misused(case: Case) -> bool:
    """Code saw an unattended/SSH-driven agent or web-content-then-action, or Jev judged it so (>= 0.6).
    Jev's call only counts when code tied the connection to an agent session (process proof): a
    transcript that merely mentions the destination is context, never routing. Case #63
    (2026-10-13) was a voice call escalated on transcript-only facts.
    Jev also needs a risk that code saw: it only reads code's facts, so with none it's guessing. Case
    #64 (2026-10-13) was the owner's own git push, attended, right after a prompt, called misused at 0.93."""
    f = case.facts
    return f.get("host_who") == "agent_misused" or (
        bool(f.get("host_agent_session")) and f.get("host_jev_who") == "agent_misused"
        and f.get("host_jev_conf", 0) >= 0.6 and bool(agent_risks(f)))


def agent_risks(f: dict) -> list[str]:
    """Facts that make an agent-made connection worth a second look, short of code's own 'misused'."""
    risks = []
    if not f.get("host_attended_known", True):  # the agent was found by its binary: no marker to read
        risks.append("the session's attendance could not be read")
    elif not f.get("host_attended"):
        risks.append("no one was attending the session")
    if not f.get("host_in_terminal"):
        risks.append("the session wasn't in the owner's terminal")
    if f.get("host_minutes_since_prompt", 0) >= STALE_PROMPT_MIN:
        risks.append("the owner's last prompt was long before")
    if f.get("host_outside_content") and not f.get("host_session_guessed"):  # a guessed session's reading is not this agent's
        risks.append("the agent read outside content first")
    return risks


def owner_confirmed(case: Case) -> bool:
    """Lower a case only when code corroborates it (an attended session, and the owner asked for it or
    the command followed their prompt with no outside content in between) AND Jev doesn't disagree."""
    f = case.facts
    if not f.get("host_corroborated"):
        return False
    jev = f.get("host_jev_who")
    return not jev or (jev == "owner_using_agent" and f.get("host_jev_conf", 0) >= 0.8)


def owner_likely(case: Case) -> bool:
    """An attended agent session made it, the owner didn't name the destination, and Jev reads it as
    the owner's work (>= 0.8). Enough to hold an alert back to the digest, never to log it away."""
    f = case.facts
    return (f.get("host_who") == "agent_unconfirmed" and f.get("host_attended") and not f.get("host_via_ssh")
            and f.get("host_jev_who") == "owner_using_agent" and f.get("host_jev_conf", 0) >= 0.8)


def critical(case: Case, verdict: Verdict | None, r: Route, ai_severity: float = 3.5) -> bool:
    """Truly critical: worth interrupting someone at the terminal, not just an alert email.

    Always-alert cases (threat-intel hit, IDS severity 1, internet exposure, rogue DHCP, exfil
    channel); deterministic code-only rules that alert at severity 4+ (admin-port access, tunnel or
    remote-control tool, after-hours remote session, telnet/FTP login to the internet); and AI-routed
    alerts only when Jev rates them critical (>= 3.5 of 4). The STUN false-alarm storm of
    2026-10-12 was rated 2.8 and would not have popped up.
    """
    if r is not Route.ALERT:
        return False
    if case.must_alert or agent_misused(case):
        return True
    if case.detector in CODE_ONLY:
        return case.base_severity >= 4
    return verdict is not None and verdict.severity >= ai_severity
