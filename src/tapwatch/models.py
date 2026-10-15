"""Shared data types.

A *Case* is one suspicious thing a detector noticed. Detectors are plain code
(counting, time windows, set lookups). The AI never sees raw log rows, only a
short written summary of a Case.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum


class Route(str, Enum):
    ALERT = "alert"    # notify now (ntfy, Discord, Teams, email, webhook)
    DIGEST = "digest"  # include in the daily summary
    LOG = "log"        # keep in the database only


def main_indicator(indicators: list[str], facts: dict) -> str:
    """The one string that makes a case "the same thing": first domain/SNI seen, else the detector's dedupe fact."""
    return indicators[0] if indicators else str(facts.get("dedupe", ""))


def device_id(host: str, facts: dict) -> str:
    """The stablest handle on the device behind a case: `name:<DHCP hostname>`, else `mac:<address>`,
    else the IP. The hostname survives a dock swap and a DHCP change; the MAC a DHCP change (both
    facts come from the Identity detector). Suppression rules are keyed on this, so a rule made
    for a laptop follows it between addresses."""
    if facts.get("device_name"):
        return f"name:{str(facts['device_name']).lower()}"
    if facts.get("device_mac"):
        return f"mac:{str(facts['device_mac']).lower()}"
    return host


@dataclass
class Case:
    detector: str            # which detector fired, e.g. "beaconing"
    host: str                # internal IP the activity came from
    ts: float                # epoch seconds of the triggering record
    title: str               # one-line human title (no attacker strings)
    facts: dict              # detector-specific numbers/words, used by the summarizer
    indicators: list[str] = field(default_factory=list)  # attacker-controllable strings (domains, SNI)
    must_alert: bool = False  # True = AI is not allowed to suppress it (IOC hit, critical IDS alert)
    base_severity: int = 2    # 1..5, the rule's own opinion, used when the AI is unavailable

    @property
    def indicator(self) -> str:
        return main_indicator(self.indicators, self.facts)

    @property
    def key(self) -> str:
        """Dedupe key: same detector + host + indicator counts as the same case."""
        raw = f"{self.detector}|{self.host}|{self.indicator}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass
class Verdict:
    """What Jev said about a case."""

    category: str
    category_confidence: float
    severity: float            # 0..4, probability-weighted (0 = informational, 4 = critical)
    severity_confidence: float
    routine: float             # P("this is routine IT activity")
    page_admin: float          # P("a solo admin should be interrupted now")
    model: str = ""
    input_tokens: int = 0
