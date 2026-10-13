"""Ask Jev (TypeSafe's System One API) to triage a case.

One HTTP call per case carries all four questions; TypeSafe evaluates them in
parallel against the same state. Raw HTTP via urllib keeps us dependency-free;
the endpoint and shapes follow https://docs.typesafe.ai/api.md.

Two providers speak the same API:
  * TypeSafe directly (TYPESAFE_API_KEY), with the model version pinned
  * Vercel AI Gateway's TypeSafe-compatible route (AI_GATEWAY_API_KEY), billed by Vercel
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from .models import Verdict

API_URL = "https://api.typesafe.ai/v1/systemone"
DEFAULT_MODEL = "jev-1.13.0"  # pinned: "jev-latest" would silently change behaviour under us
GATEWAY_URL = "https://ai-gateway.vercel.sh/typesafe/v1/systemone"
GATEWAY_MODEL = "typesafe-ai/jev"  # gateway model id; check GET /typesafe/v1/models for pinnable versions
PRICE_PER_M_INPUT = 0.042     # USD per million input tokens at TypeSafe list price; output tokens are free

# Benign is listed first on purpose: Jev 1.13 leans toward the first option, and a
# lean toward "benign" is caught by the router (confidence gates + must_alert), while
# a lean toward "c2" would just create noise.
CATEGORIES = {
    "benign": "Routine, expected activity: software or OS updates, cloud services, backups, time sync, normal browsing",
    "c2_beaconing": "Malware checking in with a command-and-control server",
    "malware_delivery": "Downloading or running malicious software",
    "data_exfiltration": "Stealing or uploading company data to an outside party",
    "recon_scanning": "Mapping the network or probing for vulnerable services",
    "policy_violation": "Not an attack but against normal business policy: torrents, personal VPNs, crypto mining",
    "unknown": "Not enough information to tell what this is",
}

SEVERITY_LEVELS = [
    "Informational: nothing to do",
    "Low: worth a glance in a weekly review",
    "Medium: check within a day",
    "High: likely compromise, check within the hour",
    "Critical: active attack or data loss in progress, act now",
]

def build_questions(audience: str = "office") -> dict:
    """The four triage questions, framed for an office (measured) or a home (see summarizer.WORDING)."""
    home = audience == "home"
    cats = dict(CATEGORIES)
    if home:
        cats["data_exfiltration"] = "Stealing or uploading personal or family data to an outside party"
        cats["policy_violation"] = ("Not an attack but not something the household wants: torrents, "
                                    "unexpected VPNs or proxies, crypto mining")
    return {
        "category": {"type": "choice", "instructions": "What kind of activity is this most likely to be?",
                     "criteria": cats},
        "severity": {"type": "score",
                     "instructions": "How urgent is this for the household?" if home
                     else "How urgent is this for the business?",
                     "criteria": SEVERITY_LEVELS},
        "routine": {"type": "noul",
                    "instructions": "This is consistent with routine activity of home devices such as updates, "
                                    "backups, cloud sync or streaming." if home else
                                    "This is consistent with routine IT activity such as updates, backups, "
                                    "cloud sync or administration."},
        "page_admin": {"type": "noul",
                       "instructions": "The owner should be interrupted right now to look at this." if home else
                                       "A solo IT administrator should be interrupted right now to look at this."},
    }


QUESTIONS = build_questions("office")


# Asked only when tapwatch has host context from the PC (hostctx.py): the facts are code's,
# Jev judges what they add up to. Owner listed first per the "benign first" convention above;
# the router only lets this lower a case when code facts corroborate it.
WHO = {"who": {"type": "choice", "instructions": "Who most likely caused this activity on the PC?",
               "criteria": {
                   "owner_using_agent": "The owner was using their coding agent and asked for this, or it is a "
                                        "normal part of what they asked for",
                   "agent_misused": "A coding agent did this but the owner did not ask for it: the agent was "
                                    "tricked by content it read, or someone else was driving it",
                   "other_program": "A program unrelated to any coding agent did this, such as malware or an "
                                    "attacker's tools",
                   "unknown": "Not enough information to tell"}}}


class TriageError(RuntimeError):
    pass


class JevClient:
    def __init__(self, api_key: str, model: str = DEFAULT_MODEL, timeout: float = 10.0, retries: int = 3,
                 url: str = API_URL, audience: str = "office"):
        if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
            raise ValueError("Jev API url must be http(s)")
        self.api_key, self.model, self.timeout, self.retries, self.url = api_key, model, timeout, retries, url
        self.questions = build_questions(audience)

    def ask(self, state: str, questions: dict | None = None) -> dict:
        body = json.dumps({"state": state, "model": self.model, "questions": questions or self.questions}).encode()
        req = urllib.request.Request(self.url, data=body, method="POST", headers={
            "Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"})
        for attempt in range(self.retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected -- scheme checked in __init__
                    return json.loads(resp.read())
            except urllib.error.HTTPError as e:
                # 429 = rate limited, 529 = overloaded, 5xx = server trouble: back off and retry
                if (e.code in (429, 529) or e.code >= 500) and attempt < self.retries:
                    time.sleep(2 ** attempt)
                    continue
                raise TriageError(f"{self.url} returned HTTP {e.code}") from e
            except (urllib.error.URLError, TimeoutError) as e:
                if attempt < self.retries:
                    time.sleep(2 ** attempt)
                    continue
                raise TriageError(f"TypeSafe API unreachable: {e}") from e
        raise TriageError("unreachable")  # pragma: no cover

    def triage(self, state: str) -> Verdict:
        return parse(self.ask(state))

    def who(self, state: str) -> tuple[str, float]:
        """(answer, confidence) for the WHO question."""
        try:
            a = self.ask(state, WHO)["answers"]["who"]
            return str(a["choice"]), float(a["confidence"])
        except (KeyError, TypeError, ValueError) as e:
            raise TriageError(f"unexpected TypeSafe response shape: {e}") from e


def parse(resp: dict) -> Verdict:
    try:
        a = resp["answers"]
        return Verdict(
            category=a["category"]["choice"],
            category_confidence=float(a["category"]["confidence"]),
            severity=float(a["severity"]["score"]),
            severity_confidence=float(a["severity"]["confidence"]),
            routine=float(a["routine"]["noul"]),
            page_admin=float(a["page_admin"]["noul"]),
            model=resp.get("model", ""),
            input_tokens=int(resp.get("usage", {}).get("input_tokens", 0)),
        )
    except (KeyError, TypeError, ValueError) as e:
        raise TriageError(f"unexpected TypeSafe response shape: {e}") from e


def cost_usd(input_tokens: int) -> float:
    return input_tokens / 1_000_000 * PRICE_PER_M_INPUT
