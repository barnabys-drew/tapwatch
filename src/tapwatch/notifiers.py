"""Send alerts to a Teams channel (via a Workflows webhook) and/or email.

Teams setup (about 5 minutes, no Azure app needed): in the channel, open
Workflows, pick "Post to a channel when a webhook request is received", copy the
URL. The old Office 365 Connector webhooks were retired in May 2026.
"""

from __future__ import annotations

import json
import re
import smtplib
import subprocess
import urllib.parse
import urllib.request
from email.message import EmailMessage

from .summarizer import clean_untrusted

# Adaptive Card TextBlocks render Markdown, so a domain like "[click](http://evil)"
# would become a live link. Escape Markdown in anything from the network.
_MD = re.compile(r"([\\`*_{}\[\]()#+\-.!|>~])")

# Discord's Cloudflare front answers 403 to urllib's default "Python-urllib/3.x"
# agent (measured: same request, any other agent gets through), so name ourselves.
USER_AGENT = "tapwatch (+https://github.com/barnabys-drew/tapwatch)"


def md_escape(s: str) -> str:
    return _MD.sub(r"\\\1", clean_untrusted(s))


def card(title: str, items: list[dict]) -> dict:
    """items: [{"heading": str, "facts": {label: value}, "untrusted": [str]}]"""
    body: list[dict] = [{"type": "TextBlock", "size": "Large", "weight": "Bolder", "text": title, "wrap": True}]
    for it in items:
        body.append({"type": "TextBlock", "weight": "Bolder", "text": it["heading"], "wrap": True,
                     "separator": True, "spacing": "Medium"})
        facts = [{"title": k, "value": str(v)} for k, v in it.get("facts", {}).items()]
        if it.get("untrusted"):
            facts.append({"title": "Seen in traffic", "value": ", ".join(md_escape(u) for u in it["untrusted"])})
        body.append({"type": "FactSet", "facts": facts})
    return {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard", "version": "1.4", "body": body},
        }],
    }


def post_teams(webhook_url: str, payload: dict, timeout: float = 10) -> None:
    if urllib.parse.urlsplit(webhook_url).scheme not in ("http", "https"):
        raise ValueError("Teams webhook URL must be http(s)")
    req = urllib.request.Request(webhook_url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected -- scheme checked above
        if resp.status >= 300:
            raise RuntimeError(f"Teams webhook returned HTTP {resp.status}")


def as_text(title: str, items: list[dict]) -> str:
    out = [title, "=" * len(title), ""]
    for it in items:
        out.append(it["heading"])
        out += [f"  {k}: {v}" for k, v in it.get("facts", {}).items()]
        if it.get("untrusted"):
            out.append("  Seen in traffic (do not click): " + ", ".join(clean_untrusted(u) for u in it["untrusted"]))
        out.append("")
    return "\n".join(out)


def defang(s: str) -> str:
    """Make network-copied text inert in chat and push apps: no clickable links (example[.]com, hxxps)."""
    s = clean_untrusted(s)
    s = re.sub(r"(?i)\bhttp", "hxxp", s)
    return s.replace("://", "[://]").replace(".", "[.]")


def as_push_text(title: str, items: list[dict], limit: int = 3500) -> str:
    """Plain text for ntfy/Discord: facts as written by tapwatch, network strings defanged."""
    out = []
    for it in items:
        out.append(it["heading"])
        out += [f"{k}: {v}" for k, v in it.get("facts", {}).items()]
        if it.get("untrusted"):
            out.append("Seen in traffic: " + ", ".join(defang(u) for u in it["untrusted"]))
        out.append("")
    text = "\n".join(out).strip()
    return text if len(text) <= limit else text[:limit] + "\n..."


def _post(url: str, data: bytes, headers: dict, timeout: float = 10) -> None:
    if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
        raise ValueError("notification URLs must be http(s)")
    req = urllib.request.Request(url, data=data, method="POST", headers={"User-Agent": USER_AGENT, **headers})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected -- scheme checked above
        if resp.status >= 300:
            raise RuntimeError(f"HTTP {resp.status}")


def post_ntfy(url: str, token: str | None, title: str, items: list[dict], urgent: bool) -> None:
    """ntfy (ntfy.sh or self-hosted): a phone push. The topic URL is the secret; keep it in an env var."""
    headers = {"Title": clean_untrusted(title)[:200], "Priority": "high" if urgent else "default",
               "Tags": "rotating_light" if urgent else "spiral_notepad", "Content-Type": "text/plain; charset=utf-8"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    _post(url, as_push_text(title, items).encode(), headers)


def post_discord(url: str, title: str, items: list[dict]) -> None:
    """Discord webhook. Mentions are disabled, so text from the network can't ping @everyone."""
    content = f"**{clean_untrusted(title)}**\n" + as_push_text(title, items, limit=1800)
    payload = {"content": content, "allowed_mentions": {"parse": []}}
    _post(url, json.dumps(payload).encode(), {"Content-Type": "application/json"})


def post_webhook(url: str, title: str, items: list[dict]) -> None:
    """Generic JSON webhook for anything else (Home Assistant, Slack workflows, n8n...).
    `untrusted` strings are passed as data; the receiver must not render them as links."""
    _post(url, json.dumps({"title": title, "items": items}).encode(), {"Content-Type": "application/json"})


def send_email(smtp: dict, password: str | None, subject: str, text: str) -> None:
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, smtp["from"], smtp["to"]
    msg.set_content(text)
    with smtplib.SMTP(smtp["host"], int(smtp.get("port", 587)), timeout=15) as s:
        s.starttls()
        if smtp.get("username"):
            s.login(smtp["username"], password or "")
        s.send_message(msg)


class Notifier:
    """Fan out to every configured push channel (Teams, ntfy, Discord, webhook); email is the
    fallback when they all fail, or a copy with `always`."""

    def __init__(self, teams_url: str | None = None, smtp: dict | None = None, smtp_password: str | None = None,
                 email_always: bool = False, ntfy_url: str | None = None, ntfy_token: str | None = None,
                 discord_url: str | None = None, webhook_url: str | None = None):
        self.teams_url, self.smtp, self.smtp_password, self.email_always = teams_url, smtp, smtp_password, email_always
        self.ntfy_url, self.ntfy_token, self.discord_url, self.webhook_url = ntfy_url, ntfy_token, discord_url, webhook_url

    def channels(self) -> list[str]:
        names = [n for n, on in (("teams", self.teams_url), ("ntfy", self.ntfy_url), ("discord", self.discord_url),
                                 ("webhook", self.webhook_url)) if on]
        return names + (["email"] if self.smtp else [])

    def send(self, title: str, items: list[dict]) -> list[str]:
        """Returns the channels that succeeded. Raises if every configured channel failed."""
        sent, errors = [], []
        urgent = "digest" not in title.lower()
        push = [("teams", self.teams_url, lambda: post_teams(self.teams_url, card(title, items))),
                ("ntfy", self.ntfy_url, lambda: post_ntfy(self.ntfy_url, self.ntfy_token, title, items, urgent)),
                ("discord", self.discord_url, lambda: post_discord(self.discord_url, title, items)),
                ("webhook", self.webhook_url, lambda: post_webhook(self.webhook_url, title, items))]
        for name, configured, call in push:
            if not configured:
                continue
            try:
                call()
                sent.append(name)
            except Exception as e:  # noqa: BLE001 - one channel failing mustn't stop the others
                errors.append(f"{name}: {e}")
        if self.smtp and (self.email_always or not sent):
            try:
                send_email(self.smtp, self.smtp_password, title, as_text(title, items))
                sent.append("email")
            except Exception as e:  # noqa: BLE001
                errors.append(f"email: {e}")
        if not sent and errors:
            raise RuntimeError("; ".join(errors))
        return sent


class HerdrNotifier:
    """Pop a notification in the Herdr terminal workspace (https://herdr.dev) for critical cases.

    Runs `herdr notification show`, which talks to the local Herdr server over its socket, so it
    works from any process of the same user. Arguments go to the binary as a list (no shell), and
    text is stripped of control characters, so nothing in a case can inject terminal escapes.
    """

    def __init__(self, bin_path: str, sound: str = "request", position: str = "top-right",
                 timeout: float = 5.0, runner=subprocess.run):
        self.bin, self.sound, self.position, self.timeout, self.runner = bin_path, sound, position, timeout, runner

    def show(self, title: str, body: str) -> None:
        cmd = [self.bin, "notification", "show", clean_untrusted(title)[:80], "--body", clean_untrusted(body)[:300],
               "--position", self.position, "--sound", self.sound]
        try:
            res = self.runner(cmd, capture_output=True, text=True, timeout=self.timeout)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise RuntimeError(f"herdr notification failed: {e}") from e
        if res.returncode != 0:
            raise RuntimeError(f"herdr notification failed: {(res.stderr or res.stdout).strip()[:200]}")
