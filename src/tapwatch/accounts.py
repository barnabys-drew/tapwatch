"""Account check: ask the owner's own Google accounts what was uploaded around an upload_spike case.

The network shows that a device sent 1.5 GB to Google's upload service, not what it was. The account knows. Drive
Activity lists files created or uploaded in a time window, YouTube lists the channel's uploads, and Gmail's metadata
lists sent and draft messages with their sizes (attachments up to 25 MB; bigger ones become Drive links, which
Drive Activity sees). Nothing else answers it: My Activity has no API and leaves out Drive uploads, the Photos
Library API only sees media the calling app created (since 2025), and iCloud has no usable API.

Opt-in and on demand (`tapwatch account-check <case>`, or the enrich-case skill): the alerter never calls Google.
Read-only scopes. Accounts are labels in config; each one's refresh token sits in a mode-600 file outside the repo
(`account_check.token_dir`), and the OAuth client in `.env`. File names, subjects and recipients are never stored:
a check records counts, file types, times and sizes, and `--names` prints Drive and YouTube titles to the terminal.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
REVOKE_URL = "https://oauth2.googleapis.com/revoke"
REDIRECT_URI = "http://127.0.0.1:8749/"   # loopback: the browser lands there and the owner pastes the address back
SCOPES = {
    "drive": "https://www.googleapis.com/auth/drive.activity.readonly",
    "youtube": "https://www.googleapis.com/auth/youtube.readonly",
    "gmail": "https://www.googleapis.com/auth/gmail.metadata",   # restricted: no search, no bodies, sizes and dates
}
API_HOSTS = ("https://oauth2.googleapis.com/", "https://driveactivity.googleapis.com/",
             "https://www.googleapis.com/youtube/", "https://gmail.googleapis.com/")
# Upload endpoints of Google services an account check can explain (Drive, Gmail attachments, YouTube).
GOOGLE_UPLOAD_SUFFIXES = ("content-storage-upload.googleapis.com", "upload.youtube.com", "upload.video.google.com")
LABEL = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
CLIENT_ENV = ("TAPWATCH_GOOGLE_CLIENT_ID", "TAPWATCH_GOOGLE_CLIENT_SECRET")
WINDOW = 1800          # seconds either side of the case's hours
GMAIL_MAX_GETS = 100   # message lookups per label per check


class AccountError(RuntimeError):
    pass


def google_upload_host(name: str) -> bool:
    name = (name or "").lower().rstrip(".")
    return any(name == s or name.endswith("." + s) for s in GOOGLE_UPLOAD_SUFFIXES)


# ---------------------------------------------------------------- HTTP (https to Google's API hosts only)

class Http:
    def _open(self, req: urllib.request.Request) -> dict:
        if not req.full_url.startswith(API_HOSTS):
            raise AccountError(f"refusing to call {req.full_url.split('?')[0]}: not a Google API host")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected -- https to API_HOSTS only, checked above
                return json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            detail = e.read()[:300].decode("utf-8", "replace")
            raise AccountError(f"{req.full_url.split('?')[0]}: HTTP {e.code} {detail}") from e

    def post_form(self, url: str, form: dict) -> dict:
        return self._open(urllib.request.Request(url, data=urllib.parse.urlencode(form).encode(), method="POST"))

    def post_json(self, url: str, token: str, body: dict) -> dict:
        return self._open(urllib.request.Request(url, data=json.dumps(body).encode(), method="POST", headers={
            "Authorization": f"Bearer {token}", "Content-Type": "application/json"}))

    def get(self, url: str, token: str, params: dict) -> dict:
        return self._open(urllib.request.Request(f"{url}?{urllib.parse.urlencode(params)}",
                                                 headers={"Authorization": f"Bearer {token}"}))


# ---------------------------------------------------------------- consent and tokens

def client() -> tuple[str, str]:
    cid, secret = (os.environ.get(k, "").strip() for k in CLIENT_ENV)
    if not cid or not secret:
        raise AccountError(f"set {CLIENT_ENV[0]} and {CLIENT_ENV[1]} in .env (a Desktop-app OAuth client: "
                           "docs/setup/account-check.md)")
    return cid, secret


def token_dir(cfg: dict) -> Path:
    return Path((cfg.get("account_check") or {}).get("token_dir") or "~/.local/state/tapwatch/accounts").expanduser()


def check_label(label: str) -> str:
    if not LABEL.match(label or ""):
        raise AccountError(f"account label {label!r}: lowercase letters, digits, - and _ (a name, never the address)")
    return label


def auth_request(client_id: str, services: list[str]) -> tuple[str, str, str]:
    """The consent URL, and the PKCE verifier and state to finish it with."""
    verifier = secrets.token_urlsafe(64)
    state = secrets.token_urlsafe(16)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    query = {"client_id": client_id, "redirect_uri": REDIRECT_URI, "response_type": "code",
             "scope": " ".join(SCOPES[s] for s in services), "access_type": "offline", "prompt": "consent",
             "code_challenge": challenge, "code_challenge_method": "S256", "state": state}
    return f"{AUTH_URL}?{urllib.parse.urlencode(query)}", verifier, state


def code_from_redirect(pasted: str, state: str) -> str:
    """The authorization code from the address the browser landed on (or the bare code)."""
    pasted = (pasted or "").strip()
    if "?" not in pasted and "=" not in pasted and pasted:
        return pasted
    q = urllib.parse.parse_qs(urllib.parse.urlparse(pasted).query)
    if q.get("error"):
        raise AccountError(f"Google said: {q['error'][0]}")
    if q.get("state", [""])[0] != state:
        raise AccountError("that address belongs to a different sign-in (state mismatch); start again")
    if not q.get("code"):
        raise AccountError("no code in that address; paste the whole address from the browser's bar")
    return q["code"][0]


def exchange(http: Http, client_id: str, secret: str, code: str, verifier: str) -> dict:
    tok = http.post_form(TOKEN_URL, {"client_id": client_id, "client_secret": secret, "code": code,
                                     "code_verifier": verifier, "grant_type": "authorization_code",
                                     "redirect_uri": REDIRECT_URI})
    if not tok.get("refresh_token"):
        raise AccountError("Google returned no refresh token; remove tapwatch's access at "
                           "myaccount.google.com/permissions and add the account again")
    return tok


def save_token(directory: Path, label: str, data: dict) -> Path:
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    path = directory / f"google-{check_label(label)}.json"
    tmp = path.with_suffix(".part")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(data, fh)
    os.replace(tmp, path)
    return path


def load_token(directory: Path, label: str) -> dict:
    path = directory / f"google-{check_label(label)}.json"
    if not path.exists():
        raise AccountError(f"no token for {label!r}: run `tapwatch accounts add {label}`")
    return json.loads(path.read_text())


def saved_labels(directory: Path) -> list[str]:
    return sorted(p.stem.removeprefix("google-") for p in directory.glob("google-*.json")) if directory.is_dir() else []


def access_token(http: Http, client_id: str, secret: str, refresh_token: str) -> str:
    tok = http.post_form(TOKEN_URL, {"client_id": client_id, "client_secret": secret,
                                     "refresh_token": refresh_token, "grant_type": "refresh_token"})
    if not tok.get("access_token"):
        raise AccountError("Google refused the refresh token (revoked, or expired: a consent screen left in "
                           "Testing expires them after 7 days); add the account again")
    return tok["access_token"]


# ---------------------------------------------------------------- the three sources

def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ts(iso: str) -> float:
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


def drive_activity(http: Http, token: str, start: float, end: float, max_pages: int = 5) -> list[dict]:
    """Files created or uploaded in Drive between start and end: time, how, file type (and title, never stored)."""
    body = {"filter": f'time >= "{_iso(start)}" AND time <= "{_iso(end)}" AND detail.action_detail_case:CREATE',
            "pageSize": 100}
    out = []
    for _ in range(max_pages):
        page = http.post_json("https://driveactivity.googleapis.com/v2/activity:query", token, body)
        for act in page.get("activities", []):
            when = act.get("timestamp") or (act.get("timeRange") or {}).get("endTime")
            create = (act.get("primaryActionDetail") or {}).get("create") or {}
            how = "upload" if "upload" in create else "copy" if "copy" in create else "new"
            for target in act.get("targets", []):
                item = target.get("driveItem")
                if item is not None and when:
                    out.append({"time": _ts(when), "how": how, "type": item.get("mimeType", ""),
                                "title": item.get("title", "")})
        if not page.get("nextPageToken"):
            break
        body["pageToken"] = page["nextPageToken"]
    return out


def youtube_uploads(http: Http, token: str, start: float, end: float) -> list[dict]:
    """Videos added to the channel's uploads list between start and end (newest first, one page)."""
    ch = http.get("https://www.googleapis.com/youtube/v3/channels", token, {"part": "contentDetails", "mine": "true"})
    items = ch.get("items") or []
    if not items:
        return []   # the account has no channel
    playlist = items[0]["contentDetails"]["relatedPlaylists"]["uploads"]
    page = http.get("https://www.googleapis.com/youtube/v3/playlistItems", token,
                    {"part": "snippet", "playlistId": playlist, "maxResults": 50})
    out = []
    for it in page.get("items", []):
        sn = it.get("snippet") or {}
        if sn.get("publishedAt") and start <= _ts(sn["publishedAt"]) <= end:
            out.append({"time": _ts(sn["publishedAt"]), "type": "video", "title": sn.get("title", "")})
    return out


def gmail_messages(http: Http, token: str, start: float, end: float) -> list[dict]:
    """Sent and draft messages dated between start and end, with their sizes. The metadata scope can't search,
    so it walks each label newest first and stops at the window's start; nothing but the date and size is read."""
    base = "https://gmail.googleapis.com/gmail/v1/users/me/messages"
    out = []
    for label in ("SENT", "DRAFT"):
        gets, page_token = 0, None
        while gets < GMAIL_MAX_GETS:
            params = {"labelIds": label, "maxResults": 25, **({"pageToken": page_token} if page_token else {})}
            page = http.get(base, token, params)
            older = False
            for m in page.get("messages", []):
                if gets >= GMAIL_MAX_GETS:
                    break
                msg = http.get(f"{base}/{m['id']}", token, {"format": "minimal"})
                gets += 1
                when = int(msg.get("internalDate", "0")) / 1000
                if when < start:
                    older = True
                    break
                if when <= end:
                    out.append({"time": when, "type": label.lower(), "bytes": int(msg.get("sizeEstimate", 0))})
            page_token = page.get("nextPageToken")
            if older or not page_token:
                break
    return out


# ---------------------------------------------------------------- the check

def _services(cfg: dict, label: str, saved: dict) -> list[str]:
    granted = {s for s, scope in SCOPES.items() if scope in (saved.get("scope") or "").split()}
    for a in (cfg.get("account_check") or {}).get("google") or ():
        if isinstance(a, dict) and a.get("label") == label and a.get("services"):
            return [s for s in a["services"] if s in granted]
    return [s for s in SCOPES if s in granted]


def accounts(cfg: dict) -> list[str]:
    """Configured labels, or every account with a saved token when config lists none."""
    listed = [a["label"] if isinstance(a, dict) else a for a in (cfg.get("account_check") or {}).get("google") or ()]
    return [check_label(x) for x in listed] or saved_labels(token_dir(cfg))


def check(cfg: dict, start: float, end: float, http: Http | None = None) -> dict:
    """Every configured account's Drive, YouTube and Gmail activity between start and end."""
    http = http or Http()
    cid, secret = client()
    result: dict = {"window": [round(start), round(end)], "accounts": {}}
    for label in accounts(cfg):
        entry: dict = {}
        try:
            saved = load_token(token_dir(cfg), label)
            token = access_token(http, cid, secret, saved["refresh_token"])
            for service in _services(cfg, label, saved):
                fn = {"drive": drive_activity, "youtube": youtube_uploads, "gmail": gmail_messages}[service]
                try:
                    entry[service] = fn(http, token, start, end)
                except AccountError as e:
                    entry[service] = {"error": str(e)}
        except AccountError as e:
            entry = {"error": str(e)}
        result["accounts"][label] = entry
    return result


def facts(result: dict) -> dict:
    """What goes into the case: per account and service, counts, types, times and sizes; no titles."""
    out = {"window": result["window"], "checked": round(time.time()), "accounts": {}}
    for label, entry in result["accounts"].items():
        if "error" in entry:
            out["accounts"][label] = {"error": entry["error"][:200]}
            continue
        acc = {}
        for service, rows in entry.items():
            if isinstance(rows, dict):
                acc[service] = {"error": rows["error"][:200]}
                continue
            s: dict = {"count": len(rows)}
            if rows:
                s["types"] = dict(Counter(r["type"] or "unknown" for r in rows).most_common(5))
                s["first"], s["last"] = round(min(r["time"] for r in rows)), round(max(r["time"] for r in rows))
                if any("bytes" in r for r in rows):
                    s["bytes"] = sum(r.get("bytes", 0) for r in rows)
            acc[service] = s
        out["accounts"][label] = acc
    return out


def _hm(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%H:%M")


NOUNS = {"drive": ("file created or uploaded", "files created or uploaded"),
         "youtube": ("video uploaded", "videos uploaded"),
         "gmail": ("sent or draft message", "sent or draft messages")}


def summary(f: dict) -> str:
    """One line per account, for the terminal, the case note and the skill: "personal: Drive shows 2 ..."."""
    lines, found = [], False
    for label, acc in f["accounts"].items():
        if "error" in acc:
            lines.append(f"{label}: couldn't check ({acc['error']})")
            continue
        parts = []
        for service, s in acc.items():
            name = {"drive": "Drive", "youtube": "YouTube", "gmail": "Gmail"}[service]
            if "error" in s:
                parts.append(f"{name} couldn't be checked ({s['error']})")
            elif not s["count"]:
                parts.append(f"{name} shows nothing")
            else:
                found = True
                n = s["count"]
                noun = NOUNS[service][n != 1]
                span = _hm(s["first"]) if s["first"] == s["last"] else f"{_hm(s['first'])}-{_hm(s['last'])}"
                types = ", ".join(f"{c} {t}" for t, c in s["types"].items())
                size = f", {s['bytes'] / 1e6:.1f} MB" if s.get("bytes") else ""
                parts.append(f"{name} shows {n} {noun} at {span} UTC ({types}{size})")
        lines.append(f"{label}: " + ("; ".join(parts) if parts else "no services granted"))
    w = f["window"]
    head = f"Account check {_hm(w[0])}-{_hm(w[1])} UTC: " + ("" if found else "the accounts show nothing: unexplained. ")
    return head + " | ".join(lines)
