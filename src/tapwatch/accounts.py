"""Account check: ask the owner's own Google accounts what was uploaded around an upload_spike case.

The network shows that a device sent 1.5 GB to Google's upload service, not what it was. The account knows. Drive
Activity lists files the account itself created, uploaded or replaced with a new version in a time window, YouTube
lists the channel's uploads, and Gmail's metadata lists sent and draft messages with their sizes (attachments up to
25 MB; bigger ones become Drive links, which Drive Activity sees). Nothing else answers it: My Activity has no API
and leaves out Drive uploads, the Photos Library API only sees media the calling app created (since 2025), and
iCloud has no usable API.

Three outcomes, never two: something explains the upload; every account was fully checked and shows nothing
("unexplained"); or a check failed, stopped short or wasn't set up ("incomplete"), which says nothing either way.
An unexplained upload whose device talked to a managed-account marker (MANAGED_MARKERS) in its Zeek DNS or TLS
records around the upload becomes "possibly_managed_account": a work or school Google account on the device may
explain it, and the check can't see that account.

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
# Google upload endpoints seen carrying Drive, Gmail-attachment and YouTube uploads from browsers and apps. Google
# doesn't document which service uses which; the check asks every source either way.
GOOGLE_UPLOAD_SUFFIXES = ("content-storage-upload.googleapis.com", "upload.youtube.com", "upload.video.google.com")
LABEL = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
MIME = re.compile(r"^[a-z0-9][a-z0-9.+-]{0,40}/[a-z0-9][a-z0-9.+-]{0,80}$")   # anything else is someone's free text
CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
CLIENT_ENV = ("TAPWATCH_GOOGLE_CLIENT_ID", "TAPWATCH_GOOGLE_CLIENT_SECRET")
WINDOW = 1800          # seconds either side of the case's hours
GMAIL_MAX_GETS = 100   # message lookups per label per check
SMALL_SHARE = 0.25     # Gmail messages under this share of the upload's size don't explain it
# Names only a managed (work or school) Google account makes a device look up or connect to. #986: a phone's
# 1.56 GB upload that the personal accounts couldn't explain came from a Workspace account in Gmail on it, and the
# phone reached ios-mdm.google.com, Google's iOS device management endpoint, during the upload. Add a name here
# only once it has been seen doing the same.
MANAGED_MARKERS = ("ios-mdm.google.com",)
MARKER_ROWS = 20_000   # DNS and TLS rows read per log type when looking for a marker
GMAIL_PAST_START = 5   # keep walking this many older messages: list order isn't promised, internalDate isn't send time


class AccountError(RuntimeError):
    pass


def google_upload_host(name: str) -> bool:
    name = (name or "").lower().rstrip(".")
    return any(name == s or name.endswith("." + s) for s in GOOGLE_UPLOAD_SUFFIXES)


def clean_type(t: str) -> str:
    t = (t or "").lower()
    return t if MIME.match(t) else "other"


def clean_title(t: str) -> str:
    return CONTROL.sub("", t or "")[:120]


# ---------------------------------------------------------------- HTTP (https to Google's API hosts only)

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None   # a redirect would carry the bearer token to wherever it points; the allowlist must hold


_OPENER = urllib.request.build_opener(_NoRedirect)


class Http:
    def _open(self, req: urllib.request.Request) -> dict:
        url = req.full_url.split("?")[0]
        if not req.full_url.startswith(API_HOSTS):
            raise AccountError(f"refusing to call {url}: not a Google API host")
        try:
            with _OPENER.open(req, timeout=30) as resp:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected -- https to API_HOSTS only, checked above; redirects refused
                return json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            detail = CONTROL.sub(" ", e.read()[:300].decode("utf-8", "replace"))
            raise AccountError(f"{url}: HTTP {e.code} {detail}") from e
        except (OSError, ValueError) as e:   # DNS, refused, timeout, reset; a body that isn't JSON
            raise AccountError(f"{url}: {type(e).__name__}: {e}") from e

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
             "scope": " ".join(SCOPES[s] for s in services), "access_type": "offline",
             "prompt": "consent select_account",   # always the chooser: a signed-in browser picks silently otherwise
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
    if not directory.exists():
        directory.mkdir(parents=True, mode=0o700)
        # mkdir's mode is masked by the umask. 0o700 on a directory is owner-only, the strictest that still works
        os.chmod(directory, 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- owner-only directory for refresh tokens
    path = directory / f"google-{check_label(label)}.json"
    tmp = path.with_suffix(".part")
    tmp.unlink(missing_ok=True)      # a leftover would keep its old mode
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(data, fh)
    os.replace(tmp, path)
    return path


def load_token(directory: Path, label: str) -> dict:
    path = directory / f"google-{check_label(label)}.json"
    if not path.exists():
        raise AccountError(f"no token for {label!r}: run `tapwatch accounts add {label}`")
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError) as e:
        raise AccountError(f"{path} is unreadable ({e}); remove it and add the account again") from e
    if not isinstance(data, dict) or not data.get("refresh_token"):
        raise AccountError(f"{path} holds no refresh token; remove it and add the account again")
    return data


def granted(saved: dict) -> list[str]:
    scopes = set((saved.get("scope") or "").split())
    return [s for s, scope in SCOPES.items() if scope in scopes]


def saved_labels(directory: Path) -> list[str]:
    return sorted(p.stem.removeprefix("google-") for p in directory.glob("google-*.json")) if directory.is_dir() else []


def _mailbox(http: Http, token: str) -> str:
    """A fingerprint of the Gmail mailbox behind a token (sha256 of the address; the address itself isn't kept)."""
    addr = http.get("https://gmail.googleapis.com/gmail/v1/users/me/profile", token, {}).get("emailAddress", "")
    return hashlib.sha256(addr.lower().encode()).hexdigest() if addr else ""


def same_account(http: Http, client_id: str, secret: str, directory: Path, label: str, tok: dict) -> str:
    """The saved label that is the same Google account as a new sign-in, or "". Needs the Gmail scope on both
    sides; without it, nothing to compare, so "". A browser already signed in to one account picks it silently,
    which is how a second label once became a copy of the first."""
    if SCOPES["gmail"] not in (tok.get("scope") or "").split() or not tok.get("access_token"):
        return ""
    new = _mailbox(http, tok["access_token"])
    for other in saved_labels(directory):
        if other == label:
            continue
        try:
            saved = load_token(directory, other)
            if SCOPES["gmail"] not in granted_scopes(saved):
                continue
            if new and new == _mailbox(http, access_token(http, client_id, secret, saved["refresh_token"])):
                return other
        except AccountError:
            continue
    return ""


def granted_scopes(saved: dict) -> set[str]:
    return set((saved.get("scope") or "").split())


def access_token(http: Http, client_id: str, secret: str, refresh_token: str) -> str:
    try:
        tok = http.post_form(TOKEN_URL, {"client_id": client_id, "client_secret": secret,
                                         "refresh_token": refresh_token, "grant_type": "refresh_token"})
    except AccountError as e:
        if "invalid_grant" in str(e):   # Google's answer for a revoked or expired refresh token: HTTP 400
            raise AccountError("Google refused the saved sign-in (revoked, or expired: a consent screen left in "
                               "Testing expires them after 7 days); add the account again") from e
        raise
    if not tok.get("access_token"):
        raise AccountError("Google returned no access token; add the account again")
    return tok["access_token"]


# ---------------------------------------------------------------- the three sources
# Each returns (rows, complete): complete is False when it stopped before covering the whole window.

def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ts(iso: str) -> float:
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


def _own(act: dict) -> bool:
    """The account itself did it: a collaborator's file in a shared folder explains nothing about this device."""
    return any(((a.get("user") or {}).get("knownUser") or {}).get("isCurrentUser") for a in act.get("actors", []))


def drive_activity(http: Http, token: str, start: float, end: float, max_pages: int = 5) -> tuple[list[dict], bool]:
    """Files the account created, uploaded or replaced with a new version in My Drive between start and end. Shared
    drives aren't covered (Drive Activity's default scope is My Drive, and listing shared drives needs another
    scope). Edits count only for uploaded files: an edit to a Google Doc is typing, not an upload."""
    body = {"filter": f'time >= "{_iso(start)}" AND time <= "{_iso(end)}" AND detail.action_detail_case:(CREATE EDIT)',
            "pageSize": 100}
    out = []
    for _ in range(max_pages):
        page = http.post_json("https://driveactivity.googleapis.com/v2/activity:query", token, body)
        for act in page.get("activities", []):
            when = act.get("timestamp") or (act.get("timeRange") or {}).get("endTime")
            detail = act.get("primaryActionDetail") or {}
            if not when or not _own(act):
                continue
            create = detail.get("create")
            how = ("upload" if "upload" in create else "copy" if "copy" in create else "new") if create is not None \
                else "new version" if "edit" in detail else ""
            if not how:
                continue
            for target in act.get("targets", []):
                item = target.get("driveItem")
                if item is None:
                    continue
                kind = item.get("mimeType", "")
                if how == "new version" and kind.startswith("application/vnd.google-apps."):
                    continue
                out.append({"time": _ts(when), "how": how, "type": clean_type(kind), "title": item.get("title", "")})
        if not page.get("nextPageToken"):
            return out, True
        body["pageToken"] = page["nextPageToken"]
    return out, False


def youtube_uploads(http: Http, token: str, start: float, end: float) -> tuple[list[dict], bool]:
    """Videos added to the channel's uploads list between start and end (newest first; one page of 50)."""
    ch = http.get("https://www.googleapis.com/youtube/v3/channels", token, {"part": "contentDetails", "mine": "true"})
    items = ch.get("items") or []
    playlist = (((items[0] if items else {}).get("contentDetails") or {}).get("relatedPlaylists") or {}).get("uploads")
    if not playlist:
        return [], True   # the account has no channel, so no uploads
    page = http.get("https://www.googleapis.com/youtube/v3/playlistItems", token,
                    {"part": "snippet", "playlistId": playlist, "maxResults": 50})
    out, oldest = [], None
    for it in page.get("items", []):
        sn = it.get("snippet") or {}
        if not sn.get("publishedAt"):
            continue
        t = _ts(sn["publishedAt"])
        oldest = t if oldest is None else min(oldest, t)
        if start <= t <= end:
            out.append({"time": t, "type": "video", "title": sn.get("title", "")})
    # complete when the page reached back past the window, or there was nothing more to page through
    return out, not page.get("nextPageToken") or (oldest is not None and oldest < start)


def gmail_messages(http: Http, token: str, start: float, end: float) -> tuple[list[dict], bool]:
    """Sent and draft messages dated between start and end, with their sizes. The metadata scope can't search,
    so it walks each label from the newest, until GMAIL_PAST_START messages older than the window have gone by;
    nothing but the date and size is read. Hitting GMAIL_MAX_GETS first means the window wasn't reached."""
    base = "https://gmail.googleapis.com/gmail/v1/users/me/messages"
    out, complete = [], True
    for label in ("SENT", "DRAFT"):
        gets, older, page_token, reached = 0, 0, None, False
        while not reached:
            params = {"labelIds": label, "maxResults": 25, **({"pageToken": page_token} if page_token else {})}
            page = http.get(base, token, params)
            for m in page.get("messages", []):
                if gets >= GMAIL_MAX_GETS:
                    break
                msg = http.get(f"{base}/{m['id']}", token, {"format": "minimal"})
                gets += 1
                when = int(msg.get("internalDate") or 0) / 1000
                if when < start:
                    older += 1
                    if older >= GMAIL_PAST_START:
                        reached = True
                        break
                elif when <= end:
                    out.append({"time": when, "type": label.lower(), "bytes": int(msg.get("sizeEstimate") or 0)})
            page_token = page.get("nextPageToken")
            if reached or not page_token:
                break   # past the window, or the whole label was read
            if gets >= GMAIL_MAX_GETS:
                complete = False
                break
    return out, complete


# ---------------------------------------------------------------- the check

SOURCES = {"drive": drive_activity, "youtube": youtube_uploads, "gmail": gmail_messages}


def _services(cfg: dict, label: str, saved: dict) -> list[str]:
    have = granted(saved)
    for a in (cfg.get("account_check") or {}).get("google") or ():
        if isinstance(a, dict) and a.get("label") == label and a.get("services"):
            return [s for s in a["services"] if s in have]
    return have


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
                try:
                    rows, complete = SOURCES[service](http, token, start, end)
                    entry[service] = {"rows": rows, "complete": complete}
                except AccountError as e:
                    entry[service] = {"error": str(e)}
        except AccountError as e:
            entry = {"error": str(e)}
        result["accounts"][label] = entry
    return result


def managed_markers(zeek_dirs, host: str, start: float, end: float) -> list[str]:
    """The MANAGED_MARKERS that `host` looked up (dns.log) or connected to by name (ssl.log) between start and end,
    read with the case pages' evidence lookup. Empty when no Zeek logs are configured or found."""
    from . import evidence
    if not evidence.expand_dirs(zeek_dirs):
        return []
    found = evidence.lookup(zeek_dirs, host, (start + end) / 2, window=(end - start) / 2, limit=MARKER_ROWS,
                            kinds=("dns", "ssl"))
    names = {str(r.get(field) or "").lower().rstrip(".")
             for kind, field in (("dns", "query"), ("ssl", "server_name")) for r in found[kind]["rows"]}
    return [m for m in MANAGED_MARKERS if m in names]


def facts(result: dict, upload_bytes: float | None = None, markers: list[str] | None = None) -> dict:
    """What goes into the case: per account and service, counts, types, times and sizes; no titles. `outcome` is
    explained (something in the window that could account for the upload), unexplained (everything fully checked,
    nothing that could) or incomplete. Drive and YouTube give no sizes, so any file or video there could; Gmail gives
    sizes, so messages that add up to under SMALL_SHARE of the upload can't (#986: five small emails beside 1.5 GB). An
    unexplained outcome with managed-account `markers` (managed_markers) becomes possibly_managed_account."""
    out: dict = {"window": result["window"], "checked": round(time.time()), "accounts": {}}
    if upload_bytes:
        out["upload_mb"] = round(upload_bytes / 1e6)
    found, whole, mail_bytes, mail_rows = False, bool(result["accounts"]), 0, 0
    for label, entry in result["accounts"].items():
        if "error" in entry:
            out["accounts"][label] = {"error": entry["error"][:200]}
            whole = False
            continue
        acc = {}
        for service, res in entry.items():
            if "error" in res:
                acc[service] = {"error": res["error"][:200]}
                whole = False
                continue
            rows = res["rows"]
            s: dict = {"count": len(rows)}
            if not res["complete"]:
                s["complete"] = False
                whole = False
            if rows and service == "gmail":
                mail_rows += len(rows)
                mail_bytes += sum(r.get("bytes", 0) for r in rows)
            elif rows:
                found = True
            if rows:
                s["types"] = dict(Counter(r["type"] or "unknown" for r in rows).most_common(5))
                s["first"], s["last"] = round(min(r["time"] for r in rows)), round(max(r["time"] for r in rows))
                if any("bytes" in r for r in rows):
                    s["bytes"] = sum(r.get("bytes", 0) for r in rows)
            acc[service] = s
        if not acc:
            whole = False   # an account with no services granted checked nothing
        out["accounts"][label] = acc
    if mail_rows and (not upload_bytes or mail_bytes >= SMALL_SHARE * upload_bytes):
        found = True
    elif mail_rows:
        out["too_small"] = True   # there was mail in the window, far smaller than the upload
    out["outcome"] = "explained" if found else "unexplained" if whole else "incomplete"
    if out["outcome"] == "unexplained" and markers:
        out["outcome"], out["managed_markers"] = "possibly_managed_account", list(markers)
    return out


def _size(b: float) -> str:
    return f"{b / 1e6:.1f} MB" if b >= 1e6 else f"{max(1, round(b / 1e3))} KB"


def _hm(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%H:%M")


NOUNS = {"drive": ("file created or uploaded", "files created or uploaded"),
         "youtube": ("video uploaded", "videos uploaded"),
         "gmail": ("sent or draft message", "sent or draft messages")}
NAMES = {"drive": "Drive", "youtube": "YouTube", "gmail": "Gmail"}


def summary(f: dict) -> str:
    """One line per account, for the terminal, the case note and the skill: "personal: Drive shows 2 ..."."""
    w = f["window"]
    head = f"Account check {_hm(w[0])}-{_hm(w[1])} UTC: "
    if not f["accounts"]:
        return head + "incomplete: no Google accounts are set up (docs/setup/account-check.md)."
    lines = []
    for label, acc in f["accounts"].items():
        if "error" in acc:
            lines.append(f"{label}: couldn't check ({acc['error']})")
            continue
        parts = []
        for service, s in acc.items():
            name = NAMES[service]
            short = "" if s.get("complete", True) else " (stopped before covering the whole window)"
            if "error" in s:
                parts.append(f"{name} couldn't be checked ({s['error']})")
            elif not s["count"]:
                parts.append(f"{name} shows nothing{short}")
            else:
                n = s["count"]
                span = _hm(s["first"]) if s["first"] == s["last"] else f"{_hm(s['first'])}-{_hm(s['last'])}"
                types = ", ".join(f"{c} {t}" for t, c in s["types"].items())
                size = f", {_size(s['bytes'])}" if s.get("bytes") else ""
                parts.append(f"{name} shows {n} {NOUNS[service][n != 1]} at {span} UTC ({types}{size}){short}")
        lines.append(f"{label}: " + ("; ".join(parts) if parts else "no services granted"))
    lead = {"explained": "", "unexplained": "the accounts show nothing: unexplained. ",
            "incomplete": "incomplete, so this says nothing either way. "}.get(f["outcome"], "")
    if f["outcome"] == "possibly_managed_account":
        lead = (f"the accounts show nothing, but the device reached {', '.join(f['managed_markers'])}, which only a "
                "managed (work or school) Google account does: possibly_managed_account. That account may explain "
                "the upload, and this check can't see it. ")
    if f["outcome"] == "unexplained" and f.get("too_small"):
        up = f" the {f['upload_mb']} MB" if f.get("upload_mb") else " the"
        lead = f"nothing big enough to explain{up} upload: unexplained. "
    return head + lead + " | ".join(lines)
