"""Account check (accounts.py): Google sign-in, Drive/YouTube/Gmail parsing, what reaches the case. No network."""
import json
import stat
import urllib.parse
from datetime import datetime, timezone

import pytest

from tapwatch import accounts as acc
from tapwatch.models import Case, Route
from tapwatch.store import Store

T = datetime(2026, 10, 20, 23, 59, 59, tzinfo=timezone.utc).timestamp()   # an upload_spike case's stamp


def iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


class FakeHttp(acc.Http):
    """Answers by URL; records every call."""

    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def _answer(self, url, payload):
        self.calls.append((url, payload))
        for prefix, answer in self.routes.items():
            if url.startswith(prefix):
                return answer(url, payload) if callable(answer) else answer
        raise AssertionError(f"unexpected call {url}")

    def post_form(self, url, form):
        return self._answer(url, form)

    def post_json(self, url, token, body):
        assert token == "access-1"
        return self._answer(url, dict(body))

    def get(self, url, token, params):
        assert token == "access-1"
        return self._answer(url, params)


def test_google_upload_hosts():
    assert acc.google_upload_host("gcs-us-00003.content-storage-upload.googleapis.com")
    assert acc.google_upload_host("upload.youtube.com.")
    assert not acc.google_upload_host("content-storage-upload.googleapis.com.example.net")
    assert not acc.google_upload_host("www.googleapis.com") and not acc.google_upload_host("")


def test_consent_url_uses_pkce_and_read_only_scopes():
    url, verifier, state = acc.auth_request("client-1", ["drive", "gmail"])
    q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    assert q["code_challenge_method"] == ["S256"] and len(verifier) > 43 and q["state"] == [state]
    assert q["scope"][0].split() == [acc.SCOPES["drive"], acc.SCOPES["gmail"]]
    assert q["access_type"] == ["offline"] and q["redirect_uri"] == [acc.REDIRECT_URI]
    assert all("readonly" in s or s.endswith("metadata") for s in acc.SCOPES.values())


def test_the_pasted_address_must_belong_to_this_sign_in():
    assert acc.code_from_redirect(f"{acc.REDIRECT_URI}?state=s1&code=c-9&scope=x", "s1") == "c-9"
    assert acc.code_from_redirect("c-9", "s1") == "c-9"
    with pytest.raises(acc.AccountError, match="state"):
        acc.code_from_redirect(f"{acc.REDIRECT_URI}?state=other&code=c-9", "s1")
    with pytest.raises(acc.AccountError, match="access_denied"):
        acc.code_from_redirect(f"{acc.REDIRECT_URI}?error=access_denied&state=s1", "s1")


def test_tokens_are_private_files_under_a_label(tmp_path):
    d = tmp_path / "accounts"
    path = acc.save_token(d, "personal", {"refresh_token": "r-1", "scope": acc.SCOPES["drive"]})
    assert stat.S_IMODE(path.stat().st_mode) == 0o600 and stat.S_IMODE(d.stat().st_mode) == 0o700
    assert acc.load_token(d, "personal")["refresh_token"] == "r-1" and acc.saved_labels(d) == ["personal"]
    with pytest.raises(acc.AccountError):
        acc.save_token(d, "someone@example.com", {})          # labels, never addresses


ME = [{"user": {"knownUser": {"personName": "people/1", "isCurrentUser": True}}}]
OTHER = [{"user": {"knownUser": {"personName": "people/2"}}}]


def test_drive_activity_pages_reads_own_creates_and_new_versions():
    pages = iter([
        {"activities": [
            {"timestamp": iso(T - 900), "actors": ME, "primaryActionDetail": {"create": {"upload": {}}},
             "targets": [{"driveItem": {"title": "clip.mov", "mimeType": "video/quicktime"}}]},
            {"timestamp": iso(T - 800), "actors": OTHER, "primaryActionDetail": {"create": {"upload": {}}},
             "targets": [{"driveItem": {"title": "theirs.zip", "mimeType": "application/zip"}}]}],   # a collaborator
         "nextPageToken": "p2"},
        {"activities": [
            {"timeRange": {"endTime": iso(T - 300)}, "actors": ME, "primaryActionDetail": {"edit": {}},
             "targets": [{"driveItem": {"title": "big.pst", "mimeType": "application/vnd.ms-outlook"}},
                         {"driveItem": {"title": "doc", "mimeType": "application/vnd.google-apps.document"}}]},
            {"timestamp": iso(T - 200), "actors": ME, "primaryActionDetail": {"create": {"new": {}}},
             "targets": [{"driveItem": {"title": "x", "mimeType": "text/html<script>"}}, {"drive": {"name": "s"}}]}]},
    ])
    http = FakeHttp({"https://driveactivity": lambda url, body: next(pages)})
    rows, complete = acc.drive_activity(http, "access-1", T - 7200, T)
    assert complete and [(r["how"], r["type"]) for r in rows] == [
        ("upload", "video/quicktime"), ("new version", "application/vnd.ms-outlook"), ("new", "other")]
    first, second = http.calls[0][1], http.calls[1][1]
    assert "detail.action_detail_case:(CREATE EDIT)" in first["filter"] and "pageToken" not in first
    assert second["pageToken"] == "p2"
    endless = FakeHttp({"https://driveactivity": {"activities": [], "nextPageToken": "more"}})
    assert acc.drive_activity(endless, "access-1", T - 7200, T, max_pages=2) == ([], False)   # cut short


def test_youtube_without_a_channel_and_with_uploads():
    none = FakeHttp({"https://www.googleapis.com/youtube/v3/channels": {"items": [{"contentDetails": {}}]}})
    assert acc.youtube_uploads(none, "access-1", T - 7200, T) == ([], True)
    http = FakeHttp({
        "https://www.googleapis.com/youtube/v3/channels": {
            "items": [{"contentDetails": {"relatedPlaylists": {"uploads": "UU1"}}}]},
        "https://www.googleapis.com/youtube/v3/playlistItems": {"items": [
            {"snippet": {"publishedAt": iso(T - 600), "title": "a video"}},
            {"snippet": {"publishedAt": iso(T - 86400), "title": "yesterday"}}], "nextPageToken": "n"},
    })
    rows, complete = acc.youtube_uploads(http, "access-1", T - 7200, T)
    assert [r["title"] for r in rows] == ["a video"] and complete       # the page reached back past the window


def gmail(msgs, ids):
    return FakeHttp({
        "https://gmail.googleapis.com/gmail/v1/users/me/messages/": lambda url, p: {
            "internalDate": str(int(msgs[url.rsplit("/", 1)[1]] * 1000)), "sizeEstimate": 21_000_000},
        "https://gmail.googleapis.com/gmail/v1/users/me/messages": lambda url, p: ids(p),
    })


def test_gmail_walks_past_the_window_a_little_and_reads_dates_and_sizes_only():
    # m1 after the window; o1 an old message out of order before m2; o2..o6 older than the window
    msgs = {"m1": T + 600, "o1": T - 90000, "m2": T - 1200, "d1": T - 60,
            **{f"o{i}": T - 90000 - i for i in range(2, 7)}}
    order = ["m1", "o1", "m2"] + [f"o{i}" for i in range(2, 7)]
    http = gmail(msgs, lambda p: {"messages": [{"id": i} for i in (order if p["labelIds"] == "SENT" else ["d1"])]})
    rows, complete = acc.gmail_messages(http, "access-1", T - 7200, T)
    assert complete and [(r["type"], r["bytes"]) for r in rows] == [("sent", 21_000_000), ("draft", 21_000_000)]
    assert all(c[1].get("format") in (None, "minimal") for c in http.calls)   # never bodies or headers


def test_gmail_that_never_reaches_the_window_is_incomplete(monkeypatch):
    monkeypatch.setattr(acc, "GMAIL_MAX_GETS", 4)
    msgs = {f"n{i}": T + 86400 * 3 - i for i in range(10)}           # all newer than the window
    http = gmail(msgs, lambda p: {"messages": [{"id": f"n{i}"} for i in range(10)], "nextPageToken": "more"})
    assert acc.gmail_messages(http, "access-1", T - 7200, T) == ([], False)


def routes_for_one_upload():
    return {
        acc.TOKEN_URL: {"access_token": "access-1"},
        "https://driveactivity": {"activities": [{
            "timestamp": iso(T - 900), "actors": ME, "primaryActionDetail": {"create": {"upload": {}}},
            "targets": [{"driveItem": {"title": "private name.mp4", "mimeType": "video/mp4"}}]}]},
        "https://www.googleapis.com/youtube/v3/channels": {"items": []},
        "https://gmail.googleapis.com/gmail/v1/users/me/messages": {"messages": []},
    }


@pytest.fixture
def two_accounts(tmp_path, monkeypatch):
    monkeypatch.setenv("TAPWATCH_GOOGLE_CLIENT_ID", "client-1")
    monkeypatch.setenv("TAPWATCH_GOOGLE_CLIENT_SECRET", "secret-1")
    d = tmp_path / "accounts"
    acc.save_token(d, "personal", {"refresh_token": "r-1", "scope": " ".join(acc.SCOPES.values())})
    acc.save_token(d, "work", {"refresh_token": "r-2", "scope": acc.SCOPES["drive"]})
    return {"account_check": {"google": ["personal", {"label": "work", "services": ["drive", "gmail"]}],
                              "token_dir": str(d)}}


def test_check_uses_each_accounts_granted_services_and_keeps_names_out(two_accounts):
    result = acc.check(two_accounts, T - 9000, T + 1800, http=FakeHttp(routes_for_one_upload()))
    assert set(result["accounts"]["personal"]) == {"drive", "youtube", "gmail"}
    assert set(result["accounts"]["work"]) == {"drive"}          # gmail listed in config but never granted
    f = acc.facts(result)
    assert f["accounts"]["personal"]["drive"] == {"count": 1, "types": {"video/mp4": 1}, "first": round(T - 900),
                                                  "last": round(T - 900)}
    assert f["outcome"] == "explained" and "private name" not in json.dumps(f)
    text = acc.summary(f)
    assert "personal: Drive shows 1 file created or uploaded at 23:44 UTC (1 video/mp4)" in text
    assert "unexplained" not in text and "YouTube shows nothing" in text


def test_unexplained_only_when_everything_was_fully_checked(two_accounts, tmp_path):
    routes = routes_for_one_upload()
    routes["https://driveactivity"] = {"activities": []}
    f = acc.facts(acc.check(two_accounts, T - 9000, T + 1800, http=FakeHttp(routes)))
    assert f["outcome"] == "unexplained"
    assert acc.summary(f).startswith("Account check 21:29-00:29 UTC: the accounts show nothing: unexplained.")
    # one service failing makes it incomplete, not unexplained (review of #293)
    failing = FakeHttp(routes)
    failing.routes = {"https://gmail": lambda url, p: (_ for _ in ()).throw(acc.AccountError("HTTP 403")), **routes}
    f = acc.facts(acc.check(two_accounts, T - 9000, T + 1800, http=failing))
    assert f["outcome"] == "incomplete" and "says nothing either way" in acc.summary(f)
    # no accounts at all
    f = acc.facts(acc.check({"account_check": {"token_dir": str(tmp_path / "none")}}, T - 9000, T + 1800,
                            http=FakeHttp(routes)))
    assert f["outcome"] == "incomplete" and "no Google accounts are set up" in acc.summary(f)


def test_an_expired_sign_in_says_so(two_accounts):
    routes = routes_for_one_upload()
    def refused(url, form):
        raise acc.AccountError(f'{url}: HTTP 400 {{"error": "invalid_grant"}}')   # what Google sends
    routes[acc.TOKEN_URL] = refused
    f = acc.facts(acc.check(two_accounts, T - 9000, T + 1800, http=FakeHttp(routes)))
    assert f["outcome"] == "incomplete" and "7 days" in f["accounts"]["personal"]["error"]


def test_network_failures_become_account_errors_and_redirects_are_refused(monkeypatch):
    import urllib.error

    class Opener:
        def __init__(self, exc):
            self.exc = exc

        def open(self, req, timeout):
            raise self.exc

    for exc in (urllib.error.URLError("no route"), TimeoutError("slow"), ValueError("not json")):
        monkeypatch.setattr(acc, "_OPENER", Opener(exc))
        with pytest.raises(acc.AccountError):
            acc.Http().get("https://gmail.googleapis.com/gmail/v1/users/me/messages", "t", {})
    with pytest.raises(acc.AccountError, match="not a Google API host"):
        acc.Http().get("https://example.com/x", "t", {})
    assert acc._NoRedirect().redirect_request(None, None, 302, "", {}, "https://example.com/") is None


def test_the_cli_checks_google_uploads_only_and_saves_counts(tmp_path, two_accounts, monkeypatch, capsys):
    from tapwatch import cli
    db = str(tmp_path / "t.db")
    store = Store(db)
    up = store.add(Case("upload_spike", "192.168.50.23", T, "Upload spike", {"mb": 1577},
                        ["gcs-us-00003.content-storage-upload.googleapis.com"]), "new", None, Route.DIGEST, "test")
    other = store.add(Case("upload_spike", "192.168.50.23", T, "Upload spike", {"mb": 900},
                           ["backup.example.net"]), "new", None, Route.DIGEST, "test")
    monkeypatch.setattr(acc, "Http", lambda: FakeHttp(routes_for_one_upload()))
    cfg = {**two_accounts, "db_path": db}
    monkeypatch.setattr(cli.config, "load", lambda path: cfg)
    assert cli.main(["account-check", str(other)]) == 1
    assert cli.main(["account-check", str(up), "--window", "-5"]) == 2
    assert cli.main(["account-check", str(up), "--save"]) == 0
    saved = json.loads(Store(db).get(up)["facts"])["account_check"]
    assert saved["accounts"]["personal"]["drive"]["count"] == 1 and "private name" not in json.dumps(saved)
    assert Store(db).notes(up)[-1]["text"].startswith("Account check")
    assert "private name" not in capsys.readouterr().out          # titles only with --names
    assert cli.main(["account-check", str(up), "--names"]) == 0 and "private name.mp4" in capsys.readouterr().out
