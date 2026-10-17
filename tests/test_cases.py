"""Case management: migration, workflow, suppressions, evidence and the web UI's security."""

import html
import http.client
import json
import re
import sqlite3
import threading
from urllib.parse import urlencode

import pytest
from conftest import T0, conn, dns, jev_response, ssl, write_logs

from tapwatch import evidence, ui
from tapwatch.detectors import Beaconing, IOCMatch, NewDevice, Warmup
from tapwatch.models import Case, Route
from tapwatch.pipeline import Pipeline, alert_item
from tapwatch.router import route
from tapwatch.store import SCHEMA, Store, WorkflowError
from tapwatch.summarizer import Assets

PAYLOADS = ["<script>alert(1)</script>.evil.example", '"><img src=x onerror=alert(1)>', "javascript:alert(1)"]


def make_case(store, detector="beaconing", host="192.168.50.10", indicators=None, facts=None, must_alert=False,
              route_=Route.ALERT, verdict=None):
    case = Case(detector, host, T0, "Regular repeating connection to an external host",
                facts if facts is not None else {"port": 3478, "dedupe": "port:3478"},
                indicators or [], must_alert=must_alert)
    return store.add(case, "state text", verdict, route_, "test"), case


# ------------------------------------------------------------------ migration

def test_migration_adds_columns_to_an_old_database_and_keeps_rows(tmp_path):
    path = tmp_path / "old.db"
    old = sqlite3.connect(path)
    old.executescript(SCHEMA)  # the schema before case management
    old.execute("INSERT INTO cases (key, first_ts, last_ts, detector, host, title, facts, indicators, must_alert,"
                " state, route, reason, feedback) VALUES ('k', 1, 1, 'scan', 'h', 't', '{}', '[]', 0, 's', 'alert',"
                " 'r', 'fp')")
    old.commit()

    store = Store(str(path))
    row = store.get(1)
    assert row["status"] == "new" and row["disposition"] == "false_positive"  # old `mark fp` carried over
    for table in ("notes", "audit", "suppressions"):
        store.db.execute(f"SELECT * FROM {table}")
    # The old code's INSERT (without the new columns) still works on the migrated database.
    old.execute("INSERT INTO cases (key, first_ts, last_ts, detector, host, title, facts, indicators, must_alert,"
                " state, route, reason) VALUES ('k2', 2, 2, 'scan', 'h', 't', '{}', '[]', 0, 's', 'log', 'r')")
    old.commit()
    assert store.get(2)["status"] == "new"
    Store(str(path))  # running it again is harmless


# ------------------------------------------------------------------ workflow

def test_status_moves_and_disposition_rules():
    store = Store(":memory:")
    cid, _ = make_case(store)
    with pytest.raises(WorkflowError, match="disposition"):
        store.update_case(cid, "t", status="closed")  # can't close without saying what it was
    assert store.update_case(cid, "t", status="investigating") == ["status"]
    with pytest.raises(WorkflowError):
        store.update_case(cid, "t", status="new")  # no going back to new
    with pytest.raises(WorkflowError):
        store.update_case(cid, "t", disposition="maybe")
    store.update_case(cid, "t", status="closed", disposition="benign_expected", note="STUN for video calls")
    row = store.get(cid)
    assert (row["status"], row["disposition"], row["feedback"]) == ("closed", "benign_expected", "fp")
    store.update_case(cid, "t", status="investigating")  # reopen
    trail = [(a["action"], a["old"], a["new"]) for a in store.audit_trail(cid)]
    assert trail == [("status", "new", "investigating"), ("disposition", None, "benign_expected"),
                     ("status", "investigating", "closed"), ("note", None, "STUN for video calls"),
                     ("status", "closed", "investigating")]
    assert [n["text"] for n in store.notes(cid)] == ["STUN for video calls"]


def test_failed_update_changes_nothing():
    store = Store(":memory:")
    cid, _ = make_case(store)
    with pytest.raises(WorkflowError):
        store.update_case(cid, "t", status="investigating", disposition="maybe", note="x")
    assert store.get(cid)["status"] == "new" and store.audit_trail(cid) == [] and store.notes(cid) == []


def test_mark_maps_onto_disposition_and_closes():
    store = Store(":memory:")
    cid, _ = make_case(store)
    assert store.set_feedback(cid, "tp")
    row = store.get(cid)
    assert (row["feedback"], row["disposition"], row["status"]) == ("tp", "true_positive", "closed")
    assert store.set_feedback(cid, "fp")  # relabelling a closed case is fine
    assert store.get(cid)["disposition"] == "false_positive"
    assert not store.set_feedback(999, "fp")


# ------------------------------------------------------------------ suppressions

def test_suppression_scopes_match_what_they_say():
    store = Store(":memory:")
    cid, _ = make_case(store, detector="new_domain", indicators=["cdn.example.com"], facts={})
    store.add_suppression(cid, "device_indicator", "my laptop's CDN", "t")
    same = Case("new_domain", "192.168.50.10", T0, "t", {}, ["cdn.example.com"])
    other_device = Case("new_domain", "192.168.50.11", T0, "t", {}, ["cdn.example.com"])
    other_detector = Case("dns_anomaly", "192.168.50.10", T0, "t", {}, ["cdn.example.com"])
    assert store.match_suppression(same).startswith("#1 new_domain")
    assert store.match_suppression(other_device) is None
    assert store.match_suppression(other_detector) is None

    store.add_suppression(cid, "indicator", "everyone uses it", "t")
    assert store.match_suppression(other_device).startswith("#2")

    pid, _ = make_case(store)  # beaconing on port 3478
    store.add_suppression(pid, "port", "STUN", "t")
    assert store.match_suppression(Case("beaconing", "192.168.50.99", T0, "t", {"port": 3478}))
    assert store.match_suppression(Case("beaconing", "192.168.50.99", T0, "t", {"port": 443})) is None
    assert [s["hits"] for s in store.suppressions()] == [1, 1, 1]

    # domain scopes: the registrable domain, so a sibling host (zone-02 after zone-01) matches too
    did, _ = make_case(store, detector="odd_port", indicators=["ch-zone-01.mgmt.example.net"], facts={"port": 17472})
    store.add_suppression(did, "device_domain", "zone servers, this laptop", "t")
    assert store.suppressions()[0]["indicator"] == "example.net"
    sibling = Case("odd_port", "192.168.50.10", T0, "t", {}, ["ch-zone-02.mgmt.example.net"])
    assert store.match_suppression(sibling).startswith("#4 odd_port (192.168.50.10, any host under example.net)")
    assert store.match_suppression(Case("odd_port", "192.168.50.11", T0, "t", {}, ["ch-zone-02.mgmt.example.net"])) is None
    assert store.match_suppression(Case("odd_port", "192.168.50.10", T0, "t", {}, ["example.org"])) is None
    uk, _ = make_case(store, detector="odd_port", indicators=["www.bbc.co.uk"], facts={"port": 1})
    store.add_suppression(uk, "domain", "the BBC", "t")
    assert store.suppressions()[0]["indicator"] == "bbc.co.uk"           # not co.uk
    assert store.match_suppression(Case("odd_port", "192.168.50.99", T0, "t", {}, ["news.bbc.co.uk"])).startswith("#5")
    assert store.match_suppression(Case("odd_port", "192.168.50.99", T0, "t", {}, ["itv.co.uk"])) is None


def test_suppress_form_names_the_device_identity_the_rule_will_follow():
    # The rule is keyed on models.device_id (DHCP hostname, then MAC, then IP), so the label shows that
    # identity next to the address when they differ, and only the address when the IP is the identity.
    store = Store(":memory:")
    named, _ = make_case(store, detector="odd_port", host="192.168.50.19", indicators=["ch-zone-01.mgmt.example.net"],
                         facts={"device_name": "Office-PC", "device_mac": "00:00:5e:00:53:19", "port": 8443})
    html = ui._suppress_form(store.get(named), {"device_name": "Office-PC", "device_mac": "00:00:5e:00:53:19", "port": 8443},
                             ["ch-zone-01.mgmt.example.net"], "csrf")
    assert "odd_port + this device (name:office-pc, 192.168.50.19) + ch-zone-01.mgmt.example.net" in html
    assert "this device (name:office-pc, 192.168.50.19) + any host under example.net" in html
    assert "this device (192.168.50.19)" not in html
    assert "odd_port + ch-zone-01.mgmt.example.net, any device" in html  # device-less scopes are unchanged

    by_mac, _ = make_case(store, host="192.168.50.20", indicators=["x.example.com"],
                          facts={"device_mac": "00:00:5E:00:53:20", "port": 3478})
    html = ui._suppress_form(store.get(by_mac), {"device_mac": "00:00:5E:00:53:20", "port": 3478}, ["x.example.com"], "c")
    assert "this device (mac:00:00:5e:00:53:20, 192.168.50.20)" in html

    plain, _ = make_case(store, host="192.168.50.21", indicators=["x.example.com"], facts={"port": 3478})
    html = ui._suppress_form(store.get(plain), {"port": 3478}, ["x.example.com"], "c")
    assert "this device (192.168.50.21) + x.example.com" in html and "name:" not in html and "mac:" not in html


def test_expired_suppressions_stop_matching():
    store = Store(":memory:")
    cid, case = make_case(store)
    store.add_suppression(cid, "port", "for now", "t", expires_ts=T0 + 100)
    assert store.match_suppression(case, now=T0)
    assert store.match_suppression(case, now=T0 + 101) is None


def test_suppression_needs_reason_and_a_real_scope():
    store = Store(":memory:")
    cid, _ = make_case(store)
    with pytest.raises(WorkflowError, match="reason"):
        store.add_suppression(cid, "port", "  ", "t")
    with pytest.raises(WorkflowError):
        store.add_suppression(cid, "everything", "x", "t")
    nid, _ = make_case(store, facts={})  # no port, no indicator
    with pytest.raises(WorkflowError):
        store.add_suppression(nid, "port", "x", "t")


def test_must_alert_cases_can_never_be_suppressed():
    store = Store(":memory:")
    cid, _ = make_case(store, detector="ioc_match", indicators=["bad.example"], facts={"port": 443},
                       must_alert=True)
    with pytest.raises(WorkflowError, match="can't be suppressed"):
        store.add_suppression(cid, "indicator", "x", "t")
    # Even a rule made some other way (here: straight into the table) can't silence one.
    store.db.execute("INSERT INTO suppressions (scope, detector, indicator, port, reason, created_ts)"
                     " VALUES ('indicator', 'ioc_match', 'bad.example', NULL, 'x', 0),"
                     " ('port', 'ioc_match', NULL, 443, 'x', 0)")
    ioc = Case("ioc_match", "192.168.50.10", T0, "t", {"port": 443}, ["bad.example"], must_alert=True)
    assert store.match_suppression(ioc) is None
    assert route(ioc, None, suppression="#1 anything") == (Route.ALERT, "always-alert rule")


def test_pipeline_logs_suppressed_cases_without_asking_ai_or_alerting(fake_jev):
    class Recorder:
        def __init__(self):
            self.sent = []

        def send(self, title, items):
            self.sent.append(title)

    store = Store(":memory:")
    cid, _ = make_case(store, host="192.168.50.99", facts={"port": 443, "dedupe": "port:443"})
    store.add_suppression(cid, "port", "update checker", "t")  # made on another device, applies to any
    jev = fake_jev(jev_response("c2_beaconing", conf=0.9, severity=3.3, routine=0.0, page=0.9))
    note = Recorder()
    p = Pipeline([Beaconing(), IOCMatch({"203.0.113.5"}, set())], Assets(), store, client=jev, notifier=note)
    out = []
    for i in range(15):
        out += p.process(conn(T0 + i * 60))
    by_detector = {c.detector: (r, store.get(i)["reason"]) for i, c, _, r in out}
    assert by_detector["beaconing"] == (Route.LOG, "suppressed: #1 beaconing (any device, port 443)")
    assert by_detector["ioc_match"][0] is Route.ALERT
    assert jev.states == []
    assert len(note.sent) == 1
    sup_id = next(i for i, c, _, _ in out if c.detector == "beaconing")
    row = store.get(sup_id)
    assert (row["status"], row["disposition"]) == ("closed", "benign_expected")   # arrives closed, not queued
    assert store.notes(sup_id)[0]["text"].startswith("closed on arrival: matched suppression #1")


# ------------------------------------------------------------------ email links

def test_alert_and_digest_link_to_the_case_page():
    item = alert_item(Case("scan", "192.168.50.10", T0, "t", {}), None, "r", Assets(), 7, "http://127.0.0.1:8765/")
    assert item["facts"]["Open"] == "http://127.0.0.1:8765/case/7"

    class Recorder:
        def send(self, title, items):
            self.items = items

    store, note = Store(":memory:"), Recorder()
    make_case(store, route_=Route.DIGEST)
    Pipeline([], Assets(), store, notifier=note, base_url="http://box:8765").send_digest()
    assert note.items[0]["facts"]["Case"] == "http://box:8765/case/1"


# ------------------------------------------------------------------ evidence

def test_evidence_finds_device_rows_in_window(tmp_path):
    host, other = "192.168.50.10", "192.168.50.11"
    conns = [conn(T0 + i, src=host if i % 2 else other) for i in range(-2000, 2000, 7)]
    write_logs(tmp_path, conn=conns, dns=[dns(T0 + 10, "a.example"), dns(T0 + 400, "late.example")],
               ssl=[ssl(T0 - 60, "s.example")])
    found = evidence.lookup([str(tmp_path)], host, T0, window=300, limit=1000)
    times = [r["ts"] for r in found["conn"]["rows"]]
    assert times and all(T0 - 300 <= t <= T0 + 300 for t in times)
    assert {r["id.orig_h"] for r in found["conn"]["rows"]} == {host}
    assert len(times) == len([c for c in conns if c["id.orig_h"] == host and abs(c["ts"] - T0) <= 300])
    assert [r["query"] for r in found["dns"]["rows"]] == ["a.example"]
    assert [r["server_name"] for r in found["ssl"]["rows"]] == ["s.example"]


def test_evidence_caps_rows_and_does_not_read_the_whole_file(tmp_path, monkeypatch):
    host = "192.168.50.10"
    with open(tmp_path / "conn.log", "w") as fh:  # ~ 40 MB-equivalent spread: 200k rows over 2 days
        fh.writelines(json.dumps({"ts": T0 - 86400 + i, "id.orig_h": host, "id.resp_h": "203.0.113.5"}) + "\n" for i in range(200_000))
    parsed = 0
    real = json.loads

    def counting(s, *a, **k):
        nonlocal parsed
        parsed += 1
        return real(s, *a, **k)

    monkeypatch.setattr(evidence.json, "loads", counting)
    found = evidence.lookup([str(tmp_path)], host, T0, limit=50)
    assert len(found["conn"]["rows"]) == 50 and found["conn"]["more"]
    assert found["conn"]["rows"][0]["ts"] == T0 - 300
    assert parsed < 20_000  # binary search jumped close; nowhere near 200k lines


def test_evidence_dirs_accept_globs(tmp_path):
    (tmp_path / "cap-1").mkdir()
    (tmp_path / "cap-2").mkdir()
    write_logs(tmp_path / "cap-2", conn=[conn(T0)])
    assert len(evidence.lookup([str(tmp_path / "cap-*")], "192.168.50.10", T0)["conn"]["rows"]) == 1


# ------------------------------------------------------------------ rendering: hostile strings

def hostile_store():
    store = Store(":memory:")
    verdict = {"category": "<b>c2</b>", "category_confidence": 0.9, "severity": 3.0, "severity_confidence": 0.8,
               "routine": 0.1, "page_admin": 0.9, "model": "jev"}

    cid = store.add(Case("new_domain", "192.168.50.10", T0, "New domains", {"note": PAYLOADS[1]}, PAYLOADS),
                    f"Names seen: {PAYLOADS[0]}", None, Route.DIGEST, "test")
    store.db.execute("UPDATE cases SET verdict=? WHERE id=?", (json.dumps(verdict), cid))
    store.update_case(cid, "t", note=PAYLOADS[1])
    store.add_suppression(cid, "indicator", PAYLOADS[0], "t")
    return store, cid


def assert_inert(page: str):
    assert "<script" not in page.lower()
    assert "<img" not in page.lower()
    assert not re.search(r"""(href|src|action)\s*=\s*["']?\s*javascript:""", page, re.IGNORECASE)
    assert '"><img' not in page


def test_hostile_strings_are_escaped_on_every_page(tmp_path):
    store, cid = hostile_store()
    write_logs(tmp_path, dns=[dns(T0, PAYLOADS[0])], ssl=[ssl(T0, PAYLOADS[1])])
    pages = [
        ui.render_queue(store, Assets(), {}, "tok")[1],
        ui.render_case(store, Assets(), cid, [str(tmp_path)], "tok")[1],
        ui.render_suppressions(store, "tok")[1],
        ui.render_stats(store)[1],
    ]
    case_page = pages[1]
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in case_page  # shown, but as text
    assert "&quot;&gt;&lt;img src=x onerror=alert(1)&gt;" in case_page
    assert PAYLOADS[0].replace("<", "&lt;").replace(">", "&gt;") in case_page  # evidence table too
    for p in pages:
        assert_inert(p)
    # Untrusted strings never become links: every href is one of ours.
    for p in pages:
        for href in re.findall(r'href="([^"]*)"', p):
            assert href.startswith("/"), href


def test_stats_tiles_open_the_cases_they_count(tmp_path):
    store = Store(str(tmp_path / "t.db"))
    for i, (disposition, verdict) in enumerate((("true_positive", '{"category": "x"}'), ("false_positive", None),
                                                ("benign_expected", None), (None, '{"category": "y"}'), (None, None))):
        cid, _ = make_case(store, facts={"port": 3478 + i, "dedupe": f"port:{3478 + i}"})
        store.db.execute("UPDATE cases SET disposition = ?, verdict = ?, status = 'closed' WHERE id = ?",
                         (disposition, verdict, cid))
    store.db.commit()
    page = ui.render_stats(store)[1]
    for href in ("/?status=all&route=all", "/?status=all&route=all&disposition=decided",
                 "/?status=all&route=all&disposition=noise", "/?status=all&route=all&disposition=true_positive",
                 "/?status=all&route=all&triaged=1", "/suppressions"):
        assert f'href="{html.escape(href)}"' in page, href

    def count(**params):
        text = ui.render_queue(store, Assets(), {k: [v] for k, v in params.items()}, "tok")[1]
        return text.count('href="/case/')

    assert count(status="all", route="all") == 10          # two links per row: the id and the title
    assert count(status="all", route="all", disposition="decided") == 6
    assert count(status="all", route="all", disposition="noise") == 4
    assert count(status="all", route="all", disposition="true_positive") == 2
    assert count(status="all", route="all", triaged="1") == 4
    assert count(status="all", route="all", disposition="junk", triaged="yes") == 10   # unknown values fall away
    page = ui.render_queue(store, Assets(), {"status": ["all"], "route": ["all"], "disposition": ["noise"]}, "tok")[1]
    assert "false positive or benign ×" in page   # the bucket shows as a pill that removes itself
    assert 'name="disposition" value="noise"' in page   # and Apply keeps it
    page = ui.render_queue(store, Assets(), {"status": ["all"], "route": ["all"], "triaged": ["1"]}, "tok")[1]
    assert "Jev triaged ×" in page and 'name="triaged" value="1"' in page
    assert 'href="/?status=all&amp;route=all&amp;detector=beaconing"' in ui.render_stats(store)[1]  # the table too


def test_queue_filters_ignore_junk_and_stay_escaped():
    store, _ = hostile_store()
    page = ui.render_queue(store, Assets(), {"status": ['"><script>'], "device": ['"><img onerror=x>'],
                                             "sort": ["id; DROP TABLE cases"], "disposition": ['"><script>'],
                                             "triaged": ['"><img onerror=x>']}, "tok")[1]
    assert_inert(page)
    assert store.db.execute("SELECT COUNT(*) FROM cases").fetchone()[0] == 1


# ------------------------------------------------------------------ live server: CSRF, auth, headers

@pytest.fixture
def server(tmp_path):
    def start(token=None, host="127.0.0.1", tailscale_users=None, base_url=None):
        db = str(tmp_path / "t.db")
        store = Store(db)
        make_case(store, indicators=["cdn.example.com"])
        store.db.close()
        app = ui.App(db, Assets(), host=host, port=0, token=token, tailscale_users=tailscale_users,
                     base_url=base_url)
        srv = ui.make_server(app)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        started.append(srv)
        return app, db

    started = []
    yield start
    for s in started:
        s.shutdown()
        s.server_close()


def request(app, method, path, body=None, cookie=None, host=None, origin=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", app.port, timeout=5)
    headers = {"Host": host or f"127.0.0.1:{app.port}", **(headers or {})}
    if cookie:
        headers["Cookie"] = f"{ui.COOKIE}={cookie}"
    if origin:
        headers["Origin"] = origin
    data = None
    if body is not None:
        data = urlencode(body, doseq=True)
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    c.request(method, path, body=data, headers=headers)
    r = c.getresponse()
    text = r.read().decode()
    c.close()
    return r, text


def session(app):
    """GET a page to receive a session cookie and the CSRF token in its forms."""
    r, text = request(app, "GET", "/case/1")
    sid = re.search(rf"{ui.COOKIE}=([^;]+)", r.getheader("Set-Cookie")).group(1)
    return sid, re.search(r'name="csrf" value="([^"]+)"', text).group(1)


def test_pages_send_strict_security_headers(server):
    app, _ = server()
    r, _ = request(app, "GET", "/")
    csp = r.getheader("Content-Security-Policy")
    assert "default-src 'none'" in csp and "script-src" not in csp and "'unsafe-inline'" not in csp
    assert "frame-ancestors 'none'" in csp and "form-action 'self'" in csp
    assert r.getheader("X-Content-Type-Options") == "nosniff"
    assert "HttpOnly" in r.getheader("Set-Cookie") and "SameSite" in r.getheader("Set-Cookie")


def test_post_needs_a_valid_csrf_token(server):
    app, db = server()
    sid, csrf = session(app)
    form = {"status": "investigating", "disposition": "", "note": ""}
    assert request(app, "POST", "/case/1/update", form, cookie=sid)[0].status == 403            # no token
    assert request(app, "POST", "/case/1/update", {**form, "csrf": "0" * 64}, cookie=sid)[0].status == 403
    assert request(app, "POST", "/case/1/update", {**form, "csrf": csrf})[0].status == 403      # no cookie
    other_sid, _ = session(app)
    assert request(app, "POST", "/case/1/update", {**form, "csrf": csrf}, cookie=other_sid)[0].status == 403
    assert request(app, "POST", "/case/1/update", {**form, "csrf": csrf}, cookie=sid,
                   origin="http://evil.example")[0].status == 403
    assert Store(db).get(1)["status"] == "new"
    r, _ = request(app, "POST", "/case/1/update", {**form, "csrf": csrf}, cookie=sid)
    assert r.status == 303 and Store(db).get(1)["status"] == "investigating"


def test_get_never_changes_anything(server):
    app, db = server()
    request(app, "GET", "/case/1/update?status=investigating")
    request(app, "GET", "/suppressions/1/delete")
    assert Store(db).get(1)["status"] == "new"


def test_suppress_and_delete_through_the_ui(server):
    app, db = server()
    sid, csrf = session(app)
    r, _ = request(app, "POST", "/case/1/suppress", {"csrf": csrf, "scope": "port", "reason": "STUN", "days": "7"},
                   cookie=sid)
    assert r.status == 303
    rule = Store(db).suppressions()[0]
    assert rule["port"] == 3478 and rule["expires_ts"] is not None
    assert Store(db).get(1)["status"] == "new"                              # no "close" box ticked
    request(app, "POST", "/case/1/suppress", {"csrf": csrf, "scope": "port", "reason": "STUN", "close": "1"}, cookie=sid)
    closed = Store(db).get(1)
    assert (closed["status"], closed["disposition"]) == ("closed", "benign_expected")
    request(app, "POST", f"/suppressions/{Store(db).suppressions()[0]['id']}/delete", {"csrf": csrf}, cookie=sid)
    r, text = request(app, "POST", "/case/1/suppress", {"csrf": csrf, "scope": "port", "reason": ""}, cookie=sid)
    assert r.status == 400 and "reason" in text
    request(app, "POST", f"/suppressions/{rule['id']}/delete", {"csrf": csrf}, cookie=sid)
    assert Store(db).suppressions() == []


def test_bulk_close(server):
    app, db = server()
    store = Store(db)
    make_case(store)
    sid, csrf = session(app)
    r, _ = request(app, "POST", "/bulk", {"csrf": csrf, "ids": ["1", "2"], "disposition": "false_positive",
                                          "note": "storm"}, cookie=sid)
    assert r.status == 303
    assert [(c["status"], c["disposition"]) for c in store.db.execute("SELECT * FROM cases")] == \
        [("closed", "false_positive")] * 2


def test_localhost_rejects_other_host_headers(server):
    app, _ = server()
    assert request(app, "GET", "/", host="attacker.example:8765")[0].status == 421  # DNS rebinding


def test_lan_mode_requires_a_token(server):
    with pytest.raises(SystemExit):
        ui.App(":memory:", Assets(), host="0.0.0.0")
    with pytest.raises(SystemExit):
        ui.App(":memory:", Assets(), host="0.0.0.0", token="short")


def test_token_login_flow(server):
    token = "a-long-test-token-123"
    app, _ = server(token=token)
    r, _ = request(app, "GET", "/")
    assert r.status == 303 and r.getheader("Location") == "/login"
    r, text = request(app, "GET", "/login")
    pre = re.search(rf"{ui.COOKIE}=([^;]+)", r.getheader("Set-Cookie")).group(1)
    csrf = re.search(r'name="csrf" value="([^"]+)"', text).group(1)
    r, text = request(app, "POST", "/login", {"csrf": csrf, "token": token})  # CSRF on login too:
    cookie = re.search(rf"{ui.COOKIE}=([^;]+)", r.getheader("Set-Cookie") or "")
    assert r.status == 200 and "expired" in text and not (cookie and app.session_ok(cookie.group(1)))  # form again, no login
    r, _ = request(app, "POST", "/login", {"csrf": csrf, "token": "wrong-wrong-wrong"}, cookie=pre)
    assert r.status == 401
    assert request(app, "GET", "/case/1", cookie=pre)[0].status == 303  # pre-login cookie isn't a session
    r, _ = request(app, "POST", "/login", {"csrf": csrf, "token": token}, cookie=pre)
    sid = re.search(rf"{ui.COOKIE}=([^;]+)", r.getheader("Set-Cookie")).group(1)
    assert r.status == 303 and sid != pre
    r, text = request(app, "GET", "/case/1", cookie=sid)
    assert r.status == 200
    csrf = re.search(r'name="csrf" value="([^"]+)"', text).group(1)
    request(app, "POST", "/logout", {"csrf": csrf}, cookie=sid)
    assert request(app, "GET", "/case/1", cookie=sid)[0].status == 303


def test_favicon_never_hands_out_a_session(server):
    app, _ = server(token="abcde-fghij-klmno-pqrst", host="0.0.0.0")
    r, _ = request(app, "GET", "/favicon.ico")
    assert r.status == 204 and r.getheader("Set-Cookie") is None


def test_login_survives_the_favicon_race(server):
    """Login page sets cookie A, a cookie-less favicon used to set cookie B over it, and the
    form's CSRF (for A) then failed with a dead-end 403. Now: no B, and a stale form re-renders."""
    tok = "abcde-fghij-klmno-pqrst"
    app, _ = server(token=tok, host="0.0.0.0")
    r, text = request(app, "GET", "/login")
    sid_a = re.search(rf"{ui.COOKIE}=([^;]+)", r.getheader("Set-Cookie")).group(1)
    csrf_a = re.search(r'name="csrf" value="([^"]+)"', text).group(1)
    other = re.search(rf"{ui.COOKIE}=([^;]+)", request(app, "GET", "/login")[0].getheader("Set-Cookie")).group(1)
    r, text = request(app, "POST", "/login", {"csrf": csrf_a, "token": tok}, cookie=other)  # stale form
    assert r.status == 200 and "expired" in text and "Set-Cookie" not in dict(r.getheaders())
    csrf_b = re.search(r'name="csrf" value="([^"]+)"', text).group(1)
    r, _ = request(app, "POST", "/login", {"csrf": csrf_b, "token": tok}, cookie=other)
    assert r.status == 303 and app.session_ok(re.search(rf"{ui.COOKIE}=([^;]+)", r.getheader("Set-Cookie")).group(1))
    r, _ = request(app, "POST", "/login", {"csrf": csrf_a, "token": tok}, cookie=sid_a)
    assert r.status == 303  # the original, unraced flow still works


# ------------------------------------------------------------------ behind `tailscale serve`

TS_HOST = "desk.tailnet-example.ts.net"


def ts(login):
    return {"Tailscale-User-Login": login}


def test_tailscale_mode_admits_only_listed_tailnet_users(server):
    app, _ = server(token="abcde-fghij-klmno-pqrst", tailscale_users=["Owner@example.com"],
                    base_url=f"https://{TS_HOST}")
    assert app.token is None                                     # Tailscale replaces the token login
    r, _ = request(app, "GET", "/", host=TS_HOST, headers=ts("owner@example.com"))
    assert r.status == 200
    for headers in ({}, ts("someone-else@example.com"), ts("")):
        r, _ = request(app, "GET", "/", host=TS_HOST, headers=headers)
        assert r.status == 403                                   # no identity, or not on the list
    r, _ = request(app, "GET", "/")                              # straight to the port: no side door
    assert r.status == 403
    r, _ = request(app, "GET", "/", host="evil.example", headers=ts("owner@example.com"))
    assert r.status == 421                                       # Host check still applies


def test_tailscale_mode_records_the_login_and_still_checks_csrf(server):
    app, db = server(tailscale_users=["owner@example.com"], base_url=f"https://{TS_HOST}")
    who = ts("owner@example.com")
    r, text = request(app, "GET", "/case/1", host=TS_HOST, headers=who)
    sid = re.search(rf"{ui.COOKIE}=([^;]+)", r.getheader("Set-Cookie")).group(1)
    csrf = re.search(r'name="csrf" value="([^"]+)"', text).group(1)
    r, _ = request(app, "POST", "/case/1/update", {"status": "investigating"}, cookie=sid, host=TS_HOST,
                   headers=who)
    assert r.status == 403                                       # identity isn't a CSRF token
    r, _ = request(app, "POST", "/case/1/update", {"csrf": csrf, "status": "investigating"}, cookie=sid,
                   host=TS_HOST, headers=who)
    assert r.status == 303
    actors = [row[0] for row in sqlite3.connect(db).execute("SELECT actor FROM audit")]
    assert actors and all(a == "ui owner@example.com" for a in actors)


def test_tailscale_mode_refuses_a_non_loopback_listener(tmp_path):
    with pytest.raises(SystemExit):
        ui.App(str(tmp_path / "t.db"), Assets(), host="0.0.0.0", token="abcde-fghij-klmno-pqrst",
               tailscale_users=["owner@example.com"])


def test_queue_names_the_severity_level_next_to_the_score(tmp_path):
    from tapwatch.models import Verdict

    store = Store(str(tmp_path / "t.db"))
    for sev in (0.2, 1.5, 2.49, 2.5, 2.9, 3.9):
        make_case(store, host=f"192.168.50.{int(sev * 10)}", verdict=Verdict("benign", 0.9, sev, 0.8, 0.1, 0.1))
    make_case(store, host="192.168.50.99", must_alert=True)
    make_case(store, host="192.168.50.98")                           # rules-only: no score
    labels = {r["id"]: ui.severity_label(r) for r in store.db.execute("SELECT * FROM cases")}
    assert list(labels.values()) == ["informational", "medium", "medium", "high", "high", "critical",
                                     "critical", "–"]
    _, body = ui.render_queue(store, Assets(), {"status": ["all"]}, "x")
    assert "<th>severity</th><th>label</th>" in body and "<td>high</td>" in body


def test_only_the_stats_page_refreshes_itself(server):
    app, _ = server()
    for path in ("/", "/case/1", "/suppressions", "/stats"):
        _, text = request(app, "GET", path)
        assert ('http-equiv="refresh"' in text) == (path == "/stats"), path   # forms must never reload
    _, text = request(app, "GET", "/stats")
    assert f'<meta http-equiv="refresh" content="{ui.STATS_REFRESH_S}">' in text


def test_case_page_notes_order_toggle(server):
    app, db = server()
    store = Store(db)
    store.update_case(1, "t", note="first look")
    store.update_case(1, "t", note="follow-up")
    store.db.close()
    sid, _ = session(app)
    _, text = request(app, "GET", "/case/1", cookie=sid)              # default: oldest first, as written
    assert text.index("first look") < text.index("follow-up")
    assert 'class="pill on" href="/case/1?notes=oldest#notes"' in text
    _, text = request(app, "GET", "/case/1?notes=newest", cookie=sid)
    assert text.index("follow-up") < text.index("first look")
    assert 'class="pill on" href="/case/1?notes=newest#notes"' in text
    _, text = request(app, "GET", "/case/1?notes=<script>", cookie=sid)  # unknown value: default order
    assert text.index("first look") < text.index("follow-up") and "<script>" not in text


def test_learning_period_clock_is_the_warmup_start_and_survives_a_restart(fake_jev):
    jev = fake_jev(jev_response("c2_beaconing", conf=0.95, severity=3.5, routine=0.0, page=0.9))

    class Recorder:
        def __init__(self):
            self.sent = []

        def send(self, title, items):
            self.sent.append(title)

    store, note = Store(":memory:"), Recorder()
    w = Warmup(600)
    p = Pipeline([Beaconing(), NewDevice(w, {})], Assets(), store, client=jev, notifier=note,
                 learning_seconds=2 * 86400)
    out = []
    for i in range(15):
        out += p.process(conn(T0 + i * 60))
    assert [r for _, c, _, r in out if c.detector == "beaconing"] == [Route.DIGEST] and note.sent == []
    assert store.get(out[0][0])["reason"].startswith("learning period (day 1 of 2): ")
    p.save_state()
    # a restart two days later: the clock is the saved warm-up start, so the learning period is over
    p2 = Pipeline([Beaconing(), NewDevice(Warmup(600), {})], Assets(), store, client=jev, notifier=note,
                  learning_seconds=2 * 86400)
    p2.restore_state()
    assert p2.learning_label(T0 + 86400 + 1) == "learning period (day 2 of 2)"
    assert p2.learning_label(T0 + 2 * 86400) is None
    out = []
    for i in range(15):
        out += p2.process(conn(T0 + 2 * 86400 + i * 60, port=8443))
    assert [r for _, c, _, r in out if c.detector == "beaconing"] == [Route.ALERT] and len(note.sent) == 1


def test_device_scoped_rules_follow_the_device_across_addresses():
    store = Store(":memory:")
    laptop = {"device_mac": "aa:bb:cc:dd:ee:01", "device_name": "ACCT-LAPTOP"}
    cid, _ = make_case(store, detector="new_domain", host="192.168.50.102", indicators=["cdn.example.com"],
                       facts={**laptop})
    store.add_suppression(cid, "device_indicator", "the laptop's CDN", "t")
    assert store.suppressions()[0]["host"] == "name:acct-laptop"                   # keyed on the identity
    docked = Case("new_domain", "192.168.50.215", T0, "t", {**laptop}, ["cdn.example.com"])   # same laptop, new IP
    other = Case("new_domain", "192.168.50.215", T0, "t", {"device_mac": "aa:bb:cc:dd:ee:02"}, ["cdn.example.com"])
    assert store.match_suppression(docked).startswith("#1 new_domain (name:acct-laptop, cdn.example.com)")
    assert store.match_suppression(other) is None                                   # a different machine on that IP
    # a rule written before identities (host = IP) still matches that IP
    store.db.execute("INSERT INTO suppressions (scope, detector, host, indicator, reason, created_ts)"
                     " VALUES ('device_indicator', 'beaconing', '192.168.50.7', 'x.example', 'old', 1)")
    assert store.match_suppression(Case("beaconing", "192.168.50.7", T0, "t", {"device_mac": "aa:bb:cc:dd:ee:07"},
                                        ["x.example"])).startswith("#2")


def test_queue_shows_alerts_and_digest_items_by_default_and_log_cases_on_request(server):
    app, db = server()
    make_case(Store(db), detector="new_domain", host="192.168.50.44", indicators=["x.example"], facts={}, route_=Route.LOG)
    sid, _ = session(app)
    _, home = request(app, "GET", "/", cookie=sid)
    assert 'href="/case/1"' in home and 'href="/case/2"' not in home        # the alert, not the log entry
    _, everything = request(app, "GET", "/?route=all", cookie=sid)
    assert 'href="/case/2"' in everything
    _, logs = request(app, "GET", "/?route=log", cookie=sid)
    assert 'href="/case/2"' in logs and 'href="/case/1"' not in logs


def test_rules_made_from_the_old_port_indicator_still_match():
    store = Store(":memory:")
    store.db.execute("INSERT INTO suppressions (scope, detector, host, indicator, reason, created_ts)"
                     " VALUES ('device_indicator', 'beaconing', '192.168.50.19', 'port:1883', 'frame keepalive', 1)")
    frame = Case("beaconing", "192.168.50.19", T0, "t", {"port": 1883, "dedupe": "203.0.113.5:1883"}, [])
    assert store.match_suppression(frame).startswith("#1 beaconing")
    assert store.match_suppression(Case("beaconing", "192.168.50.19", T0, "t", {"port": 8883}, [])) is None
    assert store.match_suppression(Case("beaconing", "192.168.50.20", T0, "t", {"port": 1883}, [])) is None
