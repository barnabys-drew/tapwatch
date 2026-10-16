"""Endpoint rules (R17-R21): host cases from the agent's own rows, on synthetic osquery/Sysmon rows only."""

import json
from datetime import datetime, timezone

from conftest import T0, conn, dns

from tapwatch import config, detectors, zeek
from tapwatch.hostrules import (
    NAMES,
    AppSpawnsShell,
    BadSignatureConnects,
    EncodedCommand,
    EndpointState,
    LolbinConnects,
    TempFolderConnects,
    build,
    folder_class,
)
from tapwatch.models import Route
from tapwatch.pipeline import Pipeline
from tapwatch.router import CODE_ONLY, critical, route, wants_ai
from tapwatch.store import Store
from tapwatch.summarizer import Assets, summarize

PC = "192.168.50.10"
DST = "203.0.113.50"
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
CMD = r"C:\Windows\System32\cmd.exe"
WORD = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
OUTLOOK = r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"
CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
EXPLORER = r"C:\Windows\explorer.exe"
TEMP_EXE = r"C:\Users\<user>\AppData\Local\Temp\7zS1\setup.exe"
PUBLIC_EXE = r"C:\Users\Public\svc.exe"
DOWNLOADS_EXE = r"C:\Users\<user>\Downloads\tool.exe"


def utc(t):
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def sysmon(eid, t, guid="{g1}", **cols):
    """One Sysmon row as the agent's `sysmon_events` query logs it, read 40 s later (the query interval)."""
    return {"_type": "osquery", "name": "sysmon_events", "unixTime": int(t) + 40, "ts": int(t) + 40,
            "action": "added", "columns": {"eventid": str(eid), "utc": utc(t), "guid": guid, **cols}}


def start(t, path, parent, guid="{g1}", **flags):
    return sysmon(1, t, guid, path=path, parent_path=parent, **flags)


def connect(t, path, guid="{g1}", remote=DST, port=443):
    return sysmon(3, t, guid, path=path, remote_address=remote, remote_port=str(port))


def snapshot_conn(t, name, path, signature, signer="", remote=DST, port=443, action="added"):
    return {"_type": "osquery", "name": "outbound_connections", "unixTime": int(t), "ts": int(t), "action": action,
            "columns": {"name": name, "path": path, "pid": "4242", "remote_address": remote, "remote_port": str(port),
                        "signature": signature, "signer": signer, "parent_name": "explorer.exe"}}


def addrs(t, *ips):
    return {"_type": "osquery", "name": "host_addresses", "action": "snapshot", "unixTime": int(t), "ts": int(t),
            "snapshot": [{"address": a} for a in ips]}


def run(det, *recs):
    out = []
    for r in recs:
        out += det.feed(r)
    return out


def st():
    return EndpointState(PC)


def no_paths(case):
    """A case carries program names (as indicators) and folder classes, never a path or a command line."""
    text = json.dumps(case.facts) + json.dumps(case.indicators)
    assert "C:\\\\" not in text and "<user>" not in text and "cmdline" not in text, text
    assert case.indicators and case.host == PC and case.facts["source"] == "endpoint"


# ------------------------------------------------------------ R17 encoded or download-and-run command

def test_encoded_download_from_a_document_app_is_must_alert():
    (c,) = run(EncodedCommand(st()), start(T0, PS, WORD, cmd_enc="1", cmd_dl="1", cmd_url="1"))
    assert c.must_alert and c.base_severity == 5 and c.detector == "host_encoded_cmd"
    assert c.facts["signals"] == ["an encoded payload", "a download-and-run"] and c.facts["parent_class"] == "document"
    assert c.facts["program"] == "powershell.exe" and c.facts["folder"] == "installed" and c.ts == T0
    assert c.indicators == ["powershell.exe"] and c.indicator == "powershell.exe"
    no_paths(c)


def test_one_strong_signal_alerts_and_hidden_window_makes_it_must_alert():
    (enc,) = run(EncodedCommand(st()), start(T0, PS, EXPLORER, cmd_enc="1"))
    assert (enc.base_severity, enc.must_alert) == (4, False)
    (hidden,) = run(EncodedCommand(st()), start(T0, PS, EXPLORER, cmd_dl="1", cmd_hidden="1"))
    assert (hidden.base_severity, hidden.must_alert) == (5, True) and hidden.facts["unusual"] == ["a hidden window"]
    (enc2,) = run(EncodedCommand(st()), start(T0, PS, EXPLORER, cmd_enc="1", cmd_b64="1"))
    assert enc2.must_alert


def test_chocolateys_install_line_alerts_but_is_suppressible():
    """dl + iex + an execution-policy bypass is Chocolatey's documented install command: a benign reading
    exists, and must_alert can't be suppressed, so it stays at severity 4 (review of PR #87)."""
    (choco,) = run(EncodedCommand(st()), start(T0, PS, EXPLORER, cmd_dl="1", cmd_iex="1", cmd_bypass="1", cmd_url="1"))
    assert (choco.base_severity, choco.must_alert) == (4, False) and choco.facts["unusual"] == ["an execution-policy bypass"]


def test_a_weak_signal_alone_raises_nothing_unless_a_browser_started_it():
    """`iex (irm ...)` installs dev tools; base64 decoding is in ordinary scripts. From a browser it isn't."""
    assert run(EncodedCommand(st()), start(T0, PS, EXPLORER, cmd_iex="1"), start(T0, CMD, EXPLORER, cmd_b64="1")) == []
    (c,) = run(EncodedCommand(st()), start(T0, PS, CHROME, cmd_iex="1"))
    assert (c.base_severity, c.must_alert, c.facts["parent_class"]) == (4, False, "browser")
    (both,) = run(EncodedCommand(st()), start(T0, PS, EXPLORER, cmd_iex="1", cmd_b64="1"))
    assert (both.base_severity, both.must_alert) == (4, False)                              # two weak ones together: an alert


def test_signals_on_programs_that_are_not_shells_are_ignored():
    """Measured: the only encoded-payload signal in 34.5 h was msiexec passing a long argument to itself."""
    msi = r"C:\Windows\System32\msiexec.exe"
    assert run(EncodedCommand(st()), start(T0, msi, msi, cmd_enc="1")) == []
    assert run(EncodedCommand(st()), start(T0, PS, EXPLORER, cmd_url="1")) == []           # a URL alone is no signal
    assert run(EncodedCommand(st()), start(T0, PS, EXPLORER, cmd_hidden="1", cmd_bypass="1")) == []  # installers do this


# ------------------------------------------------------------ R18 document app or browser starts a shell

def test_document_app_starting_powershell_alerts():
    (c,) = run(AppSpawnsShell(st()), start(T0, PS, WORD))
    assert c.base_severity == 4 and not c.must_alert and c.facts["parent_class"] == "document"
    assert "document" in c.title and c.facts["parent"] == "WINWORD.EXE"
    assert c.indicators == ["WINWORD.EXE > powershell.exe"]                                # what a suppression keys on
    no_paths(c)


def test_browser_starting_cmd_alone_raises_nothing():
    """Measured: Chrome started cmd.exe 37 times in 34.5 h (native-messaging hosts), none with a URL, none connected."""
    d = AppSpawnsShell(st())
    assert run(d, start(T0, CMD, CHROME), start(T0 + 60, CMD, CHROME, guid="{g2}", cmd_url="1"),
               start(T0 + 60, PS, CHROME, guid="{g3}", cmd_dl="1")) == []
    assert run(EncodedCommand(st()), start(T0, PS, CHROME, cmd_dl="1"))[0].base_severity == 4   # R17 has that one


def test_browser_child_that_connects_to_the_internet_alerts_once():
    d = AppSpawnsShell(st())
    assert run(d, start(T0, CMD, CHROME)) == []
    assert run(d, connect(T0 + 2, CMD, remote="192.168.50.1")) == []                       # the LAN doesn't count
    (c,) = run(d, connect(T0 + 5, CMD))
    assert c.base_severity == 4 and c.facts["connected"] and c.facts["port"] == 443 and "connected" in c.title
    assert c.indicators == ["chrome.exe > cmd.exe"]
    assert run(d, connect(T0 + 6, CMD, port=8443)) == []                                   # one case per process
    no_paths(c)
    late = AppSpawnsShell(st())
    run(late, start(T0, CMD, CHROME))
    assert run(late, connect(T0 + 700, CMD)) == []                                         # outside the 10-minute join


def test_document_child_is_not_reported_twice_and_other_parents_are_ignored():
    d = AppSpawnsShell(st())
    assert len(run(d, start(T0, PS, WORD), connect(T0 + 1, PS))) == 1
    wsl = r"C:\Windows\System32\wslhost.exe"
    assert run(AppSpawnsShell(st()), start(T0, CMD, wsl), start(T0, PS, EXPLORER, guid="{g2}"),
               start(T0, PS, CMD, guid="{g3}")) == []


# ------------------------------------------------------------ R19 program in a temp folder connects out

def test_temp_and_downloads_programs_connecting_out_are_digest_items():
    (c,) = run(TempFolderConnects(st()), connect(T0, TEMP_EXE))
    assert c.base_severity == 3 and c.facts == {"source": "endpoint", "program": "setup.exe", "folder": "temp", "port": 443}
    assert c.indicators == ["setup.exe"]
    no_paths(c)
    (dl,) = run(TempFolderConnects(st()), connect(T0, DOWNLOADS_EXE))
    assert dl.base_severity == 3 and dl.facts["folder"] == "downloads"
    d = TempFolderConnects(st())
    run(d, connect(T0, TEMP_EXE))
    assert run(d, connect(T0 + 60, TEMP_EXE, guid="{g2}", port=80)) == []                  # the installer keeps going


def test_shared_folders_and_dropper_shapes_alert():
    (pub,) = run(TempFolderConnects(st()), connect(T0, PUBLIC_EXE))
    assert pub.base_severity == 4 and pub.facts["folder"] == "shared"
    (dropped,) = run(TempFolderConnects(st()), start(T0, TEMP_EXE, OUTLOOK), connect(T0 + 3, TEMP_EXE))
    assert dropped.base_severity == 4 and dropped.facts["parent"] == "OUTLOOK.EXE" and dropped.facts["parent_class"] == "document"
    (scripted,) = run(TempFolderConnects(st()), start(T0, TEMP_EXE, EXPLORER, cmd_dl="1"), connect(T0 + 3, TEMP_EXE))
    assert scripted.base_severity == 4 and scripted.facts["signals"] == ["a download-and-run"]


def test_installed_programs_lan_and_dns_do_not_count():
    d = TempFolderConnects(st())
    assert run(d, connect(T0, CHROME), connect(T0, TEMP_EXE, remote="192.168.50.1"),
               connect(T0, TEMP_EXE, remote="203.0.113.1", port=53), connect(T0, TEMP_EXE, remote="not an ip")) == []


# ------------------------------------------------------------ R20 built-in tool connects out

def test_download_lolbins_are_must_alert_and_the_rest_alert():
    certutil = r"C:\Windows\System32\certutil.exe"
    (c,) = run(LolbinConnects(st()), connect(T0, certutil))
    assert c.must_alert and c.base_severity == 5 and c.facts["downloader"] and c.facts["program"] == "certutil.exe"
    no_paths(c)
    rundll = r"C:\Windows\System32\rundll32.exe"
    (r,) = run(LolbinConnects(st()), start(T0, rundll, WORD, cmd_url="1"), connect(T0 + 1, rundll))
    assert (r.base_severity, r.must_alert) == (4, False)
    assert r.facts["parent"] == "WINWORD.EXE" and r.facts["url"] and r.facts["parent_class"] == "document"


def test_msbuild_is_a_weekly_digest_item_not_an_hourly_alert():
    """MSBuild restores NuGet packages on any Visual Studio PC (review of PR #87)."""
    d = LolbinConnects(st())
    msbuild = r"C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
    (c,) = run(d, connect(T0, msbuild))
    assert (c.base_severity, c.must_alert, c.facts["downloader"]) == (3, False, False)
    assert run(d, connect(T0 + 3600, msbuild, guid="{g2}")) == []
    assert len(run(d, connect(T0 + 8 * 86400, msbuild, guid="{g3}"))) == 1


def test_lolbins_on_the_lan_and_ordinary_programs_are_ignored():
    rundll = r"C:\Windows\System32\rundll32.exe"
    assert run(LolbinConnects(st()), connect(T0, rundll, remote="192.168.50.2"), connect(T0, rundll, port=53),
               connect(T0, CHROME), connect(T0, PS)) == []


# ------------------------------------------------------------ R21 bad code signature connects out

def test_untrusted_and_distrusted_signatures_alert_missing_is_ignored():
    """osquery's authenticode says trusted, missing, untrusted or distrusted; a tampered file is `untrusted`."""
    app = r"C:\Program Files\App\app.exe"
    (bad,) = run(BadSignatureConnects(st()), snapshot_conn(T0, "app.exe", app, "untrusted", "App Maker"))
    assert (bad.base_severity, bad.must_alert) == (4, False) and bad.facts["signature"] == "untrusted"
    assert bad.facts["signer"] == "App Maker" and bad.facts["folder"] == "installed" and bad.facts["parent"] == "explorer.exe"
    no_paths(bad)
    (blocked,) = run(BadSignatureConnects(st()), snapshot_conn(T0, "x.exe", app, "Distrusted"))
    assert blocked.base_severity == 4
    # measured: every "missing" or unreadable signature in 34.5 h was an installed app osquery couldn't read
    assert run(BadSignatureConnects(st()), snapshot_conn(T0, "a.exe", app, "missing"), snapshot_conn(T0, "b.exe", app, ""),
               snapshot_conn(T0, "c.exe", app, "trusted"), snapshot_conn(T0, "d.exe", app, "untrusted", action="removed"),
               snapshot_conn(T0, "e.exe", app, "untrusted", remote="192.168.50.9")) == []


# ------------------------------------------------------------ the framework

def test_pc_address_follows_the_agents_snapshots_and_prefers_the_lan():
    s = EndpointState("")
    d = EncodedCommand(s)
    assert s.host == "this PC"                                                              # never an empty host
    d.feed(addrs(T0, "172.28.0.1", "192.168.50.77", "fe80::1", "100.64.0.5"))
    assert s.host == "192.168.50.77"
    d.feed(addrs(T0 + 300, "172.28.0.1", "10.0.0.5"))
    assert s.host == "10.0.0.5"
    configured = EndpointState(PC)
    EncodedCommand(configured).feed(addrs(T0, "192.168.50.77", PC))
    assert configured.host == PC                                                            # the configured one wins
    (c,) = run(EncodedCommand(s), start(T0, PS, WORD, cmd_enc="1", cmd_dl="1"))
    assert c.host == "10.0.0.5"


def test_wsl_nat_snapshot_never_moves_the_host_off_the_lan():
    """Two agents report for one PC: WSL in NAT mode lists only its 172.x address. Taking it at face value gave
    about half the cases the wrong host (review of PR #87), splitting dedupe keys and suppressions."""
    s = EndpointState("")
    d = EncodedCommand(s)
    d.feed(addrs(T0, "192.168.50.77", "172.28.0.1"))                                       # Windows agent
    d.feed(addrs(T0 + 10, "172.28.5.2"))                                                    # WSL agent, NAT mode
    assert s.host == "192.168.50.77"
    fresh = EndpointState("")
    EncodedCommand(fresh).feed(addrs(T0, "172.28.5.2"))
    assert fresh.host == "172.28.5.2"                                                       # better than "this PC"...
    EncodedCommand(fresh).feed(addrs(T0 + 10, "192.168.50.77", "172.28.0.1"))
    assert fresh.host == "192.168.50.77"                                                    # ...until the LAN address shows
    (c,) = run(EncodedCommand(EndpointState("")), start(T0, PS, WORD, cmd_enc="1", cmd_dl="1"))
    assert c.host == "this PC" and c.must_alert                                             # no address yet: still raised


def test_names_are_code_only_and_build_wires_them():
    assert set(NAMES) <= CODE_ONLY
    dets = build({"host_context": {"host": PC}})
    assert [d.name for d in dets] == list(NAMES) and len({id(d.state) for d in dets}) == 1
    assert dets[0].state.host == PC
    for d in dets:
        assert d.feed(conn(T0)) == [] and d.feed(dns(T0, "a.example")) == []               # Zeek records: not ours
    assert build({"detectors": {"host_rules": {"enabled": False}}}) == []
    tuned = build({"detectors": {"host_app_shell": {"reported_days": 1}}})
    assert next(d for d in tuned if d.name == "host_app_shell").ttl == 86400.0


def test_network_detectors_ignore_endpoint_records():
    for d in detectors.build({}):
        assert d.feed(start(T0, PS, WORD, cmd_enc="1")) == [] and d.feed(addrs(T0, PC)) == []


def test_reported_state_persists_and_restores():
    d = TempFolderConnects(st())
    assert len(run(d, connect(T0, TEMP_EXE))) == 1
    fresh = TempFolderConnects(st())
    fresh.restore(d.snapshot())
    assert run(fresh, connect(T0 + 60, TEMP_EXE, guid="{g2}")) == []                        # still this week's item


def test_folder_classes_never_echo_the_path():
    assert folder_class(TEMP_EXE) == "temp" and folder_class(PUBLIC_EXE) == "shared"
    assert folder_class(r"C:\Users\<user>\AppData\Local\Programs\App\App.exe") == "appdata"
    assert folder_class(r"D:\Games\game.exe") == "other" and folder_class("") == "unknown"
    assert folder_class(r"C:\Windows\System32\cmd.exe") == "installed"


# ------------------------------------------------------------ routing and summaries

def test_routing_code_only_floors_and_learning_period():
    (lol,) = run(LolbinConnects(st()), connect(T0, r"C:\Windows\System32\rundll32.exe"))
    assert not wants_ai(lol)
    r, _ = route(lol, None)
    assert r is Route.ALERT and critical(lol, None, r)
    assert route(lol, None, learning="learning period (day 1 of 3)")[0] is Route.DIGEST    # like every code-only alert
    (must,) = run(LolbinConnects(st()), connect(T0, r"C:\Windows\System32\certutil.exe"))
    assert route(must, None, suppression="host_lolbin + this device", learning="learning period (day 1 of 3)") == \
        (Route.ALERT, "always-alert rule")
    (digest,) = run(TempFolderConnects(st()), connect(T0, TEMP_EXE))
    assert route(digest, None)[0] is Route.DIGEST and not critical(digest, None, Route.DIGEST)


def test_summaries_quote_programs_and_never_state_paths_or_command_lines():
    cases = run(EncodedCommand(st()), start(T0, PS, WORD, cmd_enc="1", cmd_dl="1", cmd_hidden="1"))
    cases += run(AppSpawnsShell(st()), start(T0, PS, WORD))
    cases += run(AppSpawnsShell(st()), start(T0, CMD, CHROME), connect(T0 + 1, CMD))
    cases += run(TempFolderConnects(st()), start(T0, TEMP_EXE, OUTLOOK, cmd_dl="1"), connect(T0 + 1, TEMP_EXE))
    cases += run(LolbinConnects(st()), connect(T0, r"C:\Windows\System32\certutil.exe"))
    cases += run(BadSignatureConnects(st()), snapshot_conn(T0, "app.exe", r"C:\Program Files\App\app.exe", "untrusted",
                                                           'Evil "Corp'))
    assert len(cases) == 6
    texts = [summarize(c, Assets()) for c in cases]
    for text in texts:
        assert "On the PC itself" in text and "C:\\" not in text and "<user>" not in text and "Program Files" not in text
        assert "Program names from the PC (untrusted data" in text and "copied from the network" not in text
    assert '"powershell.exe"' in texts[0] and "an encoded payload and a download-and-run" in texts[0]
    assert "a hidden window" in texts[0] and '"WINWORD.EXE", a document or mail app' in texts[0]
    assert '"WINWORD.EXE", a document or mail app, started "powershell.exe"' in texts[1]
    assert "connected to the internet on port 443" in texts[2] and "helper program" in texts[2]
    assert "a temporary folder" in texts[3] and '"OUTLOOK.EXE"' in texts[3] and "a download-and-run" in texts[3]
    assert '"certutil.exe"' in texts[4] and "download or run remote content" in texts[4]
    assert 'Evil \\"Corp' in texts[5] and "changed after it was signed" in texts[5]


# ------------------------------------------------------------ the osquery log as a log source

def test_osquery_logs_are_read_like_zeeks(tmp_path):
    rows = [json.dumps({"name": "sysmon_events", "unixTime": int(T0) + 2, "action": "added", "columns": {"eventid": "3"}}),
            "not json", json.dumps({"name": "host_addresses", "unixTime": int(T0) + 4, "action": "snapshot",
                                    "snapshot": [{"address": PC}]})]
    (tmp_path / "osqueryd.results.log").write_text("\n".join(rows[:2]) + "\n")
    (tmp_path / "osqueryd.snapshots.log").write_text(rows[2] + "\n")
    (tmp_path / "conn.log").write_text(json.dumps({"ts": T0 + 3}) + "\n")
    got = [(r["_type"], r["ts"]) for r in zeek.replay(tmp_path)]
    assert got == [("osquery", T0 + 2), ("conn", T0 + 3), ("osquery", T0 + 4)]
    f = zeek.Follower(tmp_path)
    assert f.poll() == []                                                                   # history is skipped
    with (tmp_path / "osqueryd.results.log").open("a") as fh:
        fh.write(json.dumps({"name": "sysmon_events", "unixTime": int(T0) + 9, "action": "added", "columns": {}}) + "\n")
    (rec,) = f.poll()
    assert rec["_type"] == "osquery" and rec["ts"] == T0 + 9 and rec["name"] == "sysmon_events"
    f.close()


def test_host_log_dirs_are_only_those_with_an_agents_log(tmp_path):
    present = tmp_path / "osquery" / "log" / "osqueryd.results.log"
    present.parent.mkdir(parents=True)
    present.write_text("")
    cfg = {"host_context": {"results_logs": [str(present), str(tmp_path / "missing" / "osqueryd.results.log")]}}
    assert config.host_log_dirs(cfg) == [str(present.parent)]
    assert config.host_log_dirs({"host_context": {"results_logs": [str(tmp_path / "nope.log")]}}) == []


def test_pipeline_routes_host_cases_by_code_without_jev_or_host_context(tmp_path):
    from conftest import FakeJev, write_logs

    from tapwatch.hostctx import HostContext

    class Note:
        def __init__(self):
            self.sent = []

        def send(self, title, items):
            self.sent.append((title, items))
            return ["fake"]

    jev, note = FakeJev(), Note()
    zeek_dir = write_logs(tmp_path, conn=[conn(T0, src=PC)])
    hc = HostContext(PC, None, [], str(tmp_path / "t"))                                     # would apply: it's this PC
    p = Pipeline(build({"host_context": {"host": PC}}), Assets(), Store(":memory:"), client=jev, notifier=note,
                 hostctx=hc, zeek_dirs=[str(zeek_dir)])
    (cid, c, verdict, r), = p.process(connect(T0, r"C:\Windows\System32\certutil.exe"))
    assert r is Route.ALERT and verdict is None and jev.states == []                        # code decided; no tokens
    assert "host_who" not in c.facts                                                        # host context stays out
    assert note.sent and "certutil.exe" in json.dumps(note.sent) and "C:\\\\" not in json.dumps(note.sent)
    row = p.store.get(cid)
    assert row["reason"] == "always-alert rule" and "On the PC itself" in row["state"]
    assert p.process(connect(T0 + 60, r"C:\Windows\System32\certutil.exe", guid="{g2}")) == []   # counted, not re-sent
    assert p.store.get(cid)["hits"] == 2
