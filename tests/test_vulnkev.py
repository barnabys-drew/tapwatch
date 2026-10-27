"""R48 vuln_kev (#226) and its effect on the device's other cases (#227), on fixture inventories and feeds."""

from pathlib import Path

import pytest
from conftest import T0

from tapwatch import vulns
from tapwatch.hostrules import EndpointState
from tapwatch.models import Case, Route
from tapwatch.pipeline import Pipeline
from tapwatch.store import Store
from tapwatch.summarizer import Assets, summarize
from tapwatch.vulnkev import NAME, DeviceKev, VulnKev

PC = "192.168.50.10"
DAY = 86400
WIN = {"name": "Microsoft Windows 11 Home", "version": "10.0.26300", "platform": "windows"}
UBUNTU = {"name": "Ubuntu", "version": "24.04.3 LTS (Noble Numbat)", "platform": "ubuntu"}
ECO = "Ubuntu:24.04:LTS"


def index(extra_kev=()):
    kev = {"CVE-2026-2000": {"vendor": "Google", "product": "Chromium V8", "added": "2026-09-04", "ransomware": True},
           "CVE-2026-1000": {"vendor": "OpenSSL", "product": "OpenSSL", "added": "2026-10-01", "ransomware": False}}
    for cve in extra_kev:
        kev[cve] = {"vendor": "Google", "product": "Chromium Mojo", "added": "2026-10-15", "ransomware": False}
    nvd = {c: {"fetched": T0, "ranges": [{"cpe": "google:chrome", "exact": "", "versionEndExcluding": "152.0.7977.82"}]}
           for c in ("CVE-2026-2000", *extra_kev)}
    osv = {ECO: {"openssl": [("UBUNTU-CVE-2026-1000", "CVE-2026-1000", "0", "3.0.13-0ubuntu3.4", "")],
                 "curl": [("UBUNTU-CVE-2026-1002", "CVE-2026-1002", "0", "8.5.0-2ubuntu10.4", "")]}}
    return vulns.VulnIndex(kev=kev, osv=osv, nvd=nvd, kev_by_product=vulns.kev_for_products(kev))


def snap(name, rows, agent="win-agent", ts=T0):
    return {"_type": "osquery", "name": name, "hostIdentifier": agent, "action": "snapshot", "snapshot": rows, "ts": ts}


def chrome(version, ts=T0):
    return snap("software_programs", [{"name": "Google Chrome", "version": version, "publisher": "Google LLC"},
                                      {"name": "Some Game", "version": "1.0"}], ts=ts)


@pytest.fixture
def rule():
    r = VulnKev(EndpointState(PC), index=index())
    r.feed(snap("os_version", [WIN]))
    return r


def test_an_old_browser_with_a_kev_bug_is_one_digest_case(rule):
    [c] = rule.feed(chrome("150.0.7000.1"))
    assert (c.detector, c.host, c.base_severity, c.indicators) == (NAME, PC, 3, ["Google Chrome"])
    f = c.facts
    assert (f["product"], f["version"], f["kev_cves"], f["cves"], f["fixed_in"], f["ransomware"]) == \
        ("Google Chrome", "150.0.7000.1", 1, ["CVE-2026-2000"], "152.0.7977.82", True)
    assert "Windows 11" in f["os"] and f["source"] == "endpoint"
    text = summarize(c, Assets())
    assert "Google Chrome" in text and "152.0.7977.82" in text and "ransomware" in text


def test_patched_or_unmapped_software_is_quiet(rule):
    assert rule.feed(chrome("155.0.8059.85")) == []


def test_no_verdict_without_os_or_feeds():
    r = VulnKev(EndpointState(PC), index=index())
    assert r.feed(snap("software_deb", [{"name": "libssl3t64", "version": "3.0.13-0ubuntu3", "source": "openssl"}],
                       agent="wsl")) == []                                       # OS not known yet
    r2 = VulnKev(EndpointState(PC), index=vulns.VulnIndex())
    r2.feed(snap("os_version", [WIN]))
    assert r2.feed(chrome("150.0")) == []                                         # nothing downloaded


def test_linux_kev_package_is_a_case_and_osv_only_is_a_fact():
    r = VulnKev(EndpointState(PC), index=index())
    r.feed(snap("os_version", [UBUNTU], agent="wsl"))
    cases = r.feed(snap("software_deb", [{"name": "libssl3t64", "version": "3.0.13-0ubuntu3", "source": "openssl"},
                                         {"name": "openssl", "version": "3.0.13-0ubuntu3", "source": "openssl"},
                                         {"name": "curl", "version": "8.5.0-2ubuntu10", "source": ""}], agent="wsl"))
    assert [(c.facts["product"], c.facts["kev_cves"]) for c in cases] == [("openssl", 1)]   # one per source package
    assert r.osv_only["wsl"]["cves"] == 1 and r.osv_only["wsl"]["packages"] == 1          # curl: not on KEV
    assert cases[0].facts["osv_only"]["cves"] == 1


def test_raised_again_on_a_new_kev_cve_or_after_fourteen_days(rule):
    assert len(rule.feed(chrome("150.0", ts=T0))) == 1
    assert rule.feed(chrome("150.0", ts=T0 + DAY)) == []                          # daily snapshot, nothing new
    rule._index = index(extra_kev=("CVE-2026-3000",))
    [again] = rule.feed(chrome("150.0", ts=T0 + 2 * DAY))
    assert again.facts["repeat"] == "new known-exploited CVE" and again.facts["kev_cves"] == 2
    assert rule.feed(chrome("150.0", ts=T0 + 10 * DAY)) == []
    [late] = rule.feed(chrome("150.0", ts=T0 + 16 * DAY))
    assert late.facts["repeat"].startswith("still unpatched after 14 days") and "still unpatched" in late.title


def test_an_empty_snapshot_resolves_nothing(rule):
    rule.feed(chrome("150.0"))
    assert rule.feed(snap("software_programs", [], ts=T0 + DAY)) == [] and rule.resolved == []


def test_state_survives_a_restart(rule):
    rule.feed(chrome("150.0"))
    again = VulnKev(EndpointState(PC), index=index())
    again.restore(rule.snapshot())
    assert again.feed(chrome("150.0", ts=T0 + DAY)) == []                         # os and report remembered


# ---- through the pipeline -----------------------------------------------------------------------------------------

def pipeline():
    store = Store(":memory:")
    rule = VulnKev(EndpointState(PC), index=index())
    return Pipeline([rule], Assets(), store), store


def test_routed_to_the_digest_by_code_and_closed_when_patched():
    p, store = pipeline()
    p.process(snap("os_version", [WIN]))
    [(case_id, _case, verdict, r)] = p.process(chrome("150.0"))
    assert (r, verdict) == (Route.DIGEST, None)
    p.process(chrome("156.0.1", ts=T0 + DAY))                                      # the update arrived
    row = store.get(case_id)
    assert (row["status"], row["disposition"]) == ("closed", "true_positive")
    note = store.notes(case_id)[-1]
    assert note["actor"] == "tapwatch" and "Google Chrome 156.0.1" in note["text"] and "was 150.0" in note["text"]


def test_uninstalled_counts_as_fixed():
    p, store = pipeline()
    p.process(snap("os_version", [WIN]))
    [(case_id, *_)] = p.process(chrome("150.0"))
    p.process(snap("software_programs", [{"name": "Some Game", "version": "1.0"}], ts=T0 + DAY))
    assert store.get(case_id)["status"] == "closed"
    assert "no longer installed" in store.notes(case_id)[-1]["text"]


def other_case(detector="host_temp_exec", host=PC, severity=2, program="notepad.exe", **facts):
    """A host case on the PC: its program is its indicator (so two programs are two cases, not one deduped)."""
    return Case(detector, host, T0 + 60, "A program in a temporary folder connected out",
                {"source": "endpoint", "program": program, "folder": "temp", **facts}, [program],
                base_severity=severity)


def test_227_other_cases_on_the_device_are_raised_one_level():
    p, _store = pipeline()
    p.process(snap("os_version", [WIN]))
    p.process(chrome("150.0"))
    _, case, _, _r = p.handle(other_case())
    assert case.base_severity == 3 and case.facts["device_kev"] == {"products": ["Google Chrome"], "cves": 1}
    assert "known-exploited" in summarize(case, Assets())
    _, clean, _, _ = p.handle(other_case(host="192.168.50.99", program="other.exe"))                   # another device: untouched
    assert clean.base_severity == 2 and "device_kev" not in clean.facts


def test_227_the_vulnerable_program_itself_alerts():
    p, _store = pipeline()
    p.process(snap("os_version", [WIN]))
    p.process(chrome("150.0"))
    host_case = other_case(severity=3, program="chrome.exe")
    _, case, _, r = p.handle(host_case)
    assert r is Route.ALERT and case.facts["min_route"] == "alert"
    _, other, _, r2 = p.handle(other_case(severity=2, program="notepad.exe"))
    assert r2 is Route.DIGEST and "min_route" not in other.facts                  # raised to 3, still a digest


def test_227_never_lowers_and_ignores_closed_or_suppressed_r48():
    store = Store(":memory:")
    dk = DeviceKev(store)
    p = Pipeline([VulnKev(EndpointState(PC), index=index())], Assets(), store)
    p.process(snap("os_version", [WIN]))
    [(case_id, *_)] = p.process(chrome("150.0"))
    top = other_case(severity=5)
    dk.apply(top)
    assert top.base_severity == 5 and not top.must_alert
    store.update_case(case_id, "owner", status="closed", disposition="benign_expected", note="not used")
    later = other_case()
    assert dk.apply(later) is False and later.base_severity == 2


def test_227_log_level_cases_stay_in_the_log():
    p, _store = pipeline()
    p.process(snap("os_version", [WIN]))
    p.process(chrome("150.0"))
    _, case, _, r = p.handle(other_case(severity=1, program="quiet.exe"))
    assert case.base_severity == 1 and r is Route.LOG and "device_kev" in case.facts   # the fact, not the nudge


def test_benchmark_what_if_counts_only_rules_routed_cases_that_move(tmp_path):
    from tapwatch import benchmark
    from tapwatch.models import Verdict
    store = Store(str(tmp_path / "t.db"))
    for i, (sev, verdict) in enumerate([(3, None), (2, None), (1, None), (4, None),
                                        (3, Verdict("benign", 0.9, 1.0, 0.9, 0.9, 0.0))]):
        c = other_case(severity=sev, program=f"p{i}.exe")
        r, why = (Route.DIGEST, "rules-only") if sev in (2, 3) else \
            (Route.LOG, "rules-only: low severity") if sev == 1 else (Route.ALERT, "rules-only: high severity")
        store.add(c, "", verdict, Route.LOG if verdict else r, "AI: benign" if verdict else why)
    store.db.execute("INSERT INTO cases (key, first_ts, last_ts, detector, host, title, facts, indicators, must_alert,"
                     " state, route, reason) VALUES ('old', 1, 1, 'tls_odd', 'x', 't', '{}', '[]', 0, '', 'digest',"
                     " 'rules-only')")   # stored before base_severity was recorded
    k = benchmark.kev_what_if(store.db)
    assert (k["cases"], k["rules_routed"], k["up"], k["maybe"]) == (6, 5, 1, 1)
    assert "1 of 6 cases would have routed one step louder" in benchmark.markdown(store.db)


def test_349_standing_rules_are_not_raised_by_an_open_r48_case():
    """A stale-signatures digest item (R49, severity 3) must not become a critical alert because the PC also has an
    unpatched browser: R49-R51 describe the PC's state, the same story R48 tells (review of #349)."""
    from tapwatch.hostrules import STANDING
    store = Store(":memory:")
    p = Pipeline([VulnKev(EndpointState(PC), index=index())], Assets(), store)
    p.process(snap("os_version", [WIN]))
    p.process(chrome("150.0"))
    dk = DeviceKev(store)
    for name in sorted(STANDING - {NAME}):
        case = other_case(detector=name, severity=3)
        dk.apply(case)
        assert case.base_severity == 3, name
    usual = other_case(severity=3)
    assert dk.apply(usual) and usual.base_severity == 4                        # other host rules still rise


def test_349_standing_rules_do_not_back_a_long_horizon_case():
    from tapwatch import hostrules, longhaul
    assert {"host_av_off", "host_usb_new", "host_patch", "vuln_kev"} == hostrules.STANDING
    assert "hostrules.STANDING" in Path(longhaul.__file__).read_text()
