"""Software inventory (#224) and vulnerability feeds (#225): normalising agent rows, version ordering, the OSV
index, NVD ranges, update-feeds, the store tables and the pipeline hook. Fixtures are trimmed copies of the real
formats (OSV Ubuntu 24.04 dump, NVD API 2.0, CISA KEV) as downloaded 2026-10-20."""

import gzip
import io
import json
import zipfile

import pytest
from conftest import T0

from tapwatch import doctor, feeds, inventory, vulns
from tapwatch.pipeline import Pipeline
from tapwatch.store import Store
from tapwatch.summarizer import Assets

ECO = "Ubuntu:24.04:LTS"
UBUNTU = {"name": "Ubuntu", "version": "24.04.3 LTS (Noble Numbat)", "platform": "ubuntu"}


# ---- normalising ------------------------------------------------------------------------------------------------

def test_programs_keep_name_version_only_and_map_known_products():
    rows = [{"name": "Google Chrome", "version": "155.0.8059.85", "publisher": "Google LLC",
             "install_location": "C:\\Users\\<user>\\AppData\\Local\\Google\\Chrome"},
            {"name": "Google Chrome Remote Desktop Host", "version": "1.0"},
            {"name": "Zoom Workplace", "version": "7.1.9 (48550)"},
            {"name": "Some Game", "version": "2.0"},
            {"name": "", "version": "1"},
            {"name": "Google Chrome", "version": "155.0.8059.85"}]   # per-user and machine rows: one entry
    out = inventory.normalise("software_programs", rows)
    assert [(r["name"], r["product"]) for r in out] == [("Google Chrome", "chrome"),
                                                         ("Google Chrome Remote Desktop Host", ""),
                                                         ("Zoom Workplace", "zoom"), ("Some Game", "")]
    assert all(set(r) == {"kind", "name", "version", "source", "product"} for r in out)
    assert "<user>" not in json.dumps(out)


def test_deb_and_rpm_rows_name_their_source_package():
    deb = inventory.normalise("software_deb", [{"name": "libssl3t64", "version": "3.0.13-0ubuntu3.6",
                                                 "source": "openssl"},
                                                {"name": "zlib1g", "version": "1:1.3", "source": "zlib (1:1.3)"},
                                                {"name": "bash", "version": "5.2", "source": ""}])
    assert [r["source"] for r in deb] == ["openssl", "zlib", "bash"]
    rpm = inventory.normalise("software_rpm", [{"name": "openssl-libs", "version": "3.0.7", "release": "27.el9",
                                                 "source": "openssl-3.0.7-27.el9.src.rpm"}])
    assert (rpm[0]["version"], rpm[0]["source"]) == ("3.0.7-27.el9", "openssl")


@pytest.mark.parametrize("os_row,kind,eco", [
    (UBUNTU, "deb", "Ubuntu:24.04:LTS"),
    ({"name": "Ubuntu", "version": "25.10 (Questing Quokka)"}, "deb", "Ubuntu:25.10"),
    ({"name": "Debian GNU/Linux", "version": "12 (bookworm)"}, "deb", "Debian:12"),
    ({"name": "Arch Linux", "version": "rolling"}, "deb", None),
    (None, "deb", None),
    ({"name": "Microsoft Windows 11 Pro", "version": "10.0.26200"}, "windows", "windows"),
    ({"name": "Fedora", "version": "40"}, "rpm", None),
])
def test_ecosystem_from_the_agents_os(os_row, kind, eco):
    assert inventory.ecosystem(kind, os_row) == eco


# ---- versions ---------------------------------------------------------------------------------------------------

# Every pair checked against `dpkg --compare-versions` on Ubuntu 24.04 (2026-10-20), plus 134 real pairs from the
# OSV dump against the WSL inventory: all agreed.
@pytest.mark.parametrize("a,b,sign", [
    ("1.0~rc1", "1.0", -1), ("1.0", "1.0-0", 0), ("1:1.0", "2.0", 1), ("1.0+dfsg", "1.0", 1), ("1.0a", "1.0+", -1),
    ("1.0-1ubuntu1", "1.0-1", 1), ("2.39-0ubuntu8.6", "2.39-0ubuntu8.10", -1), ("1.0~~", "1.0~", -1),
    ("3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3", 1), ("1:9.6p1-3ubuntu13.4", "1:9.6p1-3ubuntu13", 1), ("1.2.3", "1.2.3", 0),
])
def test_dpkg_ordering(a, b, sign):
    got = inventory.dpkg_compare(a, b)
    assert (got > 0) - (got < 0) == sign


def test_windows_versions_compare_numerically():
    assert inventory.numeric_compare("155.0.8059.85", "153.0.8010.36") > 0
    assert inventory.numeric_compare("7.1.9 (48550)", "7.1.10") < 0
    assert inventory.numeric_compare("155.0", "155") == 0
    assert inventory.numeric_key("unknown") == ()


# ---- OSV --------------------------------------------------------------------------------------------------------

def osv_zip(*records) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for r in records:
            z.writestr(r["id"] + ".json", json.dumps(r))
    return buf.getvalue()


def osv_rec(rid, pkg, events, eco=ECO, related=("CVE-2026-1000",)):
    return {"id": rid, "related": list(related),
            "affected": [{"package": {"name": pkg, "ecosystem": eco}, "ranges": [{"type": "ECOSYSTEM", "events": events}]}]}


DUMP = osv_zip(
    osv_rec("UBUNTU-CVE-2026-1000", "openssl", [{"introduced": "0"}, {"fixed": "3.0.13-0ubuntu3.4"}]),
    osv_rec("UBUNTU-CVE-2026-1001", "openssl", [{"introduced": "0"}, {"fixed": "3.0.13-0ubuntu3.4"}],
            eco="Ubuntu:14.04:LTS", related=("CVE-2026-1001",)),                 # another release in the dump
    osv_rec("UBUNTU-CVE-2026-1002", "curl", [{"introduced": "8.0"}, {"fixed": "8.5.0-2ubuntu10.4"},
                                             {"introduced": "9.0"}, {"last_affected": "9.1"}],
            related=("CVE-2026-1002",)),
    osv_rec("UBUNTU-CVE-2026-1003", "curl", [{"introduced": "0"}], related=("CVE-2026-1003",)),   # no fix yet
    osv_rec("UBUNTU-CVE-2026-1004", "vim", [{"introduced": "0"}, {"fixed": "9.9"}], related=("CVE-2026-1004",)),
)


@pytest.fixture
def feeds_dir(tmp_path):
    data, rows = vulns.build_osv_index(DUMP, ECO, {"openssl", "curl"})
    assert rows == 4   # openssl, curl's two ranges, curl's unfixed; vim not installed, 14.04 not this release
    (tmp_path / vulns.osv_file(ECO)).write_bytes(data)
    (tmp_path / "kev.json").write_text(json.dumps({"vulnerabilities": [
        {"cveID": "CVE-2026-1000", "vendorProject": "OpenSSL", "product": "OpenSSL", "dateAdded": "2026-10-01"},
        {"cveID": "CVE-2026-2000", "vendorProject": "Google", "product": "Chromium V8", "dateAdded": "2026-09-04",
         "knownRansomwareCampaignUse": "Known"}]}))
    (tmp_path / vulns.NVD_FILE).write_text(json.dumps({"CVE-2026-2000": {"fetched": T0, "ranges": [
        {"cpe": "google:chrome", "exact": "", "versionEndExcluding": "152.0.7977.82"}]}}))
    return tmp_path


def deb(source, version):
    return {"kind": "deb", "name": source, "version": version, "source": source, "product": ""}


def test_osv_match_ranges_and_kev_flag(feeds_dir):
    idx = vulns.VulnIndex.load(feeds_dir)
    old = idx.match(ECO, deb("openssl", "3.0.13-0ubuntu3"))
    assert [(h.cve, h.kev, h.fixed) for h in old] == [("CVE-2026-1000", True, "3.0.13-0ubuntu3.4")]
    assert idx.match(ECO, deb("openssl", "3.0.13-0ubuntu3.4")) == []          # the fixed version itself
    assert [h.cve for h in idx.match(ECO, deb("curl", "8.2"))] == ["CVE-2026-1002"]
    assert idx.match(ECO, deb("curl", "7.9")) == []                          # before introduced
    assert idx.match(ECO, deb("curl", "9.2")) == []                          # after last_affected
    assert [h.cve for h in idx.match(ECO, deb("curl", "9.0.5"))] == ["CVE-2026-1002"]
    assert idx.match("Debian:12", deb("openssl", "1")) == []                 # no feed for that release
    assert idx.match(None, deb("openssl", "1")) == []                        # OS not known yet


def test_windows_match_through_kev_and_nvd(feeds_dir):
    idx = vulns.VulnIndex.load(feeds_dir)
    chrome = {"kind": "windows", "name": "Google Chrome", "source": "", "product": "chrome"}
    hits = idx.match("windows", dict(chrome, version="150.0.1"))
    assert [(h.cve, h.kev, h.ransomware, h.fixed) for h in hits] == [("CVE-2026-2000", True, True, "152.0.7977.82")]
    assert idx.match("windows", dict(chrome, version="155.0.8059.85")) == []
    assert idx.match("windows", dict(chrome, product="", version="1")) == []


def test_load_with_nothing_downloaded(tmp_path):
    idx = vulns.VulnIndex.load(tmp_path)
    assert (idx.kev, idx.osv, idx.nvd) == ({}, {}, {})
    assert idx.match(ECO, deb("openssl", "1")) == []


# ---- NVD --------------------------------------------------------------------------------------------------------

NVD_RECORD = {"vulnerabilities": [{"cve": {"id": "CVE-2026-2000", "configurations": [{"nodes": [{"cpeMatch": [
    {"vulnerable": True, "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", "versionEndExcluding": "152.0.7977.82"},
    {"vulnerable": True, "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*"},                  # placeholder
    {"vulnerable": False, "criteria": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"},
    {"vulnerable": True, "criteria": "cpe:2.3:a:other:thing:*:*:*:*:*:*:*:*", "versionEndExcluding": "9"}]}]}]}}]}


def test_nvd_ranges_keep_only_the_products_ranges():
    assert vulns.nvd_ranges(NVD_RECORD, {"google:chrome"}) == [
        {"cpe": "google:chrome", "exact": "", "versionEndExcluding": "152.0.7977.82"}]


def test_update_nvd_paces_limits_and_survives_failures():
    calls, sleeps = [], []

    def fetch(url):
        calls.append(url)
        if url.endswith("CVE-2026-3"):
            raise OSError("rate limited")
        return json.dumps(NVD_RECORD).encode()

    wanted = {f"CVE-2026-{i}": {"google:chrome"} for i in range(1, 6)}
    cache, note = vulns.update_nvd({}, wanted, fetch, now=T0, limit=3, sleep=sleeps.append)
    assert len(calls) == 3 and len(sleeps) == 2 and sorted(cache) == ["CVE-2026-1", "CVE-2026-2"]
    assert "1 failed" in note and "3 still to fetch" in note
    cache, _ = vulns.update_nvd(cache, wanted, fetch, now=T0 + 60, limit=10, sleep=sleeps.append)
    assert "CVE-2026-1" not in [c.rsplit("=", 1)[1] for c in calls[3:]]   # cached ones are not asked again


# ---- update-feeds -----------------------------------------------------------------------------------------------

def vuln_fetch(url, timeout=None):
    if "cisa.gov" in url:
        return (b'{"vulnerabilities": [{"cveID": "CVE-2026-2000", "vendorProject": "Google", '
                b'"product": "Chromium V8", "dateAdded": "2026-09-04"}]}')
    if "osv-vulnerabilities" in url:
        assert "Ubuntu:24.04:LTS" in url
        return DUMP
    if "nvd.nist.gov" in url:
        return json.dumps(NVD_RECORD).encode()
    raise AssertionError(url)


def test_vuln_feeds_fetch_only_what_the_inventory_needs(tmp_path):
    report = feeds.vuln_feeds(tmp_path, {ECO: {"openssl"}, "windows": {"chrome", ""}}, vuln_fetch,
                              sleep=lambda s: None)
    assert report["kev.json"] == "ok, 1 known-exploited CVEs"
    assert report[vulns.osv_file(ECO)].startswith("ok, 1 ranges over 1 packages")
    assert report[vulns.NVD_FILE].startswith("ok, 1 CVE records")
    idx = vulns.VulnIndex.load(tmp_path)
    assert idx.nvd["CVE-2026-2000"]["ranges"][0]["versionEndExcluding"] == "152.0.7977.82"


def test_no_agents_means_kev_only(tmp_path):
    assert list(feeds.vuln_feeds(tmp_path, {}, vuln_fetch)) == ["kev.json"]


def test_blocked_network_keeps_the_old_files(tmp_path, feeds_dir):
    before = {p.name: p.read_bytes() for p in feeds_dir.iterdir()}

    def down(url, timeout=None):
        raise OSError("network down")

    report = feeds.vuln_feeds(feeds_dir, {ECO: {"openssl"}, "windows": {"chrome"}}, down, sleep=lambda s: None)
    assert report["kev.json"].startswith("failed") and report[vulns.osv_file(ECO)].startswith("failed")
    # NVD runs on the old kev.json; its one CVE is cached and fresh, so nothing is asked and nothing lost
    assert report[vulns.NVD_FILE].startswith("ok, 1 CVE records cached (0 new")
    assert {p.name: p.read_bytes() for p in feeds_dir.iterdir() if p.name != vulns.NVD_FILE} == \
        {k: v for k, v in before.items() if k != vulns.NVD_FILE}
    assert vulns.VulnIndex.load(feeds_dir).nvd["CVE-2026-2000"]["ranges"]


# ---- store and pipeline -----------------------------------------------------------------------------------------

def snapshot(name, rows, agent="agent-wsl", ts=T0):
    return {"_type": "osquery", "name": name, "hostIdentifier": agent, "action": "snapshot", "snapshot": rows,
            "ts": ts}


def test_pipeline_keeps_each_agents_latest_inventory():
    store = Store(":memory:")
    p = Pipeline([], Assets(), store)
    p.process(snapshot("os_version", [UBUNTU]))
    p.process(snapshot("software_deb", [{"name": "libssl3t64", "version": "1", "source": "openssl"},
                                        {"name": "curl", "version": "8", "source": ""}]))
    p.process(snapshot("software_programs", [{"name": "Google Chrome", "version": "150"}], agent="agent-win"))
    assert len(store.software()) == 3
    p.process(snapshot("software_deb", [{"name": "curl", "version": "9", "source": ""}], ts=T0 + 86400))
    assert [(r["name"], r["version"]) for r in store.software("agent-wsl")] == [("curl", "9")]   # replaced
    p.process(snapshot("software_deb", [], ts=T0 + 2 * 86400))                                  # failed read
    assert len(store.software("agent-wsl")) == 1
    # the Windows agent has no os_version row yet: its programs still count as the windows ecosystem
    assert store.ecosystems() == {ECO: {"curl"}, "windows": {"chrome"}}


def test_doctor_vuln_data_age(tmp_path):
    cfg = {"feeds_dir": str(tmp_path), "host_context": {"results_logs": ["x"]}}
    assert doctor.check_vuln_feeds(cfg, T0)[0].level == doctor.WARN          # nothing downloaded
    (tmp_path / "kev.json").write_text("{}")
    now = (tmp_path / "kev.json").stat().st_mtime
    assert doctor.check_vuln_feeds(cfg, now + 86400)[0].level == doctor.OK
    assert doctor.check_vuln_feeds(cfg, now + 20 * 86400)[0].level == doctor.WARN
    assert doctor.check_vuln_feeds({"feeds_dir": str(tmp_path)}, now) == []     # no agents: not worth a line


def test_index_file_is_small_text(feeds_dir):
    text = gzip.decompress((feeds_dir / vulns.osv_file(ECO)).read_bytes()).decode()
    assert text.startswith("# package") and "\topenssl\t" not in text and text.count("\n") == 5


def test_agent_config_has_every_inventory_query_as_a_daily_snapshot():
    from pathlib import Path
    sched = json.loads(Path(__file__).resolve().parents[1].joinpath("agents", "config", "osquery.conf").read_text(),
                       strict=False)["schedule"]
    for name in inventory.QUERIES:
        q = sched[name]
        assert q["snapshot"] is True and q["interval"] == 86400, name
    # privacy: the Windows query must not select an install path or source (per-user ones hold the user's name)
    cols = sched["software_programs"]["query"].lower().split("from")[0]
    assert not any(c in cols for c in ("install_location", "install_source", "uninstall_string", "identifying"))
