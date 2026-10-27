"""Public reference lists: download, atomic writes, ASN lookup, config defaults."""

import gzip
import hashlib
import io
import tarfile
import zipfile

import pytest

from tapwatch import config, feeds

# The AdFection list's shape: indicator<TAB>tier<TAB>confidence<TAB>source, '#' comments.
IOC_LIST = ("# as-of: 2026-10-18\n"
            "c2.example\tcc\tprimary\tcitizenlab\n"
            "ads.example\tdelivery\tprimary\tcitizenlab\n"
            "adtimizer.co\tdelivery\tprimary\tcitizenlab\n"
            "old.example\thistorical\tsecondary\teset\n"
            "198.51.100.66\tcandiru-ip\tprimary\trecordedfuture\n"
            "10.0.0.5\tcandiru-ip\tprimary\tbad-row\n"
            "localhost\tcc\tprimary\tbad-row\n"
            + "ab" * 32 + "\tsample\tprimary\tmsft\n").encode()


@pytest.fixture(autouse=True)
def pinned_ioc_list(monkeypatch):
    """Pin the IOC feed to the fixture above, the way feeds.IOC_FEEDS pins the real release."""
    monkeypatch.setattr(feeds, "IOC_FEEDS", {"iocs-adfection.tsv": ("https://iocs.example/adfection_iocs.txt",
                                                                   hashlib.sha256(IOC_LIST).hexdigest())})


def ut1_archive(cat, domains):
    """A UT1 category archive as the site serves it: `<cat>/domains`, one name per line, plus a usage note."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in ((f"{cat}/domains", ("\n".join(domains) + "\n").encode()), (f"{cat}/usage", b"black\n")):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


KEV = (b'{"catalogVersion": "2026.10.20", "count": 1, "vulnerabilities": [{"cveID": "CVE-2026-0001", '
       b'"vendorProject": "Google", "product": "Chromium V8", "dateAdded": "2026-10-01", '
       b'"knownRansomwareCampaignUse": "Unknown"}]}')


def fake_fetch(url):
    if "newly-registered-domains" in url:
        return b"fresh-shop.example\nanother-new.example\n"
    if "cisa.gov" in url:
        return KEV
    if url.startswith("https://iocs.example/"):
        return IOC_LIST
    if "ut-capitole" in url:
        cat = url.rsplit("/", 1)[1].removesuffix(".tar.gz")
        return ut1_archive(cat, [f"{cat}.example", f"two.{cat}.example"])
    if url.endswith(".zip"):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("top-1m.csv", "".join(f"{i},site{i}.example\n" for i in range(1, 150_001)))
        return buf.getvalue()
    if url.endswith("oui.csv"):
        return b"Registry,Assignment,Organization Name,Organization Address\nMA-L,3C7C3F,Example Inc.,x\n"
    if url.endswith("public_suffix_list.dat"):
        return b"// ===BEGIN ICANN DOMAINS===\ncom\nco.uk\n// ===END ICANN DOMAINS===\n"
    if url.endswith(".gz"):
        return gzip.compress(b"1.0.0.0\t1.0.0.255\t13335\tUS\tEXAMPLE\n1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n")
    raise AssertionError(url)


def test_update_downloads_all_three_and_keeps_the_top_100k(tmp_path):
    report = feeds.update(str(tmp_path), fetch=fake_fetch)
    assert all(v.startswith("ok") for v in report.values()), report
    assert len((tmp_path / "top-100k.csv").read_text().splitlines()) == 100_000
    assert not list(tmp_path.glob("*.part"))


def test_a_failed_download_is_reported_and_leaves_the_old_file(tmp_path):
    (tmp_path / "oui.csv").write_text("old\n")

    def flaky(url):
        if url.endswith("oui.csv"):
            raise OSError("network down")
        return fake_fetch(url)

    report = feeds.update(str(tmp_path), fetch=flaky)
    assert report["oui.csv"].startswith("failed") and (tmp_path / "oui.csv").read_text() == "old\n"


def test_only_https_is_fetched():
    import pytest
    with pytest.raises(ValueError):
        feeds._fetch("http://example.com/list.csv")


def test_asn_lookup_skips_unrouted_and_ipv6(tmp_path):
    feeds.update(str(tmp_path), fetch=fake_fetch)
    t = feeds.AsnTable.load(str(tmp_path / "ip2asn-v4.tsv.gz"))
    assert t.lookup("1.0.0.7") == (13335, "US")
    assert t.network("1.0.0.7") == {"asn": 13335, "network": "EXAMPLE", "country": "US"} and t.network("1.0.2.1") is None
    assert t.lookup("1.0.2.1") is None and t.lookup("2001:db8::1") is None and t.lookup("9.9.9.9") is None
    assert feeds.AsnTable.load(None) is None


def test_config_points_unset_lists_at_feeds_dir(tmp_path):
    (tmp_path / "oui.csv").write_text("x")
    cfg = config.with_feeds({"feeds_dir": str(tmp_path), "popular_domains_file": "/mine.csv"})
    assert cfg["oui_file"] == str(tmp_path / "oui.csv") and cfg["popular_domains_file"] == "/mine.csv"
    assert "asn_file" not in cfg


def test_missing_feeds_names_what_the_detectors_lose(tmp_path):
    msg = config.missing_feeds(config.with_feeds({"feeds_dir": str(tmp_path)}))
    assert msg.startswith("public lists not downloaded, run `tapwatch update-feeds`")
    assert "popular domains" in msg and "MAC vendors" in msg and "IP-to-network" in msg
    (tmp_path / "top-100k.csv").write_text("x")
    assert "popular domains" not in config.missing_feeds(config.with_feeds({"feeds_dir": str(tmp_path)}))
    assert "domain categories" in msg
    full = {"popular_domains_file": "a", "oui_file": "b", "asn_file": "c", "categories_file": "d"}
    assert config.missing_feeds(full) == ""


def test_update_builds_the_category_file_from_the_ut1_archives(tmp_path):
    report = feeds.update(str(tmp_path), fetch=fake_fetch)
    n = len(feeds.UT1_CATEGORIES)
    assert report["categories.tsv"] == f"ok, {2 * n:,} domains from {n} of {n} lists"
    lines = (tmp_path / "categories.tsv").read_text().splitlines()
    assert lines[0].startswith("#") and "publicite.example\tadvertising" in lines and "two.vpn.example\tvpn" in lines
    assert len(lines) == 2 * n + 1


def test_a_failed_category_list_is_named_and_the_others_are_kept(tmp_path):
    def flaky(url):
        if url.endswith("/vpn.tar.gz"):
            raise OSError("network down")
        return fake_fetch(url)

    report = feeds.update(str(tmp_path), fetch=flaky)
    assert report["categories.tsv"].startswith("ok,") and "failed: vpn (network down)" in report["categories.tsv"]
    text = (tmp_path / "categories.tsv").read_text()
    assert "vpn.example" not in text and "publicite.example\tadvertising" in text
    # last week's file still had the vpn rows: they are carried over rather than silently dropped
    (tmp_path / "categories.tsv").write_text("# old\nold-vpn.example\tvpn\nold-ads.example\tadvertising\n")
    feeds.update(str(tmp_path), fetch=flaky)
    text = (tmp_path / "categories.tsv").read_text()
    assert "old-vpn.example\tvpn" in text and "old-ads.example" not in text   # only the failed list's rows


def test_a_domain_on_two_lists_keeps_the_security_relevant_one():
    def both(url):
        cat = url.rsplit("/", 1)[1].removesuffix(".tar.gz")
        return ut1_archive(cat, ["shared.example"])

    data, _ = feeds.categories_feed(fetch=both)
    assert "shared.example\tcryptojacking" in data.decode()   # not "advertising"


def test_categories_load_and_match_by_suffix(tmp_path):
    from tapwatch import categories
    f = tmp_path / "categories.tsv"
    f.write_text("# header\nads.example\tadvertising\nTube.Example\tmedia\n")
    try:
        assert categories.load(str(f)) == 2
        assert categories.category("x.y.ads.example") == "advertising" and categories.category("ADS.example") == "advertising"
        assert categories.category("tube.example.") == "media"
        assert categories.category("notads.example") == "" and categories.category("example") == "" and categories.category("") == ""
        assert categories.load(None) == 0 and categories.category("ads.example") == ""   # no file: nothing listed
    finally:
        categories.set_categories({})
    assert config.with_feeds({"feeds_dir": str(tmp_path)})["categories_file"] == str(f)


def test_the_ioc_list_is_written_only_when_it_matches_the_pinned_checksum(tmp_path):
    report = feeds.update(str(tmp_path), fetch=fake_fetch)
    assert report["iocs-adfection.tsv"] == "ok, 8 indicators"
    (tmp_path / "iocs-adfection.tsv").write_bytes(b"c2.example\tcc\n")

    def tampered(url):
        return IOC_LIST + b"google.com\tcc\tprimary\tx\n" if url.startswith("https://iocs.") else fake_fetch(url)

    report = feeds.update(str(tmp_path), fetch=tampered)
    assert report["iocs-adfection.tsv"].startswith("failed: checksum")
    assert (tmp_path / "iocs-adfection.tsv").read_bytes() == b"c2.example\tcc\n"  # the old list stays


def test_iocs_reads_your_list_and_the_tiered_feed(tmp_path):
    feeds.update(str(tmp_path), fetch=fake_fetch)
    (tmp_path / "mine.txt").write_text("bad.example  # from a vendor report\n203.0.113.9\n10.0.0.7\n")
    cfg = config.with_feeds({"feeds_dir": str(tmp_path), "ioc_file": str(tmp_path / "mine.txt")})
    ips, domains, labels = config.iocs(cfg)
    assert ips == {"203.0.113.9", "10.0.0.7", "198.51.100.66"}  # your own LAN entry is kept; the feed's is not
    assert domains == {"bad.example", "c2.example", "ads.example", "old.example"}  # no hash, no dotless name, no bare adtimizer.co
    assert labels["c2.example"] == {"list": "AdFection / Candiru", "tier": "cc", "confidence": "primary",
                                    "source": "citizenlab"}
    assert labels["198.51.100.66"]["tier"] == "candiru-ip" and "bad.example" not in labels


def test_nrd_keeps_a_rolling_30_days_and_finds_archived_days(tmp_path):
    import urllib.error
    from datetime import date

    asked = []

    def fetch(url):
        asked.append(url)
        day = url.rsplit("/", 1)[1][:10]
        if day == "2026-10-20":
            raise urllib.error.HTTPError(url, 404, "missing", {}, None)        # not published at all
        if "/archive/" not in url and day < "2026-10-15":
            raise urllib.error.HTTPError(url, 404, "moved", {}, None)          # older days sit in archive/
        return f"domain\nNew-{day}.Example.\n\nnot a domain!\n".encode()

    nrd = tmp_path / "nrd"
    nrd.mkdir()
    (nrd / "2026-09-01.txt").write_text("too-old.example\n")                 # older than 30 days: deleted
    note = feeds.nrd_feed(tmp_path, fetch, today=date(2026, 10, 27))
    names = sorted(p.name for p in nrd.glob("*.txt"))
    assert len(names) == 29 and names[0] == "2026-09-27.txt" and names[-1] == "2026-10-26.txt"
    assert "2026-10-20.txt" not in names and "2026-09-01.txt" not in names
    assert (nrd / "2026-10-01.txt").read_text() == "new-2026-10-01.example\n"   # lower-cased, junk lines dropped
    assert "29 days" in note and "1 not published" in note
    assert any("/archive/2026-10-01" in u for u in asked)
    asked.clear()
    feeds.nrd_feed(tmp_path, fetch, today=date(2026, 10, 27))
    assert [u.rsplit("/", 1)[1][:10] for u in asked] == ["2026-10-20", "2026-10-20"]   # only the missing day again
    (nrd / "my-notes.txt").write_text("keep me\n")                         # not one of its own files: left alone
    feeds.nrd_feed(tmp_path, fetch, today=date(2026, 11, 27))
    assert (nrd / "my-notes.txt").exists() and not (nrd / "2026-10-01.txt").exists()


def test_nrd_never_caches_an_empty_day_and_one_error_skips_only_that_day(tmp_path):
    import urllib.error
    from datetime import date

    def fetch(url):
        day = url.rsplit("/", 1)[1][:10]
        if day == "2026-10-26":
            return b"<html>rate limited</html>"                             # a 200 with no domain names in it
        if day == "2026-10-25":
            raise urllib.error.HTTPError(url, 503, "busy", {}, None)
        return f"ok-{day}.example\n".encode()

    note = feeds.nrd_feed(tmp_path, fetch, today=date(2026, 10, 27))
    names = {p.name for p in (tmp_path / "nrd").iterdir()}
    assert "2026-10-26.txt" not in names and "2026-10-25.txt" not in names and len(names) == 28
    assert "1 not published" in note and "1 failed" in note
