"""Public reference lists: download, atomic writes, ASN lookup, config defaults."""

import gzip
import io
import tarfile
import zipfile

from tapwatch import config, feeds


def ut1_archive(cat, domains):
    """A UT1 category archive as the site serves it: `<cat>/domains`, one name per line, plus a usage note."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in ((f"{cat}/domains", ("\n".join(domains) + "\n").encode()), (f"{cat}/usage", b"black\n")):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def fake_fetch(url):
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
