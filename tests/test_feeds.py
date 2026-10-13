"""Public reference lists: download, atomic writes, ASN lookup, config defaults."""

import gzip
import io
import zipfile

from tapwatch import config, feeds


def fake_fetch(url):
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
