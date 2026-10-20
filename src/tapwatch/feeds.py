"""Public reference lists tapwatch reads offline. `tapwatch update-feeds` downloads them.

Downloads only: nothing about the house is sent. Each file is written to a temporary name
and renamed into place, so a failed download never leaves a half-written list behind.

  top-100k.csv       Tranco popular domains (rank,domain), for "is this domain widely used"
  oui.csv            IEEE MAC vendor registry, for new-device vendor names (R05)
  ip2asn-v4.tsv.gz   iptoasn.com IP range -> network (ASN) and country, for IoT drift (R02)
  public_suffix_list.dat  the Public Suffix List, for registrable domains (bbc.co.uk, not co.uk)
  iocs-adfection.tsv  AdFection / Candiru spyware indicators, tiered, for ioc_match
"""

from __future__ import annotations

import bisect
import gzip
import hashlib
import io
import ipaddress
import tarfile
import urllib.request
import zipfile
from pathlib import Path

SOURCES = {
    "top-100k.csv": "https://tranco-list.eu/top-1m.csv.zip",
    "oui.csv": "https://standards-oui.ieee.org/oui/oui.csv",
    "ip2asn-v4.tsv.gz": "https://iptoasn.com/data/ip2asn-v4.tsv.gz",
    "public_suffix_list.dat": "https://publicsuffix.org/list/public_suffix_list.dat",
}
TOP_N = 100_000

# Threat-intel lists, each pinned to one release and its published SHA-256. Every hit on a spyware tier always
# alerts, so a changed upstream list has to be read before tapwatch trusts it: bump the URL and hash together.
#   iocs-adfection.tsv  the AdFection / Candiru set curated by the zero-breach project (CC0) from The Citizen Lab's
#                       "Exposing AdFection" (2026-10-15), Confiant, Recorded Future and older Candiru reporting:
#                       indicator<TAB>tier<TAB>confidence<TAB>source per line (config.iocs reads the tiers)
IOC_FEEDS = {
    "iocs-adfection.tsv": ("https://github.com/interplains/zero-breach/releases/download/v0.1.6/adfection_iocs.txt",
                           "c9801e3ba37376535a676d9938d65550bcaa5478578cb80a6dd09eb2ac402d38"),
}

# Domain categories: the UT1 blacklists (Université Toulouse Capitole, CC BY-SA), one small archive per
# category with a `<category>/domains` member. Only the categories a home network's cases turn on; the
# adult, press, shopping and games lists are large and say nothing tapwatch needs, and maliciousness
# comes from the IOC feeds, not from here. The order is the precedence: a domain on two lists keeps the
# first, so the ones that matter to a security case come before the ones that explain traffic away
# (a cryptojacking host that also serves ads must not read as "an advertising site"). Measured
# 2026-10-16: these 21 archives total under 1 MB and 43k domains; `redirector` (web proxies and
# filter-bypass sites) was 130k domains on its own and is left out.
UT1_URL = "https://dsi.ut-capitole.fr/blacklists/download/{}.tar.gz"
UT1_TIMEOUT = 30  # s per archive: they are tiny, and `tapwatch init` waits on this
UT1_CATEGORIES = {
    "cryptojacking": "cryptojacking", "stalkerware": "stalkerware", "ddos": "ddos_service", "hacking": "hacking",
    "dialer": "dialer", "residential-proxies": "residential_proxy", "doh": "doh_resolver", "vpn": "vpn",
    "remote-control": "remote_control", "warez": "warez", "download": "download", "filehosting": "file_hosting",
    "shortener": "url_shortener", "publicite": "advertising", "marketingware": "marketing", "chat": "chat",
    "social_networks": "social", "webmail": "webmail", "audio-video": "media", "update": "software_update",
    "webhosting": "web_hosting",
}
CATEGORIES_FILE = "categories.tsv"


def _fetch(url: str, timeout: float = 120) -> bytes:
    if not url.startswith("https://"):
        raise ValueError("feeds are only fetched over https")
    req = urllib.request.Request(url, headers={"User-Agent": "tapwatch-feeds"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected -- fixed https URLs above
        return resp.read()


def _write(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".part")
    tmp.write_bytes(data)
    tmp.replace(path)


def _ut1_domains(archive: bytes, category: str) -> list[str]:
    """The `<category>/domains` member of a UT1 archive, read in memory: nothing is extracted to disk."""
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        member = tar.getmember(f"{category}/domains")
        fh = tar.extractfile(member)
        text = fh.read().decode("utf-8", errors="replace") if fh else ""
    return [line.strip().lower() for line in text.splitlines() if line.strip() and not line.startswith("#")]


def categories_feed(fetch=_fetch, existing: Path | None = None) -> tuple[bytes, str]:
    """Fetch the UT1 category archives and build `categories.tsv`: (file bytes, report line).
    A category that fails to download is named in the report and its rows are carried over from the
    `existing` file, so one bad mirror run does not silently drop a kind of site until next week."""
    table: dict[str, str] = {}
    failed = []
    lost_labels = set()
    for cat, label in UT1_CATEGORIES.items():
        try:
            data = fetch(UT1_URL.format(cat), UT1_TIMEOUT) if fetch is _fetch else fetch(UT1_URL.format(cat))
            for dom in _ut1_domains(data, cat):
                table.setdefault(dom, label)  # precedence: the first list in UT1_CATEGORIES wins
        except Exception as e:  # noqa: BLE001 - one list failing must not lose the others
            failed.append(f"{cat} ({e})")
            lost_labels.add(label)
    if lost_labels and existing and existing.exists():
        for line in existing.read_text(errors="replace").splitlines():
            dom, _, label = line.partition("\t")
            if label in lost_labels and dom and not dom.startswith("#"):
                table.setdefault(dom, label)
    if not table:
        raise OSError("no category list could be read: " + "; ".join(failed))
    body = "".join(f"{dom}\t{label}\n" for dom, label in sorted(table.items()))
    head = "# domain<TAB>category, from the UT1 blacklists (dsi.ut-capitole.fr, CC BY-SA); tapwatch update-feeds\n"
    ok = len(UT1_CATEGORIES) - len(failed)
    note = f"ok, {len(table):,} domains from {ok} of {len(UT1_CATEGORIES)} lists"
    if failed:
        note += "; failed: " + ", ".join(failed)
    return (head + body).encode(), note


def update(directory: str, fetch=_fetch) -> dict[str, str]:
    """Download every list into `directory`. Returns {file: "ok, N bytes" | "failed: reason"}."""
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    report = {}
    try:
        data, note = categories_feed(fetch, existing=d / CATEGORIES_FILE)
        _write(d / CATEGORIES_FILE, data)
        report[CATEGORIES_FILE] = note
    except Exception as e:  # noqa: BLE001 - report it, keep going
        report[CATEGORIES_FILE] = f"failed: {e}"
    for name, url in SOURCES.items():
        try:
            data = fetch(url)
            if name == "top-100k.csv":  # the zip holds the top million; keep the top 100k
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    text = z.read(z.namelist()[0]).decode()
                data = ("\n".join(text.splitlines()[:TOP_N]) + "\n").encode()
            _write(d / name, data)
            report[name] = f"ok, {len(data):,} bytes"
        except Exception as e:  # noqa: BLE001 - report every list, don't stop at the first failure
            report[name] = f"failed: {e}"
    for name, (url, sha256) in IOC_FEEDS.items():
        try:
            data = fetch(url)
            if hashlib.sha256(data).hexdigest() != sha256:
                raise ValueError("checksum does not match the pinned release, list not replaced")
            _write(d / name, data)
            rows = sum(1 for line in data.decode().splitlines() if line.strip() and not line.startswith("#"))
            report[name] = f"ok, {rows} indicators"
        except Exception as e:  # noqa: BLE001 - as above
            report[name] = f"failed: {e}"
    return report


class AsnTable:
    """IPv4 address -> (ASN, country) from iptoasn.com's range file, by binary search."""

    def __init__(self, starts: list[int], ends: list[int], asns: list[int], countries: list[str]):
        self.starts, self.ends, self.asns, self.countries = starts, ends, asns, countries

    @classmethod
    def load(cls, path: str | None) -> AsnTable | None:
        if not path or not Path(path).exists():
            return None
        opener = gzip.open if str(path).endswith(".gz") else open
        starts, ends, asns, countries = [], [], [], []
        with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 4 or parts[2] == "0":  # "Not routed"
                    continue
                try:
                    starts.append(int(ipaddress.IPv4Address(parts[0])))
                    ends.append(int(ipaddress.IPv4Address(parts[1])))
                except ValueError:
                    continue
                asns.append(int(parts[2]))
                countries.append(parts[3])
        return cls(starts, ends, asns, countries)

    def lookup(self, ip: str) -> tuple[int, str] | None:
        try:
            n = int(ipaddress.IPv4Address(ip))
        except ValueError:
            return None  # IPv6 isn't in this file
        i = bisect.bisect_right(self.starts, n) - 1
        if i >= 0 and n <= self.ends[i]:
            return self.asns[i], self.countries[i]
        return None
