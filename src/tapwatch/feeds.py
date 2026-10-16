"""Public reference lists tapwatch reads offline. `tapwatch update-feeds` downloads them.

Downloads only: nothing about the house is sent. Each file is written to a temporary name
and renamed into place, so a failed download never leaves a half-written list behind.

  top-100k.csv       Tranco popular domains (rank,domain), for "is this domain widely used"
  oui.csv            IEEE MAC vendor registry, for new-device vendor names (R05)
  ip2asn-v4.tsv.gz   iptoasn.com IP range -> network (ASN) and country, for IoT drift (R02)
"""

from __future__ import annotations

import bisect
import gzip
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
}
TOP_N = 100_000

# Domain categories: the UT1 blacklists (Université Toulouse Capitole, CC BY-SA), one small archive per
# category with a `<category>/domains` member. Only the categories a home network's cases turn on; the
# adult, press, shopping and games lists are large and say nothing tapwatch needs, and maliciousness
# comes from the IOC feeds, not from here. Measured 2026-10-16: these 22 archives total under 1 MB.
UT1_URL = "https://dsi.ut-capitole.fr/blacklists/download/{}.tar.gz"
UT1_CATEGORIES = {
    "publicite": "advertising", "marketingware": "marketing", "remote-control": "remote_control",
    "filehosting": "file_hosting", "download": "download", "warez": "warez", "vpn": "vpn",
    "doh": "doh_resolver", "residential-proxies": "residential_proxy", "redirector": "redirector",
    "shortener": "url_shortener", "chat": "chat", "social_networks": "social", "webmail": "webmail",
    "audio-video": "media", "update": "software_update", "webhosting": "web_hosting",
    "cryptojacking": "cryptojacking", "stalkerware": "stalkerware", "ddos": "ddos_service",
    "hacking": "hacking", "dialer": "dialer",
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


def categories_feed(fetch=_fetch) -> tuple[bytes, str]:
    """Fetch the UT1 category archives and build `categories.tsv`: (file bytes, report line).
    A category that fails to download is left out of this run's file and named in the report."""
    table: dict[str, str] = {}
    failed = []
    for cat, label in UT1_CATEGORIES.items():
        try:
            for dom in _ut1_domains(fetch(UT1_URL.format(cat)), cat):
                table.setdefault(dom, label)  # the first (more specific) list a domain appears in wins
        except Exception as e:  # noqa: BLE001 - one list failing must not lose the others
            failed.append(f"{cat} ({e})")
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
        data, note = categories_feed(fetch)
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
