"""Vulnerability data for the software inventory (#225): CISA KEV, OSV distro dumps and NVD version ranges.

Checking what is installed against vulnerabilities must not send the house's software list anywhere. OSV's query
API would; downloading the data does not. `tapwatch update-feeds` downloads:

  kev.json           CISA's Known Exploited Vulnerabilities catalog (CVE, vendor, product, date added), ~1.8 MB
  osv-<eco>.tsv.gz   OSV's dump for each Linux distro release an agent runs, cut down to the source packages the
                     inventory holds. The dump itself is not kept: Ubuntu 24.04's was a 142 MB zip (11,853
                     records) on 2026-10-20, read in memory once a run; the index is a few hundred KB.
  nvd-ranges.json    for the KEV CVEs on the Windows products inventory.WINDOWS_PRODUCTS maps, the affected
                     version ranges from NVD's CVE records, fetched by CVE id (public; says nothing about the
                     house). Without an API key NVD allows 5 requests in 30 s, so a run fetches at most NVD_PER_RUN
                     new records and the cache fills over a few runs; a cached record is kept NVD_KEEP_DAYS.

The OSV feed for an ecosystem is only fetched once an agent of that release has sent its inventory, and only
the packages it lists are kept, so a package installed after the last `update-feeds` is checked from the next one.
"""

from __future__ import annotations

import gzip
import io
import json
import re
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from . import inventory

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_URL = "https://osv-vulnerabilities.storage.googleapis.com/{}/all.zip"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}"
KEV_FILE = "kev.json"
NVD_FILE = "nvd-ranges.json"
NVD_PER_RUN = 60          # ~6.5 min without a key; the cache fills over runs
NVD_PAUSE = 6.5           # s between requests: NVD's public limit is 5 in 30 s
NVD_KEEP_DAYS = 90        # NVD revises CPE ranges after publication; refresh old records
OSV_TIMEOUT = 600         # s: a 142 MB download


def osv_file(eco: str) -> str:
    return "osv-" + re.sub(r"[^A-Za-z0-9.]+", "_", eco) + ".tsv.gz"


# ---- KEV --------------------------------------------------------------------------------------------------------

def parse_kev(data: bytes) -> dict[str, dict]:
    """CVE id -> {vendor, product, added, ransomware}. Raises on a file that is not the catalog."""
    doc = json.loads(data)
    vulns = doc["vulnerabilities"]
    if not isinstance(vulns, list) or not vulns:
        raise ValueError("no vulnerabilities in the KEV catalog")
    return {v["cveID"]: {"vendor": v.get("vendorProject", ""), "product": v.get("product", ""),
                         "added": v.get("dateAdded", ""),
                         "ransomware": v.get("knownRansomwareCampaignUse", "") == "Known"} for v in vulns}


def kev_for_products(kev: dict[str, dict]) -> dict[str, list[str]]:
    """Product key -> the KEV CVEs that name it (by KEV's vendor/product strings)."""
    out: dict[str, list[str]] = {}
    for p in inventory.WINDOWS_PRODUCTS:
        rv, rp = re.compile(p.kev_vendor, re.IGNORECASE), re.compile(p.kev_product, re.IGNORECASE)
        out[p.key] = sorted(c for c, k in kev.items() if rv.search(k["vendor"]) and rp.search(k["product"]))
    return out


# ---- OSV --------------------------------------------------------------------------------------------------------

def build_osv_index(archive: bytes, eco: str, packages: set[str]) -> tuple[bytes, int]:
    """OSV's all.zip for one ecosystem -> gzipped TSV of the ranges that touch `packages` (source package names):
    package, osv id, CVE ids, introduced, fixed, last_affected. Returns (bytes, rows). A dump carries entries for
    other releases too (Ubuntu 24.04's had 14.04's), so `affected` is filtered by the exact ecosystem."""
    rows: list[str] = []
    with zipfile.ZipFile(io.BytesIO(archive)) as z:
        for name in z.namelist():
            if not name.endswith(".json"):
                continue
            try:
                rec = json.loads(z.read(name))
            except (ValueError, KeyError):
                continue
            cves = sorted({c for c in [rec.get("id", "")] + list(rec.get("aliases") or []) + list(rec.get("related") or [])
                           + list(rec.get("upstream") or []) if c.startswith("CVE-")})
            for a in rec.get("affected") or []:
                pkg = a.get("package") or {}
                if pkg.get("ecosystem") != eco or pkg.get("name") not in packages:
                    continue
                for rg in a.get("ranges") or []:
                    if rg.get("type") != "ECOSYSTEM":
                        continue
                    intro, fixed, last = "0", "", ""
                    for ev in rg.get("events") or []:   # events are in order: an introduced opens a range
                        if "introduced" in ev:
                            if fixed or last:
                                rows.append(_osv_row(pkg["name"], rec["id"], cves, intro, fixed, last))
                            intro, fixed, last = ev["introduced"], "", ""
                        fixed = ev.get("fixed", fixed)
                        last = ev.get("last_affected", last)
                    rows.append(_osv_row(pkg["name"], rec["id"], cves, intro, fixed, last))
    head = f"# package\tosv\tcves\tintroduced\tfixed\tlast_affected  ({eco}, OSV; tapwatch update-feeds)\n"
    return gzip.compress((head + "".join(sorted(set(rows)))).encode()), len(set(rows))


def _osv_row(pkg: str, osv_id: str, cves: list[str], intro: str, fixed: str, last: str) -> str:
    clean = [s.replace("\t", " ").replace("\n", " ") for s in (pkg, osv_id, ",".join(cves), intro, fixed, last)]
    return "\t".join(clean) + "\n"


# ---- NVD --------------------------------------------------------------------------------------------------------

def nvd_ranges(record: dict, cpes: set[str]) -> list[dict]:
    """The vulnerable version ranges for `cpes` (vendor:product) in one NVD API 2.0 response."""
    out = []
    for v in record.get("vulnerabilities") or []:
        for conf in (v.get("cve") or {}).get("configurations") or []:
            for node in conf.get("nodes") or []:
                for m in node.get("cpeMatch") or []:
                    parts = str(m.get("criteria", "")).split(":")
                    if not m.get("vulnerable") or len(parts) < 6 or parts[2] != "a":
                        continue
                    vp = f"{parts[3]}:{parts[4]}"
                    if vp not in cpes:
                        continue
                    exact = parts[5] if parts[5] not in ("*", "-") else ""
                    r = {"cpe": vp, "exact": exact}
                    for k in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding",
                              "versionEndExcluding"):
                        if m.get(k):
                            r[k] = m[k]
                    if exact or len(r) > 2:   # a bare "every version" match is NVD's placeholder, not a range
                        out.append(r)
    return out


def update_nvd(cache: dict, wanted: dict[str, set[str]], fetch, now: float | None = None,
               pause: float = NVD_PAUSE, limit: int = NVD_PER_RUN, sleep=time.sleep) -> tuple[dict, str]:
    """Fetch NVD records for CVE ids in `wanted` (cve -> CPEs) that the cache lacks or holds too long.
    Returns (cache, report note)."""
    now = now or time.time()
    todo = sorted(c for c in wanted
                  if c not in cache or now - cache[c].get("fetched", 0) > NVD_KEEP_DAYS * 86400)
    done, failed = 0, 0
    for i, cve in enumerate(todo[:limit]):
        if i:
            sleep(pause)
        try:
            rec = json.loads(fetch(NVD_URL.format(cve)))
            cache[cve] = {"fetched": now, "ranges": nvd_ranges(rec, wanted[cve])}
            done += 1
        except Exception:  # noqa: BLE001 - one record failing keeps the rest; it is retried next run
            failed += 1
    left = len(todo) - done   # what the limit skipped, and what failed: both are asked next run
    note = f"ok, {len(cache)} CVE records cached ({done} new"
    note += f", {failed} failed" if failed else ""
    note += f", {left} still to fetch next run)" if left else ")"
    return cache, note


# ---- matching ---------------------------------------------------------------------------------------------------

@dataclass
class Hit:
    cve: str
    kev: bool
    kev_added: str = ""
    ransomware: bool = False
    fixed: str = ""          # the first version without this bug, when the data says


@dataclass
class VulnIndex:
    """KEV, the OSV indexes and the NVD ranges, loaded from the feeds directory."""
    kev: dict[str, dict] = field(default_factory=dict)
    osv: dict[str, dict[str, list[tuple]]] = field(default_factory=dict)   # eco -> package -> rows
    nvd: dict[str, dict] = field(default_factory=dict)
    kev_by_product: dict[str, list[str]] = field(default_factory=dict)
    loaded_at: float = 0.0

    @classmethod
    def load(cls, directory: str | Path | None) -> VulnIndex:
        idx = cls(loaded_at=time.time())
        if not directory:
            return idx
        d = Path(directory)
        try:
            idx.kev = parse_kev((d / KEV_FILE).read_bytes())
        except (OSError, ValueError, KeyError):
            idx.kev = {}
        idx.kev_by_product = kev_for_products(idx.kev)
        for p in d.glob("osv-*.tsv.gz"):
            try:
                with gzip.open(p, "rt", encoding="utf-8") as fh:
                    head = fh.readline()
                    m = re.search(r"\(([^,]+), OSV", head)
                    if not m:
                        continue
                    pkgs: dict[str, list[tuple]] = {}
                    for line in fh:
                        parts = line.rstrip("\n").split("\t")
                        if len(parts) == 6:
                            pkgs.setdefault(parts[0], []).append(tuple(parts[1:]))
                    idx.osv[m.group(1)] = pkgs
            except (OSError, EOFError):
                continue
        try:
            idx.nvd = json.loads((d / NVD_FILE).read_text())
        except (OSError, ValueError):
            idx.nvd = {}
        return idx

    def _kev(self, cve: str) -> dict | None:
        return self.kev.get(cve)

    def hit(self, cve: str, fixed: str = "") -> Hit:
        k = self._kev(cve)
        return Hit(cve, bool(k), (k or {}).get("added", ""), bool((k or {}).get("ransomware")), fixed)

    def match(self, eco: str | None, row: dict) -> list[Hit]:
        """The vulnerabilities that apply to one inventory row, one Hit per CVE (deduplicated)."""
        if eco == "windows":
            return self._match_windows(row)
        if not eco or eco not in self.osv:
            return []
        hits: dict[str, Hit] = {}
        version = row["version"]
        for osv_id, cves, intro, fixed, last in self.osv[eco].get(row.get("source") or row["name"], ()):
            if intro not in ("", "0") and inventory.dpkg_compare(version, intro) < 0:
                continue
            if fixed and inventory.dpkg_compare(version, fixed) >= 0:
                continue
            if last and inventory.dpkg_compare(version, last) > 0:
                continue
            if not fixed and not last:
                continue   # no fix released yet: OSV still lists it; the KEV case needs something to upgrade to
            for cve in (cves.split(",") if cves else [osv_id]):
                if cve not in hits:
                    hits[cve] = self.hit(cve, fixed)
        return list(hits.values())

    def _match_windows(self, row: dict) -> list[Hit]:
        key = row.get("product")
        if not key:
            return []
        prod = next(p for p in inventory.WINDOWS_PRODUCTS if p.key == key)
        out = []
        for cve in self.kev_by_product.get(key, ()):
            ranges = [r for r in (self.nvd.get(cve) or {}).get("ranges", ()) if r["cpe"] in prod.cpes]
            fixed = next((r.get("versionEndExcluding", "") for r in ranges if in_range(row["version"], r)), None)
            if fixed is not None:
                out.append(self.hit(cve, fixed))
        return out


def in_range(version: str, r: dict) -> bool:
    """An NVD cpeMatch range over dotted numeric versions."""
    cmp = inventory.numeric_compare
    if r.get("exact"):
        return cmp(version, r["exact"]) == 0
    if not inventory.numeric_key(version):
        return False
    if r.get("versionStartIncluding") and cmp(version, r["versionStartIncluding"]) < 0:
        return False
    if r.get("versionStartExcluding") and cmp(version, r["versionStartExcluding"]) <= 0:
        return False
    if r.get("versionEndIncluding") and cmp(version, r["versionEndIncluding"]) > 0:
        return False
    if r.get("versionEndExcluding") and cmp(version, r["versionEndExcluding"]) >= 0:
        return False
    return any(k in r for k in ("versionEndIncluding", "versionEndExcluding"))
