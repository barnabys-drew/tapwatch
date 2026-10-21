"""Software inventory from the endpoint agents (#224): what is installed on each PC, at which version.

The agents snapshot their installed software once a day (agents/config/osquery.conf `software_*`): Windows
`programs` (name, version, publisher, nothing else: install paths of per-user programs hold the user's name),
Linux `deb_packages` / `rpm_packages` (name, version, source package, arch) and macOS `homebrew_packages`. A
snapshot is the full list, so each one replaces the agent's previous inventory (`Store.replace_software`).

Inventory is per agent (osquery's `hostIdentifier`), not per address: the WSL distro and the Windows host are two
agents on one PC, with different software. Each agent's `os_version` snapshot decides which vulnerability
ecosystem its packages belong to (`ecosystem`), at match time, so a package list that arrives before the agent's
first `os_version` row is not lost.

Windows has no package ecosystem. The programs that known-exploited bugs keep landing in (browsers, PDF readers,
Java, archivers, Zoom...) are mapped by name to the NVD product (CPE vendor:product) and the CISA KEV
vendor/product strings that name them (`WINDOWS_PRODUCTS`); everything else stays in the inventory but is not
checked. Windows itself (patched through Windows Update by build number) is not covered.

Measured 2026-10-20 on the main PC: Windows `programs` 255 rows, 0.76 s, 27 KB per snapshot; WSL `deb_packages`
1,081 rows, 0.25 s, 94 KB.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

QUERIES = {"software_programs": "windows", "software_deb": "deb", "software_rpm": "rpm",
           "software_brew": "brew"}
OS_QUERY = "os_version"


@dataclass(frozen=True)
class Product:
    """A Windows program the vulnerability check knows: how to find it, and what NVD and KEV call it."""
    key: str             # stable id, the handle a case and a suppression use: "chrome"
    label: str           # how a case names it: "Google Chrome"
    program: str         # regex over the `programs` name, case-insensitive
    cpes: tuple[str, ...]          # NVD CPE vendor:product pairs whose version ranges apply
    kev_vendor: str                # regex over KEV vendorProject
    kev_product: str               # regex over KEV product
    exes: tuple[str, ...] = ()     # its executables (lower case), for "the vulnerable program itself did this" (#227)


# The products KEV keeps listing that a home PC runs. Order matters only for readability; names are anchored so
# "Google Chrome" does not also match "Google Chrome Remote Desktop Host". Edge: Chromium bugs are filed against
# google:chrome in NVD, and only some name edge_chromium too, so an old Edge is under-reported (it updates itself).
WINDOWS_PRODUCTS: tuple[Product, ...] = (
    Product("chrome", "Google Chrome", r"^google chrome$", ("google:chrome",), r"^google$", r"chrom", ("chrome.exe",)),
    Product("edge", "Microsoft Edge", r"^microsoft edge$", ("microsoft:edge_chromium", "microsoft:edge"),
            r"^microsoft$", r"\bedge\b", ("msedge.exe",)),
    Product("firefox", "Mozilla Firefox", r"^mozilla firefox\b", ("mozilla:firefox",), r"^mozilla$", r"firefox", ("firefox.exe",)),
    Product("acrobat", "Adobe Acrobat / Reader", r"^adobe acrobat|^adobe reader|acrobat reader",
            ("adobe:acrobat_reader_dc", "adobe:acrobat_dc", "adobe:acrobat_reader", "adobe:acrobat"),
            r"^adobe$", r"acrobat|reader", ("acrord32.exe", "acrobat.exe")),
    Product("java", "Oracle Java", r"^java( \d+)?( update \d+)?|^java\(tm\)|^java se", ("oracle:jre", "oracle:jdk"),
            r"^oracle$", r"java|jre|jdk", ("java.exe", "javaw.exe", "javaws.exe")),
    Product("7zip", "7-Zip", r"^7-zip\b", ("7-zip:7-zip",), r"^7-zip$", r"7-zip", ("7z.exe", "7zfm.exe", "7zg.exe")),
    Product("winrar", "WinRAR", r"^winrar\b", ("rarlab:winrar",), r"^rarlab$", r"winrar", ("winrar.exe", "rar.exe", "unrar.exe")),
    Product("zoom", "Zoom", r"^zoom( workplace| meetings)?$|^zoom$",
            ("zoom:zoom", "zoom:meetings", "zoom:workplace_desktop", "zoom:workplace"), r"^zoom", r".", ("zoom.exe",)),
    Product("vlc", "VLC media player", r"^vlc media player", ("videolan:vlc_media_player",), r"^videolan$", r"vlc", ("vlc.exe",)),
    Product("notepadpp", "Notepad++", r"^notepad\+\+", ("notepad-plus-plus:notepad\\+\\+",), r"notepad", r"notepad",
            ("notepad++.exe",)),
    Product("putty", "PuTTY", r"^putty\b", ("putty:putty", "simon_tatham:putty"), r"putty|tatham", r"putty",
            ("putty.exe",)),
    Product("teams", "Microsoft Teams", r"^microsoft teams\b", ("microsoft:teams",), r"^microsoft$", r"\bteams\b", ("ms-teams.exe", "teams.exe")),
    Product("nodejs", "Node.js", r"^node\.js$", ("nodejs:node.js",), r"node", r"node", ("node.exe",)),
)
_PROGRAM_RES = [(p, re.compile(p.program, re.IGNORECASE)) for p in WINDOWS_PRODUCTS]


PRODUCTS = {p.key: p for p in WINDOWS_PRODUCTS}


def product_of(program_name: str) -> Product | None:
    name = (program_name or "").strip()
    return next((p for p, rx in _PROGRAM_RES if rx.search(name)), None)


def normalise(query: str, rows: list[dict]) -> list[dict]:
    """Agent rows -> inventory rows {kind, name, version, source, product}. Only the columns named here are kept:
    `programs` carries install paths in other columns, and a per-user install's path has the user's name in it."""
    kind = QUERIES.get(query)
    out: list[dict] = []
    seen: set[tuple] = set()
    for r in rows:
        name, version = str(r.get("name") or "").strip()[:200], str(r.get("version") or "").strip()[:80]
        if not name:
            continue
        source = ""
        product = ""
        if kind == "deb":
            # osquery's `source` is the source package, sometimes with its own version in parentheses
            source = re.sub(r"\s*\(.*\)$", "", str(r.get("source") or "")).strip() or name
        elif kind == "rpm":
            rel = str(r.get("release") or "").strip()
            version = f"{version}-{rel}" if rel else version
            source = re.sub(r"-[^-]+-[^-]+\.src\.rpm$", "", str(r.get("source") or "")).strip() or name
        elif kind == "windows":
            p = product_of(name)
            product = p.key if p else ""
        key = (name, version)
        if key in seen:
            continue
        seen.add(key)
        out.append({"kind": kind, "name": name, "version": version, "source": source, "product": product})
    return out


def ecosystem(kind: str, os_row: dict | None) -> str | None:
    """The OSV ecosystem an agent's packages belong to: `Ubuntu:24.04:LTS`, `Debian:12`, or "windows". None when
    the agent's OS is not known yet, or has no feed tapwatch reads (rpm and Homebrew: inventory only, for now)."""
    if kind == "windows":
        return "windows"
    if kind != "deb" or not os_row:
        return None
    name = str(os_row.get("name") or "").lower()
    version = str(os_row.get("version") or "")
    m = re.match(r"(\d+)(?:\.(\d+))?", version)
    if not m:
        return None
    if "ubuntu" in name:
        release = f"{m.group(1)}.{(m.group(2) or '0').zfill(2)}"
        return f"Ubuntu:{release}:LTS" if "lts" in version.lower() else f"Ubuntu:{release}"
    if "debian" in name:
        return f"Debian:{m.group(1)}"
    return None


# ---- version ordering ------------------------------------------------------------------------------------------

def _dpkg_order(c: str) -> int:
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _dpkg_part(a: str, b: str) -> int:
    """dpkg's comparison of an upstream version or revision: alternating non-digit and digit runs; in non-digit
    runs letters sort before symbols and `~` before everything, even the end of the string."""
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _dpkg_order(a[i]) if i < len(a) and not a[i].isdigit() else 0
            bc = _dpkg_order(b[j]) if j < len(b) and not b[j].isdigit() else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def _dpkg_split(v: str) -> tuple[int, str, str]:
    epoch, _, rest = v.partition(":") if ":" in v else ("0", "", v)
    upstream, _, revision = rest.rpartition("-") if "-" in rest else (rest, "", "")
    try:
        return int(epoch or 0), upstream, revision
    except ValueError:
        return 0, rest, ""


def dpkg_compare(a: str, b: str) -> int:
    """<0, 0, >0 as Debian version a sorts before, equal to, after b (dpkg --compare-versions)."""
    ea, ua, ra = _dpkg_split(a)
    eb, ub, rb = _dpkg_split(b)
    if ea != eb:
        return ea - eb
    return _dpkg_part(ua, ub) or _dpkg_part(ra, rb)


def numeric_key(v: str) -> tuple[int, ...]:
    """Windows program versions: the leading dotted numbers ("7.1.9 (48550)" -> 7, 1, 9). Vendors pad
    differently (155.0.8059.85 vs 155.0.8059), so trailing zeros do not count."""
    m = re.match(r"\s*v?(\d+(?:\.\d+)*)", v or "")
    if not m:
        return ()
    parts = [int(x) for x in m.group(1).split(".")]
    while parts and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def numeric_compare(a: str, b: str) -> int:
    ka, kb = numeric_key(a), numeric_key(b)
    return (ka > kb) - (ka < kb)
