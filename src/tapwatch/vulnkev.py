"""R48 `vuln_kev`: a device runs software with a known-exploited vulnerability (#226), and what that does to the
device's other cases (#227).

Reads the endpoint agents' daily software snapshots (inventory.py, #224) against the KEV, OSV and NVD data that
`update-feeds` downloads (vulns.py, #225). Nothing leaves the box and Jev is never asked: whether a version is in a
vulnerable range is a fact.

- A product (a mapped Windows program, or a Linux source package) with at least one CVE on CISA's KEV list and a
  fixed version is a case: one per (agent, product), DIGEST at severity 3, code-routed. Patching is not a 2 a.m.
  task, and #58 asks for these in the digest.
- It is raised again only when a KEV CVE it did not list before matches, or 14 days pass and it is still unpatched.
- A product whose next snapshot is outside every range (patched, or uninstalled) is "resolved": the pipeline closes
  its open case with a note saying so, audited as `tapwatch`.
- OSV-only matches (fixed bugs nobody is known to exploit) raise no case; their count per agent is kept as a fact
  (`osv_only`) that R48's cases and `tapwatch software --vulns` show.

Expected false positives: version-range errors in the data; a portable or leftover copy of a program that is not
actually run (the inventory says installed, not running); a browser that updated in memory before the day's
snapshot ran (the next snapshot resolves it); Debian/Ubuntu backports are accounted for by OSV's distro ecosystems,
the Windows ranges (NVD) are not distro-aware and need none.

#227 (`DeviceKev`): when any case is handled, an open R48 case on the same device adds the fact `device_kev`
(products, CVE count) and raises a digest-level `base_severity` (2 or more) by one, to at most 5; log-level cases
stay where they are (an ordinary new domain is severity 1, and there are hundreds a week); a host case whose program *is* the
vulnerable product (its executable, inventory.Product.exes) gets `min_route: alert`, the floor the router already
honours. It never touches `must_alert` and never lowers anything; a closed or suppressed R48 case does not count.
"""

from __future__ import annotations

import functools
import json
import os
import time
from pathlib import Path
from typing import ClassVar

from . import inventory, vulns
from .detectors import Detector
from .models import Case, device_id

NAME = "vuln_kev"
REPEAT_DAYS = 14
DAY = 86400.0
CVES_SHOWN = 5


class VulnKev(Detector):
    name = NAME
    PERSIST: ClassVar[tuple[str, ...]] = ("agents_os", "reported", "osv_only")

    def __init__(self, state, feeds_dir: str | None = None, index: vulns.VulnIndex | None = None,
                 repeat_days: float = REPEAT_DAYS):
        self.state = state                                # hostrules.EndpointState: the PC's address for the case
        self.feeds_dir = feeds_dir
        self._index, self._index_mtime = index, None
        self.repeat = repeat_days * DAY
        self.agents_os: dict[str, dict] = {}              # agent -> its os_version row (name, version)
        self.reported: dict[str, dict] = {}               # "agent|product" -> {cves, ts, label, version}
        self.osv_only: dict[str, dict] = {}               # agent -> {cves, packages, ts}: fixed bugs not on KEV
        self.resolved: list[dict] = []                    # fixed since the last snapshot; Pipeline closes their cases

    def index(self) -> vulns.VulnIndex:
        """The vulnerability data, reloaded when update-feeds has written a newer kev.json."""
        if self.feeds_dir:
            try:
                mtime = os.stat(Path(self.feeds_dir) / vulns.KEV_FILE).st_mtime
            except OSError:
                mtime = None
            if self._index is None or mtime != self._index_mtime:
                self._index, self._index_mtime = vulns.VulnIndex.load(self.feeds_dir), mtime
        return self._index or vulns.VulnIndex()

    def feed(self, rec: dict) -> list[Case]:
        if rec.get("_type") != "osquery" or rec.get("action") != "snapshot":
            return []
        name, agent = rec.get("name"), str(rec.get("hostIdentifier") or "")
        rows = [r for r in rec.get("snapshot") or () if isinstance(r, dict)]
        if not agent or not rows:
            return []   # an empty snapshot is a failed table read, not "everything uninstalled"
        if name == inventory.OS_QUERY:
            self.agents_os[agent] = {"name": str(rows[0].get("name") or ""), "version": str(rows[0].get("version") or "")}
            return []
        if name not in inventory.QUERIES:
            return []
        kind = inventory.QUERIES[name]
        eco = inventory.ecosystem(kind, self.agents_os.get(agent))
        idx = self.index()
        if not eco or not idx.kev:
            return []   # OS not known yet, or nothing downloaded: no verdict either way, so nothing is resolved
        return self.check(agent, kind, eco, inventory.normalise(name, rows), float(rec.get("ts") or time.time()), idx)

    def check(self, agent: str, kind: str, eco: str, rows: list[dict], ts: float, idx: vulns.VulnIndex) -> list[Case]:
        groups: dict[str, dict] = {}
        versions: dict[str, set[str]] = {}
        for r in rows:
            key = r["product"] if kind == "windows" else (r["source"] or r["name"])
            if key:
                versions.setdefault(key, set()).add(r["version"])
            hits = idx.match(eco, r)
            if not hits:
                continue
            g = groups.setdefault(key, {"label": inventory.PRODUCTS[key].label if kind == "windows" else key,
                                        "hits": {}, "versions": set()})
            g["versions"].add(r["version"])
            for h in hits:
                g["hits"].setdefault(h.cve, h)
        kev = {k: g for k, g in groups.items() if any(h.kev for h in g["hits"].values())}
        self.osv_only[agent] = {"cves": sum(len(g["hits"]) for k, g in groups.items() if k not in kev),
                                "packages": len(groups) - len(kev), "ts": ts}
        prefix = agent + "|"
        for rk in [k for k in self.reported if k.startswith(prefix) and k[len(prefix):] not in kev]:
            was = self.reported.pop(rk)
            product = rk[len(prefix):]
            now = sorted(versions.get(product, ()))
            self.resolved.append({"agent": agent, "product": product, "label": was.get("label", product),
                                  "was": was.get("version", ""), "now": ", ".join(now) or "", "ts": ts})
        out = []
        for key, g in sorted(kev.items()):
            out += self._case(agent, key, g, eco, ts)
        return out

    def _case(self, agent: str, key: str, g: dict, eco: str, ts: float) -> list[Case]:
        kev = sorted((h for h in g["hits"].values() if h.kev), key=lambda h: (h.kev_added, h.cve), reverse=True)
        cves = sorted(h.cve for h in kev)
        rk = f"{agent}|{key}"
        was = self.reported.get(rk)
        new = set(cves) - set(was["cves"]) if was else set(cves)
        if was and not new and ts - was["ts"] < self.repeat:
            return []
        version = ", ".join(sorted(g["versions"]))
        self.reported[rk] = {"cves": cves, "ts": ts, "label": g["label"], "version": version}
        fixed = [h.fixed for h in kev if h.fixed]
        fixed_in = max(fixed, key=inventory.numeric_key if eco == "windows" else _dpkg_key) if fixed else ""
        os_row = self.agents_os.get(agent) or {}
        facts = {
            "source": "endpoint", "agent": agent, "os": f"{os_row.get('name', '')} {os_row.get('version', '')}".strip(),
            "ecosystem": eco, "product": g["label"][:80], "product_key": key, "version": version[:80],
            "kev_cves": len(cves), "cves": [h.cve for h in kev[:CVES_SHOWN]],
            "kev_added_oldest": min(h.kev_added for h in kev), "kev_added_newest": max(h.kev_added for h in kev),
            "ransomware": any(h.ransomware for h in kev), "fixed_in": fixed_in[:60],
            "other_cves": len(g["hits"]) - len(cves),
            "osv_only": dict(self.osv_only.get(agent) or {}),
            "repeat": ("new known-exploited CVE" if was and new else "still unpatched after "
                       f"{round((ts - was['ts']) / DAY)} days" if was else ""),
        }
        title = "Software with a known-exploited vulnerability" + (" (still unpatched)" if was and not new else "")
        return [Case(self.name, self.state.host, ts, title, facts, [g["label"][:80]], base_severity=3)]


_dpkg_key = functools.cmp_to_key(inventory.dpkg_compare)


def close_resolved(store, det: VulnKev) -> int:
    """Close the open R48 cases whose product the latest inventory shows outside every range. Returns how many."""
    closed = 0
    while det.resolved:
        r = det.resolved.pop(0)
        for row in store.db.execute("SELECT id, facts FROM cases WHERE detector=? AND status != 'closed'", (NAME,)):
            f = json.loads(row["facts"])
            if f.get("agent") != r["agent"] or f.get("product_key") != r["product"]:
                continue
            when = time.strftime("%Y-%m-%d", time.localtime(r["ts"]))
            now = f"{r['label']} {r['now']}" if r["now"] else f"{r['label']} is no longer installed"
            store.update_case(row["id"], "tapwatch", status="closed", disposition="true_positive",
                              note=f"fixed: the {when} inventory shows {now}, outside every known-exploited range "
                                   f"(was {r['was']})")
            closed += 1
    return closed


class DeviceKev:
    """#227: what an open R48 case on a device does to that device's other cases."""

    def __init__(self, store):
        self.store = store

    def open_on(self, case: Case) -> list[dict]:
        dev = device_id(case.host, case.facts)
        out = []
        for row in self.store.db.execute(
                "SELECT host, facts FROM cases WHERE detector=? AND status != 'closed' AND route != 'log'", (NAME,)):
            f = json.loads(row["facts"])
            if device_id(row["host"], f) == dev or row["host"] == case.host:
                out.append(f)
        return out

    def apply(self, case: Case) -> bool:
        """Adds the facts and raises the severity; True when it changed the case. A suppressed R48 case was
        stored with route `log`, so it does not count."""
        if case.detector == NAME:
            return False
        kev = self.open_on(case)
        if not kev:
            return False
        products = sorted({f.get("product", "") for f in kev})
        case.facts["device_kev"] = {"products": products[:5], "cves": sum(int(f.get("kev_cves") or 0) for f in kev)}
        if case.base_severity >= 2:
            # digest items move up a level; log-level ones stay in the log. Measured 2026-10-20 on the live case
            # store: 358 of 987 cases in eight days were new_domain at severity 1 (an ordinary new domain), and a
            # flat +1 would have made every one a digest item on any device with an unpatched browser.
            case.base_severity = min(5, case.base_severity + 1)
        program = str(case.facts.get("program") or "").lower()
        if case.facts.get("source") == "endpoint" and program:
            vulnerable = {e for f in kev if (p := inventory.PRODUCTS.get(f.get("product_key", ""))) for e in p.exes}
            if program in vulnerable:
                case.facts["min_route"] = "alert"
                case.facts.setdefault("host_signals", []).insert(0, f"{program} has a known-exploited vulnerability")
        return True

