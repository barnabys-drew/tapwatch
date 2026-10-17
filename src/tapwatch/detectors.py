"""Deterministic detectors. No AI here.

Each detector gets every log record via `feed(rec)` and returns zero or more
Cases. All counting, time windows and math live here on purpose: TypeSafe's own
docs say Jev is unreliable at arithmetic, counting, raw IPs and timestamps.
"""

from __future__ import annotations

import csv
import ipaddress
import logging
import math
import re
import statistics
import time
from collections import Counter, defaultdict, deque
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path
from typing import ClassVar
from zoneinfo import ZoneInfo

from .categories import from_config as ai_categorizer
from .categories import load as load_categories
from .categories import resolve, set_categorizer
from .feeds import AsnTable
from .models import Case, device_id

log = logging.getLogger("tapwatch")

# Explicit list rather than ipaddress.is_private, which also counts documentation
# and reserved ranges as "private" and would hide them from outbound detectors.
INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",  # RFC 1918
    "100.64.0.0/10",                                  # carrier-grade NAT
    "169.254.0.0/16", "fe80::/10",                    # link-local
    "fc00::/7",                                       # IPv6 unique local
    # Multicast and broadcast never leave the LAN. Counting them as outside made
    # mDNS (224.0.0.251 / ff02::fb) look like a device phoning home.
    "224.0.0.0/4", "ff00::/8", "255.255.255.255/32",
)]


def unicast(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_multicast or str(addr) == "255.255.255.255" or str(addr).endswith(".255"))


# The site's own routable prefixes (network.local_nets), set by build(): a LAN device's IPv6 global
# address is not in any list above, so without this every detector skipped its traffic, and Apple
# and Android devices prefer IPv6 whenever the router offers it.
LOCAL_NETS: list = []


def set_local_nets(cidrs) -> None:
    LOCAL_NETS[:] = [ipaddress.ip_network(c, strict=False) for c in cidrs]


def is_internal(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in INTERNAL_NETS) or any(addr in net for net in LOCAL_NETS)


# Two-label public suffixes, so bbc.co.uk is a registrable domain and co.uk is not. The common
# ones only (stdlib, no public-suffix list dependency).
PUBLIC_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "com.br", "net.br", "co.za", "com.mx", "com.ar", "co.in", "net.in",
    "com.sg", "com.hk", "com.tw", "co.kr", "com.cn", "net.cn", "com.tr", "co.il", "com.sa", "com.eg", "com.my",
    "co.th", "com.ph", "com.vn", "com.pk", "com.ua", "com.pl", "co.id", "com.co", "com.pe", "com.ve"})


def base_domain(name: str) -> str:
    """Rough registered domain: the last two labels, or three under a two-label public suffix (bbc.co.uk)."""
    parts = [p for p in name.lower().rstrip(".").split(".") if p]
    if len(parts) >= 3 and ".".join(parts[-2:]) in PUBLIC_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else name.lower()


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def suffix_match(name: str, domains: set[str] | frozenset[str]) -> str | None:
    """The entry of `domains` that `name` equals or sits under (a.b.example.com -> example.com), else None."""
    labels = [p for p in name.lower().rstrip(".").split(".") if p]
    for i in range(len(labels) - 1):
        cand = ".".join(labels[i:])
        if cand in domains:
            return cand
    return None


# Services that dev and AI-agent work on a dev workstation talks to all day: model APIs,
# editors, code hosting, package and container registries, and the lookups the enrich-case
# skill makes. Measured 2026-10-12: the main PC's first-seen names over 2.9 h were mostly these.
DEV_DOMAINS = frozenset({
    "anthropic.com", "claude.ai", "claude.com", "claudeusercontent.com", "openai.com", "typesafe.ai",
    "cursor.sh", "cursor.com", "githubcopilot.com", "vscode-cdn.net", "visualstudio.com", "vsassets.io",
    "github.com", "githubusercontent.com", "githubassets.com", "ghcr.io", "gitlab.com",
    "pypi.org", "pythonhosted.org", "astral.sh", "npmjs.org", "npmjs.com", "yarnpkg.com", "crates.io",
    "rust-lang.org", "golang.org", "go.dev", "docker.io", "docker.com", "gcr.io", "pkg.dev", "quay.io",
    "trivy.dev", "ubuntu.com", "debian.org", "herdr.dev",
    # enrich-case lookups: RDAP/WHOIS registries and VirusTotal
    "rdap.org", "rdap.verisign.com", "arin.net", "ripe.net", "apnic.net", "lacnic.net", "afrinic.net",
    "iana.org", "virustotal.com",
})


class DevProfile:
    """Dev workstations (config `dev_profile.hosts`) and the services their dev/agent work uses.

    Detectors skip a dev host's traffic only when it can be tied to one of these services by
    name (DNS query or TLS server name). Traffic with no name, and every other device, is
    judged as usual. The takeover rule ignores this profile on purpose.
    """

    def __init__(self, hosts=(), domains=()):
        self.hosts = set(hosts)
        self.domains = DEV_DOMAINS | {d.lower().strip(".") for d in domains}

    def covers(self, host: str, name: str | None) -> bool:
        return bool(name) and host in self.hosts and suffix_match(name, self.domains) is not None


def encode(obj):
    """Detector state -> JSON-safe value. Sets, tuples, deques and non-string dict keys survive the trip."""
    if isinstance(obj, set):
        return {"$set": [encode(x) for x in obj]}
    if isinstance(obj, tuple):
        return {"$tuple": [encode(x) for x in obj]}
    if isinstance(obj, deque):
        return {"$deque": [encode(x) for x in obj], "maxlen": obj.maxlen}
    if isinstance(obj, dict):
        if all(isinstance(k, str) for k in obj):
            return {"$dict": {k: encode(v) for k, v in obj.items()}}
        return {"$items": [[encode(k), encode(v)] for k, v in obj.items()]}
    if isinstance(obj, list):
        return [encode(x) for x in obj]
    return obj


def decode(obj):
    if isinstance(obj, list):
        return [decode(x) for x in obj]
    if not isinstance(obj, dict):
        return obj
    if "$set" in obj:
        return {decode(x) for x in obj["$set"]}
    if "$tuple" in obj:
        return tuple(decode(x) for x in obj["$tuple"])
    if "$deque" in obj:
        return deque((decode(x) for x in obj["$deque"]), maxlen=obj.get("maxlen"))
    if "$dict" in obj:
        return {k: decode(v) for k, v in obj["$dict"].items()}
    if "$items" in obj:
        return {decode(k): decode(v) for k, v in obj["$items"]}
    raise ValueError(f"unknown state encoding: {sorted(obj)[:3]}")


PERMANENT = -1.0  # a `reported` entry learned during warm-up: it never expires


def dests(*addrs) -> dict:
    """{"dests": [...]} naming the outside addresses a case is about, or {} when none is known. Host context
    scopes the PC's connection rows to these (hostctx.case_destinations); until 2026-10-17 it inferred them from
    the DNS answers in the window, which misses a connection made from a cached lookup (review of #117)."""
    out = list(dict.fromkeys(a for a in addrs if isinstance(a, str) and a and _is_ip(a) and not is_internal(a)))
    return {"dests": out[:8]} if out else {}  # first-seen order, so a caller can put the ones that matter first



def still_reported(reported: dict, key, ts: float, ttl: float) -> bool:
    """Was `key` reported within `ttl` seconds before `ts`, or learned for good (PERMANENT)?

    Detectors used to keep a *set* of reported keys, which silenced a repeat forever (a C2 on a
    port where something benign had once been reported). A dict of times lets it be raised again."""
    t = reported.get(key)
    return t is not None and (t == PERMANENT or ts - t < ttl)


def prune_reported(reported: dict, now: float, ttl: float) -> dict:
    return {k: t for k, t in reported.items() if t == PERMANENT or now - t < ttl}


class Detector:
    name = "base"
    # Attributes that hold what the detector has learned (baselines, first-seen sets, things
    # already reported). The pipeline saves them so a restart doesn't start learning from scratch.
    # Sliding windows and caches are left out on purpose: stale after a restart anyway. The exception is a
    # window whose detection needs longer than the gap between restarts (Beaconing's beat times).
    PERSIST: ClassVar[tuple[str, ...]] = ()

    def snapshot(self) -> dict:
        return {a: encode(getattr(self, a)) for a in self.PERSIST}

    def restore(self, data: dict) -> None:
        for a in self.PERSIST:
            if a not in data:
                continue
            cur, val = getattr(self, a), decode(data[a])
            if isinstance(cur, dict) and isinstance(val, dict):
                cur.clear()
                cur.update(val)  # keeps a defaultdict's factory for keys learned from now on
            elif isinstance(cur, set) and isinstance(val, set):
                cur.clear()
                cur.update(val)
            else:
                setattr(self, a, val)

    def feed(self, rec: dict) -> list[Case]:  # pragma: no cover - interface
        raise NotImplementedError

    def flush(self) -> list[Case]:
        """Emit anything still buffered (end of a replay). Most detectors buffer nothing."""
        return []

    def tick(self, now: float) -> list[Case]:  # pragma: no cover - interface
        """Once a minute while `run` follows live logs, records or not: for rules about the passage of time
        (R22 feed_silence). Replays never tick."""
        return []

    # Per-device baselines are keyed on the device identity (name:<hostname>, mac:<address>, else
    # the IP) rather than the IP of the day, so a laptop keeps its baselines across a dock swap or a
    # DHCP change and a different machine on that address doesn't inherit them. DEVICE_KEYED names
    # the attributes whose keys are device keys (a str, or a tuple whose first item is one); entries
    # recorded under an IP before its identity was known move under the identity when it is.
    ident: Identity | None = None
    DEVICE_KEYED: ClassVar[tuple[str, ...]] = ()

    def dev_key(self, ip: str) -> str:
        if self.ident is None:
            return ip
        key = self.ident.key(ip)
        moved = self.__dict__.setdefault("_moved", {})
        if key != ip and moved.get(ip) != key:
            moved[ip] = key
            # Entries this device recorded under any of its addresses before they resolved to it
            # (the laptop learned on Wi-Fi, then docked and was first resolved on the dock's address).
            for old in self.ident.ips_for(key):
                for a in self.DEVICE_KEYED:
                    move_entries(getattr(self, a), old, key)
        return key

    def dev_ip(self, key: str) -> str:
        """The address a device key was last seen on (cases always name an address)."""
        return self.ident.ip_for(key) if self.ident is not None else key


def _keyed_on(k, ip: str) -> bool:
    return k == ip or (isinstance(k, tuple) and bool(k) and k[0] == ip)


def _rekeyed(k, ip: str, key: str):
    return key if k == ip else (key, *k[1:])


def move_entries(container, ip: str, key: str) -> None:
    """Move a detector's entries keyed by `ip` under `key`, merging with what is already there."""
    if isinstance(container, dict):
        for k in [k for k in container if _keyed_on(k, ip)]:
            v, nk = container.pop(k), _rekeyed(k, ip, key)
            if nk not in container:
                container[nk] = v
                continue
            old = container[nk]
            if isinstance(old, set) and isinstance(v, set):
                old |= v
            elif isinstance(old, dict) and isinstance(v, dict):
                old.update(v)
            elif isinstance(old, deque) and isinstance(v, deque):
                old.extend(v)
            elif isinstance(old, list) and isinstance(v, list):
                container[nk] = [a + b for a, b in zip(old, v)]
    elif isinstance(container, set):
        moved = {k for k in container if _keyed_on(k, ip)}
        container -= moved
        container |= {_rekeyed(k, ip, key) for k in moved}


class Warmup:
    """Tracks when we first saw traffic, so 'first seen' detectors stay quiet while learning."""

    def __init__(self, seconds: float):
        self.seconds = seconds
        self.start: float | None = None

    def learning(self, ts: float) -> bool:
        if self.start is None:
            self.start = ts
        return ts - self.start < self.seconds


# --------------------------------------------------------------------------- IOC


class IOCMatch(Detector):
    """Traffic to an address or domain on a threat-intel list. Always alerts."""

    name = "ioc_match"

    def __init__(self, ips: set[str], domains: set[str]):
        self.ips = ips
        self.domains = {d.lower().rstrip(".") for d in domains}

    def _domain_hit(self, name: str) -> bool:
        name = name.lower().rstrip(".")
        return any(name == d or name.endswith("." + d) for d in self.domains)

    def feed(self, rec: dict) -> list[Case]:
        src = rec.get("id.orig_h", "")
        if not is_internal(src):
            return []
        kind = rec["_type"]
        hit, what = None, ""
        if kind == "conn" and rec.get("id.resp_h") in self.ips:
            hit, what = rec["id.resp_h"], "address"
        elif kind == "dns" and rec.get("query") and self._domain_hit(rec["query"]):
            hit, what = rec["query"], "domain lookup"
        elif kind == "ssl" and rec.get("server_name") and self._domain_hit(rec["server_name"]):
            hit, what = rec["server_name"], "TLS connection"
        if hit is None:
            return []
        return [Case(self.name, src, rec["ts"], f"Contact with threat-intel listed {what}",
                     {"what": what, "port": rec.get("id.resp_p"), **dests(rec.get("id.resp_h"))}, [hit],
                     must_alert=True, base_severity=5)]


# -------------------------------------------------------------------- Suricata


class SuricataAlert(Detector):
    """Pass through Suricata IDS alerts. Severity 1 (Suricata's highest) always alerts."""

    name = "ids_alert"

    def feed(self, rec: dict) -> list[Case]:
        if rec["_type"] != "eve" or rec.get("event_type") != "alert":
            return []
        alert = rec.get("alert", {})
        src, dst = rec.get("src_ip", ""), rec.get("dest_ip", "")
        host = src if is_internal(src) else dst
        if not is_internal(host):
            return []
        sev = int(alert.get("severity", 3))
        return [Case(self.name, host, rec["ts"], "IDS signature matched",
                     {"signature": alert.get("signature", ""), "category": alert.get("category", ""),
                      "ids_severity": sev, "direction": "outbound" if host == src else "inbound",
                      "dedupe": str(alert.get("signature_id", ""))},
                     must_alert=(sev == 1), base_severity={1: 5, 2: 3}.get(sev, 2))]


# ------------------------------------------------------------------- Beaconing


# NAT traversal and time sync: regular by design, never C2-shaped on their own.
# STUN/TURN (3478/3479/5349), Tailscale direct (41641), Google STUN (19302-19309), NTP (123).
# Measured 2026-10-12: Tailscale's netcheck hit all 57 DERP relays on UDP 3478
# every ~317s and produced 43 c2_beaconing alerts.
# Names that never leave the LAN or never reach a zone someone else controls: reverse lookups,
# mDNS, the DHCP search suffix, reserved private TLDs. DGA and tunnelling can't use them.
LOCAL_ONLY_SUFFIXES = (".arpa", ".local", ".localdomain", ".lan", ".home", ".internal")
HOUSEKEEPING_UDP_PORTS = {3478, 3479, 5349, 41641, 123, *range(19302, 19310)}


class Beaconing(Detector):
    """Same internal host -> same external host:port at very regular intervals (C2 heartbeat).

    Reported once per (host, port, destination) every `reported_days`, where the destination is
    the base domain when the server has a name, else its address. Until 2026-10-15 it was once
    per (host, port) forever: after one benign heartbeat on 443 (Spotify, Windows push) a C2 on
    443 from the same PC could never be reported again, and that survived restarts. A client that
    fans out to many servers on one port at the same cadence (latency probes, CDNs) is held to
    `fanout_per_day` cases per (host, port) a day, not one per server.
    """

    name = "beaconing"
    # seen/durations are the beat window itself. Ten beats at least ten minutes apart from the first is the bar, so
    # a slow heartbeat needs hours of uninterrupted watching, and the alerter restarts on every deploy (seven
    # times on 2026-10-16; a 12-beat test heartbeat that straddled the 17:54 restart raised nothing while the
    # offline replay of the same rows did). Saved with single-beat pairs dropped: measured 2026-10-17, 8.6k pairs
    # a day on this network, about 2 MB of JSON, in line with the hourly and odd_port baselines. The ceiling is
    # the 20k-pair bound at 60 beats each: measured 31 MB and about 2 s to encode, every 10 minutes and on stop.
    # The pairs are keyed by source address, not device identity (unlike reported): after a lease change the
    # restored window sits under the old address until _forget_quiet drops it a day later.
    PERSIST: ClassVar[tuple[str, ...]] = ("reported", "users", "device", "seen", "durations")  # users/device: the shared_by cap
    DEVICE_KEYED: ClassVar[tuple[str, ...]] = ("reported",)

    def __init__(self, min_count: int = 10, min_span: float = 600, max_cv: float = 0.15, min_interval: float = 5,
                 ignore_udp_ports: set[int] | None = None, dev: DevProfile | None = None, burst: float = 10,
                 popular: set[str] | None = None, expected: dict[str, set[str]] | None = None,
                 benign_classes: dict[str, Iterable[str]] | None = None, reported_days: float = 7,
                 fanout_per_day: int = 3):
        self.min_count, self.min_span, self.max_cv, self.min_interval = min_count, min_span, max_cv, min_interval
        self.burst, self.popular = burst, popular or set()
        self.reported_s, self.fanout_per_day = reported_days * 86400, fanout_per_day
        self.expected = expected or {}             # host -> services it's expected to poll (takeover.expected)
        self.classes = {k: set(v) for k, v in BEACON_CLASSES.items()}  # class -> domains (config adds to it)
        for cls, domains in (benign_classes or {}).items():
            self.classes.setdefault(cls, set()).update(domains or ())
        self.users: dict[str, set[str]] = defaultdict(set)   # base domain -> household devices that used it
        self.device: dict[str, str] = {}                      # IP -> MAC, so one device's IPv4 and IPv6 count once
        self.dev = dev or DevProfile()
        self.ignore_udp = HOUSEKEEPING_UDP_PORTS if ignore_udp_ports is None else set(ignore_udp_ports)
        self.seen: dict[tuple, deque] = defaultdict(lambda: deque(maxlen=60))
        self.durations: dict[tuple, deque] = defaultdict(lambda: deque(maxlen=60))
        self.reported: dict[tuple, float] = {}  # (host, port, base domain or address) -> when it was reported
        self.regular: dict[tuple, set[str]] = defaultdict(set)  # (host, port) -> destinations with regular timing
        self.sni: dict[str, str] = {}  # external ip -> last TLS server name seen
        self.dns: dict[str, str] = {}  # external ip -> name a client looked up to reach it

    def name_for(self, ip: str) -> str | None:
        """Best name for a destination: TLS SNI, else the DNS name that resolved to it.

        QUIC and plain-TCP keepalives carry no SNI in Zeek's ssl.log, so without the DNS
        mapping a beaconing case had no destination at all (case #54 was Claude's
        s-cdn.anthropic.com, #58 was Windows push at client.wns.windows.com)."""
        return self.sni.get(ip) or self.dns.get(ip)

    def class_for(self, name: str | None) -> str | None:
        """The benign beacon class the destination belongs to (push, EDR, NTP, STUN), if any."""
        return next((cls for cls, domains in self.classes.items() if suffix_match(name, domains)), None) if name else None

    def restore(self, data: dict) -> None:
        super().restore(data)
        if isinstance(self.reported, set):  # the pre-2026-10-15 shape, (host, port) forever: start over
            self.reported = {}
        for attr in ("seen", "durations"):  # a window whose saved shape no longer fits starts fresh, not crashes later
            cur = getattr(self, attr)
            if not isinstance(cur, dict) or not all(isinstance(v, deque) for v in cur.values()):
                setattr(self, attr, defaultdict(lambda: deque(maxlen=60)))

    def snapshot(self) -> dict:
        now = max((*self.reported.values(), *(t[-1] for t in self.seen.values() if t)), default=0.0)
        self._prune(now)
        self._forget_quiet(now)
        keep = {p for p, t in self.seen.items() if len(t) >= 2}  # one beat alone can't make a case; not worth the bytes
        out = {a: encode(getattr(self, a)) for a in self.PERSIST if a not in ("seen", "durations")}
        out["seen"] = encode({p: self.seen[p] for p in keep})
        out["durations"] = encode({p: self.durations[p] for p in keep if p in self.durations})
        return out

    def _prune(self, now: float) -> None:
        self.reported = {k: t for k, t in self.reported.items() if now - t < self.reported_s}

    def _forget_quiet(self, now: float) -> None:
        stale = [p for p, t in self.seen.items() if not t or now - t[-1] > 86400]
        for p in stale:
            self.seen.pop(p, None)
            self.durations.pop(p, None)
        if len(self.users) > 100_000:  # base domains the house has used: relearned quickly
            self.users.clear()

    def already_reported(self, src: str, port, key: str, ts: float) -> bool:
        """This destination within reported_days, or this (host, port) already at its fan-out budget today."""
        if ts - self.reported.get((src, port, key), -1e18) < self.reported_s:
            return True
        today = sum(1 for (s, p, _), t in self.reported.items() if (s, p) == (src, port) and ts - t < 86400)
        return today >= self.fanout_per_day

    def feed(self, rec: dict) -> list[Case]:
        if rec["_type"] == "conn" and mac_ok(rec.get("orig_l2_addr")) and is_internal(rec.get("id.orig_h", "")):
            if len(self.device) > 100_000:
                self.device.clear()
            self.device[rec["id.orig_h"]] = rec["orig_l2_addr"]
        named = rec.get("server_name") if rec["_type"] == "ssl" else rec.get("query") if rec["_type"] == "dns" else None
        if named and is_internal(rec.get("id.orig_h", "")) and "." in named:
            self.users[base_domain(named)].add(rec["id.orig_h"])
        if rec["_type"] == "ssl" and rec.get("server_name"):
            if len(self.sni) > 200_000:
                self.sni.clear()
            self.sni[rec.get("id.resp_h", "")] = rec["server_name"]
        if rec["_type"] == "dns" and rec.get("query"):
            if len(self.dns) > 200_000:  # bound memory on a long run; names get relearned quickly
                self.dns.clear()
            for answer in rec.get("answers") or []:
                try:
                    ipaddress.ip_address(answer)
                except ValueError:
                    continue  # CNAME/TXT answers, not addresses
                self.dns[answer] = rec["query"]
        if rec["_type"] != "conn":
            return []
        src, dst, port = rec.get("id.orig_h", ""), rec.get("id.resp_h", ""), rec.get("id.resp_p")
        if not is_internal(src) or is_internal(dst):
            return []
        if rec.get("proto") == "udp" and port in self.ignore_udp:
            return []
        name = self.name_for(dst)
        key, who = base_domain(name) if name else dst, self.dev_key(src)
        if self.already_reported(who, port, key, rec["ts"]) or self.dev.covers(src, name) \
                or (name and suffix_match(name, self.expected.get(src, frozenset()))):
            return []  # already reported, or a dev host polling a dev service (model API, registry)
        pair = (src, dst, port)
        if len(self.seen) > 20_000:  # weeks of a busy network: drop pairs quiet for a day
            self._forget_quiet(rec["ts"])
        times = self.seen[pair]
        if times and abs(rec["ts"] - times[-1]) < self.burst:
            return []  # a retry within the same beat (malware retrying a dead C2), not a new beat
        times.append(rec["ts"])
        self.durations[pair].append(float(rec.get("duration") or 0))
        if len(times) < self.min_count or times[-1] - times[0] < self.min_span:
            return []
        gaps = [b - a for a, b in zip(times, list(times)[1:])]
        mean = statistics.mean(gaps)
        if mean < self.min_interval:
            return []
        # One long UDP stream, not a heartbeat: Zeek splits a long UDP flow (a voice call) into
        # records that each last about the whole interval, which looks perfectly regular. Measured
        # 2026-10-13: a Discord call, UDP 50003, ~500 KB up per 60 s record, alerted as case #63.
        # UDP only: a TCP session held for the interval and then reopened is a classic C2 loop
        # (FluBot's capture: 300 s sessions every 300 s).
        if rec.get("proto") == "udp" and statistics.median(self.durations[pair]) >= 0.8 * mean:
            return []
        cv = statistics.pstdev(gaps) / mean  # coefficient of variation: 0 = perfectly regular
        if cv > self.max_cv:
            return []
        self.reported[(who, port, key)] = rec["ts"]
        if len(self.reported) > 5000:
            self._prune(rec["ts"])
        indicators = [name] if name else []
        dom = base_domain(name) if name else ""
        me = self.device.get(src, src)
        shared_by = len({self.device.get(ip, ip) for ip in self.users.get(dom, set())} - {me}) if dom else 0
        popular = dom in self.popular
        facts = {**dests(dst), "interval_s": round(mean), "count": len(times), "span_s": round(times[-1] - times[0]),
                 "regularity": "very regular" if cv < 0.05 else "regular", "port": port,
                 "service": rec.get("service") or "unknown", "popular": popular, "shared_by": shared_by,
                 "dedupe": f"{key}:{port}"}
        # Code-proven ceiling from household prevalence (home eval 2026-10-13: Windows push, OneDrive
        # and a CDN poll, each used by other devices, were 3 of 8 beaconing items): a widely used
        # service other devices also use -> log. Deliberately no cap for a shared *obscure* domain:
        # that is also what two devices in one botnet look like. Devices are counted by MAC, since
        # one infected machine's IPv4 and IPv6 addresses made it look "shared" (HtBot capture).
        if shared_by and popular:
            facts["max_route"] = "log"
        # A popular service nobody else here uses, or one that is regular by design (BEACON_CLASSES):
        # digest at most. These are the only caps that can apply on a one-computer network, where
        # nothing is ever "shared". Digest, not log, because popular services are also C2 channels
        # (Discord, Telegram, GitHub), so the owner still sees it in the daily digest. the owner's call,
        # 2026-10-15.
        cls = self.class_for(name)
        if cls:
            facts["known_class"] = cls
        if (cls or popular) and facts.get("max_route") != "log":
            facts["max_route"] = "digest"
        return [Case(self.name, src, rec["ts"], "Regular repeating connection to an external host",
                     facts, indicators, base_severity=3)]


# ------------------------------------------------------------------------- DNS


class SuspiciousDNS(Detector):
    """Many failed lookups or many random-looking names from one host (DGA malware, tunneling).

    Random-looking names under widely used domains (the popular list) don't count: CDNs
    number their hosts (gspe79-ssl.ls.apple.com, <uuid>-netseer-ipaddr-assoc.xz.fbcdn.net),
    and DGA or tunnelling needs a zone the attacker controls, which apple.com is not.
    Measured 2026-10-12: case #53 was an iPhone whose 15 "random" names were all Apple,
    Meta, AWS and Google hosts.

    Local-only names (LOCAL_ONLY_SUFFIXES) don't count at all. Measured 2026-10-14 on a home
    network: every dns_anomaly case on a Windows PC was reverse PTR lookups of CDN IPs with no
    PTR record, wpad.localdomain probes and Chrome's <uuid>.local WebRTC names; none had a
    failed internet lookup that mattered.
    """

    name = "dns_anomaly"

    def __init__(self, window: float = 600, nx_threshold: int = 25, random_threshold: int = 15,
                 entropy_min: float = 3.5, popular: set[str] | None = None, dev: DevProfile | None = None,
                 nx_min_names: int = 5, tunnel_queries: int = 200, tunnel_label_len: int = 30,
                 tunnel_txt_share: float = 0.5):
        self.window, self.nx_threshold, self.random_threshold, self.entropy_min = (
            window, nx_threshold, random_threshold, entropy_min)
        self.popular, self.dev = popular or set(), dev or DevProfile()
        self.nx_min_names = nx_min_names
        self.tunnel_queries, self.tunnel_label_len, self.tunnel_txt_share = (
            tunnel_queries, tunnel_label_len, tunnel_txt_share)
        self.events: dict[str, deque] = defaultdict(deque)  # host -> (ts, nx, random, name)
        self.zones: dict[tuple, deque] = defaultdict(deque)  # (host, base domain) -> (ts, first-label length, TXT/NULL?)
        self.cooldown: dict[str, float] = {}

    def feed(self, rec: dict) -> list[Case]:
        if rec["_type"] != "dns" or not rec.get("query"):
            return []
        host, ts, q = rec.get("id.orig_h", ""), rec["ts"], rec["query"]
        if not is_internal(host) or q.lower().rstrip(".").endswith(LOCAL_ONLY_SUFFIXES) \
                or self.dev.covers(host, q):
            return []
        nx = rec.get("rcode_name") == "NXDOMAIN"
        dom = base_domain(q)
        rnd = looks_random(q) and dom not in self.popular
        ev = self.events[host]
        ev.append((ts, nx, rnd, q))
        while ev and ts - ev[0][0] > self.window:
            ev.popleft()
        out = self._tunnel(host, ts, q, dom, rec.get("qtype_name"))
        if ts < self.cooldown.get(host, 0):
            return out
        nx_names = {e[3] for e in ev if e[1]}
        # One dead name retried in a loop (a remote-access agent, WPAD) isn't DGA: that needs many names.
        nx_n = sum(1 for e in ev if e[1]) if len(nx_names) >= self.nx_min_names else 0
        rnd_n = len({e[3] for e in ev if e[2]})
        if nx_n < self.nx_threshold and rnd_n < self.random_threshold:
            return out
        self.cooldown[host] = ts + self.window
        samples = list(dict.fromkeys(e[3] for e in ev if e[1] or e[2]))[:3]
        return out + [Case(self.name, host, ts, "Unusual DNS lookup pattern",
                           {"failed": nx_n, "random_looking": rnd_n, "total": len(ev),
                            "window_min": round(self.window / 60)},
                           samples, base_severity=3)]

    def _tunnel(self, host: str, ts: float, q: str, dom: str, qtype: str | None) -> list[Case]:
        """R15. Data smuggled through DNS: many queries to one zone with long encoded labels or TXT/NULL answers."""
        if dom in self.popular or dom.endswith((".arpa", ".local")) or "." not in dom:
            return []
        if len(self.zones) > 20_000:  # (host, zone) pairs quiet for a window: drop them
            for k in [k for k, z in self.zones.items() if not z or ts - z[-1][0] > self.window]:
                del self.zones[k]
        zone = self.zones[(host, dom)]
        zone.append((ts, len(q.split(".")[0]), qtype in ("TXT", "NULL")))
        while zone and ts - zone[0][0] > self.window:
            zone.popleft()
        key = f"{host}|tunnel|{dom}"
        if len(zone) < self.tunnel_queries or ts < self.cooldown.get(key, 0):
            return []
        mean_len = sum(z[1] for z in zone) / len(zone)
        txt_share = sum(z[2] for z in zone) / len(zone)
        if mean_len <= self.tunnel_label_len and txt_share < self.tunnel_txt_share:
            return []
        self.cooldown[key] = ts + 6 * self.window
        return [Case(self.name, host, ts, "Possible DNS tunnelling",
                     {"tunnel": True, "queries": len(zone), "mean_label": round(mean_len),
                      "txt_pct": round(100 * txt_share), "window_min": round(self.window / 60),
                      "dedupe": f"tunnel|{dom}"},
                     [dom], base_severity=4)]


# -------------------------------------------------------------------- Scanning


class PortScan(Detector):
    """One internal host failing to reach many hosts/ports in a short window (recon, worm spread).

    Only *failed* attempts count: a PC or phone opening 50 normal HTTPS connections a
    minute is browsing, not scanning (measured 2026-10-12: 10-13% failure, 3 false alerts).
    Multicast/broadcast discovery (SSDP, mDNS) is ignored.

    UDP is different: Zeek never sees a UDP "refused", so an unanswered datagram is S0 whether
    it was a probe or a normal NBSTAT, LLMNR, SSDP or QUIC attempt. Measured 2026-10-14: 63
    udp/137 S0 to public addresses was the main PC's NetBIOS name fallback, alerted as a scan
    (#73, and 4 more like it). So UDP to the discovery ports never counts, and other UDP counts
    only in a sweep shape: one host on many ports, or one port across many hosts. Many hosts
    on many ports (BitTorrent DHT, game peers) is how those protocols look when peers are gone.

    A device losing its network fails every connection at once, which on one port to many hosts
    is the sweep shape (a phone walking out of Wi-Fi range: 50 SYNs to 50 web servers in a minute,
    alerted 2026-10-15 as #122). When the failures are silent (no SYN-ACK, no refusal: S0, OTH, SH,
    RSTOS0) and nothing from the source has succeeded since they began, the case carries
    `all_failed` and is capped at digest. A refusal or a reset is the target answering, which
    proves the path works, so a refused-port scan from a quiet host still alerts.

    `failed_pct` is the share of the source's connections in the window that failed, discovery
    traffic left out of both sides. Under 50% is capped at digest: a phone on marginal Wi-Fi failed
    48 SYNs to 47 CDN prefixes while 336 other connections succeeded (2026-10-16 #339, 12.5%).
    The 50 is a judgement, not a measurement; a busy workstation that also probes 50 hosts can
    stay under it, which is the trade-off against the day's phone cases.

    A reset ends many ordinary sessions: a phone leaving a news page tore down 87 TLS sessions to
    ad and CDN hosts with RST in one minute (2026-10-16 #363; median 2.5 KB sent, 8.5 KB received,
    80 s long; 199 such resets from that phone in the hour), which Zeek records as RSTO and this
    rule alerted on as a 50-host sweep. A SYN scan closes with a reset too (SYN, SYN-ACK, RST), but
    it has sent and received nothing. So a reset after data went both ways is an answered
    connection (the target served something); a reset with nothing exchanged, or data only one way
    (a banner grab reads the target's greeting and sends nothing; a ClientHello answered by a reset,
    not seen on the home network as of 2026-10-16), still counts as a probe. The cost, a judgement
    like the 50%: a service-version scan against open ports also exchanges data and resets, so
    those rows count as answered and the sweep is carried by the closed ports' refusals.

    The router reports its Wi-Fi clients roaming between access points and disconnecting
    (udm.log, the syslog feed with the Clients content ticked, docs/setup/router-syslog.md). A
    failure burst from a client the router moved or dropped within `WIFI_WINDOW` seconds of the
    trigger is that move, not a scan: measured 2026-10-16, a phone's "scan" (#321) came 3 seconds
    after its roam between two access points. The case keeps the `wifi_event` (roamed /
    disconnected) and how many seconds before the trigger it was, and is capped at digest. A
    join ("WiFi Client Connected") explains nothing: a device that joins and sweeps the LAN is
    the strongest scan shape, so it does not count. Only events the router has already reported
    by the time the case is raised can match (each poll is sorted by ts, and Zeek writes an
    unanswered attempt 5 s or more after its ts, so an event a moment after the trigger is
    usually in); the same phone's disconnect, logged 215 s later, is not seen, and a device the
    router never mentions is judged on the other facts.
    """

    name = "scan"
    FAILED: ClassVar[set[str]] = {"S0", "REJ", "RSTO", "RSTR", "RSTOS0", "SH", "OTH"}
    SILENT: ClassVar[set[str]] = {"S0", "OTH", "SH", "RSTOS0"}  # the target never answered at all
    # Answered, as a scanner would see it. ESTABLISHED (defined below) also holds RSTO/RSTR, but a reset
    # right after the handshake is how a SYN scan closes and how tarpits answer a probe: a failure
    # here unless data went both ways first (RESET, below).
    ANSWERED: ClassVar[set[str]] = {"SF", "S1", "S2", "S3"}
    RESET: ClassVar[set[str]] = {"RSTO", "RSTR"}  # answered when both sides sent data; a probe otherwise
    # DNS, DHCP, NTP, NetBIOS, SSDP, WS-Discovery, mDNS, LLMNR, UniFi discovery
    DISCOVERY_UDP: ClassVar[set[int]] = {53, 67, 68, 123, 137, 138, 1900, 3702, 5353, 5355, 10001}
    # The router's CEF event names for a Wi-Fi client changing state (syslogin.py keeps `name` as sent).
    WIFI_EVENTS: ClassVar[dict[str, str]] = {"WiFi Client Roamed": "roamed", "WiFi Client Disconnected": "disconnected"}
    WIFI_WINDOW: ClassVar[float] = 180     # s: the failure window plus two minutes either side of the trigger
    WIFI_KEEP: ClassVar[int] = 200         # events remembered: a few a minute in a busy house (measured 2026-10-16)

    def __init__(self, window: float = 60, threshold: int = 50):
        self.window, self.threshold = window, threshold
        self.events: dict[str, deque] = defaultdict(deque)
        self.ok: dict[str, deque] = defaultdict(deque)  # source -> times of its answered connections
        self.cooldown: dict[str, float] = {}
        self.wifi: deque = deque(maxlen=self.WIFI_KEEP)  # (ts, client MAC, client IP, event) from the router

    def feed(self, rec: dict) -> list[Case]:
        if rec["_type"] == "udm":
            self._wifi_event(rec)
            return []
        if rec["_type"] != "conn":
            return []
        src, dst, ts = rec.get("id.orig_h", ""), rec.get("id.resp_h", ""), rec["ts"]
        proto, port = rec.get("proto") or "tcp", rec.get("id.resp_p")
        if not is_internal(src) or (proto == "udp" and port in self.DISCOVERY_UDP):
            return []  # discovery traffic is left out of both sides of failed_pct
        state = rec.get("conn_state")
        if state in self.ANSWERED or (state in self.RESET and int(rec.get("orig_bytes") or 0) > 0
                                      and int(rec.get("resp_bytes") or 0) > 0):
            ok = self.ok[src]
            ok.append(ts)
            while ok and ts - ok[0] > self.window:
                ok.popleft()
            return []
        if rec.get("conn_state") not in self.FAILED or not unicast(dst):
            return []
        ev = self.events[src]
        ev.append((ts, dst, port, proto, rec.get("conn_state")))
        while ev and ts - ev[0][0] > self.window:
            ev.popleft()
        if ts < self.cooldown.get(src, 0) or not self._sweep(ev):
            return []
        self.cooldown[src] = ts + 10 * self.window
        targets, hosts, protos = {(e[1], e[2]) for e in ev}, {e[1] for e in ev}, {e[3] for e in ev}
        internal = sum(1 for h in hosts if is_internal(h))
        # A device losing its network fails every connection at once, which on one port to many
        # hosts is the sweep shape (a phone walking out of Wi-Fi range: 50 SYNs to 50 web servers in
        # a minute, alerted 2026-10-15 as #122). A scanner's other traffic keeps working.
        # Offline means silence: no answered connection since the failures began AND no refusal
        # either (a REJ or a reset is the target answering, which proves the path works).
        okq = self.ok.get(src)
        silent = all(e[4] in self.SILENT for e in ev)
        all_failed = silent and (not okq or okq[-1] < ev[0][0])
        # The share of the source's connections in the window that failed. A scanner's probes are
        # most of what it sends; a phone on marginal Wi-Fi fails a few dozen SYNs to CDN hosts while
        # hundreds of others succeed (measured 2026-10-16 #339: 48 failed, 336 succeeded, 12.5%).
        answered = sum(1 for t in (okq or ()) if ts - t <= self.window)
        failed_pct = round(100 * len(ev) / (len(ev) + answered))
        facts = {"targets": len(targets), "hosts": len(hosts), "ports": len({e[2] for e in ev}),
                 "proto": protos.pop() if len(protos) == 1 else "mixed", "all_failed": all_failed,
                 "failed_pct": failed_pct, "internal_targets": internal == len(hosts), "window_s": round(self.window)}
        if all_failed or failed_pct < 50:
            facts["max_route"] = "digest"
        mac = (rec.get("orig_l2_addr") or "").lower()
        if wifi := self._wifi_near(src, mac if mac_ok(mac) else "", ts):
            facts["wifi_event"], facts["wifi_event_age_s"] = wifi
            facts["max_route"] = "digest"
        return [Case(self.name, src, ts, "Possible port or host scan", facts, base_severity=3)]

    def _wifi_event(self, rec: dict) -> None:
        """Remember a router Wi-Fi client event by the client's MAC and address."""
        kind = self.WIFI_EVENTS.get(rec.get("name") or "")
        mac, ip = (rec.get("UNIFIclientMac") or "").lower(), rec.get("UNIFIclientIp") or ""
        if kind and (mac or ip):
            try:
                self.wifi.append((float(rec.get("ts") or 0), mac, ip, kind))
            except (TypeError, ValueError):
                pass

    def _wifi_near(self, src: str, mac: str, ts: float) -> tuple[str, int] | None:
        """The router's latest Wi-Fi event for this client within WIFI_WINDOW of `ts`: (event, seconds before)."""
        for ets, emac, eip, kind in reversed(self.wifi):
            if abs(ts - ets) <= self.WIFI_WINDOW and ((mac and emac == mac) or (not mac and eip == src)):
                return kind, round(ts - ets)
        return None

    def _sweep(self, ev: deque) -> bool:
        """TCP: `threshold` distinct (host, port) targets. UDP: that many ports on one host or hosts on one port."""
        if len({(h, p) for _, h, p, pr, _s in ev if pr != "udp"}) >= self.threshold:
            return True
        ports_by_host, hosts_by_port = defaultdict(set), defaultdict(set)
        for _, h, p, pr, _s in ev:
            if pr == "udp":
                ports_by_host[h].add(p)
                hosts_by_port[p].add(h)
        return any(len(v) >= self.threshold for v in (*ports_by_host.values(), *hosts_by_port.values()))


# ---------------------------------------------------------------------- Volume


# Cloud sync/backup services: an upload spike mostly to one of these is a sync, not exfiltration.
# Deliberately narrow: general storage (S3, Mega, file-drop sites) is where exfiltration goes.
SYNC_DOMAINS = frozenset({"onedrive.com", "sharepoint.com", "icloud.com", "icloud-content.com", "apple-cloudkit.com",
                          "dropbox.com", "dropboxapi.com", "googleusercontent.com", "backblazeb2.com", "box.com",
                          "photos.google.com", "drive.google.com", "synology.me"})


# Endpoint-security agents on work laptops ship large telemetry uploads (home eval 2026-10-13: a work
# computer's 700 MB hour went to its security vendor's cloud, and Jev called it exfiltration at 0.99).
SECURITY_TELEMETRY = frozenset({"cloudsink.net", "crowdstrike.com", "sentinelone.net", "endpoint.security.microsoft.com",
                                "securitycenter.windows.com", "sophos.com", "sophosupd.com", "eset.com",
                                "bitdefender.net", "tanium.com", "cybereason.net", "carbonblack.io"})

# Services whose clients are regular by design, so a heartbeat to them is expected, not a C2 sign:
# a code-proven ceiling (digest, never log: a C2 hiding under a push service's domain should still
# show up in the digest). Vendor-level public domains only; a site extends it with
# detectors.beaconing.benign_classes. Measured 2026-10-15: a work laptop's endpoint-management
# check-in every 75 s was scored c2 0.99 by Jev because the summary said only "same server, port
# 17472, every 75 s"; the class is the fact the summary was missing.
BEACON_CLASSES: dict[str, frozenset[str]] = {
    "push notification": frozenset({"push.apple.com", "wns.windows.com", "notify.windows.com", "mtalk.google.com",
                                    "gcm.googleapis.com", "fcm.googleapis.com", "push.services.mozilla.com"}),
    "endpoint security agent": SECURITY_TELEMETRY,
    "time sync": frozenset({"ntp.org", "time.apple.com", "time.windows.com", "time.google.com",
                            "time.cloudflare.com", "time.nist.gov"}),
    "NAT traversal / VPN relay": frozenset({"stun.l.google.com", "stun.cloudflare.com", "tailscale.com"}),
}


def sync_service(name: str) -> bool:
    n = name.lower()
    return suffix_match(n, SYNC_DOMAINS) is not None or (("onedrive" in n or "sharepoint" in n)
                                                          and n.endswith(".blob.core.windows.net"))


class HourlyProfile(Detector):
    """Per-device hourly profiles: R09 upload drift, steady upload stopped, R12 off-hours activity.

    Every device's hour closes on the log clock, including hours it was silent (counted as zero).
    A camera that stops sending sends nothing, so waiting for its next connection would never
    notice. Baselines compare an hour with the same hour of the day over the last 14 days once
    there are 3+ such days, else with the device's recent average (the old upload_spike rule).

      * upload_spike: an hour above `floor_bytes` and `multiple` x the baseline. Measured at
        home: the camera uploads ~340 MB/h steadily, so a fixed house-wide threshold can't work.
      * upload_stopped: a device that steadily uploads >= `steady_mb` an hour drops below 5% for
        `stop_hours` hours in a row (camera offline, unplugged or jammed). Once a day per device.
      * off_hours: an hour of the day when the device is normally near-idle (median < 5
        connections over 7+ days) with >= `busy_min` connections and >= 20x that median.

    Managed devices: a device whose assets.yaml role says it is employer-managed or carries a
    security agent (MANAGED_ROLE_WORDS) has its upload_spike capped at digest whatever the
    destination, with the role in `managed_device`. Measured at home: the work laptop (employer-
    managed, runs an EDR agent) uploads ~1 GB to plain AWS addresses most mornings (#139, #325,
    closed as the EDR agent's telemetry) and 1.5 GB to a Google Meet address on
    2026-10-16 (#371, a video call). Neither destination is a sync service or a vendor domain,
    so the destination caps never applied and Jev scored them as exfiltration. Digest, not log:
    the device stays visible in the daily digest; its employer's tooling is what watches it, and a
    home monitor should not page the owner for a managed laptop's telemetry.
    """

    name = "hourly"
    PERSIST: ClassVar[tuple[str, ...]] = ("current", "dests", "history", "last_hour", "reported", "names")
    DEVICE_KEYED: ClassVar[tuple[str, ...]] = ("current", "dests", "history", "reported")

    def restore(self, data: dict) -> None:
        super().restore(data)  # dests comes back as plain dicts: make them Counters again
        self.dests = defaultdict(Counter, {k: Counter(v) for k, v in self.dests.items()})

    # Networks whose own address space a device uploads to only for that company's cloud: an iPhone's
    # 2 GB to Apple's ASN is an iCloud backup even when no DNS or TLS name was visible (Apple relays
    # and ECH hide them; measured 2026-10-15). AWS, Google and Cloudflare host everyone, so not them.
    SYNC_ASNS: ClassVar[dict[int, str]] = {714: "Apple", 8075: "Microsoft", 19679: "Dropbox", 40401: "Backblaze"}

    def __init__(self, multiple: float = 10, floor_bytes: int = 500_000_000, min_hours: int = 6,
                 steady_mb: float = 50, stop_hours: int = 2, busy_min: int = 200, timezone: str | None = None,
                 asn: AsnTable | None = None, managed: dict[str, str] | None = None):
        self.multiple, self.floor, self.min_hours, self.asn = multiple, floor_bytes, min_hours, asn
        self.managed = managed or {}  # device key or address -> assets role (managed_hosts)
        self.tz = ZoneInfo(timezone) if timezone else None  # None = this machine's local time
        self.steady, self.stop_hours, self.busy_min = steady_mb * 1e6, stop_hours, busy_min
        self.current: dict[str, list] = {}                       # host -> [conns, upload bytes, download bytes] this hour
        self.dests: dict[str, Counter] = defaultdict(Counter)     # host -> upload bytes per destination name, this hour
        # external IP -> name (DNS/TLS). Saved: a 2 GB iCloud upload right after a restart had no name, so
        # the sync-service cap could not apply and it alerted (2026-10-15 07:59).
        self.names: dict[str, str] = {}
        self.history: dict[str, deque] = defaultdict(lambda: deque(maxlen=14 * 24))  # host -> (hour, conns, up, down)
        self.last_hour: int | None = None
        self.reported: set[tuple] = set()

    def feed(self, rec: dict) -> list[Case]:
        if rec["_type"] == "dns":
            for a in rec.get("answers") or ():
                self.names[a] = rec.get("query") or ""
            if len(self.names) > 200_000:
                self.names.clear()
            return []
        if rec["_type"] == "ssl" and rec.get("server_name"):
            self.names[rec.get("id.resp_h", "")] = rec["server_name"]
            return []
        if rec["_type"] != "conn":
            return []
        hour = int(rec["ts"] // 3600)
        out = self._advance(hour) if self.last_hour is not None and hour > self.last_hour else []
        if self.last_hour is None or hour > self.last_hour:
            self.last_hour = hour
        src, dst = rec.get("id.orig_h", ""), rec.get("id.resp_h", "")
        if is_unicast_lan(src) and not is_internal(dst):
            src = self.dev_key(src)
            cur = self.current.setdefault(src, [0, 0, 0])
            if len(cur) < 3:
                cur.append(0)  # state saved before downloads were counted
            cur[0] += 1
            cur[1] += int(rec.get("orig_bytes") or 0)
            cur[2] += int(rec.get("resp_bytes") or 0)
            if rec.get("orig_bytes"):
                self.dests[src][self.names.get(dst) or dst] += int(rec["orig_bytes"])  # unnamed: by address
        return out

    def flush(self) -> list[Case]:
        return []  # a partial hour proves nothing

    def _advance(self, hour: int) -> list[Case]:
        out: list[Case] = []
        closing = range(max(self.last_hour, hour - 48), hour)  # cap the catch-up after a long gap
        for h in closing:
            for host in set(self.current) | set(self.history):
                conns, up, down = (self.current.pop(host, [0, 0, 0]) + [0])[:3] if h == self.last_hour else (0, 0, 0)
                out += self._judge(host, h, conns, up, down)
                self.history[host].append((h, conns, up, down))
        self.current.clear()
        self.dests.clear()
        for host in [h for h, hist in self.history.items()
                     if len(hist) >= 7 * 24 and not any(x[1] for x in list(hist)[-7 * 24:])]:
            del self.history[host]  # gone a week (guest phone, old address): stop tracking it
        return out

    def _same_hour(self, host: str, hour: int, idx: int) -> list:
        local = datetime.fromtimestamp(hour * 3600, self.tz).hour
        return [x[idx] for x in self.history[host] if datetime.fromtimestamp(x[0] * 3600, self.tz).hour == local]

    def _judge(self, host: str, hour: int, conns: int, up: int, down: int = 0) -> list[Case]:
        hist, ts, out = self.history[host], hour * 3600 + 3599, []
        ip = self.dev_ip(host)  # cases name the address the device was last seen on
        same_up = self._same_hour(host, hour, 2)
        if len(same_up) >= 3:
            normal, basis = statistics.median(same_up), "same hour on earlier days"
        elif len(hist) >= self.min_hours:
            normal, basis = statistics.mean(x[2] for x in hist), "recent hours"
        else:
            normal = None
        if normal is not None and up > self.floor and up > self.multiple * max(normal, 1):
            top, top_bytes = (self.dests.get(host) or Counter({"": 0})).most_common(1)[0]
            share = top_bytes / up if up else 0
            owner = self.asn.lookup(top) if self.asn and top and _is_ip(top) else None
            sync_network = self.SYNC_ASNS.get(owner[0], "") if owner else ""
            # A video call is symmetric (measured 2026-10-14: an all-day Google Meet, ~0.8 Mbit/s each
            # way, 2.17 GB up, alerted as #82). Exfiltration is lopsided: the data goes one way.
            symmetric = 0.35 <= up / (up + down) <= 0.65 if down else False
            top_category, top_source = resolve(top)  # dests is keyed by name whenever one is known
            facts = {"mb": round(up / 1e6), "normal_mb": round(normal / 1e6, 1),
                     "times_normal": round(up / max(normal, 1)), "basis": basis, "down_mb": round(down / 1e6),
                     "symmetric": symmetric,
                     "top_share_pct": round(100 * share), "to_sync_service": bool(top) and sync_service(top),
                     "to_security_vendor": bool(top) and suffix_match(top, SECURITY_TELEMETRY) is not None,
                     "to_sync_network": sync_network,
                     "top_category": top_category, "top_category_source": top_source}
            if (facts["to_sync_service"] or facts["to_security_vendor"] or sync_network or symmetric) and share >= 0.6:
                facts["max_route"] = "digest"  # home eval: a 700 MB OneDrive hour was Jev's "exfiltration 1.00"
            # host is the device key (name:/mac:/IP); the assets entry may be under it, the address, or
            # the MAC when the device's key is its DHCP hostname
            mac = self.ident.mac_for(ip) if self.ident else ""
            role = self.managed.get(host) or self.managed.get(ip) or (mac and self.managed.get(f"mac:{mac.lower()}"))
            if role:
                facts["managed_device"] = role  # employer-managed / security agent: see the class docstring
                facts["max_route"] = "digest"
            out.append(Case("upload_spike", ip, ts, "Unusually large upload", facts,
                            [top] if top else [], base_severity=3))
        day = datetime.fromtimestamp(ts, self.tz).date().isoformat()
        recent = [x[2] for x in list(hist)[-24:]]
        if len(recent) >= 12 and (host, "stopped", day) not in self.reported:
            steady = statistics.median(recent)
            last = [x[2] for x in list(hist)[-(self.stop_hours - 1):]] + [up] if self.stop_hours > 1 else [up]
            earlier = recent[:-(self.stop_hours - 1)] if self.stop_hours > 1 else recent
            if steady >= self.steady and all(v < 0.05 * steady for v in last) and statistics.median(earlier) >= self.steady:
                self.reported.add((host, "stopped", day))
                out.append(Case("upload_stopped", ip, ts, "A steady uploader went quiet",
                                {"normal_mb": round(steady / 1e6), "hours": self.stop_hours, "dedupe": day},
                                base_severity=2))
        same_conns = self._same_hour(host, hour, 1)
        if len(same_conns) >= 7 and (host, "off", day) not in self.reported:
            quiet = statistics.median(same_conns)
            if quiet < 5 and conns >= max(self.busy_min, 20 * max(quiet, 1)):
                self.reported.add((host, "off", day))
                out.append(Case("off_hours", ip, ts, "Busy at an hour it's normally idle",
                                {"conns": conns, "normal": round(quiet), "hour": datetime.fromtimestamp(ts, self.tz).hour,
                                 "days": len(same_conns), "dedupe": day},
                                base_severity=3))
        return out


# ------------------------------------------------------------- First-seen stuff


VOWELS = set("aeiou")


def looks_random(name: str) -> bool:
    """Machine-generated label (DGA, tunnelling) vs a readable word.

    Entropy alone fails: long readable names like "krebsonsecurity" score high. Real
    words have vowels and few digits, so flag labels that are long AND either mix in
    several digits or have almost no vowels / long consonant runs.
    """
    label = name.lower().split(".")[0]
    if len(label) < 10:
        return False
    letters = [c for c in label if c.isalpha()]
    digits = sum(c.isdigit() for c in label)
    vowel_ratio = sum(c in VOWELS for c in letters) / max(len(letters), 1)
    run = longest = 0
    for c in label:
        run = run + 1 if c.isalpha() and c not in VOWELS else 0
        longest = max(longest, run)
    return digits >= 3 or vowel_ratio < 0.2 or longest >= 6


class NewExternalDomain(Detector):
    """A host starts using domains (DNS or TLS name) it has never used before.

    Grouped per host into windows, so a burst of new names is one case, not one case per
    name. Failed lookups (NXDOMAIN etc.) are skipped: those are SuspiciousDNS's job, and a
    name that never resolved was never contacted. Each case carries facts computed here,
    because "first contact with a domain" on its own gives the AI nothing to judge.
    """

    name = "new_domain"
    PERSIST: ClassVar[tuple[str, ...]] = ("known", "users")
    DEVICE_KEYED: ClassVar[tuple[str, ...]] = ("known",)

    def __init__(self, warmup: Warmup, window: float = 300, popular: set[str] | None = None,
                 dev: DevProfile | None = None):
        self.warmup, self.window, self.popular, self.dev = warmup, window, popular or set(), dev or DevProfile()
        self.known: dict[str, set[str]] = defaultdict(set)       # host -> base domains it has used
        self.users: dict[str, set[str]] = defaultdict(set)       # base domain -> hosts that used it
        self.pending: dict[str, dict] = {}                       # host -> open window

    def feed(self, rec: dict) -> list[Case]:
        out = self._close_due(rec.get("ts", 0.0))
        name = rec.get("query") if rec["_type"] == "dns" else rec.get("server_name") if rec["_type"] == "ssl" else None
        host = rec.get("id.orig_h", "")
        if not name or "." not in name.strip(".") or not is_internal(host) \
                or name.endswith(LOCAL_ONLY_SUFFIXES) \
                or self.dev.covers(host, name):
            return out
        if rec["_type"] == "dns" and rec.get("rcode_name") not in (None, "NOERROR"):
            return out
        dom, who = base_domain(name), self.dev_key(host)
        if dom in self.known[who]:
            return out
        self.known[who].add(dom)
        others = len(self.users[dom])  # other devices that already used it
        self.users[dom].add(who)
        if self.warmup.learning(rec["ts"]):
            return out
        win = self.pending.setdefault(host, {"start": rec["ts"], "items": []})
        cat, cat_source = resolve(name)  # the offline list, else the model's cached or fresh answer (categories.py)
        win["items"].append({"name": name, "via": "TLS" if rec["_type"] == "ssl" else "DNS",
                             "ips": [rec.get("id.resp_h")] if rec["_type"] == "ssl"
                             else [a for a in (rec.get("answers") or []) if _is_ip(a)][:4],
                             # numbered CDN hosts under widely used domains aren't DGA (home eval 2026-10-13:
                             # googlevideo, microsoftaik, cdn77 made 16 of 26 digest items)
                             "random": looks_random(name) and dom not in self.popular,
                             "others": others, "popular": dom in self.popular,
                             "category": cat, "category_source": cat_source})
        return out

    def _close_due(self, now: float) -> list[Case]:
        due = [h for h, w in self.pending.items() if now - w["start"] >= self.window]
        return [self._case(h, self.pending.pop(h)) for h in due]

    def flush(self) -> list[Case]:
        return [self._case(h, self.pending.pop(h)) for h in list(self.pending)]

    def _case(self, host: str, win: dict) -> Case:
        items = win["items"]
        n = len(items)
        # Show the odd ones first: random-looking, then ones no other device uses.
        shown = sorted(items, key=lambda i: (not i["random"], i["others"] > 0))[:3]
        facts = {"count": n, "window_min": round(self.window / 60),
                 "random": sum(i["random"] for i in items),
                 "shared": sum(i["others"] > 0 for i in items),
                 "popular": sum(i["popular"] for i in items),
                 "popular_known": bool(self.popular),
                 "via": items[0]["via"], "max_others": max(i["others"] for i in items),
                 "dedupe": f"{int(win['start'] // self.window)}",
                 # the addresses behind the three names the case shows come first, so the cap keeps them
                 **dests(*(ip for i in shown + items for ip in i.get("ips") or ())),
                 # what kind of sites, from the offline category list or the model: distinct, most frequent first,
                 # and where the kinds came from ("list", "ai") so the summary can say which
                 "categories": [c for c, _ in Counter(i["category"] for i in items if i.get("category")).most_common(3)],
                 "category_sources": [s for s in ("list", "ai")
                                      if any(i.get("category") and i.get("category_source") == s for i in items)]}
        title = "First contact with a new domain" if n == 1 else f"First contact with {n} new domains"
        return Case(self.name, host, win["start"], title, facts, [i["name"] for i in shown],
                    base_severity=2 if facts["random"] else 1)


def mac_ok(mac: str | None) -> bool:
    """A real device MAC: well formed, not broadcast, multicast or all-zero."""
    if not mac or len(mac) != 17 or mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
        return False
    try:
        return int(mac[:2], 16) & 1 == 0  # the low bit of the first octet marks multicast
    except ValueError:
        return False


def mac_randomized(mac: str) -> bool:
    """Locally administered ("private") address: phones and laptops rotate these per network or per day."""
    return mac[1].lower() in "26ae"


class NewDevice(Detector):
    """R05. A device never seen before joins the network.

    Keyed on the MAC Zeek logs in conn.log (deploy/zeek/tapwatch.zeek loads mac-logging), so a
    device keeps its identity through DHCP changes and rotating IPv6 addresses. Falls back to the
    IP when the logs have no MACs. A randomized ("private") MAC that reuses the DHCP hostname of a
    known device is that device on a new address, not a new device. Vendor comes from the IEEE
    OUI list when configured (offline file); randomized MACs have no vendor.
    """

    name = "new_device"
    PERSIST: ClassVar[tuple[str, ...]] = ("known", "hostnames", "known_names")

    def __init__(self, warmup: Warmup, oui: dict[str, str] | None = None, timezone: str | None = None):
        self.warmup, self.oui = warmup, oui or {}
        self.tz = ZoneInfo(timezone) if timezone else None
        self.known: set[str] = set()            # MACs (or IPs when there's no MAC)
        self.hostnames: dict[str, str] = {}     # MAC -> DHCP hostname
        self.known_names: set[str] = set()      # hostnames of devices already known

    def feed(self, rec: dict) -> list[Case]:
        if rec["_type"] == "dhcp":
            mac, name = (rec.get("mac") or "").lower(), (rec.get("host_name") or "").strip()
            if mac_ok(mac) and name:
                self.hostnames[mac] = name
                if mac in self.known:
                    self.known_names.add(name.lower())
            return []
        if rec["_type"] != "conn":
            return []
        host = rec.get("id.orig_h", "")
        if not is_internal(host):
            return []
        mac = (rec.get("orig_l2_addr") or "").lower()
        if not mac_ok(mac):
            mac = ""
            if host.startswith("fe80:") or not is_unicast_lan(host):
                return []  # no MAC to key on, and link-local IPv6 rotates for privacy
        key = mac or host
        if key in self.known:
            return []
        self.known.add(key)
        name = self.hostnames.get(mac, "")
        if self.warmup.learning(rec["ts"]):
            if name:
                self.known_names.add(name.lower())
            return []
        randomized = bool(mac) and mac_randomized(mac)
        if randomized and name and name.lower() in self.known_names:
            return []  # a known phone/laptop on a new private address
        if name:
            self.known_names.add(name.lower())
        dst = rec.get("id.resp_h", "")
        hour = datetime.fromtimestamp(rec["ts"], self.tz).hour
        night = 1 <= hour < 6
        vendor = "" if randomized or not mac else self.oui.get(mac[:8].replace(":", "").upper(), "")
        # A private MAC with no DHCP hostname whose first move is on the LAN (DHCP, mDNS) is most
        # likely a known phone on its next rotation (Android sends no hostname by default): log it.
        rotation = randomized and not name and is_internal(dst)
        return [Case(self.name, host, rec["ts"], "New device on the network",
                     {"first_port": rec.get("id.resp_p"), "first_service": rec.get("service") or "unknown",
                      "first_dest": "another device on the network" if is_internal(dst) else "an outside server",
                      "has_mac": bool(mac), "randomized_mac": randomized, "likely_rotation": rotation,
                      "vendor": vendor, "vendor_known": bool(self.oui), "night": night, "dedupe": key},
                     [name] if name else [], base_severity=1 if rotation else 3 if night and not randomized else 2)]


def load_oui(path: str | None) -> dict[str, str]:
    """IEEE MA-L registry CSV (standards-oui.ieee.org/oui/oui.csv): 'AABBCC' -> organisation name."""
    if not path or not Path(path).exists():
        return {}
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        return {row["Assignment"].upper(): row["Organization Name"].strip()
                for row in csv.DictReader(fh) if row.get("Assignment")}


# ---------------------------------------------- Home rules: R01, R03, R13, R14
# Code-only: each fact is the verdict, so Jev is never asked (see docs/detections/DESIGN.md).


def is_unicast_lan(ip: str) -> bool:
    """A real LAN address: internal, but not multicast, broadcast or unspecified."""
    if not is_internal(ip) or ip in ("0.0.0.0", "::") or ip.endswith(".255"):
        return False
    return not ipaddress.ip_address(ip).is_multicast


ESTABLISHED = {"SF", "S1", "S2", "S3", "RSTO", "RSTR"}


def subnet(ip: str) -> str | None:
    """IPv4 /24 a LAN address belongs to (home LANs here are /24s). None for IPv6."""
    return ip.rsplit(".", 1)[0] if ":" not in ip and is_unicast_lan(ip) else None


class Gateways(Detector):
    """Which address is each LAN's router. Configured (`network.gateways`) or learned from the logs.

    Learning: per /24, count the distinct devices that treat an address as their router. They
    send it DNS (port 53) or NAT-PMP/PCP port-mapping requests (5351, a router-only protocol), or
    it answers their DHCP. The first address that `min_clients` devices agree on is elected and
    then kept (sticky), so a rogue that later collects votes can't take over. A configured address
    settles its own /24; every other /24 (a VLAN the config doesn't list) is still learned. Emits
    no cases; it must be fed before the detectors that ask it.
    """

    name = "gateways"
    PERSIST: ClassVar[tuple[str, ...]] = ("leaders",)
    ROUTER_PORTS: ClassVar[set[int]] = {53, 5351}

    def __init__(self, configured: set[str] | None = None, min_clients: int = 3):
        self.configured, self.min_clients = set(configured or ()), min_clients
        self.votes: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))  # subnet -> ip -> clients
        self.leaders: dict[str, str] = {}  # subnet -> elected router

    def __contains__(self, ip: str) -> bool:
        return ip in self.configured or (bool(ip) and self.leaders.get(subnet(ip) or "") == ip)

    def configured_for(self, sub: str | None) -> str | None:
        """The configured gateway on this /24, if the config names one."""
        return next((ip for ip in self.configured if subnet(ip) == sub), None) if sub else None

    def leader(self, sub: str | None) -> str | None:
        return (self.configured_for(sub) or self.leaders.get(sub)) if sub else None

    def feed(self, rec: dict) -> list[Case]:
        if rec["_type"] == "conn" and rec.get("id.resp_p") in self.ROUTER_PORTS:
            self._vote(rec.get("id.resp_h", ""), rec.get("id.orig_h", ""))
        elif rec["_type"] == "dhcp" and rec.get("server_addr"):
            self._vote(rec["server_addr"], rec.get("assigned_addr") or rec.get("client_addr") or "")
        return []

    def _vote(self, ip: str, client: str) -> None:
        sub = subnet(ip)
        if sub is None or self.leader(sub) or client == ip or not is_unicast_lan(client):
            return
        clients = self.votes[sub][ip]
        clients.add(client)
        if len(clients) >= self.min_clients:
            self.leaders[sub] = ip
            log.info("learned router for %s.0/24 from the logs (%d devices use it)", sub, len(clients))


class Identity(Detector):
    """Who is behind an address: IP -> MAC from conn.log, MAC -> DHCP hostname from dhcp.log.

    Emits no cases. Fed first, so the pipeline can stamp every case with `device_mac` and
    `device_name` facts, and Assets can label a device by its DHCP hostname or MAC as well as
    by IP. Needed because an IP changes hands: a dock shared by two laptops gave both the same
    "main PC" label and mixed their baselines (2026-10-14). The hostname is network data (a
    device can claim any name), so it is shown escaped and never sent to the AI unless the owner
    mapped it to a name in assets.yaml.
    """

    name = "identity"
    PERSIST: ClassVar[tuple[str, ...]] = ("mac", "hostname", "last_ip")

    def __init__(self):
        self.mac: dict[str, str] = {}       # internal IP -> MAC
        self.hostname: dict[str, str] = {}  # MAC -> DHCP hostname
        self.last_ip: dict[str, str] = {}   # device key -> the address it was last seen on

    def feed(self, rec: dict) -> list[Case]:
        kind = rec["_type"]
        if kind == "conn":
            for ip_key, mac_key in (("id.orig_h", "orig_l2_addr"), ("id.resp_h", "resp_l2_addr")):
                ip, mac = rec.get(ip_key, ""), (rec.get(mac_key) or "").lower()
                if mac_ok(mac) and is_unicast_lan(ip):
                    if len(self.mac) > 50_000:
                        self.mac.clear()
                    self.mac[ip] = mac
                    self._note_ip(ip)
        elif kind == "dhcp":
            mac, name = (rec.get("mac") or "").lower(), (rec.get("host_name") or "").strip()
            if mac_ok(mac):
                if name:
                    if len(self.hostname) > 10_000:
                        self.hostname.clear()
                    self.hostname[mac] = name
                ip = rec.get("assigned_addr") or rec.get("client_addr") or ""
                if is_unicast_lan(ip):
                    self.mac[ip] = mac
                    self._note_ip(ip)
        return []

    def _note_ip(self, ip: str) -> None:
        """Remember the address a device is on, preferring IPv4: a link-local IPv6 address can't be the
        one a case is about (it never reaches the internet), and it would mislabel a merged case."""
        key = self.key(ip)
        if ":" not in ip or (key not in self.last_ip and not ip.lower().startswith("fe80:")):
            self.last_ip[key] = ip

    def key(self, ip: str) -> str:
        """The device key for an address: name:<hostname>, else mac:<address>, else the IP itself."""
        return device_id(ip, self.facts_for(ip))

    def ip_for(self, key: str) -> str:
        return self.last_ip.get(key, key)

    def ips_for(self, key: str) -> list[str]:
        """Every address known to belong to this device key."""
        return [ip for ip in self.mac if self.key(ip) == key]

    def mac_for(self, ip: str) -> str:
        return self.mac.get(ip, "")

    def hostname_for(self, ip: str) -> str:
        return self.hostname.get(self.mac.get(ip, ""), "")

    def facts_for(self, ip: str) -> dict:
        """The identity facts for a case on `ip`: only what is known."""
        out = {}
        if mac := self.mac_for(ip):
            out["device_mac"] = mac
            if name := self.hostname.get(mac, ""):
                out["device_name"] = name
        return out


class InternetExposure(Detector):
    """R01. A LAN device answers a connection started from the internet (port forward, UPnP, rogue listener).

    The mirror sits between the switch and the UDM, so forwarded traffic shows up after NAT as
    outside -> inside. Measured at home: 0 established inbound services, only unanswered P2P probes.
    Exposures already present during warmup count as known (an existing, intended port forward).

    Zeek guesses direction from the first packet it sees, so a VPN flow already running when
    capture starts looks "inbound". So flows in the first `startup` seconds are skipped, TCP must
    show the outside host's SYN, and UDP is dropped when Zeek flipped it or the device contacted
    that remote recently (a reply, not an exposure).
    """

    name = "exposure"
    PERSIST: ClassVar[tuple[str, ...]] = ("known", "last_mapping")
    MAPPING_PORTS: ClassVar[set[int]] = {5351, 1900}  # NAT-PMP/PCP, SSDP (UPnP discovery)

    def __init__(self, warmup: Warmup, stun_window: float = 600, mapping_window: float = 86400,
                 reply_window: float = 1800, startup: float = 120, expected: list[dict] | None = None):
        self.warmup, self.stun_window, self.mapping_window = warmup, stun_window, mapping_window
        self.reply_window, self.startup = reply_window, startup
        self.first_ts: float | None = None
        # Declared port forwards (config detectors.exposure.expected: host, proto, port) count as
        # known from the start, like one seen during warmup: config, not a suppression, so the
        # rule stays must_alert for everything else.
        self.known: set[tuple] = {(e["host"], str(e.get("proto", "tcp")).lower(), int(e["port"]))
                                  for e in (expected or ()) if e.get("host") and e.get("port")}
        self.recent_peer: dict[tuple, float] = {}  # (LAN host, remote) -> last outbound contact
        self.last_stun: dict[str, float] = {}     # host -> last outbound STUN (games, calls)
        self.last_mapping: dict[str, float] = {}  # host -> last port-mapping request to the router

    def feed(self, rec: dict) -> list[Case]:
        if rec["_type"] != "conn":
            return []
        src, dst, ts = rec.get("id.orig_h", ""), rec.get("id.resp_h", ""), rec["ts"]
        port, proto = rec.get("id.resp_p"), rec.get("proto", "")
        if self.first_ts is None:
            self.first_ts = ts
        if is_internal(src):
            if not is_internal(dst):
                self._remember(src, dst, ts)
            if proto == "udp" and port == 3478:
                self.last_stun[src] = ts
            elif port in self.MAPPING_PORTS and is_unicast_lan(dst):
                self.last_mapping[src] = ts
            return []
        if not is_unicast_lan(dst) or rec.get("conn_state") not in ESTABLISHED or not rec.get("resp_bytes"):
            return []
        if ts - self.first_ts < self.startup:
            return []  # already running when capture started: direction is a guess
        history = rec.get("history") or ""
        if proto == "tcp" and ("S" not in history or "^" in history):
            return []  # no SYN from outside seen: mid-stream or flipped, not proof of a listener
        if proto == "udp" and ("^" in history
                               # P2P apps punch UDP holes right after STUN; these are replies to that
                               or ts - self.last_stun.get(dst, -1e18) < self.stun_window
                               or ts - self.recent_peer.get((dst, src), -1e18) < self.reply_window):
            return []
        key = (dst, proto, port)
        if key in self.known:
            return []
        self.known.add(key)
        if self.warmup.learning(ts):
            return []
        mapped = ts - self.last_mapping.get(dst, -1e18) < self.mapping_window
        return [Case(self.name, dst, ts, "Device reachable from the internet",
                     {"proto": proto, "port": port, "service": rec.get("service") or "unknown",
                      "after_mapping_request": mapped, "dedupe": f"{proto}/{port}"},
                     must_alert=True, base_severity=5)]

    def _remember(self, host: str, remote: str, ts: float) -> None:
        self.recent_peer[(host, remote)] = ts
        if len(self.recent_peer) > 50_000:  # keep memory flat on a busy day
            cutoff = ts - self.reply_window
            self.recent_peer = {k: v for k, v in self.recent_peer.items() if v >= cutoff}


class ManagementAccess(Detector):
    """R03. A device touches the router's admin UI, or an admin port (SSH, RDP, SMB...) on another device.

    Same-switch device-to-device traffic is not on the mirror, so this sees routed/cross-VLAN
    attempts and anything aimed at the UDM. Sources in `admin_devices` and the gateways (configured
    or learned, see Gateways) are exempt; the router-UI clause waits until a gateway is known;
    (source, target, port) pairs seen during warmup count as known. Attempts count, not just
    successes, but severity follows the outcome: an accepted remote-control or router-admin
    session is 4 (alert), accepted file sharing 3, an unanswered attempt 2 (digest). Windows
    network discovery probing 445 across VLANs is an attempt, not an intrusion.
    """

    name = "mgmt_access"
    PERSIST: ClassVar[tuple[str, ...]] = ("known",)
    DEVICE_KEYED: ClassVar[tuple[str, ...]] = ("known",)
    ADMIN_PORTS: ClassVar[dict[int, str]] = {22: "SSH", 23: "Telnet", 445: "Windows file sharing (SMB)",
                                             3389: "Remote Desktop", 5900: "VNC remote control",
                                             8291: "router admin (Winbox)"}
    GATEWAY_PORTS: ClassVar[dict[int, str]] = {443: "router admin web page", 8443: "router admin web page"}

    SWEEP_WINDOW, SWEEP_TARGETS = 600, 5  # new admin-port pairs to this many devices in 10 min = a sweep

    def __init__(self, warmup: Warmup, gateways: Gateways | None = None, admin_devices: set[str] | None = None):
        self.warmup = warmup
        # admin_devices entries are addresses or device ids (name:<DHCP hostname>, mac:<address>): the
        # owner's phones run the UniFi app against the router's 443 and sit on private MACs, so an
        # address entry is brittle (two phones alerted on 2026-10-15/16; both carry the name "iPhone").
        self.gateways = gateways or Gateways()
        self.admins = {a.lower() if str(a).lower().startswith(("name:", "mac:")) else a for a in (admin_devices or ())}
        self.known: set[tuple] = set()
        self.recent: dict[str, deque] = defaultdict(deque)  # source -> (ts, target) of its new admin pairs
        self.swept: dict[str, float] = {}                   # source -> until when its sweep is already reported

    def feed(self, rec: dict) -> list[Case]:
        if rec["_type"] != "conn" or rec.get("proto") != "tcp":
            return []
        src, dst, port = rec.get("id.orig_h", ""), rec.get("id.resp_h", ""), rec.get("id.resp_p")
        if not is_unicast_lan(src) or not is_unicast_lan(dst) or src in self.gateways or src in self.admins:
            return []
        what = self.ADMIN_PORTS.get(port) or (self.GATEWAY_PORTS.get(port) if dst in self.gateways else None)
        if what is None or self.dev_key(src) in self.admins:  # identity only for admin-port traffic
            return []
        key = (self.dev_key(src), dst, port)
        if key in self.known:
            return []
        self.known.add(key)
        if self.warmup.learning(rec["ts"]):
            return []
        answered, target = rec.get("conn_state") in ESTABLISHED, "router" if dst in self.gateways else "device"
        ts = rec["ts"]
        # A worm: one source trying admin ports on device after device. WannaCry (CTU-297-1) made
        # 9,900 SMB attempts to other hosts in 16 min; as single unanswered probes each is only a
        # digest item, so the sweep itself is the alert, once an hour, and the probes it covers stay
        # learned but raise nothing more.
        q = self.recent[src]
        q.append((ts, dst))
        while q and ts - q[0][0] > self.SWEEP_WINDOW:
            q.popleft()
        targets = {d for _, d in q}
        if len(targets) >= self.SWEEP_TARGETS:
            if ts < self.swept.get(src, 0):
                return []
            self.swept[src] = ts + 3600
            return [Case(self.name, src, ts, "Admin-port sweep across the network",
                         {"what": what, "port": port, "target": target, "answered": answered, "sweep": True,
                          "targets": len(targets), "window_min": self.SWEEP_WINDOW // 60, "dedupe": f"sweep:{port}"},
                         base_severity=5)]
        severity = 2 if not answered else 4 if target == "router" or port != 445 else 3
        return [Case(self.name, src, ts, "Device tried an admin connection",
                     {"what": what, "port": port, "target": target, "answered": answered, "dedupe": f"{dst}:{port}"},
                     base_severity=severity)]


class CleartextAuth(Detector):
    """R13. Credentials or login protocols sent without encryption.

    Internet-bound -> digest (hygiene); telnet or an FTP login to the internet -> alert;
    inside the LAN -> log. Usernames and passwords are never copied into the case.
    """

    name = "cleartext_auth"
    PERSIST: ClassVar[tuple[str, ...]] = ("reported",)
    PORTS: ClassVar[dict[int, str]] = {23: "Telnet", 110: "POP3 email", 143: "IMAP email", 1883: "MQTT"}
    ANONYMOUS: ClassVar[set[str]] = {"anonymous", "ftp", "-"}

    def __init__(self):
        self.reported: set[tuple] = set()

    def feed(self, rec: dict) -> list[Case]:
        kind = rec["_type"]
        src, dst = rec.get("id.orig_h", ""), rec.get("id.resp_h", "")
        if not is_internal(src):
            return []
        if kind == "http" and rec.get("username"):
            what, indicators = "HTTP login (basic auth)", [rec["host"]] if rec.get("host") else []
        elif kind == "ftp" and rec.get("user") and rec["user"].lower() not in self.ANONYMOUS:
            what, indicators = "FTP login", []
        elif kind == "conn" and rec.get("proto") == "tcp" and rec.get("id.resp_p") in self.PORTS \
                and rec.get("conn_state") in ESTABLISHED and not is_internal(dst):
            what, indicators = self.PORTS[rec["id.resp_p"]], []
        else:
            return []
        key = (src, dst, what)
        if key in self.reported:
            return []
        self.reported.add(key)
        outside = not is_internal(dst)
        severity = (4 if what in ("Telnet", "FTP login") else 2) if outside else 1
        # The dedupe (and so the suppression indicator) names the protocol and "outside", not the server:
        # a device's cloud broker rotates addresses (a photo frame's MQTT went to three AWS addresses in
        # one day, 2026-10-15, and a per-address rule matched none of them). Inside the LAN the server
        # is the point, so it stays in the key.
        return [Case(self.name, src, rec["ts"], "Unencrypted login or protocol",
                     {"what": what, "port": rec.get("id.resp_p"), "outside": outside, "server": dst, **dests(dst),
                      "dedupe": f"{what}|outside" if outside else f"{what}|{dst}"},
                     indicators, base_severity=severity)]


class RogueDHCP(Detector):
    """R14. A DHCP server other than the router answers clients (hostile gateway/DNS, or a stray travel router).

    Uses dhcp.log `server_addr` and conn rows where something answered on udp/67 (Zeek logs the
    server as the responder). On a /24 whose gateway is in `network.gateways`, any other server is
    rogue. On every other /24 (the config lists one address; a VLAN'd network has a gateway per
    VLAN), one DHCP server is expected: the router learned by Gateways, the first server seen on
    that LAN, or any server seen during warmup. Anything else is rogue.
    """

    name = "rogue_dhcp"
    PERSIST: ClassVar[tuple[str, ...]] = ("trusted", "reported")

    def __init__(self, warmup: Warmup, gateways: Gateways | None = None):
        self.warmup, self.gateways = warmup, gateways or Gateways()
        self.trusted: dict[str, set[str]] = defaultdict(set)  # subnet -> DHCP servers accepted from the logs
        self.reported: set[str] = set()

    def feed(self, rec: dict) -> list[Case]:
        if rec["_type"] == "dhcp":
            server, how = rec.get("server_addr") or "", "DHCP reply"
        elif rec["_type"] == "conn" and rec.get("proto") == "udp" and rec.get("id.resp_p") == 67 \
                and rec.get("resp_bytes"):
            server, how = rec.get("id.resp_h", ""), "answered on the DHCP port"
        else:
            return []
        if not is_unicast_lan(server) or server in self.gateways or server in self.reported:
            return []
        sub = subnet(server) or server
        if server in self.trusted[sub]:
            return []
        if self.gateways.configured_for(sub) is None and (
                self.warmup.learning(rec["ts"])
                # the LAN's only DHCP server so far, and no learned router says otherwise
                or (self.gateways.leader(sub) is None and not self.trusted[sub])):
            self.trusted[sub].add(server)
            return []
        self.reported.add(server)
        return [Case(self.name, server, rec["ts"], "Unexpected DHCP server on the network",
                     {"how": how, "msg_types": ",".join(rec.get("msg_types") or [])},
                     must_alert=True, base_severity=5)]


class OddPort(Detector):
    """R06. Outbound on a port no device in the house has used, or a connection lasting hours.

    Reverse shells, tunnels, personal VPNs and proxyware pick rare ports and hold long sessions.
    Measured at home: 14 outbound proto/ports for the whole house. The house's port set and its
    long-lived (device, port) pairs are learned for `learn_days`, then saved with the rest of the
    state. Skipped, from a 14-hour home replay (2026-10-13):
      * UDP at or above port 1024: games and calls open new high UDP ports constantly
      * port 443 for the long-lived check: streams and push channels hold HTTPS open for hours
      * a new port to a service the device already uses (a camera rotating vendor ports
        32301/32403 to its own cloud): not the reverse-shell pattern
      * named dev services of a dev workstation (DevProfile)
    A (device, port, kind) is reported once every `reported_days`, not once forever.
    """

    name = "odd_port"
    PERSIST: ClassVar[tuple[str, ...]] = ("ports", "long_pairs", "services", "reported", "start", "names")
    DEVICE_KEYED: ClassVar[tuple[str, ...]] = ("long_pairs", "services", "reported")

    def __init__(self, learn_days: float = 7, long_hours: float = 4, dev: DevProfile | None = None,
                 reported_days: float = 7):
        self.learn, self.long_s, self.dev = learn_days * 86400, long_hours * 3600, dev or DevProfile()
        self.reported_s = reported_days * 86400
        self.start: float | None = None
        self.ports: set[str] = set()            # "tcp/443" used by any device
        self.long_pairs: set[tuple] = set()     # (host, "tcp/5223") that normally runs for hours
        self.services: dict[str, set[str]] = defaultdict(set)  # host -> base domains it has connected to
        self.reported: dict[tuple, float] = {}  # (host, "tcp/4444", new_for_house) -> when reported
        self.names: dict[str, str] = {}         # external IP -> name from DNS or TLS (saved, like hourly's)

    def restore(self, data: dict) -> None:
        super().restore(data)
        if isinstance(self.reported, set):  # the pre-2026-10-15 set: keep those silences, expire new ones
            self.reported = dict.fromkeys(self.reported, PERMANENT)

    def snapshot(self) -> dict:
        self.reported = prune_reported(self.reported, max(self.reported.values(), default=0.0), self.reported_s)
        return super().snapshot()

    def feed(self, rec: dict) -> list[Case]:
        kind = rec["_type"]
        if kind == "dns":
            if len(self.names) > 200_000:  # bound memory on a long run; names are relearned quickly
                self.names.clear()
            for a in rec.get("answers") or ():
                self.names[a] = rec.get("query") or ""
            return []
        if kind == "ssl" and rec.get("server_name"):
            self.names[rec.get("id.resp_h", "")] = rec["server_name"]
            return []
        if kind != "conn" or rec.get("conn_state") not in ESTABLISHED:
            return []
        src, dst, proto, port = rec.get("id.orig_h", ""), rec.get("id.resp_h", ""), rec.get("proto"), rec.get("id.resp_p")
        if not is_internal(src) or is_internal(dst) or proto not in ("tcp", "udp") or not isinstance(port, int):
            return []
        if proto == "udp" and port >= 1024:
            return []
        if self.dev.covers(src, self.names.get(dst)):
            return []
        pp, dur, who = f"{proto}/{port}", float(rec.get("duration") or 0), self.dev_key(src)
        name = self.names.get(dst)
        dom = base_domain(name) if name else ""
        known_service = bool(dom) and dom in self.services[who]
        if dom:
            self.services[who].add(dom)
        if self.start is None:
            self.start = rec["ts"]
        if rec["ts"] - self.start < self.learn:
            self.ports.add(pp)
            if dur > self.long_s:
                self.long_pairs.add((who, pp))
            return []
        new_port = pp not in self.ports and not known_service
        long_new = dur > self.long_s and port != 443 and (who, pp) not in self.long_pairs
        if not (new_port or long_new) or still_reported(self.reported, (who, pp, new_port), rec["ts"], self.reported_s):
            return []
        self.reported[(who, pp, new_port)] = rec["ts"]
        return [Case(self.name, src, rec["ts"], "Connection on an unusual port" if new_port else "Unusually long connection",
                     {"proto": proto, "port": port, "service": rec.get("service") or "unknown", **dests(dst),
                      "new_for_house": new_port, "minutes": round(dur / 60),
                      "mb_out": round((rec.get("orig_bytes") or 0) / 1e6, 1),
                      "mb_in": round((rec.get("resp_bytes") or 0) / 1e6, 1),
                      "learn_days": round(self.learn / 86400), "dedupe": pp},
                     [name] if name else [], base_severity=3)]


class DnsBypass(Detector):
    """R07. A device resolves names somewhere other than the household's resolver.

    Plain DNS to an outside server, DNS-over-TLS (853), DNS-over-QUIC (853/8853), or DoH to a
    well-known resolver. Devices that already did it during warmup (a camera with a hardcoded
    resolver, measured at home) are learned as normal. Apple Private Relay is not a bypass.
    """

    name = "dns_bypass"
    PERSIST: ClassVar[tuple[str, ...]] = ("known",)
    DEVICE_KEYED: ClassVar[tuple[str, ...]] = ("known",)
    DOH_NAMES: ClassVar[frozenset[str]] = frozenset({
        "dns.google", "cloudflare-dns.com", "dns.quad9.net", "nextdns.io", "doh.opendns.com",
        "dns.adguard-dns.com", "doh.cleanbrowsing.org", "dns.mullvad.net", "doh.dns.sb"})

    def __init__(self, warmup: Warmup):
        self.warmup = warmup
        self.known: set[tuple] = set()   # (host, kind)

    def feed(self, rec: dict) -> list[Case]:
        kind = rec["_type"]
        src, dst = rec.get("id.orig_h", ""), rec.get("id.resp_h", "")
        if not is_internal(src) or is_internal(dst):
            return []
        how = None
        if kind == "conn" and rec.get("conn_state") in ESTABLISHED:
            port, proto = rec.get("id.resp_p"), rec.get("proto")
            if port == 53:
                how = "plain DNS to an outside server"
            elif port == 853 and proto == "tcp":
                how = "DNS over TLS"
            elif port in (853, 8853) and proto == "udp":
                how = "DNS over QUIC"
        elif kind == "ssl" and suffix_match(rec.get("server_name") or "", self.DOH_NAMES):
            how = "DNS over HTTPS"
        if how is None:
            return []
        key = (self.dev_key(src), how)
        if key in self.known:
            return []
        self.known.add(key)
        if self.warmup.learning(rec["ts"]):
            return []
        encrypted = how != "plain DNS to an outside server"
        return [Case(self.name, src, rec["ts"], "DNS bypassing the home resolver",
                     {"how": how, "encrypted": encrypted, "dedupe": how, **dests(dst)},
                     [rec["server_name"]] if kind == "ssl" else [], base_severity=3 if encrypted else 2)]


FIXED_ROLE_WORDS = ("camera", "doorbell", "tv", "streamer", "chromecast", "hub", "iot", "printer", "speaker",
                    "sensor", "thermostat", "plug", "bulb", "frame", "network gear", "router", "access point",
                    "nvr", "vacuum", "appliance")


def fixed_function_hosts(assets_table: dict | None) -> dict[str, str]:
    """IP -> role for devices whose assets.yaml role marks them fixed-function (predictable traffic)."""
    out = {}
    for ip, a in (assets_table or {}).items():
        role = str((a or {}).get("role", "")).lower()
        if any(re.search(rf"\b{re.escape(w)}\b", role) for w in FIXED_ROLE_WORDS):
            out[str(ip)] = role
    return out


# Roles whose device an employer's tooling already watches: an EDR/security agent uploads telemetry
# (the work laptop's ~1 GB a morning to plain AWS, #139/#325) that a home monitor should not page
# the owner for. HourlyProfile caps that device's upload_spike at digest whatever the destination.
# Not the bare word "managed": it would match a "managed switch" or a "self-managed NAS".
MANAGED_ROLE_WORDS = ("employer-managed", "security agent", "edr", "work laptop", "corporate")


def managed_hosts(assets_table: dict | None) -> dict[str, str]:
    """Device key or IP -> role for devices whose assets.yaml role marks them employer-managed or
    as carrying a security agent. Keys may be an address, `name:<dhcp hostname>` or `mac:<address>`
    (the ids lowercased, as Identity keys them)."""
    out = {}
    for key, a in (assets_table or {}).items():
        role = str((a or {}).get("role", "")).lower()
        if any(re.search(rf"\b{re.escape(w)}\b", role) for w in MANAGED_ROLE_WORDS):
            key = str(key)
            out[key.lower() if key.lower().startswith(("name:", "mac:")) else key] = role
    return out


class IotDrift(Detector):
    """R02. A camera, TV, hub or other fixed-function device talks to networks it never used.

    Botnets, proxyware and residential-proxy SDKs turn quiet devices into busy ones. Each device
    (from assets.yaml roles) learns its own networks (ASN), countries and ports for its first
    `learn_days`. After that, a new country, a new port, or 3+ new networks within an hour is a
    case. Destinations whose name belongs to a service the device already uses are skipped:
    vendors move between clouds and CDNs. Needs the IP -> network file (`tapwatch update-feeds`).
    Jev isn't asked whether a network or country is OK, only whether the behaviour fits the role.
    """

    name = "iot_drift"
    PERSIST: ClassVar[tuple[str, ...]] = ("first", "asns", "countries", "ports", "services", "reported", "names")
    DEVICE_KEYED: ClassVar[tuple[str, ...]] = ("first", "asns", "countries", "ports", "services", "reported", "burst")

    def __init__(self, hosts: dict[str, str], asn=None, learn_days: float = 7, new_asns: int = 3):
        self.hosts, self.asn, self.learn, self.new_asns = hosts, asn, learn_days * 86400, new_asns
        self.first: dict[str, float] = {}
        self.asns: dict[str, set] = defaultdict(set)
        self.countries: dict[str, set] = defaultdict(set)
        self.ports: dict[str, set] = defaultdict(set)
        self.services: dict[str, set] = defaultdict(set)
        self.reported: set[tuple] = set()
        self.names: dict[str, str] = {}
        self.burst: dict[str, deque] = defaultdict(deque)  # host -> (ts, new asn)

    def feed(self, rec: dict) -> list[Case]:
        kind = rec["_type"]
        if kind == "dns":
            if len(self.names) > 200_000:  # bound memory on a long run; names are relearned quickly
                self.names.clear()
            for a in rec.get("answers") or ():
                self.names[a] = rec.get("query") or ""
            return []
        if kind == "ssl" and rec.get("server_name"):
            self.names[rec.get("id.resp_h", "")] = rec["server_name"]
            return []
        if kind != "conn" or not self.asn or rec.get("conn_state") not in ESTABLISHED:
            return []
        src, dst, port, proto = rec.get("id.orig_h", ""), rec.get("id.resp_h", ""), rec.get("id.resp_p"), rec.get("proto")
        if src not in self.hosts or is_internal(dst) or proto not in ("tcp", "udp"):
            return []
        ip, src = src, self.dev_key(src)  # baselines follow the device; the role and the case use the address
        if proto == "udp" and port == 123:
            return []  # NTP pools are volunteer servers worldwide: a "new country" every few hours (measured)
        hit = self.asn.lookup(dst)
        if not hit:
            return []
        asn, country = hit
        name = self.names.get(dst)
        dom = base_domain(name) if name else ""
        known_service = bool(dom) and dom in self.services[src]
        if dom:
            self.services[src].add(dom)
        pp = f"{proto}/{port}" if proto == "tcp" or (isinstance(port, int) and port < 1024) else ""
        ts = rec["ts"]
        start = self.first.setdefault(src, ts)
        if ts - start < self.learn:
            self.asns[src].add(asn)
            self.countries[src].add(country)
            if pp:
                self.ports[src].add(pp)
            return []
        out = []
        if not known_service:
            if country not in self.countries[src] and (src, "country", country) not in self.reported:
                self.reported.add((src, "country", country))
                out.append(self._case(ip, src, ts, "country", country, name, port))
            if pp and pp not in self.ports[src] and (src, "port", pp) not in self.reported:
                self.reported.add((src, "port", pp))
                out.append(self._case(ip, src, ts, "port", pp, name, port))
            if asn not in self.asns[src]:
                b = self.burst[src]
                b.append((ts, asn))
                while b and ts - b[0][0] > 3600:
                    b.popleft()
                fresh = {a for _, a in b}
                if len(fresh) >= self.new_asns and (src, "asns", int(ts // 3600)) not in self.reported:
                    self.reported.add((src, "asns", int(ts // 3600)))
                    out.append(self._case(ip, src, ts, "networks", str(len(fresh)), name, port))
        self.asns[src].add(asn)  # report each novelty once, then treat it as known
        self.countries[src].add(country)
        if pp:
            self.ports[src].add(pp)
        return out

    def _case(self, host, who, ts, what, value, name, port) -> Case:
        return Case(self.name, host, ts, "Fixed-function device talking somewhere new",
                    {"role": self.hosts[host], "what": what, "value": value, "port": port,
                     "known_networks": len(self.asns[who]), "known_countries": len(self.countries[who]),
                     "dedupe": f"{what}:{value}"},
                    [name] if name else [], base_severity=3)


class TlsOddities(Detector):
    """R10. Encrypted sessions that stack several weak oddities: no server name, an address no DNS
    lookup explains, a port other than 443, a self-signed or expired certificate. Each alone is
    common (measured: 22% of TLS had no name; 0.7% of TCP went to unexplained IPs). Three together
    look like hand-rolled malware or bare-IP command-and-control. Score 3 is a digest item, 4 goes
    to Jev. Windows' "unable to get local issuer" is Zeek missing intermediates, never counted.

    A device that already did this on the same port during warmup is learned: the home camera
    talks to its vendor with no name, hardcoded IPs and self-signed TLS on port 32403 (measured,
    6 servers in one night). Reported once per (device, port) every `reported_days`, not per
    server; a pair learned during warmup is kept for good.
    """

    name = "tls_odd"
    PERSIST: ClassVar[tuple[str, ...]] = ("reported",)
    DEVICE_KEYED: ClassVar[tuple[str, ...]] = ("reported",)
    BAD_CERT: ClassVar[set[str]] = {"self signed certificate", "self signed certificate in certificate chain",
                                    "certificate has expired"}

    def __init__(self, warmup: Warmup | None = None, threshold: int = 3, reported_days: float = 7):
        self.warmup, self.threshold, self.reported_s = warmup or Warmup(0), threshold, reported_days * 86400
        self.answered: dict[str, float] = {}   # IP -> last time a DNS answer named it
        self.reported: dict[tuple, float] = {}  # (device, port) -> when reported, or PERMANENT (learned in warmup)

    def restore(self, data: dict) -> None:
        super().restore(data)
        if isinstance(self.reported, set):  # the pre-2026-10-15 set: can't tell learned from reported, keep all
            self.reported = dict.fromkeys(self.reported, PERMANENT)

    def snapshot(self) -> dict:
        self.reported = prune_reported(self.reported, max(self.reported.values(), default=0.0), self.reported_s)
        return super().snapshot()

    def feed(self, rec: dict) -> list[Case]:
        kind, ts = rec["_type"], rec.get("ts", 0.0)
        if kind == "dns":
            for a in rec.get("answers") or ():
                self.answered[a] = ts
            if len(self.answered) > 200_000:
                self.answered = {k: v for k, v in self.answered.items() if ts - v < 3600}
            return []
        if kind != "ssl" or not rec.get("established"):
            return []
        src, dst, port = rec.get("id.orig_h", ""), rec.get("id.resp_h", ""), rec.get("id.resp_p")
        if not is_internal(src) or is_internal(dst):
            return []
        who = self.dev_key(src)
        if still_reported(self.reported, (who, port), ts, self.reported_s):
            return []
        # Real-time media (WebRTC's DTLS-SRTP) has no server name and self-signed certificates on both ends by
        # design: the fingerprints travel through the app's signalling. Measured 2026-10-17 over two days of ssl.log:
        # every DTLS session with a client certificate was a call (the baby monitor streaming to a phone on cellular,
        # 13, eight digest cases #332-#417 on eight ICE-chosen ports; the Mac on video calls, 6; four others, 1-4).
        # Those two signs don't count for that shape; port and address still do, so it stays under the threshold
        # until another sign (JA4) joins. client_cert_chain_fuids is the Zeek 4/5 name of the field.
        media = (rec.get("version") or "").startswith("DTLS") and bool(rec.get("client_cert_chain_fps")
                                                                        or rec.get("client_cert_chain_fuids"))
        signs = {"no_name": not rec.get("server_name") and not media,
                 "unexplained_ip": ts - self.answered.get(dst, -1e18) > 3600,
                 "odd_port": port != 443,
                 "bad_cert": rec.get("validation_status") in self.BAD_CERT and not media}
        score = sum(signs.values())
        if score < self.threshold:
            return []
        learning = self.warmup.learning(ts)
        self.reported[(who, port)] = PERMANENT if learning else ts
        if learning:
            return []
        cat, cat_source = resolve(rec.get("server_name"))
        return [Case(self.name, src, ts, "Unusual encrypted connection",
                     {**signs, "score": score, "port": port, "dedupe": f"{dst}:{port}", **dests(dst),
                      "category": cat, "category_source": cat_source},
                     [rec["server_name"]] if rec.get("server_name") else [], base_severity=2 if score < 4 else 3)]


class TakeoverChannel(Detector):
    """R16. A device uses a channel that taking over a machine or its accounts needs.

    With no EDR or SaaS audit logs, an account or machine takeover shows on the network as the
    attacker's plumbing: an out-of-band callback or webhook catcher (where a prompt-injected agent
    or a token stealer posts secrets), a paste or file-drop site, a tunnel that opens a way in,
    or a remote-control tool. Matched by DNS answer (resolved names only), TLS server name or
    HTTP host. Applies to every device and ignores the dev profile: dev work is exactly what
    an injected agent would hide behind. Exfil and drop sites always alert; tunnels and remote
    tools alert but can be suppressed per device.

    `expected` entries cover a tool someone uses on purpose (a work laptop's remote-support
    app). For that device and service, sightings never raise a case, because the client polls its
    servers all day even when idle (measured: about 20 KB per 10 min). Outside the entry's
    `hours`, a live session still alerts: at least `session_bytes` to the service's servers
    within 10 minutes. An entry with a `mac` stops applying when a DHCP lease shows that address
    given to a different device. Callback and file-drop services can't be marked expected.
    """

    name = "takeover"
    PERSIST: ClassVar[tuple[str, ...]] = ("reported", "leases")
    CHANNELS: ClassVar[dict[str, frozenset[str]]] = {
        "callback": frozenset({
            "webhook.site", "requestbin.net", "requestcatcher.com", "pipedream.net", "beeceptor.com",
            "hookbin.com", "interact.sh", "oast.fun", "oast.pro", "oast.live", "oast.site", "oast.online",
            "oast.me", "oastify.com", "burpcollaborator.net", "canarytokens.com", "dnslog.cn", "ceye.io"}),
        "file_drop": frozenset({
            "pastebin.com", "paste.ee", "hastebin.com", "rentry.co", "transfer.sh", "file.io", "temp.sh",
            "0x0.st", "bashupload.com", "gofile.io", "catbox.moe", "oshi.at", "api.telegram.org"}),
        "tunnel": frozenset({
            "ngrok.io", "ngrok.app", "ngrok-free.app", "ngrok.dev", "ngrok-free.dev", "trycloudflare.com",
            "loca.lt", "localtunnel.me", "serveo.net", "localhost.run", "pinggy.io", "pinggy.link",
            "bore.pub", "tunnelmole.net", "devtunnels.ms", "playit.gg"}),
        "remote_control": frozenset({
            "anydesk.com", "teamviewer.com", "rustdesk.com", "screenconnect.com", "splashtop.com",
            "getscreen.me", "remotepc.com", "logmein.com", "logme.in", "atera.com", "ammyy.com",
            "supremocontrol.com", "simple-help.com", "meshcentral.com"}),
    }
    ALWAYS: ClassVar[set[str]] = {"callback", "file_drop"}
    SESSION_PORTS: ClassVar[dict[str, set[int]]] = {"teamviewer.com": {5938}, "anydesk.com": {7070},
                                                    "rustdesk.com": {21115, 21116, 21117, 21118, 21119}}
    SESSION_WINDOW = 600

    def __init__(self, extra: dict[str, list[str]] | None = None, expected: list[dict] | None = None,
                 session_bytes: int = 2_000_000, timezone: str | None = None):
        self.channels = {k: v | {d.lower().strip(".") for d in (extra or {}).get(k, ())}
                         for k, v in self.CHANNELS.items()}
        self.session_bytes = session_bytes
        self.tz = ZoneInfo(timezone) if timezone else None  # None = this machine's local time
        self.expected: dict[tuple, dict] = {}  # (host, service) -> {"hours", "spec", "mac"}
        for e in expected or ():
            for svc in e.get("services", ()):
                svc = svc.lower().strip(".")
                channel = next((c for c, doms in self.channels.items() if svc in doms), None)
                if channel is None or channel in self.ALWAYS:
                    log.warning("takeover.expected: %s is not a tunnel or remote-control service; ignored", svc)
                    continue
                spec = e.get("hours", "")
                self.expected[(e["host"], svc)] = {"hours": parse_hours(spec) if spec else None, "spec": spec,
                                                   "mac": (e.get("mac") or "").lower()}
        self.leases: dict[str, str] = {}                 # ip -> MAC from the latest DHCP lease
        self.lookups: dict[str, tuple] = {}              # host -> (ts, service, name, answers) of its last remote-control lookup
        self.service_ips: dict[tuple, set[str]] = defaultdict(set)   # (host, service) -> server IPs
        self.traffic: dict[tuple, deque] = defaultdict(deque)        # (host, service) -> (ts, bytes)
        self.reported: set[tuple] = set()

    def feed(self, rec: dict) -> list[Case]:
        kind = rec["_type"]
        if kind == "dhcp" and rec.get("assigned_addr") and rec.get("mac"):
            self.leases[rec["assigned_addr"]] = rec["mac"].lower()
            return []
        if kind == "conn":
            return self._followed_lookup(rec) + self._session(rec)
        if kind == "dns" and rec.get("rcode_name") == "NOERROR":
            name, via = rec.get("query"), "DNS"
        elif kind == "ssl":
            name, via = rec.get("server_name"), "TLS"
        elif kind == "http":
            name, via = rec.get("host"), "HTTP"
        else:
            return []
        host = rec.get("id.orig_h", "")
        if not name or not is_unicast_lan(host):
            return []
        for channel, domains in self.channels.items():
            hit = suffix_match(name, domains)
            if hit:
                break
        else:
            return []
        if self._expected(host, hit):
            ips = self.service_ips[(host, hit)]  # learn where the tool's servers are, to measure sessions
            ips.update(a for a in (rec.get("answers") or []) if _is_ip(a))
            if kind != "dns":
                ips.add(rec.get("id.resp_h", ""))
            return []
        if (host, hit) in self.reported:
            return []
        if channel == "remote_control" and via == "DNS":
            # Resolving teamviewer.com is also what visiting its website does. The case needs
            # contact: TLS/HTTP to the service, or a connection to one of these answers within
            # LOOKUP_FOLLOW seconds (_followed_lookup). Callback and file-drop lookups stay as they
            # are: there the lookup itself is the signal.
            if len(self.lookups) > 10_000:
                self.lookups.clear()
            self.lookups[host] = (rec["ts"], hit, name, {a for a in (rec.get("answers") or []) if _is_ip(a)})
            return []
        return self._raise(host, rec["ts"], channel, hit, name, via,
                           *((rec.get("answers") or []) if kind == "dns" else [rec.get("id.resp_h")]))

    LOOKUP_FOLLOW = 60  # seconds between a remote-control vendor lookup and a connection to its answer

    def _raise(self, host: str, ts: float, channel: str, hit: str, name: str, via: str, *addrs) -> list[Case]:
        self.reported.add((host, hit))
        always = channel in self.ALWAYS
        indicators = [hit] + ([name] if name.lower().rstrip(".") != hit else [])  # service first: stable key
        return [Case(self.name, host, ts, "Possible takeover: " + channel.replace("_", " ") + " service",
                     {"channel": channel, "via": via, "dedupe": hit, **dests(*addrs)},
                     indicators, must_alert=always, base_severity=5 if always else 4)]

    def _followed_lookup(self, rec: dict) -> list[Case]:
        host, dst, ts = rec.get("id.orig_h", ""), rec.get("id.resp_h", ""), rec["ts"]
        p = self.lookups.get(host)
        if not p or dst not in p[3] or ts - p[0] > self.LOOKUP_FOLLOW or (host, p[1]) in self.reported:
            return []
        del self.lookups[host]
        return self._raise(host, ts, "remote_control", p[1], p[2], "DNS, then a connection to the answer", dst)

    def _expected(self, host: str, service: str) -> dict | None:
        e = self.expected.get((host, service))
        if e and e["mac"] and self.leases.get(host, e["mac"]) != e["mac"]:
            return None  # that address now belongs to a different device
        return e

    def _session(self, rec: dict) -> list[Case]:
        host, dst, ts = rec.get("id.orig_h", ""), rec.get("id.resp_h", ""), rec["ts"]
        for (h, svc) in self.expected:
            if h != host or (dst not in self.service_ips[(h, svc)]
                             and rec.get("id.resp_p") not in self.SESSION_PORTS.get(svc, ())):
                continue
            e = self._expected(h, svc)
            if e is None or e["hours"] is None:
                return []
            win = self.traffic[(h, svc)]
            win.append((ts, int(rec.get("orig_bytes") or 0) + int(rec.get("resp_bytes") or 0)))
            while win and ts - win[0][0] > self.SESSION_WINDOW:
                win.popleft()
            total = sum(b for _, b in win)
            when = datetime.fromtimestamp(ts, self.tz)
            day = when.date().isoformat()
            if total < self.session_bytes or in_hours(when, e["hours"]) or (h, svc, day) in self.reported:
                return []
            self.reported.add((h, svc, day))
            return [Case(self.name, h, ts, "Remote-control session outside expected hours",
                         {"channel": "remote_control", "via": "traffic", "session": True,
                          "mb": round(total / 1e6, 1), "expected_hours": e["spec"], "dedupe": f"{svc}|{day}"},
                         [svc], base_severity=4)]
        return []


DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


def parse_hours(spec: str) -> tuple[set[int], int, int]:
    """'Mon-Fri 08:00-18:00' (or 'Mon,Wed 9-17') -> (weekdays 0=Mon, start minute, end minute)."""
    days_part, _, time_part = spec.strip().lower().partition(" ")
    days: set[int] = set()
    for chunk in days_part.split(","):
        a, _, b = chunk.partition("-")
        i, j = DAYS.index(a[:3]), DAYS.index((b or a)[:3])
        days.update(range(i, j + 1) if i <= j else [*range(i, 7), *range(j + 1)])

    def minute(t: str) -> int:
        h, _, m = t.partition(":")
        return int(h) * 60 + int(m or 0)

    start, _, end = time_part.strip().partition("-")
    return days, minute(start), minute(end)


def in_hours(when: datetime, hours: tuple[set[int], int, int]) -> bool:
    days, start, end = hours
    return when.weekday() in days and start <= when.hour * 60 + when.minute < end


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
    except ValueError:
        return False
    return True

# ------------------------------------------------------- Router syslog (UniFi CEF, syslogin.py)


class UdmIps(Detector):
    """The router's own IPS (UniFi CyberSecure / Suricata signatures) from its CEF syslog.

    The router already matches signatures; tapwatch adds case management, dedupe and routing.
    Inbound attempts it blocked (internet noise like "ET DROP Dshield") are log-only. A
    high-risk alert it did not block always alerts. Everything else goes through normal routing.
    """

    name = "udm_ips"

    def feed(self, rec: dict) -> list[Case]:
        if rec["_type"] != "udm":
            return []
        sig = rec.get("UNIFIipsSignature") or ""
        if not sig and "intrusion" not in (rec.get("UNIFIsubCategory") or "").lower():
            return []
        src, dst = rec.get("src", ""), rec.get("dst", "")
        host = src if is_internal(src) else dst if is_internal(dst) else rec.get("sender", "")
        outbound = is_internal(src) and not is_internal(dst)
        blocked = "block" in (rec.get("name") or "").lower()
        risk = (rec.get("UNIFIrisk") or "").lower()
        must = risk in ("high", "critical") and not blocked
        sev = 5 if must else 1 if blocked and not outbound else 3 if risk in ("high", "critical") else 2
        return [Case(self.name, host, rec["ts"], "Router IPS signature matched",
                     {"signature": sig, "risk": risk or "unknown", "blocked": blocked,
                      "direction": "outbound" if outbound else "inbound" if is_internal(dst) else "other",
                      "port": rec.get("dpt"), "dedupe": rec.get("UNIFIipsSignatureId") or sig},
                     must_alert=must, base_severity=sev)]


def _admin_event(rec: dict) -> bool:
    if rec.get("UNIFIadmin"):
        return True
    text = " ".join(str(rec.get(k) or "") for k in ("name", "msg", "UNIFIsubCategory")).lower()
    return bool(rec.get("suser")) and any(w in text for w in ("login", "log in", "logged in", "sign in",
                                                                "accessed", "authenticat", "ssh"))


class UdmAdmin(Detector):
    """R11. Someone logs in to the router's admin, from a new place or after repeated failures.

    The router controls everything else, so stolen UniFi credentials are the worst event in the
    house, and the network can't see them: the login is to the router itself. Reads the
    router's CEF admin events (UNIFIadmin / suser, src, UNIFIaccessMethod). A (user, source)
    pair not seen during warmup always alerts. Whether the owner did it is a fact only the owner
    knows, so Jev can't supply it, and a wrong "routine" would hide the worst case. 5+ failures
    from one source in 10 minutes alerts too.
    """

    name = "udm_admin"
    PERSIST: ClassVar[tuple[str, ...]] = ("known",)

    def __init__(self, warmup: Warmup, fail_threshold: int = 5, window: float = 600):
        self.warmup, self.fail_threshold, self.window = warmup, fail_threshold, window
        self.known: set[tuple] = set()
        self.fails: dict[str, deque] = defaultdict(deque)
        self.fail_reported: dict[str, float] = {}

    def feed(self, rec: dict) -> list[Case]:
        if rec["_type"] != "udm" or not _admin_event(rec):
            return []
        user = rec.get("UNIFIadmin") or rec.get("suser") or "unknown"
        src, ts = rec.get("src") or "unknown", rec["ts"]
        how = rec.get("UNIFIaccessMethod") or rec.get("UNIFIauthMethod") or ""
        text = " ".join(str(rec.get(k) or "") for k in ("name", "msg", "outcome", "reason")).lower()
        failed = any(w in text for w in ("fail", "invalid", "denied", "incorrect", "wrong"))
        host = src if is_unicast_lan(src) else rec.get("sender", "")
        if failed:
            q = self.fails[src]
            q.append(ts)
            while q and ts - q[0] > self.window:
                q.popleft()
            if len(q) >= self.fail_threshold and ts - self.fail_reported.get(src, -1e18) > self.window:
                self.fail_reported[src] = ts
                return [Case(self.name, host, ts, "Repeated failed router admin logins",
                             {"failed": True, "count": len(q), "from_lan": is_internal(src), "method": how,
                              "dedupe": f"fail|{src}"}, [user], must_alert=True, base_severity=5)]
            return []
        key = (user, src)
        if key in self.known:
            return []
        self.known.add(key)
        if self.warmup.learning(ts):
            return []
        return [Case(self.name, host, ts, "Router admin login from a new place",
                     {"failed": False, "from_lan": is_internal(src), "method": how, "dedupe": f"{user}|{src}"},
                     [user], must_alert=True, base_severity=5)]


def _expected_services(takeover_cfg: dict) -> dict[str, set[str]]:
    """host -> services it's expected to poll, from takeover.expected (remote-support tools)."""
    out: dict[str, set[str]] = defaultdict(set)
    for e in takeover_cfg.get("expected", ()) or ():
        out[e.get("host", "")].update(s.lower().strip(".") for s in e.get("services", ()))
    return dict(out)


class FeedSilence(Detector):
    """R22. A log feed tapwatch relies on has stopped arriving, so the rules that read it are blind.

    The monitor did not monitor itself: osquery's watchdog denylisted the Windows socket query on 2026-10-14
    and again on 2026-10-16, and R21 and the Windows host context were blind for a day each time before a
    person noticed. Each expected feed gets a longest-allowed silence; `tick` (once a minute) raises one case
    per silence, and a row arriving again re-arms it. Silence is measured from the feed's last row or from
    tapwatch's own start, whichever is later, so a restart gives every feed a full grace period and a feed
    that was already dead at start is still reported once the period passes.

    Limits, from the gaps measured over 2026-10-15..17 (two days): Zeek's conn and dns rows never paused
    over 0.1 min at the 99.9th percentile; the one long gap was the box's reboot (34 min), which this rule
    should report. The Windows socket query ran every 1.1 min until it stopped, Sysmon every 1.3, the
    5-minute snapshots within 5.4; WSL's eBPF connections idle up to 16 min at night and its 1-minute
    socket history up to 8. Inventory queries (hourly to daily) and the router syslog (178 rows in two
    days) are too sparse to watch and are not expected.
    """

    name = "feed_silence"
    ZEEK: ClassVar[dict[str, int]] = {"conn": 1200, "dns": 1200}
    WINDOWS: ClassVar[dict[str, int]] = {"outbound_connections": 600, "sysmon_events": 900, "host_addresses": 1200,
                                         "process_signatures": 1200}
    LINUX: ClassVar[dict[str, int]] = {"outbound_connections_ctx": 1800, "bpf_process_events": 900,
                                       "bpf_connections": 3600, "host_addresses": 1800}

    def __init__(self, expected: dict[str, float], host: str = "this PC", started: float | None = None):
        self.expected = dict(expected)   # feed key -> longest allowed silence, seconds
        self.host = host
        self.started = time.time() if started is None else started
        self.last: dict[str, float] = {}
        self.silent: set[str] = set()

    @staticmethod
    def key(rec: dict) -> str:
        """Zeek feeds by record type; agent feeds by log directory and query name (two agents share the names)."""
        if rec.get("_type") == "osquery":
            return f"{rec.get('_log', '')}|{rec.get('name', '')}"
        return str(rec.get("_type", ""))

    @staticmethod
    def describe(key: str) -> tuple[str, str]:
        """(feed name, where it comes from) for the case."""
        if "|" in key:
            where, name = key.split("|", 1)
            return name, "the Windows agent" if where.startswith("/mnt/") else "the Linux agent"
        return f"{key}.log", "the network tap"

    def feed(self, rec: dict) -> list[Case]:
        key, ts = self.key(rec), rec.get("ts") or 0.0
        if key in self.expected and ts:
            self.last[key] = max(self.last.get(key, 0.0), float(ts))
            self.silent.discard(key)  # resumed: the next silence is a new case
        return []

    def tick(self, now: float) -> list[Case]:
        out = []
        for key, limit in self.expected.items():
            since = max(self.last.get(key, 0.0), self.started)
            if key in self.silent or now - since < limit:
                continue
            self.silent.add(key)
            name, where = self.describe(key)
            out.append(Case(self.name, self.host, now, "A log feed has stopped arriving",
                            {"feed": name, "source": where, "silent_minutes": round((now - since) / 60),
                             "limit_minutes": round(limit / 60), "never_seen": key not in self.last,
                             "dedupe": key},
                            [name], base_severity=4))
        return out


def feed_expectations(cfg: dict) -> dict[str, float]:
    """Which feeds R22 expects and how long each may be silent: Zeek's conn and dns, plus the agent feeds of
    every results log that exists (`host_context.results_logs`), keyed like FeedSilence.key. Config
    `detectors.feed_silence`: `minutes: {feed: n}` overrides a limit by feed name, `ignore: [feed, ...]` drops one."""
    from .config import (
        HOST_LOGS,  # here, not at the top: config imports the modules this one feeds
    )
    fs = (cfg.get("detectors") or {}).get("feed_silence") or {}
    minutes, ignore = fs.get("minutes") or {}, set(fs.get("ignore") or ())
    out: dict[str, float] = {}
    for name, secs in FeedSilence.ZEEK.items():
        out[name] = secs
    for p in (cfg.get("host_context") or {}).get("results_logs") or HOST_LOGS:
        if not Path(p).is_file():
            continue
        where = str(Path(p).parent)
        for name, secs in (FeedSilence.WINDOWS if where.startswith("/mnt/") else FeedSilence.LINUX).items():
            out[f"{where}|{name}"] = secs
    for key in list(out):
        name = key.split("|", 1)[-1]
        if name in ignore:
            del out[key]
        elif name in minutes:
            out[key] = float(minutes[name]) * 60
    return out


def build(cfg: dict, ioc_ips: set[str] | None = None, ioc_domains: set[str] | None = None,
          popular: set[str] | None = None, assets_table: dict | None = None) -> list[Detector]:
    d = cfg.get("detectors", {})
    net = cfg.get("network", {})
    set_local_nets(net.get("local_nets") or ())  # the LAN's IPv6 prefix, so its devices count as inside
    load_categories(cfg.get("categories_file"), cfg.get("learned_categories_file"))  # domain -> kind of site (categories.py), offline
    set_categorizer(ai_categorizer(cfg))  # opt-in `categories: {ai: true}` + key in the environment, else None: no network
    gateways = Gateways(set(net.get("gateways") or ()))  # learned from the logs when not configured
    identity = Identity()
    asn_table = AsnTable.load(cfg.get("asn_file"))  # IP -> (ASN, country), offline
    admins = set(net.get("admin_devices") or ())
    devp = cfg.get("dev_profile", {})
    dev = DevProfile(devp.get("hosts") or (), devp.get("domains") or ())
    warmup = Warmup(cfg.get("warmup_seconds", 86400))
    tz = cfg.get("timezone")  # for time-of-day rules; None = this machine's local time
    dets: list[Detector] = [
        gateways,  # first: the home rules below ask it about every record
        identity,  # who is behind each address: cases are stamped with it, baselines keyed on it
        SuricataAlert(),
        Beaconing(dev=dev, popular=popular, expected=_expected_services(d.get("takeover", {})),
                  **d.get("beaconing", {})),
        SuspiciousDNS(popular=popular, dev=dev, **d.get("dns_anomaly", {})),
        PortScan(**d.get("scan", {})),
        HourlyProfile(**{"timezone": tz, "asn": asn_table, "managed": managed_hosts(assets_table),
                         **d.get("upload_spike", {}), **d.get("hourly", {})}),
        NewExternalDomain(warmup, popular=popular, dev=dev, **d.get("new_domain", {})),
        NewDevice(warmup, load_oui(cfg.get("oui_file")), timezone=tz),
        InternetExposure(warmup, **d.get("exposure", {})),
        ManagementAccess(warmup, gateways, admins),
        CleartextAuth(),
        RogueDHCP(warmup, gateways),
        TakeoverChannel(**{"timezone": tz, **d.get("takeover", {})}),
        OddPort(dev=dev, **d.get("odd_port", {})),
        DnsBypass(warmup),
        IotDrift(fixed_function_hosts(assets_table), asn_table, **d.get("iot_drift", {})),
        TlsOddities(warmup, **d.get("tls_odd", {})),
        UdmIps(),
        UdmAdmin(warmup, **d.get("udm_admin", {})),
    ]
    if (d.get("feed_silence") or {}).get("enabled", True):  # R22: the feeds themselves, ticked by `run` once a minute
        dets.append(FeedSilence(feed_expectations(cfg), host=(cfg.get("host_context") or {}).get("host") or "this PC"))
    if ioc_ips or ioc_domains:
        dets.insert(0, IOCMatch(ioc_ips or set(), ioc_domains or set()))
    for det in dets:
        det.ident = identity  # per-device baselines follow the device, not the address (Detector.dev_key)
    return dets
