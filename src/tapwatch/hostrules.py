"""Endpoint rules: host cases raised from the agent's own rows (R17-R21 in docs/detections/DESIGN.md).

Host context (hostctx.py) explains *network* cases: which program on the PC held the connection.
The detectors here read the same osquery results log as a log source of its own (`_type: osquery`,
zeek.LOG_TYPES) and raise cases for living-off-the-land activity that never looks odd on the wire:
an encoded or download-and-run command, a document app or browser starting a shell, a program in a
temp folder connecting out, a built-in Windows tool connecting out, a program with a bad code
signature connecting out, a new persistence entry (a scheduled task, service, startup item, cron
job or launch agent) that runs a script, a shell or something from a user-writable folder, and a command
that removes backups, recovery or logs, turns off Defender, or adds an account.

The rows are Sysmon events the Windows agent's `sysmon_events` query reduced on the PC
(agents/config/osquery.conf): process starts (event 1) with the parent and yes/no command-line
signals, outgoing connections (3) and DNS lookups (22), joined by Sysmon's ProcessGuid. Command
lines never enter a case: osquery turned them into signals, and the signals are what the rules read.
A case names the program and the *class* of folder it runs from, never the path (it holds the
user's name). Program names are attacker-chosen strings, so they travel as the case's indicators: quoted
and labelled untrusted for Jev, defanged in notifications, and the handle a suppression can key on.

Code decides every route (router.CODE_ONLY). Jev is never asked whether a program is normal: that
is the same question as "is this domain normal?", its measured weak spot.

Measured 2026-10-14/15 on the main PC, 34.5 h of the agent's log: 9,709 process starts, 108,423
outgoing connections, 7,423 DNS lookups. The per-rule comments cite what each would have raised.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import re
from dataclasses import dataclass
from typing import ClassVar

from . import vulnkev
from .detectors import (
    HOUSE_IPS,
    Detector,
    Warmup,
    _expected_services,
    is_internal,
    prune_reported,
    still_reported,
)
from .hostctx import (
    ADDRS,
    BPF,
    CMD_DESTRUCTIVE,
    CMD_SUSPICIOUS,
    CMD_UNUSUAL,
    PROCS,
    SIGS,
    SUSPICIOUS_CMD,
    SUSPICIOUS_DIRS,
    SYSMON,
    SYSTEM_DIRS,
    WIN_DOC_APPS,
    WIN_INSTALLED_DIRS,
    WIN_LOLBINS,
    WIN_SHELLS,
    WIN_SUSPICIOUS_CMD,
    _basename,
    _sysmon_ts,
)
from .models import Case
from .zeek import FLEET_OSQUERY

log = logging.getLogger(__name__)

OSQUERY = "osquery"
SNAPSHOT = "outbound_connections"   # Windows, every minute: program and parent per socket
SIG_WINDOW = 600             # seconds a connection is remembered, so a signature arriving later can still name it
SIG_PATHS = 500              # program paths whose signature or last connection is kept
WIN_BROWSERS = {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe", "arc.exe",
                "iexplore.exe", "chromium.exe"}
# Built-in tools whose only use on the internet is to fetch or run remote content (certutil -urlcache,
# bitsadmin /transfer, mshta http://..., regsvr32 /i:http... scrobj.dll). Measured 0 connections in 34.5 h.
LOLBIN_DOWNLOADERS = {"certutil.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe"}
# Built-in tools that connect out legitimately in dev work: MSBuild restores NuGet packages on any Visual Studio
# PC, so an hourly severity-4 alert would be noise there. A digest item once per reported_days instead.
LOLBIN_DEV_TOOLS = {"msbuild.exe"}
# Windows' own service hosts: a LOLBin they start from the system folder with a clean command line is scheduled work.
WINDOWS_SERVICE_HOSTS = frozenset({"svchost.exe", "taskhostw.exe"})
# Command-line signals that are weak alone on a dev PC: `iex (irm ...)` installs tools, scripts decode base64.
WEAK_SIGNALS = {"b64", "iex"}
GUID_WINDOW = 600            # seconds a process start is remembered, to join the connections it makes next
DAY = 86400.0
TEMP_DIRS = ("/appdata/local/temp/", "c:/windows/temp/")
SHARED_DIRS = ("/users/public/", "/$recycle.bin/", "c:/perflogs/")  # writable by every account, never an install

NAMES = ("host_encoded_cmd", "host_app_shell", "host_temp_exec", "host_lolbin", "host_bad_sig", "host_persist",
         "host_destructive", "host_recon", "host_extension", "host_linux_connect", "host_linux_cmd",
         "host_lsass", "host_rmm", "host_tunnel", "host_staging", "host_fim", "vuln_kev")
FIM = "file_changes"   # R39: the Linux agent's inotify query over the file_paths in osquery.conf
# Queries whose every row is one event (a process start, a connection, a file change). The same row read twice is
# the same event read twice: a log replayed after the follower took a drvfs rewrite for a rotation, or re-read
# after a restart. Host rules remember the events that raised a case for SEEN_TTL and skip a repeat (#303).
EVENT_QUERIES = frozenset({SYSMON, BPF, PROCS, FIM})
SEEN_TTL = 3 * DAY
SEEN_MAX = 20000   # per rule: past it, entries older than SEEN_TTL go, then the oldest
# R23: the agent's hourly differential queries over the places programs register to run again (osquery.conf).
PERSIST_QUERIES = {"scheduled_tasks": "scheduled task", "auto_start_services": "service",
                   "startup_items": "startup item", "crontab": "cron job", "launchd_run_at_load": "launch agent",
                   "wmi_persistence": "WMI event subscription", "authorized_keys": "SSH authorized key",
                   "systemd_units": "systemd unit", "suid_bin": "set-user-ID program", "kernel_modules": "kernel module",
                   "ld_preload": "preloaded library (/etc/ld.so.preload)",
                   "risky_containers": "privileged or Docker-socket container", "listening_ports": "listening port"}
LINUX_SYSTEM = ("suid_bin", "kernel_modules", "ld_preload", "risky_containers", "listening_ports")
SCRIPT_EXT = (".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".bat", ".cmd", ".hta", ".sh", ".py", ".pl", ".rb")
EXEC_EXT = SCRIPT_EXT + (".exe", ".com", ".dll", ".msc", ".scr", ".cpl", ".lnk")
POSIX_SHELLS = {"sh", "bash", "zsh", "dash", "python", "python3", "perl", "node", "ruby", "nohup"}
BATCH_GRACE = 120            # seconds after a query run before its rows are read as one batch (they log within a second)
DUMP_MIN = 5                 # adds with no removes in one batch: osquery's first run of the query, an inventory, not a change
KNOWN_MAX = 5000             # entries remembered per PC (a PC has a few hundred); older ones are forgotten first
LAN_PREFIXES = ("192.168.", "10.")   # where home LANs live; 172.16/12 is where Hyper-V and WSL put their switches
PC_UNKNOWN = "this PC"               # the case's host until an agent snapshot or host_context.host names the address
CONFIGURED_HOLD = 3600   # s: the configured address holds while a snapshot listed it this recently
# WSL's own internal address in mirrored networking mode (its DNS tunnel and loopback to Windows), which the WSL
# agent lists with the PC's real ones. Every such PC has the same one and no packet carries it onto the LAN, so it
# never names a device: as a host it split one PC's cases between its name and this address (measured 2026-10-25).
WSL_INTERNAL = "10.255.255.254"
ALIAS_WINDOW = 900       # s: an address a snapshot listed this recently is still one of the PC's (snapshots every 5 min)


def folder_class(path: str) -> str:
    """Where a Windows program runs from, as a class. Never the path: it carries the user's name."""
    p = path.replace("\\", "/").lower()
    if not p:
        return "unknown"
    if any(d in p for d in TEMP_DIRS):
        return "temp"
    if any(d in p for d in SHARED_DIRS):
        return "shared"
    if "/downloads/" in p:
        return "downloads"
    if p.startswith(WIN_INSTALLED_DIRS):
        return "installed"
    if "/appdata/" in p:
        return "appdata"
    if p.startswith("c:/users/"):
        return "profile"
    return "other"


FOLDER_WORDS = {"temp": "a temporary folder", "shared": "a folder every account can write to (Public, the "
                "Recycle Bin or PerfLogs)", "downloads": "a Downloads folder", "installed": "an installed location",
                "appdata": "a per-user application folder", "profile": "a user profile folder",
                "other": "a location outside Windows and Program Files", "unknown": "an unknown location"}


def parent_class(parent: str) -> str:
    n = parent.lower()
    if n in WIN_DOC_APPS:
        return "document"   # Office, Outlook, PDF readers: the macro and attachment path
    if n in WIN_BROWSERS:
        return "browser"
    if n in WIN_SHELLS:
        return "shell"
    return "other"


def flags_of(c: dict) -> tuple[str, ...]:
    """The command-line signals osquery set on a Sysmon process-start row (cmd_enc=1 -> "enc")."""
    return tuple(k for k in (*CMD_SUSPICIOUS, *CMD_UNUSUAL, *CMD_DESTRUCTIVE, "url") if str(c.get(f"cmd_{k}", "0")) == "1")


def signal_words(flags) -> tuple[list[str], list[str]]:
    """(suspicious, unusual) signals as words, for facts and summaries."""
    return ([CMD_SUSPICIOUS[f] for f in flags if f in CMD_SUSPICIOUS],
            [CMD_UNUSUAL[f] for f in flags if f in CMD_UNUSUAL])


def outside(remote: str, port) -> bool:
    """An outgoing connection to the internet: not the LAN, loopback or a DNS lookup (event 22 covers those)."""
    try:
        addr = ipaddress.ip_address(remote)
    except ValueError:
        return False
    if getattr(addr, "ipv4_mapped", None):  # ::ffff:192.168.x.x is the LAN (3,276 such eBPF rows, 2026-10-18)
        addr = addr.ipv4_mapped
    # the house's own public address (network.public_ips) is a way back in, not the internet
    return not (addr.is_loopback or is_internal(str(addr)) or str(addr) in HOUSE_IPS) and str(port) != "53"


@dataclass
class Start:
    """A Sysmon process start (event 1), kept for GUID_WINDOW to explain the connections that follow it."""

    ts: float
    name: str
    parent: str
    flags: tuple
    folder: str


class EndpointState:
    """What every host rule shares: the PC's address, and recent process starts by ProcessGuid.

    The address comes from the agents' `host_addresses` snapshots (every 5 minutes); `host_context.host` is
    the fallback and the tie-breaker. Two agents report for one PC: Windows lists the LAN address with its
    Hyper-V and WSL virtual switches (172.x), and WSL in NAT mode lists only its own 172.x address. So a
    snapshot moves the host only to a LAN address (192.168/16, 10/8), and a 172.x-only snapshot is accepted
    only while no address is known at all. Taking the WSL snapshot at face value gave about half the cases
    the wrong host (review of PR #87), which splits the dedupe key and misses same-device suppressions.
    Until an address is known the cases name the PC as `PC_UNKNOWN`, never an empty string."""

    def __init__(self, host: str = "", gateways: list[str] | None = None, unknown: str = ""):
        self.configured = host
        self._host = host
        self.unknown = unknown or PC_UNKNOWN   # Fleet's agents: their name, not "this PC", until an address is known
        # the router's networks (network.gateways, documented as one router per /24): the LAN address is the one
        # on a router's /24; a /16 or /23 LAN falls back to the old order. Measured 2026-10-17: the WSL agent in
        # mirrored mode also lists 10.255.255.254, which sorted ahead of 192.168.x and gave three host cases a host
        # no identity knew (#792-#794)
        self.lan_nets = {".".join(g.split(".")[:3]) for g in (gateways or ()) if g.count(".") == 3}
        self._routed = False   # once an address on a router's net was seen, a snapshot without one keeps it
        self._configured_seen: float | None = None   # when a snapshot last listed `host_context.host`; None: none yet
        self.seen_addrs: dict[str, float] = {}   # address -> when a snapshot last listed it (for Case.aliases)
        self.starts: dict[str, Start] = {}
        self.latest = 0.0
        # Signatures arrive every 5 minutes per program path (process_signatures), connections every minute
        # (outbound_connections): either can come first, so both sides are remembered and joined by path.
        self.signatures: dict[str, tuple[str, str]] = {}   # path (lowercased) -> (authenticode result, signer)
        self.connected: dict[str, tuple[float, dict]] = {}  # path (lowercased) -> (when, the socket row)

    @property
    def host(self) -> str:
        return self._host or self.unknown

    def aliases(self) -> tuple[str, ...]:
        """The PC's other addresses, as its agents listed them lately (both agents on a PC with WSL), sorted."""
        return tuple(sorted(a for a in self.seen_addrs if a != self._host))

    def update_addresses(self, rows: list[dict], ts: float = 0.0) -> None:
        addrs = {str(r.get("address")) for r in rows if r.get("address")} - {WSL_INTERNAL}
        self.seen_addrs = {a: t for a, t in self.seen_addrs.items() if ts - t <= ALIAS_WINDOW} | dict.fromkeys(addrs, ts)
        if self.configured and self.configured in addrs:
            self._host, self._configured_seen = self.configured, ts
            return
        if self._configured_seen is None:
            self._configured_seen = ts   # after a start, the first snapshot opens the hold (review of #250)
        if self.configured and self._host == self.configured and ts - self._configured_seen < CONFIGURED_HOLD:
            # Measured 2026-10-20: the PC has two adapters (two LAN addresses); a snapshot listing only the other
            # one moved the host, and the same events were filed twice under two keys (#948/#960, #949/#961). Keep
            # the configured address while any snapshot showed it within the hour; a real DHCP change moves it after.
            return
        v4 = [a for a in addrs if ":" not in a and is_internal(a)]
        lan = sorted(a for a in v4 if a.startswith(LAN_PREFIXES))
        routed = [a for a in lan if ".".join(a.split(".")[:3]) in self.lan_nets]
        if routed:
            self._host, self._routed = routed[0], True
        elif lan and not self._routed:
            self._host = lan[0]
        elif v4 and not self._host:
            self._host = min(v4)   # better than nothing, replaced by the first LAN address seen

    def remember(self, guid: str, start: Start) -> None:
        if not guid:
            return
        self.starts[guid] = start
        self.latest = max(self.latest, start.ts)
        if len(self.starts) > 500:  # about 10 minutes of starts on the main PC (measured ~280/h)
            self.starts = {g: s for g, s in self.starts.items() if self.latest - s.ts <= GUID_WINDOW}

    def start_of(self, guid: str, ts: float) -> Start | None:
        s = self.starts.get(guid or "")
        return s if s is not None and ts - s.ts <= GUID_WINDOW else None

    def update_signatures(self, rows: list[dict]) -> None:
        for r in rows:
            if r.get("path"):
                self.signatures[str(r["path"]).lower()] = ((r.get("signature") or "").lower(), r.get("signer") or "")
        if len(self.signatures) > SIG_PATHS:  # the snapshot is a few dozen paths; a bigger map is churn, relearned in 5 min
            self.signatures = dict(list(self.signatures.items())[-SIG_PATHS:])

    def signature_of(self, path: str) -> tuple[str, str]:
        return self.signatures.get((path or "").lower(), ("", ""))

    def remember_connection(self, c: dict, ts: float) -> None:
        if c.get("path"):
            self.connected[str(c["path"]).lower()] = (ts, c)
            if len(self.connected) > SIG_PATHS:
                self.connected = {p: v for p, v in self.connected.items() if ts - v[0] <= SIG_WINDOW}

    def connection_of(self, path: str, ts: float) -> dict | None:
        """The last outside connection `path` held within SIG_WINDOW of `ts`, if any."""
        hit = self.connected.get((path or "").lower())
        return hit[1] if hit and ts - hit[0] <= SIG_WINDOW else None


class HostDetector(Detector):
    """A rule over the endpoint agent's rows (`_type: osquery`).

    Subclasses name the scheduled queries they read (QUERIES) and implement `row(query, columns, ts)`.
    `feed` unpacks the osquery record (one differential row, or a snapshot's list), keeps the PC's
    address and the recent process starts up to date, and ignores `removed` rows (a connection that
    closed is not an event). Repeats of one situation below alert severity are one case per
    `reported_days`; alerts rely on the store's one-hour dedupe, so a repeat is counted, not re-sent."""

    QUERIES: ClassVar[tuple[str, ...]] = ()
    PERSIST: ClassVar[tuple[str, ...]] = ("reported", "seen")

    def __init__(self, state: EndpointState | None = None, reported_days: float = 7):
        self.state = state or EndpointState()
        self.reported: dict = {}
        self.ttl = reported_days * DAY
        self.seen: dict[str, float] = {}   # fingerprints of event rows that raised a case (EVENT_QUERIES)
        self._event: tuple | None = None   # (query, row) being judged while row() runs; hashed only if it emits

    def feed(self, rec: dict) -> list[Case]:
        if rec.get("_type") != OSQUERY:
            return []
        name, ts = rec.get("name"), float(rec.get("ts") or 0)
        rows = rec.get("snapshot") if rec.get("action") == "snapshot" else [rec.get("columns")]
        rows = [r for r in (rows or ()) if isinstance(r, dict)]
        if name == ADDRS:
            self.state.update_addresses(rows, ts)
            return []
        if rec.get("action") == "removed":
            return self.removed(name, rows, ts)
        if name == SIGS:
            self.state.update_signatures(rows)
        out: list[Case] = []
        for c in rows:
            if name == SNAPSHOT and outside(c.get("remote_address", ""), c.get("remote_port")):
                self.state.remember_connection(c, _row_ts(c, ts))
            if name == SYSMON and str(c.get("eventid")) == "1":
                path = c.get("path") or ""
                self.state.remember(c.get("guid") or "", Start(_row_ts(c, ts), _basename(path).lower(),
                                                              _basename(c.get("parent_path") or ""),
                                                              flags_of(c), folder_class(path)))
            if name in self.QUERIES:
                self._event = (name, c) if name in EVENT_QUERIES else None
                try:
                    out += self.row(name, c, _row_ts(c, ts))
                finally:
                    self._event = None
        return out

    def row(self, query: str, c: dict, ts: float) -> list[Case]:  # pragma: no cover - interface
        raise NotImplementedError

    def removed(self, query: str, rows: list[dict], ts: float) -> list[Case]:
        """A differential `removed` row. A connection that closed is not an event, so most rules ignore it;
        R23 needs it to tell a changed entry from a new one."""
        return []

    def emit(self, ts: float, title: str, facts: dict, severity: int, indicator: str, key: tuple = (),
             must_alert: bool = False) -> list[Case]:
        """One case. `indicator` is the program (or "parent > child"): an attacker-chosen string, so it travels as
        an indicator (quoted, defanged, suppressible), and the store dedupes on it for an hour. `key` is the
        situation a digest-level case is reported once per `reported_days`."""
        seen = f"{_fingerprint(*self._event)}|{title}|{indicator}" if self._event else ""
        if seen in self.seen:
            return []   # this very event already raised this case: a replayed log line, not a new start
        if severity < 4 and not must_alert:
            if still_reported(self.reported, key, ts, self.ttl):
                return []
            self.reported[key] = ts
            if len(self.reported) > 2000:
                self.reported = prune_reported(self.reported, ts, self.ttl)
        if seen:   # remembered only when it raises a case, so a rule's suppressed repeats don't fill it
            self.seen[seen] = ts
            if len(self.seen) > SEEN_MAX:
                kept = {k: t for k, t in self.seen.items() if ts - t < SEEN_TTL}
                self.seen = dict(sorted(kept.items(), key=lambda kv: kv[1])[-SEEN_MAX // 2:])
        return [Case(self.name, self.state.host, ts, title, {"source": "endpoint", **facts}, [indicator],
                     must_alert=must_alert, base_severity=severity, aliases=self.state.aliases())]


def _fingerprint(query: str, c: dict) -> str:
    """One event row, whatever address the PC has when it is read: the query and every column, hashed."""
    raw = json.dumps([query, c], sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


def _row_ts(c: dict, rec_ts: float) -> float:
    """A Sysmon row's own time (UtcTime), else when the query ran (up to a minute later)."""
    return (_sysmon_ts(c.get("utc")) or rec_ts) if c.get("utc") else rec_ts


def _start_facts(s: Start | None) -> dict:
    """What the process start says about a connection, when it was seen (GUID join within 10 minutes)."""
    if s is None:
        return {}
    sus, unusual = signal_words(s.flags)
    return {"parent": s.parent, "parent_class": parent_class(s.parent), "signals": sus, "unusual": unusual,
            "url": "url" in s.flags}


class EncodedCommand(HostDetector):
    """R17. A shell or script host started with an encoded, base64-decoding, download-and-run or
    Invoke-Expression command line: the signals osquery computed on the PC (the text never gets here).

    Scoped to shells and script hosts. The only encoded-payload signal in 34.5 h (9,709 starts) was
    msiexec passing a long base64-looking argument to itself, which is not PowerShell's -EncodedCommand.
    On shells, every suspicious signal fired 0 times in that window. Base64 decoding or Invoke-Expression
    alone, from an ordinary parent, raises nothing: `iex (irm ...)` is how dev tools install themselves,
    and a weekly digest item about it would carry no action.
    """

    name = "host_encoded_cmd"
    QUERIES: ClassVar[tuple[str, ...]] = (SYSMON,)

    def row(self, query: str, c: dict, ts: float) -> list[Case]:
        if str(c.get("eventid")) != "1":
            return []
        path = c.get("path") or ""
        prog = _basename(path).lower()
        if prog not in WIN_SHELLS:
            return []
        flags = flags_of(c)
        sus, unusual = signal_words(flags)
        if not sus:
            return []
        parent = _basename(c.get("parent_path") or "")
        pclass = parent_class(parent)
        keys = {f for f in flags if f in CMD_SUSPICIOUS}
        if ("enc" in keys and len(keys) >= 2) or "hidden" in flags or pclass == "document":
            # An encoded payload with a second signal, any suspicious signal in a hidden window, or a document or
            # mail app as the parent: the shape of a macro or attachment payload, with no benign reading on a home
            # PC. must_alert can't be suppressed, so the bar stops here: download-and-run plus Invoke-Expression
            # (plus a policy bypass) is Chocolatey's documented install line, and alerts suppressibly below.
            severity, must = 5, True
        elif len(keys) >= 2 or keys - WEAK_SIGNALS or pclass == "browser":
            severity, must = 4, False   # two signals, or an encoded payload or download-and-run alone, or a browser parent
        else:
            return []
        facts = {"program": prog, "parent": parent, "parent_class": pclass, "folder": folder_class(path),
                 "signals": sus, "unusual": unusual, "url": "url" in flags}
        return self.emit(ts, "Encoded or download-and-run command on the PC", facts, severity, prog, must_alert=must)


class AppSpawnsShell(HostDetector):
    """R18. A document, mail or PDF app, or a browser, started a shell or script host.

    Document and mail apps: the macro and attachment path; 0 measured (no Office on the main PC), and the
    Sigma community rates it high. Browsers: measured 37 cmd.exe starts from Chrome in 34.5 h, none with
    a URL on the command line and none that connected anywhere (native-messaging hosts are often batch
    files), so a browser's child raises nothing on its own. It alerts when the child itself connects to
    the internet (event 3, joined by ProcessGuid), which a messaging host has no reason to do. A browser's
    child with a suspicious command line is R17's case (the browser parent lifts it to an alert there).
    """

    name = "host_app_shell"
    QUERIES: ClassVar[tuple[str, ...]] = (SYSMON,)

    def __init__(self, state: EndpointState | None = None, reported_days: float = 7):
        super().__init__(state, reported_days)
        self.connected: set[str] = set()   # GUIDs whose follow-up connection was already raised

    def row(self, query: str, c: dict, ts: float) -> list[Case]:
        eid = str(c.get("eventid"))
        if eid == "1":
            prog = _basename(c.get("path") or "").lower()
            parent = _basename(c.get("parent_path") or "")
            if prog not in WIN_SHELLS or parent_class(parent) != "document":
                return []
            sus, unusual = signal_words(flags_of(c))
            facts = {"program": prog, "parent": parent, "parent_class": "document", "signals": sus, "unusual": unusual,
                     "url": "url" in flags_of(c), "connected": False}
            return self.emit(ts, "A document or mail app started a shell or script host", facts, 4, f"{parent} > {prog}")
        if eid == "3":
            guid = c.get("guid") or ""
            s = self.state.start_of(guid, ts)
            if s is None or guid in self.connected or s.name not in WIN_SHELLS or parent_class(s.parent) != "browser" \
                    or not outside(c.get("remote_address", ""), c.get("remote_port")):
                return []
            self.connected.add(guid)
            if len(self.connected) > 500:
                self.connected = {g for g in self.connected if g in self.state.starts}
            facts = {"program": s.name, "parent": s.parent, "parent_class": "browser", "connected": True,
                     "port": _port(c.get("remote_port")), **{k: v for k, v in _start_facts(s).items()
                                                            if k in ("signals", "unusual", "url")}}
            return self.emit(ts, "A browser started a shell that connected to the internet", facts, 4,
                             f"{s.parent} > {s.name}")
        return []


class TempFolderConnects(HostDetector):
    """R19. A program running from a temp, Downloads or shared folder connected to the internet.

    Measured 0 of 108,423 connections in 34.5 h; 6 process starts from a temp folder (installers
    unpacking themselves), none of which connected. Temp and Downloads: digest, because that is what a
    downloaded installer does. Users\\Public, the Recycle Bin and PerfLogs: alert, nothing legitimate
    installs there. Alert too when the process start (ProcessGuid join) carried a suspicious command-line
    signal or came from a document or mail app: a dropper that a document wrote and ran.
    """

    name = "host_temp_exec"
    QUERIES: ClassVar[tuple[str, ...]] = (SYSMON,)

    def row(self, query: str, c: dict, ts: float) -> list[Case]:
        if str(c.get("eventid")) != "3" or not outside(c.get("remote_address", ""), c.get("remote_port")):
            return []
        path = c.get("path") or ""
        folder = folder_class(path)
        if folder not in ("temp", "downloads", "shared"):
            return []
        prog = _basename(path).lower()
        s = self.state.start_of(c.get("guid") or "", ts)
        started = _start_facts(s)
        severity = 4 if folder == "shared" or started.get("signals") or started.get("parent_class") == "document" else 3
        facts = {"program": prog, "folder": folder, "port": _port(c.get("remote_port")), **started}
        return self.emit(ts, "Program in a temporary folder connected to the internet", facts, severity, prog,
                         (self.state.host, prog, folder))


class LolbinConnects(HostDetector):
    """R20. A built-in Windows tool attackers use to download or proxy-execute code connected out.

    Measured 0 of 108,423 connections in 34.5 h (rundll32 started 19 times, by svchost and msiexec, and
    never connected). certutil, bitsadmin, mshta and regsvr32 exist to fetch or run remote content and
    have no home use on the internet: must_alert. The rest (rundll32, wmic, wscript, cscript, installutil,
    cmstp...) alert, suppressible per program for a tool the owner's software relies on. msbuild is a digest
    item: on a Visual Studio PC it connects out for every NuGet restore. So is one of the rest when Windows' own
    service host started it from the system folder with a clean command line: measured 2026-10-17..20, rundll32
    started by svchost from System32 connected out on 443 thousands of times (one case alone counted 3,454 hits),
    Windows' own scheduled work, raising an alert a day that the owner closed as expected each time. A command
    line with any signal, or another parent or folder, still alerts.
    """

    name = "host_lolbin"
    QUERIES: ClassVar[tuple[str, ...]] = (SYSMON,)

    def row(self, query: str, c: dict, ts: float) -> list[Case]:
        if str(c.get("eventid")) != "3" or not outside(c.get("remote_address", ""), c.get("remote_port")):
            return []
        path = c.get("path") or ""
        prog = _basename(path).lower()
        if prog not in WIN_LOLBINS:
            return []
        must = prog in LOLBIN_DOWNLOADERS
        started = _start_facts(self.state.start_of(c.get("guid") or "", ts))
        windows_own = (started.get("parent", "").lower() in WINDOWS_SERVICE_HOSTS and folder_class(path) == "installed"
                       and not started.get("signals") and not started.get("unusual") and not started.get("url"))
        severity = 5 if must else 3 if prog in LOLBIN_DEV_TOOLS or windows_own else 4
        facts = {"program": prog, "folder": folder_class(path), "port": _port(c.get("remote_port")),
                 "downloader": must, "windows_service": windows_own, **started}
        # the downgrade is in the key: Windows' own weekly digest item can't hide a different run of the same tool
        return self.emit(ts, "Built-in Windows tool connected to the internet", facts, severity, prog,
                         (self.state.host, prog, windows_own), must_alert=must)


class BadSignatureConnects(HostDetector):
    """R21. A program whose code signature Windows rejects held an outside connection: the Windows agent's
    1-minute `outbound_connections` rows (program, parent, socket) joined by path to its 5-minute
    `process_signatures` snapshot (osquery's authenticode result per program with a socket). Until 2026-10-17
    the socket query carried the signature itself, checked per socket: 15 s on a quiet PC (57 sockets, 11
    programs; publishers osquery "could not find" cost seconds each), so osquery's watchdog killed it and
    denylisted it by name for 24 h, twice, and this rule and the Windows host context were blind for a day
    each time. Per path the check is 5.8 s for 11 programs. Either side can arrive first, so a connection
    whose signature is already known fires at once, and a bad signature arriving within SIG_WINDOW of the
    program's last connection fires then; rows from an older agent that still carry `signature` work as before.

    osquery reports four results: trusted, missing, untrusted and distrusted. A file changed after it was
    signed (a hash mismatch), a self-signed or self-built binary and an expired certificate all come back
    `untrusted`; `distrusted` is a publisher Windows blocks. Both alert, suppressible per program, because
    the tampered-binary case is inside `untrusted` and a dev build is a one-time suppression. Missing or
    unreadable signatures don't count: in 34.5 h, all 7 programs osquery reported without a readable
    signature were installed apps (Program Files, AppData\\Local\\Programs), the Signal Desktop case
    that hostctx settles by asking Windows itself. The signer name is kept as a fact for the local case
    page and summary (this rule is code-only, so the summary never leaves the box); for a self-signed
    certificate that can be the owner's own name, which is why it is quoted and never a title.
    """

    name = "host_bad_sig"
    QUERIES: ClassVar[tuple[str, ...]] = (SNAPSHOT, SIGS)
    BAD: ClassVar[dict[str, int]] = {"untrusted": 4, "distrusted": 4}

    def row(self, query: str, c: dict, ts: float) -> list[Case]:
        if query == SIGS:  # a signature for a program that connected out in the last SIG_WINDOW
            sig, signer = (c.get("signature") or "").lower(), c.get("signer") or ""
            conn = self.state.connection_of(c.get("path") or "", ts) if sig in self.BAD else None
            if conn is None:
                return []
            c = {**conn, "signature": sig, "signer": signer}
        sig = (c.get("signature") or "").lower()
        if not sig:
            sig, signer = self.state.signature_of(c.get("path") or "")
            c = {**c, "signature": sig, "signer": signer}
        if sig not in self.BAD or not outside(c.get("remote_address", ""), c.get("remote_port")):
            return []
        path = c.get("path") or ""
        prog = (c.get("name") or _basename(path)).lower()
        facts = {"program": prog, "folder": folder_class(path), "signature": sig, "signer": c.get("signer") or "",
                 "parent": c.get("parent_name") or "", "port": _port(c.get("remote_port"))}
        return self.emit(ts, "Program with a bad code signature connected to the internet", facts, self.BAD[sig], prog,
                         (self.state.host, prog, sig))


class DestructiveCommand(HostDetector):
    """R24. A command that removes the way back or covers tracks: shadow copies, backups or recovery deleted
    (what ransomware runs before encrypting), event logs cleared, Defender turned off or given an exclusion, a
    local account or administrator added. The agent flags them on the PC (cmd_shadow, cmd_logclear,
    cmd_defender, cmd_admin); the text never gets here.

    Any program, not only shells: `vssadmin delete shadows` is vssadmin's own command line, and the PowerShell
    forms (Clear-EventLog, Set-MpPreference, Add-LocalGroupMember) are PowerShell's. Measured 2026-10-16/17 over
    40 h of the main PC's log, 15,389 process starts: vssadmin, wbadmin, bcdedit, wevtutil, net, net1 and wmic
    started 0 times (mpcmdrun, Defender's own updater, 24 times, none with -RemoveDefinitions); the 13 command
    lines the agent kept matched none of the patterns. Backups and logs gone: severity 5, must_alert (no benign
    reading on a home PC; an administrator who does it on purpose knows the alert is coming). Recovery turned
    off, Defender and accounts: severity 4, suppressible: `bcdedit recoveryenabled no` is a documented fix for
    an Automatic Repair loop, and an installer or the owner adding an exclusion or a user happens once. A shell
    chain (`cmd /c vssadmin ...`) carries the same line on both process starts, milliseconds apart: the same
    harm within a minute is the same command and one case, named after the first program seen.
    """

    name = "host_destructive"
    QUERIES: ClassVar[tuple[str, ...]] = (SYSMON,)
    CHAIN = 60   # seconds within which the same harm on the same PC is the same command (a shell and its child)

    def __init__(self, state: EndpointState | None = None, reported_days: float = 7):
        super().__init__(state, reported_days)
        self.chain: dict[tuple, float] = {}

    def row(self, query: str, c: dict, ts: float) -> list[Case]:
        if str(c.get("eventid")) != "1":
            return []
        flags = flags_of(c)
        harm = [f for f in flags if f in CMD_DESTRUCTIVE]
        if not harm:
            return []
        chain_key = (self.state.host, tuple(sorted(harm)))
        if ts - self.chain.get(chain_key, -1e18) < self.CHAIN:
            return []
        self.chain[chain_key] = ts
        if len(self.chain) > 200:
            self.chain = {k: t for k, t in self.chain.items() if ts - t < self.CHAIN}
        path = c.get("path") or ""
        prog = _basename(path).lower()
        parent = _basename(c.get("parent_path") or "")
        sus, unusual = signal_words(flags)
        must = "shadow" in harm or "logclear" in harm
        facts = {"program": prog, "parent": parent, "parent_class": parent_class(parent), "folder": folder_class(path),
                 "harm": [CMD_DESTRUCTIVE[f] for f in harm], "signals": sus, "unusual": unusual, "url": "url" in flags}
        return self.emit(ts, "Backups, logs or protection removed on the PC" if must else "Protection or accounts changed on the PC",
                         facts, 5 if must else 4, prog, must_alert=must)


def _target_tokens(target: str) -> list[str]:
    """The program and arguments of a persistence entry's command, quotes and environment variables resolved
    enough to classify: `"C:\\Program Files\\X\\x.exe" /q` -> ['C:\\Program Files\\X\\x.exe', '/q']."""
    t = target.strip()
    if not t:
        return []
    for var, val in (("%systemroot%", "C:\\Windows"), ("%windir%", "C:\\Windows"), ("%programfiles%", "C:\\Program Files"),
                     ("%localappdata%", "C:\\Users\\<user>\\AppData\\Local"), ("%appdata%", "C:\\Users\\<user>\\AppData\\Roaming"),
                     ("%temp%", "C:\\Users\\<user>\\AppData\\Local\\Temp"), ("%userprofile%", "C:\\Users\\<user>"),
                     ("%programdata%", "C:\\ProgramData"), ("%systemdrive%", "C:")):
        t = t.replace(var, val).replace(var.upper(), val)
    if t.startswith('"'):
        end = t.find('"', 1)
        if end > 0:
            return [t[1:end]] + t[end + 1:].split()
    parts = t.split()
    # An unquoted path with spaces (`C:\\Program Files\\X\\x.exe /q`, a Start Menu\\Programs\\Startup script): the program
    # runs to the first part that ends like a file, as Windows itself resolves it. Measured 2026-10-17: without this,
    # Copilot's RunOnce read as a program named "Program" and a Startup-folder .vbs as one named "Start".
    for i in range(1, len(parts)):
        if parts[i - 1].lower().endswith(EXEC_EXT):
            return [" ".join(parts[:i])] + parts[i:]
    if len(parts) > 1 and not parts[0].lower().endswith(EXEC_EXT) and parts[0][1:3] == ":\\":
        return [" ".join(parts)] if parts[-1].lower().endswith(EXEC_EXT) else parts
    return parts


def win_folder_class(path: str) -> str:
    """folder_class, with the whole Windows directory as installed: a service or task under C:\\Windows\\servicing
    or C:\\Windows\\Temp is written by Windows itself (admin-only), not by a user."""
    p = path.replace("\\", "/").lower()
    return "installed" if p.startswith("c:/windows/") and "/temp/" not in p else folder_class(path)


def posix_folder_class(path: str) -> str:
    p = path.lower()
    if any(d in p for d in SUSPICIOUS_DIRS):
        return "temp"
    if p.startswith(SYSTEM_DIRS):
        return "installed"
    if p.startswith(("/home/", "/root/", "/users/")):
        return "profile"
    return "other"


class NewPersistence(HostDetector):
    """R23. A new place for a program to run again: a scheduled task, service, startup item (Run keys and the
    Startup folder), cron job or launch agent that was not there before.

    The agent's queries run hourly in osquery's differential mode, so the log carries `added` and `removed` rows.
    Three things in those rows are not new entries, measured 2026-10-16/17 over 40 h of the main PC's log
    (1,429 rows): a task that ran gets a removed+added pair because `last_run_time` changed (503 pairs); the
    first run after the agent's database was reset lists everything as added (3 batches of 36, 108 and 224);
    and 29 entries were genuinely new, of which 19 were Windows' own or an installed app's (per-user svchost
    services for a new logon session, Windows Update tasks, TrustedInstaller, a sandbox service's version bump).
    So: rows are read per query run (same `unixTime`), a key present on both sides of a run is a change, a run
    of DUMP_MIN or more adds with no removes is an inventory, and a key seen before (`known`, persisted; a removed
    row counts as seen) or seen during warmup is learned silently. What is left is scored by what the entry runs: a suspicious command line
    or a temp, Downloads or shared folder -> alert; a script, a shell or script host, a LOLBin, or a per-user
    folder -> digest (the measured 40 h replayed: six, the owner's two .vbs files in the Startup folder, OneDrive's
    three RunOnce entries that run cmd.exe, and its startup task under AppData); an installed program with none of
    those -> learned, no case. The entry's name and its program travel as untrusted strings; the command line
    and path never enter the case, only the folder class and yes/no signals, as for the other host rules.
    """

    name = "host_persist"
    QUERIES: ClassVar[tuple[str, ...]] = tuple(PERSIST_QUERIES)
    PERSIST: ClassVar[tuple[str, ...]] = ("reported", "seen", "known")

    def __init__(self, state: EndpointState | None = None, reported_days: float = 7, warmup: Warmup | None = None):
        super().__init__(state, reported_days)
        self.warmup = warmup or Warmup(0)
        self.known: dict[tuple, float] = {}   # (host, query, entry name, target) -> last seen, persisted
        # (query, unixTime) -> {"ts", "added": [rows], "removed": [rows]}. Not persisted: a run read in the two
        # minutes before a restart is neither judged nor learned, and its entries are judged at their next change.
        self.pending: dict[tuple, dict] = {}

    def restore(self, data: dict) -> None:
        try:
            super().restore(data)
        except TypeError as e:  # a saved key that decodes to something unhashable
            raise ValueError(f"known: {e}") from e
        if not isinstance(self.known, dict) or not all(isinstance(k, tuple) and len(k) == 4 and isinstance(v, (int, float))
                                                       for k, v in self.known.items()):
            raise ValueError("known: not a dict of 4-tuples to times")  # restore_state discards it; relearned in a day

    def feed(self, rec: dict) -> list[Case]:
        now = float(rec.get("ts") or 0)
        out = super().feed(rec) if rec.get("_type") == OSQUERY else []
        if rec.get("name") in self.QUERIES and str(rec.get("counter", "")) == "0" and rec.get("action") == "added":
            # osquery's first run of a query (new config, or its database reset) lists what already exists: an
            # inventory whatever its size. Measured: all three dumps (36, 108, 224 rows) and the 18-row extension
            # listing had counter 0; a machine with one or two SSH keys would otherwise alert on them (review of #148).
            self._batch(rec["name"], float(rec.get("ts") or 0))["first_run"] = True
        return out + self.settle(now)

    def _batch(self, query: str, rec_ts: float) -> dict:
        return self.pending.setdefault((query, int(rec_ts)), {"ts": rec_ts, "added": [], "removed": []})

    def row(self, query: str, c: dict, ts: float) -> list[Case]:
        self._batch(query, ts)["added"].append(c)
        return []

    def removed(self, query: str, rows: list[dict], ts: float) -> list[Case]:
        if query in self.QUERIES:
            self._batch(query, ts)["removed"].extend(rows)
        return []

    @staticmethod
    def target_of(query: str, c: dict) -> str:
        if query == "scheduled_tasks":
            return str(c.get("action") or "")
        if query == "crontab":
            return str(c.get("command") or "")
        if query == "launchd_run_at_load":
            return " ".join(str(c.get(k) or "") for k in ("program", "program_arguments")).strip()
        if query == "wmi_persistence":
            return " ".join(str(c.get(k) or "") for k in ("action", "args")).strip()
        if query == "authorized_keys":
            return str(c.get("key_tail") or "")
        if query == "listening_ports":
            port = int(c.get("port") or 0)
            # ephemeral ports change every run; the program, its folder and the protocol are the listener (a /tmp
            # copy taking over a port must not match the installed program's key)
            where = posix_folder_class(str(c.get("path") or "")) if str(c.get("path") or "").startswith("/") else "win"
            return f'{c.get("protocol")}/{port if port < 32768 else "ephemeral"}/{where}'
        if query in ("suid_bin", "ld_preload"):
            return str(c.get("path") or "")
        if query == "risky_containers":   # the image: a container's name is the owner's choice and can name a project
            return str(c.get("image") or "")
        return str(c.get("path") or "")   # services, startup items

    @staticmethod
    def entry_of(query: str, c: dict) -> str:
        if query == "crontab":  # the file's path names the user (/var/spool/cron/crontabs/<user>): never stored
            p = str(c.get("path") or "")
            return "a user's crontab" if "/etc/" not in p else _basename(p) or "crontab"   # /etc/cron.d/<file>, /etc/crontab
        if query == "authorized_keys":  # the key file's path names the user: the algorithm only
            return f"authorized key ({c.get('algorithm') or 'unknown type'})"
        if query in ("suid_bin", "ld_preload"):
            return _basename(str(c.get("path") or "")) or query
        if query == "risky_containers":
            return str(c.get("image") or "container")
        if query == "listening_ports":
            return _basename(str(c.get("path") or c.get("name") or "")) or "unknown"
        return str(c.get("label") if query == "launchd_run_at_load" else c.get("name") or "")

    def judge_linux_system(self, query: str, c: dict, ts: float, entry: str, target: str) -> list[Case]:
        """#28: Linux changes that mean root or a way back to it. Measured 2026-10-18 on the WSL box: 40 SUID programs,
        23 kernel modules, no /etc/ld.so.preload, no privileged or Docker-socket container, 11 stable listeners; the
        first run after the agent's config is updated lists them all and is learned as an inventory."""
        kind = PERSIST_QUERIES[query]
        path = str(c.get("path") or "")
        folder = posix_folder_class(path) if path.startswith("/") else "other"
        if query == "listening_ports":
            if not path.startswith("/") or str(c.get("address") or "") in ("127.0.0.1", "::1", "::ffff:127.0.0.1"):
                return []   # Windows rows churn (47 new listeners in 21 h, mostly svchost): Linux, outside loopback only
            name = _basename(path).lower()
            bind_shell = name in POSIX_REMOTE_SHELLS   # a shell or netcat; interpreters fall under the folder test
            if not (bind_shell or folder in ("temp", "profile")):
                return []   # an installed service starting to listen is routine
            facts = _linux_system_facts(kind, entry, folder)
            facts.update({"shell": bind_shell, "port": _port(c.get("port"))})
            return self.emit(ts, "New listening program on the PC (Linux)", facts, 4, entry[:80],
                             (self.state.host, query, entry, target))
        severity = {"ld_preload": 5, "suid_bin": 4 if folder in ("temp", "profile", "other") else 3,
                    "kernel_modules": 3, "risky_containers": 3}[query]
        facts = _linux_system_facts(kind, entry, folder)
        if query == "risky_containers":
            facts.update({"privileged": str(c.get("privileged")) == "1", "docker_socket": str(c.get("sock") or "0") != "0"})
        if query == "risky_containers":
            entry = str(c.get("image") or "container")
            facts["entry"] = facts["program"] = entry[:80]
        return self.emit(ts, f"New {kind} on the PC (Linux)", facts, severity, entry[:80],
                         (self.state.host, query, entry, folder), must_alert=query == "ld_preload")

    def key(self, query: str, c: dict) -> tuple:
        """What makes an entry the same entry across runs: never `last_run_time`, which changes whenever it runs."""
        return (self.state.host, query, self.entry_of(query, c), self.target_of(query, c))

    def flush(self) -> list[Case]:
        """End of a replay: read every run still waiting for its grace period."""
        return self.settle(float("inf"))

    def settle(self, now: float) -> list[Case]:
        """Read every query run whose grace period has passed as one batch."""
        out: list[Case] = []
        for bkey in [k for k, b in self.pending.items() if now - b["ts"] >= BATCH_GRACE]:
            query, b = bkey[0], self.pending.pop(bkey)
            gone = {self.key(query, c) for c in b["removed"]}
            # An entry seen being removed existed, so its return at a later run is not new: learn it now. First for
            # listeners (review of #169: a dev server down at one hourly run and up at the next). Then for every
            # query, measured 2026-10-20 (#911-#924): osquery's Linux startup_items listed 16 of WSL's package-owned
            # /etc/init.d scripts as removed at one run and added back at the next; they predated the sensor, so
            # `known` lacked them and each became a case. The key holds what the entry runs, so one that comes
            # back pointing somewhere else is still a new key and still judged.
            for k in gone:
                self.known[k] = b["ts"]
            new = [c for c in b["added"] if self.key(query, c) not in gone]
            inventory = b.get("first_run") or (len(new) >= DUMP_MIN and not b["removed"])
            for c in new:
                k = self.key(query, c)
                seen = k in self.known
                self.known[k] = b["ts"]
                if seen or inventory or self.warmup.learning(b["ts"]):
                    continue
                out += self.judge(query, c, b["ts"])
            if len(self.known) > KNOWN_MAX:
                self.known = dict(sorted(self.known.items(), key=lambda kv: kv[1])[-KNOWN_MAX:])
        return out

    def judge(self, query: str, c: dict, ts: float) -> list[Case]:
        target, entry = self.target_of(query, c), self.entry_of(query, c)
        if query == "wmi_persistence":
            # A WMI command-line or script consumer runs code when an event fires, survives reboots and leaves no
            # file in a startup place (T1546.003). Measured 2026-10-18 on the main PC: the only subscription is
            # Windows' own SCM event-log filter, whose consumer is the built-in log kind, so 0 of these. Any new one
            # is an alert, whatever it runs.
            first = (_target_tokens(target) or [""])[0]
            prog = _basename(first).lower() or str(c.get("action") or "script").lower()
            script = c.get("kind") == "script"
            facts = {"kind": PERSIST_QUERIES[query], "entry": entry[:120], "program": prog,
                     "folder": "unknown" if script or not first else win_folder_class(first), "script": script,
                     "shell": prog in WIN_SHELLS or prog in WIN_LOLBINS, "signals": [], "url": "http" in target.lower(),
                     "registry": False}
            return self.emit(ts, "New WMI event subscription on the PC", facts, 4, prog or "wmi",
                             (self.state.host, query, _entry_key(entry)))
        if query in LINUX_SYSTEM:
            return self.judge_linux_system(query, c, ts, entry, target)
        if query in ("authorized_keys", "systemd_units"):
            # Linux persistence with no program to read: a new SSH key someone can log in with (T1098.004) is an
            # alert; a new systemd unit (T1543.002) is a digest item, since installing a service is also what
            # package installs and the owner's own `systemctl --user` services do (tapwatch's included, learned in
            # warm-up). Measured 2026-10-18 on the WSL box: 0 authorized keys, no system units outside the package
            # directories besides snap mounts (excluded in the query), 24 user unit files incl. timers and
            # enablement links (all learned: the first run after deploy lists them at once, an inventory).
            key = query == "authorized_keys"
            facts = {"kind": PERSIST_QUERIES[query], "entry": entry[:120], "program": entry[:80] if not key else "sshd",
                     "folder": "profile" if "/home/" in target or "/root/" in target else "installed",
                     "script": False, "shell": False, "signals": [], "url": False, "registry": False}
            return self.emit(ts, f"New {PERSIST_QUERIES[query]} on the PC", facts, 4 if key else 3, facts["program"],
                             (self.state.host, query, _entry_key(entry)))
        if (query == "startup_items" and entry.lower().endswith(".scope") and "\\" not in target
                and not str(c.get("source") or "").upper().startswith("HKEY")):
            # (Linux rows only: a Windows Run-key value can be named anything, `.scope` included; review of #150.)
            # A systemd scope is transient, made at run time for a container or a login session, never something that
            # starts at boot. Measured 2026-10-18, #811: the Zeek capture container's docker-<id>.scope, new each time
            # the sensor restarts.
            return []
        tokens = _target_tokens(target)
        if not tokens:
            return []   # a task with no action (Windows' SoftLanding tasks), or a bare registry value
        first = tokens[0]
        # The platform comes from the query and the row, not from the command: a Run key's value is often a bare
        # `powershell -nop -w hidden -c ...` or `mshta http://...` with no drive letter (review of #137).
        windows = query in ("scheduled_tasks", "auto_start_services") or (
            query == "startup_items" and (str(c.get("source") or "").upper().startswith("HKEY") or "\\" in target
                                          or ":" in first[:2]))
        prog = _basename(first).lower()
        if not re.search(r"[a-z]", prog):
            return []   # not a program at all (startup_items logs StartupApproved values as a number)
        if windows and "." not in prog:
            prog += ".exe"   # `cmd /c`, `powershell -enc`, `rundll32 x.dll,Entry`: Windows adds the extension too
        scripts = [t.strip('"') for t in tokens if t.lower().rstrip('"').endswith(SCRIPT_EXT)]
        script = bool(scripts)
        # the folder that matters is the script's when there is one (`wscript.exe C:\Users\<user>\Downloads\a.vbs` is
        # a script in Downloads, not a program in System32), else the first thing that looks like a path (`cmd /c
        # start C:\...\Downloads\x.exe` is about Downloads, not about cmd)
        paths = [t.strip('"') for t in tokens if "\\" in t or ":" in t[:2] or (t.startswith("/") and "/" in t[1:])]
        where = scripts[0] if scripts else (paths[0] if paths else first)
        folder = win_folder_class(where) if windows else posix_folder_class(where)
        shell = prog in WIN_SHELLS or prog in WIN_LOLBINS or prog in POSIX_SHELLS
        signals = bool(WIN_SUSPICIOUS_CMD.search(target) or SUSPICIOUS_CMD.search(target))
        url = "http://" in target.lower() or "https://" in target.lower()
        if signals or folder in ("temp", "shared", "downloads"):
            severity = 4
        elif script or shell or folder in ("appdata", "profile", "other"):
            severity = 3
        else:
            return []   # an installed program registering itself: Windows Update, an installer, a version bump
        kind = PERSIST_QUERIES[query]
        registry = str(c.get("source") or "").upper().startswith("HKEY")
        facts = {"kind": kind, "entry": entry[:120], "program": prog, "folder": folder, "script": script, "shell": shell,
                 "signals": ["an encoded or download-and-run command"] if signals else [], "url": url, "registry": registry}
        return self.emit(ts, f"New {kind} on the PC", facts, severity, prog, (self.state.host, query, _entry_key(entry)))


def _linux_system_facts(kind: str, entry: str, folder: str) -> dict:
    return {"kind": kind, "entry": entry[:120], "program": entry[:80], "folder": folder, "script": False,
            "shell": False, "signals": [], "url": False, "registry": False}


def _entry_key(entry: str) -> str:
    """An entry name with the parts that change per install removed (GUIDs, SIDs, version numbers, per-session
    suffixes), so one app's re-created entry is one digest line per week, not one per update."""
    e = re.sub(r"\{[0-9a-f-]{36}\}|s-1-5-[\d-]+|\d+(\.\d+){2,}|_(?=[0-9a-f]*\d)[0-9a-f]{5}\b", "", entry.lower())
    return e.strip(" -_")


def _port(v) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None



DISCOVERY_STRONG = {"whoami.exe", "systeminfo.exe", "nltest.exe", "net.exe", "net1.exe", "quser.exe", "query.exe",
                    "klist.exe", "cmdkey.exe", "dsquery.exe", "arp.exe", "wmic.exe"}
DISCOVERY_WEAK = {"ipconfig.exe", "netstat.exe", "nslookup.exe", "route.exe", "hostname.exe", "tasklist.exe",
                  "getmac.exe"}
RECON_WINDOW = 300
INTERACTIVE_PARENTS = {"explorer.exe", "windowsterminal.exe", "openconsole.exe", "conhost.exe", "code.exe",
                       "wezterm-gui.exe", "alacritty.exe"}   # what starts a shell a person types in


class DiscoveryBurst(HostDetector):
    """R25. One program starts three or more different discovery tools within five minutes, at least two of them
    the ones an intruder runs and a home user rarely does (whoami, systeminfo, nltest, net, quser, klist, arp…):
    the first minutes on a new foothold (T1033, T1082, T1016, T1087).

    Measured 2026-10-16/18 over 51.5 h of the main PC's log, 17,577 process starts: 37 discovery starts, all weak
    (ipconfig 27 from tailscaled, tasklist 10 from wslhost), and no parent ever started three different ones in
    five minutes. The owner troubleshooting a network (ipconfig, nslookup, netstat in a terminal) uses the weak
    tools, so they count towards the three but never make it alone. A shell as the parent (someone typing) is a
    digest item; anything else (a script host, an Office app, an unknown program running them) alerts.
    """

    name = "host_recon"
    QUERIES: ClassVar[tuple[str, ...]] = (SYSMON,)

    def __init__(self, state: EndpointState | None = None, reported_days: float = 7):
        super().__init__(state, reported_days)
        self.recent: dict[str, list[tuple[float, str]]] = {}   # parent -> (time, discovery program) in the window
        self.fired: dict[str, float] = {}

    def row(self, query: str, c: dict, ts: float) -> list[Case]:
        if str(c.get("eventid")) != "1":
            return []
        prog = _basename(c.get("path") or "").lower()
        if prog not in DISCOVERY_STRONG and prog not in DISCOVERY_WEAK:
            return []
        parent = _basename(c.get("parent_path") or "") or "unknown"
        seen = [(t, p) for t, p in self.recent.get(parent.lower(), []) if ts - t <= RECON_WINDOW] + [(ts, prog)]
        self.recent[parent.lower()] = seen[-30:]
        if len(self.recent) > 500:
            self.recent = {k: v for k, v in self.recent.items() if v and ts - v[-1][0] <= RECON_WINDOW}
            self.fired = {k: t for k, t in self.fired.items() if ts - t <= RECON_WINDOW}
        tools = sorted({p for _, p in seen})
        if len(tools) < 3 or len(set(tools) & DISCOVERY_STRONG) < 2:
            return []
        if ts - self.fired.get(parent.lower(), -1e18) < RECON_WINDOW:
            return []   # the same burst keeps going: one case
        self.fired[parent.lower()] = ts
        pclass = parent_class(parent)
        # A shell parent is someone typing only if that shell was started by Explorer or a terminal: an implant
        # runs `cmd /c whoami` too (review of #147). The shell's own start is known when it began within the last
        # ten minutes (EndpointState); a long-open terminal is not, and keeps the digest.
        shell_start = self.state.start_of(c.get("parent_guid") or "", ts)
        interactive = shell_start is None or shell_start.parent.lower() in INTERACTIVE_PARENTS
        severity = 3 if pclass == "shell" and interactive else 4
        facts = {"programs": tools[:8], "parent": parent, "parent_class": pclass, "count": len(tools)}
        if shell_start is not None:
            facts["parent_started_by"] = shell_start.parent
        return self.emit(ts, "Burst of discovery commands on the PC", facts, severity, parent,
                         (self.state.host, parent.lower()))


BROAD_HOSTS = ("<all_urls>", "*://*/*", "http://*/*", "https://*/*")
SENSITIVE_APIS = {"debugger", "nativemessaging", "proxy", "cookies", "webrequest", "webrequestblocking", "management",
                  "history", "clipboardread", "desktopcapture"}


class BrowserExtension(NewPersistence):
    """R26. A browser extension installed after warm-up that asks for the debugger or proxy control (alert: they
    reach past the browser, to every page's memory or all of its traffic) or for cookies, history, web requests,
    native programs or other extensions (digest): cookie and session theft without malware on disk (T1176).

    The agent's `chrome_extensions` query runs daily in differential mode on every OS (Chrome, Edge, Brave and the
    other Chromium browsers). Same batching, inventory and warm-up learning as R23: an update is a removed+added pair
    with the same identifier and is a change, not a new extension. Measured 2026-10-18: 1 added and 2 removed rows
    in 51.5 h; of the 7 installed extensions, 4 ask for a digest-level API (both password managers, an ad blocker,
    a mouse vendor's) and none for an alert-level one. osquery's `permissions` column carries API permissions but
    not Manifest V3 host permissions, so "every site" counts only where an extension lists it there (MV2).
    """

    name = "host_extension"
    QUERIES: ClassVar[tuple[str, ...]] = ("chrome_extensions",)
    DANGEROUS: ClassVar[set[str]] = {"debugger", "proxy"}

    @staticmethod
    def target_of(query: str, c: dict) -> str:
        return str(c.get("identifier") or "")

    @staticmethod
    def entry_of(query: str, c: dict) -> str:
        return str(c.get("name") or "")

    def key(self, query: str, c: dict) -> tuple:
        """The identifier alone: an update that renames or relocalises the extension is the same extension. The
        4-tuple shape matches R23's saved state."""
        return (self.state.host, query, "", self.target_of(query, c))

    def judge(self, query: str, c: dict, ts: float) -> list[Case]:
        # optional_permissions are granted at runtime on request: an extension can ask for the debugger later
        raw = f'{c.get("permissions") or ""},{c.get("optional_permissions") or ""}'
        perms = {p.strip().lower() for p in re.split(r"[,\s]+", raw) if p.strip()}
        broad = any(h.lower() in perms for h in BROAD_HOSTS)
        apis = sorted(perms & SENSITIVE_APIS)
        if not broad and not apis:
            return []   # a narrow extension (one site, a theme, a new-tab page)
        severity = 4 if set(apis) & self.DANGEROUS else 3
        name = self.entry_of(query, c)
        facts = {"extension": name[:80], "identifier": self.target_of(query, c)[:40], "all_sites": broad,
                 "apis": apis}
        return self.emit(ts, "New browser extension with broad access", facts, severity, name[:80] or "extension",
                         (self.state.host, self.target_of(query, c)))


POSIX_REMOTE_SHELLS = {"bash", "sh", "dash", "zsh", "ksh", "ash", "nc", "ncat", "netcat", "nc.openbsd", "nc.traditional",
                       "socat", "telnet"}


class LinuxSuspiciousConnect(HostDetector):
    """R27. On Linux or WSL: a program running from a temporary folder or from memory (memfd, a file that never
    touched the disk) connects out, or a shell or netcat holds an outgoing connection itself: the shapes of a
    dropped second stage and of a reverse shell (`bash -i >& /dev/tcp/…`, `nc -e`, `socat exec:`), T1059.004.

    Reads the agent's eBPF `bpf_connections` rows, which catch even a one-second connection. Measured 2026-10-16/18
    over 30.7 h of the WSL box's log: 49,975 outgoing connections, none from /tmp, /dev/shm, /var/tmp, /run/user or
    memfd; shells ran 78,967 times and held a connection 0 times (curl, git, python, node and the agent do the
    talking). A binary deleted while running is not counted: java, lua and python did that during upgrades. Any
    match is an alert, suppressible per program. Likely false positives: `go run` binaries under /tmp/go-build*,
    AppImages mounted under /tmp/.mount_*, installers or test copies run from /tmp. Blind spot: 26,447 of the
    49,975 rows carry no path (the process was gone when osquery looked it up), so the rule sees the other half.
    Repeats are folded by the store's one-hour dedupe on the program; no weekly memory (severity 4).
    """

    name = "host_linux_connect"
    QUERIES: ClassVar[tuple[str, ...]] = (BPF,)

    def row(self, query: str, c: dict, ts: float) -> list[Case]:
        if not outside(c.get("remote_address", ""), c.get("remote_port")):
            return []
        path = str(c.get("path") or "")
        prog = path.rsplit("/", 1)[-1] or "unknown"
        memory = "memfd:" in path
        temp = path.startswith(SUSPICIOUS_DIRS)
        shell = prog in POSIX_REMOTE_SHELLS
        if not (memory or temp or shell):
            return []
        what = "memory" if memory else "temp" if temp else "shell"
        facts = {"program": prog[:80], "how": what, "parent": str(c.get("parent_name") or "")[:80],
                 "port": _port(c.get("remote_port"))}
        title = ("A shell or netcat held an internet connection" if shell and not (memory or temp)
                 else "Program from a temporary folder or memory connected to the internet")
        return self.emit(ts, title, facts, 4, prog[:80])


LINUX_CMD = {"dlrun": "a download piped into a shell", "revshell": "a reverse shell", "b64exec": "base64 decoded into a shell",
             "histclear": "shell history switched off or cleared", "tmpexec": "a file in a temporary folder made executable",
             "miner": "a cryptocurrency miner"}


class LinuxCommand(HostDetector):
    """R28. On Linux or WSL, a program started with a command line that downloads and runs (`curl … | sh`), opens a
    reverse shell (`/dev/tcp/`, `nc -e`, `socat exec:`, `bash -i >&`, a Python or Perl socket one-liner), runs
    decoded base64, switches shell history off, or makes a file in /tmp, /dev/shm or /var/tmp executable (T1059.004,
    T1105, T1027, T1070.003).

    The agent's eBPF exec query computes these yes/no signals on the PC (lcmd_*) and keeps the command line in its
    own log only when one fires: the log is readable by every local account (mode 0644), as on Windows. The text
    never gets here. Each pattern was checked against matching lines and against harmless neighbours (`curl -o`,
    `nc -zv`, `nc -l`, `base64 -d file`, `chmod 644 /tmp/…`, `grep -e`, `docker exec`). No baseline exists: command
    lines were never collected before 2026-10-18, so the first day of flags is the measurement. A reverse shell is
    severity 4 like the rest (a developer testing with netcat can suppress it), the temp-folder chmod is a digest
    item. `sudo bash -c "curl … | sh"` shows the same line on two starts: the same signal within a minute is one
    case, as for R24 (two users' commands in that minute merge too: a single-owner box).

    Blind spot: a pipeline typed in an interactive shell is never one exec's command line (each program gets its
    own argv, with no `|`), and `history -c` or `unset HISTFILE` typed there are shell builtins that exec nothing.
    What it sees is `bash -c "…"` and `sh -c "…"` strings, which is how scripts, cron and coding agents run commands.
    """

    name = "host_linux_cmd"
    QUERIES: ClassVar[tuple[str, ...]] = (PROCS,)
    CHAIN = 60

    def __init__(self, state: EndpointState | None = None, reported_days: float = 7):
        super().__init__(state, reported_days)
        self.chain: dict[tuple, float] = {}

    def row(self, query: str, c: dict, ts: float) -> list[Case]:
        hits = [k for k in LINUX_CMD if str(c.get(f"lcmd_{k}", "0")) == "1"]
        if not hits:
            return []
        key = (self.state.host, tuple(hits))
        if ts - self.chain.get(key, -1e18) < self.CHAIN:
            return []
        self.chain[key] = ts
        if len(self.chain) > 200:
            self.chain = {k: t for k, t in self.chain.items() if ts - t < self.CHAIN}
        prog = str(c.get("path") or "").rsplit("/", 1)[-1] or "unknown"
        severity = 3 if hits == ["tmpexec"] else 4
        facts = {"program": prog[:80], "signals": [LINUX_CMD[k] for k in hits]}
        return self.emit(ts, "Suspicious command on the PC (Linux)", facts, severity, prog[:80],
                         (self.state.host, prog, tuple(hits)))


VM_READ = 0x10   # PROCESS_VM_READ: what reading lsass.exe's memory (credentials) needs


class LsassAccess(HostDetector):
    """R29. A program other than Windows' own opens lsass.exe with the right to read its memory: credential dumping
    (mimikatz's sekurlsa, comsvcs.dll MiniDump, procdump -ma lsass, T1003.001).

    Sysmon event 10 (process access) with lsass.exe as the target; sysmon.xml already drops svchost, wininit, csrss,
    services, wmiprvse and the Defender engine, which open it all day. Only an access mask with PROCESS_VM_READ
    (0x10) counts: querying lsass (0x1000, 0x1400) is what monitoring tools do; Task Manager sometimes asks 0x1410,
    which does count (suppress it per program if it shows up). A program from a
    temporary, Downloads or shared folder, or one a document or mail app started, is must_alert; anything else is
    severity 4, suppressible per program (an EDR or a password manager may read it). No baseline yet: event 10 was
    off before 2026-10-18, so the first days after the Sysmon config is reloaded are the measurement.
    """

    name = "host_lsass"
    QUERIES: ClassVar[tuple[str, ...]] = (SYSMON,)

    def row(self, query: str, c: dict, ts: float) -> list[Case]:
        if str(c.get("eventid")) != "10" or _basename(c.get("target_path") or "").lower() != "lsass.exe":
            return []
        try:
            mask = int(str(c.get("granted") or "0"), 0)
        except ValueError:
            return []
        if not mask & VM_READ:
            return []
        src = c.get("source_path") or ""
        prog, folder = _basename(src).lower() or "unknown", folder_class(src)
        started = _start_facts(self.state.start_of(c.get("source_guid") or "", ts))   # event 10 has no ProcessGuid
        must = folder in ("temp", "downloads", "shared") or started.get("parent_class") == "document"
        facts = {"program": prog, "folder": folder, "access": hex(mask), **started}
        return self.emit(ts, "A program read the memory of Windows' credential store (lsass)", facts, 5 if must else 4,
                         prog, must_alert=must)

# R36: remote-access and RMM programs by file name -> (tool, its R16 service). Quick Assist is built into Windows and
# talks to Microsoft, so it has no R16 service. File names, not paths: a portable copy has the same name.
RMM_PROGRAMS: dict[str, tuple[str, str]] = {
    **dict.fromkeys(("anydesk.exe", "anydesk"), ("AnyDesk", "anydesk.com")),
    **dict.fromkeys(("teamviewer.exe", "teamviewer_service.exe", "tv_w32.exe", "tv_x64.exe", "teamviewerqs.exe",
                     "teamviewerqs_x64.exe", "teamviewer", "teamviewerd"), ("TeamViewer", "teamviewer.com")),
    **dict.fromkeys(("rustdesk.exe", "rustdesk"), ("RustDesk", "rustdesk.com")),
    **dict.fromkeys(("screenconnect.clientservice.exe", "screenconnect.windowsclient.exe",
                     "connectwisecontrol.client.exe"), ("ScreenConnect", "screenconnect.com")),
    **dict.fromkeys(("srservice.exe", "srstreamer.exe", "srmanager.exe", "strwinclt.exe", "splashtopsos.exe"),
                    ("Splashtop", "splashtop.com")),
    **dict.fromkeys(("ateraagent.exe", "atera_agent.exe"), ("Atera", "atera.com")),
    **dict.fromkeys(("logmein.exe", "lmiguardiansvc.exe", "logmeinsystray.exe", "lmi_rescue.exe"), ("LogMeIn", "logmein.com")),
    **dict.fromkeys(("ammyy_admin.exe", "aa_v3.exe", "ammyy.exe"), ("Ammyy Admin", "ammyy.com")),
    **dict.fromkeys(("supremo.exe", "supremoservice.exe"), ("Supremo", "supremocontrol.com")),
    **dict.fromkeys(("remote access.exe", "simplehelp.exe", "simplegatewayservice.exe"), ("SimpleHelp", "simple-help.com")),
    **dict.fromkeys(("meshagent.exe", "meshagent"), ("MeshCentral", "meshcentral.com")),
    **dict.fromkeys(("getscreen.exe",), ("Getscreen", "getscreen.me")),
    **dict.fromkeys(("remotepcservice.exe", "remotepc.exe"), ("RemotePC", "remotepc.com")),
    **dict.fromkeys(("tacticalrmm.exe", "rmmagent"), ("Tactical RMM", "")),
    **dict.fromkeys(("client32.exe",), ("NetSupport", "")),
    **dict.fromkeys(("ultraviewer_desktop.exe", "ultraviewer_service.exe"), ("UltraViewer", "")),
    **dict.fromkeys(("dwagent.exe", "dwagsvc.exe", "dwagent"), ("DWService", "")),
    **dict.fromkeys(("zaservice.exe", "zohoassist.exe", "zohoassistagent.exe"), ("Zoho Assist", "")),
    **dict.fromkeys(("action1_agent.exe",), ("Action1", "")),
    **dict.fromkeys(("ninjarmmagent.exe", "ninjarmmagentpatcher.exe"), ("NinjaOne", "")),
    **dict.fromkeys(("agentmon.exe",), ("Kaseya", "")),
    **dict.fromkeys(("pcmonitorsrv.exe", "pcmonitormanager.exe"), ("Pulseway", "")),
    **dict.fromkeys(("tvnserver.exe", "winvnc.exe", "vncserver.exe", "x11vnc", "vncserver", "x0vncserver"),
                    ("VNC server", "")),
    **dict.fromkeys(("aeroadmin.exe",), ("AeroAdmin", "")),
    **dict.fromkeys(("rutserv.exe", "rfusclient.exe"), ("Remote Utilities", "")),
    **dict.fromkeys(("rserver3.exe",), ("Radmin", "")),
    **dict.fromkeys(("anyviewer.exe", "rcservice.exe"), ("AnyViewer", "")),
    **dict.fromkeys(("remoting_host.exe",), ("Chrome Remote Desktop", "")),
    **dict.fromkeys(("gotoassist.exe", "gotoassistcustomer.exe", "g2ax_customer.exe"), ("GoTo Resolve", "")),
    **dict.fromkeys(("bomgar-scc.exe", "bomgar-rep.exe"), ("BeyondTrust Remote Support", "")),
    **dict.fromkeys(("quickassist.exe",), ("Quick Assist", "")),
}
RMM_LEARN_DAYS = 7   # an office's own RMM, or the owner's, is learned in the rule's first week on a box


class RemoteAccessTool(HostDetector):
    """R36. A remote-access or RMM program starts on the PC for the first time (T1219): the PC's side of R16, which
    sees the same tools' servers on the wire. Tech-support scams talk people into AnyDesk or Quick Assist; ransomware
    crews install ScreenConnect, AnyDesk or Atera because they are signed and allowed out.

    Reads the process starts already collected (Sysmon event 1 on Windows, eBPF exec on Linux) and matches the file
    name or, on Windows, the original file name from the program's version resource (so a renamed copy matches)
    against RMM_PROGRAMS. Per tool, the first start after a learning window is a case and later starts aren't: the
    window is the rule's first RMM_LEARN_DAYS on a box (persisted), so an office's own RMM is learned, not reported
    forever. A risky start (Temp, a shared folder or a document app) is tracked apart and never learned, even in that
    week, so a portable or Outlook-started copy of a tool the box already uses still reports, once. Known as
    well: `expected_tools` (tool names, `detectors.host_rmm`) and a `takeover.expected` entry for this PC and the
    tool's R16 service. Scored by the folder: installed (Program Files, /usr, /opt) 3; a user folder or Downloads 4,
    suppressible per tool; Temp, a shared folder, or started by a document or mail app 5, must_alert. Quick Assist
    is 4 wherever it runs. Measured 2026-10-19/20: 11,055 Windows process starts in 29 h and 288,764 Linux execs in
    two days, no remote-access program among them. Blind spot: a renamed copy with no version resource; R16 still
    sees its servers.
    """

    name = "host_rmm"
    QUERIES: ClassVar[tuple[str, ...]] = (SYSMON, PROCS)
    PERSIST: ClassVar[tuple[str, ...]] = ("reported", "seen", "known", "since")

    def __init__(self, state: EndpointState | None = None, reported_days: float = 7,
                 learn_days: float = RMM_LEARN_DAYS, expected: dict[str, set[str]] | None = None,
                 expected_tools: list[str] | None = None):
        super().__init__(state, reported_days)
        self.learn = learn_days * DAY
        self.expected = expected or {}      # host -> R16 services it's expected to use (takeover.expected)
        self.expected_tools = {t.lower() for t in expected_tools or ()}
        self.known: set[str] = set()        # tools seen on this box
        self.since: float | None = None     # when this rule first read a process start here

    def row(self, query: str, c: dict, ts: float) -> list[Case]:
        if query == SYSMON and str(c.get("eventid")) != "1":
            return []
        path = str(c.get("path") or "")
        windows = query == SYSMON
        prog = (_basename(path) if windows else path.rsplit("/", 1)[-1]).lower()
        if self.since is None:
            self.since = ts
        original = str(c.get("original_name") or "").lower() if windows else ""
        hit = RMM_PROGRAMS.get(prog) or RMM_PROGRAMS.get(original)
        if hit is None:
            return []
        tool, service = hit
        folder = win_folder_class(path) if windows else posix_folder_class(path)
        parent = _basename(c.get("parent_path") or "") if windows else ""
        must = folder in ("temp", "shared") or parent_class(parent) == "document"
        seen = f"{tool} (risky)" if must else tool    # a risky start of a known tool is still news
        if seen in self.known or tool.lower() in self.expected_tools \
                or (service and service in self.expected.get(self.state.host, ())):
            return []
        self.known.add(seen)
        if ts - self.since < self.learn and not must:
            return []   # learned: there before the rule, or the box's own tool in its first week
        if must:
            severity = 5
        elif tool == "Quick Assist" or folder not in ("installed",):
            severity = 4
        else:
            severity = 3
        facts = {"tool": tool, "program": prog[:80], "folder": folder, "parent": parent[:80] or None,
                 "parent_class": parent_class(parent) if parent else None, "service": service or None,
                 "renamed": bool(original) and prog != original and prog not in RMM_PROGRAMS}
        # The tool's name is the indicator (and the suppression handle), so a renamed copy can't slip a suppression.
        return self.emit(ts, f"Remote-access tool started on the PC for the first time: {tool}", facts, severity,
                         tool, (seen,), must_alert=must)


def _agent_facts(c: dict) -> dict:
    """R37/R38 on Linux: the Claude Code markers the agent's query read from the process (or its parent) when a tunnel
    or sync signal fired. Attended means the owner is at the keyboard and asked for it; unattended is a session
    nobody is watching, which a prompt injection could drive."""
    if not c.get("claude_session"):
        return {}
    attended = str(c.get("claude_attended") or "")
    ssh = str(c.get("via_ssh") or "0") not in ("", "0")   # driven over an SSH login: not the owner at the keyboard
    return {"agent_started": True, "agent_attended": attended == "1" and not ssh,
            "agent_unattended": attended == "0" or ssh, "via_ssh": ssh}


# R37/R38: programs that only *carry* another command line (`bash -c "7z a -p..."`, `timeout 40 powershell -Command
# ...`, `sudo ngrok ...`): the tool's own start has the same signal, so these are skipped. Measured 2026-10-20: the
# R38 safe test raised four cases, for bash, timeout, powershell.exe and 7z.exe.
WRAPPERS = frozenset({"bash", "sh", "dash", "zsh", "fish", "ksh", "sudo", "doas", "env", "timeout", "nohup", "nice",
                      "setsid", "xargs", "script", "strace", "watch", "su", "runuser", "flock", "stdbuf", "time",
                      "ionice", "chrt", "taskset", "unbuffer", "sudo.exe", "wt.exe",
                      "cmd.exe", "powershell.exe", "bash.exe", "sh.exe", "pwsh.exe", "wsl.exe", "wslhost.exe", "conhost.exe", "cscript.exe",
                      "wscript.exe", "runas.exe"})
SIGNAL_CHAIN = 60   # seconds: the same program with the same signal again is one command (`sudo` runs it twice)


def _is_wrapper(prog: str, folder: str) -> bool:
    """A wrapper only where wrappers live: ngrok copied to %TEMP%\\cmd.exe or /tmp/sh is the tool, not a wrapper."""
    return prog in WRAPPERS and folder == "installed"


def _program_and_folder(query: str, c: dict) -> tuple[str, str]:
    path = str(c.get("path") or "")
    if query == SYSMON:
        return _basename(path).lower() or "unknown", win_folder_class(path)
    return path.rsplit("/", 1)[-1] or "unknown", posix_folder_class(path)


class TunnelOpened(HostDetector):
    """R37. A program opens a tunnel that lets the internet in past the router (T1572): `ngrok`, `cloudflared tunnel`,
    `code tunnel`, `devtunnel host`, `tailscale funnel`, `ssh -R`, localtunnel, bore. The agent computes the signal
    on the PC (cmd_tunnel on Windows, lcmd_tunnel on Linux) and never keeps the command line, which carries the
    tunnel's token. Severity 4, suppressible per program; from Temp or a shared folder 5, must_alert. On Linux, an
    attended Claude Code session (the markers the query read) makes it 3, a digest item with `agent_started`: the
    owner asked for it. An unattended one stays an alert: a prompt-injected agent opening a tunnel is the threat.
    """

    name = "host_tunnel"
    QUERIES: ClassVar[tuple[str, ...]] = (SYSMON, PROCS)

    def __init__(self, state: EndpointState | None = None, reported_days: float = 7):
        super().__init__(state, reported_days)
        self.chain: dict[tuple, float] = {}

    def row(self, query: str, c: dict, ts: float) -> list[Case]:
        flag = "cmd_tunnel" if query == SYSMON else "lcmd_tunnel"
        if str(c.get(flag, "0")) != "1" or (query == SYSMON and str(c.get("eventid")) != "1"):
            return []
        prog, folder = _program_and_folder(query, c)
        if _is_wrapper(prog, folder):
            return []
        agent = _agent_facts(c)
        must = folder in ("temp", "shared")
        severity = 5 if must else 3 if agent.get("agent_attended") else 4
        if _chained(self.chain, ("tunnel", prog, folder, severity), ts):   # a louder start is never hidden by a quieter
            return []
        if prog in ("node", "node.exe"):
            prog = "localtunnel"   # the only tunnel pattern node runs (lt.js): name the tool, so a suppression is narrow
        facts = {"program": prog[:80], "folder": folder, **agent}
        return self.emit(ts, "A tunnel into the PC was opened", facts, severity, prog[:80], (prog, folder),
                         must_alert=must)


STAGING_LEARN_DAYS = 7   # the box's own backups and sync jobs are learned in the rule's first week
USER_FOLDERS = {"documents", "desktop", "pictures", "onedrive"}


def _chained(chain: dict[tuple, float], key: tuple, ts: float) -> bool:
    """True when the same key was seen within SIGNAL_CHAIN seconds of the first one, either side (the Windows and Linux
    feeds and a backlog arrive out of order). A hit doesn't move the window. The key always names the program and its
    folder, so one program can't hide another (a suppressed 7-Zip can't cover a rar.exe from Temp); the cost is that
    a wrapper not in WRAPPERS can still double a case."""
    if abs(ts - chain.get(key, -1e18)) < SIGNAL_CHAIN:   # abs: the agents' feeds arrive out of order
        return True
    chain[key] = max(ts, chain.get(key, ts))   # a late row doesn't wind the window back
    if len(chain) > 200:
        for k in [k for k, t in chain.items() if ts - t >= SIGNAL_CHAIN]:
            del chain[k]
    return False


class FilesStaged(HostDetector):
    """R38. Files copied or synced somewhere new with a trusted tool, or packed into a password-protected archive
    (T1567, T1560): rclone, restic, MEGA, the AWS, Azure and Google cloud CLIs, WinSCP scripts; 7-Zip, RAR and zip
    with a password. The agent never keeps the command line (it can hold an archive password or a repository's
    user:pass); its query extracts only the destination: the rclone remote, the bucket, the storage account, the
    restic repository's host. Per (tool, destination), new after a learning window (the rule's first week on a box,
    persisted, so the nightly backup is learned) is a digest item; known is nothing. A password archive is a digest
    item, an alert when it packs Documents, Desktop, Pictures or OneDrive. An upload_spike from the same device
    within five minutes pairs with it into an alert (host <-> network correlation). Agent-started on Linux:
    `agent_started`, stays digest. Measured 2026-10-20: a nightly restic on the Linux box (3 execs); 7-Zip twice from
    a vendor installer, no password.
    """

    name = "host_staging"
    QUERIES: ClassVar[tuple[str, ...]] = (SYSMON, PROCS)
    PERSIST: ClassVar[tuple[str, ...]] = ("reported", "seen", "known", "since")

    def __init__(self, state: EndpointState | None = None, reported_days: float = 7,
                 learn_days: float = STAGING_LEARN_DAYS):
        super().__init__(state, reported_days)
        self.learn = learn_days * DAY
        self.known: set[tuple] = set()      # (tool, destination) seen on this box
        self.since: float | None = None
        self.chain: dict[tuple, float] = {}

    def row(self, query: str, c: dict, ts: float) -> list[Case]:
        if query == SYSMON and str(c.get("eventid")) != "1":
            return []
        if self.since is None:
            self.since = ts
        pre = "cmd_" if query == SYSMON else "lcmd_"
        prog, folder = _program_and_folder(query, c)
        if _is_wrapper(prog, folder):
            return []
        agent = _agent_facts(c)
        if str(c.get(pre + "sync", "0")) == "1":
            # No destination on the command line: a restic repository from the environment, or a local one (never
            # captured: its path holds the user name). One key for those, so a new remote repository still reports.
            dest = str(c.get("sync_dest") or "local or from the environment").lower()[:120]
            tool = prog.removesuffix(".exe").removesuffix(".com")
            key = (tool, dest)
            if key in self.known or _chained(self.chain, ("sync", prog, folder, dest), ts):
                return []
            self.known.add(key)
            if ts - self.since < self.learn:
                return []
            facts = {"program": prog[:80], "tool": tool, "destination": dest, "folder": folder, **agent}
            return self.emit(ts, "Files sent to a destination this PC hasn't used before", facts, 3, dest,
                             ("sync",) + key)
        if str(c.get(pre + "archive_pw", "0")) == "1":
            of = str(c.get("archive_of") or "").lower()
            user = of in USER_FOLDERS
            if _chained(self.chain, ("archive", prog, folder, of, bool(agent.get("agent_attended"))), ts):
                return []
            facts = {"program": prog[:80], "archive_of": of or None, "folder": folder, **agent}
            return self.emit(ts, "A password-protected archive was made" + (f" of {of.title()}" if user else ""),
                             facts, 4 if user and not agent.get("agent_attended") else 3, prog[:80],
                             ("archive", prog, of))
        return []


class FileChanged(HostDetector):
    """R39. A file that gives persistence or privilege changes (T1546.004, T1574.006, T1548.003, T1547.001): on Linux,
    `/etc/ld.so.preload` or sudoers written, a shell's start-up file, `/etc/profile.d/` or an XDG autostart entry
    changed (the agent's `file_changes` inotify query, the home part reduced to ~ on the PC; it watches the
    directories and picks the files, because a missing file is never watched and a save-by-rename drops a file's
    watch: measured with osqueryd 5.23.1, a new file is CREATED and `sed -i` is MOVED_TO the real name); on Windows, a file
    created in a Startup folder (Sysmon event 11, only the file name and per-user or all-users).

    Privilege files and a Startup-folder file written by a shell, script host, LOLBin, document or mail app, or a
    program in Temp, Downloads or a shared folder are 4 and alert; the rest 3. It shipped as digest-only until a
    week's volume was measured on the dev PC, where editors and coding agents touch dotfiles: 2026-10-20 to 10-25 gave
    one case (the safe test), no Startup-folder writes beside ~8,000 process starts a day, and no Linux file events,
    so the 4s alert since v0.3 (`alert: false` under detectors.host_fim puts every case back in the digest, with
    `would_alert` set). R23 still reports ld.so.preload *content* at 5 and the
    Startup folder hourly; this one is immediate and names the program on Windows. Blind spots: which program read a
    file (file monitoring can't say), and on WSL, Windows paths (inotify sees Linux paths only).
    """

    name = "host_fim"
    QUERIES: ClassVar[tuple[str, ...]] = (SYSMON, FIM)

    def __init__(self, state: EndpointState | None = None, reported_days: float = 1, alert: bool = True):
        super().__init__(state, reported_days)
        self.alert = alert

    def row(self, query: str, c: dict, ts: float) -> list[Case]:
        if query == FIM:
            f = str(c.get("file") or "")
            if f == "/etc/ld.so.preload" or f.startswith("/etc/sudoers"):
                kind, level = "privilege file", 4
            elif f.startswith("~/.config/autostart/"):
                kind, level = "autostart entry", 3
            elif f.startswith(("~/.", "/etc/profile.d/")):
                kind, level = "shell start-up file", 3
            else:
                return []
            facts = {"file": f[:120], "kind": kind, "action": str(c.get("action") or "").lower(), "os": "linux"}
            return self._case(ts, facts, level, f[:120], (f,))
        if str(c.get("eventid")) != "11":
            return []
        name = str(c.get("file_name") or "")[:120] or "unknown"
        path = str(c.get("path") or "")
        prog, folder = _basename(path).lower() or "unknown", win_folder_class(path)
        risky = prog in WIN_SHELLS or prog in WIN_LOLBINS or prog in WIN_DOC_APPS or \
            folder in ("temp", "downloads", "shared")
        facts = {"file": name, "kind": "Startup folder file", "scope": c.get("startup_scope"), "program": prog[:80],
                 "folder": folder, "os": "windows"}
        return self._case(ts, facts, 4 if risky else 3, name, (name, prog))

    def _case(self, ts: float, facts: dict, level: int, indicator: str, key: tuple) -> list[Case]:
        severity = level if self.alert else 3
        facts["would_alert"] = level >= 4
        if severity >= 4:   # emit's once-a-day applies below alert level only; a file is one case a day either way
            if still_reported(self.reported, key, ts, self.ttl):
                return []
            self.reported[key] = ts
        return self.emit(ts, f"A {facts['kind']} changed on the PC", facts, severity, indicator, key)


# Host <-> network correlation (pipeline.correlate): which network rules tell the same story as each host rule, so a
# pairing within five minutes means something. Measured 2026-10-20: with any pairing allowed, every R36-R39 safe test
# was lifted to an alert by an unrelated dns_bypass digest item three minutes earlier (this PC has network digest items
# most hours). Both sides are filtered with this one table. A host rule not listed pairs with nothing.
# The program reached somewhere: what a first contact looks like. Not dns_bypass: none of the true pairs measured on
# 2026-10-17 involved it, and it was the coincidence that lifted the 2026-10-20 tests. The IDS verdicts (Suricata,
# the router's IPS) are rare and strong, so they pair.
CONTACT = frozenset({"new_domain", "beaconing", "dns_anomaly", "tls_odd", "takeover", "ioc_match", "upload_spike",
                     "odd_port", "ids_alert", "udm_ips"})
PAIRS: dict[str, frozenset[str]] = {
    **dict.fromkeys(("host_encoded_cmd", "host_app_shell", "host_temp_exec", "host_lolbin", "host_bad_sig",
                     "host_linux_connect", "host_linux_cmd"), CONTACT),
    "host_persist": frozenset({"beaconing", "takeover", "ioc_match"}),
    "host_destructive": frozenset({"upload_spike", "takeover", "ioc_match"}),
    "host_recon": frozenset({"scan", "takeover", "ioc_match", "new_domain"}),
    "host_extension": frozenset({"new_domain", "takeover", "ioc_match", "upload_spike"}),
    "host_lsass": frozenset({"takeover", "ioc_match", "upload_spike", "new_domain"}),
    # R16 sees the same tool's servers or tunnel service; Suricata and the router's IPS have signatures for them; a
    # tunnel or a remote-access tool next to a port opened to the internet is one story.
    "host_rmm": frozenset({"takeover", "ids_alert", "udm_ips", "exposure"}),
    "host_tunnel": frozenset({"takeover", "ids_alert", "udm_ips", "exposure"}),
    "host_staging": frozenset({"upload_spike", "takeover", "ids_alert", "udm_ips"}),  # the upload, or file-drop sites
    "host_fim": frozenset(),                                 # a file change has no network side
    # R48 is a daily inventory fact, not an event; #227 (vulnkev.DeviceKev) raises the device's other cases instead
    "vuln_kev": frozenset(),
}


# Network rules that pair with no host rule, on purpose: about the network or a device rather than a program on this PC.
# A test holds every network rule to PAIRS or this set, so a new one can't be left out by accident.
NEVER_PAIRED = frozenset({"new_device", "identity", "gateways", "mgmt_access", "cleartext_auth", "rogue_dhcp",
                          "dns_bypass", "iot_drift", "udm_admin", "feed_silence", "off_hours", "upload_stopped"})


def pairs_with(host_detector: str, network_detector: str) -> bool:
    return network_detector in PAIRS.get(host_detector, frozenset())


def build(cfg: dict, warmup: Warmup | None = None) -> list[Detector]:
    """The endpoint rules, sharing one EndpointState. `detectors.host_rules: {enabled: false}` turns them off;
    `detectors.<name>: {reported_days: N}` tunes one. The PC's address starts as `host_context.host` and follows
    the agent's `host_addresses` snapshots (the same rows host context uses). `warmup` is the network detectors'
    clock (the one the pipeline persists), so R23 learns the existing entries during the same first day.
    FleetAgents, last, reads the computers enrolled in Fleet, each with a set of these rules of its own."""
    d = cfg.get("detectors", {})
    if (d.get("host_rules") or {}).get("enabled", True) is False:
        return []
    state = EndpointState((cfg.get("host_context") or {}).get("host") or "", _gateways(cfg))
    return rules_for(cfg, state, warmup) + [FleetAgents(cfg)]


def _gateways(cfg: dict) -> list[str]:
    return [str(g) for g in (cfg.get("network") or {}).get("gateways") or ()]


def rules_for(cfg: dict, state: EndpointState, warmup: Warmup | None = None) -> list[Detector]:
    """One computer's host rules, sharing `state`."""
    d = cfg.get("detectors", {})
    classes = (EncodedCommand, AppSpawnsShell, TempFolderConnects, LolbinConnects, BadSignatureConnects)
    rules = [cls(state, **d.get(cls.name, {})) for cls in classes]
    rules.append(NewPersistence(state, warmup=warmup or Warmup(cfg.get("warmup_seconds", 86400)),
                                **d.get(NewPersistence.name, {})))
    rules.append(DestructiveCommand(state, **d.get(DestructiveCommand.name, {})))
    rules.append(DiscoveryBurst(state, **d.get(DiscoveryBurst.name, {})))
    rules.append(BrowserExtension(state, warmup=warmup or Warmup(cfg.get("warmup_seconds", 86400)),
                                  **d.get(BrowserExtension.name, {})))
    rules.append(LinuxSuspiciousConnect(state, **d.get(LinuxSuspiciousConnect.name, {})))
    rules.append(LinuxCommand(state, **d.get(LinuxCommand.name, {})))
    rules.append(LsassAccess(state, **d.get(LsassAccess.name, {})))
    rules.append(RemoteAccessTool(state, expected=_expected_services(d.get("takeover", {})),
                                  **d.get(RemoteAccessTool.name, {})))
    rules.append(TunnelOpened(state, **d.get(TunnelOpened.name, {})))
    rules.append(FilesStaged(state, **d.get(FilesStaged.name, {})))
    rules.append(FileChanged(state, **d.get(FileChanged.name, {})))
    if (d.get(vulnkev.NAME) or {}).get("enabled", True):
        # `_vuln_index`: an in-memory index (selfcheck's fixture) instead of the feeds directory
        opts = {k: v for k, v in (d.get(vulnkev.NAME) or {}).items() if k != "enabled"}
        rules.append(vulnkev.VulnKev(state, feeds_dir=cfg.get("feeds_dir", "feeds"), index=cfg.get("_vuln_index"),
                                     **opts))
    return rules


class FleetAgents(Detector):
    """#14. The computers enrolled in Fleet (deploy/fleet): every agent gets the full set of host rules, with its own
    EndpointState, warm-up and learned state, as if tapwatch ran on it.

    Fleet writes every agent's results to one log (`fleet.results_log`), keyed by `hostIdentifier` (the agent's
    uuid, --host_identifier=uuid). A shared state would mix two PCs' process starts, signatures and persistence
    inventories; separate rule sets keep each one's first-run inventory (R23, R26), learning week (R36, R38) and
    address (from its own `host_addresses` snapshots). Until a snapshot names the address, its cases name the
    computer by the hostname Fleet's decorator adds. A new agent learns quietly for `warmup_seconds`, from its
    own first row. Persisted per agent; at most MAX_AGENTS (the least recently heard is forgotten first).

    Records are told apart by name (zeek: `pack/...` is Fleet's), so the PC tapwatch runs on stays standalone: an
    agent there enrolled in Fleet stops writing its local log (docs/setup/fleet.md)."""

    name = "fleet_agents"
    PERSIST: ClassVar[tuple[str, ...]] = ("agents",)
    MAX_AGENTS = 200

    def __init__(self, cfg: dict):
        self.cfg = cfg
        # agent uuid -> {"host", "label", "warmup_start", "seen", "rules": {rule name: its snapshot}}; persisted
        self.agents: dict[str, dict] = {}
        self.live: dict[str, list[Detector]] = {}

    def rules(self, agent: str, label: str, ts: float) -> list[Detector]:
        if agent in self.live:
            return self.live[agent]
        saved = self.agents.get(agent) or {}
        state = EndpointState("", _gateways(self.cfg), unknown=f"{saved.get('label') or label} (address not known yet)")
        state._host = saved.get("host") or ""
        warmup = Warmup(self.cfg.get("warmup_seconds", 86400))
        # The agent's learning day starts at its first row. Left to the rules, it would start at the first entry they
        # judge: the first-run inventory is learned without asking, so a new task days later would open the window
        # and be learned with it (review of #270).
        warmup.start = saved.get("warmup_start") or ts or None
        rules = rules_for(self.cfg, state, warmup)
        for r in rules:
            if r.PERSIST and r.name in (saved.get("rules") or {}):
                try:
                    r.restore(saved["rules"][r.name])
                except Exception as e:  # noqa: BLE001 - one rule's old shape shouldn't cost the agent its others
                    log.warning("fleet agent %s: discarding saved state for %s: %s", agent, r.name, e)
        self.live[agent] = rules
        self.agents.setdefault(agent, {"label": label})
        return rules

    def feed(self, rec: dict) -> list[Case]:
        agent = str(rec.get("hostIdentifier") or "")
        if rec.get("_type") != FLEET_OSQUERY or not agent:
            return []
        label = str((rec.get("decorations") or {}).get("hostname") or agent[:8])
        ts = float(rec.get("ts") or 0)
        rules = self.rules(agent, label, ts)
        self.agents[agent]["seen"] = ts
        if len(self.agents) > self.MAX_AGENTS:
            gone = min((a for a in self.agents if a != agent), key=lambda a: self.agents[a].get("seen") or 0)
            self.agents.pop(gone)
            self.live.pop(gone, None)
        r = dict(rec, _type=OSQUERY)
        return [c for d in rules for c in d.feed(r)]

    def tick(self, now: float) -> list[Case]:
        return [c for rules in self.live.values() for d in rules for c in d.tick(now)]

    def flush(self) -> list[Case]:
        return [c for rules in self.live.values() for d in rules for c in d.flush()]

    def vulns(self) -> list[vulnkev.VulnKev]:
        """Each agent's R48 rule, so the pipeline closes their fixed cases too."""
        return [d for rules in self.live.values() for d in rules if isinstance(d, vulnkev.VulnKev)]

    def snapshot(self) -> dict:
        for agent, rules in self.live.items():
            if agent not in self.agents:
                continue
            state = rules[0].state
            warmup = next((getattr(d, "warmup", None) for d in rules if isinstance(getattr(d, "warmup", None), Warmup)),
                          None)
            self.agents[agent].update(host=state._host, warmup_start=warmup.start if warmup else None,
                                      rules={d.name: d.snapshot() for d in rules if d.PERSIST})
        return super().snapshot()

    def restore(self, data: dict) -> None:
        super().restore(data)
        self.live.clear()   # rebuilt per agent from `agents` at its next row
