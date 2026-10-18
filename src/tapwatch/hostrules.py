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

import ipaddress
import re
from dataclasses import dataclass
from typing import ClassVar

from .detectors import Detector, Warmup, is_internal, prune_reported, still_reported
from .hostctx import (
    ADDRS,
    CMD_DESTRUCTIVE,
    CMD_SUSPICIOUS,
    CMD_UNUSUAL,
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
# Command-line signals that are weak alone on a dev PC: `iex (irm ...)` installs tools, scripts decode base64.
WEAK_SIGNALS = {"b64", "iex"}
GUID_WINDOW = 600            # seconds a process start is remembered, to join the connections it makes next
DAY = 86400.0
TEMP_DIRS = ("/appdata/local/temp/", "c:/windows/temp/")
SHARED_DIRS = ("/users/public/", "/$recycle.bin/", "c:/perflogs/")  # writable by every account, never an install

NAMES = ("host_encoded_cmd", "host_app_shell", "host_temp_exec", "host_lolbin", "host_bad_sig", "host_persist",
         "host_destructive")
# R23: the agent's hourly differential queries over the places programs register to run again (osquery.conf).
PERSIST_QUERIES = {"scheduled_tasks": "scheduled task", "auto_start_services": "service",
                   "startup_items": "startup item", "crontab": "cron job", "launchd_run_at_load": "launch agent"}
SCRIPT_EXT = (".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".bat", ".cmd", ".hta", ".sh", ".py", ".pl", ".rb")
EXEC_EXT = SCRIPT_EXT + (".exe", ".com", ".dll", ".msc", ".scr", ".cpl", ".lnk")
POSIX_SHELLS = {"sh", "bash", "zsh", "dash", "python", "python3", "perl", "node", "ruby", "nohup"}
BATCH_GRACE = 120            # seconds after a query run before its rows are read as one batch (they log within a second)
DUMP_MIN = 5                 # adds with no removes in one batch: osquery's first run of the query, an inventory, not a change
KNOWN_MAX = 5000             # entries remembered per PC (a PC has a few hundred); older ones are forgotten first
LAN_PREFIXES = ("192.168.", "10.")   # where home LANs live; 172.16/12 is where Hyper-V and WSL put their switches
PC_UNKNOWN = "this PC"               # the case's host until an agent snapshot or host_context.host names the address


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
    return not (addr.is_loopback or is_internal(remote)) and str(port) != "53"


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

    def __init__(self, host: str = "", gateways: list[str] | None = None):
        self.configured = host
        self._host = host
        # the router's networks (network.gateways, documented as one router per /24): the LAN address is the one
        # on a router's /24; a /16 or /23 LAN falls back to the old order. Measured 2026-10-17: the WSL agent in
        # mirrored mode also lists 10.255.255.254, which sorted ahead of 192.168.x and gave three host cases a host
        # no identity knew (#792-#794)
        self.lan_nets = {".".join(g.split(".")[:3]) for g in (gateways or ()) if g.count(".") == 3}
        self._routed = False   # once an address on a router's net was seen, a snapshot without one keeps it
        self.starts: dict[str, Start] = {}
        self.latest = 0.0
        # Signatures arrive every 5 minutes per program path (process_signatures), connections every minute
        # (outbound_connections): either can come first, so both sides are remembered and joined by path.
        self.signatures: dict[str, tuple[str, str]] = {}   # path (lowercased) -> (authenticode result, signer)
        self.connected: dict[str, tuple[float, dict]] = {}  # path (lowercased) -> (when, the socket row)

    @property
    def host(self) -> str:
        return self._host or PC_UNKNOWN

    def update_addresses(self, rows: list[dict]) -> None:
        addrs = {str(r.get("address")) for r in rows if r.get("address")}
        if self.configured and self.configured in addrs:
            self._host = self.configured
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
    PERSIST: ClassVar[tuple[str, ...]] = ("reported",)

    def __init__(self, state: EndpointState | None = None, reported_days: float = 7):
        self.state = state or EndpointState()
        self.reported: dict = {}
        self.ttl = reported_days * DAY

    def feed(self, rec: dict) -> list[Case]:
        if rec.get("_type") != OSQUERY:
            return []
        name, ts = rec.get("name"), float(rec.get("ts") or 0)
        rows = rec.get("snapshot") if rec.get("action") == "snapshot" else [rec.get("columns")]
        rows = [r for r in (rows or ()) if isinstance(r, dict)]
        if name == ADDRS:
            self.state.update_addresses(rows)
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
                out += self.row(name, c, _row_ts(c, ts))
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
        if severity < 4 and not must_alert:
            if still_reported(self.reported, key, ts, self.ttl):
                return []
            self.reported[key] = ts
            if len(self.reported) > 2000:
                self.reported = prune_reported(self.reported, ts, self.ttl)
        return [Case(self.name, self.state.host, ts, title, {"source": "endpoint", **facts}, [indicator],
                     must_alert=must_alert, base_severity=severity)]


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
    item: on a Visual Studio PC it connects out for every NuGet restore.
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
        severity = 5 if must else 3 if prog in LOLBIN_DEV_TOOLS else 4
        facts = {"program": prog, "folder": folder_class(path), "port": _port(c.get("remote_port")),
                 "downloader": must, **_start_facts(self.state.start_of(c.get("guid") or "", ts))}
        return self.emit(ts, "Built-in Windows tool connected to the internet", facts, severity, prog,
                         (self.state.host, prog), must_alert=must)


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
    started 0 times; the 13 command lines the agent kept matched none of the patterns. Backups, recovery and
    logs gone: severity 5, must_alert (no benign reading on a home PC; an administrator who does it on purpose
    knows the alert is coming). Defender and accounts: severity 4, suppressible, because an installer or the
    owner adding an exclusion or a user is a thing that happens once and can then be allowed per program.
    """

    name = "host_destructive"
    QUERIES: ClassVar[tuple[str, ...]] = (SYSMON,)

    def row(self, query: str, c: dict, ts: float) -> list[Case]:
        if str(c.get("eventid")) != "1":
            return []
        flags = flags_of(c)
        harm = [f for f in flags if f in CMD_DESTRUCTIVE]
        if not harm:
            return []
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
    of DUMP_MIN or more adds with no removes is an inventory, and a key seen before (`known`, persisted) or seen
    during warmup is learned silently. What is left is scored by what the entry runs: a suspicious command line
    or a temp, Downloads or shared folder -> alert; a script, a shell or script host, a LOLBin, or a per-user
    folder -> digest (the measured 40 h replayed: six, the owner's two .vbs files in the Startup folder, OneDrive's
    three RunOnce entries that run cmd.exe, and its startup task under AppData); an installed program with none of
    those -> learned, no case. The entry's name and its program travel as untrusted strings; the command line
    and path never enter the case, only the folder class and yes/no signals, as for the other host rules.
    """

    name = "host_persist"
    QUERIES: ClassVar[tuple[str, ...]] = tuple(PERSIST_QUERIES)
    PERSIST: ClassVar[tuple[str, ...]] = ("reported", "known")

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
        return out + self.settle(now)

    def _batch(self, query: str, rec_ts: float) -> dict:
        return self.pending.setdefault((query, int(rec_ts)), {"ts": rec_ts, "added": [], "removed": []})

    def row(self, query: str, c: dict, ts: float) -> list[Case]:
        self._batch(query, ts)["added"].append(c)
        return []

    def removed(self, query: str, rows: list[dict], ts: float) -> list[Case]:
        if query in PERSIST_QUERIES:
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
        return str(c.get("path") or "")   # services, startup items

    @staticmethod
    def entry_of(query: str, c: dict) -> str:
        if query == "crontab":  # the file's path names the user (/var/spool/cron/crontabs/<user>): never stored
            p = str(c.get("path") or "")
            return "a user's crontab" if "/etc/" not in p else _basename(p) or "crontab"   # /etc/cron.d/<file>, /etc/crontab
        return str(c.get("label") if query == "launchd_run_at_load" else c.get("name") or "")

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
            new = [c for c in b["added"] if self.key(query, c) not in gone]
            inventory = len(new) >= DUMP_MIN and not b["removed"]
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


def build(cfg: dict, warmup: Warmup | None = None) -> list[Detector]:
    """The endpoint rules, sharing one EndpointState. `detectors.host_rules: {enabled: false}` turns them off;
    `detectors.<name>: {reported_days: N}` tunes one. The PC's address starts as `host_context.host` and follows
    the agent's `host_addresses` snapshots (the same rows host context uses). `warmup` is the network detectors'
    clock (the one the pipeline persists), so R23 learns the existing entries during the same first day."""
    d = cfg.get("detectors", {})
    if (d.get("host_rules") or {}).get("enabled", True) is False:
        return []
    state = EndpointState((cfg.get("host_context") or {}).get("host") or "",
                          [str(g) for g in (cfg.get("network") or {}).get("gateways") or ()])
    classes = (EncodedCommand, AppSpawnsShell, TempFolderConnects, LolbinConnects, BadSignatureConnects)
    rules = [cls(state, **d.get(cls.name, {})) for cls in classes]
    rules.append(NewPersistence(state, warmup=warmup or Warmup(cfg.get("warmup_seconds", 86400)),
                                **d.get(NewPersistence.name, {})))
    rules.append(DestructiveCommand(state, **d.get(DestructiveCommand.name, {})))
    return rules
