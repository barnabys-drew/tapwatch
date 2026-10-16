"""Endpoint rules: host cases raised from the agent's own rows (R17-R21 in docs/detections/DESIGN.md).

Host context (hostctx.py) explains *network* cases: which program on the PC held the connection.
The detectors here read the same osquery results log as a log source of its own (`_type: osquery`,
zeek.LOG_TYPES) and raise cases for living-off-the-land activity that never looks odd on the wire:
an encoded or download-and-run command, a document app or browser starting a shell, a program in a
temp folder connecting out, a built-in Windows tool connecting out, a program with a bad code
signature connecting out.

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
from dataclasses import dataclass
from typing import ClassVar

from .detectors import Detector, is_internal, prune_reported, still_reported
from .hostctx import (
    ADDRS,
    CMD_SUSPICIOUS,
    CMD_UNUSUAL,
    SYSMON,
    WIN_DOC_APPS,
    WIN_INSTALLED_DIRS,
    WIN_LOLBINS,
    WIN_SHELLS,
    _basename,
    _sysmon_ts,
)
from .models import Case

OSQUERY = "osquery"
SNAPSHOT = "outbound_connections"   # Windows, every minute: program, parent and authenticode result per socket
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

NAMES = ("host_encoded_cmd", "host_app_shell", "host_temp_exec", "host_lolbin", "host_bad_sig")
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
    return tuple(k for k in (*CMD_SUSPICIOUS, *CMD_UNUSUAL, "url") if str(c.get(f"cmd_{k}", "0")) == "1")


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

    def __init__(self, host: str = ""):
        self.configured = host
        self._host = host
        self.starts: dict[str, Start] = {}
        self.latest = 0.0

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
        if lan:
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
            return []
        out: list[Case] = []
        for c in rows:
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
    """R21. A program whose code signature Windows rejects held an outside connection, from the Windows
    agent's 1-minute `outbound_connections` snapshot, which carries osquery's authenticode result.

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
    QUERIES: ClassVar[tuple[str, ...]] = (SNAPSHOT,)
    BAD: ClassVar[dict[str, int]] = {"untrusted": 4, "distrusted": 4}

    def row(self, query: str, c: dict, ts: float) -> list[Case]:
        sig = (c.get("signature") or "").lower()
        if sig not in self.BAD or not outside(c.get("remote_address", ""), c.get("remote_port")):
            return []
        path = c.get("path") or ""
        prog = (c.get("name") or _basename(path)).lower()
        facts = {"program": prog, "folder": folder_class(path), "signature": sig, "signer": c.get("signer") or "",
                 "parent": c.get("parent_name") or "", "port": _port(c.get("remote_port"))}
        return self.emit(ts, "Program with a bad code signature connected to the internet", facts, self.BAD[sig], prog,
                         (self.state.host, prog, sig))


def _port(v) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def build(cfg: dict) -> list[Detector]:
    """The endpoint rules, sharing one EndpointState. `detectors.host_rules: {enabled: false}` turns them off;
    `detectors.<name>: {reported_days: N}` tunes one. The PC's address starts as `host_context.host` and follows
    the agent's `host_addresses` snapshots (the same rows host context uses)."""
    d = cfg.get("detectors", {})
    if (d.get("host_rules") or {}).get("enabled", True) is False:
        return []
    state = EndpointState((cfg.get("host_context") or {}).get("host") or "")
    classes = (EncodedCommand, AppSpawnsShell, TempFolderConnects, LolbinConnects, BadSignatureConnects)
    return [cls(state, **d.get(cls.name, {})) for cls in classes]
