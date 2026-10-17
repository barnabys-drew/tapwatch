"""Host context: who on the tapwatch PC made a case's connections.

Network data can't tell the owner's coding agent from an attacker. On the PC that runs
tapwatch, osquery can. For a case on that PC, this module answers in code:

  * which program held the connection (a live osquery check, plus the agent's
    1-minute `outbound_connections_ctx` history for connections already closed)
  * whether a Claude Code session started it. That's read from environment markers
    (CLAUDE_CODE_SESSION_ID, CLAUDE_CODE_SESSION_ATTENDED, CLAUDE_CODE_ENTRYPOINT), which
    survive reparenting, unlike the parent chain. Also: started from the owner's Herdr
    terminal, or from an SSH login? A process that exited before osquery could read its
    environment (a one-second `curl`; measured 2026-10-15, case #259) is credited to the
    nearest ancestor that still carries markers, through the eBPF exec events' parent chain.
    When the chain ends at the agent's binary with no markers at all (measured 2026-10-16,
    case #376: osquery's eBPF rows carry thread ids, a thread has no process_envs row, and
    the agent's own environment never holds CLAUDE_CODE_SESSION_ID, only its child shells'
    do), the connection still counts as the agent's; the transcript then names the session.
    The agent binary's own connections (its API traffic) are judged by program name like any
    other program's; the chain rule is about what the agent ran.
  * from that session's transcript (~/.claude/projects/*/<session>.jsonl): did the agent
    run a command naming this destination, did the owner's prompt name it, and did
    the agent read outside web content between the prompt and the command (the
    prompt-injection pattern)? Transcripts are matched by the destination's names; its
    addresses are the fallback only when the case has no name at all (measured 2026-10-17,
    case #379: an IP needle picked a transcript that mentioned a shared Cloudflare address).

Measured 2026-10-16/17 on the live box: of 84 cases with host context, 79 named the program,
66 were other_program, 14 agent_unconfirmed and none a corroborated owner_using_agent, because
the markers live on the agent's short-lived child shells and never on the `claude` process or
its threads. The chain-only path is therefore the one real cases take. It is corroborated when
the owner's own prompt named the destination by name (`verdict`): a human typing the name is
stronger evidence of a person present than a marker, and a name match cannot be a shared-address
coincidence. Attendance stays unknown and is reported as such; the session id stays a best guess.

The answers become case facts (`host_*`). Jev reads them as plain sentences and picks
between "owner using the agent", "agent misused" and "other program"; the router only
lets that lower a case when the code facts back it up. No transcript text, session
id, path or command line ever leaves the PC: only the yes/no facts and minutes do.

Works on Linux/WSL and macOS (osquery's process_envs). Windows processes get names
from the Windows agent's log but no Claude markers. Other devices need Fleet.
"""

from __future__ import annotations

import glob
import ipaddress
import json
import logging
import os
import re
import socket
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .detectors import base_domain, is_internal

log = logging.getLogger("tapwatch")

# Same columns as agents/config/osquery.conf `outbound_connections_ctx`. Selects named
# environment variables only: the Claude messaging token sits in the same environment.
LIVE_SQL = (
    "SELECT p.pid, p.name, p.path, p.cmdline, p.on_disk, p.cgroup_path, s.remote_address, s.remote_port, "
    "(SELECT name FROM processes pp WHERE pp.pid = p.parent) AS parent_name, "
    "(SELECT value FROM process_envs e WHERE e.pid = p.pid AND e.key = 'CLAUDE_CODE_SESSION_ID') AS claude_session, "
    "(SELECT value FROM process_envs e WHERE e.pid = p.pid AND e.key = 'CLAUDE_CODE_SESSION_ATTENDED') AS claude_attended, "
    "(SELECT value FROM process_envs e WHERE e.pid = p.pid AND e.key = 'CLAUDE_CODE_ENTRYPOINT') AS claude_entrypoint, "
    "(SELECT count(*) FROM process_envs e WHERE e.pid = p.pid AND e.key = 'HERDR_PANE_ID') AS in_herdr, "
    "(SELECT count(*) FROM process_envs e WHERE e.pid = p.pid AND e.key IN ('SSH_CONNECTION', 'SSH_CLIENT')) AS via_ssh "
    "FROM process_open_sockets s JOIN processes p USING (pid) "
    "WHERE s.remote_address NOT IN ('', '0.0.0.0', '::', '127.0.0.1', '::1') AND s.remote_port != 0;"
)
# Windows has no process_envs (so no Claude markers) but can check code signatures (authenticode).
WIN_LIVE_SQL = (
    "SELECT p.pid, p.name, p.path, p.cmdline, p.on_disk, s.remote_address, s.remote_port, "
    "(SELECT name FROM processes pp WHERE pp.pid = p.parent) AS parent_name, "
    "(SELECT result FROM authenticode a WHERE a.path = p.path) AS signature, "
    "(SELECT subject_name FROM authenticode a WHERE a.path = p.path) AS signer "
    "FROM process_open_sockets s JOIN processes p USING (pid) "
    "WHERE s.remote_address NOT IN ('', '0.0.0.0', '::', '127.0.0.1', '::1') AND s.remote_port != 0;"
)
QUERIES = ("outbound_connections", "outbound_connections_ctx", "sysmon_events", "bpf_connections",
           "bpf_process_events")
QUERY_KEYS = tuple(f'"{q}"'.encode() for q in QUERIES)
BPF = "bpf_connections"   # Linux/WSL: every outgoing connection from osquery's eBPF publisher, as it happens
PROCS = "bpf_process_events"  # Linux/WSL: every exec, with its parent pid, so a gone process's chain is still known
# Parent-chain walk for a connection whose process left no markers (it had exited before osquery read
# /proc/<pid>/environ). A Claude Code shell runs commands as bash -> (tool) a few levels deep; 12 is plenty.
CHAIN_MAX = 12
AGENT_BINARIES = frozenset({"claude"})  # program names (after _name) that are the owner's coding agent
AGENTS_KEEP = 10_000          # agent rows kept per index; one process's threads share a few hundred pids at most
EXEC_KEEP = 50_000            # exec rows kept per index: ~an hour of a busy dev box, well under the 50 MB log tail
SYSMON = "sysmon_events"   # Windows: Sysmon process starts (1), connections (3) and DNS lookups (22), as they happen
# Command-line signals the sysmon_events query computes (agents/config/osquery.conf), so benign command lines never
# reach the results log, which every local account can read. Raw text is logged only when a suspicious one fires.
CMD_SUSPICIOUS = {"enc": "an encoded payload", "b64": "base64 decoding", "dl": "a download-and-run",
                  "iex": "Invoke-Expression"}
CMD_UNUSUAL = {"hidden": "a hidden window", "bypass": "an execution-policy bypass"}
# The PC's own addresses (agents/config/osquery.conf `host_addresses`, a snapshot every 5 minutes). DHCP moves the
# PC, so the configured IP is only a fallback for when no agent reports them.
ADDRS = "host_addresses"
ADDR_KEY = f'"{ADDRS}"'.encode()
ADDR_WINDOW = 900             # an address is the PC's for cases within 15 minutes of a snapshot that holds it
ADDR_KEEP = 6000              # snapshots kept in memory: about 8 days from two agents
REJECTED_NAMES_MAX = 16       # distinct DHCP names warned about once each when they differ from the PC's own
SLACK = 90                    # snapshot interval plus splay
LIVE_WINDOW = 600             # a live osquery check only counts for cases this recent
LOG_TAIL = 50_000_000         # bytes of a results log to read at most
BEFORE, AFTER = 900, 120      # transcript window around the case: 15 min before, 2 min after
OUTSIDE_TOOLS = ("WebFetch", "WebSearch")
OUTSIDE_TOOL_HINTS = ("browser", "playwright", "fetch", "chrome")


@dataclass
class Owner:
    """A process seen holding a connection."""

    name: str
    path: str = ""
    session: str = ""        # Claude Code session id, if a session started it
    attended: str = ""       # "1" attended, "0" not, "" unknown
    entrypoint: str = ""     # "cli" for the interactive app
    in_herdr: bool = False
    via_ssh: bool = False
    cmdline: str = ""        # redacted before it's stored anywhere (see redact)
    parent: str = ""
    on_disk: str = ""        # "0" = the program's file was deleted after it started (or it's in a container)
    container: bool | None = None  # None = unknown (an older log row without cgroup_path)
    signature: str = ""      # Windows authenticode: "trusted", "missing", "invalid", "untrusted"...
    signer: str = ""
    start: float = 0.0       # first seen (log rows); 0 for live rows
    end: float | None = None
    guid: str = ""           # Sysmon ProcessGuid: joins a connection or lookup to its process start (command line)
    cmd_flags: tuple = ()    # Sysmon: command-line signals osquery computed (raw text is only logged when suspicious)
    pid: int = 0             # Linux rows: the process, and its parent, for the exec-chain walk (0 = unknown)
    ppid: int = 0
    inherited: bool = False  # markers came from an ancestor (the process itself was gone before osquery looked)
    agent: str = ""          # the agent binary found in the exec chain when no ancestor carried markers


VERSION_NAME = re.compile(r"^\d+(\.\d+)+$")


def _int(v) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _name(c: dict) -> str:
    name, path = c.get("name") or "?", (c.get("path") or "").replace("\\", "/")
    if VERSION_NAME.match(name) and "/claude/versions/" in path:
        return "claude"  # Claude Code's binary is named after its version
    return name


def _owner(c: dict, start: float = 0.0) -> Owner:
    return Owner(name=_name(c), path=c.get("path") or "", session=c.get("claude_session") or "",
                 attended=str(c.get("claude_attended") or ""), entrypoint=c.get("claude_entrypoint") or "",
                 in_herdr=str(c.get("in_herdr") or "0") not in ("0", ""),
                 via_ssh=str(c.get("via_ssh") or "0") not in ("0", ""), cmdline=redact(c.get("cmdline") or ""),
                 parent=c.get("parent_name") or "", on_disk=str(c.get("on_disk") if c.get("on_disk") is not None else ""),
                 container=None if "cgroup_path" not in c else bool(CONTAINER.search(c.get("cgroup_path") or "")),
                 signature=(c.get("signature") or "").lower(), signer=c.get("signer") or "", start=start,
                 pid=_int(c.get("pid")), ppid=_int(c.get("parent")))


# A container's program file lives in the container's filesystem, so from the host it looks deleted
# (measured 2026-10-13: every process of a local Jitsi stack reported on_disk=0).
CONTAINER = re.compile(r"docker|containerd|libpod|kubepods|/lxc/|machine\.slice", re.IGNORECASE)


SECRET = re.compile(r"(?i)(\b(?:token|secret|password|passwd|pass|key|auth|bearer|api[_-]?key|sig)[=: ]+)\S+"
                    r"|\b[A-Za-z0-9+/=_-]{32,}\b")


def redact(cmd: str, limit: int = 240) -> str:
    """A command line with anything secret-looking masked, for local case facts only (never sent to Jev)."""
    out = SECRET.sub(lambda m: (m.group(1) or "") + "<redacted>", cmd)
    return out if len(out) <= limit else out[:limit] + "..."


# What makes a program on the PC look suspicious or ordinary. Code decides; Jev only reads the outcome.
SUSPICIOUS_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/")
SUSPICIOUS_CMD = re.compile(r"(curl|wget)[^|;]*\|\s*(ba|z|da)?sh\b|base64\s+(-d|--decode)|/dev/tcp/|\bnc\b.*\s-e\s"
                            r"|\bbash\s+-i\b|mkfifo|-enc(odedcommand)?\s|python[0-9.]*\s+-c\s.*socket", re.IGNORECASE)
SYSTEM_DIRS = ("/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/libexec/", "/usr/share/", "/usr/local/bin/", "/bin/",
               "/sbin/", "/lib/", "/opt/", "/snap/")
USER_TOOL_DIRS = ("/.local/share/claude/", "/.local/bin/", "/.nvm/", "/.vscode-server/", "/.cursor-server/",
                  "/.cargo/bin/", "/.pyenv/", "/.rustup/", "/.venv/bin/", "/node_modules/.bin/")


# Windows (paths compared lower-case with forward slashes).
WIN_SUSPICIOUS_DIRS = ("/appdata/local/temp/", "c:/windows/temp/", "c:/users/public/", "/$recycle.bin/", "c:/perflogs/")
WIN_INSTALLED_DIRS = ("c:/windows/system32/", "c:/windows/syswow64/", "c:/program files/", "c:/program files (x86)/",
                      "c:/windows/systemapps/", "c:/program files/windowsapps/")
WIN_USER_INSTALL_DIRS = ("/appdata/local/programs/",)  # per-user installs (Signal, VS Code, ...): need a signature
# Built-in Windows tools attackers use to download, proxy-execute or bypass controls (LOLBins). A browser
# or app connecting out is normal; these connecting out on their own is not.
WIN_LOLBINS = {"rundll32.exe", "regsvr32.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe", "msbuild.exe",
               "installutil.exe", "cmstp.exe", "wmic.exe", "regasm.exe", "regsvcs.exe", "cscript.exe", "wscript.exe",
               "odbcconf.exe", "msxsl.exe", "ieexec.exe", "presentationhost.exe", "forfiles.exe"}
WIN_SUSPICIOUS_CMD = re.compile(r"frombase64string|downloadstring|downloadfile|invoke-webrequest.*\|\s*iex|\biex\s*\("
                                r"|\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}", re.IGNORECASE)
# Common in legitimate installers and scheduled scripts (measured: tapwatch's own installer), so only "unclear".
WIN_UNUSUAL_CMD = re.compile(r"-w(indowstyle)?\s+hidden|-(ep|executionpolicy)\s+bypass", re.IGNORECASE)
WIN_SHELLS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
              "regsvr32.exe", "bitsadmin.exe", "certutil.exe"}
WIN_DOC_APPS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe",
                "mspub.exe", "acrord32.exe", "acrobat.exe", "foxitpdfreader.exe", "hxoutlook.exe", "olk.exe"}
WIN_PSEUDO = {"[system process]", "system", "registry", "memory compression"}  # not programs
# Programs that make DNS lookups for others: WSL's DNS proxy answers every Linux lookup through Windows.
DNS_PROXIES = {"wslservice.exe"}
DNS_FOLLOW = 30               # a lookup belongs to the program that connects to its answer within 30 s


def _windows_signals(o: Owner, path: str, bad: list, good: list, unclear: list) -> None:
    name = o.name.lower()
    if any(d in path for d in WIN_SUSPICIOUS_DIRS):
        bad.append(f"{o.name} runs from a temporary or shared folder")
    if name in WIN_LOLBINS:
        bad.append(f"{o.name} is a built-in Windows tool often abused to download or run code, and it connected out")
    if o.cmdline and WIN_SUSPICIOUS_CMD.search(o.cmdline):
        bad.append(f"{o.name}'s command line is encoded, hidden or downloads-and-runs")
    if sus := [CMD_SUSPICIOUS[f] for f in o.cmd_flags if f in CMD_SUSPICIOUS]:
        bad.append(f"{o.name}'s command line has " + " and ".join(sus))
    if o.signature in ("invalid", "distrusted", "untrusted"):
        bad.append(f"{o.name}'s code signature is {o.signature}")
    if name in WIN_SHELLS and o.parent.lower() in WIN_DOC_APPS:
        bad.append(f"{o.name} was started by {o.parent}, a document or mail app")
    if bad:
        return
    if (o.cmdline and WIN_UNUSUAL_CMD.search(o.cmdline)) or any(f in CMD_UNUSUAL for f in o.cmd_flags):
        unclear.append(f"{o.name} runs hidden or bypasses PowerShell's execution policy")
        return
    if not path:
        unclear.append(f"couldn't see where {o.name} runs from (a system service; the agent's own log has it)")
        return
    if o.signature == "trusted":
        good.append(f"{o.name} is signed by {o.signer or 'a trusted publisher'}")
    elif path.startswith(WIN_INSTALLED_DIRS):
        good.append(f"{o.name} is an installed program ({path.rsplit('/', 1)[0]})")
    elif any(d in path for d in WIN_USER_INSTALL_DIRS):
        unclear.append(f"{o.name} is installed for one user, but its signature couldn't be checked" if not o.signature
                       else f"{o.name} is installed for one user, but isn't code-signed")
    elif "/downloads/" in path:
        unclear.append(f"{o.name} runs from a Downloads folder")
    elif o.signature == "missing":
        unclear.append(f"{o.name} isn't code-signed")


def assess(owners: list[Owner], who: str, programs: list[str] | None = None) -> tuple[str, list[str]]:
    """(assessment, signals): likely_benign / suspicious / unclear, from what ran on the PC.

    `programs` is the case's listed programs (`host_programs`, the three most frequent). Every owner still
    counts for the verdict, but the "X is signed by Y" / "X is an installed program" signals are shown only
    for those, so a fourth or fifth program the case page never names doesn't clutter them. Suspicious signals
    are always shown, whoever they're about."""
    if not owners:
        return "unclear", ["no program on the PC could be tied to the connection"]
    owners = [o for o in owners if o.name.lower() not in WIN_PSEUDO]
    with_path = {o.name for o in owners if o.path}
    owners = [o for o in owners if o.path or o.name not in with_path]  # prefer the row that knows the path
    if not owners:
        return "unclear", ["only Windows pseudo-processes held the connection"]
    bad, bad_or_unclear = [], []
    good: dict[str, list[str]] = {}  # program -> its benign signals
    for o in owners:
        path, og = o.path or "", good.setdefault(o.name, [])
        if re.match(r"^[a-z]:\\", path, re.IGNORECASE) or o.name.lower().endswith(".exe"):   # a Windows process
            ob = []
            _windows_signals(o, path.replace("\\", "/").lower(), ob, og, bad_or_unclear)
            bad += ob
            continue
        if path.startswith(SUSPICIOUS_DIRS):
            bad.append(f"{o.name} runs from a temporary folder")
        if o.on_disk == "0" and o.container is False:
            bad.append(f"{o.name}'s program file was deleted after it started")
        elif o.on_disk == "0" and o.container is None:
            bad_or_unclear.append(f"{o.name}'s program file isn't on disk (deleted, or inside a container)")
        if o.cmdline and SUSPICIOUS_CMD.search(o.cmdline):
            bad.append(f"{o.name}'s command line downloads-and-runs or opens a raw shell")
        if path.startswith(SYSTEM_DIRS):
            og.append(f"{o.name} is an installed program ({path.rsplit('/', 1)[0]})")
        elif any(d in path for d in USER_TOOL_DIRS):
            og.append(f"{o.name} is a user-installed tool")
    if who == "agent_misused":
        bad.append("a coding agent did this without the owner asking")
    if bad:
        return "suspicious", sorted(set(bad))
    if bad_or_unclear:
        return "unclear", sorted(set(bad_or_unclear))
    shown = sorted({s for name, sigs in good.items() if programs is None or name in programs for s in sigs})
    if who == "owner_using_agent":
        return "likely_benign", ["the owner's coding agent did this at the owner's request", *shown]
    if who == "agent_unconfirmed":
        return "unclear", ["a coding agent did this; the owner didn't name the destination", *shown]
    if all(good.values()):  # every program has something in its favour
        return "likely_benign", shown
    return "unclear", shown or ["the program isn't in an installed location"]


@dataclass
class OwnerIndex:
    """(remote address, port) -> processes that held a connection there."""

    by_remote: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    lookups: dict = field(default_factory=dict)   # Sysmon 22: query name -> [Owner]
    procs: dict = field(default_factory=dict)     # Sysmon 1: ProcessGuid -> (command line, parent path)
    by_ip: dict | None = None                     # remote address -> owners, built on first who_ip
    execs: dict = field(default_factory=dict)     # eBPF exec: pid -> (parent pid, path, time), the latest per pid
    markers: dict = field(default_factory=dict)   # pid -> an Owner seen with Claude markers (the long-lived agent)
    agents: dict = field(default_factory=dict)    # pid -> an Owner whose program is the agent itself, markers or not

    def who_dns(self, query: str, ts: float, answers=()) -> tuple[list[Owner], bool]:
        """Programs that looked up `query` around `ts`, and whether that's inferred. Sysmon event 22 names the
        program directly, unless it's a DNS proxy (WSL's). Otherwise: whoever connected to one of the answers
        right after, which covers Linux programs and resolvers that skip Windows (Chrome's own)."""
        named = [o for o in self.lookups.get(query.lower().rstrip("."), ())
                 if abs(o.start - ts) <= SLACK and o.name.lower() not in DNS_PROXIES]
        if named:
            return named, False
        followed = [o for ip in answers if isinstance(ip, str) for o in self.who_ip(ip, ts, DNS_FOLLOW)]
        return followed, bool(followed)

    def who_ip(self, remote: str, ts: float, within: float) -> list[Owner]:
        """Processes that connected to `remote`, any port, from `ts` to `ts + within`."""
        if self.by_ip is None:
            self.by_ip = {}
            for (addr, _port), owners in self.by_remote.items():
                self.by_ip.setdefault(addr, []).extend(owners)
        out = []
        for o in self.by_ip.get(remote, ()):
            if o.start and o.end == o.start:  # an event (Sysmon, eBPF): the connect itself must follow the lookup
                hit = ts - 2 <= o.start <= ts + within
            else:                              # a snapshot interval: held open around then
                hit = o.start - SLACK <= ts + within and (o.end is None or ts <= o.end + SLACK)
            if hit:
                out.append(o)
        return out

    def _sysmon(self, c: dict, fallback_ts: float) -> None:
        eid, guid, path = str(c.get("eventid", "")), c.get("guid") or "", c.get("path") or ""
        ts = _sysmon_ts(c.get("utc")) or fallback_ts
        if eid == "1":
            flags = tuple(k for k in (*CMD_SUSPICIOUS, *CMD_UNUSUAL, "url") if str(c.get(f"cmd_{k}", "0")) == "1")
            self.procs[guid] = (c.get("cmdline") or "", c.get("parent_path") or "", flags)
            return
        o = Owner(name=_basename(path) or "?", path=path, start=ts, end=ts, guid=guid)
        if eid == "3":
            self.add(c.get("remote_address", ""), c.get("remote_port"), o)
        elif eid == "22" and c.get("query"):
            self.lookups.setdefault(str(c["query"]).lower().rstrip("."), []).append(o)

    def resolve(self) -> None:
        """Give Sysmon-attributed owners their command line and parent from the process-start event, and
        marker-less eBPF owners the markers of their nearest marker-bearing ancestor."""
        for owners in (*self.by_remote.values(), *self.lookups.values()):
            for o in owners:
                if o.guid and o.guid in self.procs and not o.cmdline:
                    cmdline, parent, flags = self.procs[o.guid]
                    o.cmdline, o.parent, o.cmd_flags = redact(cmdline), _basename(parent), flags
                elif o.pid and not o.session and o.start:
                    self._inherit(o)

    def _exec(self, c: dict) -> None:
        pid = _int(c.get("pid"))
        if not pid:
            return
        self.execs.pop(pid, None)  # re-insert so the dict stays in time order for trimming
        self.execs[pid] = (_int(c.get("parent")), c.get("path") or "", float(c.get("time") or 0))
        if len(self.execs) > EXEC_KEEP:
            for old in list(self.execs)[: EXEC_KEEP // 10]:
                del self.execs[old]

    def _inherit(self, o: Owner) -> None:
        """Walk pid -> parent from the connection's process until an ancestor with markers (a `claude` process
        that is still running and connects out itself, so its own rows carry them). osquery reads
        /proc/<pid>/environ at query time: a one-second `curl` has exited by then, and so has the `bash -c` that
        ran it, so both the markers and parent_name come back empty (measured 2026-10-15, case #259). The exec
        events still hold each pid's parent. An exec logged after the connection is a reused pid: stop there."""
        cur = o.ppid or self._parent_of(o.pid, o.start)
        if not o.parent and cur:
            o.parent = self._name_of(cur, o.start)
        seen: set[int] = set()
        while cur and cur not in seen and len(seen) < CHAIN_MAX:
            seen.add(cur)
            anc = self._markers_of(cur, o.start) or self._agent_of(cur, o.start)
            if anc is not None:
                o.session, o.attended, o.entrypoint = anc.session, anc.attended, anc.entrypoint
                o.in_herdr, o.via_ssh, o.inherited = anc.in_herdr, anc.via_ssh, True
                o.agent = anc.name if anc.name in AGENT_BINARIES else ""
                return
            if self._name_of(cur, o.start) in AGENT_BINARIES:
                # The agent's exec row names it, but its connection rows are logged under its threads' ids, so
                # the main pid has no marker or agent row of its own (measured 2026-10-17, case #413: the chain
                # curl -> bash -> claude 4622 -> bash -> herdr ended at a pid with only an exec row, and the
                # agent's 59 connection rows that half hour sat under two thread ids). The exec path is proof
                # enough that an agent ran the chain; the session and attendance stay unknown, as for _agent_of.
                o.agent, o.inherited = self._name_of(cur, o.start), True
                return
            cur = self._parent_of(cur, o.start)

    def _exec_of(self, pid: int, before: float) -> tuple[int, str, float] | None:
        """The exec that made `pid` the process it was at `before`; None if the only exec known came later (a
        reused pid) or none was logged (a process older than the log window, such as a long-running agent)."""
        row = self.execs.get(pid)
        return row if row and row[2] <= before + 1 else None

    def _parent_of(self, pid: int, before: float) -> int:
        row = self._exec_of(pid, before)
        return row[0] if row else 0

    def _markers_of(self, pid: int, before: float) -> Owner | None:
        """`pid`'s marker-bearing row, if it belongs to the process that held the pid at `before`. With an exec
        logged for the pid, the markers must have been read after it (a live row is "now", so always after) and
        the exec must precede the connection; otherwise a pid reused after an agent exited would borrow the
        dead agent's session."""
        return self._held_by(self.markers.get(pid), pid, before)

    def _agent_of(self, pid: int, before: float) -> Owner | None:
        """`pid`'s row as the agent binary itself, markers or not, under the same reuse rule. Measured
        2026-10-16 (#376): the shell under a `claude` process is spawned by one of its threads, osquery's eBPF
        rows carry that thread id as `pid`/`parent`, and process_envs has no row for a thread, so the agent's
        484 connection rows that day all had empty markers. The binary's name is proof enough that an agent
        ran the chain; which session is left to the transcript."""
        return self._held_by(self.agents.get(pid), pid, before)

    def _held_by(self, anc: Owner | None, pid: int, before: float) -> Owner | None:
        if anc is None:
            return None
        row = self.execs.get(pid)
        if row and (row[2] > before + 1 or 0 < anc.start < row[2] - 1):
            return None
        return anc

    def _name_of(self, pid: int, before: float) -> str:
        row = self._exec_of(pid, before)
        if row and row[1]:
            return _name({"name": _basename(row[1]), "path": row[1]})  # Claude's binary is named after its version
        anc = self._markers_of(pid, before)
        return anc.name if anc else ""

    def add(self, remote: str, port, owner: Owner) -> None:
        self.by_ip = None
        if owner.pid and owner.session and not owner.inherited:
            self.markers[owner.pid] = owner
        if owner.pid and owner.name in AGENT_BINARIES and not owner.inherited:
            if len(self.agents) > AGENTS_KEEP:
                for old in list(self.agents)[: AGENTS_KEEP // 10]:
                    del self.agents[old]
            self.agents[owner.pid] = owner  # the latest row, as for markers: a reused pid belongs to the new process
        try:
            self.by_remote.setdefault((remote, int(port)), []).append(owner)
        except (TypeError, ValueError):
            pass

    def who(self, remote: str, port: int, ts: float, duration: float = 0.0) -> list[Owner]:
        out = []
        for o in self.by_remote.get((remote, int(port)), ()):
            if not o.start or (o.start - SLACK <= ts + duration and (o.end is None or ts <= o.end + SLACK)):
                out.append(o)
        return out

    def read_log(self, path: Path, since: float) -> None:
        """osquery results log (JSON lines, differential): 'added' opens an interval, 'removed' closes it."""
        try:
            size = path.stat().st_size
            fh = path.open("rb")
        except FileNotFoundError:
            self.notes.append(f"{path}: not found (agent not installed?)")
            return
        except PermissionError:
            self.notes.append(f"{path}: not readable (the agent needs --logger_mode=0644)")
            return
        live: dict[tuple, Owner] = {}
        with fh:
            if size > LOG_TAIL:
                fh.seek(size - LOG_TAIL)
                fh.readline()
            for line in fh:
                if not any(q in line for q in QUERY_KEYS):  # skip other queries' rows without parsing them
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(rec, dict) or rec.get("name") not in QUERIES:
                    continue
                ts = float(rec.get("unixTime") or 0)
                if ts < since:
                    continue
                rows = rec.get("snapshot") if rec.get("action") == "snapshot" else [rec.get("columns") or {}]
                if rec["name"] == SYSMON:
                    for c in rows or ():
                        self._sysmon(c, ts)
                    continue
                if rec["name"] == PROCS:  # one row per exec(): pid -> parent, for the chain walk in resolve()
                    for c in rows or ():
                        self._exec(c)
                    continue
                if rec["name"] == BPF:  # one row per connect(): an instant, like Sysmon's
                    for c in rows or ():
                        if not c.get("path"):  # started before osqueryd: eBPF never saw it start (snapshots cover it)
                            continue
                        t = float(c.get("time") or ts)
                        c = {k: v for k, v in c.items() if v is not None}  # a gone process: container unknown
                        o = _owner({**c, "name": _basename(c.get("path") or "") or "?"}, t)
                        o.end = t
                        self.add(c.get("remote_address", ""), c.get("remote_port"), o)
                    continue
                for c in rows or ():
                    key = (c.get("remote_address"), c.get("remote_port"), c.get("pid"), c.get("name"))
                    if rec.get("action") == "removed":
                        if key in live:
                            live.pop(key).end = ts
                    elif key not in live:
                        live[key] = o = _owner(c, ts)
                        self.add(c.get("remote_address", ""), c.get("remote_port"), o)


def _basename(path: str) -> str:
    return path.replace("\\", "/").rsplit("/", 1)[-1]


def _sysmon_ts(utc) -> float:
    """Sysmon's UtcTime ("2026-10-14 11:22:33.123") as epoch seconds; 0 if missing or malformed."""
    try:
        return datetime.fromisoformat(str(utc)).replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return 0.0


def _epoch(stamp: str) -> float:
    try:
        return datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()
    except (ValueError, AttributeError):
        return 0.0


def _human_text(rec: dict) -> str | None:
    """The owner's own message in a transcript record, or None (tool results, meta, system)."""
    if rec.get("type") != "user" or rec.get("isMeta") or rec.get("toolUseResult") is not None:
        return None
    c = (rec.get("message") or {}).get("content")
    if isinstance(c, str):
        return c
    if isinstance(c, list):
        if any(isinstance(x, dict) and x.get("type") == "tool_result" for x in c):
            return None
        return " ".join(x.get("text", "") for x in c if isinstance(x, dict) and x.get("type") == "text")
    return None


def transcript_facts(path: Path, names: set[str], ts: float, ips: set[str] = frozenset()) -> dict:
    """What the session's transcript says about the case's destinations around `ts`.
    Tool calls and prompts are matched against the destination's `names`; the `ips` are used only when the
    case has no name at all, and `matched_by` ("name" | "ip") records which. Measured 2026-10-17 (#379):
    an address needle matched a transcript that mentioned a shared Cloudflare address, not the site."""
    matched_by = "name" if names else "ip"
    # addresses match whole: 10.0.0.1 must not match 10.0.0.10 or 110.0.0.1
    patterns = [re.compile(rf"(?<![\d.]){re.escape(ip)}(?![\d.])") for ip in ips] if not names else []

    def hit(text: str) -> bool:
        return any(n in text for n in names) if names else any(p.search(text) for p in patterns)
    prompts: list[tuple[float, str]] = []
    calls: list[tuple[float, str, str, str]] = []  # (time, tool name, input as lowercase JSON, command text)
    try:
        with path.open(errors="replace") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                t = _epoch(rec.get("timestamp", ""))
                if not t or t > ts + AFTER:
                    continue
                text = _human_text(rec)
                if text and text.strip():
                    prompts.append((t, text.lower()))
                    continue
                content = (rec.get("message") or {}).get("content") if rec.get("type") == "assistant" else None
                for c in content if isinstance(content, list) else ():
                    if isinstance(c, dict) and c.get("type") == "tool_use":
                        inp = c.get("input", {})
                        raw = inp.get("command") if isinstance(inp, dict) and isinstance(inp.get("command"), str) \
                            else json.dumps(inp)
                        calls.append((t, c.get("name", ""), json.dumps(inp).lower(), raw))
    except OSError:
        return {"transcript": False}
    named = [c for c in calls if ts - BEFORE <= c[0] and hit(c[2])]
    facts: dict = {"transcript": True, "agent_named_dest": bool(named),
                   "agent_busy": any(abs(c[0] - ts) <= AFTER for c in calls)}
    if named:
        facts["agent_command"] = redact(named[-1][3])  # what the agent ran, for the case page (local only)
    anchor = named[-1][0] if named else ts
    before = [p for p in prompts if p[0] <= anchor]
    if before:
        p_ts, p_text = before[-1]
        facts["minutes_since_prompt"] = round((anchor - p_ts) / 60)
        facts["owner_named_dest"] = hit(p_text)
        facts["outside_content"] = any(
            p_ts <= c[0] <= anchor and (c[1] in OUTSIDE_TOOLS or (c[1].startswith("mcp__")
                                                                  and any(h in c[1].lower() for h in OUTSIDE_TOOL_HINTS)))
            for c in calls)
    if named or facts.get("owner_named_dest"):
        facts["matched_by"] = matched_by
    return facts


def verdict(owners: list[Owner], tf: dict, session_guessed: bool = False) -> tuple[str, bool]:
    """Code's own answer: (who, corroborated). corroborated = safe for the router to lower the case.
    `session_guessed`: the transcript came from a search, not a marker, so its web-content reading is not
    proof that *this* agent read outside content before acting."""
    if not owners:
        return "unknown", False
    agent = [o for o in owners if o.session or o.agent]
    if not agent:
        return "other_program", False
    if any(o.via_ssh or o.attended == "0" for o in agent):
        return "agent_misused", False  # an SSH login or an unattended session drove the agent
    if tf.get("outside_content") and not tf.get("owner_named_dest") and not session_guessed:
        return "agent_misused", False  # read web content, then acted on something the owner never named
    attended = all(o.attended == "1" and o.entrypoint == "cli" for o in agent)
    # Proof needs the owner to have named the destination. "The agent did it soon after a prompt" is not
    # enough: injected instructions can also arrive through files or tool output, which aren't tracked
    # as outside content. Measured 2026-10-13: a mid-task command 9 minutes after an unrelated prompt.
    if attended and tf.get("owner_named_dest"):
        return "owner_using_agent", True
    if tf.get("owner_named_dest") and all(o.agent and not o.session for o in agent):
        # The agent's binary ran the chain and the owner named the destination, but no marker reached, so the
        # session's attendance is unknown and its id is a guess from a transcript search. Measured 2026-10-16/17:
        # this is the path real cases take (84 with host context, 0 corroborated), because the markers live on
        # the agent's short-lived child shells, never on the claude process or its threads. The owner typing the
        # destination's name in their own prompt is stronger evidence that a person was there than a marker,
        # and a name match cannot be a shared-address coincidence (an address needle is only used when the case
        # has no name; #379 matched the wrong transcript through a shared Cloudflare address). So: corroborated
        # when the match was by name and the agent read no outside content first; the SSH and attended="0"
        # cases were already answered above. Attendance stays unknown and is reported as such.
        if tf.get("matched_by") == "name" and not tf.get("outside_content"):
            return "owner_using_agent", True
        return "owner_using_agent", False
    return "agent_unconfirmed", False


# osquery's authenticode table can't read some valid signatures ("The publisher information could not be
# found"; measured 2026-10-13 on Signal Desktop, which Windows reports as Valid). Ask Windows itself. Paths go
# in through an environment variable, never the command text, so a crafted file name can't inject PowerShell.
WIN_SIG_PS = (
    "foreach ($p in $env:TAPWATCH_SIG_PATHS -split '\\|') { $s = Get-AuthenticodeSignature -LiteralPath $p; "
    "$n = if ($s.SignerCertificate) { $s.SignerCertificate.GetNameInfo('SimpleName', $false) } else { '' }; "
    "[pscustomobject]@{path=$p; status=[string]$s.Status; signer=$n} | ConvertTo-Json -Compress }")
WIN_SIG_STATUS = {"Valid": "trusted", "NotSigned": "missing", "HashMismatch": "invalid", "NotTrusted": "untrusted"}
WIN_SIG_MAX = 8  # paths per case


def first_label(name: str | None) -> str:
    """A hostname's first label, lower-cased: `PC-ONE.lan` and `pc-one` are the same machine."""
    return (name or "").strip().split(".", 1)[0].lower()


class HostContext:
    def __init__(self, host: str, osquery_bin=None, results_logs=(), transcripts: str | None = None,
                 runner=subprocess.run, timeout: float = 20.0, powershell: str | None = None,
                 hostname: str | None = None):
        # One binary or several: on a Windows PC with WSL, both osqueryi (Linux processes) and
        # osqueryi.exe (Windows processes) answer for the same IP address.
        bins = osquery_bin if isinstance(osquery_bin, (list, tuple)) else [osquery_bin] if osquery_bin else []
        self.osquery_bins = [b for b in bins if b]
        self.osquery_bin = self.osquery_bins[0] if self.osquery_bins else None
        self.host, self.results_logs = host, [Path(p) for p in results_logs]
        # The PC's own name, to match against a case's DHCP hostname: an address alone can belong to another
        # device (a shared dock). Resolved here so tests can pass one; "" means unknown, and the name rule is off.
        self.hostname = first_label(hostname if hostname is not None else socket.gethostname())
        self._rejected: set[str] = set()   # DHCP names turned away on this PC's address, warned about once each
        self.transcripts = Path(transcripts).expanduser() if transcripts else Path.home() / ".claude/projects"
        self.runner, self.timeout = runner, timeout
        self.powershell, self._sigs = powershell, {}
        self._snaps: list[tuple[float, frozenset]] = []   # (time, addresses) from the agents' host_addresses
        self._addr_pos: dict[str, tuple[int, int]] = {}   # results log -> (inode, bytes read)

    def _snapshot_logs(self) -> list[Path]:
        logs = [p.with_name(p.name.replace("results", "snapshots")) for p in self.results_logs if "results" in p.name]
        return logs + self.results_logs  # some setups log snapshots with the rest

    def _read_addresses(self) -> None:
        """Pick up new host_addresses snapshots, reading only what was appended since. osquery's filesystem logger
        writes snapshot queries to osqueryd.snapshots.log, next to the results log."""
        for p in self._snapshot_logs():
            try:
                st = p.stat()
                fh = p.open("rb")
            except OSError:
                continue
            ino, pos = self._addr_pos.get(str(p), (None, 0))
            fresh = ino != st.st_ino or st.st_size < pos  # first read, or the log was rotated
            if fresh:
                pos = max(0, st.st_size - LOG_TAIL)
            with fh:
                fh.seek(pos)
                data = fh.read(max(0, st.st_size - pos))
            end = data.rfind(b"\n") + 1  # leave a half-written last line for next time
            start = data.find(b"\n") + 1 if fresh and pos else 0  # seeked into the middle of a line
            self._addr_pos[str(p)] = (st.st_ino, pos + end)
            for line in data[start:end].splitlines():
                if ADDR_KEY not in line:
                    continue
                try:
                    rec = json.loads(line)
                    rows = rec["snapshot"] if rec.get("name") == ADDRS else None
                    ts = float(rec.get("unixTime") or 0)
                except (ValueError, KeyError, TypeError, AttributeError):
                    continue
                if isinstance(rows, list) and ts:
                    self._snaps.append((ts, frozenset(r["address"] for r in rows
                                                      if isinstance(r, dict) and r.get("address"))))
        del self._snaps[:-ADDR_KEEP]

    def addresses_near(self, ts: float) -> set[str] | None:
        """The PC's addresses around `ts`, as its agents reported them; None when no agent reported then."""
        self._read_addresses()
        near = [a for t, a in self._snaps if abs(t - ts) <= ADDR_WINDOW]
        return set().union(*near) if near else None

    def is_this_pc(self, ip: str, ts: float, device_name: str | None = None) -> bool:
        """Was `ip` this PC at `ts`? The agents' reports win; the configured IP counts only without them.

        `device_name` is the DHCP hostname seen on that address. When it and the PC's own name are both known,
        they must match (first label, any case): the address can belong to another device. Measured 2026-10-16,
        case #373: the PC and a work laptop share a docking station, so the dock's MAC and DHCP address go to
        whichever machine is docked, and a lookup by the laptop's own security agent got the PC's programs
        attached. No DHCP name seen: the address rule alone, as before."""
        near = self.addresses_near(ts)
        if not (ip in near if near is not None else ip == self.host):
            return False
        name = first_label(device_name)
        if name and self.hostname and name != self.hostname:
            if name not in self._rejected and len(self._rejected) < REJECTED_NAMES_MAX:
                # Once per name: if it is this PC's own DHCP name (WSL with its own hostname, a DHCP client that
                # sends another name), every case here is losing host context, and the fix is a config line.
                self._rejected.add(name)
                log.warning("DHCP name %r on %s differs from this PC's name %r, so cases there get no host "
                            "context; if that is this PC, set host_context.hostname", name, ip, self.hostname)
            log.debug("%s is this PC's address but the DHCP name there is another device's: not this PC", ip)
            return False
        return True

    def config_mismatch(self, now: float | None = None) -> str | None:
        """A warning when the configured IP isn't one of the PC's addresses any more (DHCP moved it)."""
        near = self.addresses_near(now or time.time())
        if near is None or self.host in near:
            return None
        lan = sorted(a for a in near if is_internal(a) and ":" not in a) or sorted(near)
        return (f"host_context.host is {self.host}, but this PC is now {', '.join(lan[:4])}: tapwatch follows "
                "the PC's reported addresses, but set a fixed IP for it in the router and update config.yaml")

    def check_signatures(self, owners: list[Owner]) -> None:
        """Fill in Windows signatures osquery left empty, from PowerShell (cached per path)."""
        if not self.powershell:
            return
        todo = sorted({o.path for o in owners if not o.signature and re.match(r"^[a-z]:\\", o.path, re.IGNORECASE)}
                      - set(self._sigs))[:WIN_SIG_MAX]
        if todo:
            env = {**os.environ, "TAPWATCH_SIG_PATHS": "|".join(todo), "WSLENV": "TAPWATCH_SIG_PATHS"}
            try:
                res = self.runner([self.powershell, "-NoProfile", "-NonInteractive", "-Command", WIN_SIG_PS],
                                  capture_output=True, text=True, timeout=self.timeout, env=env)
                for line in res.stdout.splitlines():
                    r = json.loads(line)
                    self._sigs[r["path"]] = (WIN_SIG_STATUS.get(r.get("status"), ""), r.get("signer") or "")
            except (OSError, subprocess.TimeoutExpired, ValueError, KeyError, TypeError):
                pass
            for p in todo:
                self._sigs.setdefault(p, ("", ""))  # don't ask again for a file Windows couldn't answer for
        for o in owners:
            if not o.signature and o.path in self._sigs:
                o.signature, o.signer = self._sigs[o.path]

    def live(self) -> list[dict]:
        rows: list[dict] = []
        for b in self.osquery_bins:
            windows = b.lower().endswith(".exe")
            shell = ["-S"] if Path(b).name.startswith("osqueryd") else []  # osqueryd -S = osqueryi
            try:
                res = self.runner([b, *shell, "--disable_database", "--json", WIN_LIVE_SQL if windows else LIVE_SQL],
                                  capture_output=True, text=True, timeout=self.timeout)
                rows += json.loads(res.stdout) if res.returncode == 0 else []
            except (OSError, subprocess.TimeoutExpired, ValueError):
                continue
        return rows

    def index(self, since: float, live: bool = True) -> OwnerIndex:
        idx = OwnerIndex()
        for p in self.results_logs:
            idx.read_log(p, since)
        for c in self.live() if live else ():
            idx.add(c.get("remote_address", ""), c.get("remote_port"), _owner(c))
        idx.resolve()  # after the live rows: a running agent's live row can be the chain's marker-bearing end
        return idx

    def collect(self, case, conn_rows: list[dict], dns_rows: list[dict], now: float | None = None) -> dict:
        """host_* facts for a case on this PC (check is_this_pc first), from its Zeek conn/dns rows around the case time."""
        now = now or time.time()
        # Live sockets only describe "now": use them for fresh cases, never for a replay of old traffic.
        idx = self.index(since=case.ts - BEFORE - 3600, live=now - case.ts < LIVE_WINDOW)
        outbound = [r for r in conn_rows if r.get("id.orig_h") == case.host and not is_internal(r.get("id.resp_h", ""))
                    and isinstance(r.get("id.resp_p"), int)]
        owners: list[Owner] = []
        matched = 0
        for r in outbound:
            found = idx.who(r["id.resp_h"], r["id.resp_p"], r["ts"], float(r.get("duration") or 0))
            matched += bool(found)
            owners += found
        # DNS lookups the PC made, tied to the program that asked (Sysmon 22): what DNS-anomaly cases need.
        lookups = [r for r in dns_rows if r.get("id.orig_h") == case.host and r.get("query")]
        lookups_matched = 0
        lookups_followed = 0
        for r in lookups:
            found, followed = idx.who_dns(r["query"], r["ts"], r.get("answers") or ())
            lookups_matched += bool(found)
            lookups_followed += followed
            owners += found
        ips = {r["id.resp_h"] for r in outbound}
        names = set()
        for n in case.indicators:  # a bare-IP indicator (an HTTP Host header, an IP intel hit) is an address, not a name
            try:
                ips.add(str(ipaddress.ip_address(n.strip())))
            except ValueError:
                names.add(n.lower().rstrip("."))
        names |= {(r.get("query") or "").lower() for r in dns_rows if set(r.get("answers") or ()) & ips}
        # Names first; the addresses only when the case has no name at all (#379: a shared address matched
        # the wrong transcript). transcript_facts records which in `matched_by`.
        name_needles = {n for n in names | {base_domain(n) for n in names} if n and "." in n}
        sessions = sorted({o.session for o in owners if o.session})
        tf: dict = {}
        for sid in sessions[:3]:
            for path in glob.glob(str(self.transcripts / "*" / f"{sid}.jsonl")):
                tf = transcript_facts(Path(path), name_needles, case.ts, ips=ips)
                if tf.get("agent_named_dest"):
                    break
        transcript_only = False
        session_guessed = False
        agent_proof = any(o.agent for o in owners)  # the chain reached the agent binary, but no session marker
        if not sessions:  # no session id from a process: look at recent sessions, newest first
            stamped = [(Path(p).stat().st_mtime, p) for p in glob.glob(str(self.transcripts / "*" / "*.jsonl"))]
            recent = [p for m, p in sorted(stamped, reverse=True) if m >= case.ts - BEFORE][:20]
            for path in recent:
                found = transcript_facts(Path(path), name_needles, case.ts, ips=ips)
                if found.get("agent_named_dest"):
                    tf, transcript_only = found, not agent_proof
                    if agent_proof:  # process proof says an agent; the transcript that named it is the best guess
                        sessions, session_guessed = [Path(path).stem], True
                    break
        who, corroborated = verdict(owners, {} if transcript_only else tf, session_guessed)
        named = [o for o in owners if o.name.lower() not in WIN_PSEUDO]  # [System Process] etc. aren't programs
        programs = sorted({o.name for o in named}, key=lambda n: -sum(o.name == n for o in named))
        facts = {"host_who": who, "host_corroborated": corroborated, "host_conns": len(outbound),
                 "host_matched": matched, "host_lookups": len(lookups), "host_lookups_matched": lookups_matched,
                 "host_lookups_followed": lookups_followed,
                 "host_programs": programs[:3],
                 "host_agent_session": bool(sessions), "host_session": sessions[0] if sessions else "",
                 "host_attended": any(o.attended == "1" for o in owners if o.session),
                 "host_attended_known": any(o.attended in ("0", "1") for o in owners if o.session or o.agent),
                 "host_session_guessed": session_guessed,  # the id came from a transcript search, not a marker
                 "host_inherited": any(o.inherited for o in owners),  # credited through the exec parent chain
                 "host_via_ssh": any(o.via_ssh for o in owners), "host_in_terminal": any(o.in_herdr for o in owners),
                 "host_transcript_only": transcript_only}
        facts.update({f"host_{k}": v for k, v in tf.items()})
        self.check_signatures(owners)
        assessment, signals = assess(owners, who, programs[:3])
        facts["host_assessment"], facts["host_signals"] = assessment, signals[:4]
        paths = sorted({o.path for o in owners if o.path})
        if len(paths) == 1:  # one program explains every matched connection: suppressions can key on it
            facts["host_program_path"] = paths[0]
            o = next(o for o in owners if o.path == paths[0])
            facts["host_parent"], facts["host_cmdline"] = o.parent, o.cmdline
        if assessment == "suspicious":
            facts["min_route"] = "alert"
        elif assessment == "likely_benign" and not corroborated:
            facts["host_max_route"] = "digest"  # its own key: never loosens a detector's stricter max_route
        if idx.notes:
            facts["host_notes"] = idx.notes[:2]
        return facts
