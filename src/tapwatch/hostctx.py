"""Host context: who on the tapwatch PC made a case's connections.

Network data can't tell the owner's coding agent from an attacker. On the PC that runs
tapwatch, osquery can. For a case on that PC, this module answers in code:

  * which program held the connection (a live osquery check, plus the agent's
    1-minute `outbound_connections_ctx` history for connections already closed)
  * whether a Claude Code session started it. That's read from environment markers
    (CLAUDE_CODE_SESSION_ID, CLAUDE_CODE_SESSION_ATTENDED, CLAUDE_CODE_ENTRYPOINT), which
    survive reparenting, unlike the parent chain. Also: started from the owner's Herdr
    terminal, or from an SSH login?
  * from that session's transcript (~/.claude/projects/*/<session>.jsonl): did the agent
    run a command naming this destination, did the owner's prompt name it, and did
    the agent read outside web content between the prompt and the command (the
    prompt-injection pattern)?

The answers become case facts (`host_*`). Jev reads them as plain sentences and picks
between "owner using the agent", "agent misused" and "other program"; the router only
lets that lower a case when the code facts back it up. No transcript text, session
id, path or command line ever leaves the PC: only the yes/no facts and minutes do.

Works on Linux/WSL and macOS (osquery's process_envs). Windows processes get names
from the Windows agent's log but no Claude markers. Other devices need Fleet.
"""

from __future__ import annotations

import glob
import json
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .detectors import base_domain, is_internal

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
QUERIES = ("outbound_connections", "outbound_connections_ctx")
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


VERSION_NAME = re.compile(r"^\d+(\.\d+)+$")


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
                 signature=(c.get("signature") or "").lower(), signer=c.get("signer") or "", start=start)


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
WIN_PSEUDO = {"[system process]", "system", "registry", "memory compression"}  # not programs


def _windows_signals(o: Owner, path: str, bad: list, good: list, unclear: list) -> None:
    name = o.name.lower()
    if any(d in path for d in WIN_SUSPICIOUS_DIRS):
        bad.append(f"{o.name} runs from a temporary or shared folder")
    if name in WIN_LOLBINS:
        bad.append(f"{o.name} is a built-in Windows tool often abused to download or run code, and it connected out")
    if o.cmdline and WIN_SUSPICIOUS_CMD.search(o.cmdline):
        bad.append(f"{o.name}'s command line is encoded, hidden or downloads-and-runs")
    if o.signature in ("invalid", "distrusted", "untrusted"):
        bad.append(f"{o.name}'s code signature is {o.signature}")
    if bad:
        return
    if o.cmdline and WIN_UNUSUAL_CMD.search(o.cmdline):
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


def assess(owners: list[Owner], who: str) -> tuple[str, list[str]]:
    """(assessment, signals): likely_benign / suspicious / unclear, from what ran on the PC."""
    if not owners:
        return "unclear", ["no program on the PC could be tied to the connection"]
    owners = [o for o in owners if o.name.lower() not in WIN_PSEUDO]
    with_path = {o.name for o in owners if o.path}
    owners = [o for o in owners if o.path or o.name not in with_path]  # prefer the row that knows the path
    if not owners:
        return "unclear", ["only Windows pseudo-processes held the connection"]
    bad, good, bad_or_unclear = [], [], []
    for o in owners:
        path = o.path or ""
        if re.match(r"^[a-z]:\\", path, re.IGNORECASE) or o.name.lower().endswith(".exe"):   # a Windows process
            ob, og = [], []
            _windows_signals(o, path.replace("\\", "/").lower(), ob, og, bad_or_unclear)
            bad += ob
            good += og
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
            good.append(f"{o.name} is an installed program ({path.rsplit('/', 1)[0]})")
        elif any(d in path for d in USER_TOOL_DIRS):
            good.append(f"{o.name} is a user-installed tool")
    if who == "agent_misused":
        bad.append("a coding agent did this without the owner asking")
    if bad:
        return "suspicious", sorted(set(bad))
    if bad_or_unclear:
        return "unclear", sorted(set(bad_or_unclear))
    if who == "owner_using_agent":
        return "likely_benign", ["the owner's coding agent did this at the owner's request", *sorted(set(good))]
    if who == "agent_unconfirmed":
        return "unclear", ["a coding agent did this; the owner didn't name the destination", *sorted(set(good))]
    if good and len(good) >= len({o.name for o in owners}):
        return "likely_benign", sorted(set(good))
    return "unclear", sorted(set(good)) or ["the program isn't in an installed location"]


@dataclass
class OwnerIndex:
    """(remote address, port) -> processes that held a connection there."""

    by_remote: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def add(self, remote: str, port, owner: Owner) -> None:
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
                for c in rows or ():
                    key = (c.get("remote_address"), c.get("remote_port"), c.get("pid"), c.get("name"))
                    if rec.get("action") == "removed":
                        if key in live:
                            live.pop(key).end = ts
                    elif key not in live:
                        live[key] = o = _owner(c, ts)
                        self.add(c.get("remote_address", ""), c.get("remote_port"), o)


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


def transcript_facts(path: Path, needles: set[str], ts: float) -> dict:
    """What the session's transcript says about the case's destinations around `ts`."""
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
    named = [c for c in calls if ts - BEFORE <= c[0] and any(n in c[2] for n in needles)]
    facts: dict = {"transcript": True, "agent_named_dest": bool(named),
                   "agent_busy": any(abs(c[0] - ts) <= AFTER for c in calls)}
    if named:
        facts["agent_command"] = redact(named[-1][3])  # what the agent ran, for the case page (local only)
    anchor = named[-1][0] if named else ts
    before = [p for p in prompts if p[0] <= anchor]
    if before:
        p_ts, p_text = before[-1]
        facts["minutes_since_prompt"] = round((anchor - p_ts) / 60)
        facts["owner_named_dest"] = any(n in p_text for n in needles)
        facts["outside_content"] = any(
            p_ts <= c[0] <= anchor and (c[1] in OUTSIDE_TOOLS or (c[1].startswith("mcp__")
                                                                  and any(h in c[1].lower() for h in OUTSIDE_TOOL_HINTS)))
            for c in calls)
    return facts


def verdict(owners: list[Owner], tf: dict) -> tuple[str, bool]:
    """Code's own answer: (who, corroborated). corroborated = safe for the router to lower the case."""
    if not owners:
        return "unknown", False
    agent = [o for o in owners if o.session]
    if not agent:
        return "other_program", False
    if any(o.via_ssh or o.attended == "0" for o in agent):
        return "agent_misused", False  # an SSH login or an unattended session drove the agent
    if tf.get("outside_content") and not tf.get("owner_named_dest"):
        return "agent_misused", False  # read web content, then acted on something the owner never named
    attended = all(o.attended == "1" and o.entrypoint == "cli" for o in agent)
    # Proof needs the owner to have named the destination. "The agent did it soon after a prompt" is not
    # enough: injected instructions can also arrive through files or tool output, which aren't tracked
    # as outside content. Measured 2026-10-13: a mid-task command 9 minutes after an unrelated prompt.
    if attended and tf.get("owner_named_dest"):
        return "owner_using_agent", True
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


class HostContext:
    def __init__(self, host: str, osquery_bin=None, results_logs=(), transcripts: str | None = None,
                 runner=subprocess.run, timeout: float = 20.0, powershell: str | None = None):
        # One binary or several: on a Windows PC with WSL, both osqueryi (Linux processes) and
        # osqueryi.exe (Windows processes) answer for the same IP address.
        bins = osquery_bin if isinstance(osquery_bin, (list, tuple)) else [osquery_bin] if osquery_bin else []
        self.osquery_bins = [b for b in bins if b]
        self.osquery_bin = self.osquery_bins[0] if self.osquery_bins else None
        self.host, self.results_logs = host, [Path(p) for p in results_logs]
        self.transcripts = Path(transcripts).expanduser() if transcripts else Path.home() / ".claude/projects"
        self.runner, self.timeout = runner, timeout
        self.powershell, self._sigs = powershell, {}

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
        return idx

    def collect(self, case, conn_rows: list[dict], dns_rows: list[dict], now: float | None = None) -> dict:
        """host_* facts for a case on this PC, from its Zeek conn/dns rows around the case time."""
        now = now or time.time()
        # Live sockets only describe "now": use them for fresh cases, never for a replay of old traffic.
        idx = self.index(since=case.ts - BEFORE - 3600, live=now - case.ts < LIVE_WINDOW)
        outbound = [r for r in conn_rows if r.get("id.orig_h") == self.host and not is_internal(r.get("id.resp_h", ""))
                    and isinstance(r.get("id.resp_p"), int)]
        owners: list[Owner] = []
        matched = 0
        for r in outbound:
            found = idx.who(r["id.resp_h"], r["id.resp_p"], r["ts"], float(r.get("duration") or 0))
            matched += bool(found)
            owners += found
        ips = {r["id.resp_h"] for r in outbound}
        names = {n.lower().rstrip(".") for n in case.indicators}
        names |= {(r.get("query") or "").lower() for r in dns_rows if set(r.get("answers") or ()) & ips}
        needles = {n for n in names | {base_domain(n) for n in names} if n and "." in n} | ips
        sessions = sorted({o.session for o in owners if o.session})
        tf: dict = {}
        for sid in sessions[:3]:
            for path in glob.glob(str(self.transcripts / "*" / f"{sid}.jsonl")):
                tf = transcript_facts(Path(path), needles, case.ts)
                if tf.get("agent_named_dest"):
                    break
        transcript_only = False
        if not sessions:  # no process proof (osquery missing, or too short to see): look at recent sessions
            recent = [p for p in glob.glob(str(self.transcripts / "*" / "*.jsonl"))
                      if Path(p).stat().st_mtime >= case.ts - BEFORE][:20]
            for path in recent:
                found = transcript_facts(Path(path), needles, case.ts)
                if found.get("agent_named_dest"):
                    tf, transcript_only = found, True
                    break
        who, corroborated = verdict(owners, {} if transcript_only else tf)
        programs = sorted({o.name for o in owners}, key=lambda n: -sum(o.name == n for o in owners))
        facts = {"host_who": who, "host_corroborated": corroborated, "host_conns": len(outbound),
                 "host_matched": matched, "host_programs": programs[:3],
                 "host_agent_session": bool(sessions), "host_session": sessions[0] if sessions else "",
                 "host_attended": any(o.attended == "1" for o in owners if o.session),
                 "host_via_ssh": any(o.via_ssh for o in owners), "host_in_terminal": any(o.in_herdr for o in owners),
                 "host_transcript_only": transcript_only}
        facts.update({f"host_{k}": v for k, v in tf.items()})
        self.check_signatures(owners)
        assessment, signals = assess(owners, who)
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
