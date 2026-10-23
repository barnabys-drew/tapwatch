"""`tapwatch doctor`: check every piece of an install and say, in plain words, how to fix what isn't working.

Written for an owner who has never run a sensor before: each line is a part of the setup they can picture
(the capture, the mirror port, the router, the alerts), not a process name, and each failure carries the one
thing to do about it. Every problem the clean-machine test hit (#6) has a check here: a capture that stopped,
a mirror port that only shows this PC, the router not sending syslog, no alert channel, missing lists.

Three levels: ok, warn (works, but something is missing or optional is off), fail (tapwatch is not doing its
job). The exit code is 1 on any fail, so the Windows installer can run this last and stop on a broken step.

Nothing here changes anything or sends anything, except `--send`, which sends the same test alert as
`tapwatch test-alert`.
"""

from __future__ import annotations

import ipaddress
import json
import os
import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from . import config, service

OK, WARN, FAIL = "ok", "warn", "fail"
MARK = {OK: "[ok]  ", WARN: "[!]   ", FAIL: "[FAIL]"}
CONN_STALE = 600           # same as the watchdog: a busy network writes conn.log every few seconds
SYSLOG_STALE = 1800        # the listener writes a heartbeat row every 10 minutes it hears the router
AGENT_STALE = 900          # the agents' busiest queries run every minute
FEEDS_OLD_DAYS = 30
VULN_FEEDS_OLD_DAYS = 14   # KEV gains entries most weeks; an old copy misses the newest exploited bugs
TAIL_BYTES = 2_000_000     # enough recent conn.log for the mirror check without reading the whole file
SETTLING = 900             # services this new may not have written a log yet: a missing log is a note, not a failure


@dataclass
class Result:
    level: str
    part: str
    said: str
    fix: str = ""


def _run(cmd: list[str], timeout: float = 10) -> tuple[int, str]:
    try:
        # errors="replace": sc.exe and schtasks.exe answer in the OEM code page on a non-English Windows
        p = subprocess.run(cmd, check=False, capture_output=True, text=True, errors="replace", timeout=timeout)
        return p.returncode, p.stdout
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return -1, ""


def _age(p: Path, now: float) -> float | None:
    try:
        return now - p.stat().st_mtime
    except OSError:
        return None


def _mins(seconds: float) -> str:
    m = int(seconds // 60)
    return f"{m} min" if m < 120 else f"{m // 60} h"


# The long-running units `service install` creates. Others named tapwatch-* (a timer's one-shot job, say)
# are inactive between runs by design, so they aren't checked.
SERVICES = ("tapwatch-alerter", "tapwatch-ui", "tapwatch-watchdog", "tapwatch-capture", "tapwatch-syslog")


def installed_units(unit_dir: Path = service.UNIT_DIR) -> list[str]:
    return [u for u in SERVICES if (unit_dir / f"{u}.service").is_file()]


def zeek_dir_from_units(unit_dir: Path = service.UNIT_DIR) -> str | None:
    """The log directory `service install` gave the alerter, so `doctor` needs no arguments after an install.
    The unit quotes it with shlex.quote, so shlex.split undoes that, quotes inside the path included."""
    try:
        text = (unit_dir / "tapwatch-alerter.service").read_text()
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith("ExecStart="):
            try:
                words = shlex.split(line.removeprefix("ExecStart="))
            except ValueError:
                return None
            if "--zeek-dir" in words[:-1]:
                return words[words.index("--zeek-dir") + 1]
    return None


def units_age(units: list[str], now: float, unit_dir: Path = service.UNIT_DIR) -> float | None:
    """Seconds since `service install` last wrote the units: right after an install, logs may not exist yet."""
    ages = [a for u in units if (a := _age(unit_dir / f"{u}.service", now)) is not None]
    return min(ages) if ages else None


def tail_records(path: Path, limit: int = TAIL_BYTES) -> list[dict]:
    try:
        with path.open("rb") as fh:
            fh.seek(max(0, path.stat().st_size - limit))
            lines = fh.read().decode(errors="replace").splitlines()[1:]  # the first may be cut
    except OSError:
        return []
    out = []
    for ln in lines:
        try:
            rec = json.loads(ln)
        except json.JSONDecodeError:
            continue
        if isinstance(rec, dict):
            out.append(rec)
    return out


def lan_talkers(recs: list[dict], this_pc: set[str]) -> set[str]:
    """Private addresses that started connections, other than this PC: what only a mirror port shows."""
    seen = set()
    for r in recs:
        a = r.get("id.orig_h")
        if not a or a in this_pc:
            continue
        try:
            ip = ipaddress.ip_address(a)
        except ValueError:
            continue
        if ip.is_private and not (ip.is_loopback or ip.is_link_local or ip.is_multicast):
            seen.add(a)
    return seen


def check_setup(cfg_path: str) -> list[Result]:
    out = []
    if not Path(cfg_path).exists():
        return [Result(FAIL, "Setup", f"no {cfg_path} here", "run `tapwatch init` in this folder first")]
    env = Path(".env")
    if not env.exists():
        out.append(Result(WARN, "Setup", "no .env (alert addresses and keys live there)", "run `tapwatch init`"))
    elif env.stat().st_mode & 0o077:
        out.append(Result(WARN, "Setup", ".env can be read by other accounts on this machine", "chmod 600 .env"))
    else:
        out.append(Result(OK, "Setup", f"{cfg_path} and .env are here"))
    return out


def check_services(units: list[str], run=_run) -> list[Result]:
    if not units:
        return [Result(FAIL, "Services", "tapwatch isn't installed as a service, so it stops when this window closes",
                       "tapwatch service install --zeek-dir logs/zeek  (add --capture-iface and --syslog as needed)")]
    if run(["systemctl", "--user", "show-environment"])[0] != 0:
        return [Result(WARN, "Services", "can't reach your Linux services from here",
                       "run tapwatch doctor from an Ubuntu window")]
    down = [u for u in units if run(["systemctl", "--user", "is-active", "--quiet", u])[0] != 0]
    out = [Result(FAIL, "Services", f"not running: {', '.join(down)}",
                  f"systemctl --user restart {' '.join(down)}; if it stops again: journalctl --user -u {down[0]} -n 30")
           if down else Result(OK, "Services", f"all {len(units)} running ({', '.join(u.removeprefix('tapwatch-') for u in units)})")]
    user = os.environ.get("USER", "")
    if user and "Linger=yes" not in run(["loginctl", "show-user", user, "-p", "Linger"])[1]:
        out.append(Result(WARN, "Services", "they stop when you sign out of Linux", f"loginctl enable-linger {user}"))
    return out


def check_capture(zeek_dir: Path, this_pc: set[str], now: float, new: bool = False) -> list[Result]:
    conn = zeek_dir / "conn.log"
    age = _age(conn, now)
    if age is None and new:
        return [Result(WARN, "Capture", "just started: no traffic logged yet", "check again in 15 minutes: tapwatch doctor")]
    if age is None:
        return [Result(FAIL, "Capture", f"no traffic log yet in {zeek_dir}",
                       "check the capture: systemctl --user status tapwatch-capture (Windows: is Npcap installed "
                       "and the network adapter name right?)")]
    if age > CONN_STALE:
        return [Result(FAIL, "Capture", f"no new traffic for {_mins(age)}",
                       "systemctl --user restart tapwatch-capture; check the mirror cable is plugged in")]
    out = [Result(OK, "Capture", f"traffic logged {int(age)} s ago")]
    others = lan_talkers(tail_records(conn), this_pc)
    if not others:
        out.append(Result(WARN, "Mirror port", "only this PC's own traffic is seen, not the other devices",
                          "set the switch port this PC's capture adapter is plugged into to mirror the router's port "
                          "(docs/setup/mirror-port.md), and check --capture-iface names that adapter"))
    else:
        out.append(Result(OK, "Mirror port", f"seeing {len(others)} other device{'s' if len(others) != 1 else ''} on the network"))
    return out


def check_router(units: list[str], zeek_dir: Path, now: float, new: bool = False) -> list[Result]:
    if "tapwatch-syslog" not in units:
        return [Result(WARN, "Router", "router logs are off (optional: the router's own blocks and admin logins)",
                       "docs/setup/router-syslog.md, then tapwatch service install ... --syslog")]
    age = _age(zeek_dir / "udm.log", now)
    if age is None and new:  # the listener writes its first row when the router has spoken for 10 minutes
        return [Result(WARN, "Router", "just started: nothing from the router yet",
                       "set up the router's logs (docs/setup/router-syslog.md), then check again in 15 minutes")]
    if age is None or age > SYSLOG_STALE:
        when = "nothing has arrived" if age is None else f"nothing for {_mins(age)}"
        return [Result(FAIL, "Router", f"the router isn't sending its logs: {when}",
                       "in UniFi, set the SIEM/syslog server to this PC's address, port 5514; on Windows, add the two "
                       "firewall rules in docs/setup/router-syslog.md; on Linux with ufw: sudo ufw allow 5514/udp")]
    return [Result(OK, "Router", f"router logs arriving ({_mins(age)} ago)")]


def check_agents(cfg: dict, now: float) -> list[Result]:
    logs = (cfg.get("host_context") or {}).get("results_logs") or config.HOST_LOGS
    found = [Path(p) for p in logs if Path(p).is_file()]
    if not found:
        return [Result(WARN, "PC agent", "the endpoint agent isn't installed (optional: names the program behind "
                       "a connection, and the PC rules)", "agents/README.md: double-click agents\\install.cmd on Windows")]
    out = []
    for p in found:
        age = _age(p, now)
        if age is None or not os.access(p, os.R_OK):
            out.append(Result(FAIL, "PC agent", f"can't read {p}", "re-run the agent installer (agents/README.md)"))
        elif age > AGENT_STALE:
            out.append(Result(FAIL, "PC agent", f"{p} hasn't changed for {_mins(age)}",
                              "restart osquery (Windows: Restart-Service osqueryd in an admin PowerShell; "
                              "Linux: sudo systemctl restart osqueryd)"))
        else:
            out.append(Result(OK, "PC agent", f"{p} is up to date"))
    if not (cfg.get("host_context") or {}).get("host"):
        out.append(Result(WARN, "PC agent", "cases don't say which program made a connection (host context is off)",
                          "add to config.yaml:  host_context: {host: <this PC's IP>}"))
    return out


def check_alerts(cfg: dict) -> list[Result]:
    n = config.notifier(cfg)
    if not n:
        return [Result(FAIL, "Alerts", "no alert channel, so nothing will reach you",
                       "add TAPWATCH_NTFY_URL (or _DISCORD_URL, _TEAMS_URL, _WEBHOOK_URL) to .env, or re-run init")]
    return [Result(OK, "Alerts", f"alerts go to {', '.join(n.channels())} (tapwatch doctor --send sends a test)")]


def check_ai(cfg: dict) -> list[Result]:
    out = []
    t = cfg.get("typesafe") or {}
    if t.get("enabled", True) is False:
        out.append(Result(WARN, "AI", "AI triage is off (optional: the rules work alone)",
                          "TYPESAFE_API_KEY in .env and typesafe: {enabled: true} in config.yaml"))
    elif config.jev_client(cfg) is None:
        out.append(Result(FAIL, "AI", "AI triage is on but has no key", "add TYPESAFE_API_KEY to .env"))
    else:
        out.append(Result(OK, "AI", "AI triage has its key"))
    c = cfg.get("categories") or {}
    key_env = c.get("api_key_env", "ANTHROPIC_API_KEY")
    if c.get("ai") and not os.environ.get(key_env):
        out.append(Result(FAIL, "AI", "site categories are on but have no key", f"add {key_env} to .env"))
    return out


def check_feeds(cfg: dict, now: float) -> list[Result]:
    missing = config.missing_feeds(cfg)
    if missing:
        return [Result(FAIL, "Lists", "the public lists aren't downloaded, so the first days are much noisier",
                       "tapwatch update-feeds")]
    ages = [a for k in config.FEED_FILES if cfg.get(k) and (a := _age(Path(cfg[k]), now)) is not None]
    if ages and max(ages) > FEEDS_OLD_DAYS * 86400:
        return [Result(WARN, "Lists", f"the public lists are {int(max(ages) // 86400)} days old", "tapwatch update-feeds")]
    return [Result(OK, "Lists", "public lists downloaded")]


def check_vuln_feeds(cfg: dict, now: float) -> list[Result]:
    """The known-exploited data (#225). Only worth a line where an endpoint agent reports software."""
    if not (cfg.get("host_context") or {}).get("results_logs"):
        return []
    kev = Path(cfg.get("feeds_dir", "feeds")) / "kev.json"
    age = _age(kev, now)
    if age is None:
        return [Result(WARN, "Vuln data", "no known-exploited (KEV) list, so installed software isn't checked",
                       "tapwatch update-feeds")]
    days = int(age // 86400)
    if age > VULN_FEEDS_OLD_DAYS * 86400:
        return [Result(WARN, "Vuln data", f"the known-exploited list is {days} days old", "tapwatch update-feeds")]
    return [Result(OK, "Vuln data", f"known-exploited list {days} day{'s' if days != 1 else ''} old")]


def check_disk(path: Path) -> list[Result]:
    free = shutil.disk_usage(path).free / 1e9
    if free < 1:
        return [Result(FAIL, "Disk", f"{free:.1f} GB free", "free space; zeek_retention_days in config.yaml keeps less")]
    if free < 5:
        return [Result(WARN, "Disk", f"{free:.1f} GB free", "zeek_retention_days in config.yaml keeps less")]
    return [Result(OK, "Disk", f"{free:.0f} GB free")]


def check_windows(run=_run) -> list[Result]:
    """WSL only: the parts on the Windows side. Skipped elsewhere."""
    if not Path("/mnt/c/Windows").exists():
        return []
    out = []
    code, text = run(["/mnt/c/Windows/System32/sc.exe", "query", "npcap"])
    if code == -1:
        return []  # Windows interop is off; nothing to check from here
    out.append(Result(OK, "Windows", "Npcap is running") if "RUNNING" in text else
               Result(FAIL, "Windows", "Npcap isn't running, so nothing can be captured",
                      "install Npcap from https://npcap.com (docs/setup/windows.md, step 4)"))
    code, _ = run(["/mnt/c/Windows/System32/schtasks.exe", "/query", "/tn", "tapwatch keep-alive"])
    out.append(Result(OK, "Windows", "keep-alive task is set up") if code == 0 else
               Result(WARN, "Windows", "the PC may sleep and Linux may stop when nobody is signed in",
                      "set up keep-alive (docs/setup/windows.md, 'Keep it awake')"))
    return out


def capture_iface_from_units(unit_dir: Path = service.UNIT_DIR) -> str | None:
    """The mirror interface `service install --capture-iface` gave the capture unit (its last argument)."""
    try:
        text = (unit_dir / "tapwatch-capture.service").read_text()
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith("ExecStart="):
            try:
                words = shlex.split(line.removeprefix("ExecStart="))
            except ValueError:
                return None
            return words[-1] if len(words) >= 4 else None
    return None


SLEEP_TARGETS = ("sleep.target", "suspend.target", "hibernate.target", "hybrid-sleep.target")


def check_this_host(host: str | None, run=_run) -> list[Result]:
    """Whether `host_context.host` is this computer: a config moved from another computer (tapwatch import-state)
    still names that one, and cases about it would be explained with this one's programs. WSL in mirrored mode
    lists Windows' own addresses; in NAT mode it only has its 172.x address, so nothing is concluded there."""
    try:
        want = ipaddress.ip_address(str(host or ""))
    except ValueError:
        return []
    words = run(["ip", "-o", "addr", "show", "scope", "global"])[1].split()
    mine = set()
    for i, w in enumerate(words[:-1]):
        if w in ("inet", "inet6"):
            try:
                mine.add(ipaddress.ip_address(words[i + 1].split("/")[0]))
            except ValueError:
                continue
    # WSL in NAT mode has only its own 172.16/12 address (and WSL's DNS proxy, 10.255.255.254): an office LAN in
    # 172.16/12 counts once another address shows this is mirrored mode or a plain Linux host.
    wsl_nat = ipaddress.ip_network("172.16.0.0/12")
    v4 = {a for a in mine if a.version == 4 and str(a) != "10.255.255.254"}
    if not v4 or all(a in wsl_nat for a in v4) and want not in wsl_nat or want in mine:
        return []
    return [Result(WARN, "PC agent", f"host_context.host is {host}, which isn't this computer, so cases about that "
                   "one would be explained with this one's programs",
                   "in config.yaml set host_context: {host: <this computer's IP>}, then restart tapwatch")]


def check_linux_host(units: list[str], run=_run, unit_dir: Path = service.UNIT_DIR,
                     sys_net: Path = Path("/sys/class/net"), wsl: bool | None = None) -> list[Result]:
    """A Linux host capturing the mirror itself (deploy/omarchy/install.sh): the parts the Windows side covers on
    WSL. The mirror NIC, dumpcap's permission to capture, and sleep. Skipped on WSL and without a capture unit."""
    if (Path("/mnt/c/Windows").exists() if wsl is None else wsl) or "tapwatch-capture" not in units:
        return []
    out = []
    iface = capture_iface_from_units(unit_dir)
    if not iface:
        return out
    state = None
    try:
        state = (sys_net / iface / "operstate").read_text().strip()
    except OSError:
        out.append(Result(FAIL, "Mirror NIC", f"there is no network interface named {iface}",
                          "ip -br link lists them; then tapwatch service install ... --capture-iface <name>"))
    if state is not None:
        if state not in ("up", "unknown"):
            out.append(Result(FAIL, "Mirror NIC", f"{iface} is {state}: no link",
                              "check the cable from this computer to the switch's mirror port"))
        elif run(["ip", "-o", "addr", "show", "dev", iface, "scope", "global"])[1].strip():
            out.append(Result(WARN, "Mirror NIC", f"{iface} has an IP address; the mirror port should have none",
                              "run deploy/omarchy/install.sh again, or tell the network manager to leave it alone"))
        else:
            out.append(Result(OK, "Mirror NIC", f"{iface} is up with no address"))
    if os.geteuid() != 0 and "wireshark" not in run(["id", "-nG"])[1].split():
        out.append(Result(FAIL, "Capture", "this account can't capture (not in the wireshark group)",
                          f"sudo usermod -aG wireshark {os.environ.get('USER', '$USER')}, then restart the computer"))
    enabled = run(["systemctl", "is-enabled", *SLEEP_TARGETS])[1].split()
    if enabled and any(e != "masked" for e in enabled):
        out.append(Result(WARN, "Sleep", "this computer can go to sleep, and then nothing is watched",
                          "sudo systemctl mask " + " ".join(SLEEP_TARGETS)))
    elif enabled:
        out.append(Result(OK, "Sleep", "sleep is off"))
    return out


def this_pc_addresses(cfg: dict) -> set[str]:
    net = cfg.get("network") or {}
    found = set(net.get("admin_devices") or [])
    host = (cfg.get("host_context") or {}).get("host")
    if host:
        found.add(host)
    return found


def run_all(cfg: dict, cfg_path: str, zeek_dir: str, now: float | None = None, run=_run,
            unit_dir: Path = service.UNIT_DIR) -> list[Result]:
    now = time.time() if now is None else now
    units = installed_units(unit_dir)
    z = Path(zeek_dir)
    results = check_setup(cfg_path)
    if results and results[0].level == FAIL:
        return results
    age = units_age(units, now, unit_dir)
    new = age is not None and age < SETTLING
    results += check_services(units, run)
    results += check_capture(z, this_pc_addresses(cfg), now, new)
    results += check_router(units, z, now, new)
    results += check_agents(cfg, now)
    results += check_alerts(cfg)
    results += check_ai(cfg)
    results += check_feeds(cfg, now)
    results += check_vuln_feeds(cfg, now)
    results += check_disk(Path("."))
    results += check_windows(run)
    results += check_linux_host(units, run, unit_dir)
    results += check_this_host((cfg.get("host_context") or {}).get("host"), run)
    return results


def report(results: list[Result]) -> str:
    lines = []
    for r in results:
        lines.append(f"{MARK[r.level]} {r.part:12} {r.said}")
        if r.fix and r.level != OK:
            lines.append(f"{'':20}-> {r.fix}")
    fails = sum(r.level == FAIL for r in results)
    warns = sum(r.level == WARN for r in results)
    lines.append("")
    lines.append("All good." if not fails and not warns else
                 f"{fails} problem{'s' if fails != 1 else ''} to fix, {warns} note{'s' if warns != 1 else ''}.")
    return "\n".join(lines)
