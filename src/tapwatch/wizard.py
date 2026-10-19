"""`tapwatch init`: answer a few questions, get a working config.yaml, assets.yaml and .env.

Facts the machine can tell us (gateway, this machine's address, timezone, capture interfaces,
whether Npcap's dumpcap is installed) are detected, then offered as defaults. Nothing is sent
anywhere. Secrets (notification URLs, API keys) go to .env (mode 600), never into config.yaml.
Existing files are never overwritten without --force.

Everything interactive goes through `ask(question, default, choices, key=...)`, so tests, `--yes` and
`--answers` (the Windows installer asks in Windows and hands the answers over as JSON) can answer for
the user. `key` is the question's stable name in an answers file; the wording can change, the key can't.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import yaml

DUMPCAP = Path("/mnt/c/Program Files/Wireshark/dumpcap.exe")
SKIP_IFACES = ("lo", "docker", "br-", "veth", "virbr", "tailscale", "wg", "tun", "loopback")


@dataclass
class Facts:
    gateway: str = ""
    this_ip: str = ""
    timezone: str = ""
    interfaces: list[tuple[str, bool]] = field(default_factory=list)  # (name, has an IPv4 address)
    windows_capture: bool = False
    local_v6: str = ""  # this machine's global IPv6 prefix (/64), if the LAN has one


def _run(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def detect() -> Facts:
    f = Facts()
    m = re.search(r"default via (\S+) dev (\S+)", _run(["ip", "route", "show", "default"]))
    if m:
        f.gateway = m.group(1)
        src = re.search(r"src (\S+)", _run(["ip", "route", "get", m.group(1)]))
        f.this_ip = src.group(1) if src else ""
        f.local_v6 = global_v6_prefix(_run(["ip", "-6", "addr", "show", "dev", m.group(2), "scope", "global"]))
    tz = Path("/etc/timezone")
    f.timezone = tz.read_text().strip() if tz.exists() else _run(["timedatectl", "show", "-p", "Timezone", "--value"]).strip()
    with_ip = set(re.findall(r"^\d+:\s+(\S+)\s+inet\s", _run(["ip", "-o", "-4", "addr", "show"]), re.MULTILINE))
    net = Path("/sys/class/net")
    for p in sorted(net.glob("*")) if net.exists() else []:
        if not p.name.startswith(SKIP_IFACES):
            f.interfaces.append((p.name, p.name in with_ip))
    f.windows_capture = DUMPCAP.exists()
    return f


def global_v6_prefix(ip_addr_output: str) -> str:
    """The /64 of the first global IPv6 address in `ip -6 addr` output (not a temporary/privacy one)."""
    import ipaddress

    for addr, plen, flags in re.findall(r"inet6 (\S+)/(\d+) scope global([^\n]*)", ip_addr_output):
        if "temporary" in flags:
            continue
        try:
            return str(ipaddress.ip_interface(f"{addr}/{min(int(plen), 64)}").network)
        except ValueError:
            continue
    return ""


def suggest_iface(f: Facts) -> str:
    """A mirror-port NIC has no IP address; prefer one of those."""
    no_ip = [n for n, has_ip in f.interfaces if not has_ip]
    return (no_ip or [n for n, _ in f.interfaces] or [""])[0]


def build(f: Facts, ask) -> tuple[dict, dict, dict, list[str]]:
    """Ask the questions. Returns (config, assets, env vars, notes for the user)."""
    notes: list[str] = []
    # Not asked: "office" framing makes Jev better at alerting on real C2, even on a home network
    # (eval/RESULTS.md, "Wording"). A home user would answer "home" and get the worse wording.
    audience = "office"
    gateway = ask("Router (gateway) IP", f.gateway, key="gateway")
    this_ip = ask("This machine's IP on that network", f.this_ip, key="this_ip")
    tz = ask("Timezone", f.timezone or "UTC", key="timezone")
    if f.windows_capture:
        capture = ask("Capture with Npcap on Windows (mirror NIC plugged into this PC)?", "yes", ["yes", "no"],
                      key="windows_capture")
        iface = ask("Npcap interface name (as Windows shows it)", "Ethernet", key="capture_iface") \
            if capture == "yes" else ""
        if iface:
            notes.append(f"Start capture and the alerter: tapwatch service install --zeek-dir logs/zeek "
                         f"--capture-iface '{iface}', then loginctl enable-linger $USER")
    else:
        iface = ask("Network interface plugged into the mirror port", suggest_iface(f), key="capture_iface")
        notes.append(f"Start capturing: TAP_IFACE={iface} docker compose -f deploy/docker-compose.yml up -d")
    channel = ask("Where should alerts go?", "ntfy", ["ntfy", "discord", "email", "none"], key="alerts")
    env: dict[str, str] = {"TAPWATCH_UI_TOKEN": secrets.token_urlsafe(24)}  # case desk login
    cfg: dict = {
        "db_path": "tapwatch.db", "assets_file": "assets.yaml", "feeds_dir": "feeds",
        "audience": audience, "timezone": tz,
        "network": {"gateways": [gateway] if gateway else [], "admin_devices": [this_ip] if this_ip else [],
                    "local_nets": [v6] if (v6 := ask("Your LAN's IPv6 prefix (Enter to skip if you don't use IPv6)",
                                                      f.local_v6, key="ipv6_prefix")) else []},
        "warmup_seconds": 86400, "learning_days": 3, "zeek_retention_days": 30, "digest_hour_utc": 13,
        "ui": {"host": "127.0.0.1", "port": 8765},
    }
    if channel == "ntfy":
        topic = "tapwatch-" + secrets.token_urlsafe(18)
        env["TAPWATCH_NTFY_URL"] = ask("ntfy server", "https://ntfy.sh", key="ntfy_server").rstrip("/") + "/" + topic
        notes.append(f"Subscribe in the ntfy app to: {env['TAPWATCH_NTFY_URL']}  (keep it secret; it's the password)")
    elif channel == "discord":
        env["TAPWATCH_DISCORD_URL"] = ask("Discord webhook URL (Channel settings > Integrations > Webhooks)", "",
                                            key="discord_url")
    elif channel == "email":
        host = ask("SMTP server", "smtp.gmail.com", key="smtp_host")
        user = ask("SMTP username (your address)", "", key="smtp_user")
        cfg["smtp"] = {"host": host, "port": 587, "username": user, "from": user,
                       "to": ask("Send alerts to", user, key="smtp_to"), "password_env": "TAPWATCH_SMTP_PASSWORD"}
        env["TAPWATCH_SMTP_PASSWORD"] = ask("SMTP password (Gmail: an app password)", "", key="smtp_password")
    key = ask("TypeSafe API key: an AI reads each unclear case and helps decide whether it is worth "
              "interrupting you (optional, Enter to skip: the rules work alone)", "", key="typesafe_key")
    if key:
        env["TYPESAFE_API_KEY"] = key
        cfg["typesafe"] = {"enabled": True, "provider": "typesafe", "model": "jev-1.13.0"}
    else:
        cfg["typesafe"] = {"enabled": False}
        notes.append("AI triage is off (rules-only). Add TYPESAFE_API_KEY to .env and set typesafe.enabled later.")
    key = ask("Anthropic API key: names the kind of site (video call, security vendor...) when the offline "
              "list doesn't know it; only public website names are sent (optional, Enter to skip)", "",
              key="anthropic_key")
    if key:
        env["ANTHROPIC_API_KEY"] = key
        cfg["categories"] = {"ai": True, "model": "claude-haiku-5-5", "per_hour": 60, "api_key_env": "ANTHROPIC_API_KEY"}
    assets = {}
    if gateway:
        assets[gateway] = {"name": "router", "role": "router"}
    if this_ip:
        assets[this_ip] = {"name": "tapwatch box", "role": "workstation"}
    notes.append("Name your devices in assets.yaml (role: camera / tv / hub / printer / workstation...) as you learn them.")
    notes.append("Download the public lists: tapwatch update-feeds")
    notes.append("Case desk login token: TAPWATCH_UI_TOKEN in .env")
    return cfg, assets, env, notes


HEADER = ("# Written by `tapwatch init`. Every option, with comments: config.example.yaml.\n"
          "# Secrets live in .env, not here.\n")


def write(directory: str, cfg: dict, assets: dict, env: dict, force: bool = False) -> list[str]:
    d = Path(directory)
    targets = {d / "config.yaml": HEADER + yaml.safe_dump(cfg, sort_keys=False),
               d / "assets.yaml": "# Device -> name and role. Keys: an IP, mac:<address> or name:<DHCP hostname>.\n"
                                  "# Jev sees names, never IPs, MACs or DHCP hostnames.\n"
                                  + yaml.safe_dump(assets, sort_keys=False)}
    clash = [str(p) for p in targets if p.exists()]
    if clash and not force:
        raise FileExistsError(f"already there (use --force to replace): {', '.join(clash)}")
    for p, text in targets.items():
        p.write_text(text)
    written = [str(p) for p in targets]
    if env:
        envp = d / ".env"
        old = envp.read_text() if envp.exists() else ""
        keep = [ln for ln in old.splitlines() if ln.split("=", 1)[0].strip() not in env]
        envp.write_text("\n".join(keep + [f"{k}={v}" for k, v in env.items()]) + "\n")
        os.chmod(envp, 0o600)
        written.append(f"{envp} (mode 600)")
    return written


ANSWER_KEYS = {"gateway", "this_ip", "timezone", "windows_capture", "capture_iface", "alerts", "ipv6_prefix",
               "ntfy_server", "discord_url", "smtp_host", "smtp_user", "smtp_to", "smtp_password",
               "typesafe_key", "anthropic_key", "download_feeds"}


def from_answers(text: str):
    """An `ask` that answers from a JSON object keyed by question key, else takes the detected default.
    An unknown key is refused (a typo would otherwise silently fall back to a default), and so is an
    answer outside a question's choices."""
    given = json.loads(text)
    if not isinstance(given, dict):
        raise TypeError("answers must be a JSON object")
    unknown = sorted(set(given) - ANSWER_KEYS)
    if unknown:
        raise ValueError(f"unknown answer keys: {', '.join(unknown)}")

    def ask(question: str, default: str, choices: list[str] | None = None, key: str = "") -> str:
        got = str(given[key]).strip() if key in given else default
        if choices and got not in choices:
            raise ValueError(f"{key}: answer one of {', '.join(choices)}, not {got!r}")
        return got
    return ask


def prompt(question: str, default: str, choices: list[str] | None = None, key: str = "") -> str:
    hint = f" [{'/'.join(choices)}]" if choices else ""
    while True:
        got = input(f"{question}{hint} ({default}): " if default else f"{question}{hint}: ").strip() or default
        if not choices or got in choices:
            return got
        print(f"  please answer one of: {', '.join(choices)}")
