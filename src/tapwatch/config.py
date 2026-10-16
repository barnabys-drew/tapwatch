"""Load config.yaml, assets.yaml and the IOC list. Secrets come from environment
variables named in the config, never from the YAML itself."""

from __future__ import annotations

import ipaddress
import os
import shutil
from pathlib import Path

import yaml

from .hostctx import HostContext
from .notifiers import HerdrNotifier, Notifier
from .router import Thresholds
from .summarizer import Assets
from .triage import DEFAULT_MODEL, GATEWAY_MODEL, GATEWAY_URL, JevClient

FEED_FILES = {"popular_domains_file": "top-100k.csv", "oui_file": "oui.csv", "asn_file": "ip2asn-v4.tsv.gz",
              "categories_file": "categories.tsv"}


def load(path: str | None) -> dict:
    cfg = (yaml.safe_load(Path(path).read_text()) or {}) if path and Path(path).exists() else {}
    return with_feeds(cfg)


def with_feeds(cfg: dict) -> dict:
    """Point unset list settings at what `tapwatch update-feeds` downloaded into feeds_dir."""
    d = Path(cfg.get("feeds_dir", "feeds"))
    for key, name in FEED_FILES.items():
        if not cfg.get(key) and (d / name).exists():
            cfg[key] = str(d / name)
    return cfg


def missing_feeds(cfg: dict) -> str:
    """What's lost without the downloaded lists: a warning line for the log, or "" when all are set.

    The popular-domains list is the one that matters: without it the beaconing cap never applies,
    every numbered CDN host counts as random to dns_anomaly and new_domain, and the "popular"
    fact is always false. That is a much noisier first day, and nothing else says why."""
    lost = []
    if not cfg.get("popular_domains_file"):
        lost.append("popular domains (beaconing and DNS detectors treat every CDN host as unknown)")
    if not cfg.get("oui_file"):
        lost.append("MAC vendors (new devices have no maker)")
    if not cfg.get("asn_file"):
        lost.append("IP-to-network (destinations have no owner)")
    if not cfg.get("categories_file"):
        lost.append("domain categories (new_domain, tls_odd and upload_spike say nothing about the kind of site)")
    if not lost:
        return ""
    return "public lists not downloaded, run `tapwatch update-feeds`: missing " + "; ".join(lost)


def assets(cfg: dict) -> Assets:
    p = cfg.get("assets_file")
    table = yaml.safe_load(Path(p).read_text()) if p and Path(p).exists() else {}
    return Assets(table or {}, cfg.get("audience", "office"))


def iocs(cfg: dict) -> tuple[set[str], set[str]]:
    """IOC file: one IP or domain per line, '#' comments allowed."""
    p = cfg.get("ioc_file")
    ips, domains = set(), set()
    if p and Path(p).exists():
        for line in Path(p).read_text().splitlines():
            v = line.split("#", 1)[0].strip()
            if not v:
                continue
            try:
                ips.add(str(ipaddress.ip_address(v)))
            except ValueError:
                domains.add(v.lower())
    return ips, domains


def popular_domains(cfg: dict) -> set[str]:
    """Optional list of widely used domains: one per line, or Tranco-style "rank,domain" CSV."""
    p = cfg.get("popular_domains_file")
    if not p or not Path(p).exists():
        return set()
    out = set()
    for line in Path(p).read_text().splitlines():
        v = line.split("#", 1)[0].strip().split(",")[-1].strip().lower()
        if v:
            out.add(v)
    return out


def jev_client(cfg: dict) -> JevClient | None:
    """provider: typesafe | vercel | auto (default: TypeSafe key if set, else Vercel AI Gateway key)."""
    t = cfg.get("typesafe", {})
    if t.get("enabled", True) is False:
        return None
    provider = t.get("provider", "auto")
    ts_key = os.environ.get(t.get("api_key_env", "TYPESAFE_API_KEY"))
    gw_key = os.environ.get(t.get("gateway_key_env", "AI_GATEWAY_API_KEY"))
    if provider in ("typesafe", "auto") and ts_key:
        return JevClient(ts_key, t.get("model", DEFAULT_MODEL), audience=cfg.get("audience", "office"))
    if provider in ("vercel", "auto") and gw_key:
        return JevClient(gw_key, t.get("gateway_model", GATEWAY_MODEL), url=GATEWAY_URL,
                         audience=cfg.get("audience", "office"))
    return None


def load_dotenv(path: str = ".env") -> None:
    """Minimal .env support (KEY=value lines). Never overrides variables already set."""
    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip("'\""))


def notifier(cfg: dict) -> Notifier | None:
    """Every URL comes from an environment variable (.env): they're secrets (an ntfy topic, a webhook)."""
    def env(section: str, key: str, default: str) -> str | None:
        return os.environ.get((cfg.get(section) or {}).get(key, default)) or None

    teams = env("teams", "webhook_url_env", "TAPWATCH_TEAMS_URL")
    ntfy, ntfy_token = env("ntfy", "url_env", "TAPWATCH_NTFY_URL"), env("ntfy", "token_env", "TAPWATCH_NTFY_TOKEN")
    discord = env("discord", "webhook_url_env", "TAPWATCH_DISCORD_URL")
    webhook = env("webhook", "url_env", "TAPWATCH_WEBHOOK_URL")
    smtp = cfg.get("smtp")
    pw = os.environ.get(smtp.get("password_env", "TAPWATCH_SMTP_PASSWORD")) if smtp else None
    if not any((teams, ntfy, discord, webhook, smtp)):
        return None
    return Notifier(teams, smtp, pw, email_always=bool(smtp and smtp.get("always")), ntfy_url=ntfy,
                    ntfy_token=ntfy_token, discord_url=discord, webhook_url=webhook)


def herdr(cfg: dict) -> HerdrNotifier | None:
    """Herdr pop-ups for critical cases. Opt-in: `herdr: {enabled: true}`."""
    h = cfg.get("herdr") or {}
    if not h.get("enabled"):
        return None
    path = h.get("bin") or shutil.which("herdr") or str(Path.home() / ".local/bin/herdr")
    if not Path(path).exists():
        return None
    return HerdrNotifier(path, sound=h.get("sound", "request"), position=h.get("position", "top-right"))


# The endpoint agents' results logs: Linux/WSL, and Windows as seen from WSL (agents/README.md).
HOST_LOGS = ["/var/log/osquery/osqueryd.results.log", "/mnt/c/Program Files/osquery/log/osqueryd.results.log"]


def host_log_dirs(cfg: dict) -> list[str]:
    """Directories holding the endpoint agents' osquery logs (`host_context.results_logs`, else HOST_LOGS), for
    the endpoint rules (hostrules.py): `run` follows them like Zeek's directories (zeek.LOG_TYPES names the
    files). Only directories that exist, so a box without an agent changes nothing."""
    h = cfg.get("host_context") or {}
    dirs = {str(Path(p).parent) for p in (h.get("results_logs") or HOST_LOGS) if Path(p).is_file()}
    return sorted(dirs)


def hostctx(cfg: dict) -> HostContext | None:
    """`host_context: {host: <this PC's IP>}`: ask osquery and Claude Code transcripts who made a case's traffic."""
    h = cfg.get("host_context") or {}
    if not h.get("host"):
        return None
    osq = h.get("osquery_bin") or shutil.which("osqueryi") or shutil.which("osqueryd")
    if not osq and Path("/opt/osquery/bin/osqueryd").exists():
        osq = "/opt/osquery/bin/osqueryd"
    bins = osq if isinstance(osq, list) else [osq] if osq else []
    win = Path("/mnt/c/Program Files/osquery/osqueryi.exe")  # Windows PC running tapwatch in WSL
    if not h.get("osquery_bin") and win.exists():
        bins.append(str(win))
    logs = h.get("results_logs") or HOST_LOGS
    ps = Path("/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe")
    return HostContext(h["host"], bins, logs, h.get("transcripts"),
                       powershell=str(ps) if win.exists() and ps.exists() else None,
                       hostname=h.get("hostname"))  # None: this machine's own name


def thresholds(cfg: dict) -> Thresholds:
    return Thresholds(**cfg.get("thresholds", {}))
