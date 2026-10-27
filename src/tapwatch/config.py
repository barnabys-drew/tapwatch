"""Load config.yaml, assets.yaml and the IOC list. Secrets come from environment
variables named in the config, never from the YAML itself."""

from __future__ import annotations

import ipaddress
import os
import shutil
from pathlib import Path

import yaml

from . import detectors, hostrules, judge
from .hostctx import HostContext
from .notifiers import HerdrNotifier, Notifier
from .router import Thresholds
from .summarizer import Assets
from .triage import DEFAULT_MODEL, GATEWAY_MODEL, GATEWAY_URL, JevClient

FEED_FILES = {"popular_domains_file": "top-100k.csv", "oui_file": "oui.csv", "asn_file": "ip2asn-v4.tsv.gz",
              "categories_file": "categories.tsv", "public_suffix_file": "public_suffix_list.dat",
              "adfection_iocs_file": "iocs-adfection.tsv"}
LEARNED_CATEGORIES = "categories.learned.tsv"  # the model's cached domain categories (categories.py): written, not downloaded


def load(path: str | None) -> dict:
    cfg = (yaml.safe_load(Path(path).read_text()) or {}) if path and Path(path).exists() else {}
    return with_feeds(cfg)


def with_feeds(cfg: dict) -> dict:
    """Point unset list settings at what `tapwatch update-feeds` downloaded into feeds_dir."""
    d = Path(cfg.get("feeds_dir", "feeds"))
    for key, name in FEED_FILES.items():
        if not cfg.get(key) and (d / name).exists():
            cfg[key] = str(d / name)
    if not cfg.get("newly_registered_dir") and (d / "nrd").is_dir():   # feeds.NRD_DIR: one file per day
        cfg["newly_registered_dir"] = str(d / "nrd")
    if not cfg.get("learned_categories_file"):  # an output: it need not exist yet
        cfg["learned_categories_file"] = str(d / LEARNED_CATEGORIES)
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


# Threat-intel lists read on top of your own ioc_file: config key -> the list's name on a case.
IOC_LISTS = {"ioc_file": "your list", "adfection_iocs_file": "AdFection / Candiru"}
# Downloaded entries left out, as the list's own blocklist export leaves them out: a bare entry matches every
# subdomain. Adtimizer denies involvement in Discover-Tech's infrastructure (Citizen Lab), so only its named
# operational hosts (dtech., noas., tekma.adtimizer.co) are matched.
IOC_SKIP = frozenset({"adtimizer.co"})


def iocs(cfg: dict) -> tuple[set[str], set[str], dict[str, dict]]:
    """IOC files: one IP or domain per line, '#' comments allowed. A line may carry more columns, tab separated,
    as the downloaded lists do: indicator, tier, confidence, source. Returns (ips, domains, labels), where
    labels maps each tiered indicator to {"list", "tier", "confidence", "source"} for ioc_match.

    Your own file is read as written. A downloaded list is checked on the way in: file hashes are skipped
    (64 hex digits, nothing on the wire to match), and so are LAN, loopback and multicast addresses and names
    without a dot, so a bad upstream row can't turn ordinary LAN traffic into an always-alert case."""
    ips, domains, labels = set(), set(), {}
    for key, list_name in IOC_LISTS.items():
        p = cfg.get(key)
        if not p or not Path(p).exists():
            continue
        feed = key != "ioc_file"
        for line in Path(p).read_text().splitlines():
            cols = [c.strip() for c in line.split("#", 1)[0].split("\t")]
            v = cols[0].lower()
            if not v or (feed and (v in IOC_SKIP or len(v) == 64 and all(c in "0123456789abcdef" for c in v))):
                continue
            try:
                ip = ipaddress.ip_address(v)
            except ValueError:
                if feed and "." not in v.strip("."):
                    continue
                domains.add(v)
            else:
                if feed and (detectors.is_internal(str(ip)) or ip.is_loopback or ip.is_multicast or ip.is_unspecified):
                    continue
                ips.add(v := str(ip))
            if len(cols) > 1 and cols[1]:
                labels[v.rstrip(".")] = {"list": list_name, "tier": cols[1].lower(),
                                         "confidence": cols[2] if len(cols) > 2 else "",
                                         "source": cols[3] if len(cols) > 3 else ""}
    return ips, domains, labels


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
    logs = list(h.get("results_logs") or HOST_LOGS) + [p for p in [fleet_results_log(cfg)] if p]
    dirs = {str(Path(p).parent) for p in logs if Path(p).is_file()}
    return sorted(dirs)


def fleet_results_log(cfg: dict) -> str | None:
    """`fleet: {results_log: <path>}`: the results log a Fleet server writes for every enrolled agent (#14,
    deploy/fleet). Its rows are other computers' (zeek.FLEET_OSQUERY), each read by its own set of host rules."""
    return ((cfg.get("fleet") or {}).get("results_log")) or None


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


def build_detectors(cfg: dict) -> list:
    """Every detector `run` uses, built from the config: the network rules with the IOC lists, the popular-domain
    list and the asset table, plus the endpoint rules. `tapwatch selfcheck` builds through here too, so what it
    measures is what runs."""
    ips, doms, labels = iocs(cfg)
    net = detectors.build(cfg, ips, doms, popular_domains(cfg), assets(cfg).table, labels)
    warmup = next((d.warmup for d in net if isinstance(getattr(d, "warmup", None), detectors.Warmup)), None)
    return net + hostrules.build(cfg, warmup)  # one warm-up clock: the pipeline persists the first detector's


def judge_settings(cfg: dict) -> judge.Settings:
    """`judge:`: auto-close (#204) and back-off (#205). Off unless `auto_close: true` and a detector is listed."""
    return judge.Settings.from_config(cfg)


def judge_autoclose(cfg: dict) -> judge.AutoClose:
    return judge.AutoClose(judge_settings(cfg))


def thresholds(cfg: dict) -> Thresholds:
    return Thresholds(**cfg.get("thresholds", {}))
