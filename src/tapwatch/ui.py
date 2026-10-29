"""`tapwatch ui`: a small local web app for working the case queue.

Standard library only. Pages are rendered on the server; there is no JavaScript.

Security, because this page shows strings an attacker put on the network
(domain names, TLS server names, IDS signatures):
  * every value goes through e() (html.escape) on its way into the page,
    including into attributes; untrusted strings are never turned into links
  * a strict Content-Security-Policy: no scripts at all, only our one inline
    stylesheet (by nonce), forms may only post back to us
  * binds to 127.0.0.1 by default and checks the Host header there, so a web
    page using DNS rebinding can't read it
  * on any other address a token is required (TAPWATCH_UI_TOKEN), entered once
    on a login form and kept as a session cookie
  * anything that changes data is a POST carrying a CSRF token; GETs only read
  * all SQL uses ? placeholders
"""

from __future__ import annotations

import base64
import hmac
import html
import ipaddress
import json
import logging
import re
import secrets
import time
from datetime import datetime
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

from . import benchmark, deskstats, evidence, judge
from .store import (
    DISPOSITIONS,
    JUDGE_DECIDED,
    OWNER_DISPOSITION,
    STATUSES,
    TRANSITIONS,
    Store,
    WorkflowError,
    describe_rule,
)
from .summarizer import Assets
from .triage import SEVERITY_LEVELS

log = logging.getLogger("tapwatch.ui")

COOKIE = "tapwatch_sid"
MAX_BODY = 64 * 1024
MAX_NOTE = 10_000
PAGE_SIZE = 200
JUDGE_LIST = 500   # judge closes listed on the Judge page
ROUTES = ("alert", "digest", "log")


def e(value) -> str:
    """HTML-escape anything (quotes too, so it's safe inside attributes). None becomes ''."""
    return "" if value is None else html.escape(str(value), quote=True)


def when(ts) -> str:
    if ts is None:
        return ""
    return datetime.fromtimestamp(ts).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


def label(value: str | None) -> str:
    return (value or "").replace("_", " ")


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


# ---------------------------------------------------------------- page shell

# The look of homebase, the owner's hub page: pine-green on near-black (or paper-white in light mode), flat
# cards with thin borders, small uppercase section labels, big numbers with their label above. Hand-written rather
# than Tailwind, because the CSP allows no scripts and there's no build step. Charts are inline SVG with classes.
CSS = """
:root { --bg:#f6f7f5; --panel:#ffffff; --panel2:#eef1ee; --ink:#1d2320; --strong:#0f1411; --muted:#66706b;
  --faint:#8b948f; --line:#dde2de; --line2:#e9ece9; --accent:#2f7d63; --on-accent:#ffffff; --red:#d24b3e;
  --amber:#b8772a; --green:#2f9a6c; --violet:#7a55b8; --blue:#3c6fc2; --shadow:none;
  --lift:0 6px 18px rgba(20,30,25,.10); color-scheme:light; }
@media (prefers-color-scheme: dark) { :root { --bg:#121715; --panel:#1a201d; --panel2:#161c19; --ink:#e3e9e5;
  --strong:#f4f8f5; --muted:#8d9792; --faint:#68716c; --line:#2a322e; --line2:#222a26; --accent:#5cc29a;
  --on-accent:#0c1f17; --red:#e76a5c; --amber:#d89a45; --green:#46b884; --violet:#a37ad6; --blue:#5687d6;
  --shadow:none; --lift:0 8px 22px rgba(0,0,0,.45); color-scheme:dark; } }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--ink); min-height:100vh; -webkit-font-smoothing:antialiased;
  font:14px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; }
a { color:var(--accent); text-decoration:none; } a:hover { text-decoration:underline; }
::-webkit-scrollbar { width:6px; height:6px; } ::-webkit-scrollbar-track { background:var(--panel2); }
::-webkit-scrollbar-thumb { background:var(--line); border-radius:3px; }

/* header + nav */
.top { position:sticky; top:0; z-index:5; background:color-mix(in srgb, var(--bg) 88%, transparent);
  backdrop-filter:blur(8px); border-bottom:1px solid var(--line2); }
.top-in { max-width:1400px; margin:0 auto; padding:10px 24px; display:flex; align-items:center; gap:18px; flex-wrap:wrap; }
.brand { display:flex; align-items:center; gap:8px; color:var(--strong); font-weight:700; font-size:19px; letter-spacing:-.01em; }
.brand:hover { text-decoration:none; }
.brand svg { color:var(--accent); }
.brand small { color:var(--faint); font-weight:500; font-size:12px; }
.tabs { display:flex; gap:4px; flex-wrap:wrap; }
.tabs { gap:2px 14px; } .tab { color:var(--muted); padding:4px 0; font-size:15px; border-bottom:2px solid transparent; }
.tab:hover { color:var(--ink); text-decoration:none; }
.tab.on { color:var(--ink); font-weight:600; border-bottom-color:var(--accent); }
.top .end { margin-left:auto; display:flex; align-items:center; gap:14px; }
.home { color:var(--muted); border:1px solid var(--line); border-radius:999px; padding:3px 12px; font-size:13px; }
.home:hover { color:var(--ink); border-color:var(--accent); text-decoration:none; }
main { max-width:1400px; margin:0 auto; padding:22px 24px 48px; animation:fade .22s ease both; }
@keyframes fade { from { opacity:0; transform:translateY(7px); } to { opacity:1; transform:none; } }

/* type */
h1 { font-size:21px; font-weight:650; margin:0; color:var(--strong); letter-spacing:-.01em; }
.sub { color:var(--muted); font-size:13px; margin:3px 0 18px; }
h2, .section { font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:.08em; font-weight:650;
  margin:24px 0 8px; }
.card > h2:first-child { margin-top:0; }
.muted { color:var(--muted); } .faint { color:var(--faint); } .err { color:var(--red); font-weight:600; }
code, .mono, pre { font-family:ui-monospace, SFMono-Regular, Consolas, monospace; font-size:12.5px; overflow-wrap:anywhere; }
.tnum, td.num, th.num { font-variant-numeric:tabular-nums; } td.num, th.num { text-align:right; }

/* panels */
.card { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:14px 16px; margin-bottom:12px; }
.card.flush { padding:0; overflow:hidden; }
.scroll { overflow-x:auto; }
.grid2 { display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-bottom:12px; } .grid2 > .card { margin-bottom:0; }
.grid2 > div > h2:first-child, .grid2 > section > h2:first-child { margin-top:0; }
.grid3 { display:grid; grid-template-columns:1.4fr 1fr 1fr; gap:12px; margin-bottom:12px; } .grid3 > .card { margin-bottom:0; }
.accent-alert { border-left:4px solid var(--red); } .accent-digest { border-left:4px solid var(--amber); }
.accent-log { border-left:4px solid var(--line); } .accent-critical { border-left:4px solid var(--red);
  box-shadow:0 0 0 1px color-mix(in srgb, var(--red) 35%, transparent), var(--shadow); }

/* stat tiles */
.tiles { display:grid; grid-template-columns:repeat(auto-fit, minmax(170px, 1fr)); gap:10px; margin:0 0 14px; }
.tile { display:flex; flex-direction:column; background:var(--panel); border:1px solid var(--line); border-radius:10px;
  padding:12px 14px; color:var(--ink); position:relative; overflow:hidden; transition:border-color .15s ease; }
a.tile:hover, a.tile:focus { border-color:var(--accent); text-decoration:none; outline:none; }
.tile .l { order:-1; display:flex; align-items:center; gap:7px; font-size:11px; color:var(--muted); text-transform:uppercase;
  letter-spacing:.07em; font-weight:600; }
.tile .l::before { content:""; width:8px; height:8px; border-radius:50%; background:var(--tone, var(--accent)); flex:none; }
.tile .v { font-size:26px; font-weight:650; color:var(--strong); line-height:1.15; letter-spacing:-.01em;
  font-variant-numeric:tabular-nums; margin-top:4px; }
.tile .h { font-size:12px; color:var(--muted); margin-top:1px; }
.tile svg.spark { margin-top:8px; }
.t-red { --tone:var(--red); } .t-amber { --tone:var(--amber); } .t-green { --tone:var(--green); }
.t-blue { --tone:var(--accent); } .t-violet { --tone:var(--violet); }

/* badges and pills */
.badge { display:inline-flex; align-items:center; gap:5px; font-size:11px; font-weight:600; padding:2px 9px; border-radius:999px;
  white-space:nowrap; border:1px solid color-mix(in srgb, var(--c, var(--muted)) 40%, transparent);
  background:color-mix(in srgb, var(--c, var(--muted)) 14%, transparent); color:var(--c, var(--muted)); }
.badge::before { content:""; width:6px; height:6px; border-radius:50%; background:currentColor; }
.b-alert, .b-critical, .b-true_positive { --c:var(--red); } .b-digest, .b-investigating, .b-high { --c:var(--amber); }
.b-closed, .b-false_positive, .b-benign_expected { --c:var(--green); } .b-new { --c:var(--blue); }
.b-log, .b-none { --c:var(--faint); } .b-ai { --c:var(--violet); }
.pills { display:flex; flex-wrap:wrap; gap:8px; margin:0 0 14px; }
.pill { border-radius:20px; font-size:12px; padding:4px 13px; border:1px solid var(--line); color:var(--muted); white-space:nowrap; }
.pill b { color:var(--ink); margin-left:4px; font-variant-numeric:tabular-nums; }
.pill:hover { border-color:var(--accent); color:var(--accent); text-decoration:none; }
.pill.on { background:var(--accent); border-color:var(--accent); color:var(--on-accent); font-weight:600; } .pill.on b { color:inherit; }

/* tables */
table { border-collapse:collapse; width:100%; }
thead th { background:var(--panel2); color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.05em;
  font-weight:600; text-align:left; padding:9px 10px; border-bottom:1px solid var(--line2); white-space:nowrap; }
tbody td { padding:9px 10px; border-bottom:1px solid var(--line2); font-size:13px; vertical-align:middle; }
tbody tr:last-child td { border-bottom:0; }
tbody tr:hover { background:color-mix(in srgb, var(--ink) 4%, transparent); }
tr.r-critical td:first-child, tr.r-alert td:first-child { box-shadow:inset 3px 0 0 var(--red); }
tr.r-digest td:first-child { box-shadow:inset 3px 0 0 var(--amber); }
td a.title { color:var(--ink); font-weight:600; } td a.title:hover { color:var(--accent); }
.dev { display:flex; flex-direction:column; line-height:1.25; } .dev small { color:var(--faint); font-size:11.5px; }
td .mono, .dev small { white-space:nowrap; }

/* definition lists, code */
dl { display:grid; grid-template-columns:max-content 1fr; gap:8px 18px; margin:0; }
dt { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.05em; font-weight:600; padding-top:2px; }
dd { margin:0; overflow-wrap:anywhere; }
pre { white-space:pre-wrap; background:var(--panel2); border:1px solid var(--line2); border-radius:10px; padding:12px 14px; margin:0; }
.untrusted { border-left:3px solid var(--amber); padding:4px 0 4px 10px; background:color-mix(in srgb, var(--amber) 6%, transparent);
  border-radius:0 8px 8px 0; }
.untrusted ul { margin:0 0 4px; padding-left:18px; } .untrusted .faint { display:block; font-size:12px; }
.meter { display:flex; align-items:center; gap:10px; } .meter svg { flex:0 0 auto; }

/* forms */
form.filters, .filters { display:flex; flex-wrap:wrap; gap:10px; align-items:end; }
label.f { display:flex; flex-direction:column; font-size:11px; color:var(--muted); gap:4px; text-transform:uppercase;
  letter-spacing:.06em; font-weight:600; }
select, input, textarea { font:inherit; font-size:13px; color:var(--ink); background:var(--panel2); border:1px solid var(--line);
  border-radius:8px; padding:7px 10px; text-transform:none; letter-spacing:0; }
select:focus, input:focus, textarea:focus { outline:none; border-color:var(--accent);
  box-shadow:0 0 0 3px color-mix(in srgb, var(--accent) 25%, transparent); }
textarea { width:100%; min-height:80px; resize:vertical; }
input[type=checkbox], input[type=radio] { accent-color:var(--accent); width:15px; height:15px; padding:0; }
button { font:inherit; font-size:13px; font-weight:600; border-radius:8px; padding:7px 16px; cursor:pointer;
  background:var(--accent); color:var(--on-accent); border:1px solid var(--accent); transition:filter .15s ease, transform .1s ease; }
button:hover { filter:brightness(1.1); } button:active { transform:translateY(1px); }
button.plain { background:transparent; color:var(--ink); border-color:var(--line); }
button.plain:hover { border-color:var(--accent); color:var(--accent); filter:none; }
button.danger { background:transparent; color:var(--red); border-color:color-mix(in srgb, var(--red) 45%, transparent); }
button.danger:hover { background:color-mix(in srgb, var(--red) 12%, transparent); filter:none; }
.bar { display:flex; flex-wrap:wrap; gap:10px; align-items:center; }
.bar b { color:var(--strong); }
.scope { display:flex; gap:10px; align-items:center; padding:9px 12px; border:1px solid var(--line2); border-radius:10px;
  margin:0 0 8px; cursor:pointer; background:var(--panel2); }
.scope:hover { border-color:var(--accent); }
.note { border-left:3px solid var(--accent); }
.card-head { display:flex; gap:10px; align-items:center; padding:12px 16px; border-bottom:1px solid var(--line2); }
.pad { padding:10px 16px; margin:0; font-size:12px; }
.empty { text-align:center; padding:34px; color:var(--muted); }

/* stats */
.chart { width:100%; height:auto; display:block; }
.chart .bar-r { fill:var(--accent); } .chart .bar-r:hover { fill:color-mix(in srgb, var(--accent) 70%, var(--strong)); }
.chart text { fill:var(--faint); font-size:12px; font-family:inherit; }
.chart .grid { stroke:var(--line2); stroke-width:1; }
.h0 { color:var(--faint); } .h1 { background:color-mix(in srgb, var(--accent) 14%, transparent); }
.h2 { background:color-mix(in srgb, var(--accent) 32%, transparent); color:var(--strong); }
.h3 { background:color-mix(in srgb, var(--accent) 55%, transparent); color:var(--strong); font-weight:700; }
.track { fill:var(--line2); } .fill-red { fill:var(--red); } .fill-green { fill:var(--green); } .fill-amber { fill:var(--amber); }
.fill-accent { fill:var(--accent); } .fill-violet { fill:var(--violet); } .fill-blue { fill:var(--blue); }
.chart .s-alert { fill:var(--red); } .chart .s-digest { fill:var(--amber); } .chart .s-log { fill:var(--faint); opacity:.55; }
.chart .s-other { fill:var(--accent); opacity:.75; }
.chart .now { fill:var(--strong); font-weight:600; }
svg.spark, svg.line { display:block; width:100%; overflow:visible; }
svg.spark polyline, svg.line polyline { fill:none; stroke:var(--tone, var(--accent)); stroke-width:1.6;
  vector-effect:non-scaling-stroke; stroke-linejoin:round; }
svg.spark polygon, svg.line polygon { fill:color-mix(in srgb, var(--tone, var(--accent)) 16%, transparent); stroke:none; }
svg.line circle { fill:var(--tone, var(--accent)); }
.legend { display:flex; gap:14px; flex-wrap:wrap; color:var(--muted); font-size:12px; margin:0 0 8px; }
.legend span { display:inline-flex; align-items:center; gap:6px; }
.legend i { width:10px; height:10px; border-radius:3px; display:inline-block; }
.legend .k-alert { background:var(--red); } .legend .k-digest { background:var(--amber); }
.legend .k-log { background:var(--faint); opacity:.55; } .legend .k-other { background:var(--accent); opacity:.75; }
.ranks { display:grid; gap:7px; } .rank { display:grid; grid-template-columns:minmax(0, 1fr) auto; gap:2px 12px; align-items:center; }
.rank .who { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-size:13px; }
.rank .who small { color:var(--faint); margin-left:6px; font-size:11.5px; }
.rank .n { font-variant-numeric:tabular-nums; font-size:12.5px; color:var(--muted); text-align:right; white-space:nowrap; }
.rank .n b { color:var(--strong); font-weight:650; }
.rank svg { grid-column:1 / -1; width:100%; height:6px; }
.headline { display:flex; gap:24px; flex-wrap:wrap; margin:2px 0 10px; }
.headline div span { display:block; font-size:11px; text-transform:uppercase; letter-spacing:.07em; color:var(--muted); }
.headline div b { font-size:20px; font-weight:650; color:var(--strong); font-variant-numeric:tabular-nums; }
.headline div small { color:var(--muted); font-size:12px; margin-left:4px; }
details.more { margin:0 0 10px; } details.more > summary { cursor:pointer; list-style:none; display:flex; align-items:center;
  gap:8px; font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:.08em; font-weight:650; padding:10px 0 8px; }
details.more > summary::-webkit-details-marker { display:none; }
details.more > summary::before { content:"▸"; font-size:11px; color:var(--accent); transition:transform .15s ease; }
details.more[open] > summary::before { transform:rotate(90deg); }
details.more > summary small { text-transform:none; letter-spacing:0; font-weight:400; color:var(--faint); font-size:12px; }
details.more > summary:hover { color:var(--ink); }

@media (max-width: 800px) { .grid2, .grid3 { grid-template-columns:1fr; } main { padding:14px; } .top-in { padding:10px 14px; }
  tbody td, thead th { padding:7px 8px; } .tile .v { font-size:24px; } dl { grid-template-columns:1fr; gap:2px; }
  dd { margin-bottom:8px; } .hide-sm { display:none; } }
"""

LOGO = ('<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
        'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 '
        '6 8 10 8 10z"/><path d="M8 12h2l1.5-3 2 6 1.5-3h1"/></svg>')
NAV = (("/", "Cases"), ("/stats", "Stats"), ("/suppressions", "Suppressions"), ("/judge", "Judge"))


STATS_REFRESH_S = 60  # the stats page reloads itself; pages with forms never do (they'd lose your typing)


def page(title: str, body: str, nonce: str, csrf: str = "", logged_in_with_token: bool = False,
         active: str = "", refresh: int = 0, home: tuple[str, str] | None = None) -> str:
    logout = (f'<form method="post" action="/logout"><input type="hidden" name="csrf" value="{e(csrf)}">'
              '<button class="plain">Log out</button></form>') if logged_in_with_token else ""
    # ui.home_url: a way back to the owner's own start page, so the desk isn't a dead end behind Back presses.
    home_link = f'<a class="home" href="{e(home[0])}">&#8962; {e(home[1])}</a>' if home else ""
    tabs = "".join(f'<a class="tab{" on" if href == active else ""}" href="{href}">{name}</a>' for href, name in NAV)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">{f'<meta http-equiv="refresh" content="{int(refresh)}">' if refresh else ""}
<title>{e(title)} · tapwatch</title>
<style nonce="{e(nonce)}">{CSS}</style></head>
<body><div class="top"><div class="top-in"><a class="brand" href="/">{LOGO}tapwatch <small>case desk</small></a>
<nav class="tabs">{tabs}</nav><div class="end">{home_link}{logout}</div></div></div>
<main>{body}</main></body></html>"""


def badge(value: str | None, text: str | None = None) -> str:
    """Tinted pill for a route/status/disposition value (our own fixed words, escaped anyway)."""
    if not value:
        return '<span class="badge b-none">none</span>'
    return f'<span class="badge b-{e(value)}">{e(text or label(value))}</span>'


def tile(value, name: str, tone: str = "blue", hint: str = "", href: str = "", spark: list | None = None) -> str:
    inner = (f'<div class="v">{e(value)}</div><div class="l">{e(name)}</div>' + (f'<div class="h">{e(hint)}</div>' if hint else "")
             + (sparkline(spark) if spark else ""))
    if href:
        return f'<a class="tile t-{tone}" href="{e(href)}">{inner}</a>'
    return f'<div class="tile t-{tone}">{inner}</div>'


def hbar(fraction: float, tone: str = "red", width: int = 90) -> str:
    """Small horizontal bar as inline SVG (attributes, not CSS, so the CSP's style rules don't apply)."""
    w = max(0, min(width, round(width * fraction)))
    return (f'<svg width="{width}" height="8" aria-hidden="true"><rect class="track" width="{width}" height="8" rx="4"/>'
            f'<rect class="fill-{tone}" width="{w}" height="8" rx="4"/></svg>')


def options(values, selected, labels: dict | None = None) -> str:
    out = []
    for v in values:
        sel = " selected" if str(v) == str(selected) else ""
        out.append(f'<option value="{e(v)}"{sel}>{e((labels or {}).get(v, label(v)))}</option>')
    return "".join(out)


def device(assets: Assets, host: str, facts: dict | None = None) -> str:
    """The device label: the assets.yaml name (by DHCP hostname, MAC or IP), else the DHCP hostname
    the device claimed (network data, escaped), else the bare address."""
    name = assets.name(host, facts)
    if name == host and facts and facts.get("device_name"):
        name = f"{facts['device_name']} (DHCP name)"
    if name == host:
        return f'<span class="mono">{e(host)}</span>'
    return f'<span class="dev">{e(name)}<small class="mono">{e(host)}</small></span>'


def severity(row) -> tuple[str, str]:
    """(text, css class) for the queue's severity column."""
    if row["must_alert"]:
        return "critical", "critical"
    if row["verdict"]:
        sev = json.loads(row["verdict"]).get("severity")
        if isinstance(sev, (int, float)):
            return f"{sev:.1f} / 4", "alert" if sev >= 2.5 else "high" if sev >= 1.5 else "log"
    return "rules", "none"


LEVEL_NAMES = [level.split(":")[0].lower() for level in SEVERITY_LEVELS]  # informational .. critical


def severity_label(row) -> str:
    """The named level a severity score rounds to (2.9 -> high), for the queue's label column."""
    if row["must_alert"]:
        return "critical"
    sev = json.loads(row["verdict"]).get("severity") if row["verdict"] else None
    if not isinstance(sev, (int, float)):
        return "\u2013"  # rules-only: no score to name
    return LEVEL_NAMES[min(len(LEVEL_NAMES) - 1, max(0, int(sev + 0.5)))]  # half up: 2.5 is high, like the badge


def csrf_field(csrf: str) -> str:
    return f'<input type="hidden" name="csrf" value="{e(csrf)}">'


# ---------------------------------------------------------------- pages

QUEUE_SORTS = {
    "newest": "last_ts DESC, id DESC",
    "severity": ("must_alert DESC, CASE route WHEN 'alert' THEN 0 WHEN 'digest' THEN 1 ELSE 2 END,"
                 " COALESCE(json_extract(verdict, '$.severity'), -1) DESC, last_ts DESC"),
}


BUCKETS = {"decided": f"{OWNER_DISPOSITION} IS NOT NULL",   # the stats tiles' buckets: the owner's decisions, never
           "noise": f"{OWNER_DISPOSITION} IN ('false_positive', 'benign_expected')"}   # a judge auto-close (#204)


def queue_filters(params: dict) -> dict:
    """Read the queue's filter params, keeping only values we recognise (others fall back to defaults)."""
    f = {k: params.get(k, [""])[0] for k in ("status", "route", "detector", "device", "sort", "disposition", "triaged")}
    if f["status"] not in (*STATUSES, "open", "all"):
        f["status"] = "open"
    if f["disposition"] not in (*DISPOSITIONS, *BUCKETS):
        f["disposition"] = ""  # the stats tiles link here: one disposition, every decided case, or the noise
    if f["triaged"] != "1":
        f["triaged"] = ""  # cases Jev gave a verdict
    if f["route"] not in (*ROUTES, "all", "triage"):
        f["route"] = "triage"  # alerts and digest items: log-only cases are for the record, not the queue
    if f["sort"] not in QUEUE_SORTS:
        f["sort"] = "newest"
    return f


def render_queue(store: Store, assets: Assets, params: dict, csrf: str) -> tuple[str, str]:
    f = queue_filters(params)
    where, args = [], []
    if f["status"] == "open":
        where.append("status != 'closed'")
    elif f["status"] != "all":
        where.append("status = ?")
        args.append(f["status"])
    if f["route"] == "triage":
        where.append("route != 'log'")
    elif f["route"] in ROUTES:
        where.append("route = ?")
        args.append(f["route"])
    if f["detector"]:
        where.append("detector = ?")
        args.append(f["detector"])
    if f["device"]:
        where.append("host = ?")
        args.append(f["device"])
    if f["disposition"] in BUCKETS:
        where.append(BUCKETS[f["disposition"]])
    elif f["disposition"]:
        where.append("disposition = ?")
        args.append(f["disposition"])
    if f["triaged"]:
        where.append("verdict IS NOT NULL")
    sql_where = (" WHERE " + " AND ".join(where)) if where else ""
    db = store.db
    # The WHERE clauses are fixed text with '?' for every value, and the sort is a QUEUE_SORTS value (f["sort"] is
    # checked against its keys above), so no request text reaches the SQL.
    # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query
    total = db.execute(f"SELECT COUNT(*) FROM cases{sql_where}", args).fetchone()[0]
    # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query
    rows = db.execute(f"SELECT * FROM cases{sql_where} ORDER BY {QUEUE_SORTS[f['sort']]} LIMIT {PAGE_SIZE}",
                      args).fetchall()
    # The tiles and pills count with the same route filter as the list, so the numbers match what is shown: the
    # default (alert + digest) hides log-only cases, and counting them made "11 open" sit over a 1-row list
    # (2026-10-18). How many open cases that hides is said once, with a link that shows them.
    route_sql = "route != 'log'" if f["route"] == "triage" else "route = ?" if f["route"] in ROUTES else "1"
    route_args = [f["route"]] if f["route"] in ROUTES else []
    # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query -- route_sql is one of three fixed strings
    by_status = dict(db.execute(f"SELECT status, COUNT(*) FROM cases WHERE {route_sql} GROUP BY status",
                                route_args).fetchall())
    hidden_log = db.execute("SELECT COUNT(*) FROM cases WHERE status != 'closed' AND route = 'log'").fetchone()[0] \
        if f["route"] == "triage" else 0
    detectors = [r[0] for r in db.execute("SELECT DISTINCT detector FROM cases ORDER BY 1")]
    hosts = [r[0] for r in db.execute("SELECT DISTINCT host FROM cases ORDER BY 1")]

    def link(**change) -> str:
        return "/?" + urlencode({**f, **change})

    open_alerts = db.execute("SELECT COUNT(*) FROM cases WHERE status != 'closed' AND route = 'alert'").fetchone()[0]
    since = time.time() - 86400
    last_day = db.execute("SELECT COUNT(*) FROM cases WHERE first_ts >= ?", (since,)).fetchone()[0]
    sup_hits = db.execute("SELECT COALESCE(SUM(hits), 0) FROM suppressions").fetchone()[0]
    n_open = by_status.get("new", 0) + by_status.get("investigating", 0)
    open_hint = f"{by_status.get('closed', 0)} closed" + (f", {hidden_log} log-only not counted" if hidden_log else "")
    tiles = (tile(n_open, "Open cases", "blue", open_hint, link(status="open"))
             + tile(open_alerts, "Open alerts", "red" if open_alerts else "green", "routed to alert",
                    link(status="open", route="alert"))
             + tile(by_status.get("new", 0), "New", "blue", "not looked at yet", link(status="new"))
             + tile(by_status.get("investigating", 0), "Investigating", "amber", "", link(status="investigating"))
             + tile(last_day, "Last 24 h", "violet", "cases raised")
             + tile(sup_hits, "Suppressed", "green", "hits on rules", "/suppressions"))

    pill_values = [("open", n_open), *((s, by_status.get(s, 0)) for s in STATUSES), ("all", sum(by_status.values()))]
    pills = "".join(f'<a class="pill{" on" if f["status"] == v else ""}" href="{e(link(status=v))}">{e(label(v))}'
                    f'<b>{n}</b></a>' for v, n in pill_values)
    bucket = {"decided": "dispositioned", "noise": "false positive or benign"}.get(f["disposition"]) \
        or (label(f["disposition"]) if f["disposition"] else "")
    for name, off in ((bucket, {"disposition": ""}), ("Jev triaged" if f["triaged"] else "", {"triaged": ""})):
        if name:
            pills += f'<a class="pill on" href="{e(link(**off))}" title="remove this filter">{e(name)} ×</a>'
    host_labels = {h: f"{assets.name(h)} ({h})" if assets.name(h) != h else h for h in hosts}
    filters = f"""<div class="card"><form class="filters" method="get" action="/">
<input type="hidden" name="status" value="{e(f["status"])}">
<input type="hidden" name="disposition" value="{e(f["disposition"])}"><input type="hidden" name="triaged" value="{e(f["triaged"])}">
<label class="f">Route<select name="route">{options(("triage", "all", *ROUTES), f["route"], {"triage": "alert + digest", "all": "any, including log"})}</select></label>
<label class="f">Detector<select name="detector"><option value="">any</option>{options(detectors, f["detector"])}</select></label>
<label class="f">Device<select name="device"><option value="">any</option>{options(hosts, f["device"], host_labels)}</select></label>
<label class="f">Sort<select name="sort">{options(QUEUE_SORTS, f["sort"])}</select></label>
<button>Apply</button> <a class="pill" href="/">reset</a></form></div>"""

    body_rows = []
    for r in rows:
        sev, sev_cls = severity(r)
        body_rows.append(
            f'<tr class="r-{e("critical" if r["must_alert"] else r["route"])}">'
            f'<td><input type="checkbox" name="ids" value="{r["id"]}" aria-label="select case {r["id"]}"></td>'
            f'<td class="num hide-sm"><a href="/case/{r["id"]}">#{r["id"]}</a></td>'
            f'<td>{badge(sev_cls, sev)}</td><td>{e(severity_label(r))}</td>'
            f'<td><a class="title" href="/case/{r["id"]}">{e(r["title"])}</a>'
            f'<div class="faint mono">{e(r["detector"])}</div></td>'
            f'<td>{device(assets, r["host"], json.loads(r["facts"] or "{}"))}</td>'
            f'<td class="hide-sm">{badge(r["route"])}</td><td>{badge(r["status"])}</td>'
            f'<td class="hide-sm">{badge(r["disposition"]) if r["disposition"] else ""}</td>'
            f'<td class="num">{r["hits"]}</td><td class="faint hide-sm tnum">{e(when(r["last_ts"]))}</td></tr>')
    shown = f"showing {len(rows)} of {total}" if total > len(rows) else f"{total} case(s)"
    table = (f"""<form method="post" action="/bulk">{csrf_field(csrf)}
<div class="card flush scroll"><table><thead><tr><th></th><th class="num hide-sm">#</th><th>severity</th><th>label</th><th>case</th><th>device</th>
<th class="hide-sm">route</th><th>status</th><th class="hide-sm">disposition</th><th class="num">hits</th><th class="hide-sm">last seen</th></tr></thead>
<tbody>{"".join(body_rows)}</tbody></table></div>
<div class="card bar"><b>Close selected</b> as
<select name="disposition">{options(DISPOSITIONS, "false_positive")}</select>
<input name="note" maxlength="{MAX_NOTE}" placeholder="note (optional)" size="30">
<button>Close selected</button></div></form>""" if rows else '<div class="card empty">No cases match these filters.</div>')
    shown = e(shown) + (f' · <a href="{e(link(route="all"))}">show {hidden_log} open log-only case(s)</a>'
                        if hidden_log else "")
    return "Cases", (f'<h1>Cases</h1><p class="sub">Triage queue for everything tapwatch has raised · {shown}</p>'
                     f'<div class="tiles">{tiles}</div><div class="pills">{pills}</div>{filters}{table}')


NOTE_ORDERS = {"oldest": "Oldest first", "newest": "Newest first"}


def render_case(store: Store, assets: Assets, case_id: int, zeek_dirs, csrf: str,
                params: dict | None = None) -> tuple[str, str] | None:
    r = store.get(case_id)
    if r is None:
        return None
    facts = json.loads(r["facts"])
    indicators = json.loads(r["indicators"])
    verdict = json.loads(r["verdict"]) if r["verdict"] else None

    def fact_value(k, v) -> str:
        if k == "host_program_path" and isinstance(v, str):  # the path names the user: the file name only
            return e(v.replace("\\", "/").rsplit("/", 1)[-1])
        if k == "correlated" and isinstance(v, list):  # pipeline.correlate: the other side of the story, as links
            return " · ".join(f'<a href="/case/{int(p["id"])}">#{int(p["id"])}</a> {e(p.get("detector", ""))} '
                              f'({e(str(p.get("route", "")))}, {abs(int(p.get("minutes", 0)))} min)'
                              for p in v if isinstance(p, dict) and str(p.get("id", "")).isdigit())
        return e(v)

    fact_rows = "".join(f'<dt>{e(k)}</dt><dd class="mono">{fact_value(k, v)}</dd>' for k, v in facts.items())
    untrusted = ("<ul>" + "".join(f'<li class="mono">{e(i)}</li>' for i in indicators) + "</ul>") if indicators \
        else '<span class="muted">none</span>'
    sev, sev_cls = severity(r)
    accent = "critical" if r["must_alert"] else r["route"]
    hero = f"""<div class="card accent-{e(accent)}">
<div class="bar">{badge(r["route"])} {badge(r["status"])} {badge(r["disposition"]) if r["disposition"] else ""}
{badge(sev_cls, "severity " + sev)}{' <span class="badge b-critical">always alerts</span>' if r["must_alert"] else ""}</div>
<h1>#{r["id"]} {e(r["title"])}</h1>
<p class="sub">{e(r["detector"])} · {e(r["reason"])}</p></div>"""
    conf = verdict.get("category_confidence") if verdict else None
    tiles = (tile(r["hits"], "Hits", "blue", "same thing, deduplicated")
             + tile(when(r["first_ts"])[11:16], "First seen", "violet", when(r["first_ts"])[:10])
             + tile(when(r["last_ts"])[11:16], "Last seen", "violet", when(r["last_ts"])[:10])
             + (tile(_pct(conf), "Jev confidence", "amber", verdict.get("category", "")) if verdict
                else tile("–", "Jev", "green", "not asked")))
    summary = f"""<div class="card"><h2>Details</h2><dl>
<dt>Device</dt><dd>{device(assets, r["host"], facts)}</dd>
<dt>Detector</dt><dd class="mono">{e(r["detector"])}</dd>
<dt>Route</dt><dd>{badge(r["route"])} {e(r["reason"])}</dd>
<dt>First seen</dt><dd class="tnum">{e(when(r["first_ts"]))}</dd>
<dt>Last seen</dt><dd class="tnum">{e(when(r["last_ts"]))}</dd>
<dt>Seen in traffic</dt><dd><div class="untrusted">{untrusted}<span class="faint">untrusted, copied from the network</span></div></dd>
{fact_rows}</dl></div>"""

    if verdict:
        def meter(name: str, key: str, tone: str) -> str:
            v = verdict.get(key)
            frac = v if isinstance(v, (int, float)) else 0
            return f'<dt>{e(name)}</dt><dd class="meter">{hbar(frac, tone, 120)} <span class="tnum">{e(_pct(v))}</span></dd>'

        sev_v = verdict.get("severity")
        answers = (f"<dl><dt>category</dt><dd>{badge('ai', verdict.get('category'))}</dd>"
                   + meter("confidence", "category_confidence", "amber")
                   + f'<dt>severity</dt><dd class="meter">{hbar((sev_v or 0) / 4, "red", 120)} '
                     f'<span class="tnum">{e(_num(sev_v))} / 4</span></dd>'
                   + meter("routine", "routine", "green") + meter("page_admin", "page_admin", "red")
                   + f"<dt>model</dt><dd class=\"mono\">{e(verdict.get('model'))}</dd></dl>")
    else:
        answers = '<p class="muted">Jev wasn\'t asked (always-alert, code-routed, suppressed, or AI off).</p>'
    jev = f"""<div class="grid2">{summary}<div class="card"><h2>Jev's answers</h2>{answers}
<h2>What Jev saw</h2><pre>{e(r["state"])}</pre></div></div>"""

    allowed = [r["status"], *sorted(TRANSITIONS[r["status"]], key=STATUSES.index)]
    workflow = f"""<div class="card"><h2>Work this case</h2>
<form method="post" action="/case/{r["id"]}/update">{csrf_field(csrf)}
<div class="filters">
<label class="f">Status<select name="status">{options(allowed, r["status"])}</select></label>
<label class="f">Disposition<select name="disposition"><option value="">(none yet)</option>
{options(DISPOSITIONS, r["disposition"] or "")}</select></label></div>
<p><label class="f">Note<textarea name="note" maxlength="{MAX_NOTE}" placeholder="What did you find?"></textarea></label></p>
<button>Save</button></form></div>"""

    shadow = _judge_closed_card(store, r, csrf) + _judge_card(store.judge_decision(case_id))
    order = (params or {}).get("notes", ["oldest"])[0]
    order = order if order in NOTE_ORDERS else "oldest"
    notes = store.notes(case_id)
    if order == "newest":
        notes = notes[::-1]
    note_pills = '<div class="pills">' + "".join(
        f'<a class="pill{" on" if k == order else ""}" href="/case/{r["id"]}?notes={k}#notes">{v}</a>'
        for k, v in NOTE_ORDERS.items()) + "</div>" if len(notes) > 1 else ""  # only worth it with two or more
    notes_html = "".join(f'<div class="card note"><div class="faint">{e(when(n["ts"]))} · {e(n["actor"])}</div>'
                         f'<pre>{e(n["text"])}</pre></div>' for n in notes) or '<div class="card empty">No notes yet.</div>'

    return f"Case #{r['id']}", (
        f'<p class="sub"><a href="/">← Cases</a></p>{hero}<div class="tiles">{tiles}</div>{jev}'
        f'<div class="grid2"><div>{workflow}{shadow}{_suppress_form(r, facts, indicators, csrf)}</div>'
        f'<div><h2 id="notes">Notes</h2>{note_pills}{notes_html}</div></div>'
        f'{_evidence(r, zeek_dirs)}{_audit(store.audit_trail(case_id))}')


def _links(ids) -> str:
    return " ".join(f'<a href="/case/{int(i)}">#{int(i)}</a>' for i in ids if isinstance(i, int))


def _judge_closed_card(store: Store, r, csrf: str) -> str:
    """#204: the judge closed this case. Says why, names the precedent, and offers the one-click undo."""
    c = judge.closure(store.db, r["id"])
    if c is None:
        return ""
    try:
        ids = json.loads(c["precedent_ids"] or "[]")
    except ValueError:
        ids = []
    where = "same device" if c["width"] == "device" else "any device"
    head = (f'<div class="card accent-digest"><h2>Closed by the judge</h2><p>{e(when(c["ts"]))} · auto-close at '
            f'{e(where)} width · {e(c["model_version"])}</p><p>{e(c["explanation"])}</p>'
            + (f'<p class="faint">Precedent: {_links(ids)}</p>' if ids else ""))
    if c["undone_ts"] is not None:
        how = {"undo": "undone", "reopened": "reopened", "true_positive": "called a true positive"}.get(
            c["undone_how"], c["undone_how"])
        return head + f'<p class="faint">{e(how)} by {e(c["undone_by"])} at {e(when(c["undone_ts"]))}</p></div>'
    if r["status"] != "closed" or r["disposition"] != "benign_expected":
        return head + "</div>"
    return head + (f'<form method="post" action="/case/{r["id"]}/undo-judge">{csrf_field(csrf)}'
                   '<button>Undo the judge\'s close</button> <span class="faint">back to investigating, its '
                   'disposition cleared; the judge counts it against itself</span></form></div>')


def render_judge(store: Store, settings: judge.Settings, csrf: str) -> tuple[str, str]:
    """#204: everything the judge closed, newest first, grouped by day with an undo for each day; back-off state."""
    rows = judge.closures(store.db, JUDGE_LIST)
    backoffs = store.db.execute("SELECT * FROM judge_backoff ORDER BY id DESC LIMIT 20").fetchall()
    open_n = sum(1 for r in rows if r["undone_ts"] is None)
    undone = len(rows) - open_n
    tiles = (tile(len(rows), "Closed by the judge", "violet", f"the newest {JUDGE_LIST}" if len(rows) >= JUDGE_LIST
                  else "")
             + tile(undone, "Undone or reopened", "amber" if undone else "green", "the owner disagreed")
             + tile(sum(1 for b in backoffs if b["lifted_ts"] is None), "Backed off", "red", "detectors stopped"))
    status = f'<div class="card"><h2>Auto-close</h2><p>{e(settings.summary())}.</p>'
    if not settings.auto_close:
        status += ('<p class="faint">Off by default. To turn it on for one detector, set <span class="mono">'
                   'judge.auto_close: true</span> and list it in <span class="mono">judge.auto_close_detectors'
                   '</span> in config.yaml, then restart <span class="mono">tapwatch run</span>. It still closes '
                   'nothing until the scorecard on the Stats page says that detector qualifies.</p>')
    detectors = judge.AutoClose(settings).status(store.db) if settings.auto_close else {}
    if detectors:   # closing, or in plain words why not (backed off, or not qualifying)
        status += "<dl>" + "".join(f'<dt class="mono">{e(d)}</dt><dd>{e(t)}</dd>' for d, t in detectors.items()) + "</dl>"
    status += "</div>"
    bo = ""
    if backoffs:
        bo = ('<h2>Back-off</h2><div class="card flush scroll"><table><thead><tr><th>detector</th><th>stopped</th>'
              '<th>why</th><th>resumed</th></tr></thead><tbody>' + "".join(
                  f'<tr><td class="mono">{e(b["detector"])}</td><td class="tnum">{e(when(b["since_ts"]))}</td>'
                  f'<td>{e(b["reason"])}</td><td>{e(when(b["lifted_ts"])) + " · " + e(b["lifted_reason"]) if b["lifted_ts"] else "not yet"}</td></tr>'
                  for b in backoffs) + "</tbody></table></div>")
    if not rows:
        listing = '<div class="card empty">The judge has closed nothing.</div>'
    else:
        days: dict[str, list] = {}
        for r in rows:
            days.setdefault(datetime.fromtimestamp(r["ts"]).strftime("%Y-%m-%d"), []).append(r)
        listing = ""
        for day, rs in days.items():
            live = [r for r in rs if r["undone_ts"] is None and r["status"] == "closed"
                    and r["disposition"] == "benign_expected"]
            undo_day = (f'<form method="post" action="/judge/undo-day">{csrf_field(csrf)}<input type="hidden" '
                        f'name="day" value="{e(day)}"><button>Undo all {len(live)} from this day</button></form>'
                        if live else "")
            body = "".join(
                f'<tr><td class="num"><a href="/case/{r["case_id"]}">#{r["case_id"]}</a></td>'
                f'<td><a class="title" href="/case/{r["case_id"]}">{e(r["title"])}</a></td>'
                f'<td class="mono">{e(r["detector"])}</td><td>{e(r["width"].replace("_", " "))}</td>'
                f'<td>{badge(r["status"])}</td>'
                f'<td>{e(r["undone_how"] + " by " + r["undone_by"]) if r["undone_ts"] else ""}</td>'
                f'<td class="faint tnum">{e(when(r["ts"])[11:16])}</td></tr>' for r in rs)
            listing += (f'<div class="bar"><h2>{e(day)} · {len(rs)}</h2>{undo_day}</div>'
                        f'<div class="card flush scroll"><table><thead><tr><th class="num">#</th><th>case</th>'
                        f'<th>detector</th><th>width</th><th>status</th><th>undone</th><th>closed</th></tr></thead>'
                        f'<tbody>{body}</tbody></table></div>')
    return "Judge", (f'<h1>What the judge closed</h1><p class="sub">Every case auto-close closed, and whether you undid '
                     f'it · {open_n} still closed</p><div class="tiles">{tiles}</div>{status}{bo}{listing}')


def _undo_day(store: Store, day: str, actor: str) -> list[str]:
    """Undo every judge close made on `day` (local YYYY-MM-DD) that is still as the judge left it. Returns errors."""
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", day or ""):
        raise WorkflowError("pick a day")
    errors = []
    for r in judge.closures(store.db, limit=100_000):
        if datetime.fromtimestamp(r["ts"]).strftime("%Y-%m-%d") != day or r["undone_ts"] is not None \
                or r["status"] != "closed" or r["disposition"] != "benign_expected":
            continue
        try:
            store.undo_judge_close(r["case_id"], actor)
        except WorkflowError as err:
            errors.append(str(err))
    return errors


def _judge_card(d) -> str:
    """The shadow judge's answer (#202): what it would do and the cases it learned from. It never acts."""
    if d is None:
        return ""
    try:
        widths = json.loads(d["widths"] or "{}")
    except (ValueError, IndexError, KeyError):   # a malformed or older row: no card rather than a broken page
        return ""
    labels = {"device": "Same device", "any_device": "Any device"}
    rows = ""
    for width, w in widths.items():
        links = " ".join(f'<a href="/case/{int(i)}">#{int(i)}</a>' for i in w.get("precedent_ids", [])
                         if isinstance(i, int))
        verdict = "would close as noise" if w.get("eligible") else f"leave it: {w.get('reason')}"
        rows += f"<dt>{e(labels.get(width, width))}</dt><dd>{e(verdict)}{' · ' + links if links else ''}</dd>"
    return (f'<div class="card"><h2>Judge (shadow)</h2><p class="faint">What the learned judge would do. It only '
            f'records this; nothing is closed. {e(d["model_version"])}</p><dl>{rows}</dl></div>')


def _pct(v) -> str:
    return f"{v:.0%}" if isinstance(v, (int, float)) else "?"


def _num(v) -> str:
    return f"{v:.1f}" if isinstance(v, (int, float)) else "?"


def _suppress_form(r, facts: dict, indicators: list, csrf: str) -> str:
    if r["must_alert"]:
        return ('<div class="card"><h2>Suppress similar</h2><p class="muted">Always-alert cases (threat-list hits, '
                'IDS severity 1) can never be suppressed.</p></div>')
    from .detectors import base_domain
    from .models import device_id, main_indicator

    ind = main_indicator(indicators, facts)
    port = facts.get("port")
    dom = base_domain(ind) if ind and "." in ind else ""
    # The rule is keyed on the device identity (name:<DHCP hostname>, mac:<address> or the IP), so say
    # which one it will follow when that isn't the address.
    dev = device_id(r["host"], facts)
    this = f"this device ({dev}, {r['host']})" if dev != r["host"] else f"this device ({r['host']})"
    choices = []
    if facts.get("host_program_path"):  # host context tied every connection to one program
        name = str(facts["host_program_path"]).replace("\\", "/").rsplit("/", 1)[-1]  # the path names the user
        choices.append(("device_program", f"{r['detector']} + {this} + program {name}"))
    if ind:
        choices.append(("device_indicator", f"{r['detector']} + {this} + {ind}"))
        if dom and dom != ind:  # a named host: offer its whole domain too (zone-02 after zone-01)
            choices.append(("device_domain", f"{r['detector']} + {this} + any host under {dom}"))
        choices.append(("indicator", f"{r['detector']} + {ind}, any device"))
        if dom and dom != ind:
            choices.append(("domain", f"{r['detector']} + any host under {dom}, any device"))
    if isinstance(port, int):
        choices.append(("port", f"{r['detector']} + port {port}, any device"))
    if not choices:
        return ""
    radios = "".join(f'<label class="scope"><input type="radio" name="scope" value="{e(s)}"{" checked" if i == 0 else ""}>'
                     f'<span class="mono">{e(text)}</span></label>' for i, (s, text) in enumerate(choices))
    return f"""<div class="card"><h2>Suppress similar</h2>
<form method="post" action="/case/{r["id"]}/suppress">{csrf_field(csrf)}
<p class="muted">Matching future cases are logged and arrive already closed as benign_expected, with the rule in a note. Always-alert cases are never suppressed.</p>
{radios}
<div class="filters"><label class="f">Reason (required)<input name="reason" required maxlength="500" size="30"></label>
<label class="f">Expires in days<input name="days" type="number" min="0.01" max="3650" step="any" placeholder="never"></label>
<label class="f"><input type="checkbox" name="close" value="1" checked> Close this case as benign_expected</label>
<button>Create rule</button></div></form></div>"""


def _evidence(r, zeek_dirs) -> str:
    if not evidence.expand_dirs(zeek_dirs):
        return ('<h2>Evidence</h2><div class="card empty">No Zeek log directory configured or found. Set '
                '<code>ui.zeek_dirs</code> in config.yaml or pass <code>--zeek-dir</code>.</div>')
    found = evidence.lookup(zeek_dirs, r["host"], r["first_ts"])
    intro = (f'<h2>Evidence</h2><p class="muted">Zeek records for {e(r["host"])} within ±{evidence.WINDOW // 60} '
             f'minutes of {e(when(r["first_ts"]))}. All values are copied from the network.</p>')
    out = [intro]
    for kind, cols in evidence.COLUMNS.items():
        rows, more = found[kind]["rows"], found[kind]["more"]
        head = "".join(f"<th>{e(c)}</th>" for c, _ in cols)
        body = "".join("<tr><td class=\"faint tnum\">" + e(when(rec["ts"])[11:19]) + "</td>"
                       + "".join(f'<td class="mono">{e(_cell(rec.get(field)))}</td>' for _, field in cols) + "</tr>"
                       for rec in rows)
        note = f' <span class="faint">first {len(rows)} shown</span>' if more else ""
        out.append(f'<div class="card flush"><div class="card-head"><b class="mono">{e(kind)}.log</b> '
                   f'<span class="badge b-new">{len(rows)} row(s)</span>{note}</div>'
                   + (f'<div class="scroll"><table><thead><tr><th>time</th>{head}</tr></thead><tbody>{body}</tbody>'
                      f'</table></div>' if rows else "") + "</div>")
    return "".join(out)


def _cell(v) -> str:
    if isinstance(v, float):
        return f"{v:.3f}".rstrip("0").rstrip(".")
    if isinstance(v, list):
        return ", ".join(str(x) for x in v)
    return "" if v is None else str(v)


def _audit(trail) -> str:
    if not trail:
        return '<h2>Audit trail</h2><div class="card empty">No changes yet.</div>'
    rows = "".join(f'<tr><td class="faint tnum">{e(when(a["ts"]))}</td><td>{e(a["actor"])}</td><td><b>{e(a["action"])}</b></td>'
                   f'<td>{e(_audit_value(a, "old"))}</td><td>{e(_audit_value(a, "new"))}</td></tr>'
                   for a in trail)
    return (f'<h2>Audit trail</h2><div class="card flush scroll"><table><thead><tr><th>when</th><th>who</th><th>what</th>'
            f'<th>from</th><th>to</th></tr></thead><tbody>{rows}</tbody></table></div>')


def _audit_value(a, which: str) -> str:
    return label(a[which]) if a["action"] in ("status", "disposition") else (a[which] or "")


def render_suppressions(store: Store, csrf: str) -> tuple[str, str]:
    now = time.time()
    rules = store.suppressions()
    rows = []
    live = 0
    for s in rules:
        expired = s["expires_ts"] is not None and s["expires_ts"] <= now
        live += not expired
        expires = badge("none", "never") if s["expires_ts"] is None else \
            badge("log", "expired") if expired else f'<span class="tnum">{e(when(s["expires_ts"]))}</span>'
        rows.append(f'<tr><td class="mono">{e(describe_rule(s))}</td><td>{e(s["reason"])}</td>'
                    f'<td class="num"><b>{s["hits"]}</b></td><td class="faint tnum hide-sm">{e(when(s["last_hit_ts"]))}</td>'
                    f'<td class="faint tnum hide-sm">{e(when(s["created_ts"]))}</td><td>{expires}</td>'
                    f'<td><form method="post" action="/suppressions/{s["id"]}/delete">{csrf_field(csrf)}'
                    f'<button class="danger">Delete</button></form></td></tr>')
    tiles = (tile(live, "Active rules", "green") + tile(len(rules) - live, "Expired", "amber")
             + tile(sum(s["hits"] for s in rules), "Cases silenced", "violet", "logged, not alerted"))
    table = (f'<div class="card flush scroll"><table><thead><tr><th>rule</th><th>reason</th><th class="num">hits</th>'
             f'<th class="hide-sm">last hit</th><th class="hide-sm">created</th><th>expires</th><th></th></tr></thead>'
             f'<tbody>{"".join(rows)}</tbody></table></div>') if rows else \
        '<div class="card empty">No suppression rules yet. Create one from a case page with "Suppress similar".</div>'
    return "Suppressions", ('<h1>Suppressions</h1><p class="sub">Cases matching a rule go to log only. Always-alert '
                            'cases are never suppressed. <code>tapwatch run</code> checks rules for every new case.</p>'
                            f'<div class="tiles">{tiles}</div>{render_explained(store, csrf)}{table}')


def render_explained(store: Store, csrf: str) -> str:
    """`tapwatch explain`'s suggestions (#12): groups of 3+ cases in 30 days, every one assessed likely benign on
    the PC, one program. Each Apply makes the same program-scoped rule as `explain --apply` (30 days) and closes
    the group's open cases, audited under the user who pressed it."""
    from . import explain
    sugg = explain.suggestions(store)
    if not sugg:
        return ""
    rows = []
    for g in sugg:
        program = explain.program_name(g["program"])   # the name only: the path holds the user's name
        rows.append(f'<tr><td class="mono">{e(g["detector"])}</td><td class="mono">{e(g["host"])}</td>'
                    f'<td class="mono">{e(program)}</td><td class="mono">{e(g["destination"])}</td>'
                    f'<td class="num"><b>{g["cases"]}</b> <span class="faint">({len(g["open"])} open)</span></td>'
                    f'<td>{e(explain.reason(g, name_only=True))}</td>'
                    f'<td><form method="post" action="/explain/{explain.group_key(g)}/apply">{csrf_field(csrf)}'
                    f'<button>Apply</button></form></td></tr>')
    return ('<h2 id="explained">Explained by host context</h2><p class="sub">Cases that keep firing for one program '
            'the PC checked and found benign. Apply makes a 30-day rule for that program on that device and closes '
            'the open cases.</p><div class="card flush scroll"><table><thead><tr><th>rule</th><th>device</th>'
            '<th>program</th><th>destination</th><th class="num">cases</th><th>reason</th><th></th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table></div>')


CONF_BUCKETS = [(0.0, 0.6, "under 60%"), (0.6, 0.8, "60–80%"), (0.8, 0.9, "80–90%"), (0.9, 1.01, "90–100%")]


NOW = ' class="now"'   # the last label on a chart: today


def _points(values: list, width: float, height: float, top: float | None = None, pad: float = 2) -> list[tuple]:
    """(x, y) for each value, spread over width, scaled to top (the largest value by default). None is skipped."""
    top = top or max([v for v in values if v is not None] or [1]) or 1
    n = max(len(values) - 1, 1)
    return [(round(i * width / n, 2), round(pad + (height - 2 * pad) * (1 - v / top), 2))
            for i, v in enumerate(values) if v is not None]


def sparkline(values: list, height: int = 26) -> str:
    """A tile's trend line: no axes, the area under it lightly filled (homebase's spark)."""
    pts = _points(values, 100, height)
    if len(pts) < 2:
        return ""
    line = " ".join(f"{x},{y}" for x, y in pts)
    return (f'<svg class="spark" viewBox="0 0 100 {height}" height="{height}" preserveAspectRatio="none" aria-hidden="true">'
            f'<polygon points="{pts[0][0]},{height} {line} {pts[-1][0]},{height}"/><polyline points="{line}"/></svg>')


def stacked_chart(labels: list[str], series: list[tuple[str, list[int]]], height: int = 190, every: int = 5,
                  what: str = "cases", width: int = 1300) -> str:
    """Columns stacked by series (class s-<name>), one per label, with a hover title per column. width is the
    viewBox's: about the card's width in pixels, so the labels come out at the page's text size."""
    n = max(len(labels), 1)
    left, base = 34, height - 22
    totals = [sum(vals[i] for _, vals in series) for i in range(n)]
    top = max(totals or [1]) or 1
    slot = (width - left) / n
    parts = [f'<line class="grid" x1="{left}" x2="{width}" y1="{base}" y2="{base}"/>',
             f'<line class="grid" x1="{left}" x2="{width}" y1="8" y2="8"/>',
             f'<text x="{left - 6}" y="12" text-anchor="end">{top}</text>',
             f'<text x="{left - 6}" y="{base}" text-anchor="end">0</text>']
    for i in range(n):
        x, w, y = round(left + i * slot + slot * 0.16, 1), round(slot * 0.68, 1), base
        tip = f"{labels[i]}: {totals[i]} {what}" + "".join(f", {vals[i]} {name}" for name, vals in series if vals[i])
        parts.append(f"<g><title>{e(tip)}</title>")
        for name, vals in series:
            h = (base - 8) * vals[i] / top
            if h > 0:
                parts.append(f'<rect class="s-{e(name)}" x="{x}" y="{round(y - h, 1)}" width="{w}" height="{round(h, 1)}"/>')
                y -= h
        parts.append("</g>")
        if i % every == 0 or i == n - 1:
            parts.append(f'<text x="{round(left + i * slot + slot / 2, 1)}" y="{height - 4}" '
                         f'text-anchor="middle"{NOW if i == n - 1 else ""}>{e(labels[i])}</text>')
    return (f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" aria-label="{e(what)} over time">'
            f'{"".join(parts)}</svg>')


def line_chart(labels: list[str], values: list[int], height: int = 150, every: int = 5, what: str = "",
               width: int = 1300) -> str:
    """An area line over the labels, with the last value marked (width as in stacked_chart)."""
    left, base = 34, height - 22
    top = max(values or [1]) or 1
    pts = [(round(left + x * (width - left) / width, 2), y) for x, y in _points(values, width, base, top, pad=8)]
    if len(pts) < 2:
        return '<div class="empty">Not enough days yet.</div>'
    line = " ".join(f"{x},{y}" for x, y in pts)
    n = len(labels)
    ticks = "".join(f'<text x="{pts[i][0]}" y="{height - 4}" text-anchor="middle"'
                    f'{NOW if i == n - 1 else ""}>{e(labels[i])}</text>'
                    for i in range(n) if i % every == 0 or i == n - 1)
    dots = "".join(f'<circle cx="{x}" cy="{y}" r="7" opacity="0"><title>{e(labels[i])}: {values[i]} {e(what)}</title></circle>'
                   for i, (x, y) in enumerate(pts))
    return (f'<svg class="line chart" viewBox="0 0 {width} {height}" role="img" aria-label="{e(what)}">'
            f'<line class="grid" x1="{left}" x2="{width}" y1="{base}" y2="{base}"/>'
            f'<line class="grid" x1="{left}" x2="{width}" y1="8" y2="8"/>'
            f'<text x="{left - 6}" y="12" text-anchor="end">{top}</text><text x="{left - 6}" y="{base}" text-anchor="end">0</text>'
            f'<polygon points="{pts[0][0]},{base} {line} {pts[-1][0]},{base}"/><polyline points="{line}"/>'
            f'<circle cx="{pts[-1][0]}" cy="{pts[-1][1]}" r="4"/>{dots}{ticks}</svg>')


def ranks(rows: list[tuple[str, str, str, float, str]]) -> str:
    """A ranked list: (label html, small text, count html, fraction of the longest bar, tone) per row."""
    if not rows:
        return '<div class="empty">Nothing yet.</div>'
    return '<div class="ranks">' + "".join(
        f'<div class="rank"><div class="who">{who}{f"<small>{e(sub)}</small>" if sub else ""}</div>'
        f'<div class="n">{n}</div>'
        f'<svg viewBox="0 0 100 6" preserveAspectRatio="none" aria-hidden="true"><rect class="track" width="100" height="6" rx="3"/>'
        f'<rect class="fill-{tone}" width="{max(1.5, round(100 * frac, 1))}" height="6" rx="3"/></svg></div>'
        for who, sub, n, frac, tone in rows) + "</div>"


def column_chart(values: list[int], labels: list[str], height: int = 170) -> str:
    """Bar chart as inline SVG. Sizes are SVG attributes, so the CSP needs no inline styles."""
    n = max(len(values), 1)
    width, left, base = 1300, 34, height - 22
    top = max(values or [1]) or 1
    slot = (width - left) / n
    parts = [f'<line class="grid" x1="{left}" x2="{width}" y1="{base}" y2="{base}"/>',
             f'<line class="grid" x1="{left}" x2="{width}" y1="8" y2="8"/>',
             f'<text x="{left - 6}" y="12" text-anchor="end">{top}</text>',
             f'<text x="{left - 6}" y="{base}" text-anchor="end">0</text>']
    for i, v in enumerate(values):
        h = round((base - 8) * v / top)
        x = round(left + i * slot + slot * 0.18, 1)
        parts.append(f'<rect class="bar-r" x="{x}" y="{base - h}" width="{round(slot * 0.64, 1)}" height="{h}" rx="2">'
                     f'<title>{e(labels[i])}: {v}</title></rect>')
        if i % max(1, n // 12) == 0:
            parts.append(f'<text x="{round(left + i * slot + slot / 2, 1)}" y="{height - 4}" '
                         f'text-anchor="middle">{e(labels[i])}</text>')
    return (f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" aria-label="cases over time">'
            f'{"".join(parts)}</svg>')


def render_stats(store: Store, qualify: benchmark.Qualify | None = None, assets: Assets | None = None) -> tuple[str, str]:
    db = store.db
    total = db.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
    # The owner's dispositions only: a judge auto-close (#204) is counted on its own tile, never as the owner's call.
    # The SQL below joins only the fixed constants BUCKETS and OWNER_DISPOSITION.
    # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query
    decided_all = db.execute(f"SELECT COUNT(*) FROM cases WHERE {BUCKETS['decided']}").fetchone()[0]
    # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query
    noisy_all = db.execute(f"SELECT COUNT(*) FROM cases WHERE {BUCKETS['noise']}").fetchone()[0]
    tp_all = db.execute("SELECT COUNT(*) FROM cases WHERE disposition = 'true_positive'").fetchone()[0]
    # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query
    judge_all = db.execute(f"SELECT COUNT(*) FROM cases WHERE {JUDGE_DECIDED}").fetchone()[0]
    triaged = db.execute("SELECT COUNT(*) FROM cases WHERE verdict IS NOT NULL").fetchone()[0]
    sup_hits = db.execute("SELECT COALESCE(SUM(hits), 0) FROM suppressions").fetchone()[0]

    def bucket(**f) -> str:  # every tile opens the cases it counts: all statuses and routes, newest first
        return "/?" + urlencode({"status": "all", "route": "all", **f})

    tiles = (tile(total, "Cases", "blue", "all time", bucket())
             + tile(f"{decided_all / total:.0%}" if total else "–", "Dispositioned", "violet", f"{decided_all} decided",
                    bucket(disposition="decided"))
             + tile(f"{noisy_all / decided_all:.0%}" if decided_all else "–", "Noise rate", "amber",
                    "FP + benign of decided", bucket(disposition="noise"))
             + tile(tp_all, "True positives", "red" if tp_all else "green", "", bucket(disposition="true_positive"))
             + tile(triaged, "Jev triaged", "violet", "verdict recorded", bucket(triaged="1"))
             + tile(sup_hits, "Suppressed", "green", "rule hits", "/suppressions")
             + (tile(judge_all, "Closed by the judge", "violet", "not counted as your decisions", "/judge")
                if judge_all else ""))

    # Cases per hour, last 48 hours
    now = time.time()
    hour0 = int(now // 3600) - 47
    counts = dict(db.execute("SELECT CAST(first_ts / 3600 AS INTEGER) AS h, COUNT(*) FROM cases WHERE first_ts >= ? "
                             "GROUP BY h", (hour0 * 3600,)).fetchall())
    hours = list(range(hour0, hour0 + 48))
    chart = column_chart([counts.get(h, 0) for h in hours],
                         [datetime.fromtimestamp(h * 3600).strftime("%H:00") for h in hours])

    # Cases per detector per day (last 14 days that had cases)
    per_day = db.execute("SELECT detector, date(first_ts, 'unixepoch', 'localtime') AS day, COUNT(*) AS n "
                         "FROM cases GROUP BY detector, day").fetchall()
    days = sorted({r["day"] for r in per_day})[-14:]
    grid: dict[str, dict[str, int]] = {}
    for r in per_day:
        grid.setdefault(r["detector"], {})[r["day"]] = r["n"]
    peak = max([n for d in grid.values() for n in d.values()] or [1])

    def heat(n: int) -> str:
        return "h0" if not n else f"h{min(3, 1 + int(3 * n / (peak + 1)))}"

    head = "".join(f'<th class="num">{e(d[5:])}</th>' for d in days)
    body = "".join(f'<tr><td class="mono">{e(det)}</td>' + "".join(
        f'<td class="num {heat(counts_.get(d, 0))}">{counts_.get(d, 0) or "·"}</td>' for d in days) + "</tr>"
        for det, counts_ in sorted(grid.items()))
    per_day_html = (f'<div class="card flush scroll"><table><thead><tr><th>detector</th>{head}</tr></thead>'
                    f'<tbody>{body}</tbody></table></div>') if grid else '<div class="card empty">No cases yet.</div>'

    # False-positive rate per detector, by disposition
    # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query -- a constant
    disp = db.execute(f"SELECT detector, COALESCE({OWNER_DISPOSITION}, '') AS d, COUNT(*) AS n FROM cases "
                      "GROUP BY detector, d").fetchall()
    by_det: dict[str, dict[str, int]] = {}
    for r in disp:
        by_det.setdefault(r["detector"], {})[r["d"]] = r["n"]
    fp_rows = []
    for det, c in sorted(by_det.items()):
        decided = sum(c.get(d, 0) for d in DISPOSITIONS)
        fp = c.get("false_positive", 0) / decided if decided else None
        noise = (c.get("false_positive", 0) + c.get("benign_expected", 0)) / decided if decided else None
        fp_rows.append(f'<tr><td class="mono"><a href="{e(bucket(detector=det))}">{e(det)}</a></td>'
                       f'<td class="num">{decided + c.get("", 0)}</td>'
                       f'<td class="num">{c.get("", 0)}</td>'
                       + "".join(f'<td class="num">{c.get(d, 0)}</td>' for d in DISPOSITIONS)
                       + f'<td class="num tnum">{_pct(fp) if fp is not None else "–"}</td>'
                       + (f'<td><span class="meter">{hbar(noise, "amber")} <span class="tnum">{_pct(noise)}</span></span></td>'
                          if noise is not None else '<td class="faint">–</td>') + '</tr>')
    fp_html = ('<div class="card flush scroll"><table><thead><tr><th>detector</th><th class="num">cases</th>'
               '<th class="num">undecided</th>' + "".join(f'<th class="num">{e(label(d))}</th>' for d in DISPOSITIONS)
               + '<th class="num">FP rate</th><th>FP + benign</th></tr></thead><tbody>'
               + "".join(fp_rows) + '</tbody></table><p class="pad faint">Rates are over cases with a disposition. '
               'FP rate counts false positives; "FP + benign" also counts expected benign activity.</p></div>') \
        if fp_rows else '<div class="card empty">No cases yet.</div>'

    # Jev confidence vs disposition
    conf: dict[str, dict[str, int]] = {b[2]: {} for b in CONF_BUCKETS}
    # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query -- a constant
    for r in db.execute(f"SELECT verdict, COALESCE({OWNER_DISPOSITION}, '') AS d FROM cases WHERE verdict IS NOT NULL"):
        c = json.loads(r["verdict"]).get("category_confidence")
        if not isinstance(c, (int, float)):
            continue
        bucket = next(b[2] for b in CONF_BUCKETS if b[0] <= c < b[1]) if c < 1.01 else CONF_BUCKETS[-1][2]
        conf[bucket][r["d"]] = conf[bucket].get(r["d"], 0) + 1
    conf_rows = []
    for bucket, c in conf.items():
        decided = sum(c.get(d, 0) for d in DISPOSITIONS)
        tp = c.get("true_positive", 0) / decided if decided else None
        conf_rows.append(f"<tr><td>{e(bucket)}</td>" + "".join(f'<td class="num">{c.get(d, 0)}</td>'
                                                               for d in (*DISPOSITIONS, ""))
                         + (f'<td><span class="meter">{hbar(tp, "green")} <span class="tnum">{_pct(tp)}</span></span></td>'
                            if tp is not None else '<td class="faint">–</td>') + "</tr>")
    conf_html = ('<div class="card flush scroll"><table><thead><tr><th>Jev category confidence</th>'
                 + "".join(f'<th class="num">{e(label(d))}</th>' for d in DISPOSITIONS)
                 + '<th class="num">undecided</th><th>% true positive</th></tr></thead><tbody>'
                 + "".join(conf_rows) + '</tbody></table><p class="pad faint">Only cases Jev triaged. A well-calibrated '
                 'model has more true positives in the higher-confidence rows.</p></div>')

    sup = store.suppressions()
    top_hits = max([s["hits"] for s in sup] or [1]) or 1
    sup_rows = "".join(f'<tr><td class="mono">{e(describe_rule(s))}</td><td>{e(s["reason"])}</td>'
                       f'<td><span class="meter">{hbar(s["hits"] / top_hits, "green")} <b class="tnum">{s["hits"]}</b></span></td>'
                       f'<td class="faint tnum hide-sm">{e(when(s["last_hit_ts"]))}</td></tr>'
                       for s in sorted(sup, key=lambda s: -s["hits"]))
    sup_html = (f'<div class="card flush scroll"><table><thead><tr><th>rule</th><th>reason</th><th>hits</th>'
                f'<th class="hide-sm">last hit</th></tr></thead><tbody>{sup_rows}</tbody></table></div>') if sup \
        else '<div class="card empty">No suppression rules.</div>'

    # Week by week: is the noise falling, is Jev agreeing more (benchmark.py; `tapwatch benchmark` prints the same)
    weeks = benchmark.weekly(db)[-12:]
    week_rows = "".join(
        f'<tr><td class="mono">{e(w["week"])}</td><td class="num">{w["cases"]}</td><td class="num">{w["alerts"]}</td>'
        f'<td class="num">{w["decided"]}</td>'
        + (f'<td><span class="meter">{hbar(w["noise_rate"], "amber")} <span class="tnum">{_pct(w["noise_rate"])}</span></span></td>'
           if w["noise_rate"] is not None else '<td class="faint">–</td>')
        + f'<td class="num">{w["true_positives"]}</td>'
        + (f'<td><span class="meter">{hbar(w["jev_agreement"], "green")} <span class="tnum">{_pct(w["jev_agreement"])}</span>'
           f' <span class="faint">of {w["jev_decided"]}</span></span></td>' if w["jev_agreement"] is not None else '<td class="faint">–</td>')
        + "</tr>" for w in weeks)
    week_html = ('<div class="card flush scroll"><table><thead><tr><th>week</th><th class="num">cases</th>'
                 '<th class="num">alerts</th><th class="num">decided</th><th>noise rate</th><th class="num">true positives</th>'
                 '<th>Jev agreed with you</th></tr></thead><tbody>' + week_rows + '</tbody></table>'
                 '<p class="pad faint">Noise rate is false positives plus expected benign activity over decided cases. '
                 'Jev agreement: it called a case benign exactly when you did, over decided cases it gave a category.</p></div>') \
        if weeks else '<div class="card empty">No cases yet.</div>'
    h = benchmark.host_context(db)
    who_rows = "".join(f'<tr><td class="mono">{e(label(k))}</td><td class="num">{v}</td></tr>' for k, v in sorted(h["who"].items()))
    host_html = (f'<div class="card flush scroll"><table><thead><tr><th>code said</th><th class="num">cases</th></tr></thead>'
                 f'<tbody>{who_rows}</tbody></table><p class="pad faint">{h["cases"]} cases on this PC, {h["corroborated"]} corroborated. '
                 f'Jev agreed with code on {_pct(h["jev_agreement"])} of the {h["jev_asked"]} it was asked. '
                 f'Where code claimed benign or hostile, your disposition agreed {_pct(h["accuracy"])} of {h["claims"]} times.</p></div>') \
        if h["cases"] else '<div class="card empty">No cases with host context yet.</div>'

    def more(title: str, hint: str, inner: str) -> str:   # a folded section: <details> needs no script
        return f'<details class="more"><summary>{e(title)} <small>{e(hint)}</small></summary>{inner}</details>'

    return "Stats", (f'<h1>Stats</h1><p class="sub">The last 30 days, then all time: how much arrives, how fast it '
                     f'gets decided, how noisy each detector is and how far to trust Jev</p>'
                     f"{_trends(db, assets or Assets())}"
                     f'<h2>All time</h2><div class="tiles">{tiles}</div>'
                     f"<h2>Week by week</h2>{week_html}"
                     f'<h2>Cases per hour · last 48 hours</h2><div class="card">{chart}</div>'
                     + more("Cases per detector per day", "the last 14 days with cases", per_day_html)
                     + more("False-positive rate per detector", f"{len(fp_rows)} detectors", fp_html)
                     + more("Jev confidence vs disposition", f"{triaged} triaged", conf_html)
                     + more("Host context: code, Jev and you", f"{h['cases']} cases on this PC", host_html)
                     + more("Judge scorecard (shadow)", "would-closes graded against you", _judge_scorecard(db, qualify))
                     + more("Suppression hits", f"{len(sup)} rules, {sup_hits} hits", sup_html))


def _hours(h: float | None) -> str:
    if h is None:
        return "–"
    return f"{round(h * 60)} min" if h < 1 else f"{h:.1f} h" if h < 48 else f"{h / 24:.1f} days"


def _trends(db, assets: Assets) -> str:
    """The Stats page's top half: 30-day tiles with sparklines, then volume, backlog, waits, hours and the busiest
    devices and detectors (deskstats has the queries)."""
    d = deskstats.daily(db)
    first = next((i for i, k in enumerate(d["days"]) if sum(d["routes"][k].values())), len(d["days"]) - 1)
    first = min(first, len(d["days"]) - 7)
    days, routes = d["days"][first:], d["routes"]
    per_day = [sum(routes[k].values()) for k in days]
    alerts = [routes[k]["alert"] for k in days]
    backlog = [d["backlog"][k] for k in days]
    decided, noise = sum(d["decided"].values()), sum(d["noise"].values())
    noise_daily = [d["noise"][k] / d["decided"][k] if d["decided"][k] else None for k in days]
    w = deskstats.waits(db)
    tps = sum(d["true_positives"].values())
    short = [k[5:] for k in days]

    def bucket(**f) -> str:
        return "/?" + urlencode({"status": "all", "route": "all", **f})

    # The 30-day tiles don't link: the queue has no date filter, and the all-time tiles below open their cases.
    tiles = (tile(sum(per_day), "Cases", "blue", f"{per_day[-1]} today", spark=per_day)
             + tile(sum(alerts), "Alerts", "red" if alerts[-1] else "green", f"{alerts[-1]} today", spark=alerts)
             + tile(backlog[-1], "Open backlog", "amber" if backlog[-1] else "green", "alert and digest cases",
                    "/?status=open", spark=backlog)
             + tile(f"{noise / decided:.0%}" if decided else "–", "Noise rate", "amber", f"of {decided} decided",
                    spark=noise_daily)
             + tile(_hours(w["median_h"]), "Time to decide", "violet", f"median of {w['timed']}")
             + tile(tps, "True positives", "red" if tps else "green", "last 30 days"))

    legend = ('<div class="legend"><span><i class="k-alert"></i>alert</span><span><i class="k-digest"></i>digest</span>'
              '<span><i class="k-log"></i>log only</span></div>')
    volume = stacked_chart(short, [(r, [routes[k][r] for k in days]) for r in deskstats.ROUTES], every=max(1, len(days) // 10))

    top_wait = max(w["hist"].values()) or 1
    waits_html = (f'<div class="headline"><div><span>median</span><b>{_hours(w["median_h"])}</b></div>'
                  f'<div><span>decided</span><b>{w["timed"]}</b></div>'
                  f'<div><span>still undecided</span><b>{w["undecided"]}</b></div></div>'
                  + ranks([(e(name), "", f"<b>{n}</b>", n / top_wait, "violet") for name, n in w["hist"].items()]))

    hod = deskstats.hour_of_day(db)
    hours_html = ('<div class="legend"><span><i class="k-alert"></i>alert</span><span><i class="k-other"></i>digest and log</span></div>'
                  + stacked_chart([f"{h:02d}" for h in range(24)], [("alert", hod["alert"]), ("other", hod["other"])],
                                  height=200, every=3, width=520))

    devs = deskstats.top(db, "host")
    most = max([r["cases"] for r in devs] or [1])

    def who(r) -> tuple[str, str]:
        try:
            facts = json.loads(r["facts"]) if r["facts"] else None
        except ValueError:
            facts = None
        name = assets.name(r["key"], facts)
        return (e(name), r["key"]) if name != r["key"] else (f'<span class="mono">{e(r["key"])}</span>', "")

    dev_rows = []
    for r in devs:
        name, sub = who(r)
        dev_rows.append((f'<a href="{e(bucket(device=r["key"]))}">{name}</a>', sub,
                         f'<b>{r["cases"]}</b>' + (f' · {r["alerts"]} alert{"s" * (r["alerts"] != 1)}' if r["alerts"] else ""),
                         r["cases"] / most, "red" if r["alerts"] else "accent"))
    dets = deskstats.top(db, "detector", limit=10)
    most_d = max([r["cases"] for r in dets] or [1])
    det_rows = [(f'<a class="mono" href="{e(bucket(detector=r["key"]))}">{e(r["key"])}</a>', "",
                 f'<b>{r["cases"]}</b>' + (f' · {r["noise"] / r["decided"]:.0%} noise' if r["decided"] else ""),
                 r["cases"] / most_d, "amber" if r["decided"] and r["noise"] / r["decided"] > .9 else "accent")
                for r in dets]

    disp = deskstats.dispositions(db)
    total30 = sum(disp.values()) or 1
    names = {"": "undecided", "judge": "closed by the judge"}
    disp_html = ranks([(badge("ai" if k == "judge" else k or "none", names.get(k, label(k))), "",
                        f"<b>{n}</b> · {n / total30:.0%}", n / total30,
                        {"true_positive": "red", "false_positive": "green", "benign_expected": "accent", "judge": "violet"}.get(k, "blue"))
                       for k, n in disp.items() if n or k != "judge"])

    return (f'<div class="tiles">{tiles}</div>'
            f'<h2>Cases a day · last {len(days)} days</h2><div class="card">{legend}{volume}</div>'
            f'<div class="grid2"><section><h2>Open backlog at the end of each day</h2><div class="card">'
            f'{line_chart(short, backlog, every=max(1, len(days) // 6), what="open", width=640, height=200)}</div></section>'
            f'<section><h2>Time to a disposition</h2><div class="card">{waits_html}</div></section></div>'
            f'<div class="grid3"><section><h2>When cases arrive · hour of day</h2><div class="card">{hours_html}</div></section>'
            f'<section><h2>Busiest devices</h2><div class="card">{ranks(dev_rows)}</div></section>'
            f'<section><h2>Busiest detectors</h2><div class="card">{ranks(det_rows)}</div></section></div>'
            f'<h2>How the last 30 days were decided</h2><div class="card">{disp_html}</div>')


def _judge_scorecard(db, qualify: benchmark.Qualify | None = None) -> str:
    """#203: the shadow judge graded against the owner, per detector and week at each key width (benchmark.judge;
    `tapwatch benchmark` prints the same). A true positive it would have closed is red: it disqualifies."""
    q = qualify or benchmark.Qualify()
    s = benchmark.judge(db, qualify=q)
    if not s["detectors"]:
        return ('<div class="card empty">No judge decisions yet. The shadow judge records one for every new case; '
                '<span class="mono">tapwatch benchmark --judge-replay</span> estimates the numbers from history.</div>')
    words = benchmark.WIDTH_WORDS

    def agree(t) -> str:
        if not t["decided"]:
            return '<td class="faint">–</td>'
        return (f'<td><span class="meter">{hbar(t["agreement"], "green")} <span class="tnum">{_pct(t["agreement"])}'
                f'</span> <span class="faint">of {t["decided"]}</span></span></td>')

    def cells(t) -> str:
        tp = (f'<b class="err">{t["tp_closed"]}</b> ' + " ".join(f'<a href="/case/{int(i)}">#{int(i)}</a>'
                                                                 for i in t["tp_ids"][:5])) if t["tp_closed"] else "0"
        return (f'<td class="num">{t["cases"]}</td><td class="num">{t["would_close"]}</td>{agree(t)}'
                f'<td class="num tnum">{_pct(t["saved"])} <span class="faint">of {t["cases"]}</span></td>'
                f'<td class="num">{tp}</td>')

    def tr(t) -> str:   # the red edge alert rows carry, on any row with a true positive it would have closed
        return '<tr class="r-alert">' if t["tp_closed"] else "<tr>"

    head = ('<th class="num">cases</th><th class="num">would close</th><th>you agreed</th><th class="num">load saved</th>'
            '<th class="num">true positives it would have closed</th>')
    det_rows = "".join(
        f'{tr(d)}<td class="mono">{e(d["detector"])}</td>'
        f'<td>{e(words.get(d["width"], d["width"]))}</td>{cells(d)}<td class="num">{d["weeks"]}</td>'
        f'<td>{badge("closed", "qualifies") if d["qualifies"] else e("no: " + d["why"])}</td></tr>'
        for d in s["detectors"])
    weeks = [w for w in s["weeks"] if w["detector"] is None]
    keep = sorted({w["week"] for w in weeks})[-12:]
    week_rows = "".join(
        f'{tr(w)}<td class="mono">{e(w["week"])}</td>'
        f'<td>{e(words.get(w["width"], w["width"]))}</td>{cells(w)}</tr>'
        for w in sorted(weeks, key=lambda w: (w["week"], s["widths"].index(w["width"]))) if w["week"] in keep)
    return (f'<div class="card flush scroll"><table><thead><tr><th>detector</th><th>width</th>{head}'
            f'<th class="num">weeks</th><th>auto-close?</th></tr></thead><tbody>{det_rows}</tbody></table>'
            f'<p class="pad faint">What the judge would have closed as noise, never acted on. "You agreed": of the '
            f'would-close cases you decided yourself (not an AI or tapwatch), the share you also called noise. Load '
            f'saved is would-close over all cases it judged; the judge\'s own closes never count as agreement. '
            f'Qualifying for auto-close (judge.qualify): at least {q.min_decided} would-close cases you decided, in '
            f'at least {q.min_weeks} weeks, {q.min_agreement:.0%} agreement and '
            f'{"no true positive" if not q.max_tp else f"at most {q.max_tp} true positive(s)"} it would have '
            f'closed. Qualifying closes nothing by itself: auto-close is off until judge.auto_close is on and you '
            f'list the detector in judge.auto_close_detectors. <a href="/judge">What the judge closed</a>.</p></div>'
            f'<div class="card flush scroll"><table><thead><tr><th>week</th><th>width</th>{head}</tr></thead>'
            f'<tbody>{week_rows}</tbody></table><p class="pad faint">All detectors together, by the week each case '
            f'happened. <span class="mono">tapwatch benchmark</span> has every week per detector.</p></div>')


# ---------------------------------------------------------------- server

class App:
    """Settings and session state shared by every request."""

    def __init__(self, db_path: str, assets: Assets, zeek_dirs=None, host: str = "127.0.0.1", port: int = 8765,
                 token: str | None = None, base_url: str | None = None, tailscale_users=None,
                 judge_settings: judge.Settings | None = None, home_url: str | None = None,
                 home_label: str | None = None):
        self.judge = judge_settings or judge.Settings()   # #204: shown on the Judge page; the desk never closes
        if home_url and not re.match(r"https?://", home_url, re.IGNORECASE):
            raise SystemExit("ui.home_url must start with http:// or https://")
        self.home = (home_url, home_label or "Home") if home_url else None
        # Behind `tailscale serve`: Tailscale authenticates, and the desk only listens on loopback.
        self.tailscale_users = {u.strip().lower() for u in tailscale_users or () if u.strip()} or None
        if self.tailscale_users:
            if not is_loopback(host):
                raise SystemExit("ui.tailscale_users needs ui.host 127.0.0.1: `tailscale serve` is the only way in")
            token = None  # Tailscale's identity replaces the token login
        if not is_loopback(host) and not token:
            raise SystemExit("--host other than 127.0.0.1 needs TAPWATCH_UI_TOKEN set (in .env) for the login form")
        if token is not None and len(token) < 16:
            raise SystemExit("TAPWATCH_UI_TOKEN must be at least 16 characters")
        self.db_path, self.assets, self.zeek_dirs = db_path, assets, zeek_dirs or []
        self.host, self.port, self.token = host, port, token
        self.secret = secrets.token_bytes(32)  # signs CSRF tokens; new each start
        # Logged-in sessions are signed with a key derived from the token, so a phone stays
        # logged in across UI restarts. Changing TAPWATCH_UI_TOKEN logs everyone out.
        self.session_key = hmac.new(token.encode(), b"tapwatch-session", "sha256").digest() if token else b""
        self.revoked: set[str] = set()          # logged out since this start
        self.base_url = base_url
        self.allowed_hosts = None              # Host header allow-list (loopback mode only); see bound()
        Store(db_path).db.close()  # run the migration once, up front

    def bound(self, port: int) -> None:
        """Called once the server has its port (which may have been 0 = pick any)."""
        self.port = port
        if is_loopback(self.host):
            self.allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}
            if self.base_url:
                self.allowed_hosts.add(urlsplit(self.base_url).netloc)

    def csrf(self, sid: str) -> str:
        return hmac.new(self.secret, b"csrf:" + sid.encode(), "sha256").hexdigest()

    def check_csrf(self, sid: str | None, token: str) -> bool:
        return bool(sid) and hmac.compare_digest(self.csrf(sid), token)

    def new_session(self) -> str:
        nonce = secrets.token_urlsafe(24)
        return f"{nonce}.{self._sign(nonce)}"

    def _sign(self, nonce: str) -> str:
        return base64.urlsafe_b64encode(hmac.new(self.session_key, nonce.encode(), "sha256").digest()[:24]).decode()

    def session_ok(self, sid: str | None) -> bool:
        if not sid or sid in self.revoked or "." not in sid:
            return False
        nonce, sig = sid.split(".", 1)
        return hmac.compare_digest(self._sign(nonce), sig)

    def check_token(self, given: str) -> bool:
        return self.token is not None and hmac.compare_digest(self.token.encode(), given.encode())


CASE_PATH = re.compile(r"^/case/(\d{1,12})(/update|/suppress|/undo-judge)?$")
SUPPRESSION_DELETE = re.compile(r"^/suppressions/(\d{1,12})/delete$")
EXPLAIN_APPLY = re.compile(r"^/explain/([0-9a-f]{16})/apply$")


class Handler(BaseHTTPRequestHandler):
    server_version = "tapwatch-ui"
    sys_version = ""
    app: App  # set by serve()

    # ---------------------------------------------------- plumbing

    def log_message(self, fmt, *args):
        log.info("%s %s", self.address_string(), fmt % args)

    def _sid(self) -> str | None:
        jar = cookies.SimpleCookie()
        try:
            jar.load(self.headers.get("Cookie", ""))
        except cookies.CookieError:
            return None
        m = jar.get(COOKIE)
        return m.value if m and re.fullmatch(r"[A-Za-z0-9_.=-]{20,100}", m.value) else None

    def _authed(self, sid: str | None) -> bool:
        return self.app.token is None or self.app.session_ok(sid)

    def _send(self, status: int, body: str = "", nonce: str = "", set_sid: str | None = None,
              location: str | None = None) -> None:
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        style = f"'nonce-{nonce}'" if nonce else "'none'"
        self.send_header("Content-Security-Policy",
                         f"default-src 'none'; style-src {style}; img-src 'self'; form-action 'self'; "
                         "frame-ancestors 'none'; base-uri 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        if set_sid:
            age = "; Max-Age=2592000" if self.app.session_ok(set_sid) else ""  # logged in: 30 days
            self.send_header("Set-Cookie", f"{COOKIE}={set_sid}; Path=/; HttpOnly; SameSite=Lax{age}")
        if location:
            self.send_header("Location", location)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _page(self, status: int, title: str, body: str, sid: str, set_sid: str | None = None,
              refresh: int = 0) -> None:
        nonce = secrets.token_urlsafe(16)
        path = urlsplit(self.path).path
        active = "/stats" if path == "/stats" else "/suppressions" if path.startswith("/suppressions") \
            else "/judge" if path.startswith("/judge") else "/"
        logged_in = self.app.token is not None and self.app.session_ok(sid)
        self._send(status, page(title, body, nonce, self.app.csrf(sid), logged_in, active, refresh, self.app.home),
                   nonce=nonce, set_sid=set_sid)

    def _error(self, status: int, message: str, sid: str | None = None) -> None:
        body = f'<h1>{status}</h1><p class="err">{e(message)}</p><p><a href="/">Back to cases</a></p>'
        self._page(status, str(status), body, sid or "none")

    def _host_ok(self) -> bool:
        return self.app.allowed_hosts is None or self.headers.get("Host", "") in self.app.allowed_hosts

    def _tailnet_user(self) -> str | None:
        """With ui.tailscale_users: the allowed Tailscale login on this request, else None.

        `tailscale serve` sets Tailscale-User-Login for tailnet users and strips any copy the client
        sent, so on a loopback-only listener the header can only come from Tailscale (or from a
        process on this machine, which can read the database directly anyway). Requests without
        it (tagged devices, Funnel, anything else) are refused."""
        login = self.headers.get("Tailscale-User-Login", "").strip().lower()
        return login if login and login in self.app.tailscale_users else None

    def _gate(self) -> bool:
        """Host check, plus the Tailscale identity check when configured. Sends the refusal itself."""
        if not self._host_ok():
            self._send(421, "wrong host")
            return False
        if self.app.tailscale_users and self._tailnet_user() is None:
            self._send(403, "This case desk only answers signed-in Tailscale users it knows.")
            return False
        return True

    def _origin_ok(self) -> bool:
        """If the browser says where a POST came from, it must be this site."""
        origin = self.headers.get("Origin")
        return origin is None or urlsplit(origin).netloc == self.headers.get("Host", "")

    # ---------------------------------------------------- GET

    def do_GET(self):
        if not self._gate():
            return
        url = urlsplit(self.path)
        if url.path == "/favicon.ico":
            # Browsers fetch this in parallel with the page, often before storing the page's
            # cookie. Handing it a session would overwrite that cookie and break the login
            # form's CSRF token, so answer with no session at all.
            return self._send(204)
        sid = self._sid()
        new_sid = None
        if sid is None:
            sid = new_sid = secrets.token_urlsafe(32)
        if url.path == "/login":
            if self.app.token is None:
                return self._send(303, location="/")
            return self._page(200, "Log in", _login_form(self.app.csrf(sid)), sid, new_sid)
        if not self._authed(sid):
            return self._send(303, set_sid=new_sid, location="/login")
        params = parse_qs(url.query)
        refresh = 0
        store = Store(self.app.db_path, migrate=False)
        try:
            csrf = self.app.csrf(sid)
            if url.path == "/":
                title, body = render_queue(store, self.app.assets, params, csrf)
            elif url.path == "/stats":
                title, body = render_stats(store, self.app.judge.qualify, self.app.assets)
                refresh = STATS_REFRESH_S
            elif url.path == "/suppressions":
                title, body = render_suppressions(store, csrf)
            elif url.path == "/judge":
                title, body = render_judge(store, self.app.judge, csrf)
            elif (m := CASE_PATH.match(url.path)) and not m.group(2):
                found = render_case(store, self.app.assets, int(m.group(1)), self.app.zeek_dirs, csrf, params)
                if found is None:
                    return self._error(404, "No such case.", sid)
                title, body = found
            else:
                return self._error(404, "Not found.", sid)
        finally:
            store.db.close()
        self._page(200, title, body, sid, new_sid, refresh)

    do_HEAD = do_GET

    # ---------------------------------------------------- POST

    def do_POST(self):
        if not self._gate():
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            return self._send(413, "too large")
        form = parse_qs(self.rfile.read(length).decode(errors="replace"), keep_blank_values=True)
        sid = self._sid()
        path = urlsplit(self.path).path
        if not self._origin_ok() or not self.app.check_csrf(sid, form.get("csrf", [""])[0]):
            if path == "/login" and self._origin_ok() and self.app.token is not None:
                # A stale login form (old cookie, server restarted): show a fresh form rather
                # than a dead-end 403. Nothing is checked or changed, so this is safe.
                fresh = sid or secrets.token_urlsafe(32)
                return self._page(200, "Log in", '<p class="err">That form had expired. Enter the token again.</p>'
                                  + _login_form(self.app.csrf(fresh)), fresh, None if sid else fresh)
            return self._error(403, "Missing or wrong CSRF token. Reload the page and try again.", sid)
        if path == "/login":
            return self._login(sid, form)
        if not self._authed(sid):
            return self._send(303, location="/login")
        if path == "/logout":
            self.app.revoked.add(sid)
            return self._send(303, location="/login")

        actor = f"ui {self._tailnet_user() or self.client_address[0]}"
        first = {k: v[0] for k, v in form.items()}
        store = Store(self.app.db_path, migrate=False)
        try:
            if (m := CASE_PATH.match(path)) and m.group(2) == "/update":
                case_id = int(m.group(1))
                store.update_case(case_id, actor, status=first.get("status"), disposition=first.get("disposition"),
                                  note=first.get("note", "")[:MAX_NOTE])
                return self._send(303, location=f"/case/{case_id}")
            if m and m.group(2) == "/undo-judge":   # #204: one click, audited, counted against the judge (#205)
                case_id = int(m.group(1))
                store.undo_judge_close(case_id, actor)
                return self._send(303, location=f"/case/{case_id}")
            if path == "/judge/undo-day":
                errors = _undo_day(store, first.get("day", ""), actor)
                if errors:
                    return self._error(400, "Some closes weren't undone: " + "; ".join(errors), sid)
                return self._send(303, location="/judge")
            if m and m.group(2) == "/suppress":
                case_id = int(m.group(1))
                rid = store.add_suppression(case_id, first.get("scope", ""), first.get("reason", "")[:500], actor,
                                            _expiry(first.get("days", "")))
                if first.get("close"):  # one form: the rule and the case it came from, closed as expected
                    store.update_case(case_id, actor, status="closed", disposition="benign_expected",
                                      note=f"suppressed: rule #{rid}")
                return self._send(303, location="/suppressions")
            if m := EXPLAIN_APPLY.match(path):
                from . import explain
                g = next((g for g in explain.suggestions(store) if explain.group_key(g) == m.group(1)), None)
                if g is None:  # applied already, or no longer all likely benign: nothing to do
                    return self._error(409, "That suggestion is gone: it was applied, or a case in it changed.", sid)
                explain.apply(store, g, actor=actor, name_only=True)
                return self._send(303, location="/suppressions")
            if m := SUPPRESSION_DELETE.match(path):
                store.delete_suppression(int(m.group(1)), actor)
                return self._send(303, location="/suppressions")
            if path == "/bulk":
                errors = _bulk_close(store, form, actor)
                if errors:
                    return self._error(400, "Some cases weren't closed: " + "; ".join(errors), sid)
                return self._send(303, location="/")
            return self._error(404, "Not found.", sid)
        except WorkflowError as err:
            return self._error(400, str(err), sid)
        finally:
            store.db.close()

    def _login(self, sid: str | None, form: dict) -> None:
        if self.app.token is None:
            return self._send(303, location="/")
        if not self.app.check_token(form.get("token", [""])[0]):
            time.sleep(1)  # slow down guessing
            return self._page(401, "Log in", '<p class="err">Wrong token.</p>' + _login_form(self.app.csrf(sid)), sid)
        fresh = self.app.new_session()  # new id after login, so a planted cookie can't ride along
        self._send(303, set_sid=fresh, location="/")


def _login_form(csrf: str) -> str:
    return (f'<h1>Log in</h1><form class="card" method="post" action="/login">{csrf_field(csrf)}'
            # Plain text on purpose: a long token is hard to type blind on a phone, and the page
            # can't run a show/hide script under its CSP. You only log in once per device.
            '<label class="f">Token (TAPWATCH_UI_TOKEN)<input type="text" name="token" autocomplete="off"'
            ' autocapitalize="none" autocorrect="off" spellcheck="false" required></label>'
            '<p class="muted">Stays logged in on this device for 30 days.</p><p><button>Log in</button></p></form>')


def _expiry(days: str) -> float | None:
    if not days.strip():
        return None
    try:
        d = float(days)
    except ValueError:
        raise WorkflowError("expiry must be a number of days") from None
    if not 0 < d <= 3650:
        raise WorkflowError("expiry must be between 0 and 3650 days")
    return time.time() + d * 86400


def _bulk_close(store: Store, form: dict, actor: str) -> list[str]:
    ids = form.get("ids", [])
    if not ids:
        raise WorkflowError("no cases selected")
    disposition = form.get("disposition", [""])[0]
    note = form.get("note", [""])[0][:MAX_NOTE]
    errors = []
    for raw in ids[:PAGE_SIZE]:
        if not raw.isdigit():
            continue
        row = store.get(int(raw))
        if row is None:
            continue
        try:
            store.update_case(row["id"], actor, disposition=disposition, note=note,
                              status=None if row["status"] == "closed" else "closed")
        except WorkflowError as err:
            errors.append(f"#{row['id']}: {err}")
    return errors


def make_server(app: App) -> ThreadingHTTPServer:
    handler = type("BoundHandler", (Handler,), {"app": app})
    server = ThreadingHTTPServer((app.host, app.port), handler)
    app.bound(server.server_port)
    return server


def serve(app: App) -> None:
    server = make_server(app)
    shown = "127.0.0.1" if is_loopback(app.host) else app.host
    log.info("tapwatch ui on http://%s:%s/ (Ctrl+C to stop)%s", shown, server.server_port,
             " - Tailscale users only: " + ", ".join(sorted(app.tailscale_users)) if app.tailscale_users
             else "" if app.token is None else " - token login required")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
