"""Detection self-check: the adversary-emulation shapes the owner used to run by hand, as a scripted corpus.

`tapwatch selfcheck` builds the detectors the way `run` does, from the real config (config.build_detectors, AI
off, no network), and pushes each scenario's synthetic records through them, routing with the rules alone. An
attack scenario passes when the detector it names raises a case at least as loud as expected; a quiet scenario (a
known false-positive shape) passes when the detector it names raises no case at all and nothing reaches alert.
The result is a number, the detection rate, so a regression after a deploy shows up as a number instead of as a
quiet feed (R22) or a test nobody re-ran. `tests/test_selfcheck.py` runs the same corpus on a fixed, empty
config, so CI's number is comparable across machines; the command's number reflects the box's own tuning, which
is the point of running it after a deploy (a threshold change that silences a shape is a regression too).

Addresses: the project's test LAN 192.168.50.0/24 (RFC 1918, as in the tests) and the documentation ranges
203.0.113.0/24 and 198.51.100.0/24; Windows paths carry `<user>`. Nothing here is read from the live network.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import config
from .models import Case
from .router import RANK, Route, Thresholds, route

T0 = 1_790_000_000.0            # 2026-09-21 UTC; the scenarios are self-contained, so any time works
PC = "192.168.50.10"            # the tapwatch PC
GW = "192.168.50.1"
DST = "203.0.113.50"
WIN = "/mnt/c/Program Files/osquery/log"


# ----------------------------------------------------------------------------------------------- record builders

def conn(ts, src=PC, dst=DST, port=443, state="SF", proto="tcp", orig_bytes=500, resp_bytes=900, **more):
    return {"_type": "conn", "ts": ts, "id.orig_h": src, "id.orig_p": 50000, "id.resp_h": dst, "id.resp_p": port,
            "proto": proto, "service": "ssl", "conn_state": state, "orig_bytes": orig_bytes, "resp_bytes": resp_bytes,
            "duration": 1.0, **more}


def dns(ts, query, src=PC, answers=(), rcode="NOERROR", **more):
    return {"_type": "dns", "ts": ts, "id.orig_h": src, "id.resp_h": GW, "query": query, "rcode_name": rcode,
            "answers": list(answers), **more}


def ssl(ts, server_name=None, src=PC, dst=DST, port=443, **more):
    r = {"_type": "ssl", "ts": ts, "id.orig_h": src, "id.resp_h": dst, "id.resp_p": port, "established": True, **more}
    if server_name:
        r["server_name"] = server_name
    return r


def dhcp(ts, server=GW, msg_types=("REQUEST", "ACK"), mac="02:00:00:00:00:01"):
    return {"_type": "dhcp", "ts": ts, "server_addr": server, "client_addr": PC, "assigned_addr": PC, "mac": mac,
            "msg_types": list(msg_types)}


def sysmon(eid, ts, guid="{g1}", **cols):
    utc = datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    return {"_type": "osquery", "_log": WIN, "name": "sysmon_events", "unixTime": int(ts) + 40, "ts": int(ts) + 40,
            "action": "added", "columns": {"eventid": str(eid), "utc": utc, "guid": guid, **cols}}


def process_start(ts, path, parent, **flags):
    return sysmon(1, ts, path=path, parent_path=parent, **flags)


def process_connect(ts, path, remote=DST, port=443):
    return sysmon(3, ts, path=path, remote_address=remote, remote_port=str(port))


def socket_row(ts, name, path, remote=DST, port=443):
    return {"_type": "osquery", "_log": WIN, "name": "outbound_connections", "unixTime": int(ts), "ts": int(ts),
            "action": "added", "columns": {"name": name, "path": path, "pid": "4242", "remote_address": remote,
                                           "remote_port": str(port), "parent_name": "explorer.exe"}}


def signatures(ts, *rows):
    return {"_type": "osquery", "_log": WIN, "name": "process_signatures", "unixTime": int(ts), "ts": int(ts),
            "action": "snapshot", "snapshot": [{"path": p, "signature": s, "signer": who} for p, s, who in rows]}


def persistence(ts, query, change="added", **cols):
    """One differential row of a persistence query (R23); `change` is osquery's added/removed, the task's own
    `action` column travels in `cols`."""
    return {"_type": "osquery", "_log": WIN, "name": query, "unixTime": int(ts), "ts": int(ts), "action": change,
            "columns": cols}


def _new_task(action):
    """A scheduled task appearing in one hourly run, then the tick that lets R23 read the run as a batch."""
    return [persistence(T0, "scheduled_tasks", name="tapwatch-selfcheck", action=action, path="\\tapwatch-selfcheck",
                        enabled="1", last_run_time="0"), tick(T0 + 130)]


def _task_inventory():
    rows = [persistence(T0, "scheduled_tasks", name=f"T{i}", action=rf"wscript.exe C:\Users\<user>\t{i}.vbs",
                        path=f"\\T{i}", enabled="1", last_run_time="0") for i in range(30)]
    return rows + [tick(T0 + 130)]


def tick(ts):
    return {"_type": "tick", "ts": ts}


PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
WORD = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
TEMP_EXE = r"C:\Users\<user>\AppData\Local\Temp\7zS1\setup.exe"
CERTUTIL = r"C:\Windows\System32\certutil.exe"
TAMPERED = r"C:\Users\<user>\AppData\Local\Temp\tapwatch-sig-test.exe"


# ----------------------------------------------------------------------------------------------------- scenarios

@dataclass
class Scenario:
    name: str
    records: list[dict]
    detector: str                   # the detector the shape is aimed at
    at_least: Route | None = Route.DIGEST  # how loud its case must route (rules only); None: a quiet shape, it must
    #                                 raise no case at all (and nothing may reach alert)
    note: str = ""
    config: dict = field(default_factory=dict)  # per-scenario config on top of the defaults (R22 needs its rule on)


def _beacon():
    return [conn(T0 + i * 60) for i in range(15)]


def _scan():
    return [conn(T0 + i * 0.1, dst=f"192.168.50.{i % 20 + 2}", port=1000 + i, state="REJ", orig_bytes=0, resp_bytes=0)
            for i in range(60)]


def _sweep():
    return [conn(T0 + i, src="192.168.50.66", dst=f"192.168.50.{100 + i}", port=445, state="S0", orig_bytes=0,
                 resp_bytes=0) for i in range(80)]


def _tunnel():
    rng = random.Random(7)
    chunk = lambda: "".join(rng.choice("abcdef0123456789") for _ in range(48))
    return [dns(T0 + i, f"{chunk()}.t.exfil-zone.net", qtype_name="TXT") for i in range(210)]


def _exposure():
    def inbound(ts, src):
        return conn(ts, src=src, dst=PC, port=8000, service="http", history="ShADadFf")
    return [inbound(T0, "198.51.100.7"), inbound(T0 + 200, "198.51.100.7"), inbound(T0 + 205, "203.0.113.9")]


def _video_call():
    return [conn(T0 + i * 60.07, dst="203.0.113.77", port=50003, proto="udp", duration=60.07, orig_bytes=500_000)
            for i in range(15)]


def _webrtc_media():
    return [ssl(T0 + i * 300, dst="203.0.113.172", port=1094 + i, version="DTLSv12",
                validation_status="self signed certificate", cert_chain_fps=["927f"], client_cert_chain_fps=["5ce9"])
            for i in range(3)]


def _reset_after_data():
    # a phone leaving a news page resets ad/CDN sessions after two-way data (#363): answered, not a scan
    return [conn(T0 + i, src="192.168.50.23", dst=f"203.0.113.{10 + i}", port=443, state="RSTO", orig_bytes=2500,
                 resp_bytes=8500) for i in range(90)]


SCENARIOS: list[Scenario] = [
    Scenario("C2 heartbeat every 60 s to a bare address", _beacon(), "beaconing"),
    Scenario("port scan: 60 refused connections across 20 LAN hosts", _scan(), "scan"),
    Scenario("admin-port sweep: 80 unanswered SMB probes", _sweep(), "mgmt_access", Route.ALERT),
    Scenario("DNS tunnel: 210 distinct long names under one unpopular zone", _tunnel(), "dns_anomaly", Route.ALERT),
    Scenario("internet exposure: answered inbound connections", _exposure(), "exposure", Route.ALERT),
    Scenario("rogue DHCP server", [dhcp(T0), dhcp(T0 + 2, server="192.168.50.99", msg_types=("OFFER",)),
                                   dhcp(T0 + 3, server="192.168.50.99")], "rogue_dhcp", Route.ALERT),
    Scenario("takeover: lookup of a callback catcher", [dns(T0, "abc.webhook.site", answers=["203.0.113.21"])],
             "takeover", Route.ALERT),
    Scenario("cleartext FTP login to the internet",
             [{"_type": "ftp", "ts": T0, "id.orig_h": PC, "id.resp_h": DST, "id.resp_p": 21, "user": "bob"}],
             "cleartext_auth", Route.ALERT),
    Scenario("DNS bypassing the home resolver",
             [conn(T0, dst="203.0.113.53", port=53, proto="udp", service="dns")], "dns_bypass"),
    Scenario("TLS to a bare address on an odd port with a self-signed certificate",
             [ssl(T0, dst="198.51.100.7", port=4443, validation_status="self signed certificate")], "tls_odd"),
    Scenario("R17 encoded download-and-run from a document app",
             [process_start(T0, PS, WORD, cmd_enc="1", cmd_dl="1", cmd_url="1")], "host_encoded_cmd", Route.ALERT),
    Scenario("R19 program in a temp folder connects out", [process_connect(T0, TEMP_EXE)], "host_temp_exec"),
    Scenario("R20 certutil connects to the internet", [process_connect(T0, CERTUTIL)], "host_lolbin", Route.ALERT),
    Scenario("R21 tampered binary (untrusted signature) connects out",
             [signatures(T0, (TAMPERED, "untrusted", "")), socket_row(T0 + 30, "tapwatch-sig-test.exe", TAMPERED)],
             "host_bad_sig", Route.ALERT),
    Scenario("R23 new scheduled task runs an encoded PowerShell command",
             _new_task("powershell.exe -w hidden -enc " + "Q" * 40), "host_persist", Route.ALERT),
    Scenario("R23 new scheduled task runs a script from Downloads",
             _new_task(r"wscript.exe C:\Users\<user>\Downloads\up.vbs"), "host_persist", Route.ALERT),
    Scenario("R22 the Zeek conn feed stops for 21 minutes", [conn(T0)] + [tick(T0 + 60 * i) for i in range(1, 22)],
             "feed_silence", Route.ALERT, config={"detectors": {"feed_silence": {"enabled": True}}}),
    Scenario("quiet: a 15-minute UDP voice call split into minute records (#63)", _video_call(), "beaconing", None),
    Scenario("quiet: the agent's first run lists 30 scheduled tasks at once (an inventory)", _task_inventory(),
             "host_persist", None),
    Scenario("quiet: WebRTC media with a client certificate on changing ports (#417)", _webrtc_media(), "tls_odd", None),
    Scenario("quiet: a phone resetting ad sessions after two-way data (#363)", _reset_after_data(), "scan", None),
]


# ------------------------------------------------------------------------------------------------------ running

@dataclass
class Outcome:
    scenario: Scenario
    cases: list[tuple[Case, Route]]
    passed: bool
    got: str


def base_config(cfg: dict | None = None) -> dict:
    """The live config with the parts the scenarios depend on pinned: no warm-up, the scenario LAN's gateway and
    PC, AI off, and R22 off unless a scenario turns it on (its ticks would otherwise fire in every scenario)."""
    cfg = dict(cfg or {})
    cfg["warmup_seconds"] = 0
    # the scenario LAN's gateway, and no admin devices: a configured admin at .66 would excuse the sweep (measured)
    cfg["network"] = {**(cfg.get("network") or {}), "gateways": [GW], "local_nets": [], "admin_devices": []}
    # the PC's address for the host rules; no agent logs, so R22 expects only the Zeek feeds when a scenario turns it on
    cfg["host_context"] = {"host": PC, "results_logs": ["/nonexistent/osqueryd.results.log"]}
    cfg["categories"] = {}
    cfg["detectors"] = {**(cfg.get("detectors") or {}), "feed_silence": {"enabled": False}}
    return cfg


def run_scenario(sc: Scenario, cfg: dict, thresholds: Thresholds | None = None) -> Outcome:
    merged = {**cfg, **sc.config, "detectors": {**cfg.get("detectors", {}), **sc.config.get("detectors", {})}}
    dets = config.build_detectors(merged)  # exactly what `run` builds
    now = [T0]  # the scenario clock: R22 measures arrivals and ticks against it, never the wall clock
    for d in dets:
        if d.name == "feed_silence":
            d.started, d.clock = T0, lambda: now[0]
    seen, cases = set(), []
    for rec in sc.records:
        now[0] = rec["ts"]
        for d in dets:
            for c in (d.tick(rec["ts"]) if rec.get("_type") == "tick" else d.feed(rec)):
                if c.key not in seen:
                    seen.add(c.key)
                    cases.append(c)
    for d in dets:
        for c in d.flush():
            if c.key not in seen:
                seen.add(c.key)
                cases.append(c)
    routed = [(c, route(c, None, thresholds)[0]) for c in cases]
    hits = [(c, r) for c, r in routed if c.detector == sc.detector]
    if sc.at_least is None:  # a quiet shape: its detector must stay silent, and nothing may reach alert
        bad = hits + [(c, r) for c, r in routed if r is Route.ALERT and c.detector != sc.detector]
        return Outcome(sc, routed, not bad, ", ".join(f"{c.detector}→{r.value}" for c, r in bad)
                       or f"no case from {sc.detector}, nothing at alert")
    best = max((RANK[r] for _, r in hits), default=-1)
    got = ", ".join(f"{c.detector}→{r.value}" for c, r in hits) or (
        "no case from " + sc.detector + (f" (others: {', '.join(sorted({c.detector for c in cases}))})" if cases else ""))
    return Outcome(sc, routed, best >= RANK[sc.at_least], got)


def run(cfg: dict | None = None, thresholds: Thresholds | None = None) -> list[Outcome]:
    base = base_config(cfg)
    return [run_scenario(sc, base, thresholds) for sc in SCENARIOS]


def report(outcomes: list[Outcome], source: str = "the default config") -> str:
    positives = [o for o in outcomes if o.scenario.at_least is not None]
    quiet = [o for o in outcomes if o.scenario.at_least is None]
    lines = [f"{'ok' if o.passed else 'FAIL':4s} {o.scenario.name:70s} expected "
             + (f"{o.scenario.detector} at {o.scenario.at_least.value}" if o.scenario.at_least else f"no {o.scenario.detector}")
             + f"; got {o.got}" for o in outcomes]
    caught = sum(o.passed for o in positives)
    rate = f" ({caught / len(positives):.0%})" if positives else ""
    lines.append(f"detected {caught}/{len(positives)}{rate}; quiet shapes staying quiet "
                 f"{sum(o.passed for o in quiet)}/{len(quiet)}; detectors built from {source}")
    return "\n".join(lines)


def as_json(outcomes: list[Outcome]) -> str:
    return json.dumps([{"scenario": o.scenario.name, "detector": o.scenario.detector,
                        "at_least": o.scenario.at_least.value if o.scenario.at_least else None,
                        "passed": o.passed, "got": o.got} for o in outcomes], indent=1)
