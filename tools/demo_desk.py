"""A case desk full of made-up cases, for screenshots and demos.

    python3 tools/demo_desk.py [--dir demo] [--port 8765]

Runs in UTC, so screenshots don't show the local time zone. Writes demo/tapwatch.db and demo/zeek/ (synthetic Zeek logs, so case pages show evidence), then serves
the case desk on 127.0.0.1. Every device, address and domain is invented: documentation address
ranges (RFC 5737), .example domains, and the network 192.168.50.0/24 the tests use.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

os.environ["TZ"] = "UTC"  # case times render in the server's zone; keep the real one out of screenshots
time.tzset()
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from tapwatch import ui
from tapwatch.models import Case, Route, Verdict
from tapwatch.store import Store
from tapwatch.summarizer import Assets, summarize

NET = "192.168.50."
DEVICES = {
    NET + "10": {"name": "family laptop", "role": "laptop"},
    NET + "11": {"name": "office PC", "role": "workstation"},
    NET + "20": {"name": "NAS", "role": "file server"},
    NET + "30": {"name": "living-room TV", "role": "smart TV"},
    NET + "31": {"name": "doorbell camera", "role": "camera"},
    NET + "32": {"name": "thermostat", "role": "IoT"},
    NET + "40": {"name": "printer", "role": "printer"},
}


def jev(category, conf, severity, page, routine=0.1):
    return Verdict(category, conf, severity, 0.8, routine, page, model="jev-1.13.0", input_tokens=700)


# (minutes ago, detector, device, title, facts, indicators, must_alert, verdict, route, reason, workflow).
# Titles and facts have the same shape the detectors produce, so summaries and case pages render as they do live.
CASES = [
    (12, "exposure", "20", "Device reachable from the internet",
     {"port": 5000, "proto": "tcp", "service": "http", "after_mapping_request": True, "dedupe": "tcp/5000"},
     [], True, None, Route.ALERT, "always-alert rule", {}),
    (38, "beaconing", "10", "Regular repeating connection to an external host",
     {"interval_s": 300, "count": 24, "span_s": 7200, "regularity": "very regular", "port": 8443,
      "service": "ssl", "dedupe": "port:8443", "host_matched": 24, "host_assessment": "unclear",
      "host_programs": ["updater.exe"], "host_signals": ["updater.exe isn't code-signed"]},
     ["cdn-sync.example"], False, jev("c2_beaconing", 0.86, 2.9, 0.84), Route.ALERT,
     "AI: c2_beaconing, severity 2.9/4",
     {"status": "investigating", "note": "Not a program we installed. Checking where updater.exe came from."}),
    (95, "takeover", "11", "Possible takeover: callback service",
     {"channel": "callback", "via": "TLS", "dedupe": "hooks.example"}, ["hooks.example"], True, None,
     Route.ALERT, "always-alert rule", {}),
    (140, "cleartext_auth", "40", "Unencrypted login or protocol",
     {"what": "an FTP login", "outside": True, "port": 21, "dedupe": "ftp"}, [], False,
     jev("policy_violation", 0.9, 2.2, 0.62), Route.DIGEST,
     "AI leaning policy_violation (0.90), not sure enough to interrupt", {}),
    (210, "new_device", "33", "New device on the network",
     {"vendor": "Espressif", "vendor_known": True, "has_mac": True, "randomized_mac": False, "night": True,
      "first_dest": "an internet server", "first_port": 8883, "first_service": "mqtt", "dedupe": "mac"},
     ["smart-plug"], False, jev("benign", 0.55, 1.6, 0.3, routine=0.5), Route.DIGEST,
     "needs a human look: AI unsure", {}),
    (300, "dns_anomaly", "30", "Unusual DNS lookup pattern",
     {"failed": 41, "random_looking": 0, "total": 380, "window_min": 10, "dedupe": "dns"}, [], False,
     jev("benign", 0.58, 0.8, 0.12, routine=0.7), Route.DIGEST, "needs a human look: AI unsure", {}),
    (420, "iot_drift", "31", "Fixed-function device talking somewhere new",
     {"what": "country", "value": "a new country", "role": "camera", "known_networks": 3, "known_countries": 1,
      "port": 443, "dedupe": "country"}, ["video-relay.example"], False,
     jev("data_exfiltration", 0.62, 2.1, 0.55), Route.DIGEST,
     "AI leaning data_exfiltration (0.62), not sure enough to interrupt", {}),
    (600, "upload_spike", "20", "Unusually large upload",
     {"mb": 2400, "normal_mb": 35.0, "times_normal": 69, "basis": "the same hour on earlier days",
      "top_share_pct": 97, "to_sync_service": False, "to_security_vendor": False}, ["backup.example"], False,
     jev("benign", 0.9, 0.6, 0.05, routine=0.9), Route.LOG, "AI: routine",
     {"status": "closed", "disposition": "benign_expected", "note": "Nightly offsite backup, first full run.",
      "suppress": ("device_indicator", "Offsite backup target for the NAS")}),
    (800, "odd_port", "32", "Connection on an unusual port",
     {"port": 8883, "proto": "tcp", "service": "mqtt", "new_for_house": True, "learn_days": 7, "minutes": 55,
      "mb_out": 0.2, "mb_in": 0.1, "dedupe": "tcp/8883"}, [], False, jev("benign", 0.8, 0.9, 0.1, 0.8),
     Route.LOG, "AI: routine", {"status": "closed", "disposition": "false_positive",
                                "note": "Thermostat cloud uses MQTT over TLS on 8883."}),
    (1000, "new_domain", "11", "First contact with a new domain",
     {"count": 1, "window_min": 10, "random": 0, "shared": 0, "popular": 0, "popular_known": True, "via": "DNS",
      "max_others": 0, "dedupe": "1"}, ["tools.example"], False, None, Route.LOG, "code-routed: log only", {}),
]

def write_zeek(zdir: Path, now: float) -> None:
    """A few minutes of conn/dns/ssl around each case, so case pages have evidence to show."""
    zdir.mkdir(parents=True, exist_ok=True)
    conn, dns, ssl = [], [], []
    for i, (ago, det, dev, *_rest) in enumerate(CASES):
        src, ts = NET + dev, now - ago * 60
        domain = (_rest[2] or ["service.example"])[0]
        dst = f"203.0.113.{10 + i}"
        for k in range(6):
            t = ts - 120 + k * 45
            dns.append({"ts": t - 1, "id.orig_h": src, "id.resp_h": NET + "1", "query": domain,
                        "rcode_name": "NOERROR", "answers": [dst]})
            conn.append({"ts": t, "id.orig_h": src, "id.orig_p": 50000 + k, "id.resp_h": dst, "id.resp_p": 443,
                         "proto": "tcp", "service": "ssl", "conn_state": "SF", "duration": 1.2,
                         "orig_bytes": 900 + 37 * k, "resp_bytes": 4100})
            ssl.append({"ts": t, "id.orig_h": src, "id.resp_h": dst, "server_name": domain, "version": "TLSv13"})
    for name, rows in (("conn", conn), ("dns", dns), ("ssl", ssl)):
        rows.sort(key=lambda r: r["ts"])
        (zdir / f"{name}.log").write_text("".join(json.dumps(r) + "\n" for r in rows))


def build(out: Path) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    db = out / "tapwatch.db"
    db.unlink(missing_ok=True)
    store, now, assets = Store(str(db)), time.time(), Assets(DEVICES, audience="home")
    for ago, det, dev, title, facts, ind, must, verdict, route, reason, wf in reversed(CASES):
        case = Case(det, NET + dev, now - ago * 60, title, facts, ind, must_alert=must)
        cid = store.add(case, summarize(case, assets), verdict, route, reason)  # what Jev was shown
        if wf.get("status") == "investigating":
            store.update_case(cid, actor="ui owner", status="investigating", note=wf.get("note"))
        elif wf.get("status") == "closed":
            store.update_case(cid, actor="ui owner", status="closed", disposition=wf["disposition"], note=wf.get("note"))
        if wf.get("suppress"):
            scope, why = wf["suppress"]
            store.add_suppression(cid, scope, why, actor="ui owner", expires_ts=now + 30 * 86400)
    write_zeek(out / "zeek", now)
    return db


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--dir", default="demo")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--build-only", action="store_true")
    a = p.parse_args()
    out = Path(a.dir)
    db = build(out)
    print(f"demo case desk: {db}")
    if not a.build_only:
        ui.serve(ui.App(str(db), Assets(DEVICES, audience="home"), zeek_dirs=[str(out / "zeek")], port=a.port))


if __name__ == "__main__":
    main()
