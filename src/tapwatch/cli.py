"""tapwatch command line.

  tapwatch run      --zeek-dir /logs        watch live Zeek logs, alert in real time
  tapwatch replay   --zeek-dir eval/out/x   push finished logs through the full pipeline once
  tapwatch eval     --zeek-dir ... --labels labels.yaml   Phase 0 rules-only vs Jev comparison
  tapwatch digest                           send the pending daily digest
  tapwatch mark 12 fp                       record admin feedback on a case (fp / tp)
  tapwatch test-alert                       send a harmless sample card to check Teams/email
  tapwatch ui                               case queue in the browser at http://127.0.0.1:8765/
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import time
from pathlib import Path

import yaml

from . import benchmark, config, detectors, evaluate, evidence, selfcheck, zeek
from .pipeline import Pipeline
from .store import Store
from .summarizer import summarize


def without_ai(cfg: dict) -> dict:
    """`--no-ai` means nothing leaves for a model: Jev (handled by the caller) and the domain categorizer
    (categories.py), which detectors.build() would otherwise construct from `categories: {ai: true}`. A replay
    of a month of logs must not ask about every first-seen domain or spend the budget the live service shares."""
    return {**cfg, "categories": {**(cfg.get("categories") or {}), "ai": False}}


def _pipeline(cfg: dict, use_ai: bool = True, notify: bool = True, zeek_dirs=None) -> Pipeline:
    if not use_ai:
        cfg = without_ai(cfg)
    return Pipeline(config.build_detectors(cfg), config.assets(cfg), Store(cfg.get("db_path", "tapwatch.db")),
                    client=config.jev_client(cfg) if use_ai else None,
                    notifier=config.notifier(cfg) if notify else None,
                    thresholds=config.thresholds(cfg), dedupe_seconds=cfg.get("dedupe_seconds", 3600),
                    base_url=(cfg.get("ui") or {}).get("base_url"),
                    herdr=config.herdr(cfg) if notify else None,
                    herdr_ai_severity=(cfg.get("herdr") or {}).get("ai_severity", 3.5),
                    hostctx=config.hostctx(cfg), zeek_dirs=zeek_dirs,
                    learning_seconds=float(cfg.get("learning_days", 3)) * 86400)


def _single_instance(db_path: str):
    """Hold an exclusive lock for the life of `run`, so two alerters can never send twice."""
    import fcntl

    fh = open(db_path + ".run.lock", "w")  # noqa: SIM115 - must stay open to keep the lock
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit(f"another `tapwatch run` already holds {db_path}.run.lock") from None
    fh.write(str(os.getpid()))
    fh.flush()
    return fh


def cmd_run(args, cfg) -> int:
    lock = _single_instance(cfg.get("db_path", "tapwatch.db"))  # noqa: F841 - held until exit
    Path("tapwatch-run.pid").write_text(str(os.getpid()))  # the watchdog checks this process is alive
    p = _pipeline(cfg, zeek_dirs=args.zeek_dir)
    log = logging.getLogger("tapwatch")
    host_dirs = config.host_log_dirs(cfg)  # the endpoint agents' osquery logs, for the host rules (R17+)
    log.info("watching %s (AI triage: %s, notifications: %s)", args.zeek_dir + host_dirs,
             "on" if p.client else "OFF - rules only", "on" if p.notifier else "OFF")
    if config.missing_feeds(cfg):
        log.warning(config.missing_feeds(cfg))
    log.info("restored learned state for %d detector(s)", p.restore_state())
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))  # so `kill` still saves state below
    try:
        _run_loop(p, args, cfg, log)
    finally:
        log.info("saved learned state for %d detector(s)", p.save_state())
    return 0


STATE_SAVE_EVERY = 600  # seconds
FOLLOW_PC_EVERY = 300    # seconds: the agents report the PC's addresses every 5 minutes


def _run_loop(p: Pipeline, args, cfg: dict, log) -> None:
    digest = DigestClock(cfg.get("digest_hour_utc", 13))
    keep_days, next_prune = cfg.get("zeek_retention_days", 30), 0.0
    next_save, next_follow, next_tick = time.time() + STATE_SAVE_EVERY, 0.0, time.time() + 60
    for rec in zeek.Follower(args.zeek_dir + config.host_log_dirs(cfg)).follow(idle_ticks=True):
        if time.time() >= next_tick:  # once a minute, whether records are flowing or not (R22 watches the feeds)
            for case_id, case, _, route in p.process({"_type": "tick", "ts": time.time()}):
                log.info("#%s %s %s -> %s", case_id, case.detector, case.host, route.value)
            next_tick = time.time() + 60
        if time.time() >= next_follow:  # DHCP moves the PC: keep its rules on the address it has now
            p.follow_this_pc()
            next_follow = time.time() + FOLLOW_PC_EVERY
        if time.time() >= next_save:
            p.save_state()
            next_save = time.time() + STATE_SAVE_EVERY
        if keep_days and time.time() >= next_prune:  # rotated Zeek logs older than this are deleted hourly
            gone = zeek.prune(args.zeek_dir, keep_days)
            if gone:
                log.info("pruned %d rotated Zeek log(s) older than %s days", len(gone), keep_days)
            next_prune = time.time() + 3600
        if rec is not None:  # None = quiet poll: still check the digest clock
            for case_id, case, _, route in p.process(rec):
                log.info("#%s %s %s -> %s", case_id, case.detector, case.host, route.value)
        if digest.due(time.time()):
            p.send_digest()


class DigestClock:
    """Once per UTC day, at or after `hour`. Fires late rather than never if tapwatch starts after
    the hour; the first check on a fresh start counts as that day's send."""

    def __init__(self, hour: int):
        self.hour, self.last_day = hour, None

    def due(self, now: float) -> bool:
        t = time.gmtime(now)
        if t.tm_hour < self.hour or self.last_day == (t.tm_year, t.tm_yday):
            return False
        self.last_day = (t.tm_year, t.tm_yday)
        return True


def cmd_replay(args, cfg) -> int:
    cfg = {**cfg, "learning_days": 0}  # a replay shows what settled routing would do
    p = _pipeline(cfg, use_ai=not args.no_ai, notify=args.notify)
    n = 0
    def results():
        for rec in zeek.replay(args.zeek_dir):
            yield from p.process(rec)
        yield from p.flush()

    for case_id, case, verdict, route in results():
        n += 1
        ai = f" ai={verdict.category}:{verdict.category_confidence:.2f}" if verdict else ""
        print(f"#{case_id:<5} {route.value:6} {case.detector:13} {case.host:15} {case.title}{ai}")
    print(f"{n} new case(s); input tokens {p.input_tokens}")
    return 0


def cmd_eval(args, cfg) -> int:
    with open(args.labels) as fh:
        labels = yaml.safe_load(fh) or {}
    cfg = {**cfg, "warmup_seconds": args.warmup}  # evaluate.run routes itself: no learning period
    if args.no_ai:
        cfg = without_ai(cfg)
    ips, doms = config.iocs(cfg)
    res = evaluate.run(args.zeek_dir, labels, detectors.build(cfg, ips, doms, config.popular_domains(cfg), config.assets(cfg).table), config.assets(cfg),
                       None if args.no_ai else config.jev_client(cfg), config.thresholds(cfg))
    print(evaluate.report(res))
    return 0


def cmd_selfcheck(args, cfg) -> int:
    """Push the scripted attack and false-positive shapes through the detectors as configured (AI off)."""
    outcomes = selfcheck.run(without_ai(cfg), config.thresholds(cfg))
    print(selfcheck.as_json(outcomes) if args.json else selfcheck.report(outcomes, source=f"the config file {args.config}"))
    return 0 if all(o.passed for o in outcomes) else 1


def cmd_benchmark(args, cfg) -> int:
    """Week-by-week noise rate, Jev agreement and host-context accuracy from the case desk, as Markdown."""
    print(benchmark.markdown(Store(cfg.get("db_path", "tapwatch.db")).db))
    return 0


def cmd_digest(args, cfg) -> int:
    p = _pipeline(cfg, use_ai=False)
    if not p.notifier:
        print("no notification channel configured (TAPWATCH_NTFY_URL, _DISCORD_URL, _TEAMS_URL, _WEBHOOK_URL or smtp)",
              file=sys.stderr)
        return 1
    print(f"sent {p.send_digest()} item(s)")
    return 0


def cmd_who(args, cfg) -> int:
    """Run the host-context check for an existing case and print what the PC says."""
    from .models import Case

    hc = config.hostctx(cfg)
    if not hc:
        print("host context not configured (host_context: {host: <this PC's IP>})", file=sys.stderr)
        return 1
    row = Store(cfg.get("db_path", "tapwatch.db")).get(args.case_id)
    if row is None:
        print(f"no case #{args.case_id}", file=sys.stderr)
        return 1
    facts = json.loads(row["facts"])
    if not hc.is_this_pc(row["host"], row["first_ts"], facts.get("device_name")):
        print(f"case #{args.case_id} is on {row['host']}, which wasn't this PC then; other devices need Fleet",
              file=sys.stderr)
        return 1
    if hc.config_mismatch():
        print(hc.config_mismatch(), file=sys.stderr)
    case = Case(row["detector"], row["host"], row["first_ts"], row["title"], facts, json.loads(row["indicators"]))
    ev = evidence.lookup(args.zeek_dir, case.host, case.ts, window=180)
    case.facts = {k: v for k, v in case.facts.items() if not k.startswith("host_")}  # stored ones are stale
    case.facts.update(hc.collect(case, ev["conn"]["rows"], ev["dns"]["rows"]))
    for k, v in case.facts.items():
        if k.startswith("host_"):
            print(f"{k:28s} {v}")
    print()
    print(summarize(case, config.assets(cfg)).splitlines()[-1])
    return 0


def cmd_service(args, cfg) -> int:
    from . import service

    if args.action == "uninstall":
        print("removed: " + (", ".join(service.uninstall()) or "nothing"))
        return 0
    if not args.zeek_dir:
        print("--zeek-dir is required", file=sys.stderr)
        return 1
    units = service.units(".", args.zeek_dir, args.capture_iface, args.syslog)
    if args.dry_run:
        for name, text in units.items():
            print(f"# {name}\n{text}")
        return 0
    for path in service.install(units):
        print(f"installed and started {path}")
    print("Services stop at logout unless lingering is on: loginctl enable-linger $USER")
    return 0


def cmd_init(args, cfg) -> int:
    from . import wizard

    facts = wizard.detect()
    print(f"Detected: gateway {facts.gateway or '?'}, this machine {facts.this_ip or '?'}, "
          f"timezone {facts.timezone or '?'}, Npcap capture {'yes' if facts.windows_capture else 'no'}")
    if args.answers:
        try:
            ask = wizard.from_answers(sys.stdin.read() if args.answers == "-" else Path(args.answers).read_text())
        except (OSError, ValueError, TypeError) as e:
            print(f"answers: {e}", file=sys.stderr)
            return 2
    else:
        ask = (lambda q, d, c=None, key="": d) if args.yes else wizard.prompt
    conf, assets, env, notes = wizard.build(facts, ask)
    try:
        written = wizard.write(args.dir, conf, assets, env, force=args.force)
    except FileExistsError as e:
        print(e, file=sys.stderr)
        return 1
    print("\nWrote: " + ", ".join(written))
    # The popular-domains list is what keeps the first day quiet (config.missing_feeds), so offer it
    # here rather than leave it to a note. --yes skips the download: it may be running offline.
    if not args.yes and ask("Download the public lists now (popular domains, MAC vendors, IP-to-network)?",
                            "yes", ["yes", "no"], key="download_feeds") == "yes":
        from . import feeds

        report = feeds.update(str(Path(args.dir) / conf.get("feeds_dir", "feeds")))
        for name, result in report.items():
            print(f"  {name:20s} {result}")
        if all(r.startswith("ok") for r in report.values()):
            notes = [n for n in notes if "update-feeds" not in n]
    print("\nNext:")
    for n in notes:
        print(f"  - {n}")
    return 0


def cmd_syslog(args, cfg) -> int:
    from . import syslogin

    s = cfg.get("syslog") or {}
    allow = set(args.allow or s.get("allow") or (cfg.get("network") or {}).get("gateways") or [])
    syslogin.serve(args.listen or s.get("listen", "0.0.0.0:5514"), args.out or s.get("out", "logs/udm"), allow)
    return 0


def cmd_explain(args, cfg) -> int:
    from . import explain

    store = Store(cfg.get("db_path", "tapwatch.db"))
    gs = explain.groups(store, time.time() - args.since_days * 86400)
    print(explain.report(gs, args.min_cases))
    if args.apply:
        for g in gs:
            if g["explained"] and g["cases"] >= args.min_cases:
                rule, closed = explain.apply(store, g, days=args.expire_days)
                print(f"applied: suppression #{rule}; closed cases {closed or 'none open'}")
    return 0


def cmd_update_feeds(args, cfg) -> int:
    from . import feeds

    report = feeds.update(args.dir or cfg.get("feeds_dir", "feeds"))
    for name, result in report.items():
        print(f"{name:20s} {result}")
    return 0 if all(r.startswith("ok") for r in report.values()) else 1


def cmd_mark(args, cfg) -> int:
    ok = Store(cfg.get("db_path", "tapwatch.db")).set_feedback(args.case_id, args.label)
    print("saved" if ok else f"no case #{args.case_id}")
    return 0 if ok else 1


def cmd_ui(args, cfg) -> int:
    from . import ui

    # The case desk groups domains for "Suppress similar" with base_domain too: the same list as the alerter's.
    detectors.set_public_suffixes(cfg.get("public_suffix_file"))

    u = cfg.get("ui") or {}
    app = ui.App(cfg.get("db_path", "tapwatch.db"), config.assets(cfg),
                 zeek_dirs=args.zeek_dir or u.get("zeek_dirs") or [],
                 host=args.host or u.get("host", "127.0.0.1"), port=args.port or u.get("port", 8765),
                 token=os.environ.get(u.get("token_env", "TAPWATCH_UI_TOKEN")) or None,
                 base_url=u.get("base_url"), tailscale_users=u.get("tailscale_users"))
    ui.serve(app)
    return 0


def cmd_notify(args, cfg) -> int:
    n = config.notifier(cfg)
    if not n:
        print("no notification channel configured (TAPWATCH_NTFY_URL, _DISCORD_URL, _TEAMS_URL, _WEBHOOK_URL or smtp)",
              file=sys.stderr)
        return 1
    n.send(args.title, [{"heading": args.title, "facts": {"Details": args.text}}])
    return 0


def cmd_doctor(args, cfg) -> int:
    from . import doctor

    zeek_dir = args.zeek_dir or doctor.zeek_dir_from_units() or "logs/zeek"
    results = doctor.run_all(cfg, args.config, zeek_dir)
    if args.send and any(r.part == "Alerts" and r.level == doctor.OK for r in results):
        try:
            sent = config.notifier(cfg).send("tapwatch test alert", [{"heading": "This is a test - no action needed",
                                                                      "facts": {"Why": "tapwatch doctor --send"}}])
            results.append(doctor.Result(doctor.OK, "Test alert", "sent via " + ", ".join(sent)))
        except Exception as e:  # noqa: BLE001 -- any channel failure is a line in the report, not a traceback
            results.append(doctor.Result(doctor.FAIL, "Test alert", f"not delivered: {e}",
                                         "check the address in .env, then: tapwatch test-alert"))
    print(doctor.report(results))
    return 1 if any(r.level == doctor.FAIL for r in results) else 0


def cmd_test_alert(args, cfg) -> int:
    if args.herdr:
        h = config.herdr(cfg)
        if not h:
            print("Herdr not enabled (herdr: {enabled: true}) or herdr binary not found", file=sys.stderr)
            return 1
        h.show("tapwatch CRITICAL: test alert", "This is a test - no action needed")
        print("shown in Herdr")
        return 0
    n = config.notifier(cfg)
    if not n:
        print("no notification channel configured (TAPWATCH_NTFY_URL, _DISCORD_URL, _TEAMS_URL, _WEBHOOK_URL or smtp)",
              file=sys.stderr)
        return 1
    sent = n.send("tapwatch test alert", [{"heading": "This is a test - no action needed",
                                           "facts": {"Device": "example PC (192.0.2.10)", "Why": "test"},
                                           "untrusted": ["[click me](http://example.invalid)"]}])
    print("delivered via " + ", ".join(sent))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="tapwatch")
    ap.add_argument("-c", "--config", default="config.yaml")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("run", help="watch live Zeek logs")
    s.add_argument("--zeek-dir", required=True, action="append", help="log dir (repeat for Suricata's)")
    s.set_defaults(fn=cmd_run)

    s = sub.add_parser("service", help="run tapwatch unattended as systemd user services (no Docker)")
    s.add_argument("action", choices=["install", "uninstall"])
    s.add_argument("--zeek-dir", help="the log dir capture writes and the alerter watches")
    s.add_argument("--capture-iface", help="Windows+WSL: Npcap interface to capture (adds the capture service)")
    s.add_argument("--syslog", action="store_true", help="also run the router syslog listener")
    s.add_argument("--dry-run", action="store_true", help="print the units instead of installing them")
    s.set_defaults(fn=cmd_service)

    s = sub.add_parser("init", help="set up: detect the network, ask a few questions, write config, assets and .env")
    s.add_argument("--dir", default=".", help="where to write config.yaml, assets.yaml and .env")
    how = s.add_mutually_exclusive_group()
    how.add_argument("--yes", action="store_true", help="accept every detected default (no questions)")
    s.add_argument("--force", action="store_true", help="replace an existing config.yaml / assets.yaml")
    how.add_argument("--answers", metavar="FILE", help="answer from a JSON object keyed by question (wizard.ANSWER_KEYS); "
                   "'-' reads stdin, so secrets need not touch the disk")
    s.set_defaults(fn=cmd_init)

    s = sub.add_parser("syslog", help="receive the router's CEF syslog (UniFi SIEM) into udm.log for `run`")
    s.add_argument("--listen", help="host:port (default 0.0.0.0:5514)")
    s.add_argument("--out", help="log dir to write udm.log into; give `run` the same dir as a --zeek-dir")
    s.add_argument("--allow", action="append", help="sender IP to accept (repeat; default: network.gateways)")
    s.set_defaults(fn=cmd_syslog)

    s = sub.add_parser("explain", help="why rules keep firing on PCs with host context; suggest or apply suppressions")
    s.add_argument("--since-days", type=float, default=7)
    s.add_argument("--min-cases", type=int, default=3, help="repeats needed before suggesting a suppression")
    s.add_argument("--expire-days", type=float, default=30)
    s.add_argument("--apply", action="store_true", help="create the suggested suppressions and close those cases")
    s.set_defaults(fn=cmd_explain)

    s = sub.add_parser("update-feeds", help="download Tranco, IEEE MAC vendors, IP-to-ASN and UT1 site-category lists (no data sent)")
    s.add_argument("--dir", help="where to save them (default: feeds_dir, or ./feeds)")
    s.set_defaults(fn=cmd_update_feeds)

    s = sub.add_parser("who", help="ask the PC (osquery + Claude Code transcripts) who made a case's traffic")
    s.add_argument("case_id", type=int)
    s.add_argument("--zeek-dir", required=True, action="append")
    s.set_defaults(fn=cmd_who)

    s = sub.add_parser("replay", help="push finished logs through the pipeline")
    s.add_argument("--zeek-dir", required=True, action="append", help="log dir (repeat for Suricata's)")
    s.add_argument("--no-ai", action="store_true")
    s.add_argument("--notify", action="store_true", help="actually send alerts (off by default)")
    s.set_defaults(fn=cmd_replay)

    s = sub.add_parser("eval", help="Phase 0: rules-only vs Jev on labelled traffic")
    s.add_argument("--zeek-dir", required=True, action="append", help="log dir (repeat for Suricata's)")
    s.add_argument("--labels", required=True)
    s.add_argument("--warmup", type=float, default=300, help="seconds of learning before first-seen rules fire")
    s.add_argument("--no-ai", action="store_true")
    s.set_defaults(fn=cmd_eval)

    s = sub.add_parser("selfcheck", help="detection rate on scripted attack shapes, rules only; exit 1 on a regression")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_selfcheck)

    sub.add_parser("benchmark", help="week-by-week noise rate, Jev agreement and host-context accuracy (Markdown)") \
        .set_defaults(fn=cmd_benchmark)

    sub.add_parser("digest", help="send the pending digest").set_defaults(fn=cmd_digest)

    s = sub.add_parser("mark", help="close a case as false/true positive")
    s.add_argument("case_id", type=int)
    s.add_argument("label", choices=["fp", "tp"])
    s.set_defaults(fn=cmd_mark)

    s = sub.add_parser("doctor", help="check every part of the install and say how to fix what isn't working")
    s.add_argument("--zeek-dir", help="the log dir `run` watches (default: the one `service install` used)")
    s.add_argument("--send", action="store_true", help="also send a test alert")
    s.set_defaults(fn=cmd_doctor)

    s = sub.add_parser("test-alert", help="send a sample alert")
    s.add_argument("--herdr", action="store_true", help="pop a test notification in Herdr instead")
    s.set_defaults(fn=cmd_test_alert)

    s = sub.add_parser("ui", help="case queue, case pages, suppressions and stats in the browser")
    s.add_argument("--host", help="address to listen on (default 127.0.0.1; anything else needs TAPWATCH_UI_TOKEN)")
    s.add_argument("--port", type=int, help="default 8765")
    s.add_argument("--zeek-dir", action="append", help="Zeek log dir for evidence (repeatable; default ui.zeek_dirs)")
    s.set_defaults(fn=cmd_ui)

    s = sub.add_parser("notify", help="send a plain message through the configured channels")
    s.add_argument("title")
    s.add_argument("text")
    s.set_defaults(fn=cmd_notify)

    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(asctime)s %(message)s")
    config.load_dotenv()
    return args.fn(args, config.load(args.config))


if __name__ == "__main__":
    sys.exit(main())
