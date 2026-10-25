"""tapwatch command line.

  tapwatch run      --zeek-dir /logs        watch live Zeek logs, alert in real time
  tapwatch replay   --zeek-dir eval/out/x   push finished logs through the full pipeline once
  tapwatch eval     --zeek-dir ... --labels labels.yaml   Phase 0 rules-only vs Jev comparison
  tapwatch digest                           send the pending daily digest
  tapwatch summarize --zeek-dir /logs       per-device daily summaries (nightly from run; --backfill for 30 days)
  tapwatch mark 12 fp                       record admin feedback on a case (fp / tp)
  tapwatch test-alert                       send a harmless sample card to check Teams/email
  tapwatch ui                               case queue in the browser at http://127.0.0.1:8765/
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import queue
import signal
import sys
import time
from pathlib import Path

import yaml

from . import (
    benchmark,
    config,
    detectors,
    evaluate,
    evidence,
    history,
    longhaul,
    selfcheck,
    zeek,
)
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
                    learning_seconds=float(cfg.get("learning_days", 3)) * 86400,
                    update_notice=_update_notice(cfg))


def _update_notice(cfg: dict):
    """The digest's daily "newer release" line (#304), cached next to the database."""
    from . import update

    state = Path(cfg.get("db_path", "tapwatch.db")).with_name(".update-check.json")
    return lambda: update.notice(cfg, state)


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
    sums = cfg.get("summaries") or {}  # per-device daily summaries (#193), built in the background each night
    nightly = history.NightlyClock(int(sums.get("hour", 4)), history.zone(cfg)) if sums.get("enabled", True) else None
    summarizing = None
    # The long-horizon rules (#194, #195) run on the summary thread after its days are written and queue their cases;
    # they are raised here, on this thread, because the pipeline (its database connection, the notifier) is not
    # thread-safe (longhaul.py).
    found: queue.Queue = queue.Queue()
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
        while not found.empty():
            handled = longhaul.admit(p, found.get_nowait())
            if handled:
                log.info("#%s %s %s -> %s", handled[0], handled[1].detector, handled[1].host, handled[3].value)
        if nightly and nightly.due(time.time()) and not (summarizing and summarizing.is_alive()):
            asn = next((d.asn for d in p.detectors if getattr(d, "asn", None)), None)   # the alerter's own table
            # what the rules borrow from the live detectors is copied here, before the thread starts
            then = longhaul.queue_into(found, cfg, longhaul.Context.from_pipeline(p, cfg)) \
                if sums.get("rules", True) else None
            summarizing = history.nightly(cfg, args.zeek_dir, lambda: Store(cfg.get("db_path", "tapwatch.db")), asn=asn,
                                          then=then)


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
    ips, doms, ioc_labels = config.iocs(cfg)
    res = evaluate.run(args.zeek_dir, labels, detectors.build(cfg, ips, doms, config.popular_domains(cfg), config.assets(cfg).table,
                                                              ioc_labels), config.assets(cfg),
                       None if args.no_ai else config.jev_client(cfg), config.thresholds(cfg))
    print(evaluate.report(res))
    return 0


def cmd_selfcheck(args, cfg) -> int:
    """Push the scripted attack and false-positive shapes through the detectors as configured (AI off)."""
    outcomes = selfcheck.run(without_ai(cfg), config.thresholds(cfg))
    print(selfcheck.as_json(outcomes) if args.json else selfcheck.report(outcomes, source=f"the config file {args.config}"))
    return 0 if all(o.passed for o in outcomes) else 1


def cmd_benchmark(args, cfg) -> int:
    """Week-by-week noise rate, Jev agreement, host-context accuracy and the judge's scorecard, as Markdown."""
    print(benchmark.markdown(Store(cfg.get("db_path", "tapwatch.db")).db, judge_replay=args.judge_replay))
    return 0


def cmd_judge(args, cfg) -> int:
    """The learned judge's training set and guardrails (#200, #201). Read-only except `backfill`."""
    from . import judge

    db = Store(cfg.get("db_path", "tapwatch.db")).db
    if args.action == "backfill":
        counts = judge.backfill(db)
        print("examples from the audit trail: " + (", ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "none"))
        return 0
    if args.action == "examples":
        print(benchmark.judge_examples_markdown(db))
        return 0
    result = judge.replay(db)
    print("| Detector | Cases | Eligible, same device | Eligible, any device | Eligible true positives |")
    print("|---|---|---|---|---|")
    for name, d in sorted(result["detectors"].items(), key=lambda kv: -kv[1]["cases"]):
        print(f"| {name} | {d['cases']} | {d['device']} | {d['any_device']} | {d['eligible_tp']} |")
    for width, reasons in result["reasons"].items():
        print(f"\nWhy not eligible ({width.replace('_', ' ')}):")
        for reason, n in sorted(reasons.items(), key=lambda kv: -kv[1]):
            if reason != "eligible":
                print(f"  {n:5d}  {reason}")
    tp = sorted({i for ids in result["true_positives_eligible"].values() for i in ids})
    print(f"\ntrue positives that would have been eligible: {', '.join(f'#{i}' for i in tp) if tp else 'none'}")
    return 1 if tp else 0


def cmd_digest(args, cfg) -> int:
    p = _pipeline(cfg, use_ai=False)
    if not p.notifier:
        print("no notification channel configured (TAPWATCH_NTFY_URL, _DISCORD_URL, _TEAMS_URL, _WEBHOOK_URL or smtp)",
              file=sys.stderr)
        return 1
    print(f"sent {p.send_digest()} item(s)")
    return 0


def cmd_summarize(args, cfg) -> int:
    """Per-device daily summaries (#193): the finished days not done yet (what `run` does each night), the last
    30 days with --backfill, or the days named, rebuilt even when done."""
    store, tz, now = Store(cfg.get("db_path", "tapwatch.db")), history.zone(cfg), time.time()
    if args.day or args.since:
        first = history.parse_day(args.day or args.since)
        last = history.parse_day(args.day or args.until) if (args.day or args.until) else first
        days = []
        for d in history.day_range(first, last):
            if not history.finished(d, tz, now):
                print(f"{d}: not finished yet (its last connections are logged a few hours after midnight)",
                      file=sys.stderr)
            elif not history.has_logs(args.zeek_dir, d, tz):
                print(f"{d}: no conn logs left for it in {', '.join(args.zeek_dir)}", file=sys.stderr)
            else:
                days.append(d)
    else:
        days = history.due_days(store.db, args.zeek_dir, tz, now, args.days if args.backfill else history.CATCH_UP)
    if not days:
        print("nothing to summarize")
        return 0
    for r in history.summarize(store, cfg, args.zeek_dir, days):
        print(f"{r.day}  {r.devices:4d} devices  {r.dests:7d} destination rows  {r.records:9d} connections  "
              f"{r.seconds:6.1f} s")
    return 0


def cmd_longhaul(args, cfg) -> int:
    """The long-horizon rules (R30, R31) over the summary tables as they stand: what they would raise now and how
    it would route, and with --stats why the other candidates were skipped. Stores nothing: the measurement tool."""
    from .router import route

    store = Store(cfg.get("db_path", "tapwatch.db"))
    res = longhaul.evaluate(store, cfg, longhaul.Context.from_config(cfg, store), mature_days=args.mature_days)
    print(f"{res.days} watched day(s); {res.mature} of {res.devices} device(s) mature")
    routes: dict[tuple, int] = {}
    for case in res.cases:
        r, _ = route(case, None, config.thresholds(cfg))
        routes[(case.detector, r.value)] = routes.get((case.detector, r.value), 0) + 1
        print(f"{r.value:6} {longhaul.describe(case)}")
    for (detector, r), n in sorted(routes.items()):
        print(f"{detector}: {n} {r}")
    print(f"{len(res.cases)} case(s) would be raised")
    if args.stats:
        for why, n in sorted(res.skipped.items()):
            print(f"  skipped {n:5d}  {why}")
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

    db = cfg.get("db_path", "tapwatch.db")
    ecosystems = Store(db).ecosystems() if Path(db).exists() else {}
    report = feeds.update(args.dir or cfg.get("feeds_dir", "feeds"), ecosystems=ecosystems)
    for name, result in report.items():
        print(f"{name:20s} {result}")
    return 0 if all(r.startswith("ok") for r in report.values()) else 1


def cmd_software(args, cfg) -> int:
    """The agents' latest software snapshots (#224), and with --vulns what the downloaded feeds match."""
    from . import inventory, vulns

    store = Store(cfg.get("db_path", "tapwatch.db"))
    agents = store.agents()
    rows = store.software()
    if not rows:
        print("no software inventory yet: the agents snapshot it once a day (agents/config/osquery.conf software_*)")
        return 1
    index = vulns.VulnIndex.load(cfg.get("feeds_dir", "feeds")) if args.vulns else None
    by_agent: dict[str, list] = {}
    for r in rows:
        by_agent.setdefault(r["agent"], []).append(r)
    for agent, rs in by_agent.items():
        a = agents.get(agent) or {}
        os_row = {"name": a.get("os_name", ""), "version": a.get("os_version", "")} if a else None
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(max(r["seen_ts"] for r in rs)))
        print(f"{a.get('os_name') or 'unknown OS'} {a.get('os_version', '')}  agent {agent[:8]}  "
              f"{len(rs)} packages, snapshot {when}")
        for r in rs:
            if args.all or r["product"]:
                print(f"  {r['name'][:50]:50s} {r['version']}")
        if index is not None:
            hits = 0
            for r in rs:
                found = index.match(inventory.ecosystem(r["kind"], os_row), dict(r))
                kev = [h for h in found if h.kev]
                hits += bool(found)
                if kev or (args.all and found):
                    print(f"  ! {r['name'][:40]} {r['version']}: {len(found)} CVEs with a fix, {len(kev)} known "
                          f"exploited ({', '.join(h.cve for h in kev[:3])})")
            print(f"  {hits} packages with a fixed vulnerability in the feeds"
                  + ("" if index.kev else "  (no kev.json: run tapwatch update-feeds)"))
    return 0


def cmd_accounts(args, cfg) -> int:
    """Sign in a Google account for the account check (consent once, refresh token kept on this machine)."""
    from . import accounts as acc

    d = acc.token_dir(cfg)
    try:
        if args.action == "list":
            for label in acc.saved_labels(d):
                mode = oct((d / f"google-{label}.json").stat().st_mode & 0o777)
                try:
                    what = ", ".join(acc.granted(acc.load_token(d, label))) or "no scopes"
                except acc.AccountError as e:
                    what = str(e)
                print(f"{label:16s} {what}   ({mode})")
            return 0
        label = acc.check_label(args.label or "")
        if args.action == "remove":
            path = d / f"google-{label}.json"
            if not path.exists():
                print(f"no account {label!r}", file=sys.stderr)
                return 1
            try:   # best effort: also withdraw the grant at Google
                acc.Http().post_form(acc.REVOKE_URL, {"token": acc.load_token(d, label)["refresh_token"]})
            except acc.AccountError as e:
                print(f"couldn't revoke at Google ({e}); remove it at myaccount.google.com/permissions", file=sys.stderr)
            path.unlink()
            print(f"removed {label}")
            return 0
        services = [s.strip() for s in args.services.split(",") if s.strip()]
        unknown = [s for s in services if s not in acc.SCOPES]
        if unknown or not services:
            print(f"services: any of {', '.join(acc.SCOPES)}", file=sys.stderr)
            return 2
        cid, secret = acc.client()
        url, verifier, state = acc.auth_request(cid, services)
        print(f"1. Open this on any computer, signed in to the Google account you call {label!r}:\n\n{url}\n")
        print("2. Approve. The browser then fails to load a 127.0.0.1 page: that's expected.")
        print("3. Copy the whole address from the browser's address bar and paste it here.\n")
        code = acc.code_from_redirect(input("address: "), state)
        tok = acc.exchange(acc.Http(), cid, secret, code, verifier)
        same = acc.same_account(acc.Http(), cid, secret, d, label, tok)
        if same:
            print(f"that's the same Google account as {same!r}: nothing saved. Open the link in a private window "
                  "and sign in to the other account.", file=sys.stderr)
            return 1
        path = acc.save_token(d, label, {"refresh_token": tok["refresh_token"], "scope": tok.get("scope", ""),
                                         "added": round(time.time())})
        print(f"saved {label} ({path}, mode 600); add it under account_check.google in config.yaml")
        return 0
    except acc.AccountError as e:
        print(e, file=sys.stderr)
        return 1


def cmd_account_check(args, cfg) -> int:
    """Ask the configured Google accounts what was uploaded around an upload_spike case."""
    from . import accounts as acc

    store = Store(cfg.get("db_path", "tapwatch.db"))
    row = store.get(args.case_id)
    if row is None:
        print(f"no case #{args.case_id}", file=sys.stderr)
        return 1
    window = acc.WINDOW if args.window is None else args.window
    if window < 0:
        print("--window can't be negative", file=sys.stderr)
        return 2
    hosts = json.loads(row["indicators"] or "[]")
    if not args.force and not (row["detector"] == "upload_spike" and any(acc.google_upload_host(h) for h in hosts)):
        print(f"case #{args.case_id} isn't an upload to a Google upload service (--force to check anyway)",
              file=sys.stderr)
        return 1
    try:
        # an upload_spike case is stamped at the end of the hour it measured, and counts that hour and the one
        # before (detectors.HourlyProfile), so the uploads it saw happened in the two hours up to its time
        result = acc.check(cfg, row["first_ts"] - 7200 - window, row["last_ts"] + window)
    except acc.AccountError as e:
        print(e, file=sys.stderr)
        return 1
    mb = json.loads(row["facts"] or "{}").get("mb")
    upload = mb * 1e6 if isinstance(mb, (int, float)) else None
    f = acc.facts(result, upload_bytes=upload)
    if f["outcome"] == "unexplained":   # a work or school account the check can't see? (#986)
        zeek_dirs = args.zeek_dir or (cfg.get("ui") or {}).get("zeek_dirs") or []
        markers = acc.managed_markers(zeek_dirs, row["host"], *result["window"])
        if markers:
            f = acc.facts(result, upload_bytes=upload, markers=markers)
    text = acc.summary(f)
    print(text)
    if args.names:   # the terminal only: titles are never stored
        for label, entry in result["accounts"].items():
            for service, res in entry.items():
                for r in res.get("rows", []) if isinstance(res, dict) else ():
                    if r.get("title"):
                        print(f"  {label} {service} {acc._hm(r['time'])} {acc.clean_title(r['title'])}")
    if args.save:
        store.add_fact(args.case_id, "account_check", f, text, actor="account-check")
        print(f"saved to case #{args.case_id}")
    return 0


def cmd_update(args, cfg) -> int:
    """Move this install to the newest release (or main), rolling back if the new version fails."""
    from . import update

    try:
        p = update.plan(cfg)
        print(f"this install: {p.current} ({p.channel})   newest: {p.target}")
        if not p.needed:
            print(f"already past {p.target} (this checkout is newer)" if p.ahead else "up to date")
            return 0
        for line in p.changes[:30]:
            print(f"  - {line}")
        if len(p.changes) > 30:
            print(f"  ... and {len(p.changes) - 30} more")
        if args.check:
            return 0
        try:
            ok = args.yes or input("update now? the alerter restarts for a few seconds [y/N] ").strip().lower() == "y"
        except (EOFError, KeyboardInterrupt):
            ok = False
        if not ok:
            print("\nnot updated")
            return 1
        update.apply(cfg, args.config, p)
        return 0
    except update.UpdateError as e:
        print(e, file=sys.stderr)
        return 1


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


def cmd_import_state(args, cfg) -> int:
    from . import migrate

    try:
        settings = migrate.import_state(args.file)
    except (migrate.ImportRefused, OSError) as e:
        print(f"tapwatch import-state: {e}", file=sys.stderr)
        return 1
    print("Imported settings, cases and learned baselines.")
    if settings:
        print("These settings came from the old computer; point them at this one in config.yaml:")
        for line in settings:
            print(f"  {line}")
    return 0


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

    s = sub.add_parser("update-feeds", help="download Tranco, IEEE MAC vendors, IP-to-ASN, UT1 site-category, AdFection IOC and vulnerability (KEV, OSV, NVD) lists (no data sent)")
    s.add_argument("--dir", help="where to save them (default: feeds_dir, or ./feeds)")
    s.set_defaults(fn=cmd_update_feeds)
    s = sub.add_parser("software", help="the endpoint agents' installed software (daily snapshot), and known vulnerabilities in it")
    s.add_argument("--all", action="store_true", help="list every package, not just the products the check knows")
    s.add_argument("--vulns", action="store_true", help="match against the downloaded KEV/OSV/NVD feeds")
    s.set_defaults(fn=cmd_software)

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

    s = sub.add_parser("benchmark", help="week-by-week noise rate, Jev agreement, host-context accuracy and the "
                                         "judge's scorecard (Markdown)")
    s.add_argument("--judge-replay", action="store_true",
                   help="score the judge by judging every stored case afresh from the examples labelled before it, "
                        "instead of reading its shadow decisions (read-only; an estimate: facts are as stored now)")
    s.set_defaults(fn=cmd_benchmark)

    sub.add_parser("digest", help="send the pending digest").set_defaults(fn=cmd_digest)

    s = sub.add_parser("summarize", help="per-device daily summaries from the rotated logs (run does this nightly)")
    s.add_argument("--zeek-dir", required=True, action="append", help="log dir (repeatable)")
    s.add_argument("--backfill", action="store_true", help="every finished day of the last --days not done yet")
    s.add_argument("--days", type=int, default=history.BACKFILL, help="how far --backfill looks back (default 30)")
    s.add_argument("--day", help="rebuild one local day (YYYY-MM-DD)")
    s.add_argument("--from", dest="since", help="rebuild from this day (YYYY-MM-DD) ...")
    s.add_argument("--to", dest="until", help="... to this one, inclusive (default: the --from day)")
    s.set_defaults(fn=cmd_summarize)

    s = sub.add_parser("longhaul", help="the long-horizon rules (R30, R31) over the daily summaries: print what they "
                                        "would raise now, storing nothing (run raises them each night)")
    s.add_argument("--mature-days", type=int, help="watched days a device needs first (default summaries.mature_days, 14)")
    s.add_argument("--stats", action="store_true", help="also count why candidates were skipped")
    s.set_defaults(fn=cmd_longhaul)

    s = sub.add_parser("judge", help="the learned judge (v0.4): build its training set, replay its guardrails")
    s.add_argument("action", choices=["backfill", "examples", "replay"],
                   help="backfill: examples from the audit trail; examples: counts per source; replay: eligibility "
                        "over the history (exit 1 if a true positive would have been eligible)")
    s.set_defaults(fn=cmd_judge)

    s = sub.add_parser("accounts", help="sign in Google accounts for the account check (docs/setup/account-check.md)")
    s.add_argument("action", choices=["add", "list", "remove"])
    s.add_argument("label", nargs="?", help="a name for the account, e.g. personal (never the address)")
    s.add_argument("--services", default="drive,youtube,gmail", help="what to grant read access to (default: all)")
    s.set_defaults(fn=cmd_accounts)

    s = sub.add_parser("account-check", help="ask the Google accounts what was uploaded around an upload_spike case")
    s.add_argument("case_id", type=int)
    s.add_argument("--save", action="store_true", help="record the result on the case (counts and types, no names)")
    s.add_argument("--names", action="store_true", help="also print file and video titles (terminal only)")
    s.add_argument("--window", type=int, default=None, help="seconds either side of the case's hours (default 1800)")
    s.add_argument("--force", action="store_true", help="check even if the case isn't a Google upload")
    s.add_argument("--zeek-dir", action="append",
                   help="Zeek log dir to look for managed-account signs in (repeatable; default ui.zeek_dirs)")
    s.set_defaults(fn=cmd_account_check)

    s = sub.add_parser("update", help="update to the newest release (or main), rolling back if it fails")
    s.add_argument("--check", action="store_true", help="only say whether there's a newer version and what changed")
    s.add_argument("--yes", action="store_true", help="don't ask before updating")
    s.set_defaults(fn=cmd_update)

    s = sub.add_parser("mark", help="close a case as false/true positive")
    s.add_argument("case_id", type=int)
    s.add_argument("label", choices=["fp", "tp"])
    s.set_defaults(fn=cmd_mark)

    s = sub.add_parser("doctor", help="check every part of the install and say how to fix what isn't working")
    s.add_argument("--zeek-dir", help="the log dir `run` watches (default: the one `service install` used)")
    s.add_argument("--send", action="store_true", help="also send a test alert")
    s.set_defaults(fn=cmd_doctor)

    s = sub.add_parser("import-state", help="take over another computer's tapwatch (from deploy/export-state.sh)")
    s.add_argument("file", help="the tapwatch-state.tar.gz export-state wrote")
    s.set_defaults(fn=cmd_import_state)

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
