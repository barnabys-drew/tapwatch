import random
from datetime import datetime, timezone

from conftest import T0, conn, dhcp, dns, eve_alert, ssl

from tapwatch.detectors import (
    Beaconing,
    CleartextAuth,
    DevProfile,
    Gateways,
    HourlyProfile,
    InternetExposure,
    IOCMatch,
    ManagementAccess,
    NewDevice,
    NewExternalDomain,
    PortScan,
    RogueDHCP,
    SuricataAlert,
    SuspiciousDNS,
    TakeoverChannel,
    Warmup,
    base_domain,
    build,
    in_hours,
    is_internal,
    looks_random,
    parse_hours,
    set_local_nets,
    suffix_match,
)
from tapwatch.zeek import _parse_line


def run(det, recs):
    out = []
    for r in recs:
        out += det.feed(r)
    return out


def test_beaconing_fires_on_regular_heartbeat():
    recs = [conn(T0 + i * 60) for i in range(15)]
    cases = run(Beaconing(), recs)
    assert len(cases) == 1
    assert cases[0].facts["interval_s"] == 60
    assert cases[0].facts["regularity"] == "very regular"


def test_beaconing_beat_window_survives_a_restart():
    # 2026-10-16: a 12-beat heartbeat straddled an alerter restart and raised nothing, because the beat times were
    # not saved; the offline replay of the same rows did. Six beats, save, restore into a fresh detector, nine more.
    import json
    first = Beaconing()
    assert run(first, [conn(T0 + i * 60) for i in range(6)] + [conn(T0 + 7, dst="203.0.113.9")]) == []  # one lone beat
    saved = json.loads(json.dumps(first.snapshot()))
    second = Beaconing()
    second.restore(saved)
    assert len(second.seen) == 1 and len(second.seen[next(iter(second.seen))]) == 6  # the single-beat pair was dropped
    cases = run(second, [conn(T0 + i * 60) for i in range(6, 15)])
    assert len(cases) == 1 and cases[0].facts["interval_s"] == 60
    assert second.seen[next(iter(second.seen))].maxlen == 60  # the deque came back bounded
    # a saved window whose shape no longer fits starts fresh instead of failing on the next record
    for bad in ({"seen": "junk"}, {"seen": {"$dict": {"x": [1, 2]}}, "durations": {"$dict": {"x": [1.0]}}}):
        fresh = Beaconing()
        fresh.restore(bad)
        assert fresh.seen == {} and fresh.durations == {}
        assert len(run(fresh, [conn(T0 + i * 60) for i in range(15)])) == 1


def test_beaconing_catches_jittered_c2_at_digest_but_not_with_jitter_off():
    """#24: Cobalt Strike-style sleep jitter (a random 0-50% less than the interval) and a missed beat defeat
    the CV test; the jitter tier catches them and caps them at digest."""
    rng = random.Random(3)
    ts, recs = T0, []
    for i in range(20):
        ts += 300 * rng.uniform(0.5, 1.0) * (2 if i == 9 else 1)
        recs.append(conn(ts))
    (c,) = run(Beaconing(), recs)
    assert c.facts["regularity"] == "jittered" and c.facts["max_route"] == "digest"
    assert 200 <= c.facts["interval_s"] <= 260          # the folded median beat, not the mean the missed beat inflates
    assert run(Beaconing(jitter=False), recs) == []
    from tapwatch.summarizer import Assets, summarize
    assert "varies randomly around a steady interval" in summarize(c, Assets())
    # a popular service with loose timing is the measured noise: logged
    (p,) = run(Beaconing(popular={"example.com"}), [ssl(T0 - 1, "api.example.com")] + recs)
    assert p.facts["max_route"] == "log"


def test_a_jittered_case_never_uses_a_regular_cases_reporting_slots():
    """Review of #143: jittered hits took the 7-day slot and the (host, port) fan-out budget, hiding 7 of 20
    regular cases on two days of home traffic."""
    rng = random.Random(5)
    b, recs = Beaconing(fanout_per_day=3), []
    for n, dst in enumerate(("203.0.113.11", "203.0.113.12", "203.0.113.13")):
        ts = T0 + n
        for i in range(20):
            ts += 300 * rng.uniform(0.5, 1.0)
            recs.append(conn(ts, dst=dst))
    recs.sort(key=lambda r: r["ts"])
    assert [c.facts["regularity"] for c in run(b, recs)] == ["jittered"] * 3
    later = [conn(T0 + 9000 + i * 60, dst="203.0.113.14") for i in range(15)]
    (reg,) = run(b, later)
    assert reg.facts["regularity"] in ("regular", "very regular")


def test_jitter_regular_returns_the_beat_and_guards_a_zero_median():
    from tapwatch.detectors import jitter_regular
    assert jitter_regular([0.0] * 11, 0) is None

def test_jitter_regular_needs_the_band_and_few_folded_beats():
    from tapwatch.detectors import jitter_regular
    assert jitter_regular([300, 290, 310, 600, 305, 295, 300, 280, 320, 300, 310]) == 300  # one missed beat folds
    assert jitter_regular([30, 30, 30, 300, 30, 300, 30, 300, 30, 300, 30]) is None         # two lengths: a keepalive mix
    assert jitter_regular([3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3]) is None                        # under the minimum interval


def test_beaconing_ignores_human_browsing_jitter():
    rng = random.Random(1)
    ts, recs = T0, []
    for _ in range(40):
        ts += rng.uniform(5, 400)
        recs.append(conn(ts))
    assert run(Beaconing(), recs) == []


def test_beaconing_reports_once_and_carries_sni():
    recs = [ssl(T0 - 1, "updates.example.com")] + [conn(T0 + i * 30) for i in range(40)]
    cases = run(Beaconing(), recs)
    assert len(cases) == 1
    assert cases[0].indicators == ["updates.example.com"]


def test_beaconing_reports_per_destination_with_an_expiry_and_a_fanout_budget():
    # One benign heartbeat on 443 used to silence every later beacon from that PC on 443, forever.
    b = Beaconing(reported_days=7, fanout_per_day=3)
    beats = lambda dst, start=T0: [conn(start + i * 300, dst=dst) for i in range(12)]
    first = run(b, [ssl(T0 - 2, "music.example", dst="203.0.113.5")] + beats("203.0.113.5"))
    second = run(b, [ssl(T0 - 1, "c2.example", dst="203.0.113.6")] + beats("203.0.113.6"))
    assert [c.indicators for c in first + second] == [["music.example"], ["c2.example"]]
    assert run(b, beats("203.0.113.5", T0 + 86400)) == []                # same destination, 1 day later: silent
    later = [conn(T0 + 8 * 86400 + i * 300, dst="203.0.113.5") for i in range(60)]  # the window rolls over
    assert len(run(b, later)) == 1                                         # 8 days later: reported again
    # fan-out: a client that polls many servers on one port the same way gets 3 cases a day, not 57
    fan = Beaconing(fanout_per_day=3)
    cases = []
    for i in range(20):
        cases += run(fan, beats(f"198.51.100.{i + 1}", T0 + i * 10))
    assert len(cases) == 3 and len(run(fan, beats("198.51.100.99", T0 + 86400 + 4000))) == 1
    # the saved state round-trips, and the old (host, port) set shape starts over instead of crashing
    again = Beaconing()
    again.restore(b.snapshot())
    assert again.reported == b.reported
    again.restore({"reported": {"$set": [{"$tuple": ["192.168.50.10", 443]}]}})
    assert again.reported == {}


def test_beaconing_skips_internal_destinations():
    assert run(Beaconing(), [conn(T0 + i * 60, dst="192.168.50.2") for i in range(20)]) == []


def test_dns_failures_trigger():
    recs = [dns(T0 + i, f"host{i}.example.net", rcode="NXDOMAIN") for i in range(30)]
    cases = run(SuspiciousDNS(), recs)
    assert len(cases) == 1 and cases[0].facts["failed"] >= 25


def test_dns_random_names_trigger_dga():
    rng = random.Random(2)
    names = ["".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(16)) + ".com"
             for _ in range(20)]
    cases = run(SuspiciousDNS(), [dns(T0 + i, n) for i, n in enumerate(names)])
    assert len(cases) == 1 and cases[0].facts["random_looking"] >= 15


def test_dns_numbered_cdn_hosts_under_popular_domains_are_not_dga():
    rng = random.Random(3)
    cdn = [f"{rng.getrandbits(32):08x}-{rng.getrandbits(16):04x}-netseer-ipaddr-assoc.xz.fbcdn.net" for _ in range(10)]
    cdn += [f"gspe{n}-ssl-{n * 7}.ls.apple.com" for n in range(10, 20)]
    popular = {"fbcdn.net", "apple.com"}
    assert run(SuspiciousDNS(popular=popular), [dns(T0 + i, n) for i, n in enumerate(cdn)]) == []
    assert run(SuspiciousDNS(), [dns(T0 + i, n) for i, n in enumerate(cdn)])  # without the list it fires
    # Random names under an unknown domain still count, popular list or not.
    dga = ["".join(rng.choice("bcdfghjklmnpqrstvwxz0123456789") for _ in range(16)) + ".com" for _ in range(20)]
    assert run(SuspiciousDNS(popular=popular), [dns(T0 + i, n) for i, n in enumerate(dga)])


def test_dns_local_only_names_dont_count():
    # Reverse lookups of CDN IPs with no PTR, search-suffix probes, and Chrome's WebRTC
    # <uuid>.local names. None of these can reach an attacker's zone.
    rng = random.Random(4)
    recs = [dns(T0 + i, f"{i}.33.18.104.in-addr.arpa", rcode="NXDOMAIN") for i in range(30)]
    recs += [dns(T0 + 30 + i, "wpad.localdomain", rcode="NXDOMAIN") for i in range(10)]
    recs += [dns(T0 + 40 + i, f"{rng.getrandbits(128):032x}.local") for i in range(20)]
    recs += [dns(T0 + 60, "metadata.google.internal.", rcode="NXDOMAIN")]
    assert run(SuspiciousDNS(), recs) == []
    # Internet failures still fire alongside them.
    recs += [dns(T0 + 70 + i, f"host{i}.example.net", rcode="NXDOMAIN") for i in range(25)]
    assert len(run(SuspiciousDNS(), recs)) == 1


def test_dns_normal_browsing_quiet():
    names = ["www.example.com", "mail.example.org", "cdn.example.net"] * 30
    assert run(SuspiciousDNS(), [dns(T0 + i, n) for i, n in enumerate(names)]) == []


def test_port_scan():
    recs = [conn(T0 + i * 0.1, dst=f"192.168.50.{i % 20 + 2}", port=1000 + i, state="REJ") for i in range(60)]
    cases = run(PortScan(), recs)
    assert len(cases) == 1
    assert cases[0].facts["internal_targets"] is True and cases[0].facts["failed_pct"] == 100
    assert cases[0].facts["proto"] == "tcp"


def test_udp_counts_as_a_scan_only_in_a_sweep_shape():
    def udp(ts, dst, port):
        r = conn(ts, dst=dst, port=port, state="S0")
        r["proto"] = "udp"
        return r
    # the main PC's NetBIOS name fallback: udp/137 S0 to 63 public addresses (#73) is discovery, not a scan
    assert run(PortScan(), [udp(T0 + i * 0.1, f"203.0.113.{i + 1}", 137) for i in range(63)]) == []
    # BitTorrent DHT / game peers gone away: many hosts on many ports, no sweep shape
    assert run(PortScan(), [udp(T0 + i * 0.1, f"203.0.113.{i + 1}", 20000 + i) for i in range(60)]) == []
    # one host, many ports (a UDP port scan) and one port, many hosts (a host sweep) still count
    ports = run(PortScan(), [udp(T0 + i * 0.1, "192.168.50.7", 1000 + i) for i in range(60)])
    hosts = run(PortScan(), [udp(T0 + i * 0.1, f"192.168.50.{i + 2}", 161) for i in range(60)])
    assert [c.facts["proto"] for c in ports + hosts] == ["udp", "udp"] and hosts[0].facts["hosts"] == 50  # fires at the threshold


def test_ioc_hits_are_must_alert():
    det = IOCMatch({"198.51.100.66"}, {"bad.example"})
    cases = run(det, [conn(T0, dst="198.51.100.66"), dns(T0 + 1, "x.bad.example"), dns(T0 + 2, "notbad.example")])
    assert [c.must_alert for c in cases] == [True, True]


def test_suricata_severity_one_is_must_alert():
    det = SuricataAlert()
    hi = det.feed(_parse_line(__import__("json").dumps(eve_alert("2026-10-11T12:00:00.000000+0000", 1)), "eve"))
    lo = det.feed(_parse_line(__import__("json").dumps(eve_alert("2026-10-11T12:00:00.000000+0000", 3)), "eve"))
    assert hi[0].must_alert and hi[0].ts > 0
    assert not lo[0].must_alert


def test_upload_spike_against_own_baseline():
    det = HourlyProfile()
    recs = [conn(T0 + h * 3600, orig_bytes=10_000_000) for h in range(8)]       # 10 MB/h for 8 hours
    recs += [conn(T0 + 8 * 3600 + 60, orig_bytes=1_000_000_000)]                 # then 1 GB in one hour
    recs += [conn(T0 + 9 * 3600)]                                                # next hour closes the spike hour
    cases = [c for c in run(det, recs) if c.detector == "upload_spike"]
    assert len(cases) == 1 and cases[0].facts["mb"] == 1000 and cases[0].facts["basis"] == "recent hours"


def test_upload_spike_from_a_managed_device_is_capped_at_digest():
    # #139/#325: the employer-managed laptop's EDR agent uploads ~1 GB to plain AWS most mornings; #371 a
    # 1.5 GB Meet call. No destination cap fits, but the role in assets.yaml says who watches the device.
    from tapwatch.detectors import Identity, managed_hosts
    assets = {"name:WorkBook": {"role": "laptop (employer-managed, security agent)"},
              "MAC:AA:BB:CC:DD:EE:21": {"role": "corporate laptop"}, "192.168.50.44": {"role": "desktop (EDR)"},
              "192.168.50.13": {"role": "workstation"}, "192.168.50.2": {"role": "managed switch"},
              "192.168.50.3": {"role": "self-managed NAS"}}
    managed = managed_hosts(assets)
    assert managed == {"name:workbook": "laptop (employer-managed, security agent)", "192.168.50.44": "desktop (edr)",
                       "mac:aa:bb:cc:dd:ee:21": "corporate laptop"}   # "managed" alone is not a work device

    def spike(src):
        recs = [conn(T0 + h * 3600, src=src, orig_bytes=10_000_000) for h in range(8)]
        return recs + [conn(T0 + 8 * 3600 + 60, src=src, orig_bytes=1_000_000_000), conn(T0 + 9 * 3600, src=src)]

    ident, det = Identity(), HourlyProfile(managed=managed)
    det.ident = ident
    feed_all([ident], [dict(dhcp(T0 - 10, mac="aa:bb:cc:dd:ee:20"), host_name="WorkBook", assigned_addr="192.168.50.80"),
                       dict(dhcp(T0 - 9, mac="aa:bb:cc:dd:ee:21"), host_name="Other", assigned_addr="192.168.50.81")])
    (c,) = [c for c in run(det, spike("192.168.50.80")) if c.detector == "upload_spike"]   # known by name: key
    assert c.facts["managed_device"] == "laptop (employer-managed, security agent)" and c.facts["max_route"] == "digest"
    det = HourlyProfile(managed=managed)
    det.ident = ident
    (m,) = [c for c in run(det, spike("192.168.50.81")) if c.detector == "upload_spike"]
    assert m.facts["managed_device"] == "corporate laptop"   # keyed name:other, but the assets entry is its MAC
    (plain,) = [c for c in run(HourlyProfile(managed=managed), spike("192.168.50.44")) if c.detector == "upload_spike"]
    assert plain.facts["managed_device"] == "desktop (edr)" and plain.facts["max_route"] == "digest"   # by address
    for src in ("192.168.50.13", "192.168.50.99"):   # "workstation" doesn't match; unlabelled stays Jev-routed
        (u,) = [c for c in run(HourlyProfile(managed=managed), spike(src)) if c.detector == "upload_spike"]
        assert "managed_device" not in u.facts and "max_route" not in u.facts


def test_cases_carry_the_site_category_from_the_offline_list():
    from tapwatch.categories import set_categories
    from tapwatch.detectors import TlsOddities
    set_categories({"ads.example": "advertising", "tube.example": "media"})
    try:
        nd = NewExternalDomain(Warmup(0), window=300)
        (c,) = run(nd, [dns(T0, "a.ads.example"), dns(T0 + 1, "b.tube.example"), dns(T0 + 2, "plain.example")]) + nd.flush()
        assert c.facts["categories"] == ["advertising", "media"] and c.facts["count"] == 3   # distinct kinds, unlisted left out
        odd = {"_type": "ssl", "ts": T0, "id.orig_h": "192.168.50.10", "id.resp_h": "198.51.100.7", "id.resp_p": 4443,
               "established": True, "server_name": "x.ads.example", "validation_status": "self signed certificate"}
        (t,) = run(TlsOddities(Warmup(0)), [odd])
        assert t.facts["category"] == "advertising" and t.facts["score"] == 3
        up = HourlyProfile()
        recs = [dict(dns(T0 - 10, "big.tube.example"), answers=["203.0.113.5"])]
        recs += [conn(T0 + h * 3600, orig_bytes=10_000_000) for h in range(8)]
        recs += [conn(T0 + 8 * 3600 + 60, orig_bytes=1_000_000_000), conn(T0 + 9 * 3600)]
        (u,) = [c for c in run(up, recs) if c.detector == "upload_spike"]
        assert u.facts["top_category"] == "media"
    finally:
        set_categories({})


def test_cases_name_the_outside_address_they_are_about():
    """`dests`: the exact address the case's connection went to, so host context scopes to it instead of inferring
    the destination from DNS answers in the window (review of #117, 2026-10-17)."""
    from tapwatch.detectors import DnsBypass, TakeoverChannel, TlsOddities
    (b,) = run(Beaconing(), [conn(T0 + i * 60) for i in range(15)])
    assert b.facts["dests"] == ["203.0.113.5"]
    odd = {"_type": "ssl", "ts": T0, "id.orig_h": "192.168.50.10", "id.resp_h": "198.51.100.7", "id.resp_p": 4443,
           "established": True, "validation_status": "self signed certificate"}
    assert run(TlsOddities(Warmup(0)), [odd])[0].facts["dests"] == ["198.51.100.7"]
    (i,) = run(IOCMatch({"203.0.113.5"}, set()), [conn(T0)])
    assert i.facts["dests"] == ["203.0.113.5"]
    resolver = dict(conn(T0, dst="203.0.113.53", port=53), service="dns")
    resolver["proto"] = "udp"
    assert run(DnsBypass(Warmup(0)), [resolver])[0].facts["dests"] == ["203.0.113.53"]
    nd = NewExternalDomain(Warmup(0), window=300)
    hello = dict(dns(T0, "one.example"), answers=["203.0.113.11", "203.0.113.12", "cname.example"])
    tls = {"_type": "ssl", "ts": T0 + 1, "id.orig_h": "192.168.50.10", "id.resp_h": "203.0.113.13", "id.resp_p": 443,
           "established": True, "server_name": "two.example"}
    (n,) = run(nd, [hello, tls]) + nd.flush()
    assert n.facts["dests"] == ["203.0.113.11", "203.0.113.12", "203.0.113.13"]   # CNAME answers are not addresses
    # a window with many names: the addresses behind the three shown names survive the cap of eight
    nd = NewExternalDomain(Warmup(0), window=300)
    many = [dict(dns(T0 + k, f"site{k}.example"), answers=[f"203.0.113.{100 + k}"]) for k in range(12)]
    many.append(dict(dns(T0 + 20, "x7q9zk2pv4m8.example"), answers=["203.0.113.250"]))   # random-looking: shown first
    (m,) = run(nd, many) + nd.flush()
    assert len(m.facts["dests"]) == 8 and m.facts["dests"][0] == "203.0.113.250"
    (tk,) = run(TakeoverChannel(), [dict(dns(T0, "abc.webhook.site"), answers=["203.0.113.21"])])
    assert tk.facts["dests"] == ["203.0.113.21"]
    # nothing outside and known: no key at all, so a scan or an upload spike keeps the whole window as its context
    from tapwatch.detectors import dests
    assert dests("192.168.50.1", "", None, "not-an-ip") == {}


def ticks(det, start, end):
    """`run` ticks once a minute; collect every case from the ticks in (start, end]."""
    out, t = [], start + 60
    while t <= end:
        out += det.tick(t)
        t += 60
    return out


def test_feed_silence_reports_a_stopped_feed_once_and_rearms_when_it_resumes():
    """R22 (2026-10-17): osquery denylisted the Windows socket query twice and nobody noticed for a day."""
    from tapwatch.detectors import FeedSilence
    win = "/mnt/c/Program Files/osquery/log"
    clock = [T0]
    det = FeedSilence({"conn": (1200, 4), f"{win}|outbound_connections": (600, 4)}, host="192.168.50.10",
                      started=T0, clock=lambda: clock[0])
    sockets = {"_type": "osquery", "_log": win, "name": "outbound_connections", "ts": 0, "action": "added"}  # ts unused
    clock[0] = T0 + 10
    assert det.feed(conn(T0 - 3600)) == []            # an old timestamp catching up still counts as arriving now
    clock[0] = T0 + 30
    assert det.feed(sockets) == []
    assert ticks(det, T0, T0 + 600) == []             # 570 s since the last socket row: under 600
    (c,) = ticks(det, T0 + 600, T0 + 660)             # 630 s: the socket feed is silent
    assert (c.detector, c.host, c.base_severity) == ("feed_silence", "192.168.50.10", 4)
    assert c.indicators == ["windows:outbound_connections"] and c.facts["feeds"] == ["outbound_connections"]
    assert c.facts["from"] == "the Windows agent" and c.facts["source"] == "monitor" and c.facts["silent_minutes"] == 10 and not c.facts["never_seen"]
    assert ticks(det, T0 + 660, T0 + 1000) == []      # one case per silence
    clock[0] = T0 + 1000
    det.feed(sockets)                                 # it resumed
    # conn: silent since its row arrived at T0 + 10, limit 20 min; the socket feed is young again
    (z,) = ticks(det, T0 + 1000, T0 + 1260)
    assert z.indicators == ["zeek:conn.log"] and z.facts["from"] == "the network tap"
    (again,) = ticks(det, T0 + 1260, T0 + 1680)       # the socket feed stopped again: a new case
    assert again.indicators == ["windows:outbound_connections"] and again.facts["silent_minutes"] == 10


def test_feed_silence_measures_from_start_resets_when_the_monitor_was_away_and_collapses_per_agent():
    from tapwatch.detectors import FeedSilence
    win, wsl = "/mnt/c/Program Files/osquery/log", "/var/log/osquery"
    det = FeedSilence({f"{win}|sysmon_events": (900, 4), f"{win}|host_addresses": (1200, 3),
                       f"{wsl}|host_addresses": (1800, 3)}, started=T0, clock=lambda: T0)
    # never seen since start: measured from the start, so a feed already dead at start is still reported
    assert ticks(det, T0, T0 + 840) == []
    (never,) = ticks(det, T0 + 840, T0 + 900)
    assert never.facts["never_seen"] and never.host == "this PC" and never.indicators == ["windows:sysmon_events"]
    # the box slept: the next tick comes an hour later; the hour does not count, so the Windows snapshot, 960 s
    # silent before the sleep, is 960 s silent after it and fires 240 s later, not at once
    woke = T0 + 960 + 3600
    assert det.tick(woke) == []
    assert ticks(det, woke, woke + 180) == []
    (snap,) = ticks(det, woke + 180, woke + 240)
    assert snap.indicators == ["windows:host_addresses"] and snap.base_severity == 3 and snap.facts["silent_minutes"] == 20
    (lin,) = ticks(det, woke + 240, woke + 840)
    assert lin.indicators == ["linux:host_addresses"] and lin.key != snap.key   # two agents, same query name, two cases
    # several feeds of one agent going silent in the same tick make one case, the loudest first
    both = FeedSilence({f"{win}|sysmon_events": (900, 4), f"{win}|host_addresses": (900, 3), "conn": (900, 4)},
                       started=T0)
    cases = ticks(both, T0, T0 + 900)
    assert sorted(c.indicators[0] for c in cases) == ["windows:sysmon_events", "zeek:conn.log"]
    agent = next(c for c in cases if c.facts["from"] == "the Windows agent" and c.facts["source"] == "monitor")
    assert agent.indicators == ["windows:sysmon_events", "windows:host_addresses"] and agent.base_severity == 4
    assert agent.title == "Log feeds have stopped arriving" and agent.facts["feeds"] == ["sysmon_events", "host_addresses"]
    # rows from other query names, or replayed rows with no log directory, are not watched
    both.feed({"_type": "osquery", "_log": win, "name": "listening_ports"})
    both.feed({"_type": "osquery", "name": "sysmon_events"})
    assert both.last == {}


def test_feed_expectations_follow_the_agents_that_exist(tmp_path, monkeypatch):
    from tapwatch import detectors as det
    monkeypatch.setattr(det, "WINDOWS_AGENT_PREFIX", str(tmp_path / "mnt"))
    win = tmp_path / "mnt" / "c" / "osquery" / "log"; win.mkdir(parents=True)
    (win / "osqueryd.results.log").write_text("")
    wsl = tmp_path / "var" / "log" / "osquery"; wsl.mkdir(parents=True)
    (wsl / "osqueryd.results.log").write_text("")
    cfg = {"host_context": {"host": "192.168.50.10",
                            "results_logs": [str(win / "osqueryd.results.log"), str(wsl / "osqueryd.results.log"),
                                             str(tmp_path / "missing" / "osqueryd.results.log")]},
           "detectors": {"feed_silence": {"minutes": {"conn": 45}, "ignore": ["bpf_connections"]}}}
    exp = det.feed_expectations(cfg)
    assert exp["conn"] == (2700, 4) and exp["dns"] == (1200, 4)                      # a limit override keeps the severity
    assert exp[f"{win}|outbound_connections"] == (600, 4) and f"{win}|bpf_process_events" not in exp
    assert exp[f"{wsl}|outbound_connections_ctx"] == (1800, 3) and f"{wsl}|bpf_connections" not in exp
    assert not any(k.startswith(str(tmp_path / "missing")) for k in exp)
    built = [d for d in det.build(cfg) if d.name == "feed_silence"]
    assert len(built) == 1 and built[0].host == "192.168.50.10"
    cfg["detectors"]["feed_silence"]["enabled"] = False
    assert not [d for d in det.build(cfg) if d.name == "feed_silence"]


def test_first_seen_rules_quiet_during_warmup():
    w = Warmup(600)
    nd, dev = NewExternalDomain(w), NewDevice(w)
    early = [dns(T0, "a.example.com"), conn(T0, src="192.168.50.11")]
    late = [dns(T0 + 700, "www.example.com"), dns(T0 + 701, "new.example.org"), conn(T0 + 702, src="192.168.50.12")]
    assert run(nd, early) == [] and run(dev, early) == []
    assert run(nd, late) == []  # new domains are buffered into a window
    cases = nd.flush()
    assert [c.indicators for c in cases] == [["new.example.org"]]  # same base domain as warmup = known
    assert [c.host for c in run(dev, late)] == ["192.168.50.12"]


def test_new_domains_grouped_per_window_and_failed_lookups_skipped():
    rng = random.Random(3)
    nd = NewExternalDomain(Warmup(0), window=300)
    recs = [dns(T0 + i, "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(16)) + ".com",
                rcode="NXDOMAIN") for i in range(30)]  # DGA misses: SuspiciousDNS's job
    recs += [dns(T0 + 40 + i, n) for i, n in enumerate(["news.example.com", "q8z3kx0vw7p2mr.example.net",
                                                          "shop.example.org"])]
    assert run(nd, recs) == []
    cases = run(nd, [dns(T0 + 400, "late.example.info")])  # a record after the window closes it
    assert len(cases) == 1
    c = cases[0]
    assert c.facts["count"] == 3 and c.facts["random"] == 1
    assert c.indicators[0] == "q8z3kx0vw7p2mr.example.net"  # odd one listed first
    assert c.title == "First contact with 3 new domains"


def test_new_domain_counts_other_devices_already_using_it():
    nd = NewExternalDomain(Warmup(0))
    run(nd, [dns(T0, "www.example.com", src="192.168.50.20"), dns(T0 + 1, "www.example.com", src="192.168.50.21")])
    by_host = {c.host: c for c in nd.flush()}
    assert by_host["192.168.50.20"].facts["shared"] == 0
    assert by_host["192.168.50.21"].facts["shared"] == 1


def test_readable_long_names_are_not_random_but_dga_is():
    for name in ["krebsonsecurity.com", "bleepingcomputer.com", "lobste.rs", "stackoverflow.com",
                 "microsoftonline.com", "googleusercontent.com"]:
        assert not looks_random(name), name
    for name in ["q8z3kx0vw7p2mr.com", "xkqjzvbnmtrpwl.net", "a1b2c3d4e5f6.org"]:
        assert looks_random(name), name


def test_multicast_and_broadcast_count_as_local():
    assert is_internal("224.0.0.251") and is_internal("ff02::fb") and is_internal("255.255.255.255")
    assert not is_internal("198.51.100.7")
    # a LAN device's global IPv6 address counts as inside only once the site's prefix is configured
    assert not is_internal("2001:db8:1:2::10")
    beats = [conn(T0 + i * 300, src="2001:db8:1:2::10", dst="2001:db8:9::1") for i in range(12)]
    assert run(Beaconing(), beats) == []                                     # unknown prefix: not a LAN device
    try:
        build({"network": {"local_nets": ["2001:db8:1::/48"]}})
        assert is_internal("2001:db8:1:2::10") and not is_internal("2001:db8:2::1")
        assert len(run(Beaconing(), beats)) == 1                             # now it is, and its beacon is seen
    finally:
        set_local_nets(())


def test_mdns_chatter_is_not_beaconing_and_link_local_is_not_a_new_device():
    assert run(Beaconing(), [conn(T0 + i * 30, dst="224.0.0.251", port=5353) for i in range(40)]) == []
    dev = NewDevice(Warmup(0))
    assert run(dev, [conn(T0, src="fe80::1489:d4b5:cb15:a5cf", dst="ff02::fb", port=5353)]) == []


# ----------------------------------------------- home rules (R01, R03, R13, R14)

GW = "192.168.50.1"


def inbound(ts, dst="192.168.50.10", port=8000, proto="tcp", state="SF", resp_bytes=900, src="198.51.100.7"):
    r = conn(ts, src=src, dst=dst, port=port, state=state, service="http")
    r.update(proto=proto, resp_bytes=resp_bytes, history="ShADadFf" if proto == "tcp" else "Dd")
    return r


def test_exposure_alerts_once_on_an_answered_inbound_connection():
    det = InternetExposure(Warmup(0))
    assert run(det, [inbound(T0, port=9999)]) == []          # first 2 minutes: may be mid-flow
    cases = run(det, [inbound(T0 + 200), inbound(T0 + 205, src="203.0.113.9")])
    assert len(cases) == 1
    c = cases[0]
    assert c.host == "192.168.50.10" and c.must_alert and c.facts["port"] == 8000
    assert not c.facts["after_mapping_request"]


def test_exposure_ignores_unanswered_probes_and_learns_existing_forwards():
    det = InternetExposure(Warmup(600), startup=0)
    assert run(det, [inbound(T0 + 1, state="S0", resp_bytes=0), inbound(T0 + 2, state="REJ")]) == []
    assert run(det, [inbound(T0 + 3, port=443)]) == []          # forward that already existed during warmup
    assert run(det, [inbound(T0 + 700, port=443)]) == []
    assert len(run(det, [inbound(T0 + 701, port=22)])) == 1


def test_exposure_skips_p2p_after_stun_and_notes_mapping_requests():
    det = InternetExposure(Warmup(0), startup=0)
    stun = conn(T0, port=3478)
    stun["proto"] = "udp"
    mapping = conn(T0 + 1, dst=GW, port=5351)
    assert run(det, [stun, mapping, inbound(T0 + 10, port=51000, proto="udp")]) == []
    cases = run(det, [inbound(T0 + 20, port=32400)])
    assert cases[0].facts["after_mapping_request"]


def test_exposure_ignores_flows_zeek_saw_mid_stream_or_that_answer_the_device():
    det = InternetExposure(Warmup(0), startup=0)
    midstream = dict(inbound(T0), history="DadA")
    flipped_udp = dict(inbound(T0 + 1, port=50733, proto="udp"), history="^dD")
    vpn_out = conn(T0 + 2, dst="203.0.113.50", port=4501)
    vpn_reply = inbound(T0 + 100, port=50734, proto="udp", src="203.0.113.50")
    assert run(det, [midstream, flipped_udp, vpn_out, vpn_reply]) == []
    assert len(run(det, [inbound(T0 + 3000, port=50734, proto="udp", src="203.0.113.50")])) == 1


def test_mgmt_access_flags_new_admin_port_pairs_but_not_admins_or_learned_pairs():
    det = ManagementAccess(Warmup(600), gateways=Gateways({GW}), admin_devices={"192.168.50.20"})
    learned = conn(T0, src="192.168.50.10", dst=GW, port=443)
    assert run(det, [learned]) == []                                       # warmup
    later = [conn(T0 + 700, src="192.168.50.10", dst=GW, port=443),       # learned pair
             conn(T0 + 701, src="192.168.50.20", dst=GW, port=22),        # admin device
             conn(T0 + 702, src=GW, dst="192.168.50.30", port=22),        # router managing an AP
             conn(T0 + 703, src="192.168.50.30", dst="192.168.50.40", port=443),  # 443 on a non-router is fine
             conn(T0 + 704, src="192.168.50.30", dst=GW, port=443, state="S0"),
             conn(T0 + 705, src="192.168.50.30", dst="192.168.50.40", port=3389, state="REJ"),
             conn(T0 + 706, src="192.168.50.30", dst="192.168.50.40", port=3389, state="REJ")]
    cases = run(det, later)
    assert [(c.facts["target"], c.facts["port"]) for c in cases] == [("router", 443), ("device", 3389)]
    assert not cases[0].facts["answered"]
    assert [c.base_severity for c in cases] == [2, 2]                     # unanswered: digest, not critical
    accepted = [conn(T0 + 710, src="192.168.50.31", dst="192.168.50.40", port=445),
                conn(T0 + 711, src="192.168.50.32", dst="192.168.50.40", port=3389),
                conn(T0 + 712, src="192.168.50.33", dst=GW, port=443)]
    assert [c.base_severity for c in run(det, accepted)] == [3, 4, 4]     # SMB session; RDP; the router's UI


def test_cleartext_auth_grades_by_destination_and_never_copies_credentials():
    det = CleartextAuth()
    http_auth = {"_type": "http", "ts": T0, "id.orig_h": "192.168.50.10", "id.resp_h": "203.0.113.5",
                 "id.resp_p": 80, "host": "api.example.com", "username": "alice"}
    lan_auth = dict(http_auth, **{"id.resp_h": "192.168.50.30", "host": "printer.lan"})
    ftp = {"_type": "ftp", "ts": T0, "id.orig_h": "192.168.50.10", "id.resp_h": "203.0.113.6",
           "id.resp_p": 21, "user": "bob", "password": "hunter2"}
    anon = dict(ftp, user="anonymous")
    mqtt = conn(T0, port=1883, service="mqtt")
    telnet = conn(T0, dst="203.0.113.7", port=23, service=None)
    failed = conn(T0, dst="203.0.113.8", port=23, state="S0")
    cases = run(det, [http_auth, http_auth, lan_auth, ftp, anon, mqtt, telnet, failed])
    sev = sorted((c.facts["what"], c.facts["outside"], c.base_severity) for c in cases)
    assert sev == [("FTP login", True, 4), ("HTTP login (basic auth)", False, 1),
                   ("HTTP login (basic auth)", True, 2), ("MQTT", True, 2), ("Telnet", True, 4)]
    blob = repr([(c.facts, c.indicators, c.title) for c in cases])
    assert "alice" not in blob and "bob" not in blob and "hunter2" not in blob


def test_rogue_dhcp_with_configured_gateway():
    det = RogueDHCP(Warmup(600), gateways=Gateways({GW}))
    assert run(det, [dhcp(T0), dhcp(T0 + 1, server="192.168.50.1")]) == []
    cases = run(det, [dhcp(T0 + 2, server="192.168.50.99", msg_types=("OFFER",)),
                      dhcp(T0 + 3, server="192.168.50.99")])
    assert len(cases) == 1 and cases[0].host == "192.168.50.99" and cases[0].must_alert


def test_rogue_dhcp_configured_gateway_still_learns_other_vlans():
    # The wizard writes one gateway; a VLAN'd router answers DHCP from an address per VLAN.
    gw = Gateways({GW})
    det = RogueDHCP(Warmup(600), gateways=gw)
    iot = lambda ts, client, server="192.168.60.1": dict(
        dhcp(ts, server=server), client_addr=client, assigned_addr=client)
    assert run(det, [iot(T0, "192.168.60.10")]) == []              # warmup: trusted, not an alert
    feed_all([gw, det], [iot(T0 + 700 + i, f"192.168.60.{20 + i}") for i in range(3)])
    assert gw.leader("192.168.60") == "192.168.60.1"               # learned as that VLAN's router
    assert run(det, [iot(T0 + 800, "192.168.60.30", server="192.168.60.99")])[0].must_alert
    # a VLAN first seen after warmup: its only DHCP server is trusted once, a second one is rogue
    guest = lambda ts, server: dict(dhcp(ts, server=server), client_addr="192.168.70.10")
    assert run(det, [guest(T0 + 900, "192.168.70.1")]) == []
    assert run(det, [guest(T0 + 901, "192.168.70.99")])[0].host == "192.168.70.99"
    # the configured /24 stays strict, even during warmup
    assert run(RogueDHCP(Warmup(600), gateways=Gateways({GW})),
               [dhcp(T0, server="192.168.50.99")])[0].must_alert


def test_rogue_dhcp_learns_servers_during_warmup_and_reads_conn_replies():
    det = RogueDHCP(Warmup(600))
    assert run(det, [dhcp(T0)]) == []                                          # learned as trusted
    reply = conn(T0 + 700, src="192.168.50.10", dst="192.168.50.77", port=67, service="dhcp")
    reply.update(proto="udp", resp_bytes=300)
    broadcast = dict(reply, **{"id.resp_h": "255.255.255.255"})
    assert run(det, [dhcp(T0 + 650), broadcast]) == []
    assert [c.facts["how"] for c in run(det, [reply])] == ["answered on the DHCP port"]


def test_build_wires_home_rules_from_network_config():
    dets = {d.name: d for d in build({"network": {"gateways": [GW], "admin_devices": ["192.168.50.20"]}})}
    assert {"gateways", "exposure", "mgmt_access", "cleartext_auth", "rogue_dhcp"} <= set(dets)
    assert GW in dets["rogue_dhcp"].gateways and dets["mgmt_access"].admins == {"192.168.50.20"}
    assert next(iter(dets)) == "gateways"  # must see each record before the rules that ask it


# ------------------------------------------- no network.gateways: learn the router

def dns_to(ts, client, resolver=GW):
    r = conn(ts, src=client, dst=resolver, port=53, service="dns")
    r["proto"] = "udp"
    return r


def feed_all(dets, recs):
    out = []
    for r in recs:
        for d in dets:
            out += d.feed(r)
    return out


def test_gateways_elects_the_address_three_devices_use_and_keeps_it():
    gw = Gateways()
    feed_all([gw], [dns_to(T0, "192.168.50.10"), dns_to(T0 + 1, "192.168.50.11")])
    assert GW not in gw                                           # 2 devices: not enough yet
    third = dict(dhcp(T0 + 2), assigned_addr="192.168.50.12")
    feed_all([gw], [third])                                       # DHCP reply to a third device counts
    assert GW in gw and gw.leader("192.168.50") == GW
    rogue_votes = [dns_to(T0 + 10 + i, f"192.168.50.{20 + i}", resolver="192.168.50.99") for i in range(5)]
    feed_all([gw], rogue_votes)
    assert gw.leader("192.168.50") == GW and "192.168.50.99" not in gw  # sticky
    assert "192.168.60.1" not in gw                               # other LANs are separate


def test_unconfigured_router_is_not_flagged_even_with_no_warmup():
    """The bug this guards: with no gateways set and warmup 0, the UDM itself was a 'rogue DHCP server'."""
    gw = Gateways()
    dets = [gw, RogueDHCP(Warmup(0), gw)]
    recs = [dns_to(T0 + i, f"192.168.50.{10 + i}") for i in range(3)] + [dhcp(T0 + 5), dhcp(T0 + 6)]
    assert feed_all(dets, recs) == []


def test_unconfigured_second_dhcp_server_is_rogue_once_the_router_is_known():
    gw = Gateways()
    dets = [gw, RogueDHCP(Warmup(0), gw)]
    feed_all(dets, [dns_to(T0 + i, f"192.168.50.{10 + i}") for i in range(3)])
    cases = feed_all(dets, [dhcp(T0 + 10, server="192.168.50.99", msg_types=("OFFER",))])
    assert [c.host for c in cases] == ["192.168.50.99"]


def test_unconfigured_first_server_on_a_quiet_lan_is_trusted_and_a_second_one_is_not():
    gw = Gateways()
    dets = [gw, RogueDHCP(Warmup(0), gw)]
    assert feed_all(dets, [dhcp(T0, server="192.168.60.1")]) == []   # 1 device: no router elected
    cases = feed_all(dets, [dhcp(T0 + 5, server="192.168.60.50")])
    assert [c.host for c in cases] == ["192.168.60.50"]


def test_unconfigured_servers_seen_in_warmup_are_trusted():
    """E.g. a Pi-hole answers DNS (elected) while the UDM does DHCP: warmup keeps the UDM trusted."""
    gw = Gateways()
    dets = [gw, RogueDHCP(Warmup(600), gw)]
    feed_all(dets, [dns_to(T0 + i, f"192.168.50.{10 + i}", resolver="192.168.50.2") for i in range(3)])
    assert feed_all(dets, [dhcp(T0 + 10), dhcp(T0 + 900)]) == []
    assert len(feed_all(dets, [dhcp(T0 + 901, server="192.168.50.77")])) == 1


def test_mgmt_access_uses_the_learned_router():
    gw = Gateways()
    dets = [gw, ManagementAccess(Warmup(0), gw)]
    feed_all(dets, [dns_to(T0 + i, f"192.168.50.{10 + i}") for i in range(3)])
    ui = conn(T0 + 10, src="192.168.50.30", dst=GW, port=443)
    router_ssh = conn(T0 + 11, src=GW, dst="192.168.50.40", port=22)   # router managing an AP
    cases = feed_all(dets, [ui, router_ssh])
    assert [(c.facts["target"], c.facts["port"]) for c in cases] == [("router", 443)]


def test_build_without_network_config_learns_the_router_from_the_logs():
    dets = build({"warmup_seconds": 0})
    recs = [dns_to(T0 + i, f"192.168.50.{10 + i}") for i in range(3)] + [dhcp(T0 + 5)]
    assert [c for c in feed_all(dets, recs) if c.detector == "rogue_dhcp"] == []
    assert GW in dets[0]


# ------------------------------------------------ dev workstation + takeover (R16)

DEV = "192.168.50.10"
OTHER = "192.168.50.11"


def test_suffix_match_needs_a_label_boundary():
    doms = frozenset({"github.com", "pkg.dev"})
    assert suffix_match("api.github.com.", doms) == "github.com"
    assert suffix_match("us-docker.pkg.dev", doms) == "pkg.dev"
    assert suffix_match("evilgithub.com", doms) is None and suffix_match("github.com.evil.io", doms) is None


def test_dev_profile_only_covers_listed_hosts_and_dev_services():
    dev = DevProfile([DEV], ["corp-registry.example"])
    assert dev.covers(DEV, "api.anthropic.com") and dev.covers(DEV, "pkgs.corp-registry.example")
    assert not dev.covers(OTHER, "api.anthropic.com")       # other devices are judged as usual
    assert not dev.covers(DEV, "q8z3kx0vw7p2mr.example.net")
    assert not dev.covers(DEV, None)


def test_dev_host_new_dev_domains_are_skipped_but_others_still_counted():
    nd = NewExternalDomain(Warmup(0), dev=DevProfile([DEV]))
    run(nd, [dns(T0, "registry-1.docker.io", src=DEV), ssl(T0 + 1, "api.individual.githubcopilot.com", src=DEV),
             dns(T0 + 2, "unknown-site.example", src=DEV), dns(T0 + 3, "registry-1.docker.io", src=OTHER)])
    by_host = {c.host: c.indicators for c in nd.flush()}
    assert by_host == {DEV: ["unknown-site.example"], OTHER: ["registry-1.docker.io"]}


def test_dev_host_dns_to_dev_services_does_not_count_toward_anomaly():
    det = SuspiciousDNS(dev=DevProfile([DEV]))
    noisy = [dns(T0 + i, f"x{i}.missing.npmjs.org", src=DEV, rcode="NXDOMAIN") for i in range(30)]
    assert run(det, noisy) == []
    assert len(run(det, [dns(T0 + 40 + i, f"h{i}.example.net", src=DEV, rcode="NXDOMAIN") for i in range(30)])) == 1


def test_dev_host_polling_a_dev_api_is_not_beaconing_but_unnamed_traffic_still_is():
    det = Beaconing(dev=DevProfile([DEV]))
    named = [ssl(T0 - 1, "api.anthropic.com", src=DEV)] + [conn(T0 + i * 60, src=DEV) for i in range(15)]
    assert run(det, named) == []
    unnamed = [conn(T0 + i * 60, src=DEV, dst="198.51.100.9", port=8443) for i in range(15)]
    assert len(run(det, unnamed)) == 1


def test_takeover_channels_alert_and_ignore_the_dev_profile():
    det = TakeoverChannel()
    http_drop = {"_type": "http", "ts": T0 + 3, "id.orig_h": DEV, "id.resp_h": "203.0.113.5", "host": "transfer.sh"}
    cases = run(det, [dns(T0, "abc123.webhook.site", src=DEV), ssl(T0 + 1, "abcd.ngrok-free.app", src=DEV),
                      ssl(T0 + 2, "net.anydesk.com", src=OTHER), http_drop,
                      dns(T0 + 4, "zzz.webhook.site", src=DEV)])           # same service again: deduped
    got = [(c.facts["channel"], c.must_alert, c.base_severity) for c in cases]
    assert got == [("callback", True, 5), ("tunnel", False, 4), ("remote_control", False, 4),
                   ("file_drop", True, 5)]


def test_takeover_ignores_failed_lookups_and_lookalikes():
    det = TakeoverChannel(extra={"tunnel": ["mytunnel.example"]})
    assert run(det, [dns(T0, "sn.splashtop.com", rcode="NXDOMAIN"), dns(T0 + 1, "notwebhook.site"),
                     ssl(T0 + 2, "webhook.site.example.com")]) == []
    assert [c.facts["channel"] for c in run(det, [ssl(T0 + 3, "a.mytunnel.example")])] == ["tunnel"]


def test_build_wires_dev_profile_and_takeover():
    dets = {d.name: d for d in build({"dev_profile": {"hosts": [DEV], "domains": ["corp.example"]}})}
    assert "takeover" in dets
    for name in ("beaconing", "dns_anomaly", "new_domain"):
        assert dets[name].dev.covers(DEV, "x.corp.example")


# --------------------------------------- R16 expected remote-support tool (work laptop)



LAPTOP = "192.168.50.22"
MON_10 = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc).timestamp()   # Monday, business hours
MON_21 = datetime(2026, 10, 12, 21, 0, tzinfo=timezone.utc).timestamp()   # Monday evening
SAT_10 = datetime(2026, 10, 17, 10, 0, tzinfo=timezone.utc).timestamp()


def laptop_takeover(**kw):
    expected = [{"host": LAPTOP, "services": ["teamviewer.com", "splashtop.com"], "hours": "Mon-Fri 08:00-18:00",
                 **kw}]
    return TakeoverChannel(expected=expected, timezone="UTC")


def tv_lookup(ts, ip="203.0.113.80"):
    r = dns(ts, "router7.teamviewer.com", src=LAPTOP)
    r["answers"] = [ip]
    return r


def tv_traffic(ts, nbytes, dst="203.0.113.80", port=443):
    r = conn(ts, src=LAPTOP, dst=dst, port=port)
    r["resp_bytes"] = nbytes
    return r


def test_parse_hours():
    days, start, end = parse_hours("Mon-Fri 08:00-18:00")
    assert days == {0, 1, 2, 3, 4} and (start, end) == (480, 1080)
    assert parse_hours("Sat,Sun 9-17")[0] == {5, 6}
    assert parse_hours("Fri-Mon 0-24")[0] == {4, 5, 6, 0}
    assert in_hours(datetime.fromtimestamp(MON_10, timezone.utc), parse_hours("Mon-Fri 08:00-18:00"))
    assert not in_hours(datetime.fromtimestamp(SAT_10, timezone.utc), parse_hours("Mon-Fri 08:00-18:00"))


def test_expected_tool_sightings_never_alert_at_any_hour():
    det = laptop_takeover()
    assert run(det, [tv_lookup(MON_10), tv_lookup(MON_21), dns(MON_21, "sn.splashtop.com", src=LAPTOP),
                     tv_traffic(MON_21, 20_000)]) == []                      # idle keepalive after hours
    assert [c.host for c in run(det, [ssl(MON_10, "net.teamviewer.com", src=OTHER)])] == [OTHER]


def test_expected_tool_session_alerts_only_outside_hours_once_per_day():
    det = laptop_takeover()
    run(det, [tv_lookup(MON_10 - 60)])
    assert run(det, [tv_traffic(MON_10 + i * 30, 1_000_000) for i in range(5)]) == []   # 5 MB in hours
    run(det, [tv_lookup(MON_21 - 60)])
    cases = run(det, [tv_traffic(MON_21 + i * 30, 1_000_000) for i in range(5)])
    assert len(cases) == 1
    c = cases[0]
    assert c.facts["session"] and c.facts["mb"] >= 2 and c.base_severity == 4 and not c.must_alert
    assert c.indicators == ["teamviewer.com"]
    assert run(det, [tv_traffic(MON_21 + 900 + i * 30, 1_000_000) for i in range(5)]) == []  # same night
    assert len(run(det, [tv_traffic(SAT_10 + i * 30, 1_000_000, dst="198.51.100.1", port=5938)
                         for i in range(3)])) == 1                    # weekend, direct TeamViewer port


def test_expected_entry_stops_applying_when_the_address_changes_hands():
    det = laptop_takeover(mac="aa:bb:cc:dd:ee:ff")
    assert run(det, [tv_lookup(MON_10)]) == []                 # no lease seen yet: entry applies
    lease = dict(dhcp(MON_10 + 1, mac="11:22:33:44:55:66"), assigned_addr=LAPTOP)
    assert run(det, [lease]) == []
    cases = run(det, [tv_lookup(MON_10 + 2), tv_traffic(MON_10 + 3, 500)])   # lookup, then contact: a sighting
    assert [c.facts["channel"] for c in cases] == ["remote_control"]


def test_callback_and_file_drop_services_cannot_be_marked_expected():
    det = TakeoverChannel(expected=[{"host": LAPTOP, "services": ["webhook.site", "teamviewer.com"]}])
    assert (LAPTOP, "webhook.site") not in det.expected and (LAPTOP, "teamviewer.com") in det.expected
    cases = run(det, [dns(MON_10, "x.webhook.site", src=LAPTOP)])
    assert len(cases) == 1 and cases[0].must_alert


def test_beaconing_names_the_destination_from_dns_when_there_is_no_sni():
    lookup = dict(dns(T0 - 5, "client.wns.windows.com"), answers=["wns.example-cname.net", "203.0.113.5"])
    cases = run(Beaconing(), [lookup] + [conn(T0 + i * 60, service="quic") for i in range(15)])
    assert len(cases) == 1 and cases[0].indicators == ["client.wns.windows.com"]


def test_sni_wins_over_dns_name():
    recs = [dict(dns(T0 - 5, "cdn.example.net"), answers=["203.0.113.5"]), ssl(T0 - 1, "api.example.com")]
    cases = run(Beaconing(), recs + [conn(T0 + i * 60) for i in range(15)])
    assert cases[0].indicators == ["api.example.com"]


# ------------------------------------------------------------- R05 new device by MAC

def mac_conn(ts, src="192.168.50.30", mac="00:00:5e:00:53:01", dst="203.0.113.5"):
    r = conn(ts, src=src, dst=dst)
    r["orig_l2_addr"] = mac
    return r


def test_new_device_keys_on_mac_through_ip_changes():
    det = NewDevice(Warmup(0), oui={"00005E": "Example Networks Inc."})
    cases = run(det, [mac_conn(T0), mac_conn(T0 + 5, src="192.168.50.31"),         # same device, new IP
                      mac_conn(T0 + 6, src="fe80::1234")])                          # and its IPv6 address
    assert len(cases) == 1
    f = cases[0].facts
    assert f["vendor"] == "Example Networks Inc." and not f["randomized_mac"] and f["dedupe"] == "00:00:5e:00:53:01"


def test_randomized_mac_with_a_known_hostname_is_the_same_device():
    det = NewDevice(Warmup(600))
    run(det, [dict(dhcp(T0, mac="aa:bb:cc:00:00:01"), host_name="Pixel-9"), mac_conn(T0 + 1, mac="aa:bb:cc:00:00:01")])
    later = [dict(dhcp(T0 + 700, mac="da:11:22:33:44:55"), host_name="Pixel-9"),        # same phone, private MAC
             mac_conn(T0 + 701, src="192.168.50.40", mac="da:11:22:33:44:55")]
    assert run(det, later) == []
    stranger = [dict(dhcp(T0 + 800, mac="da:99:88:77:66:55"), host_name="unknown-box"),
                mac_conn(T0 + 801, src="192.168.50.41", mac="da:99:88:77:66:55")]
    cases = run(det, stranger)
    assert cases[0].facts["randomized_mac"] and cases[0].facts["vendor"] == ""
    assert cases[0].indicators == ["unknown-box"]


def test_broadcast_and_multicast_macs_are_not_devices():
    det = NewDevice(Warmup(0))
    assert run(det, [mac_conn(T0, src="0.0.0.0", mac="ff:ff:ff:ff:ff:ff"),
                     mac_conn(T0, src="fe80::9", mac="33:33:00:00:00:fb")]) == []


def test_new_device_at_night_is_more_severe():
    det = NewDevice(Warmup(0), timezone="UTC")
    three_am = T0 - T0 % 86400 + 3 * 3600
    c = run(det, [mac_conn(three_am)])[0]
    assert c.facts["night"] and c.base_severity == 3
    assert not run(NewDevice(Warmup(0), timezone="UTC"), [mac_conn(three_am + 9 * 3600)])[0].facts["night"]

def test_load_oui_reads_the_ieee_csv(tmp_path):
    from tapwatch.detectors import load_oui
    p = tmp_path / "oui.csv"
    p.write_text('Registry,Assignment,Organization Name,Organization Address\n'
                 'MA-L,00005E,"Example Networks, Inc.",1 Example Way\n')
    assert load_oui(str(p)) == {"00005E": "Example Networks, Inc."} and load_oui(None) == {}


# --------------------------------------------- R06 odd port, R07 DNS bypass, R15 tunnelling

def udp(ts, port, dst="203.0.113.5", src="192.168.50.10"):
    r = conn(ts, src=src, dst=dst, port=port)
    r["proto"] = "udp"
    return r


def test_odd_port_learns_the_house_then_flags_new_ports_once():
    from tapwatch.detectors import OddPort
    det = OddPort(learn_days=1)
    day = 86400
    assert run(det, [conn(T0, port=443), conn(T0 + 10, port=5223)]) == []        # learning
    cases = run(det, [conn(T0 + day + 1, port=443), conn(T0 + day + 2, port=4444),
                      conn(T0 + day + 3, port=4444), conn(T0 + day + 4, port=4444, state="S0")])
    assert [(c.facts["port"], c.facts["new_for_house"]) for c in cases] == [(4444, True)]


def test_odd_port_ignores_high_udp_and_flags_learned_ports_only_when_unusually_long():
    from tapwatch.detectors import OddPort
    det = OddPort(learn_days=1, long_hours=4)
    day = 86400
    run(det, [conn(T0, port=443), dict(conn(T0 + 1, port=5223), duration=6 * 3600)])   # push channel: long is normal
    later = [udp(T0 + day + 1, 27015), dict(conn(T0 + day + 2, port=5223), duration=8 * 3600),
             dict(conn(T0 + day + 3, port=443), duration=5 * 3600),                   # HTTPS streams: normal
             dict(conn(T0 + day + 4, port=993), duration=5 * 3600)]
    cases = run(det, later)
    assert [(c.facts["port"], c.facts["new_for_house"]) for c in cases] == [(993, True)]


def test_odd_port_new_port_to_a_service_the_device_already_uses_is_fine():
    from tapwatch.detectors import OddPort
    det = OddPort(learn_days=1)
    cam = "192.168.50.44"
    name = lambda ts, ip: dict(dns(ts, "media.camera-vendor.example", src=cam), answers=[ip])
    run(det, [name(T0, "203.0.113.70"), conn(T0 + 1, src=cam, dst="203.0.113.70", port=32311)])
    later = [name(T0 + 86401, "203.0.113.71"), conn(T0 + 86402, src=cam, dst="203.0.113.71", port=32403),
             conn(T0 + 86403, src=cam, dst="198.51.100.9", port=6667)]               # unnamed, new: flagged
    assert [c.facts["port"] for c in run(det, later)] == [6667]


def test_odd_port_skips_named_dev_services_on_a_dev_host():
    from tapwatch.detectors import OddPort
    det = OddPort(learn_days=0, dev=DevProfile(["192.168.50.10"]))
    lookup = dict(dns(T0, "ssh.github.com"), answers=["203.0.113.5"])
    assert run(det, [lookup, conn(T0 + 1, port=22)]) == []
    assert len(run(det, [conn(T0 + 2, port=22, src="192.168.50.11")])) == 1


def test_dns_bypass_learns_hardcoded_resolvers_and_flags_new_ones():
    from tapwatch.detectors import DnsBypass
    det = DnsBypass(Warmup(600))
    camera, pc = "192.168.50.44", "192.168.50.10"
    assert run(det, [udp(T0, 53, dst="8.8.8.8", src=camera)]) == []                    # learned in warmup
    later = [udp(T0 + 700, 53, dst="8.8.4.4", src=camera),                             # same habit
             conn(T0 + 701, src=pc, dst="1.1.1.1", port=853),
             ssl(T0 + 702, "dns.google", src=pc), ssl(T0 + 703, "mask.icloud.com", src=pc),
             udp(T0 + 704, 53, dst="9.9.9.9", src=pc)]
    got = [(c.facts["how"], c.base_severity) for c in run(det, later)]
    assert got == [("DNS over TLS", 3), ("DNS over HTTPS", 3), ("plain DNS to an outside server", 2)]


def test_dns_retry_loop_on_one_dead_name_is_not_dga():
    det = SuspiciousDNS()
    assert run(det, [dns(T0 + i, "sn.remote-agent.example", rcode="NXDOMAIN") for i in range(60)]) == []


def test_dns_tunnelling_long_labels_to_one_unpopular_zone():
    rng = random.Random(7)
    det = SuspiciousDNS(popular={"example.com"})
    chunk = lambda: "".join(rng.choice("abcdef0123456789") for _ in range(48))
    cases = run(det, [dict(dns(T0 + i, f"{chunk()}.t.exfil-zone.net"), qtype_name="TXT") for i in range(210)])
    tunnel = [c for c in cases if c.facts.get("tunnel")]
    assert len(tunnel) == 1 and tunnel[0].indicators == ["exfil-zone.net"] and tunnel[0].base_severity == 4
    normal = SuspiciousDNS(popular={"example.com"})
    assert not [c for c in run(normal, [dns(T0 + i, f"img{i}.cdn.example.com") for i in range(300)])
                if c.facts.get("tunnel")]


# ------------------------------------------- R09 upload drift, upload stopped, R12 off-hours

def test_silent_hours_close_on_the_log_clock_and_a_stopped_uploader_is_noticed():
    cam, other = "192.168.50.44", "192.168.50.10"
    det = HourlyProfile(steady_mb=50, stop_hours=2)
    recs = [conn(T0 + h * 3600 + 10, src=cam, orig_bytes=300_000_000) for h in range(20)]     # 300 MB/h
    recs += [conn(T0 + h * 3600 + 20, src=other) for h in range(20, 24)]   # camera silent; only others talk
    stopped = [c for c in run(det, recs) if c.detector == "upload_stopped"]
    assert len(stopped) == 1 and stopped[0].host == cam and stopped[0].facts["normal_mb"] == 300
    assert stopped[0].base_severity == 2


def test_off_hours_needs_a_quiet_history_at_that_hour():
    det = HourlyProfile(busy_min=200, timezone="UTC")
    pc, day = "192.168.50.10", 86400
    quiet_hour = T0 - T0 % day + 3 * 3600                   # 03:00 UTC on each day
    recs = []
    for d in range(8):                                      # 8 quiet nights: 1 connection at 03:xx
        recs += [conn(quiet_hour + d * day + 60, src=pc), conn(quiet_hour + d * day + 3600 + 60, src=pc)]
    recs += [conn(quiet_hour + 8 * day + i, src=pc) for i in range(300)]   # 300 connections at 03:xx
    recs += [conn(quiet_hour + 8 * day + 3600 + 5, src=pc)]                # 04:00 closes the hour
    off = [c for c in run(det, recs) if c.detector == "off_hours"]
    assert len(off) == 1 and off[0].facts["conns"] == 300 and off[0].facts["normal"] <= 1


def test_devices_gone_a_week_are_dropped():
    det = HourlyProfile()
    run(det, [conn(T0 + 10, src="192.168.50.99")])
    run(det, [conn(T0 + h * 3600 + 5) for h in range(1, 7 * 24 + 3)])
    assert "192.168.50.99" not in det.history and "192.168.50.10" in det.history


# ------------------------------------------------------- R02 IoT drift, R10 TLS oddities

FAKE_ASN = {"203.0.113.5": (64500, "US"), "203.0.113.6": (64500, "US"), "198.51.100.7": (64511, "RU"),
            "198.51.100.8": (64512, "NL"), "198.51.100.9": (64513, "NL"), "198.51.100.10": (64514, "NL")}


class FakeAsn:
    def lookup(self, ip):
        return FAKE_ASN.get(ip)


def test_fixed_function_roles_match_whole_words():
    from tapwatch.detectors import fixed_function_hosts
    t = {"192.168.50.44": {"role": "camera"}, "192.168.50.10": {"role": "workstation"},
         "192.168.50.12": {"role": "github runner"}, "192.168.50.13": {"role": "TV streamer"}}
    assert set(fixed_function_hosts(t)) == {"192.168.50.44", "192.168.50.13"}


def test_iot_drift_learns_then_flags_country_port_and_network_bursts():
    from tapwatch.detectors import IotDrift
    cam, day = "192.168.50.44", 86400
    det = IotDrift({cam: "camera"}, FakeAsn(), learn_days=1)
    assert run(det, [conn(T0, src=cam, dst="203.0.113.5"), conn(T0 + 9, src="192.168.50.10", dst="198.51.100.7")]) == []
    later = [conn(T0 + day + 1, src=cam, dst="203.0.113.6"),                        # same network: fine
             conn(T0 + day + 2, src=cam, dst="198.51.100.7", port=6881),             # new country + new port
             conn(T0 + day + 3, src=cam, dst="198.51.100.8"), conn(T0 + day + 4, src=cam, dst="198.51.100.9"),
             conn(T0 + day + 5, src=cam, dst="198.51.100.10")]                       # 4 new networks in an hour
    got = [(c.facts["what"], c.facts["value"]) for c in run(det, later)]
    assert ("country", "RU") in got and ("port", "tcp/6881") in got and ("country", "NL") in got
    assert any(w == "networks" for w, _ in got)


def test_iot_drift_skips_known_vendor_services_and_does_nothing_without_the_table():
    from tapwatch.detectors import IotDrift
    cam = "192.168.50.44"
    det = IotDrift({cam: "camera"}, FakeAsn(), learn_days=0)
    ntp = dict(udp(T0, 123, dst="198.51.100.7", src=cam))
    assert run(det, [ntp]) == []                                       # NTP pools: never a "new country"
    lookup = lambda ts, ip: dict(dns(ts, "media.camera-vendor.example", src=cam), answers=[ip])
    run(det, [lookup(T0, "203.0.113.5"), conn(T0 + 1, src=cam, dst="203.0.113.5")])
    assert run(det, [lookup(T0 + 2, "198.51.100.7"), conn(T0 + 3, src=cam, dst="198.51.100.7")]) == []
    assert run(IotDrift({cam: "camera"}, None), [conn(T0, src=cam)]) == []


def test_tls_oddities_need_three_signs():
    from tapwatch.detectors import TlsOddities
    det = TlsOddities(Warmup(0))
    named = dict(dns(T0, "api.example.com"), answers=["203.0.113.5"])
    ok = dict(ssl(T0 + 1, "api.example.com"), established=True, **{"id.resp_p": 8443})       # 1 sign
    odd = {"_type": "ssl", "ts": T0 + 2, "id.orig_h": "192.168.50.10", "id.resp_h": "198.51.100.7",
           "id.resp_p": 4443, "established": True}                                         # 3 signs
    worse = dict(odd, **{"id.resp_h": "198.51.100.8", "validation_status": "self signed certificate"})
    cases = run(det, [named, ok, odd, dict(odd, ts=T0 + 3), worse, dict(worse, **{"id.resp_p": 5443})])
    assert [(c.facts["score"], c.base_severity) for c in cases] == [(3, 2), (4, 3)]   # once per (device, port)


def test_tls_oddities_skip_dtls_media_with_a_client_certificate():
    # #417 (2026-10-17): the baby monitor streaming to a phone on cellular; DTLS-SRTP, both ends self-signed, the
    # peer found by ICE, a new port each call, so the (device, port) memory never covered the next one
    from tapwatch.detectors import TlsOddities
    det = TlsOddities(Warmup(0))
    call = {"_type": "ssl", "ts": T0, "id.orig_h": "192.168.50.44", "id.resp_h": "198.51.100.7", "id.resp_p": 1094,
            "version": "DTLSv12", "established": True, "validation_status": "self signed certificate",
            "cert_chain_fps": ["927f"], "client_cert_chain_fps": ["5ce9"]}
    assert run(det, [call, dict(call, ts=T0 + 60, **{"id.resp_p": 1611})]) == []
    old_zeek = {k: v for k, v in call.items() if k != "client_cert_chain_fps"}
    assert run(det, [dict(old_zeek, ts=T0 + 90, client_cert_chain_fuids=["F1"], **{"id.resp_p": 1620})]) == []
    # server-only DTLS, a TLS session with a client certificate, and a row with no version are still the stack
    assert len(run(det, [dict(call, ts=T0 + 120, **{"id.resp_p": 1630, "client_cert_chain_fps": []})])) == 1
    assert len(run(det, [dict(call, ts=T0 + 180, **{"id.resp_p": 1640, "version": "TLSv12"})])) == 1
    assert len(run(det, [dict(call, ts=T0 + 240, **{"id.resp_p": 1650, "version": None})])) == 1


def test_tls_oddities_learned_in_warmup_stay_quiet():
    from tapwatch.detectors import TlsOddities
    cam = "192.168.50.44"
    det = TlsOddities(Warmup(600))
    vendor = {"_type": "ssl", "ts": T0, "id.orig_h": cam, "id.resp_h": "198.51.100.7", "id.resp_p": 32403,
              "established": True, "validation_status": "self signed certificate"}
    assert run(det, [vendor]) == []                                                     # warmup
    assert run(det, [dict(vendor, ts=T0 + 900, **{"id.resp_h": "198.51.100.9"})]) == []  # new server, same habit
    assert len(run(det, [dict(vendor, ts=T0 + 901, **{"id.resp_p": 4444})])) == 1


def test_a_long_udp_stream_split_by_zeek_is_not_beaconing():
    """Case #63: a voice call. Zeek logged the UDP flow as back-to-back ~60 s records."""
    recs = []
    for i in range(15):
        r = dict(conn(T0 + i * 60.07, dst="203.0.113.77", port=50003), duration=60.07, orig_bytes=500_000)
        r["proto"] = "udp"
        recs.append(r)
    assert run(Beaconing(), recs) == []
    short = [dict(conn(T0 + i * 60, dst="203.0.113.78", port=8443), duration=0.4) for i in range(15)]
    assert len(run(Beaconing(), short)) == 1                     # a real heartbeat still fires


def test_tcp_sessions_held_for_the_interval_are_still_beacons():
    """FluBot capture: 300 s TCP sessions, reopened every 300 s."""
    recs = [dict(conn(T0 + i * 300, dst="203.0.113.90"), duration=300.1) for i in range(12)]
    assert len(run(Beaconing(), recs)) == 1


def test_retry_bursts_collapse_into_one_beat():
    """HtBot capture: a few rejected attempts seconds apart, then ~27 minutes of quiet."""
    recs = []
    for i in range(12):
        recs += [conn(T0 + i * 1617 + k * 3, dst="203.0.113.91", port=80, state="REJ") for k in range(3)]
    cases = run(Beaconing(), recs)
    assert len(cases) == 1 and cases[0].facts["interval_s"] == 1617


# --------------------------------------------- household prevalence, sync services (home eval fixes)

def test_beacon_to_a_service_other_devices_use_is_capped():
    others = [ssl(T0 - 5, "api.popular.example", src="192.168.50.11"), ssl(T0 - 4, "x.niche.example", src="192.168.50.12")]
    b = Beaconing(popular={"popular.example"})
    run(b, others + [ssl(T0 - 3, "api.popular.example"), ssl(T0 - 2, "x.niche.example", dst="203.0.113.6")])
    pop = run(b, [conn(T0 + i * 300) for i in range(12)])[0]
    niche = run(b, [conn(T0 + i * 300, dst="203.0.113.6", port=8443) for i in range(12)])[0]
    assert (pop.facts["shared_by"], pop.facts["max_route"]) == (1, "log")
    assert niche.facts["shared_by"] == 1 and "max_route" not in niche.facts   # obscure + shared: could be a botnet
    lone = run(Beaconing(), [conn(T0 + i * 300, dst="203.0.113.7") for i in range(12)])[0]
    assert "max_route" not in lone.facts
    # popular but used by this device only: digest, never log (Discord, Telegram, GitHub are C2 channels too)
    solo = Beaconing(popular={"popular.example"})
    run(solo, [ssl(T0 - 1, "gateway.popular.example", dst="203.0.113.8")])
    only = run(solo, [conn(T0 + i * 300, dst="203.0.113.8") for i in range(12)])[0]
    assert (only.facts["popular"], only.facts["shared_by"], only.facts["max_route"]) == (True, 0, "digest")


def test_beacon_to_a_service_that_is_regular_by_design_is_capped_at_digest():
    # One computer, nothing shared: push notifications, EDR check-ins, NTP and STUN are the heartbeats
    # every such network has, and the class is a code fact for the summary.
    beats = [conn(T0 + i * 300) for i in range(12)]
    push = run(Beaconing(), [ssl(T0 - 1, "client.wns.windows.com")] + beats)[0]
    assert (push.facts["known_class"], push.facts["max_route"]) == ("push notification", "digest")
    edr = run(Beaconing(benign_classes={"endpoint security agent": ["edr.example"]}),
              [ssl(T0 - 1, "zone-01.edr.example")] + beats)[0]
    assert push.facts["shared_by"] == 0 and edr.facts["known_class"] == "endpoint security agent"
    assert "known_class" not in run(Beaconing(), [ssl(T0 - 1, "c2.example")] + beats)[0].facts
    # popular and shared stays log (the stricter cap), even for a classed service
    b = Beaconing(popular={"windows.com"})
    run(b, [ssl(T0 - 2, "client.wns.windows.com", src="192.168.50.11"), ssl(T0 - 1, "client.wns.windows.com")])
    assert run(b, beats)[0].facts["max_route"] == "log"


def test_beacon_to_an_expected_tool_is_skipped():
    b = Beaconing(expected={"192.168.50.10": {"teamviewer.com"}})
    recs = [ssl(T0 - 1, "hapi.teamviewer.com")] + [conn(T0 + i * 3600) for i in range(12)]
    assert run(b, recs) == []


def test_new_domain_random_only_off_popular_and_no_bare_hostnames():
    nd = NewExternalDomain(Warmup(0), popular={"googlevideo.com"})
    run(nd, [dns(T0, "rr4---sn-bvvbaxivnuxqjvhj5nu-vgqe.googlevideo.com"), dns(T0 + 1, "jsl-dtc-010"),
             dns(T0 + 2, "q8z3kx0vw7p2mr.example.net")])
    c = nd.flush()[0]
    assert c.facts["count"] == 2 and c.facts["random"] == 1 and c.indicators[0] == "q8z3kx0vw7p2mr.example.net"


def test_upload_spike_to_a_sync_service_is_capped_at_digest():
    det = HourlyProfile()
    lookup = dict(dns(T0, "onedriveclubprodbn1.blob.core.windows.net"), answers=["203.0.113.40"])
    recs = [lookup] + [conn(T0 + h * 3600, orig_bytes=5_000_000) for h in range(8)]
    recs += [conn(T0 + 8 * 3600 + 60, dst="203.0.113.40", orig_bytes=800_000_000), conn(T0 + 9 * 3600)]
    c = next(x for x in run(det, recs) if x.detector == "upload_spike")
    assert c.facts["to_sync_service"] and c.facts["max_route"] == "digest" and c.facts["top_share_pct"] >= 90


def test_one_device_with_several_addresses_is_not_shared():
    """HtBot capture: the infected machine's own IPv6 addresses made its C2 look 'shared'."""
    mac = "08:00:27:63:6f:08"
    b = Beaconing()
    run(b, [dict(conn(T0 - 9, src="fd77::1"), orig_l2_addr=mac), dict(conn(T0 - 8), orig_l2_addr=mac),
            dict(dns(T0 - 7, "c2.bad.example", src="fd77::1"), answers=["203.0.113.9"]),
            dict(dns(T0 - 6, "c2.bad.example"), answers=["203.0.113.9"])])
    c = run(b, [dict(conn(T0 + i * 600, dst="203.0.113.9", port=80), orig_l2_addr=mac) for i in range(12)])[0]
    assert c.facts["shared_by"] == 0


def test_upload_spike_to_an_endpoint_security_cloud_is_capped_at_digest():
    det = HourlyProfile()
    lookup = dict(dns(T0, "ts01-b.cloudsink.net"), answers=["203.0.113.41"])
    recs = [lookup] + [conn(T0 + h * 3600, orig_bytes=5_000_000) for h in range(8)]
    recs += [conn(T0 + 8 * 3600 + 60, dst="203.0.113.41", orig_bytes=700_000_000), conn(T0 + 9 * 3600)]
    c = next(x for x in run(det, recs) if x.detector == "upload_spike")
    assert c.facts["to_security_vendor"] and c.facts["max_route"] == "digest"


def test_a_symmetric_hour_is_a_video_call_not_an_upload():
    def hour(down):
        det = HourlyProfile()
        recs = [conn(T0 + h * 3600, orig_bytes=5_000_000) for h in range(8)]
        big = dict(conn(T0 + 8 * 3600 + 60, dst="203.0.113.42", orig_bytes=600_000_000), resp_bytes=down)
        return next(x for x in run(det, recs + [big, conn(T0 + 9 * 3600)]) if x.detector == "upload_spike")
    call, exfil = hour(580_000_000), hour(20_000_000)
    assert call.facts["symmetric"] and call.facts["down_mb"] == 580 and call.facts["max_route"] == "digest"
    assert not exfil.facts["symmetric"] and "max_route" not in exfil.facts


def test_base_domain_keeps_the_registrable_part_under_two_label_public_suffixes():
    assert base_domain("www.bbc.co.uk") == "bbc.co.uk" and base_domain("co.uk") == "co.uk"
    assert base_domain("a.b.example.com") == "example.com" and base_domain("localhost") == "localhost"


def test_tls_odd_and_odd_port_report_again_after_reported_days_but_keep_warmup_learning():
    from tapwatch.detectors import PERMANENT, OddPort, TlsOddities

    def bare(ts, port=8443):  # no name, no DNS answer, odd port, self-signed: score 4
        return {"_type": "ssl", "ts": ts, "id.orig_h": "192.168.50.10", "id.resp_h": "203.0.113.9", "id.resp_p": port,
                "established": True, "validation_status": "self signed certificate"}
    det = TlsOddities(Warmup(600), reported_days=7)
    assert run(det, [bare(T0)]) == []                                        # warmup: learned for good
    assert det.reported == {("192.168.50.10", 8443): PERMANENT}
    assert run(det, [bare(T0 + 30 * 86400)]) == []                           # still learned a month later
    assert len(run(det, [bare(T0 + 700, 9443)])) == 1                        # after warmup: reported
    assert run(det, [bare(T0 + 700 + 86400, 9443)]) == []                    # a day later: silent
    assert len(run(det, [bare(T0 + 700 + 8 * 86400, 9443)])) == 1            # 8 days later: reported again
    old = TlsOddities(Warmup(600))
    old.restore({"reported": {"$set": [{"$tuple": ["192.168.50.10", 1]}]}})  # the old set shape: kept, permanent
    assert old.reported == {("192.168.50.10", 1): PERMANENT}
    day = 86400
    op = OddPort(learn_days=1, reported_days=7)
    run(op, [conn(T0, port=443)])
    assert len(run(op, [conn(T0 + day + 1, port=4444)])) == 1
    assert run(op, [conn(T0 + 2 * day, port=4444)]) == []
    assert len(run(op, [conn(T0 + 9 * day, port=4444)])) == 1
    snap = op.snapshot()
    fresh = OddPort(learn_days=1)
    fresh.restore(snap)
    assert fresh.reported == op.reported


def test_identity_learns_mac_from_conn_and_hostname_from_dhcp():
    from tapwatch.detectors import Identity
    ident = Identity()
    mac = "aa:bb:cc:dd:ee:01"
    assert ident.facts_for("192.168.50.10") == {}
    run(ident, [dict(conn(T0), orig_l2_addr=mac.upper())])
    assert ident.facts_for("192.168.50.10") == {"device_mac": mac}                      # MAC, no name yet
    run(ident, [dict(dhcp(T0 + 1, mac=mac), host_name="ACCT-LAPTOP", assigned_addr="192.168.50.10")])
    assert ident.facts_for("192.168.50.10") == {"device_mac": mac, "device_name": "ACCT-LAPTOP"}
    run(ident, [dict(dhcp(T0 + 2, mac=mac), host_name="ACCT-LAPTOP", assigned_addr="192.168.50.77")])
    assert ident.hostname_for("192.168.50.77") == "ACCT-LAPTOP"                        # follows the lease
    run(ident, [dict(conn(T0 + 2.5, src="fe80::1:2:3:4"), orig_l2_addr=mac)])
    assert ident.ip_for("name:acct-laptop") == "192.168.50.77"                          # link-local never wins
    run(ident, [dict(conn(T0 + 3, src="192.168.50.10"), orig_l2_addr="ff:ff:ff:ff:ff:ff")])
    assert ident.mac_for("192.168.50.10") == mac                                          # broadcast MAC ignored
    again = Identity()
    again.restore(ident.snapshot())
    assert again.facts_for("192.168.50.77") == ident.facts_for("192.168.50.77")


def test_baselines_follow_the_device_across_a_dock_swap_and_old_entries_move_under_its_identity():
    from tapwatch.detectors import HourlyProfile, Identity, ManagementAccess
    ident = Identity()
    laptop, desktop = "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"
    nd = NewExternalDomain(Warmup(0))
    nd.ident = ident
    # the laptop on Wi-Fi (.102) learns a domain before its identity is known: keyed on the IP for now
    feed_all([ident, nd], [dns(T0, "cdn.example", src="192.168.50.102")])
    nd.flush()
    assert "cdn.example" in nd.known["192.168.50.102"]
    lease = lambda ts, mac, ip, name: dict(dhcp(ts, mac=mac), host_name=name, assigned_addr=ip)
    feed_all([ident, nd], [lease(T0 + 1, laptop, "192.168.50.102", "ACCT-LAPTOP"),
                           dict(conn(T0 + 2, src="192.168.50.102"), orig_l2_addr=laptop)])
    # the laptop docks and takes .215: the domain it knows is not new, because the baseline moved with it
    feed_all([ident, nd], [lease(T0 + 10, laptop, "192.168.50.215", "ACCT-LAPTOP"),
                           dict(conn(T0 + 11, src="192.168.50.215"), orig_l2_addr=laptop),
                           dns(T0 + 12, "cdn.example", src="192.168.50.215")])
    assert nd.flush() == [] and "192.168.50.102" not in nd.known and "cdn.example" in nd.known["name:acct-laptop"]
    # the desktop takes .102 next: it does not inherit the laptop's baseline
    feed_all([ident, nd], [dict(conn(T0 + 20, src="192.168.50.102"), orig_l2_addr=desktop),
                           dns(T0 + 21, "cdn.example", src="192.168.50.102")])
    assert [c.host for c in nd.flush()] == ["192.168.50.102"]
    # an admin-port pair learned on one address stays learned on the next
    ma = ManagementAccess(Warmup(600), gateways=Gateways({GW}))
    ma.ident = ident
    assert run(ma, [conn(T0 + 30, src="192.168.50.215", dst=GW, port=443)]) == []        # warmup: learned
    feed_all([ident], [lease(T0 + 40, laptop, "192.168.50.150", "ACCT-LAPTOP"),
                       dict(conn(T0 + 41, src="192.168.50.150"), orig_l2_addr=laptop)])
    assert run(ma, [conn(T0 + 700, src="192.168.50.150", dst=GW, port=443)]) == []       # same laptop, new IP
    assert len(run(ma, [conn(T0 + 701, src="192.168.50.102", dst=GW, port=443)])) == 1   # the desktop: new
    # hourly profiles are keyed on the device too, and the case names the address it is on now
    hp = HourlyProfile()
    hp.ident = ident
    recs = [conn(T0 + 3600 + h * 3600, src="192.168.50.150", orig_bytes=10_000_000) for h in range(8)]
    recs += [conn(T0 + 9 * 3600 + 60, src="192.168.50.150", orig_bytes=1_000_000_000), conn(T0 + 10 * 3600, src="192.168.50.150")]
    spike = next(c for c in run(hp, recs) if c.detector == "upload_spike")
    assert spike.host == "192.168.50.150" and "name:acct-laptop" in hp.history and "192.168.50.150" not in hp.history


def test_remote_control_lookup_alone_is_not_a_takeover_but_a_connection_to_its_answer_is():
    from tapwatch.detectors import TakeoverChannel
    det = TakeoverChannel()
    look = dict(dns(T0, "net.anydesk.com"), answers=["203.0.113.50", "203.0.113.51"])
    assert run(det, [look]) == []                                                          # visited the website?
    assert run(det, [conn(T0 + 30, dst="198.51.100.9")]) == []                             # unrelated connection
    assert run(det, [conn(T0 + 120, dst="203.0.113.50")]) == []                            # too late to count
    cases = run(det, [look, conn(T0 + 5, dst="203.0.113.51", port=443)])
    assert [(c.facts["channel"], c.facts["via"], c.base_severity) for c in cases] == \
        [("remote_control", "DNS, then a connection to the answer", 4)]
    assert run(det, [ssl(T0 + 400, "net.anydesk.com")]) == []                              # already reported
    assert [c.facts["channel"] for c in run(det, [dns(T0 + 500, "abc.webhook.site")])] == ["callback"]  # lookup is enough


def test_private_mac_without_a_hostname_rotating_on_the_lan_is_log_level():
    det = NewDevice(Warmup(0))
    rotate = dict(conn(T0, src="192.168.50.80", dst="192.168.50.1", port=53), orig_l2_addr="aa:bb:cc:dd:ee:55")
    named = dict(conn(T0 + 1, src="192.168.50.81", dst="192.168.50.1", port=53), orig_l2_addr="aa:bb:cc:dd:ee:66")
    outside = dict(conn(T0 + 2, src="192.168.50.82"), orig_l2_addr="aa:bb:cc:dd:ee:77")
    cases = run(det, [dict(dhcp(T0 - 1, mac="aa:bb:cc:dd:ee:66"), host_name="my-phone"), rotate, named, outside])
    assert [(c.facts["likely_rotation"], c.base_severity) for c in cases] == [(True, 1), (False, 2), (False, 2)]


def test_declared_port_forwards_are_known_exposures():
    from tapwatch.detectors import InternetExposure
    det = InternetExposure(Warmup(0), expected=[{"host": "192.168.50.10", "proto": "tcp", "port": 8000}])
    assert run(det, [inbound(T0), inbound(T0 + 200)]) == []                                 # declared: quiet
    assert [c.facts["port"] for c in run(det, [inbound(T0 + 201, port=8001)])] == [8001]   # anything else alerts


def test_beaconing_timing_windows_and_dns_zones_are_bounded():
    from tapwatch.detectors import SuspiciousDNS
    b = Beaconing()
    run(b, [conn(T0 + i, dst=f"203.0.{i // 250}.{i % 250 + 1}", port=1000 + i % 60) for i in range(20_050)])
    run(b, [conn(T0 + 2 * 86400, dst="203.0.113.250")])      # a day later: the quiet pairs are dropped
    assert len(b.seen) < 100 and len(b.durations) == len(b.seen)
    d = SuspiciousDNS(window=600)
    for i in range(20_050):
        d._tunnel("192.168.50.10", T0 + i * 0.01, f"x.z{i}.example", f"z{i}.example", "A")
    d._tunnel("192.168.50.10", T0 + 5000, "x.last.example", "last.example", "A")
    assert len(d.zones) < 100


def test_admin_port_sweep_is_one_alert_not_eighty_digest_items():
    det = ManagementAccess(Warmup(0), gateways=Gateways({GW}))
    probes = [conn(T0 + i, src="192.168.50.66", dst=f"192.168.50.{100 + i}", port=445, state="S0") for i in range(80)]
    cases = run(det, probes)
    assert [c.base_severity for c in cases] == [2, 2, 2, 2, 5]                   # 4 probes, then the sweep
    assert cases[-1].facts["sweep"] and cases[-1].facts["targets"] == 5 and cases[-1].facts["dedupe"] == "sweep:445"
    again = run(det, [conn(T0 + 3700 + i, src="192.168.50.66", dst=f"192.168.50.{200 + i}", port=445, state="S0")
                      for i in range(5)])
    assert [c.base_severity for c in again] == [2, 2, 2, 2, 5]                   # an hour later: reported again
    # five pairs spread over a day are ordinary admin use, not a sweep
    slow = ManagementAccess(Warmup(0), gateways=Gateways({GW}))
    spread = [conn(T0 + i * 3600, src="192.168.50.20", dst=f"192.168.50.{100 + i}", port=3389) for i in range(6)]
    assert all(not c.facts.get("sweep") for c in run(slow, spread))


def test_upload_to_a_sync_companys_own_network_is_capped_when_no_name_was_seen():
    class Table:
        def lookup(self, ip):
            return (714, "US") if ip.startswith("17.") else (16509, "US") if ip.startswith("54.") else None

    def spike(dst):
        det = HourlyProfile(asn=Table())
        recs = [conn(T0 + h * 3600, orig_bytes=5_000_000) for h in range(8)]
        recs += [conn(T0 + 8 * 3600 + 60, dst=dst, orig_bytes=2_000_000_000), conn(T0 + 9 * 3600)]
        return next(x for x in run(det, recs) if x.detector == "upload_spike")
    apple, aws = spike("17.250.103.75"), spike("54.67.92.206")
    assert apple.facts["to_sync_network"] == "Apple" and apple.facts["max_route"] == "digest"
    assert apple.indicators == ["17.250.103.75"]                         # the address stands in for the name
    assert aws.facts["to_sync_network"] == "" and "max_route" not in aws.facts


def test_a_device_whose_every_connection_fails_is_offline_not_scanning():
    offline = run(PortScan(), [conn(T0 + i * 0.5, dst=f"203.0.113.{i + 1}", port=443, state="S0") for i in range(60)])
    assert offline[0].facts["all_failed"] and offline[0].facts["max_route"] == "digest"
    det = PortScan()
    run(det, [conn(T0 + i, dst="203.0.113.250", port=443) for i in range(5)])       # its own traffic works
    scanning = run(det, [conn(T0 + 10 + i * 0.5, dst=f"192.168.50.{i + 2}", port=22, state="REJ") for i in range(60)])
    assert not scanning[0].facts["all_failed"] and "max_route" not in scanning[0].facts   # refused = answered: online
    det = PortScan()
    recs = [conn(T0 + i * 0.5, dst=f"192.168.50.{i + 2}", port=22, state="REJ") for i in range(60)]
    recs.insert(30, conn(T0 + 15.2, dst="203.0.113.250", port=443))                # an answered one mid-run
    live = run(det, recs)
    assert not live[0].facts["all_failed"] and "max_route" not in live[0].facts
    # a reset after the handshake (tarpits, banner-grab refusals) counts as a failed probe, but it proves the target is reachable
    rst = run(PortScan(), [conn(T0 + i * 0.5, dst=f"192.168.50.{i + 2}", port=443, state="RSTR") for i in range(60)])
    assert len(rst) == 1 and not rst[0].facts["all_failed"] and "max_route" not in rst[0].facts


def test_cleartext_to_a_rotating_cloud_broker_keeps_one_suppressable_key():
    det = CleartextAuth()
    mqtt = lambda ts, dst: dict(conn(ts, src="192.168.50.19", dst=dst, port=1883, service="mqtt"), proto="tcp")
    cases = run(det, [mqtt(T0, "203.0.113.5"), mqtt(T0 + 1, "203.0.113.6")])   # the broker moved
    assert [c.facts["dedupe"] for c in cases] == ["MQTT|outside", "MQTT|outside"]
    assert all(c.indicator == c.facts["dedupe"] for c in cases)   # what a device rule is keyed on
    http = {"_type": "http", "ts": T0 + 3, "id.orig_h": "192.168.50.19", "id.resp_h": "192.168.50.7",
            "username": "u", "host": "printer.lan"}
    assert run(det, [http])[0].facts["dedupe"] == "HTTP login (basic auth)|192.168.50.7"   # inside: the server matters


def test_admin_devices_may_name_a_device_by_hostname_or_mac():
    from tapwatch.detectors import Identity
    ident = Identity()
    det = ManagementAccess(Warmup(0), gateways=Gateways({GW}), admin_devices={"name:iPhone", "MAC:aa:bb:cc:dd:ee:21"})
    det.ident = ident
    feed_all([ident], [dict(dhcp(T0, mac="aa:bb:cc:dd:ee:20"), host_name="iPhone", assigned_addr="192.168.50.80"),
                       dict(conn(T0 + 1, src="192.168.50.81"), orig_l2_addr="aa:bb:cc:dd:ee:21")])
    app = [conn(T0 + 2, src="192.168.50.80", dst=GW, port=443), conn(T0 + 3, src="192.168.50.81", dst=GW, port=443),
           conn(T0 + 4, src="192.168.50.82", dst=GW, port=443)]
    assert [c.host for c in run(det, app)] == ["192.168.50.82"]          # the named phone and the MAC'd one pass


def test_a_few_failures_among_many_successes_is_not_a_scan_alert():
    det = PortScan()
    recs = [conn(T0 + i * 0.1, dst=f"203.0.113.{i % 200 + 1}", port=443) for i in range(336)]        # browsing works
    recs += [conn(T0 + 10 + i * 0.1, dst=f"198.51.100.{i + 1}", port=443, state="S0") for i in range(60)]  # a few don't
    recs.sort(key=lambda r: r["ts"])
    c = run(det, recs)[0]
    assert c.facts["failed_pct"] < 50 and c.facts["max_route"] == "digest" and not c.facts["all_failed"]
    pure = run(PortScan(), [conn(T0 + i * 0.1, dst=f"192.168.50.{i % 20 + 2}", port=1000 + i, state="REJ") for i in range(60)])[0]
    assert pure.facts["failed_pct"] == 100 and "max_route" not in pure.facts   # refusals are answers: online, scanning


def test_sessions_a_device_resets_after_data_are_not_a_scan():
    # #363: a phone leaving a news page reset 87 TLS sessions to ad/CDN hosts in a minute (data both ways)
    torn = [dict(conn(T0 + i * 0.1, dst=f"203.0.113.{i + 1}", port=443, state="RSTO", orig_bytes=2493), resp_bytes=8528)
            for i in range(60)]
    assert run(PortScan(), torn) == []
    # a SYN scan also closes with a reset, but sends and receives nothing; a banner grab only reads
    probes = [dict(conn(T0 + i * 0.1, dst=f"203.0.113.{i + 1}", port=22, state="RSTO", orig_bytes=0), resp_bytes=0)
              for i in range(30)]
    probes += [dict(conn(T0 + 3 + i * 0.1, dst=f"203.0.113.{i + 1}", port=25, state="RSTR", orig_bytes=0), resp_bytes=40)
               for i in range(30)]
    c = run(PortScan(), probes)[0]
    assert c.facts["targets"] == 50 and c.facts["failed_pct"] == 100   # fires at the threshold
    # the torn-down sessions count on the answered side of failed_pct
    mixed = sorted(torn[:50] + [conn(T0 + 2 + i * 0.1, dst=f"198.51.100.{i + 1}", port=443, state="S0") for i in range(50)],
                   key=lambda r: r["ts"])
    assert run(PortScan(), mixed)[0].facts["failed_pct"] == 50


def test_scan_right_after_a_router_wifi_event_is_capped():
    def wifi(ts, name, mac="aa:bb:cc:dd:ee:21", ip="192.168.50.10"):
        return {"_type": "udm", "ts": ts, "sender": "192.168.50.1", "kind": "cef", "name": name,
                "UNIFIclientMac": mac, "UNIFIclientIp": ip, "msg": f"client {mac[-5:]} {name.split()[-1].lower()}"}
    burst = [dict(conn(T0 + i * 0.1, dst=f"203.0.113.{i + 1}", port=443, state="REJ"), orig_l2_addr="AA:BB:CC:DD:EE:21")
             for i in range(60)]
    # #321: the phone roamed between access points 3 s before its "scan"; the roam was logged first
    c = run(PortScan(), [wifi(T0 - 3, "WiFi Client Roamed")] + burst)[0]
    assert (c.facts["wifi_event"], c.facts["max_route"]) == ("roamed", "digest") and c.facts["wifi_event_age_s"] == 8
    # the event already reported for a moment after the trigger also counts; a stale one does not
    assert run(PortScan(), [wifi(T0 + 7, "WiFi Client Disconnected")] + burst)[0].facts["wifi_event"] == "disconnected"
    assert "wifi_event" not in run(PortScan(), [wifi(T0 - 400, "WiFi Client Roamed")] + burst)[0].facts
    # another client's roam, or a non-client event, says nothing about this device
    assert "wifi_event" not in run(PortScan(), [wifi(T0, "WiFi Client Roamed", mac="aa:bb:cc:dd:ee:22", ip="192.168.50.11")] + burst)[0].facts
    assert "wifi_event" not in run(PortScan(), [wifi(T0, "Admin Login")] + burst)[0].facts
    # a join explains nothing: a device that joins and sweeps the LAN is the strongest scan shape
    assert "wifi_event" not in run(PortScan(), [wifi(T0 - 3, "WiFi Client Connected")] + burst)[0].facts
    # without the MAC on the connection, the client address matches; the event's address alone can't vouch for a MAC'd one
    bare = [conn(T0 + i * 0.1, dst=f"203.0.113.{i + 1}", port=443, state="REJ") for i in range(60)]
    assert run(PortScan(), [wifi(T0, "WiFi Client Disconnected")] + bare)[0].facts["wifi_event"] == "disconnected"
    assert "wifi_event" not in run(PortScan(), [wifi(T0, "WiFi Client Disconnected", mac="aa:bb:cc:dd:ee:22")] + burst)[0].facts
    bogus = [dict(r, orig_l2_addr="00:00:00:00:00:00") for r in bare]   # a MAC Zeek could not read is no MAC
    assert run(PortScan(), [wifi(T0, "WiFi Client Disconnected")] + bogus)[0].facts["wifi_event"] == "disconnected"
    from tapwatch.summarizer import Assets, summarize
    text = summarize(c, Assets())
    assert "roamed on Wi-Fi" in text and "before the burst" in text


def test_unifi_discovery_answers_to_the_controller_are_not_a_scan():
    """#768-#770: UniFi devices answer the controller's udp/10001 sweep from port 10001 to its random ports."""
    gw = "192.168.50.1"
    recs = []
    for i in range(80):
        r = conn(T0 + i * 0.5, src="192.168.50.44", dst=gw, port=40000 + i * 7, state="S0")
        r.update({"proto": "udp", "id.orig_p": 10001, "orig_bytes": 820})
        recs.append(r)
    assert run(PortScan(), recs) == []
    for r in recs:
        r["id.orig_p"] = 50000                                                     # the same sweep from any other port
    assert len(run(PortScan(), recs)) == 1
