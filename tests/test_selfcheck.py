"""The scripted detection-rate check (src/tapwatch/selfcheck.py) must stay at 100 % in CI, so a detector change
that silences an attack shape or wakes a known false-positive shape fails the build, not the next live test."""

from tapwatch import selfcheck
from tapwatch.cli import main


def test_every_scenario_passes_with_the_default_config():
    outcomes = selfcheck.run()
    failed = [o for o in outcomes if not o.passed]
    assert not failed, selfcheck.report(outcomes)
    assert sum(1 for o in outcomes if o.scenario.at_least) >= 15 and sum(1 for o in outcomes if o.scenario.at_least is None) >= 3


def test_quiet_shapes_fail_when_their_detector_wakes_and_the_rate_has_no_zero_division():
    """A quiet shape passes only when the detector it is written against raises nothing: the true-positive form
    of each false-positive shape must fail, or the check is vacuous (review of #128)."""
    from tapwatch.router import Route
    base = selfcheck.base_config()
    beats = [dict(selfcheck.conn(selfcheck.T0 + i * 60, dst="203.0.113.77", port=50003, proto="udp"), duration=1.0)
             for i in range(15)]                                                       # a real heartbeat, not a call
    o = selfcheck.run_scenario(selfcheck.Scenario("beacon as quiet", beats, "beaconing", None), base)
    assert not o.passed and "beaconing→" in o.got
    dtls = [dict(r, client_cert_chain_fps=[]) for r in selfcheck._webrtc_media()]      # server-only DTLS: the four-sign stack
    o = selfcheck.run_scenario(selfcheck.Scenario("dtls as quiet", dtls, "tls_odd", None), base)
    assert not o.passed and "tls_odd→" in o.got
    probes = [dict(r, resp_bytes=0) for r in selfcheck._reset_after_data()]           # resets with no data back: a scan
    o = selfcheck.run_scenario(selfcheck.Scenario("scan as quiet", probes, "scan", None), base)
    assert not o.passed and "scan→" in o.got
    only_quiet = [selfcheck.run_scenario(selfcheck.SCENARIOS[-1], base)]
    assert "detected 0/0; quiet shapes staying quiet 1/1" in selfcheck.report(only_quiet)
    assert selfcheck.run_scenario(selfcheck.Scenario("sweep", selfcheck._sweep(), "mgmt_access", Route.ALERT),
                                  {**base, "network": {**base["network"], "admin_devices": ["192.168.50.66"]}}).passed is False


def test_selfcheck_command_reports_and_exits_clean(tmp_path, capsys):
    (tmp_path / "config.yaml").write_text(f"db_path: {tmp_path / 't.db'}\nfeeds_dir: {tmp_path / 'feeds'}\n")
    assert main(["-c", str(tmp_path / "config.yaml"), "selfcheck"]) == 0
    out = capsys.readouterr().out
    assert "detected 24/24 (100%)" in out and "quiet shapes staying quiet 4/4" in out and "detectors built from the config file" in out
    assert main(["-c", str(tmp_path / "config.yaml"), "selfcheck", "--json"]) == 0
    assert '"passed": true' in capsys.readouterr().out
