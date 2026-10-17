"""The scripted detection-rate check (src/tapwatch/selfcheck.py) must stay at 100 % in CI, so a detector change
that silences an attack shape or wakes a known false-positive shape fails the build, not the next live test."""

from tapwatch import selfcheck
from tapwatch.cli import main


def test_every_scenario_passes_with_the_default_config():
    outcomes = selfcheck.run()
    failed = [o for o in outcomes if not o.passed]
    assert not failed, selfcheck.report(outcomes)
    assert sum(1 for o in outcomes if o.scenario.detector) >= 15 and sum(1 for o in outcomes if not o.scenario.detector) >= 3


def test_selfcheck_command_reports_and_exits_clean(tmp_path, capsys):
    (tmp_path / "config.yaml").write_text("db_path: " + str(tmp_path / "t.db") + "\n")
    assert main(["-c", str(tmp_path / "config.yaml"), "selfcheck"]) == 0
    out = capsys.readouterr().out
    assert "detected 15/15 (100%)" in out and "quiet shapes staying quiet 3/3" in out
    assert main(["-c", str(tmp_path / "config.yaml"), "selfcheck", "--json"]) == 0
    assert '"passed": true' in capsys.readouterr().out
