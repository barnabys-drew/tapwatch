"""`tapwatch doctor`: each part of the install reported in plain words, with the fix, and a failing exit code."""

import json
import os

from tapwatch import doctor

NOW = 1_800_000_000.0


def touch(p, age=0, text=""):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    os.utime(p, (NOW - age, NOW - age))
    return p


def conn(*origins):
    return "".join(json.dumps({"id.orig_h": o, "id.resp_h": "93.184.216.34"}) + "\n" for o in ("x",) + origins)


def levels(results, part):
    return [r.level for r in results if r.part == part]


def test_capture_stale_or_missing_fails_with_a_fix(tmp_path):
    assert doctor.check_capture(tmp_path, set(), NOW)[0].level == doctor.FAIL
    touch(tmp_path / "conn.log", age=3600, text=conn("192.168.1.20"))
    r = doctor.check_capture(tmp_path, set(), NOW)
    assert r[0].level == doctor.FAIL and "60 min" in r[0].said and "restart" in r[0].fix


def test_mirror_port_seen_only_when_other_lan_devices_talk(tmp_path):
    touch(tmp_path / "conn.log", text=conn("192.168.1.10", "192.168.1.10", "8.8.8.8", "fe80::1"))
    r = doctor.check_capture(tmp_path, {"192.168.1.10"}, NOW)
    assert levels(r, "Mirror port") == [doctor.WARN]                   # only this PC (and noise)
    touch(tmp_path / "conn.log", text=conn("192.168.1.10", "192.168.1.20", "10.0.0.5"))
    r = doctor.check_capture(tmp_path, {"192.168.1.10"}, NOW)
    assert levels(r, "Mirror port") == [doctor.OK] and "2 other devices" in r[1].said


def test_router_logs_optional_until_the_listener_is_installed(tmp_path):
    assert doctor.check_router([], tmp_path, NOW)[0].level == doctor.WARN
    assert doctor.check_router(["tapwatch-syslog"], tmp_path, NOW)[0].level == doctor.FAIL
    touch(tmp_path / "udm.log", age=600)
    assert doctor.check_router(["tapwatch-syslog"], tmp_path, NOW)[0].level == doctor.OK


def test_services_report_the_stopped_ones_and_linger(monkeypatch):
    monkeypatch.setenv("USER", "owner")

    def run(cmd, timeout=10):
        if cmd[0] == "loginctl":
            return 0, "Linger=no\n"
        return (3, "") if cmd[-1] == "tapwatch-capture" else (0, "")
    r = doctor.check_services(["tapwatch-alerter", "tapwatch-capture"], run)
    assert r[0].level == doctor.FAIL and "tapwatch-capture" in r[0].said and "alerter" not in r[0].said
    assert r[1].level == doctor.WARN and "enable-linger owner" in r[1].fix
    assert doctor.check_services([], run)[0].level == doctor.FAIL


def test_alerts_and_ai_keys(monkeypatch):
    for k in ("TAPWATCH_NTFY_URL", "TAPWATCH_DISCORD_URL", "TAPWATCH_TEAMS_URL", "TAPWATCH_WEBHOOK_URL",
              "TYPESAFE_API_KEY", "AI_GATEWAY_API_KEY", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    assert doctor.check_alerts({})[0].level == doctor.FAIL
    monkeypatch.setenv("TAPWATCH_NTFY_URL", "https://ntfy.sh/t")
    assert doctor.check_alerts({})[0].level == doctor.OK
    assert doctor.check_ai({"typesafe": {"enabled": False}})[0].level == doctor.WARN       # optional, said so
    assert doctor.check_ai({"typesafe": {"enabled": True}})[0].level == doctor.FAIL        # on without a key
    r = doctor.check_ai({"typesafe": {"enabled": False}, "categories": {"ai": True}})
    assert levels(r, "AI") == [doctor.WARN, doctor.FAIL]


def test_agents_missing_is_a_note_stale_is_a_failure(tmp_path):
    log = tmp_path / "osqueryd.results.log"
    cfg = {"host_context": {"results_logs": [str(log)]}}
    assert doctor.check_agents(cfg, NOW)[0].level == doctor.WARN
    touch(log, age=7200)
    assert doctor.check_agents(cfg, NOW)[0].level == doctor.FAIL
    touch(log, age=30)
    r = doctor.check_agents(cfg, NOW)
    assert r[0].level == doctor.OK and r[1].level == doctor.WARN and "host_context" in r[1].fix
    cfg["host_context"]["host"] = "192.168.1.10"
    assert levels(doctor.check_agents(cfg, NOW), "PC agent") == [doctor.OK]


def test_zeek_dir_comes_from_the_installed_alerter_unit(tmp_path):
    (tmp_path / "tapwatch-alerter.service").write_text(
        "ExecStart=/py -m tapwatch.cli -c config.yaml run --zeek-dir '/home/o/tap watch/logs'\n")
    assert doctor.zeek_dir_from_units(tmp_path) == "/home/o/tap watch/logs"
    assert doctor.zeek_dir_from_units(tmp_path / "none") is None


def test_no_config_stops_early_and_report_counts(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    r = doctor.run_all({}, "config.yaml", "logs", NOW, unit_dir=tmp_path)
    assert len(r) == 1 and r[0].level == doctor.FAIL and "tapwatch init" in r[0].fix
    text = doctor.report(r + [doctor.Result(doctor.WARN, "Router", "off", "do x")])
    assert "-> run `tapwatch init`" in text and "1 problem to fix, 1 note." in text
    assert doctor.report([doctor.Result(doctor.OK, "Disk", "9 GB free")]).endswith("All good.")


def test_only_the_long_running_units_are_checked(tmp_path):
    for u in ("tapwatch-alerter", "tapwatch-capture", "tapwatch-explain-report"):
        (tmp_path / f"{u}.service").write_text("")
    assert doctor.installed_units(tmp_path) == ["tapwatch-alerter", "tapwatch-capture"]
