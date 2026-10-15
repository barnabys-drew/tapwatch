"""`tapwatch init`: detected defaults, answers, files written safely."""

import os
import stat

import pytest
import yaml

from tapwatch import config, wizard

FACTS = wizard.Facts(gateway="192.168.50.1", this_ip="192.168.50.10", timezone="America/Chicago",
                     interfaces=[("eth0", True), ("eth1", False)])


def answers(**overrides):
    def ask(question, default, choices=None):
        for key, val in overrides.items():
            if key in question.lower():
                return val
        return default
    return ask


def test_mirror_nic_without_an_ip_is_suggested():
    assert wizard.suggest_iface(FACTS) == "eth1"
    assert wizard.suggest_iface(wizard.Facts(interfaces=[("eth0", True)])) == "eth0"


def test_defaults_give_a_loadable_home_config_with_ntfy(tmp_path):
    cfg, assets, env, notes = wizard.build(FACTS, answers())
    written = wizard.write(str(tmp_path), cfg, assets, env)
    loaded = config.load(str(tmp_path / "config.yaml"))
    assert loaded["audience"] == "office" and loaded["network"]["gateways"] == ["192.168.50.1"]
    assert loaded["typesafe"] == {"enabled": False} and "smtp" not in loaded
    assert env["TAPWATCH_NTFY_URL"].startswith("https://ntfy.sh/tapwatch-") and len(env["TAPWATCH_NTFY_URL"]) > 40
    assert len(env["TAPWATCH_UI_TOKEN"]) >= 24                                  # case desk login, >= 16 required
    assert "TAPWATCH_NTFY_URL" not in (tmp_path / "config.yaml").read_text()       # secrets stay in .env
    assert stat.S_IMODE(os.stat(tmp_path / ".env").st_mode) == 0o600
    assert yaml.safe_load((tmp_path / "assets.yaml").read_text())["192.168.50.1"]["role"] == "router"
    assert any("TAP_IFACE=eth1" in n for n in notes) and len(written) == 3


def test_email_and_jev_answers(tmp_path):
    cfg, _, env, _ = wizard.build(FACTS, answers(where="email", username="me@example.com",
                                                 password="app-pass", typesafe="ts-key"))
    assert cfg["smtp"]["to"] == "me@example.com" and env["TAPWATCH_SMTP_PASSWORD"] == "app-pass"
    assert cfg["typesafe"]["enabled"] and env["TYPESAFE_API_KEY"] == "ts-key"


def test_existing_files_need_force_and_env_keeps_other_keys(tmp_path):
    (tmp_path / "config.yaml").write_text("mine: true\n")
    (tmp_path / ".env").write_text("OTHER=1\nTAPWATCH_NTFY_URL=old\n")
    cfg, assets, env, _ = wizard.build(FACTS, answers())
    with pytest.raises(FileExistsError):
        wizard.write(str(tmp_path), cfg, assets, env)
    assert (tmp_path / "config.yaml").read_text() == "mine: true\n"
    wizard.write(str(tmp_path), cfg, assets, env, force=True)
    lines = (tmp_path / ".env").read_text().splitlines()
    assert "OTHER=1" in lines and "TAPWATCH_NTFY_URL=old" not in lines


def test_windows_capture_path_is_offered_when_npcap_is_there():
    f = wizard.Facts(gateway="192.168.50.1", windows_capture=True)
    _, _, _, notes = wizard.build(f, answers())
    assert any("capture_mirror.sh" in n and "'Ethernet'" in n for n in notes)


# ------------------------------------------------------------ systemd user services

def test_service_units_run_this_python_and_code_from_the_home_dir(tmp_path):
    from tapwatch import service
    u = service.units(str(tmp_path), str(tmp_path / "logs"), capture_iface="Ethernet 2", syslog=True)
    assert set(u) == {"tapwatch-alerter.service", "tapwatch-ui.service", "tapwatch-watchdog.service",
                      "tapwatch-capture.service", "tapwatch-syslog.service"}
    a = u["tapwatch-alerter.service"]
    assert f"WorkingDirectory={tmp_path}" in a and f"Environment=PYTHONPATH={service.CODE}" in a
    assert f"run --zeek-dir {tmp_path / 'logs'}" in a and "Restart=on-failure" in a
    assert "'Ethernet 2'" in u["tapwatch-capture.service"] and "docker rm -f tapwatch-mirror" in u["tapwatch-capture.service"]
    assert f"TAPWATCH_HOME={tmp_path}" in u["tapwatch-watchdog.service"]
    assert "tapwatch-capture.service" not in service.units(str(tmp_path), str(tmp_path))


def test_service_install_and_uninstall(tmp_path):
    from tapwatch import service
    calls = []
    run = lambda cmd, check=False: calls.append(cmd)
    paths = service.install(service.units(str(tmp_path), str(tmp_path)), run=run, unit_dir=tmp_path / "units")
    assert len(paths) == 3 and calls[0] == ["systemctl", "--user", "daemon-reload"]
    assert calls[1][:4] == ["systemctl", "--user", "enable", "--now"]
    removed = service.uninstall(run=run, unit_dir=tmp_path / "units")
    assert len(removed) == 3 and not list((tmp_path / "units").iterdir())


def test_wizard_proposes_the_lans_ipv6_prefix_and_skips_privacy_addresses():
    out = ("2: eth0    inet6 2001:db8:abcd:12:5d1e:ffff:aaaa:1/64 scope global temporary dynamic\n"
           "       valid_lft 600sec preferred_lft 600sec\n"
           "2: eth0    inet6 2001:db8:abcd:12:aaaa:bbbb:cccc:dddd/64 scope global dynamic mngtmpaddr\n")
    assert wizard.global_v6_prefix(out) == "2001:db8:abcd:12::/64"
    assert wizard.global_v6_prefix("2: eth0    inet6 fe80::1/64 scope link\n") == ""
    cfg, _, _, _ = wizard.build(wizard.Facts(gateway="192.168.50.1", local_v6="2001:db8:abcd:12::/64"), answers())
    assert cfg["network"]["local_nets"] == ["2001:db8:abcd:12::/64"]
    assert wizard.build(FACTS, answers())[0]["network"]["local_nets"] == []
