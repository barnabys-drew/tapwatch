"""#14: computers enrolled in Fleet. Their results arrive in one log, each agent read by its own set of host rules."""

import json

import yaml
from conftest import T0
from test_hostrules import PS, WORD, addrs, start

from tapwatch import config, zeek
from tapwatch.detectors import decode, encode
from tapwatch.hostrules import FleetAgents, build
from tapwatch.models import Route
from tapwatch.pipeline import Pipeline
from tapwatch.store import Store
from tapwatch.summarizer import Assets

CFG = {"host_context": {"host": "192.168.50.10"}, "network": {"gateways": ["192.168.50.1"]}}
LAPTOP, FAMILY = "uuid-laptop-0001", "uuid-family-0002"


def via_fleet(rec, agent, hostname="pc"):
    """A record as Fleet's results log carries it: pack-named, with the agent's uuid and Fleet's decorations."""
    line = json.dumps({k: v for k, v in rec.items() if k not in ("_type", "ts")}
                      | {"name": f"pack/Global/{rec['name']}", "hostIdentifier": agent,
                         "decorations": {"host_uuid": agent, "hostname": hostname}})
    return zeek._parse_line(line, "osquery")


def encoded(t, agent):
    return via_fleet(start(t, PS, WORD, cmd_enc="1", cmd_dl="1"), agent)


def enc(cases):
    return [c for c in cases if c.detector == "host_encoded_cmd"]


def test_fleet_results_are_their_own_type_with_the_query_name():
    r = via_fleet(addrs(T0, "192.168.50.20"), LAPTOP)
    assert r["_type"] == zeek.FLEET_OSQUERY and r["name"] == "host_addresses" and r["ts"] == T0
    local = zeek._parse_line(json.dumps({"name": "host_addresses", "unixTime": T0}), "osquery")
    assert local["_type"] == "osquery"


def test_each_agent_gets_its_own_address_and_the_local_rules_ignore_them():
    *local, fleet = build(CFG)
    feed = lambda r: [c for d in [*local, fleet] for c in d.feed(r)]
    assert feed(via_fleet(addrs(T0, "192.168.50.20"), LAPTOP)) == []
    feed(via_fleet(addrs(T0, "192.168.50.25"), FAMILY))
    cases = enc(feed(encoded(T0 + 60, LAPTOP)) + feed(encoded(T0 + 61, FAMILY)))
    assert sorted(c.host for c in cases) == ["192.168.50.20", "192.168.50.25"]
    assert local[0].state.host == "192.168.50.10"                  # this PC's own state untouched
    (early,) = enc(feed(via_fleet(start(T0, PS, WORD, guid="{g9}", cmd_enc="1", cmd_dl="1"), "uuid-new", "den-pc")))
    assert early.host == "den-pc (address not known yet)"           # never "this PC"


def test_a_new_agent_learns_its_existing_persistence_quietly():
    fleet = FleetAgents(CFG)
    task = {"name": "updater", "action": "C:\\Users\\Public\\x.exe", "path": "\\updater", "enabled": "1"}
    first = {"name": "scheduled_tasks", "unixTime": T0, "ts": T0, "action": "added", "counter": 0, "columns": task}
    assert fleet.feed(via_fleet(first, FAMILY)) == [] and fleet.flush() == []


def test_agents_survive_a_restart():
    fleet = FleetAgents(CFG)
    fleet.feed(via_fleet(addrs(T0, "192.168.50.25"), FAMILY, "family-pc"))
    saved = json.loads(json.dumps(fleet.snapshot()))
    assert decode(encode(saved)) == saved                           # nested rule snapshots round-trip unchanged
    again = FleetAgents(CFG)
    again.restore(saved)
    (c,) = enc(again.feed(encoded(T0 + 60, FAMILY)))
    assert c.host == "192.168.50.25"


def test_fleet_log_is_followed_and_its_inventory_recorded(tmp_path):
    log = tmp_path / "fleet" / "osqueryd.results.log"
    log.parent.mkdir()
    log.write_text("")
    assert str(log.parent) in config.host_log_dirs({"fleet": {"results_log": str(log)}})
    p = Pipeline(build(CFG), Assets(), Store(":memory:"))
    rows = [{"name": "Microsoft Windows 11 Home", "version": "10.0.26100", "platform": "windows"}]
    os_rec = {"name": "os_version", "unixTime": T0, "ts": T0, "action": "snapshot", "snapshot": rows}
    p.process(via_fleet(os_rec, FAMILY))
    assert FAMILY in p.store.agents()
    out = p.process(encoded(T0 + 60, FAMILY))
    assert out and out[0][3] is Route.ALERT


def test_the_fleet_spec_is_generated_from_osquery_conf():
    from tools import fleet_config
    conf = json.loads(fleet_config.CONF.read_text())
    assert fleet_config.OUT.read_text() == fleet_config.render(conf), "run: python tools/fleet_config.py > deploy/fleet/tapwatch.yml"
    head, *reports = yaml.safe_load_all(fleet_config.OUT.read_text())
    assert {r["spec"]["name"] for r in reports} == set(conf["schedule"])
    assert all(r["spec"]["automations_enabled"] and r["spec"]["discard_data"] for r in reports)
    opts = head["spec"]["agent_options"]["config"]["options"]
    assert opts["pack_delimiter"] == "/" and not set(opts) & fleet_config.STARTUP_ONLY
    by = {r["spec"]["name"]: r["spec"] for r in reports}
    assert by["sysmon_events"]["platform"] == "windows" and by["crontab"]["platform"] == "darwin,linux"
    assert by["host_addresses"]["logging"] == "snapshot" and by["listening_ports"]["logging"] == "differential"
