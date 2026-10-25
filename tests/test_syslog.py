"""Router syslog: CEF and firewall parsing, the listener, and the UDM IPS / admin-login rules.

REAL_* lines are sanitized copies of what a UDM Pro (UniFi Network 10.6.106) actually sent on
2026-10-15: addresses moved to 192.168.50.x, MACs to 02:00:00:00:00:0N, names made generic.
"""

import ipaddress
import json
import socket
import threading
import time

from conftest import T0

from tapwatch import syslogin, zeek
from tapwatch.detectors import UdmAdmin, UdmIps, Warmup

# From Graylog's UniFi content pack (a real UDM line; addresses there are their example's).
SAMPLE = ("<14>Oct 13 17:30:00 pandora CEF:0|Ubiquiti|UniFi Network|9.4.19|201|Threat Detected and Blocked|7|"
          "proto=TCP src=81.181.129.172 spt=54321 dst=192.168.0.233 dpt=443 UNIFIcategory=Security "
          "UNIFIsubCategory=Intrusion Prevention UNIFIhost=Office-UDM-Pro UNIFIrisk=medium "
          "UNIFIipsSignature=ET DROP Dshield Block Listed Source group 1 "
          "msg=A network intrusion attempt has been detected and blocked.")

# A real CEF event: no <PRI>, one hostname, values with spaces, and a UNIFIutcTime of its own.
REAL_CEF = ("Oct 15 19:29:37 gateway CEF:0|Ubiquiti|UniFi Network|10.6.106|401|WiFi Client Disconnected|2|"
            "UNIFIcategory=Client Devices UNIFIhost=UDM Pro UNIFIlastConnectedToDeviceName=U7 Pro "
            "UNIFIlastConnectedToDeviceIp=192.168.50.2 UNIFIlastConnectedToDeviceMac=02:00:00:00:00:02 "
            "UNIFIlastConnectedToDeviceModel=U7-Pro UNIFIlastConnectedToDeviceVersion=8.7.11 "
            "UNIFIclientAlias=speaker 0a UNIFIclientHostname=speaker UNIFIclientIp=192.168.50.18 "
            "UNIFIclientMac=02:00:00:00:00:0a UNIFIwifiChannel=40 UNIFIwifiChannelWidth=80 UNIFIwifiName=Home & Co "
            "UNIFIwifiBand=na UNIFIwifiAirtimeUtilization=32 UNIFIwifiInterference=19 UNIFIlastConnectedToWiFiRssi=-51 "
            "UNIFIduration=1d 11h UNIFIusageDown=1.19 MB UNIFIusageUp=1.50 MB UNIFInetworkName=Default "
            "UNIFInetworkSubnet=192.168.50.0/24 UNIFInetworkVlan=1 UNIFIutcTime=2026-10-16T00:29:37.902Z "
            "msg=speaker 0a disconnected from Home & Co")

# Real firewall lines ("Firewall Default Policy" content): a default-policy accept (RET) for a LAN
# DNS query to the gateway, a TCP one, an IPv6 mDNS one, and the WAN default drop (a late packet
# of a finished flow, the usual kind).
REAL_FW_UDP = ('<13>Oct 15 19:25:16 gateway gateway [LAN_LOCAL-RET-2147483647] DESCR="no rule description" IN=br0 '
               'OUT= MAC=02:00:00:00:00:01:02:00:00:00:00:0a:08:00 SRC=192.168.50.18 DST=192.168.50.1 LEN=59 TOS=00 '
               'PREC=0x00 TTL=64 ID=1 DF PROTO=UDP SPT=61975 DPT=53 LEN=39 MARK=0 ')
REAL_FW_TCP = ('<13>Oct 15 19:27:03 gateway gateway [LAN_LOCAL-RET-2147483647] DESCR="no rule description" IN=br0 '
               'OUT= MAC=02:00:00:00:00:01:02:00:00:00:00:0b:08:00 SRC=192.168.50.44 DST=192.168.50.1 LEN=60 TOS=00 '
               'PREC=0x00 TTL=64 ID=62947 DF PROTO=TCP SPT=34348 DPT=53 SEQ=976532867 ACK=0 WINDOW=29200 SYN '
               'URGP=0 MARK=0 ')
REAL_FW_V6 = ('<13>Oct 15 19:27:39 gateway gateway [LAN_LOCAL-RET-2147483646] DESCR="no rule description" IN=br0 '
              'OUT= MAC=33:33:00:00:00:fb:02:00:00:00:00:0c:86:dd SRC=fe80::1 DST=ff02::fb LEN=106 TC=0 HOPLIMIT=255 '
              'FLOWLBL=657152 PROTO=UDP SPT=5353 DPT=5353 LEN=66 MARK=1a0000 ')
REAL_FW_DROP = ('<13>Oct 15 20:09:47 gateway gateway [WAN_LOCAL-D-2147483647] DESCR="[WAN_LOCAL]Block All Other Tra" '
                'IN=eth8 OUT= MAC=02:00:00:00:00:01:02:00:00:00:00:0d:08:00 SRC=198.51.100.7 DST=203.0.113.5 LEN=103 '
                'TOS=00 PREC=0x00 TTL=58 ID=27807 DF PROTO=TCP SPT=443 DPT=38584 SEQ=658052053 ACK=589986118 '
                'WINDOW=281 ACK PSH URGP=0 MARK=1a0000 ')
# A real admin event ("Admin Activity" content): class 544, keyed by UNIFIadmin, not suser.
REAL_ADMIN = ("Oct 15 19:34:48 gateway CEF:0|Ubiquiti|UniFi Network|10.6.106|544|Network Accessed|4|UNIFIcategory=Audit "
              "UNIFIhost=UDM Pro UNIFIaccessMethod=web UNIFIadmin=Admin User src=192.168.50.10 "
              "UNIFIutcTime=2026-10-16T00:34:48.590Z msg=Admin User accessed UniFi Network using the web. "
              "Source IP: 192.168.50.10")
# The gateway's own system log also arrives; none of it is an event.
REAL_SYSTEM = "<30>Oct 15 19:28:01 gateway gateway earlyoom[1024]: mem avail:  1679 of  3946 MiB (42.55%)"


def test_parse_cef_header_and_extension_values_with_spaces():
    c = syslogin.parse_cef(SAMPLE)
    assert (c["vendor"], c["product"], c["class_id"], c["name"]) == (
        "Ubiquiti", "UniFi Network", "201", "Threat Detected and Blocked")
    assert c["UNIFIipsSignature"] == "ET DROP Dshield Block Listed Source group 1"
    assert c["UNIFIsubCategory"] == "Intrusion Prevention" and c["dpt"] == "443"
    assert c["msg"].startswith("A network intrusion attempt")


def test_parse_cef_escapes_and_rejects_non_cef():
    c = syslogin.parse_cef(r"CEF:0|Ubi\|quiti|P|1|7|Name|3|msg=a\=b c=d")
    assert c["vendor"] == "Ubi|quiti" and c["msg"] == "a=b" and c["c"] == "d"
    assert syslogin.parse_cef("<14>Oct 13 kernel: [FW-A] IN=br0") is None


def test_real_cef_line_without_pri_and_with_spaces_in_values():
    kind, c = syslogin.parse_line(REAL_CEF)
    assert kind == "cef" and (c["class_id"], c["name"]) == ("401", "WiFi Client Disconnected")
    assert c["UNIFIhost"] == "UDM Pro" and c["UNIFIwifiName"] == "Home & Co" and c["UNIFIduration"] == "1d 11h"
    assert c["UNIFIclientIp"] == "192.168.50.18" and c["msg"] == "speaker 0a disconnected from Home & Co"


def test_firewall_lines_parse_to_chain_action_and_addresses():
    kind, fw = syslogin.parse_line(REAL_FW_UDP)
    assert kind == "firewall"
    assert (fw["chain"], fw["action"], fw["rule"], fw["descr"]) == ("LAN_LOCAL", "RET", "2147483647", "no rule description")
    assert (fw["in"], fw["out"], fw["src"], fw["dst"]) == ("br0", "", "192.168.50.18", "192.168.50.1")
    assert (fw["proto"], fw["spt"], fw["dpt"], fw["len"]) == ("UDP", 61975, 53, 59)  # the IP length, not UDP's
    assert "MAC" not in fw and "mac" not in fw  # the MAC field is a 14-byte ethernet header dump; not kept
    tcp = syslogin.parse_line(REAL_FW_TCP)[1]
    assert (tcp["proto"], tcp["dpt"], tcp["ttl"]) == ("TCP", 53, 64)
    v6 = syslogin.parse_line(REAL_FW_V6)[1]
    assert (v6["src"], v6["dst"], v6["dpt"], v6["rule"]) == ("fe80::1", "ff02::fb", 5353, "2147483646")
    drop = syslogin.parse_line(REAL_FW_DROP)[1]
    assert (drop["chain"], drop["action"], drop["rule"]) == ("WAN_LOCAL", "D", "2147483647")
    assert drop["descr"] == "[WAN_LOCAL]Block All Other Tra"  # iptables truncates the prefix; the rule name is cut
    assert (drop["in"], drop["src"], drop["dst"], drop["proto"], drop["spt"], drop["dpt"]) == (
        "eth8", "198.51.100.7", "203.0.113.5", "TCP", 443, 38584)
    assert syslogin.parse_line(REAL_SYSTEM) == ("system", None)


def test_firewall_accepts_and_system_lines_are_dropped_without_a_warning_each(tmp_path, caplog):
    w, st, allow = syslogin.UdmWriter(str(tmp_path)), syslogin.Stats(every=600), {"192.168.50.1"}
    caplog.set_level("INFO", logger="tapwatch")
    for i in range(300):  # the real rate: hundreds of default-policy accepts a minute
        assert syslogin.handle(REAL_FW_UDP.encode(), "192.168.50.1", w, allow, now=T0 + i / 10, stats=st) is None
    assert syslogin.handle(REAL_SYSTEM.encode(), "192.168.50.1", w, allow, now=T0 + 31, stats=st) is None
    assert syslogin.handle(REAL_FW_DROP.encode(), "192.168.50.1", w, allow, now=T0 + 32, stats=st) == "firewall"
    assert syslogin.handle(REAL_CEF.encode(), "192.168.50.1", w, allow, now=T0 + 33, stats=st) == "cef"
    assert syslogin.handle(REAL_CEF.encode(), "192.168.50.66", w, allow, now=T0 + 34, stats=st) is None
    assert syslogin.handle(REAL_CEF.encode(), "192.168.50.66", w, allow, now=T0 + 35, stats=st) is None
    recs = [json.loads(line) for line in (tmp_path / "udm.log").read_text().splitlines()]
    assert [r["kind"] for r in recs] == ["firewall", "cef"]
    assert recs[0]["chain"] == "WAN_LOCAL" and recs[0]["src"] == "198.51.100.7" and recs[1]["class_id"] == "401"
    assert st.counts == {"firewall_accept": 300, "system": 1, "firewall_drop": 1, "cef": 1, "refused": 2}
    for i in range(50):  # spoofed sources: one warning a period, no per-sender state
        syslogin.handle(REAL_CEF.encode(), f"198.51.100.{i}", w, allow, now=T0 + 36, stats=st)
    assert [r.message for r in caplog.records if "refusing" in r.message] == [
        "syslog: refusing datagrams from 192.168.50.66 (not in syslog.allow / network.gateways)"]
    assert st.counts["refused"] == 52 and not hasattr(st, "refused")
    syslogin.handle(REAL_FW_UDP.encode(), "192.168.50.1", w, allow, now=T0 + 700, stats=st)  # the period ends
    assert st.counts == {"firewall_accept": 1}
    summary = [r.message for r in caplog.records if r.message.startswith("syslog: ")][-1]
    assert "firewall_accept 300" in summary and "cef 1" in summary and "refused 52" in summary and "last 12 min" in summary
    syslogin.handle(REAL_CEF.encode(), "192.168.50.66", w, allow, now=T0 + 701, stats=st)
    assert sum("refusing" in r.message for r in caplog.records) == 2  # a new period warns again
    st.flush(T0 + 1300)  # what the listener does on a receive timeout: silence is reported, not hidden
    assert st.flush(T0 + 1900) is None
    assert [r.message for r in caplog.records][-1] == "syslog: nothing arrived in the last 10 min"


def test_only_allowed_senders_are_written_and_the_file_rotates(tmp_path):
    w = syslogin.UdmWriter(str(tmp_path))
    assert not syslogin.handle(SAMPLE.encode(), "192.168.50.66", w, {"192.168.50.1"}, now=T0)
    assert syslogin.handle(SAMPLE.encode(), "192.168.50.1", w, {"192.168.50.1"}, now=T0)
    w.opened = T0
    assert syslogin.handle(SAMPLE.encode(), "192.168.50.1", w, {"192.168.50.1"}, now=T0 + 3700)
    names = sorted(p.name for p in tmp_path.iterdir())
    assert len(names) == 2 and "udm.log" in names and any(zeek.rotated_ts(p) for p in tmp_path.iterdir())
    recs = list(zeek.replay(tmp_path))
    assert len(recs) == 2 and all(r["_type"] == "udm" and r["sender"] == "192.168.50.1" for r in recs)


def test_listener_receives_udp_end_to_end(tmp_path):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    t = threading.Thread(target=syslogin.serve, args=(f"127.0.0.1:{port}", str(tmp_path), {"127.0.0.1"}),
                         daemon=True)
    t.start()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        for _ in range(50):
            s.sendto(SAMPLE.encode(), ("127.0.0.1", port))
            time.sleep(0.05)
            if (tmp_path / "udm.log").exists():
                break
    rec = json.loads((tmp_path / "udm.log").read_text().splitlines()[0])
    assert rec["UNIFIrisk"] == "medium"


def udm(**kw):
    base = {"_type": "udm", "ts": T0, "sender": "192.168.50.1"}
    base.update(kw)
    return base


def test_router_ips_routing():
    det = UdmIps()
    inbound_blocked = udm(name="Threat Detected and Blocked", src="198.51.100.7", dst="192.168.50.20",
                          UNIFIrisk="medium", UNIFIipsSignature="ET DROP Dshield Block Listed Source")
    outbound_high = udm(name="Threat Detected", src="192.168.50.20", dst="198.51.100.7", UNIFIrisk="high",
                        UNIFIipsSignature="ET MALWARE Possible C2", UNIFIipsSignatureId="2000001")
    a, b = det.feed(inbound_blocked)[0], det.feed(outbound_high)[0]
    assert (a.base_severity, a.must_alert, a.host) == (1, False, "192.168.50.20")
    assert (b.base_severity, b.must_alert, b.facts["direction"]) == (5, True, "outbound")
    assert det.feed(udm(name="Client connected", UNIFIcategory="Monitoring")) == []


def test_real_admin_event_is_learned_then_alerts_from_a_new_place():
    kind, rec = syslogin.parse_line(REAL_ADMIN)
    assert kind == "cef" and rec["UNIFIadmin"] == "Admin User" and rec["src"] == "192.168.50.10"
    det = UdmAdmin(Warmup(600))
    assert det.feed(udm(**rec)) == []                                                    # warmup: learned
    assert det.feed(udm(ts=T0 + 700, **rec)) == []                                       # same user, same PC
    cases = det.feed(udm(ts=T0 + 800, **dict(rec, src="192.168.50.77")))
    assert len(cases) == 1 and cases[0].must_alert and cases[0].host == "192.168.50.77"
    assert cases[0].facts == {"failed": False, "from_lan": True, "method": "web", "dedupe": "Admin User|192.168.50.77"}
    assert cases[0].indicators == ["Admin User"]


def test_router_admin_new_place_and_failure_burst():
    det = UdmAdmin(Warmup(600))
    login = udm(name="Admin Accessed UniFi Network", UNIFIadmin="owner", src="192.168.50.10",
                UNIFIaccessMethod="web", UNIFIcategory="System")
    assert det.feed(login) == []                                              # warmup: learned
    assert det.feed(dict(login, ts=T0 + 700)) == []                           # same user, same place
    cloud = det.feed(dict(login, ts=T0 + 800, src="203.0.113.9"))
    assert cloud[0].must_alert and not cloud[0].facts["from_lan"] and cloud[0].host == "192.168.50.1"
    fails = [udm(ts=T0 + 900 + i, name="Admin login failed", suser="admin", src="198.51.100.4") for i in range(5)]
    out = [c for f in fails for c in det.feed(f)]
    assert len(out) == 1 and out[0].facts["count"] == 5 and out[0].must_alert


def test_an_outside_admin_login_says_whose_network_and_which_country():
    from tapwatch.feeds import AsnTable
    from tapwatch.pipeline import alert_item
    from tapwatch.summarizer import Assets, summarize
    asn = AsnTable([int(ipaddress.IPv4Address("203.0.113.0"))], [int(ipaddress.IPv4Address("203.0.113.255"))],
                   [64500], ["NL"], {64500: "EXAMPLE-HOSTING"})
    det = UdmAdmin(Warmup(0), asn=asn)
    login = udm(name="Admin Accessed UniFi Network", UNIFIadmin="owner", UNIFIaccessMethod="web", UNIFIcategory="System")
    (outside,) = det.feed(dict(login, src="203.0.113.9"))
    f = outside.facts
    assert (f["src"], f["asn"], f["network"], f["country"], f["from_lan"]) == ("203.0.113.9", 64500, "EXAMPLE-HOSTING", "NL", False)
    assert '203.0.113.9 ("EXAMPLE-HOSTING", country NL), on the internet or the vendor\'s cloud' in summarize(outside, Assets())
    # the phone alert says it too, not only the case page (review of #289)
    assert alert_item(outside, None, "always alerts", Assets(), 7)["facts"]["From"] == "203.0.113.9 (EXAMPLE-HOSTING, NL)"
    (inside,) = det.feed(dict(login, src="192.168.50.30"))
    assert "network" not in inside.facts and "a device on the home network" in summarize(inside, Assets())
    assert "From" not in alert_item(inside, None, "always alerts", Assets(), 8)["facts"]
    (unknown,) = det.feed(dict(login, src="198.51.100.4"))                     # not in the table
    assert (unknown.facts["asn"], unknown.facts["network"]) == (None, "") and "an unknown network" in summarize(unknown, Assets())
    (mapped,) = det.feed(dict(login, src="::ffff:203.0.113.20"))               # an IPv4 address written as IPv6
    assert (mapped.facts["src"], mapped.facts["country"]) == ("203.0.113.20", "NL")
    (nosrc,) = det.feed(dict(login, UNIFIadmin="other", src="unknown"))        # no usable source: no place, old wording
    assert "src" not in nosrc.facts and "the internet or the vendor's cloud" in summarize(nosrc, Assets())
    fails = [udm(ts=T0 + 900 + i, name="Admin login failed", suser="admin", src="203.0.113.50") for i in range(5)]
    (burst,) = [c for x in fails for c in det.feed(x)]
    assert burst.facts["country"] == "NL" and "failed logins" in summarize(burst, Assets())


def test_a_port_forward_audit_line_keeps_its_settings_fields():
    """Sanitized from a UDM Pro (UniFi Network 10.6.106), 2026-10-18, #8."""
    line = ("<14>Oct 18 12:13:35 UDM-Pro CEF:0|Ubiquiti|UniFi Network|10.6.106|545|Config Created|5|UNIFIcategory=Audit "
            "UNIFIhost=UDM Pro UNIFIsettingsChanges=destination_ip: any; log: true; name:  tapwatch-test; pfwd_interface: wan; "
            "fwd: 192.168.50.10; fwd_port: 54321; src_limiting_enabled: false; proto: tcp_udp; dst_port: 54321 "
            "UNIFIsettingsEntry=tapwatch-test UNIFIsettingsSection=Port forwarding UNIFIaccessMethod=web "
            "UNIFIadmin=Admin User src=192.168.50.10 msg=Admin User created  tapwatch-test Port forwarding. Source IP: 192.168.50.10")
    kind, rec = syslogin.parse_line(line)
    assert kind == "cef" and rec["name"] == "Config Created" and rec["UNIFIsettingsSection"] == "Port forwarding"
    assert rec["UNIFIsettingsEntry"] == "tapwatch-test" and rec["UNIFIsettingsChanges"].endswith("dst_port: 54321")


def test_each_heard_period_writes_a_heartbeat_row(tmp_path):
    rows = []

    class W:
        def write(self, rec, now):
            rows.append(rec)

    st = syslogin.Stats(every=600, writer=W())
    st.add("system", 1000.0); st.add("cef", 1100.0)
    st.flush(1600.0)
    assert rows == [{"ts": 1600.0, "kind": "stats", "minutes": 10, "counts": {"system": 1, "cef": 1}}]
    st.flush(2200.0)                                                             # nothing heard: no row, R22 sees silence
    st.add("refused", 2300.0); st.flush(2900.0)                                  # only refused senders: no row either
    assert len(rows) == 1
