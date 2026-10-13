"""Router syslog: CEF parsing, the listener, and the UDM IPS / admin-login rules."""

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
