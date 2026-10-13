"""Helpers that fabricate Zeek-style records so tests don't need real captures.

Addresses use documentation ranges: 192.168.50.0/24 inside, 203.0.113.0/24 and
198.51.100.0/24 outside (RFC 5737), so nothing here points at a real host.
"""

import json

import pytest

T0 = 1_790_000_000.0


def conn(ts, src="192.168.50.10", dst="203.0.113.5", port=443, state="SF", orig_bytes=500, service="ssl"):
    return {"_type": "conn", "ts": ts, "id.orig_h": src, "id.orig_p": 50000, "id.resp_h": dst,
            "id.resp_p": port, "proto": "tcp", "service": service, "conn_state": state, "orig_bytes": orig_bytes}


def dns(ts, query, src="192.168.50.10", rcode="NOERROR"):
    return {"_type": "dns", "ts": ts, "id.orig_h": src, "id.resp_h": "192.168.50.1", "query": query,
            "rcode_name": rcode}


def ssl(ts, server_name, src="192.168.50.10", dst="203.0.113.5"):
    return {"_type": "ssl", "ts": ts, "id.orig_h": src, "id.resp_h": dst, "server_name": server_name}


def dhcp(ts, server="192.168.50.1", msg_types=("REQUEST", "ACK"), mac="02:00:00:00:00:01"):
    return {"_type": "dhcp", "ts": ts, "server_addr": server, "client_addr": "192.168.50.10",
            "assigned_addr": "192.168.50.10", "mac": mac, "msg_types": list(msg_types)}


def eve_alert(ts_iso, severity, signature="ET MALWARE Test", src="192.168.50.10", dst="198.51.100.7"):
    return {"timestamp": ts_iso, "event_type": "alert", "src_ip": src, "dest_ip": dst,
            "alert": {"severity": severity, "signature": signature, "category": "A Network Trojan was detected",
                      "signature_id": 2000001}}


def write_logs(directory, **files):
    """write_logs(tmp, conn=[...], dns=[...]) -> Zeek JSON log files (strips the _type helper key)."""
    names = {"conn": "conn.log", "dns": "dns.log", "ssl": "ssl.log", "http": "http.log", "dhcp": "dhcp.log",
             "ftp": "ftp.log", "eve": "eve.json"}
    for kind, recs in files.items():
        with open(directory / names[kind], "w") as fh:
            fh.writelines(json.dumps({k: v for k, v in r.items() if k != "_type"}) + "\n" for r in recs)
    return directory


def jev_response(category="benign", conf=0.9, severity=1.0, routine=0.9, page=0.1, tokens=120):
    return {"model": "jev-1.13.0", "usage": {"input_tokens": tokens, "output_tokens": 0}, "answers": {
        "category": {"type": "choice", "choice": category, "confidence": conf, "probabilities": {category: conf}},
        "severity": {"type": "score", "score": severity, "confidence": 0.8, "legend": {}, "probabilities": {}},
        "routine": {"type": "noul", "noul": routine},
        "page_admin": {"type": "noul", "noul": page}}}


class FakeJev:
    """Stands in for JevClient. `answer` may be a dict or a callable(state) -> dict."""

    def __init__(self, answer=None):
        self.answer = answer or jev_response()
        self.states = []

    def triage(self, state):
        from tapwatch.triage import parse

        self.states.append(state)
        return parse(self.answer(state) if callable(self.answer) else self.answer)


@pytest.fixture
def fake_jev():
    return FakeJev
