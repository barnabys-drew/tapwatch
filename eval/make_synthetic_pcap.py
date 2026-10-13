"""Write a small synthetic PCAP with no real hosts and no malware, for end-to-end tests.

Contents (documentation address ranges only):
  * 192.168.50.66 beacons to 198.51.100.9:443 every 60 s           (labelled malicious)
  * 192.168.50.66 does 40 failed DNS lookups of random names        (labelled malicious)
  * 192.168.50.10 checks 203.0.113.80:443 every 300 s, like an updater (benign)
  * 192.168.50.10 resolves a handful of normal names                (benign)

Usage: python3 eval/make_synthetic_pcap.py eval/data/synthetic.pcap
Then:  eval/replay.sh eval/data/synthetic.pcap eval/out/synthetic
"""

import random
import socket
import struct
import sys

T0 = 1_790_000_000
GW_MAC, PC_MAC = b"\x02\x00\x00\x00\x00\x01", b"\x02\x00\x00\x00\x00\x02"
DNS_SERVER = "192.168.50.1"


def csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    return ~(s + (s >> 16)) & 0xFFFF


def ip_packet(src, dst, proto, payload):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0x4000, 64, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    hdr = hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:]
    return hdr + payload


def pseudo(src, dst, proto, length):
    return socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, proto, length)


def tcp(src, dst, sport, dport, seq, ack, flags, data=b""):
    seg = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + data
    c = csum(pseudo(src, dst, 6, len(seg)) + seg)
    return ip_packet(src, dst, 6, seg[:16] + struct.pack("!H", c) + seg[18:])


def udp(src, dst, sport, dport, data):
    seg = struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data
    c = csum(pseudo(src, dst, 17, len(seg)) + seg)
    return ip_packet(src, dst, 17, seg[:6] + struct.pack("!H", c) + seg[8:])


def dns_msg(qid, name, response=False, nx=False):
    flags = 0x0100 if not response else (0x8183 if nx else 0x8180)
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0" + struct.pack("!HH", 1, 1)
    return struct.pack("!HHHHHH", qid, flags, 1, 0, 0, 0) + q


class Pcap:
    def __init__(self):
        self.pkts = []

    def add(self, ts, src_mac, dst_mac, ip):
        self.pkts.append((ts, dst_mac + src_mac + b"\x08\x00" + ip))

    def tcp_session(self, ts, src, dst, dport, sport, payload=b"x" * 200):
        out, back = (PC_MAC, GW_MAC), (GW_MAC, PC_MAC)
        a, b = 1000, 5000
        self.add(ts, *out, tcp(src, dst, sport, dport, a, 0, 0x02))
        self.add(ts + 0.02, *back, tcp(dst, src, dport, sport, b, a + 1, 0x12))
        self.add(ts + 0.04, *out, tcp(src, dst, sport, dport, a + 1, b + 1, 0x10))
        self.add(ts + 0.05, *out, tcp(src, dst, sport, dport, a + 1, b + 1, 0x18, payload))
        self.add(ts + 0.08, *back, tcp(dst, src, dport, sport, b + 1, a + 1 + len(payload), 0x18, b"y" * 100))
        self.add(ts + 0.10, *out, tcp(src, dst, sport, dport, a + 1 + len(payload), b + 101, 0x11))
        self.add(ts + 0.12, *back, tcp(dst, src, dport, sport, b + 101, a + 2 + len(payload), 0x11))
        self.add(ts + 0.14, *out, tcp(src, dst, sport, dport, a + 2 + len(payload), b + 102, 0x10))

    def dns(self, ts, src, name, qid, nx=False):
        self.add(ts, PC_MAC, GW_MAC, udp(src, DNS_SERVER, 40000 + qid % 20000, 53, dns_msg(qid, name)))
        self.add(ts + 0.01, GW_MAC, PC_MAC, udp(DNS_SERVER, src, 53, 40000 + qid % 20000,
                                                 dns_msg(qid, name, response=True, nx=nx)))

    def write(self, path):
        with open(path, "wb") as fh:
            fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            fh.writelines(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(frame), len(frame)) + frame for ts, frame in sorted(self.pkts, key=lambda p: p[0]))


def main(out):
    rng = random.Random(7)
    p = Pcap()
    for i in range(30):  # malicious beacon, 30 minutes
        p.tcp_session(T0 + i * 60 + rng.uniform(-0.5, 0.5), "192.168.50.66", "198.51.100.9", 443, 50000 + i)
    for i in range(8):  # benign updater, every 5 minutes
        p.tcp_session(T0 + i * 300 + 7, "192.168.50.10", "203.0.113.80", 443, 51000 + i)
    for i in range(40):  # DGA-style lookups
        name = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(16)) + ".com"
        p.dns(T0 + 900 + i * 5, "192.168.50.66", name, 100 + i, nx=True)
    for i, name in enumerate(["www.example.com", "mail.example.org", "files.example.net"] * 4):
        p.dns(T0 + 30 + i * 60, "192.168.50.10", name, 500 + i)
    p.write(out)
    print(f"wrote {len(p.pkts)} packets to {out}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "synthetic.pcap")
