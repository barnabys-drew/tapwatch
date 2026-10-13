"""Measure a household baseline from a Zeek JSON log directory. Read-only.

Prints aggregate numbers only: devices are shown as ranks ("dev-01" = busiest),
never as IPs or MACs, so the output is safe to paste into docs.

    python3 docs/detections/baseline.py eval/data/home-mirror-20261012

Re-run it on the full night once the capture ends; DESIGN.md quotes its output.
"""

from __future__ import annotations

import ipaddress
import json
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16",
    "fe80::/10", "fc00::/7", "224.0.0.0/4", "ff00::/8", "255.255.255.255/32")]
GATEWAY_SUFFIX = ".1"  # UDM interfaces are x.x.x.1 on every LAN here


def internal(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in NETS)


def unicast_device(ip: str) -> bool:
    """A real LAN device: internal, not multicast/broadcast/link-local/unspecified, not the gateway."""
    if not internal(ip) or ip.startswith(("fe80:", "169.254.", "0.", "::")) or ip.endswith((".255", GATEWAY_SUFFIX)):
        return False
    return not ipaddress.ip_address(ip).is_multicast


def base_domain(name: str) -> str:
    parts = [p for p in name.lower().rstrip(".").split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else name.lower()


def rows(d: Path, name: str):
    p = d / f"{name}.log"
    if not p.exists():
        return
    with p.open() as f:
        for line in f:
            if line.startswith("{"):
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    pass  # live log: last line may be half-written


def pct(xs: list[float], q: float) -> float:
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(len(xs) * q))] if xs else 0.0


def main(d: Path) -> None:
    conn = list(rows(d, "conn"))
    t0, t1 = min(r["ts"] for r in conn), max(r["ts"] for r in conn)
    hours = (t1 - t0) / 3600
    print(f"span: {hours:.2f} h, conn rows: {len(conn)}")

    devices = {r["id.orig_h"] for r in conn if unicast_device(r["id.orig_h"])}
    v6ll = {r["id.orig_h"] for r in conn if r["id.orig_h"].startswith("fe80:")}
    print(f"IPv4/ULA devices originating traffic: {len(devices)}; rotating IPv6 link-local addrs: {len(v6ll)}")

    out = [r for r in conn if unicast_device(r["id.orig_h"]) and not internal(r["id.resp_h"])]
    per: dict[str, list] = defaultdict(list)
    for r in out:
        per[r["id.orig_h"]].append(r)
    rank = {h: f"dev-{i + 1:02d}" for i, h in enumerate(sorted(per, key=lambda h: -len(per[h])))}
    print(f"\ndevices with internet traffic: {len(per)}; outbound conns/h total: {len(out) / hours:.0f}")
    print("device  conns/h  distinct-dst-IPs  up-MB/h  down-MB/h")
    for h in sorted(per, key=lambda h: -len(per[h])):
        rs = per[h]
        up = sum(r.get("orig_bytes") or 0 for r in rs) / hours / 1e6
        dn = sum(r.get("resp_bytes") or 0 for r in rs) / hours / 1e6
        print(f"{rank[h]}  {len(rs) / hours:7.0f}  {len({r['id.resp_h'] for r in rs}):16d}  {up:7.1f}  {dn:9.1f}")
    rates = [len(rs) / hours for rs in per.values()]
    print(f"conns/h per device: median {statistics.median(rates):.0f}, max {max(rates):.0f}")

    ports = Counter(f"{r['proto']}/{r['id.resp_p']}" for r in out)
    users = {p: len({r["id.orig_h"] for r in out if f"{r['proto']}/{r['id.resp_p']}" == p}) for p in ports}
    print(f"\ndistinct outbound proto/port: {len(ports)}")
    for p, n in ports.most_common():
        print(f"  {p:10s} {n:6d} conns, {users[p]} device(s)")

    dur = [r.get("duration") or 0 for r in out]
    print(f"\noutbound duration s: p50 {pct(dur, .5):.1f}, p99 {pct(dur, .99):.0f}, max {max(dur):.0f}; "
          f">10 min: {sum(x > 600 for x in dur)}, >1 h: {sum(x > 3600 for x in dur)}")

    lan = [r for r in conn if unicast_device(r["id.orig_h"]) and unicast_device(r["id.resp_h"])]
    pairs = Counter((r["id.orig_h"], r["id.resp_h"]) for r in lan)
    print(f"device->device unicast (not via gateway) rows seen on mirror: {len(lan)}, pairs: {len(pairs)}")

    dns = list(rows(d, "dns"))
    uni = [r for r in dns if r.get("id.resp_p") == 53]
    gw = [r for r in uni if r["id.resp_h"].endswith(GATEWAY_SUFFIX) and internal(r["id.resp_h"])]
    bypass = [r for r in uni if not internal(r["id.resp_h"])]
    other_internal = [r for r in uni if internal(r["id.resp_h"]) and r not in gw]
    rc = Counter(r.get("rcode_name") for r in uni)
    print(f"\nDNS port-53 queries: {len(uni)} ({len(uni) / hours:.0f}/h); to UDM: {len(gw)}; "
          f"to public resolvers (bypass): {len(bypass)} from {len({r['id.orig_h'] for r in bypass})} device(s); "
          f"to other internal resolvers (VPN): {len(other_internal)}")
    print(f"  clients using UDM DNS: {len({r['id.orig_h'] for r in gw})}; NXDOMAIN {rc.get('NXDOMAIN', 0)}; "
          f"distinct names {len({r.get('query') for r in uni})}")
    nx = Counter(r["id.orig_h"] for r in uni if r.get("rcode_name") == "NXDOMAIN")
    print(f"  NXDOMAIN per device per 10 min, max: {max(nx.values(), default=0) / hours / 6:.1f}")
    print(f"  mDNS/LLMNR/NBNS rows: {len(dns) - len(uni)}")

    ssl = list(rows(d, "ssl"))
    nosni = [r for r in ssl if not r.get("server_name")]
    print(f"\nTLS rows: {len(ssl)}; no SNI: {len(nosni)} ({100 * len(nosni) / max(len(ssl), 1):.0f}%), "
          f"of which established: {sum(bool(r.get('established')) for r in nosni)}")
    print(f"  validation_status: {dict(Counter(r.get('validation_status') for r in ssl))}")
    has_ja = any("ja3" in r or "ja4" in r for r in ssl[:50])
    print(f"  JA3/JA4 fields present: {has_ja}")

    answered = {a for r in dns for a in (r.get("answers") or [])}
    tcp_out = [r for r in out if r["proto"] == "tcp" and r.get("conn_state") in ("SF", "S1", "S3", "RSTO", "RSTR")]
    bare = [r for r in tcp_out if r["id.resp_h"] not in answered]
    print(f"\nestablished outbound TCP to an IP no DNS answer explains: {len(bare)} of {len(tcp_out)} "
          f"from {len({r['id.orig_h'] for r in bare})} device(s)")

    http = list(rows(d, "http"))
    ext = [r for r in http if not internal(r["id.resp_h"])]
    print(f"\nHTTP rows: {len(http)} (to internet: {len(ext)}); with username/password: "
          f"{sum(bool(r.get('username') or r.get('password')) for r in http)}")
    print(f"  cleartext auth-ish services seen (ftp/telnet/pop3/imap 21/23/110/143): "
          f"{sum(r['id.resp_p'] in (21, 23, 110, 143) for r in conn)}")
    print(f"  user-agent families: {len({(r.get('user_agent') or '').split('/')[0] for r in http})}")

    dhcp = list(rows(d, "dhcp"))
    servers = {r.get("server_addr") for r in dhcp if r.get("server_addr")}
    print(f"\nDHCP rows: {len(dhcp)}; distinct MACs: {len({r.get('mac') for r in dhcp})}; distinct servers: {len(servers)}")

    # First-seen rates: (device, base domain) pairs, bucketed by 10 minutes from the start.
    first: dict[tuple, float] = {}
    for r in sorted(dns + ssl, key=lambda r: r["ts"]):
        name = r.get("query") or r.get("server_name")
        h = r.get("id.orig_h", "")
        if not name or "." not in name.strip(".") or not unicast_device(h) \
                or name.endswith((".local", ".arpa", ".localdomain")):  # skip NetBIOS/single-label names
            continue
        if r.get("rcode_name") not in (None, "NOERROR"):
            continue
        first.setdefault((h, base_domain(name)), r["ts"])
    buckets = Counter(int((ts - t0) // 600) for ts in first.values())
    print(f"\nfirst-seen (device, base-domain) pairs: {len(first)}; distinct base domains: "
          f"{len({k[1] for k in first})}")
    print("  per 10-min bucket since start: " + ", ".join(str(buckets.get(i, 0)) for i in range(max(buckets) + 1)))
    pop_path = Path("eval/data/tranco/top-100k.csv")
    if pop_path.exists():
        pop = {line.strip().split(",")[-1].lower() for line in pop_path.open()}
        doms = {k[1] for k in first}
        print(f"  base domains in Tranco top-100k: {sum(dm in pop for dm in doms)} of {len(doms)}")
    single = Counter(k[1] for k in first)
    print(f"  base domains used by only one device: {sum(1 for v in single.values() if v == 1)}")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
