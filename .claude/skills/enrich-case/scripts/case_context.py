"""Print one tapwatch case plus a summary of its local Zeek evidence, for enrichment.

Reads only local files (tapwatch.db and the Zeek logs); sends nothing anywhere.

  .venv/bin/python .claude/skills/enrich-case/scripts/case_context.py 53
  .venv/bin/python .claude/skills/enrich-case/scripts/case_context.py 53 --window 600
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter

from tapwatch import config, evidence
from tapwatch.detectors import looks_random
from tapwatch.store import Store

# Per-device or per-request IDs inside hostnames. Never search the web with these left in.
ID_LABEL = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|(?=[0-9a-f]*\d)[0-9a-f]{8,}|\d{6,}", re.IGNORECASE)


def registrable(name: str) -> str:
    """Rough "example.com" from "a.b.example.com" (last two labels; wrong for co.uk-style suffixes)."""
    parts = name.rstrip(".").lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else name


def pattern(name: str) -> str:
    """Hostname with IDs replaced by '*', safe to put in a web search."""
    return ID_LABEL.sub("*", name)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("case_id", type=int)
    ap.add_argument("-c", "--config", default="config.yaml")
    ap.add_argument("--window", type=float, default=evidence.WINDOW, help="seconds either side of the case")
    args = ap.parse_args()

    cfg = config.load(args.config)
    store = Store(cfg.get("db_path", "tapwatch.db"), migrate=False)
    r = store.get(args.case_id)
    if r is None:
        raise SystemExit(f"no case #{args.case_id}")
    assets = config.assets(cfg)

    print(f"# Case #{r['id']}: {r['title']}")
    print(f"detector={r['detector']} route={r['route']} ({r['reason']}) status={r['status']} "
          f"disposition={r['disposition']} hits={r['hits']} must_alert={bool(r['must_alert'])}")
    print(f"device: {assets.name(r['host'])} ({r['host']})   <- internal, never send outside")
    print(f"facts: {r['facts']}")
    print(f"indicators (untrusted): {r['indicators']}")
    print(f"jev: {r['verdict']}")

    dirs = (cfg.get("ui") or {}).get("zeek_dirs") or []
    if not evidence.expand_dirs(dirs):
        print("\n(no ui.zeek_dirs found; no evidence)")
        return
    found = evidence.lookup(dirs, r["host"], r["first_ts"], window=args.window, limit=5000)

    dns = found["dns"]["rows"]
    print(f"\n## DNS: {len(dns)} lookups within ±{args.window:.0f}s")
    print("top registrable domains:", Counter(registrable(x.get("query") or "") for x in dns).most_common(20))
    nx = sorted({x.get("query") for x in dns if x.get("rcode_name") == "NXDOMAIN"})
    print("NXDOMAIN:", nx[:30])
    answers: dict[str, set] = {}
    for x in dns:
        answers.setdefault(x.get("query") or "", set()).update(x.get("answers") or [])
    odd = sorted(q for q in answers if q and looks_random(q))
    print("random-looking names -> answers:")
    for q in odd[:40]:
        print(f"  {q} -> {sorted(answers[q])[:4]}")
    print("search patterns (IDs stripped):", sorted({pattern(q) for q in odd})[:20])

    ssl = found["ssl"]["rows"]
    print(f"\n## TLS: {len(ssl)} handshakes; server names:",
          Counter(x.get("server_name") for x in ssl if x.get("server_name")).most_common(20))

    conn = found["conn"]["rows"]
    peers = Counter((x.get("id.resp_h"), x.get("id.resp_p"), x.get("proto")) for x in conn
                    if x.get("id.orig_h") == r["host"])
    print(f"\n## Connections: {len(conn)} rows; top destinations (ip, port, proto):", peers.most_common(15))
    for kind in ("dns", "ssl", "conn"):
        if found[kind]["more"]:
            print(f"(note: {kind} hit the 5000-row cap)")
    print("\nfull rows are on the case page:", json.dumps(f"/case/{r['id']}"))


if __name__ == "__main__":
    main()
