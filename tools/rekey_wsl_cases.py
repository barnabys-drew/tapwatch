"""One-off: give host cases filed under WSL's internal address the identity of the PC that raised them.

    python tools/rekey_wsl_cases.py tapwatch.db            # dry run: what would change
    python tools/rekey_wsl_cases.py tapwatch.db --apply    # stop the alerter first, back the database up

Before hostrules.WSL_INTERNAL was ignored, an agent could pick WSL's mirrored-mode address (10.255.255.254) as the
PC's host, and models.device_id keyed those cases on that bare address while the same PC's other host cases were
keyed on its DHCP name: one PC's precedent for the judge, and its suppressions, split in two. New cases no longer
get that address. This stamps the old ones with the device facts (device_mac, device_name) of the endpoint cases
raised within `--window` seconds on the PC's real address, and moves their judge examples to that device.

Every PC in mirrored mode shares that address, so the case's own agent decides when the case names it: an R48 case
carries `agent`, and then only that agent's other cases count, at any time. Otherwise the endpoint cases within
`--window` seconds count. Either way a case is changed only when every one of them names one and the same device;
none, or two devices (two PCs with agents, both in mirrored mode, around the same time), and it is left as it is:
a split stays a split rather than becoming a wrong merge. The address stays the case's host (its dedupe key is
history). The dry run lists every case with the device it would move to and why, to read before --apply.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from tapwatch.hostrules import NAMES, WSL_INTERNAL
from tapwatch.models import device_id

ENDPOINT = NAMES   # the host rules and R48: every case an endpoint agent raises
WINDOW = 3600


def plan(db: sqlite3.Connection, window: float = WINDOW) -> tuple[list[tuple], list[tuple]]:
    """Cases to change as (case id, the device facts to add, the device key, why), and cases left alone as
    (case id, why)."""
    marks = ",".join("?" * len(ENDPOINT))
    split = db.execute(f"SELECT id, first_ts, facts FROM cases WHERE host=? AND detector IN ({marks}) ORDER BY id",
                       (WSL_INTERNAL, *ENDPOINT)).fetchall()
    out, left = [], []
    for case_id, ts, facts in split:
        agent = json.loads(facts or "{}").get("agent")
        if json.loads(facts or "{}").get("device_mac"):
            continue   # already has an identity
        if agent:   # the case's own agent: its cases on the PC's real address, whenever they were
            near = db.execute(f"SELECT host, facts, first_ts FROM cases WHERE detector IN ({marks}) AND host != ?"
                              " AND json_extract(facts, '$.agent') = ?", (*ENDPOINT, WSL_INTERNAL, agent))
            how = f"same agent ({str(agent)[:8]})"
        else:
            near = db.execute(f"SELECT host, facts, first_ts FROM cases WHERE detector IN ({marks}) AND host != ?"
                              " AND first_ts BETWEEN ? AND ?", (*ENDPOINT, WSL_INTERNAL, ts - window, ts + window))
            how = f"endpoint cases within {window / 60:.0f} min"
        found: dict[str, tuple[float, dict]] = {}
        for host, f, t in near:
            f = json.loads(f or "{}")
            ident = {k: f[k] for k in ("device_mac", "device_name") if f.get(k)}
            if not ident:
                found.setdefault(host, (abs(t - ts), {}))   # a neighbour Zeek knew nothing about: not proof either way
                continue
            key = device_id(host, ident)
            if key not in found or abs(t - ts) < found[key][0]:
                found[key] = (abs(t - ts), ident)
        if len(found) == 1 and next(iter(found.values()))[1]:
            key, (_, ident) = next(iter(found.items()))
            out.append((case_id, ident, key, how))
        else:
            left.append((case_id, f"{how}: {'none' if not found else f'{len(found)} devices'}"))
    return out, left


def apply(db: sqlite3.Connection, changes: list[tuple[int, dict, str]]) -> None:
    examples = db.execute("SELECT 1 FROM sqlite_master WHERE name='judge_examples'").fetchone()  # none before #200
    with db:
        for case_id, ident, key, _ in changes:
            facts = json.loads(db.execute("SELECT facts FROM cases WHERE id=?", (case_id,)).fetchone()[0] or "{}")
            db.execute("UPDATE cases SET facts=? WHERE id=?", (json.dumps({**facts, **ident}), case_id))
            if examples:
                db.execute("UPDATE judge_examples SET device=?, features=json_set(features, '$.device', ?)"
                           " WHERE case_id=?", (key, key, case_id))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("db")
    ap.add_argument("--apply", action="store_true", help="write the changes (default: only report them)")
    ap.add_argument("--window", type=float, default=WINDOW, help="seconds around a case to look for its PC")
    args = ap.parse_args(argv)
    db = sqlite3.connect(args.db, timeout=10)
    changes, left = plan(db, args.window)
    for case_id, _, key, how in changes:
        print(f"#{case_id} -> {key} ({how})")
    for case_id, why in left:
        print(f"#{case_id} left on the address ({why})")
    devices = len({key for _, _, key, _ in changes})
    print(f"{len(changes)} case(s) to move to {devices} device(s); {len(left)} left on the address")
    if args.apply and changes:
        apply(db, changes)
        print("applied")
    return 0


if __name__ == "__main__":
    sys.exit(main())
