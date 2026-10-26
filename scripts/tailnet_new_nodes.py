#!/usr/bin/env python3
"""Report tailnet nodes that were not in the last snapshot.

Reads `tailscale status --json`, keys every node (self and peers) by its
node public key, and compares against a state file. The first run records
a baseline and reports nothing. Later runs print one line per new node and
exit 1 when any were found, so a timer can alert on the exit code.

A node key changes when a device re-authenticates, so a reinstalled
machine shows up as new. That is the behaviour we want: it is a new key
that someone has to account for.

Usage:
    tailnet_new_nodes.py --state ~/.local/state/tailnet-nodes.json
    tailnet_new_nodes.py --state FILE --status-json status.json   # offline
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone


def load_status(path, tailscale_bin):
    if path:
        with open(path) as f:
            return json.load(f)
    out = subprocess.run(
        [tailscale_bin, "status", "--json"],
        check=True,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )
    return json.loads(out.stdout)


def nodes_of(status):
    """Map node public key -> summary of every node in the status output."""
    nodes = {}
    entries = [status.get("Self") or {}] + list((status.get("Peer") or {}).values())
    for n in entries:
        key = n.get("PublicKey")
        if not key:
            continue
        nodes[key] = {
            "host": n.get("HostName", ""),
            "dns": n.get("DNSName", ""),
            "os": n.get("OS", ""),
            "ips": n.get("TailscaleIPs", []),
            "tags": n.get("Tags") or [],
            "user": n.get("UserID"),
            "key_expiry": n.get("KeyExpiry"),
        }
    return nodes


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--state", required=True, help="path to the known-nodes JSON file")
    ap.add_argument("--tailscale", default="tailscale", help="tailscale binary")
    ap.add_argument("--status-json", help="read status from this file instead of running tailscale")
    args = ap.parse_args()

    current = nodes_of(load_status(args.status_json, args.tailscale))
    state_path = os.path.expanduser(args.state)

    if not os.path.exists(state_path):
        save(state_path, current)
        print(f"baseline recorded: {len(current)} nodes in {state_path}")
        return 0

    with open(state_path) as f:
        known = json.load(f)["nodes"]

    new = {k: v for k, v in current.items() if k not in known}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for key, n in new.items():
        ips = ",".join(n["ips"])
        tags = ",".join(n["tags"]) or "-"
        print(f"{now} NEW-NODE host={n['host']} dns={n['dns']} os={n['os']} ips={ips} tags={tags} key={key}")

    if new:
        # Keep the old nodes so a removed device does not re-alert later.
        merged = dict(known)
        merged.update(current)
        save(state_path, merged)
        return 1

    save(state_path, current)
    return 0


def save(path, nodes):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"nodes": nodes}, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


if __name__ == "__main__":
    sys.exit(main())
