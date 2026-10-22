#!/usr/bin/env bash
# Build the one file a computer needs to join Fleet: a ZIP of agents/ with an agent.env naming this Fleet server and
# its enroll secret. On the other computer: unzip, then double-click install.cmd (Windows; osquery and Sysmon) or run
# ./install.sh (Linux, macOS). It enrolls within a minute and its results reach tapwatch through Fleet.
#
#   deploy/fleet/agent-bundle.sh [out.zip (default: ~/tapwatch-agent.zip)]
#
# Reads FLEET_URL (the address agents use, e.g. https://<this computer>.<tailnet>.ts.net:10004) and FLEET_API_TOKEN
# from deploy/fleet/.env, and asks Fleet for the current enroll secret. The ZIP holds that secret: anyone with it can
# enroll a computer (not read anything), so it is made readable by you only. Keep it out of the repo and shared
# folders, and rotate the secret in Fleet if it leaks.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
out=$(realpath -m "${1:-$HOME/tapwatch-agent.zip}")
# Only the two values this needs, read rather than sourced: the file also holds the database password and the
# server key, which no child process here should see.
env_value() { sed -n "s/^$1=//p" "$HERE/.env" | tail -1; }
FLEET_URL=$(env_value FLEET_URL)
token=$(env_value FLEET_API_TOKEN)
[ -n "$FLEET_URL" ] || { echo "set FLEET_URL in deploy/fleet/.env: the https address the agents reach Fleet at" >&2; exit 1; }
[ -n "$token" ] || { echo "set FLEET_API_TOKEN in deploy/fleet/.env (docs/setup/fleet.md)" >&2; exit 1; }
api=${FLEET_API_URL:-http://127.0.0.1:8412}
# The token goes to curl on stdin, not its command line, where every account on this computer could read it (ps).
secret=$(printf 'header = "Authorization: Bearer %s"\n' "$token" \
  | curl -fsS --config - "$api/api/v1/fleet/spec/enroll_secret" \
  | python3 -c 'import json, sys; s = json.load(sys.stdin)["spec"]["secrets"]; print(s[0]["secret"] if s else "")')
unset token
[ -n "$secret" ] || { echo "Fleet has no enroll secret yet: add one under Hosts > Manage enroll secrets" >&2; exit 1; }
# agent.env is read as plain KEY=value by both installers (install.sh sources it; install.ps1 doesn't unquote), so
# only values that need no quoting. Fleet's generated secrets are letters, digits and +/=.
for v in "$FLEET_URL" "$secret"; do
  [[ "$v" =~ ^[A-Za-z0-9._:/+=-]+$ ]] || { echo "the Fleet URL or enroll secret has characters agent.env can't carry" >&2; exit 1; }
done
FLEET_URL=$FLEET_URL ENROLL_SECRET=$secret python3 - "$REPO/agents" "$out" <<'PY'
import os
import sys
import zipfile
from pathlib import Path

src, out = Path(sys.argv[1]), Path(sys.argv[2])
skip = {"agent.env", ".gitignore"}
old = os.umask(0o077)
try:
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(src.rglob("*")):
            rel = p.relative_to(src)
            if p.is_file() and rel.name not in skip and not rel.name.endswith(".pem") and "__pycache__" not in rel.parts:
                z.write(p, Path("tapwatch-agent") / rel)
        z.writestr("tapwatch-agent/agent.env",
                   f"FLEET_URL={os.environ['FLEET_URL']}\nENROLL_SECRET={os.environ['ENROLL_SECRET']}\nFLEET_CERT=\n")
finally:
    os.umask(old)
out.chmod(0o600)   # an older ZIP being overwritten keeps its mode otherwise
PY
echo "wrote $out: unzip it on the other computer, then double-click tapwatch-agent\\install.cmd (Windows)"
echo "or run tapwatch-agent/install.sh (Linux, macOS)"
