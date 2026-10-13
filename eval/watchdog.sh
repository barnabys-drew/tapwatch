#!/usr/bin/env bash
# Checks that the whole-house capture and the live alerter are both working, and
# emails (via `tapwatch notify`) when that changes: once on failure, once on recovery.
#   eval/watchdog.sh <zeek-log-dir> [interval-seconds]      loop
#   eval/watchdog.sh <zeek-log-dir> --once                  print status and exit
set -uo pipefail
# TAPWATCH_HOME: where config.yaml, .env and tapwatch-run.pid live (systemd units set it).
cd "${TAPWATCH_HOME:-$(dirname "$0")/..}"
tw=${TAPWATCH_CMD:-.venv/bin/tapwatch}
dir=${1:?usage: watchdog.sh <zeek-log-dir> [interval|--once]}; interval=${2:-300}
stale=600   # conn.log untouched this long = capture stalled (a busy house writes every few seconds)

check() {
  local problems=()
  docker ps --filter name=^tapwatch-mirror$ --filter status=running -q | grep -q . \
    || problems+=("capture container tapwatch-mirror is not running")
  if [ -f "$dir/conn.log" ]; then
    local age=$(( $(date +%s) - $(stat -c %Y "$dir/conn.log") ))
    [ "$age" -le "$stale" ] || problems+=("no new traffic logged for $((age / 60)) min")
  else
    problems+=("no conn.log in $dir")
  fi
  local pid; pid=$(cat tapwatch-run.pid 2>/dev/null)
  { [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; } || problems+=("tapwatch run (alerter) is not running")
  printf '%s\n' "${problems[@]}"
}

if [ "$interval" = "--once" ]; then
  out=$(check); [ -z "$out" ] && echo "OK: capture running, logs fresh, alerter running" || echo "$out"; exit 0
fi

last=ok
while true; do
  out=$(check)
  if [ -n "$out" ] && [ "$last" = ok ]; then
    $tw -c config.yaml notify "tapwatch: monitoring is DOWN" "$out" && last=down
  elif [ -z "$out" ] && [ "$last" = down ]; then
    $tw -c config.yaml notify "tapwatch: monitoring recovered" "capture and alerter are running again" && last=ok
  fi
  echo "$(date '+%F %T') ${out:-ok}" | tr '\n' ' '; echo
  sleep "$interval"
done
