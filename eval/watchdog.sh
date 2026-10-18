#!/usr/bin/env bash
# Checks that the whole-house capture and the live alerter are both working (and the router
# syslog listener, when its systemd unit is installed), and emails (via `tapwatch notify`) when
# that changes: once on failure, once on recovery.
#
# It can't report its own death, or the whole machine being off (a Windows Update restart, a
# power cut). For that, set TAPWATCH_HEARTBEAT_URL in .env to a dead man's switch such as a
# healthchecks.io check: every healthy round pings it, and the service emails you when pings
# stop. Unhealthy rounds report to <url>/fail (healthchecks.io's failure endpoint) instead.
#   eval/watchdog.sh <zeek-log-dir> [interval-seconds]      loop
#   eval/watchdog.sh <zeek-log-dir> --once                  print status and exit
set -uo pipefail
# TAPWATCH_HOME: where config.yaml, .env and tapwatch-run.pid live (systemd units set it).
cd "${TAPWATCH_HOME:-$(dirname "$0")/..}"
tw=${TAPWATCH_CMD:-.venv/bin/tapwatch}
dir=${1:?usage: watchdog.sh <zeek-log-dir> [interval|--once]}; interval=${2:-300}
stale=600   # conn.log untouched this long = capture stalled (a busy house writes every few seconds)
# The heartbeat URL is a secret (anyone holding it can fake "healthy"), so it lives in .env, not config.
hb=${TAPWATCH_HEARTBEAT_URL:-$(sed -n 's/^TAPWATCH_HEARTBEAT_URL=//p' .env 2>/dev/null | tr -d '"' | tail -1)}
case "$hb" in ""|https://*) ;; *) echo "TAPWATCH_HEARTBEAT_URL must be https; heartbeat off" >&2; hb="" ;; esac
# Watch the router syslog listener only where `service install --syslog` created its unit
# (`is-active` alone says "inactive" for a unit that was never installed, which isn't a failure).
# Probed once at startup: restart the watchdog after `service install --syslog`.
syslog_unit=no
systemctl --user list-unit-files tapwatch-syslog.service 2>/dev/null | grep -q '^tapwatch-syslog\.service' && syslog_unit=yes
# The capture: check the tapwatch-capture unit where `service install --capture-iface` made one (the Windows/WSL
# path, which runs the tapwatch-mirror container), or a container named in TAPWATCH_CAPTURE_CONTAINER (Docker
# compose: `<project>-zeek-1`). Neither: conn.log freshness below is the capture check (macOS, native Zeek).
capture_unit=no
systemctl --user list-unit-files tapwatch-capture.service 2>/dev/null | grep -q '^tapwatch-capture\.service' && capture_unit=yes
capture_container=${TAPWATCH_CAPTURE_CONTAINER:-}

heartbeat() {  # heartbeat <problems>: empty = healthy
  [ -n "$hb" ] || return 0
  if [ -z "$1" ]; then
    curl -fsS -m 10 --retry 2 -o /dev/null "$hb" || echo "heartbeat ping failed" >&2
  else
    curl -fsS -m 10 --retry 2 -o /dev/null --data-raw "$1" "${hb%/}/fail" || echo "heartbeat ping failed" >&2
  fi
}

check() {
  local problems=()
  if [ "$capture_unit" = yes ]; then
    systemctl --user is-active --quiet tapwatch-capture 2>/dev/null \
      || problems+=("capture (tapwatch-capture) is not running")
  elif [ -n "$capture_container" ]; then
    docker ps --filter "name=^${capture_container}\$" --filter status=running -q | grep -q . \
      || problems+=("capture container $capture_container is not running")
  fi
  if [ -f "$dir/conn.log" ]; then
    local age=$(( $(date +%s) - $(stat -c %Y "$dir/conn.log") ))
    [ "$age" -le "$stale" ] || problems+=("no new traffic logged for $((age / 60)) min")
  else
    problems+=("no conn.log in $dir")
  fi
  local pid; pid=$(cat tapwatch-run.pid 2>/dev/null)
  { [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; } || problems+=("tapwatch run (alerter) is not running")
  # The syslog listener is optional: only a unit that exists and isn't active is a problem.
  if [ "$syslog_unit" = yes ]; then
    systemctl --user is-active --quiet tapwatch-syslog 2>/dev/null \
      || problems+=("router syslog listener (tapwatch-syslog) is not running")
  fi
  printf '%s\n' "${problems[@]}"
}

if [ "$interval" = "--once" ]; then
  ok="OK: logs fresh, alerter running"; { [ "$capture_unit" = yes ] || [ -n "$capture_container" ]; } && ok="OK: capture running, logs fresh, alerter running"
  [ "$syslog_unit" = yes ] && ok="$ok, syslog listener running"
  out=$(check); [ -z "$out" ] && echo "$ok" || echo "$out"; exit 0
fi

last=ok
while true; do
  out=$(check)
  if [ -n "$out" ] && [ "$last" = ok ]; then
    $tw -c config.yaml notify "tapwatch: monitoring is DOWN" "$out" && last=down
  elif [ -z "$out" ] && [ "$last" = down ]; then
    back="capture and alerter are running again"; [ "$syslog_unit" = yes ] && back="capture, alerter and syslog listener are running again"
    $tw -c config.yaml notify "tapwatch: monitoring recovered" "$back" && last=ok
  fi
  heartbeat "$out"
  echo "$(date '+%F %T') ${out:-ok}" | tr '\n' ' '; echo
  sleep "$interval"
done
