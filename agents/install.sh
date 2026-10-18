#!/usr/bin/env bash
# Install osquery and start it as a service.
#   macOS: Homebrew (brew install --cask osquery)
#   Linux: osquery's official apt or dnf/yum repository
#
#   ./install.sh                          standalone: scheduled queries log to local files
#   ./install.sh --fleet-url https://fleet.lan:8080 --enroll-secret XXXX [--fleet-cert fleet.pem]
#
# Fleet settings can also live in agent.env next to this script (see agent.env.example),
# so every machine is just: clone, then ./install.sh
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
FLEET_URL="" ENROLL_SECRET="" FLEET_CERT=""
[ -f "$HERE/agent.env" ] && . "$HERE/agent.env"

usage() { sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
while [ $# -gt 0 ]; do
  case "$1" in
    --fleet-url) FLEET_URL=$2; shift 2 ;;
    --enroll-secret) ENROLL_SECRET=$2; shift 2 ;;
    --fleet-cert) FLEET_CERT=$2; shift 2 ;;
    --standalone) FLEET_URL=""; shift ;;
    -h|--help) usage 0 ;;
    *) echo "unknown option: $1" >&2; usage 1 ;;
  esac
done

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

if [ -n "$FLEET_URL" ]; then
  [ -n "$ENROLL_SECRET" ] || die "--fleet-url needs --enroll-secret (or ENROLL_SECRET in agent.env)"
  FLEET_HOST=${FLEET_URL#https://}; FLEET_HOST=${FLEET_HOST#http://}; FLEET_HOST=${FLEET_HOST%%/*}
  if [ -n "$FLEET_CERT" ]; then
    case "$FLEET_CERT" in /*) ;; *) FLEET_CERT="$HERE/$FLEET_CERT" ;; esac
    [ -f "$FLEET_CERT" ] || die "Fleet certificate not found: $FLEET_CERT"
  fi
  MODE=fleet
else
  MODE=standalone
fi

# root helper: run as-is when already root, otherwise through sudo
if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo"; command -v sudo >/dev/null || die "needs root or sudo"; fi

# write_flags <dir> <db path> <log path>: render the flagfile for the chosen mode into <dir>
write_flags() {
  local dir=$1 db=$2 logs=$3 tmp
  tmp=$(mktemp)
  if [ "$MODE" = fleet ]; then
    printf '%s\n' "$ENROLL_SECRET" | $SUDO tee "$dir/enroll_secret" >/dev/null
    $SUDO chmod 600 "$dir/enroll_secret"
    local cert_flag=""
    if [ -n "$FLEET_CERT" ]; then
      $SUDO cp "$FLEET_CERT" "$dir/fleet.pem"
      cert_flag="--tls_server_certs=$dir/fleet.pem"
    fi
    sed -e "s|@FLEET_HOST@|$FLEET_HOST|" -e "s|@SECRET_PATH@|$dir/enroll_secret|" \
        -e "s|@CERT_FLAG@|$cert_flag|" -e "s|@DB_PATH@|$db|" "$HERE/config/fleet.flags" > "$tmp"
  else
    sed -e "s|@CONF_PATH@|$dir/osquery.conf|" -e "s|@LOG_PATH@|$logs|" -e "s|@DB_PATH@|$db|" \
        "$HERE/config/standalone.flags" > "$tmp"
  fi
  # Linux: turn on the eBPF publisher for bpf_connections (every connection, with its process)
  if [ "$(uname -s)" = Linux ]; then cat "$HERE/config/linux.flags" >> "$tmp"; fi
  $SUDO install -m 644 "$HERE/config/osquery.conf" "$dir/osquery.conf"
  $SUDO install -m 644 "$tmp" "$dir/osquery.flags"
  rm -f "$tmp"
  $SUDO mkdir -p "$logs" "$(dirname "$db")"
  # Readable by the installing user (tapwatch runs as them), not every account: group-owned, setgid so new and
  # rotated files keep the group, and the files already there tightened to match --logger_mode=0640.
  local reader_group
  reader_group=$(id -gn "${SUDO_USER:-$(id -un)}")
  if [ "$(id -u)" -eq 0 ] && [ -z "${SUDO_USER:-}" ]; then
    echo "note: run as root without sudo, so the results log is readable by group '$reader_group' only;" \
         "run it with sudo from the account tapwatch runs as, or chgrp $logs to that account's group" >&2
  fi
  $SUDO chgrp "$reader_group" "$logs" && $SUDO chmod 2750 "$logs"
  $SUDO find "$logs" -maxdepth 1 -type f -exec chgrp "$reader_group" {} + -exec chmod 640 {} + 2>/dev/null || true
}

install_macos() {
  local brew
  brew=$(command -v brew || true)
  [ -z "$brew" ] && [ -x /opt/homebrew/bin/brew ] && brew=/opt/homebrew/bin/brew
  [ -z "$brew" ] && [ -x /usr/local/bin/brew ] && brew=/usr/local/bin/brew
  [ -n "$brew" ] || die "Homebrew isn't installed. Install it from https://brew.sh, then run this again."
  [ "$(id -u)" -ne 0 ] || die "on macOS run this as your normal user (Homebrew refuses root); it asks for sudo when needed"

  if "$brew" list --cask osquery >/dev/null 2>&1; then
    say "osquery already installed; upgrading if needed"
    "$brew" upgrade --cask osquery || true
  else
    say "Installing osquery with Homebrew (it asks for your password for the system package)"
    "$brew" install --cask osquery
  fi

  local osqueryd=/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd
  [ -x "$osqueryd" ] || die "osqueryd not found at $osqueryd after install"
  local dir=/var/osquery
  $SUDO mkdir -p "$dir"
  write_flags "$dir" "$dir/osquery.db" /var/log/osquery

  say "Starting osqueryd (launchd: io.osquery.agent)"
  local plist=/Library/LaunchDaemons/io.osquery.agent.plist tmp
  tmp=$(mktemp)
  cat > "$tmp" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>io.osquery.agent</string>
  <key>ProgramArguments</key>
  <array><string>$osqueryd</string><string>--flagfile=$dir/osquery.flags</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>60</integer>
  <key>StandardErrorPath</key><string>/var/log/osquery/osqueryd.stderr</string>
</dict>
</plist>
EOF
  $SUDO launchctl bootout system "$plist" 2>/dev/null || true
  $SUDO install -m 644 -o root -g wheel "$tmp" "$plist"
  rm -f "$tmp"
  $SUDO launchctl bootstrap system "$plist"
  OSQUERY_BIN=$osqueryd
  echo
  warn "For full results, give osquery Full Disk Access: System Settings > Privacy & Security >"
  warn "Full Disk Access > + > /opt/osquery/lib/osquery.app (then: sudo launchctl kickstart -k system/io.osquery.agent)"
}

install_linux() {
  if command -v apt-get >/dev/null; then
    say "Adding osquery's apt repository"
    $SUDO apt-get update -qq
    $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl gnupg ca-certificates >/dev/null
    $SUDO mkdir -p /etc/apt/keyrings
    curl -fsSL https://pkg.osquery.io/deb/pubkey.gpg | $SUDO gpg --dearmor --yes -o /etc/apt/keyrings/osquery.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/osquery.gpg] https://pkg.osquery.io/deb deb main" \
      | $SUDO tee /etc/apt/sources.list.d/osquery.list >/dev/null
    $SUDO apt-get update -qq
    say "Installing osquery"
    $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq osquery >/dev/null
  elif command -v dnf >/dev/null || command -v yum >/dev/null; then
    local pm; pm=$(command -v dnf || command -v yum)
    say "Adding osquery's rpm repository"
    $SUDO mkdir -p /etc/pki/rpm-gpg
    curl -fsSL https://pkg.osquery.io/rpm/GPG | $SUDO tee /etc/pki/rpm-gpg/RPM-GPG-KEY-osquery >/dev/null
    curl -fsSL https://pkg.osquery.io/rpm/osquery-s3-rpm.repo | $SUDO tee /etc/yum.repos.d/osquery-s3-rpm.repo >/dev/null
    say "Installing osquery"
    $SUDO "$pm" install -y -q osquery
  else
    die "no apt-get, dnf or yum found; install osquery from https://osquery.io/downloads by hand"
  fi

  local dir=/etc/osquery
  $SUDO mkdir -p "$dir"
  write_flags "$dir" /var/osquery/osquery.db /var/log/osquery
  OSQUERY_BIN=$(command -v osqueryd || echo /opt/osquery/bin/osqueryd)

  if [ -d /run/systemd/system ]; then
    say "Starting osqueryd (systemd)"
    $SUDO systemctl enable osqueryd >/dev/null 2>&1
    $SUDO systemctl restart osqueryd
  else
    warn "systemd isn't running here, so osqueryd wasn't started. Start it with:"
    warn "  sudo osqueryd --flagfile=$dir/osquery.flags --daemonize"
  fi
}

say "Mode: $MODE${FLEET_HOST:+ ($FLEET_HOST)}"
case "$(uname -s)" in
  Darwin) install_macos ;;
  Linux) install_linux ;;
  *) die "unsupported OS $(uname -s); on Windows run install.cmd" ;;
esac

echo
say "Done. osquery $("$OSQUERY_BIN" --version 2>/dev/null | awk '{print $NF}')"
if [ "$MODE" = fleet ]; then
  echo "    The host should appear in Fleet (Hosts) within a minute."
else
  echo "    Scheduled results: /var/log/osquery/osqueryd.results.log"
  echo "    Ask it anything:   osqueryi \"SELECT name, port FROM listening_ports JOIN processes USING (pid);\""
fi
