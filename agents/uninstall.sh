#!/usr/bin/env bash
# Stop and remove osquery installed by install.sh (keeps nothing behind but logs).
set -euo pipefail
if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo"; fi

case "$(uname -s)" in
  Darwin)
    $SUDO launchctl bootout system /Library/LaunchDaemons/io.osquery.agent.plist 2>/dev/null || true
    $SUDO rm -f /Library/LaunchDaemons/io.osquery.agent.plist
    brew uninstall --cask osquery || true
    $SUDO rm -rf /var/osquery
    ;;
  Linux)
    if [ -d /run/systemd/system ]; then $SUDO systemctl disable --now osqueryd 2>/dev/null || true; fi
    if command -v apt-get >/dev/null; then
      $SUDO apt-get remove -y osquery
      $SUDO rm -f /etc/apt/sources.list.d/osquery.list /etc/apt/keyrings/osquery.gpg
    else
      $SUDO "$(command -v dnf || command -v yum)" remove -y osquery
      $SUDO rm -f /etc/yum.repos.d/osquery-s3-rpm.repo /etc/pki/rpm-gpg/RPM-GPG-KEY-osquery
    fi
    $SUDO rm -rf /etc/osquery /var/osquery
    ;;
esac
echo "osquery removed. Logs are left in /var/log/osquery."
