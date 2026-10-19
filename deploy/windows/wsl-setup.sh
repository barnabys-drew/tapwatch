#!/usr/bin/env bash
# The Linux half of the Windows installer (install-windows.cmd -> deploy/windows/install.ps1).
# PowerShell calls one stage at a time through wsl.exe. Secrets and answers arrive in environment
# variables passed with WSLENV, never on a command line or on disk:
#   TW_PW       "user:password" for the new Linux account (stage root)
#   TW_ANSWERS  the JSON `tapwatch init --answers -` reads (stage app)
#   TW_IFACE    the Windows adapter name for the capture, e.g. "Ethernet 2" (stage app)
#   TW_SYSLOG   "yes" to also run the router syslog listener (stage app)
#
#   wsl-setup.sh user-of                as root: print the Linux user tapwatch runs as (uid 1000), if any
#   wsl-setup.sh root <user>            as root: account, systemd, packages, docker group (then: wsl --shutdown)
#   wsl-setup.sh linger <user>          as root: keep the user's services running with nobody signed in
#   wsl-setup.sh app <repo-url>         as the user: tapwatch, init, lists, services
#   wsl-setup.sh doctor                 as the user: the final check and a test alert
#   wsl-setup.sh ntfy-url               as the user: print the ntfy address (the installer shows it after its log closes)
# Every stage checks what is already done, so the installer can be run again.
set -euo pipefail

say() { printf '==> %s\n' "$*"; }
stage=${1:?stage}

case "$stage" in
user-of)
    getent passwd 1000 | cut -d: -f1
    ;;

root)
    user=${2:?user}
    [[ "$user" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || { echo "not a usable Linux user name: $user" >&2; exit 2; }
    if ! id "$user" >/dev/null 2>&1; then
        say "Creating the Linux account $user"
        useradd -m -s /bin/bash -G sudo "$user"
    fi
    if [ -n "${TW_PW:-}" ]; then
        printf '%s\n' "$TW_PW" | chpasswd
    fi
    # The default user and systemd (tapwatch runs as systemd user services). Rewritten whole: the
    # installer owns this file on a machine it set up.
    printf '[boot]\nsystemd=true\n\n[user]\ndefault=%s\n' "$user" > /etc/wsl.conf
    say "Installing git, Python and Docker (a few minutes)"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -q
    apt-get install -y -q git python3-venv docker.io
    usermod -aG docker "$user"   # takes effect after the installer's `wsl --shutdown`
    ;;

linger)
    loginctl enable-linger "${2:?user}"
    ;;

app)
    repo=${2:?repo url}
    cd ~
    # A non-interactive wsl.exe call has no login session; point systemctl --user at the user's manager,
    # which linger started.
    export XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}
    export DBUS_SESSION_BUS_ADDRESS=${DBUS_SESSION_BUS_ADDRESS:-unix:path=$XDG_RUNTIME_DIR/bus}
    if [ -d tapwatch/.git ]; then
        say "Updating tapwatch"
        git -C tapwatch pull -q --ff-only
    else
        say "Downloading tapwatch"
        git clone -q "$repo" tapwatch
    fi
    cd tapwatch
    [ -x .venv/bin/python ] || python3 -m venv .venv
    say "Installing tapwatch's Python package"
    .venv/bin/pip install -q -e .
    if [ -f config.yaml ]; then
        say "Keeping the existing settings (config.yaml); delete it and run the installer again to start over"
    else
        say "Writing the settings"
        # The ntfy address is a secret and this output goes to the install log; the installer shows it
        # once its log is closed.
        out=$(printf '%s' "${TW_ANSWERS:?answers}" | .venv/bin/tapwatch init --answers -) \
            || { echo "tapwatch init failed" >&2; exit 1; }
        printf '%s\n' "$out" | grep -v 'ntfy app to:' || true
    fi
    say "Downloading the public lists"
    .venv/bin/tapwatch update-feeds
    args=(service install --zeek-dir logs/zeek --capture-iface "${TW_IFACE:?capture adapter}")
    [ "${TW_SYSLOG:-}" = yes ] && args+=(--syslog)
    say "Starting tapwatch's services"
    .venv/bin/tapwatch "${args[@]}"
    ;;

ntfy-url)
    sed -n 's/^TAPWATCH_NTFY_URL=//p' ~/tapwatch/.env | tail -1
    ;;

doctor)
    export XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}
    export DBUS_SESSION_BUS_ADDRESS=${DBUS_SESSION_BUS_ADDRESS:-unix:path=$XDG_RUNTIME_DIR/bus}
    cd ~/tapwatch
    .venv/bin/tapwatch doctor --send || true   # its problems are reported, not an installer failure
    ;;

*)
    echo "unknown stage: $stage" >&2
    exit 2
    ;;
esac
