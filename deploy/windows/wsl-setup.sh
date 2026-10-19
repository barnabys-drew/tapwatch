#!/usr/bin/env bash
# The Linux half of the Windows installer (install-windows.cmd -> deploy/windows/install.ps1).
# PowerShell calls one stage at a time through wsl.exe. Secrets and answers arrive in environment
# variables passed with WSLENV, never on a command line or on disk:
#   TW_PW       "user:password" for the new Linux account (stage root)
#   TW_ANSWERS  the JSON `tapwatch init --answers -` reads (stage app)
#   TW_IFACE    the Windows adapter name for the capture, e.g. "Ethernet 2" (stage app)
#   TW_SYSLOG   "yes" to also run the router syslog listener (stage app)
#
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
    # systemd (tapwatch runs as systemd user services) and, unless someone already chose one, this user
    # as the default when Ubuntu opens. Added to an existing file, never rewritten: it may be the owner's.
    touch /etc/wsl.conf
    if ! grep -qE '^\s*systemd\s*=\s*true' /etc/wsl.conf; then
        if grep -qE '^\s*systemd\s*=' /etc/wsl.conf; then sed -i -E 's/^\s*systemd\s*=.*/systemd=true/' /etc/wsl.conf
        elif grep -q '^\[boot\]' /etc/wsl.conf; then sed -i '/^\[boot\]/a systemd=true' /etc/wsl.conf
        else printf '\n[boot]\nsystemd=true\n' >> /etc/wsl.conf; fi
    fi
    grep -q '^\[user\]' /etc/wsl.conf || printf '\n[user]\ndefault=%s\n' "$user" >> /etc/wsl.conf
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
    # One list host being down shouldn't stop the install: tapwatch runs without any of them (noisier),
    # and doctor names the missing ones.
    .venv/bin/tapwatch update-feeds || say "Some lists didn't download; tapwatch works without them. Later: tapwatch update-feeds"
    args=(service install --zeek-dir logs/zeek --capture-iface "${TW_IFACE:?capture adapter}")
    [ "${TW_SYSLOG:-}" = yes ] && args+=(--syslog)
    say "Starting tapwatch's services"
    .venv/bin/tapwatch "${args[@]}"
    # `enable --now` leaves already-running units alone, so on a re-run (an update) they'd keep the old code.
    systemctl --user restart 'tapwatch-*.service'
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
