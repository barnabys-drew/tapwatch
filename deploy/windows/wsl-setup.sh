#!/usr/bin/env bash
# The Linux half of the Windows installer (install-windows.cmd -> deploy/windows/install.ps1).
# PowerShell calls one stage at a time through wsl.exe. Secrets and answers arrive in environment
# variables passed with WSLENV, never on a command line or on disk:
#   TW_PW       "user:password" for the new Linux account (stage root)
#   TW_ANSWERS  the JSON `tapwatch init --answers -` reads (stage app)
#   TW_IFACE    the Windows adapter name for the capture, e.g. "Ethernet 2" (stage app)
#   TW_SYSLOG   "yes" to also run the router syslog listener (stage app)
#   TW_IMPORT   a tapwatch-state.tar.gz from deploy/export-state.sh, as a Linux path: take over that install's
#               settings, cases and baselines instead of writing new settings (stage app)
#
#   wsl-setup.sh root <user>            as root: account, systemd, packages, docker group (then: wsl --shutdown)
#   wsl-setup.sh linger <user>          as root: keep the user's services running with nobody signed in
#   wsl-setup.sh app <repo-url> [branch] as the user: tapwatch (that branch, default main), init, lists, services
#   wsl-setup.sh doctor [send|nosend]   as the user: the final check, with a test alert unless nosend
#   wsl-setup.sh test-alert             as the user: send a test alert (after subscribing in the ntfy app)
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
    branch=${3:-main}
    git check-ref-format --branch "$branch" >/dev/null 2>&1 && [[ "$branch" != -* ]] \
        || { echo "not a branch name: $branch (rename the folder to tapwatch-main)" >&2; exit 2; }
    cd ~
    # A non-interactive wsl.exe call has no login session; point systemctl --user at the user's manager,
    # which linger started.
    export XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}
    export DBUS_SESSION_BUS_ADDRESS=${DBUS_SESSION_BUS_ADDRESS:-unix:path=$XDG_RUNTIME_DIR/bus}
    # The same branch as the ZIP the installer came from: a ZIP of one branch with the code of another fails
    # (a dev ZIP's installer passed `init --answers` to main's tapwatch, which didn't have it yet).
    if [ -d tapwatch/.git ]; then
        say "Updating tapwatch ($branch)"
        git -C tapwatch fetch -q origin "$branch"
        if git -C tapwatch rev-parse --verify -q "refs/heads/$branch" >/dev/null; then
            git -C tapwatch checkout -q "$branch"
        else
            git -C tapwatch checkout -q -b "$branch" "origin/$branch"
        fi
        git -C tapwatch merge -q --ff-only "origin/$branch"
    else
        say "Downloading tapwatch ($branch)"
        git clone -q -b "$branch" "$repo" tapwatch
    fi
    cd tapwatch
    [ -x .venv/bin/python ] || python3 -m venv .venv
    say "Installing tapwatch's Python package"
    .venv/bin/pip install -q -e .
    if [ -f config.yaml ]; then
        say "Keeping the existing settings (config.yaml); delete it and run the installer again to start over"
    elif [ -n "${TW_IMPORT:-}" ]; then
        say "Taking over the old computer's tapwatch: settings, cases and learned baselines"
        .venv/bin/tapwatch import-state "$TW_IMPORT"
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

test-alert)
    cd ~/tapwatch
    .venv/bin/tapwatch test-alert 2>&1 || true
    ;;

ntfy-url)
    sed -n 's/^TAPWATCH_NTFY_URL=//p' ~/tapwatch/.env | tail -1
    ;;

doctor)
    export XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}
    export DBUS_SESSION_BUS_ADDRESS=${DBUS_SESSION_BUS_ADDRESS:-unix:path=$XDG_RUNTIME_DIR/bus}
    cd ~/tapwatch
    flags=(); [ "${2:-send}" = send ] && flags=(--send)
    .venv/bin/tapwatch doctor "${flags[@]}" || true   # its problems are reported, not an installer failure
    ;;

*)
    echo "unknown stage: $stage" >&2
    exit 2
    ;;
esac
