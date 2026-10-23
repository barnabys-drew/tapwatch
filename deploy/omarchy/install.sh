#!/usr/bin/env bash
# tapwatch on Omarchy (or any Arch install): this computer becomes the sensor. The Omarchy counterpart of
# install-windows.cmd. Run it from a checkout, as your normal account (it asks for sudo when it needs it):
#
#   git clone https://github.com/barnabys-drew/tapwatch ~/tapwatch && cd ~/tapwatch
#   deploy/omarchy/install.sh [--mirror enp0s31f6] [--import tapwatch-state.tar.gz] [--no-syslog] [--no-agent]
#
#   --mirror   the wired interface plugged into the switch's mirror port (asked if there is more than one)
#   --import   settings, cases and learned baselines from another tapwatch (deploy/export-state.sh made it)
#   --no-syslog / --no-agent   skip the router log listener / the osquery agent on this computer
#
# What it does: installs git, Python, Docker, dumpcap (wireshark-cli); adds you to the docker and wireshark
# groups; keeps your services running with nobody signed in (linger); turns sleep off and makes closing the lid
# do nothing, since a sleeping sensor watches nothing; takes the mirror interface away from the network manager
# so it stays up with no address; opens UDP 5514 to the LAN in ufw for the router's logs; then tapwatch itself
# (init or --import, the public lists, the services), the endpoint agent, and `tapwatch doctor`.
# Every step checks what is already done, so it can be run again (to update, or after the restart it asks for);
# --import only on the first run, before there is a config.yaml.
set -euo pipefail

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mnote:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }
# Questions need a terminal: with none (ssh without -t, a script), every answer is no, so nothing risky happens
# unasked. ask: default yes. ask_no: default no, for the ones that can cut this computer off or restart it.
ask() { local a; read -r -p "$1 [Y/n] " a </dev/tty 2>/dev/null || return 1; [[ ! "$a" =~ ^[Nn] ]]; }
ask_no() { local a; read -r -p "$1 [y/N] " a </dev/tty 2>/dev/null || return 1; [[ "$a" =~ ^[Yy] ]]; }

REPO=$(cd "$(dirname "$0")/../.." && pwd)
MIRROR="" IMPORT="" SYSLOG=yes AGENT=yes
while [ $# -gt 0 ]; do
  case "$1" in
    --mirror) MIRROR=${2:?}; shift 2 ;;
    --import) IMPORT=$(realpath "${2:?}"); shift 2 ;;
    --no-syslog) SYSLOG=no; shift ;;
    --no-agent) AGENT=no; shift ;;
    -h|--help) sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1 (--help lists them)" ;;
  esac
done

[ "$(id -u)" -ne 0 ] || die "run this as your normal account, not root: tapwatch runs as you, and it uses sudo itself"
command -v pacman >/dev/null || die "this installer is for Omarchy / Arch (pacman). Other Linux: README.md, 'Install'"
[ -f "$REPO/pyproject.toml" ] || die "run it from a tapwatch checkout (deploy/omarchy/install.sh)"
[ -z "$IMPORT" ] || [ -f "$IMPORT" ] || die "no such file: $IMPORT"
sudo -v || die "needs sudo"

# ---- packages and groups -----------------------------------------------------------------------------------------
say "Installing git, Python, Docker and dumpcap (pacman)"
# -Syu: Arch supports no partial upgrades, and a few weeks' old package lists point at files mirrors have dropped.
sudo pacman -Syu --needed --noconfirm git python docker wireshark-cli iproute2 >/dev/null
sudo systemctl enable --now docker.service >/dev/null
# Groups this session doesn't have yet (`id -nG` with no name: this process's, not the group file's). Added now,
# they apply only after a restart: with linger on, the user manager the services run under outlives signing out.
NEW_GROUPS=()
for g in docker wireshark; do
  if ! id -nG | tr ' ' '\n' | grep -qx "$g"; then
    id -nG "$USER" | tr ' ' '\n' | grep -qx "$g" || sudo usermod -aG "$g" "$USER"
    NEW_GROUPS+=("$g")
  fi
done
sudo loginctl enable-linger "$USER"

# ---- never sleep -------------------------------------------------------------------------------------------------
# Masking the sleep targets makes every suspend request fail, Omarchy's idle daemon (hypridle) included; the screen
# still locks. The logind drop-in stops the lid from asking at all (it applies after the next restart).
say "Turning sleep off (the screen still locks)"
sudo systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target >/dev/null 2>&1
sudo install -d /etc/systemd/logind.conf.d
printf '[Login]\nHandleLidSwitch=ignore\nHandleLidSwitchExternalPower=ignore\nHandleLidSwitchDocked=ignore\n' \
  | sudo tee /etc/systemd/logind.conf.d/50-tapwatch.conf >/dev/null

# ---- the mirror interface ----------------------------------------------------------------------------------------
if [ -z "$MIRROR" ]; then
  # Physical wired ports: a device behind them, and not wireless (no bridges, tunnels, Docker or modem links).
  wired=()
  for d in /sys/class/net/*; do
    [ -e "$d/device" ] && [ ! -e "$d/wireless" ] && [ ! -e "$d/phy80211" ] || continue
    [ "$(cat "$d/type" 2>/dev/null)" = 1 ] && wired+=("$(basename "$d")")
  done
  case ${#wired[@]} in
    0) die "no wired interface found. Plug in the cable to the mirror port (a USB Ethernet adapter is fine), then run this again" ;;
    1) MIRROR=${wired[0]}
       ask "Use $MIRROR for the mirror port?" || die "name it with --mirror <interface> (ip -br link lists them)" ;;
    *) echo "Wired interfaces: ${wired[*]}"
       read -r -p "Which one is plugged into the mirror port? " MIRROR </dev/tty
       printf '%s\n' "${wired[@]}" | grep -qx "$MIRROR" || die "not one of them: $MIRROR" ;;
  esac
fi
[ -e "/sys/class/net/$MIRROR" ] || die "no network interface named $MIRROR (ip -br link lists them)"
[[ "$MIRROR" =~ ^[A-Za-z0-9_.:-]+$ ]] || die "unexpected interface name: $MIRROR"
if ip -o route show default | grep -q " dev $MIRROR "; then
  warn "$MIRROR is this computer's way to the internet right now. Once it's the mirror port it gets no address,"
  warn "so connect Wi-Fi or a second cable first, or this computer goes offline."
  ask_no "Carry on anyway?" || exit 1
fi
say "Leaving $MIRROR up with no address (the mirror port only receives copies)"
if systemctl is-active --quiet NetworkManager; then
  sudo install -d /etc/NetworkManager/conf.d
  printf '[keyfile]\nunmanaged-devices=interface-name:%s\n' "$MIRROR" \
    | sudo tee /etc/NetworkManager/conf.d/50-tapwatch-mirror.conf >/dev/null
  sudo nmcli general reload conf >/dev/null 2>&1 || true
  sudo nmcli device set "$MIRROR" managed no >/dev/null 2>&1 || true
fi
if systemctl is-active --quiet systemd-networkd; then
  # Sorts before other .network files, so it is the one that matches this interface.
  printf '[Match]\nName=%s\n\n[Link]\nRequiredForOnline=no\nARP=no\n\n[Network]\nDHCP=no\nLinkLocalAddressing=no\nIPv6AcceptRA=no\n' \
    "$MIRROR" | sudo tee /etc/systemd/network/05-tapwatch-mirror.network >/dev/null
  sudo networkctl reload
  sudo networkctl reconfigure "$MIRROR"   # drops a DHCP client the old match had started
fi
sudo ip addr flush dev "$MIRROR" scope global 2>/dev/null || true
sudo ip link set "$MIRROR" up

# ---- firewall ----------------------------------------------------------------------------------------------------
if [ "$SYSLOG" = yes ] && command -v ufw >/dev/null && sudo ufw status | grep -q '^Status: active'; then
  dev=$(ip -o -4 route show default | awk '{for (i = 1; i < NF; i++) if ($i == "dev") {print $(i + 1); exit}}')
  lan=$([ -n "$dev" ] && ip -o -4 addr show dev "$dev" | awk '{print $4; exit}' || true)
  if [ -n "$lan" ]; then
    lan=$(python3 -c 'import ipaddress,sys; print(ipaddress.ip_interface(sys.argv[1]).network)' "$lan")
    say "Letting the router's logs in (ufw: UDP 5514 from $lan)"
    sudo ufw allow from "$lan" to any port 5514 proto udp comment 'tapwatch router syslog' >/dev/null
  else
    warn "no LAN address yet, so ufw wasn't opened for the router's logs; later: sudo ufw allow 5514/udp"
  fi
fi

# ---- tapwatch ----------------------------------------------------------------------------------------------------
cd "$REPO"
[ -x .venv/bin/python ] || python3 -m venv .venv
say "Installing tapwatch's Python package"
.venv/bin/pip install -q -e .
if [ -n "$IMPORT" ]; then
  [ ! -f config.yaml ] || die "this checkout already has a config.yaml; move it (and tapwatch.db) aside to import"
  say "Importing settings, cases and baselines from $(basename "$IMPORT")"
  # Only the files a move carries, at the paths their config.yaml names (tapwatch import-state, migrate.py); it lists
  # the settings that named the old computer.
  .venv/bin/tapwatch import-state "$IMPORT"
elif [ -f config.yaml ]; then
  say "Keeping the existing settings (config.yaml)"
else
  say "Settings: a few questions"
  .venv/bin/tapwatch init </dev/tty
fi
say "Downloading the public lists"
.venv/bin/tapwatch update-feeds || warn "some lists didn't download; tapwatch works without them. Later: tapwatch update-feeds"
say "Building Zeek (the first time takes a few minutes)"
sudo env ZEEK_IMAGE="${ZEEK_IMAGE:-tapwatch-zeek:9.0.0}" bash eval/zeek_image.sh >/dev/null
args=(service install --zeek-dir logs/zeek --capture-iface "$MIRROR")
[ "$SYSLOG" = yes ] && args+=(--syslog)
say "Installing tapwatch's services"
.venv/bin/tapwatch "${args[@]}"

if [ "$AGENT" = yes ]; then
  say "Installing the endpoint agent on this computer (osquery)"
  bash agents/install.sh --standalone
fi

if [ ${#NEW_GROUPS[@]} -gt 0 ]; then
  echo
  say "Almost done: you were added to ${NEW_GROUPS[*]}, which takes a restart to apply. After it, tapwatch starts"
  say "by itself; check it with:  cd $REPO && .venv/bin/tapwatch doctor --send"
  if ask_no "Restart now?"; then sudo systemctl reboot; fi
  exit 0
fi
systemctl --user restart 'tapwatch-*.service'
say "Checking the install"
.venv/bin/tapwatch doctor --send || true
