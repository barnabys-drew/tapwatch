# tapwatch on Omarchy (Arch Linux)

> **On hold.** This install exists and worked in tests, but it isn't the supported path right now. On Linux,
> run tapwatch with Docker Compose as in the [README](../../README.md); on a Windows PC, use
> [the Windows installer](office-unifi.md).

A computer running [Omarchy](https://omarchy.org), or plain Arch, as the sensor. This is simpler than the
Windows path: Linux captures the mirror port itself, so there is no Npcap and no WSL. dumpcap reads the mirror
interface and streams it into Zeek in Docker. The rest runs as the same systemd user services as on Windows,
so `tapwatch doctor` and every other guide apply unchanged.

An old laptop makes a good sensor: it has its own battery, so a short power cut doesn't stop the capture.

## What you need

- **Two network connections.** One wired port for the cable to the switch's mirror port, which receives copies
  of the traffic and gets no address. The other is how the computer itself reaches the network: Wi-Fi is fine.
  A laptop with no Ethernet port can use a USB 3 gigabit adapter for the mirror.
- **A mirror port on the switch**, set to copy the router's port: [mirror-port.md](mirror-port.md).
- **Optional: the router's logs** ([router-syslog.md](router-syslog.md)), sent to this computer's address. Give
  that address a DHCP reservation in the router, so another device can't end up with it.

## Install

Connect to Wi-Fi first, and plug the mirror cable in. Then, in a terminal, as your normal account:

```bash
git clone https://github.com/barnabys-drew/tapwatch ~/tapwatch && cd ~/tapwatch
deploy/omarchy/install.sh
```

It asks for your password (sudo), confirms which wired interface is the mirror, asks tapwatch's setup
questions (`tapwatch init`), and then:

| Step | Why |
|---|---|
| installs git, Python, Docker and dumpcap (`wireshark-cli`) with pacman | Zeek runs in Docker, so Arch's rolling updates can't break it |
| adds you to the `docker` and `wireshark` groups | the capture runs as you; the `wireshark` group lets dumpcap capture without root |
| turns on linger | your tapwatch services keep running with nobody signed in |
| masks the sleep targets, and sets the lid to do nothing | a sleeping sensor watches nothing. The screen still locks; Omarchy's idle daemon just can't suspend |
| tells NetworkManager or systemd-networkd to leave the mirror interface alone | it stays up with no address and never tries DHCP on a port that only receives copies |
| opens UDP 5514 to your LAN, if ufw is on | the router's logs (skip with `--no-syslog`) |
| `tapwatch update-feeds`, builds the Zeek image, `tapwatch service install` | the same services as the Windows install: alerter, case desk, watchdog, capture, syslog |
| installs the osquery agent from Arch's own package (skip with `--no-agent`) | host context and the endpoint rules for this computer |

If it added you to a group, it asks to restart (default no; answer y). Signing out isn't enough: your tapwatch
services keep running across sign-outs, so they only get the new groups at a restart. After the restart, tapwatch
starts by itself. Check it:

```bash
cd ~/tapwatch && .venv/bin/tapwatch doctor --send
```

On Linux, doctor also checks the mirror interface (link, no address), the `wireshark` group, and sleep.

Run `deploy/omarchy/install.sh` again at any time (without `--import`): every step checks what is already done.
To update tapwatch itself, `.venv/bin/tapwatch update` (it rolls back if the new version fails its checks);
`git pull` and running the installer again also works. The installer needs a terminal for its questions; over SSH
use `ssh -t`, or every question is answered no.

## Moving an existing install

To keep the cases, suppressions and learned baselines, so the new sensor doesn't start a new learning period:

1. On the old computer, from its tapwatch folder: `deploy/export-state.sh`. It writes `tapwatch-state.tar.gz`
   with `config.yaml`, `.env`, the assets file, your own IOC list and a consistent copy of the database. The
   import takes only those files from it. The alerter can keep
   running while it does. The file holds your alert addresses and keys, so copy it directly (scp, USB stick)
   and delete it afterwards.
2. On the new computer: `deploy/omarchy/install.sh --import tapwatch-state.tar.gz`.
3. The installer lists the settings that named the old computer, from `host_context.host`, `ui.host`, `ui.base_url`,
   `ui.zeek_dirs`, `feeds_dir`, `smtp` and `fleet.results_log`. Point them at this computer in `config.yaml`, then
   `systemctl --user restart 'tapwatch-*'`. Doctor warns while `host_context.host` isn't this computer, because
   cases about the old one would be explained with this one's programs.
4. Point the router's syslog at the new computer's address.
5. Stop the old sensor, or both alert on everything: `systemctl --user disable --now 'tapwatch-*'`.

The old computer's own agent keeps writing its local log. To keep it covered, enroll it in a Fleet server
([fleet.md](fleet.md)), and its results reach the new sensor through Fleet.

## Not covered here

- **Reaching the case desk from other devices.** It listens on 127.0.0.1 on this computer. To use it from a
  phone or another PC, serve it over Tailscale (`tailscale serve`) or set `ui.host` (which needs
  `TAPWATCH_UI_TOKEN`).
- **Installed-software checks for this computer** (R48): osquery has no table for Arch's packages, and the
  vulnerability feeds don't cover Arch, so this computer's own software isn't checked. Everything else is.
