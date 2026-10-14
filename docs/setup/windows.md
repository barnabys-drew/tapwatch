# tapwatch on a Windows PC

Everything runs inside WSL except packet capture: Windows drops frames addressed to other
machines, so Npcap (on Windows) captures the mirror port and streams it into Zeek under WSL.

## Prerequisites (once)

1. **WSL 2 with systemd**, mirrored networking. In `%UserProfile%\.wslconfig`:
   ```ini
   [wsl2]
   networkingMode=mirrored
   ```
   and in the distro's `/etc/wsl.conf`:
   ```ini
   [boot]
   systemd=true
   ```
   Then `wsl --shutdown` from Windows and reopen.
2. **Docker** inside WSL (Docker Engine, or Docker Desktop with WSL integration).
3. **Wireshark with Npcap** on Windows (https://www.wireshark.org). Tick "Install Npcap". This
   provides `dumpcap.exe`.
4. A **second Ethernet port** on the PC, plugged into the switch's mirror port
   ([mirror-port.md](mirror-port.md)). Note its name in Windows (Settings → Network → Ethernet, e.g. "Ethernet 2").

## Install (inside WSL)

```bash
git clone https://github.com/barnabys-drew/tapwatch && cd tapwatch
python3 -m venv .venv && .venv/bin/pip install -e .
.venv/bin/tapwatch init                 # finds Npcap, asks for the interface name
.venv/bin/tapwatch update-feeds
.venv/bin/tapwatch service install --zeek-dir logs/zeek --capture-iface "Ethernet 2"   # add --syslog for router logs
loginctl enable-linger $USER            # keep the services running after you close the terminal
```

`service install` starts five systemd user services: capture, alerter, case desk, watchdog
(and syslog). Check them with `systemctl --user status 'tapwatch-*'`.

## Keep it awake (from Windows, once)

WSL stops when nothing is running in it, and an idle PC sleeps. In PowerShell (no admin):

```powershell
powershell -ExecutionPolicy Bypass -File \\wsl$\<distro>\home\<you>\tapwatch\deploy\windows\keep-alive.ps1 -Install
```

It registers a logon task that blocks idle sleep and keeps WSL up. If Windows refuses with
"access denied", run that one command in an elevated PowerShell. `-Uninstall` removes it.

**Survive Windows Update restarts.** A logon task only starts once someone signs in, so after an
overnight update restart nothing runs until morning. From an **elevated** PowerShell, once:

```powershell
powershell -ExecutionPolicy Bypass -File \\wsl$\<distro>\home\<you>\tapwatch\deploy\windows\keep-alive.ps1 -Install -AtStartup -Distro <distro>
```

This replaces the logon task with a boot task that runs whether or not anyone signs in. It uses
an S4U logon, so Windows stores no password. It copies the script to `%LOCALAPPDATA%\tapwatch`,
because `\\wsl$` isn't readable before WSL starts.

## Know when the whole PC is down

The watchdog emails you when capture or the alerter stops, but it runs in WSL, so it can't report
the PC itself being off. For that, create a check at a dead man's switch service such as
[healthchecks.io](https://healthchecks.io) (period 5 minutes, grace 10), and put its ping URL in
`.env`:

```
TAPWATCH_HEARTBEAT_URL=https://hc-ping.com/<your-check-uuid>
```

Then `systemctl --user restart tapwatch-watchdog`. Each healthy check pings it, and unhealthy
ones report to `<url>/fail`. When the pings stop, the service emails you. Treat the URL like a
password: anyone holding it can report "healthy".

## Reaching it from your phone or the router

The case desk listens on this PC only (127.0.0.1:8765). Mirrored WSL networking needs a Hyper-V
firewall rule before other devices can reach a port in WSL. That needs admin, so it's your call
whether to open it. For router syslog see [router-syslog.md](router-syslog.md). For the case
desk, a VPN like Tailscale on the PC and phone avoids opening it to the whole LAN.
