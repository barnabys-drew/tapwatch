# tapwatch on a Windows PC

Everything runs inside WSL except packet capture: Windows drops frames addressed to other
machines, so Npcap (on Windows) captures the mirror port and streams it into Zeek under WSL.

## Prerequisites (once)

Checked on a clean Windows 11 install (2026-10-18). Commands marked **admin** need PowerShell opened with
"Run as administrator"; without it Windows answers "error 740".

1. **WSL with Ubuntu.** In an **admin** PowerShell:
   ```powershell
   dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
   dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
   Restart-Computer
   ```
   After the restart, in a normal PowerShell: `wsl --install -d Ubuntu`, and pick a Linux user name and
   password when it asks. (`wsl --install` alone can stop with error `0x80370114`, "a required feature is not
   installed", until those two features are on and the PC has restarted.)
2. **Mirrored networking and systemd.** In a normal PowerShell:
   ```powershell
   Set-Content "$env:USERPROFILE\.wslconfig" "[wsl2]`nnetworkingMode=mirrored"
   ```
   In Ubuntu, check `cat /etc/wsl.conf`. Current Ubuntu images already contain `systemd=true`; if yours
   does not:
   ```bash
   printf '[boot]\nsystemd=true\n' | sudo tee -a /etc/wsl.conf
   ```
   Then `wsl --shutdown` from Windows and reopen Ubuntu. `systemctl is-system-running` should say `running`
   or `degraded`, and `ip -4 addr` should show the same address Windows has (mirrored), not a 172.x one.
   Inside a virtual machine (Hyper-V with nested virtualization, measured with WSL 3.0.3) WSL stays in NAT
   mode whatever `.wslconfig` says. Capture still works, since Npcap runs on Windows; only reaching the case
   desk from other devices needs mirrored mode.
3. **Python, git and Docker inside Ubuntu:**
   ```bash
   sudo apt update && sudo apt install -y git python3-venv docker.io
   sudo usermod -aG docker $USER
   ```
   Then `wsl --shutdown` from Windows and reopen Ubuntu: closing the window is not enough for the new group
   to apply, and until it does `docker` needs sudo and capture fails with "Broken pipe". `docker run --rm
   hello-world` should then work without sudo. `docker.io` is Ubuntu's own package; Docker Desktop with WSL
   integration works too.
4. **Wireshark and Npcap** on Windows. Wireshark provides `dumpcap.exe`:
   `winget install -e --id WiresharkFoundation.Wireshark --interactive`. Its installer offers Npcap, but
   on a clean machine it may not install it, and winget has no Npcap package. Download the installer from
   https://npcap.com and check its signature before running it:
   ```powershell
   Get-AuthenticodeSignature "$env:USERPROFILE\Downloads\npcap-*.exe" | Select-Object Status, @{n="Signer";e={$_.SignerCertificate.Subject}}
   ```
   It should say `Valid` with a signer containing "Nmap Software LLC". After installing,
   `Get-Service npcap` should say `Running`.
5. A **second Ethernet port** on the PC, plugged into the switch's mirror port
   ([mirror-port.md](mirror-port.md)). Note its name in Windows (Settings → Network → Ethernet, e.g. "Ethernet 2").
   To try tapwatch first on a PC with one network port (or in a virtual machine), give `--capture-iface` that
   port's name instead: tapwatch then sees only this PC's own traffic, which is enough to check the install
   end to end, not to watch the house.

## Install (inside WSL)

```bash
git clone https://github.com/barnabys-drew/tapwatch && cd tapwatch
python3 -m venv .venv && .venv/bin/pip install -e .
.venv/bin/tapwatch init                 # finds Npcap, asks for the interface name
.venv/bin/tapwatch update-feeds
.venv/bin/tapwatch service install --zeek-dir logs/zeek --capture-iface "Ethernet 2"   # add --syslog for router logs
loginctl enable-linger $USER            # keep the services running after you close the terminal
```

`init` asks where alerts should go (ntfy, Discord, email). To add or change a channel later, put it in
`.env` (for example `TAPWATCH_DISCORD_URL=https://discord.com/api/webhooks/…`), then run
`.venv/bin/tapwatch test-alert` and `systemctl --user restart tapwatch-alerter`.

**Testing in a virtual machine:** Hyper-V's "Type clipboard text" sends keystrokes, and it can drop
characters such as `$` and quotes, so check a typed command before pressing Enter, or type
`$USER` as your user name.

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
whether to open it. For router syslog see [router-syslog.md](router-syslog.md).

**The case desk over Tailscale (recommended).** With Tailscale on the PC and your phone, the desk
stays on 127.0.0.1 and Tailscale does the sign-in, so there's no token to type. From Windows:

```powershell
tailscale serve --bg --https=10000 http://127.0.0.1:8765
```

Then in `config.yaml`:

```yaml
ui:
  host: 127.0.0.1
  base_url: https://<machine>.<tailnet>.ts.net:10000   # links in alerts and digests
  tailscale_users: [you@example.com]                   # your Tailscale login(s)
```

and `systemctl --user restart tapwatch-ui`. Open the `base_url` from any of your tailnet devices,
including this PC. Requests without a listed Tailscale login get a 403, even ones sent straight to
port 8765. Use `serve`, not `funnel`, which would put the desk on the public internet. Any HTTPS
port that's free on the PC works; 443 is fine if nothing else uses it.
