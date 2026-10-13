# Router syslog (UniFi): IPS alerts and admin logins

The mirror port sees traffic between devices and the internet. It can't see what happens
*on* the router: its own intrusion prevention verdicts, or someone logging in to it. The
router can send both as syslog (CEF). tapwatch turns them into cases:

| Rule | From the router | Routing |
|---|---|---|
| `udm_ips` | IPS signature matches (UniFi CyberSecure) | Inbound attempts it blocked → log. High risk and not blocked → always alert. Otherwise normal routing |
| `udm_admin` (R11) | Admin logins | A new (user, source) after warmup → always alert. 5+ failures from one source in 10 min → always alert |

## 1. Start the listener

```bash
tapwatch -c config.yaml syslog --listen 0.0.0.0:5514 --out <the dir `run` watches>
```

It writes `udm.log` next to Zeek's logs (rotated hourly the same way), and `tapwatch run`
picks it up. It only accepts datagrams from `syslog.allow`, which defaults to `network.gateways`.
Syslog over UDP has no authentication, so this keeps other LAN devices from injecting events.

## 2. Let the router reach it

- **Linux box:** nothing to do unless a host firewall is on (`sudo ufw allow from <router-ip> to any port 5514 proto udp`).
- **Windows + WSL (mirrored networking):** inbound LAN traffic to WSL needs a Hyper-V firewall
  rule. This needs admin, so run it yourself in an elevated PowerShell:

  ```powershell
  New-NetFirewallHyperVRule -Name tapwatch-syslog -DisplayName "tapwatch syslog" -Direction Inbound `
    -VMCreatorId '{40E0AC32-46A5-438D-A0A5-56A1FF8A6E6E}' -Protocol UDP -LocalPorts 5514 `
    -RemoteAddresses <router-ip> -Action Allow
  ```

## 3. Point the router at it

UniFi Network: **Settings → Control Plane → Integrations → Activity Logging → SIEM Server**.
Enter this machine's IP and port 5514. (The menu has moved between UniFi versions; search
settings for "SIEM" if it isn't there.) Events start within a minute; check with
`tail -f <dir>/udm.log`.

## What's verified

- The CEF parser and the IPS mapping are built against a real UDM line published in Graylog's
  UniFi content pack (`Threat Detected and Blocked`, `UNIFIrisk`, `UNIFIipsSignature`, `src`/`dst`).
- The admin-login mapping uses UniFi's documented keys (`UNIFIadmin`, `suser`, `src`,
  `UNIFIaccessMethod`) and wording ("login", "accessed", "failed"). **Not yet checked against
  real admin events.** After enabling, log in to the router once and check that a `udm_admin`
  case appears (after the first day's warmup, or from a new device).

## Suricata vs the router's IPS

The router already runs signature IPS. tapwatch's optional Suricata (`docker compose --profile ids`)
only adds something when the router's IPS is off or memory-limited (some gateways cap their
signature count), or for traffic the router doesn't route (same-switch, which the mirror doesn't
see either). With UniFi CyberSecure on, leave Suricata off and use this syslog feed.
