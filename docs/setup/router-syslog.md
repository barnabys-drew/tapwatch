# Router syslog (UniFi): IPS alerts and admin logins

The mirror port sees traffic between devices and the internet. It can't see what happens
*on* the router: its own intrusion prevention verdicts, or someone logging in to it. The
router can send both as syslog. tapwatch turns them into cases:

| Rule | From the router | Routing |
|---|---|---|
| `udm_ips` | IPS signature matches (UniFi CyberSecure) | Inbound attempts it blocked → log. High risk and not blocked → always alert. Otherwise normal routing |
| `udm_admin` (R11) | Admin logins | A new (user, source) after warmup → always alert. 5+ failures from one source in 10 min → always alert |

Firewall drops and rejects are kept as evidence (`kind: firewall` records in `udm.log`: chain,
rule, addresses, ports); nothing alerts on them yet.

## 1. Start the listener

```bash
tapwatch -c config.yaml syslog --listen 0.0.0.0:5514 --out <the dir `run` watches>
```

It writes `udm.log` next to Zeek's logs (rotated hourly the same way), and `tapwatch run`
picks it up. It only accepts datagrams from `syslog.allow`, which defaults to `network.gateways`.
Syslog over UDP has no authentication, so this keeps other LAN devices from injecting events.

Every 10 minutes it logs one line with what arrived (`cef 12, firewall_accept 4210,
system 30 in the last 10 min`). Use it to see whether the router is sending anything useful,
and whether the firewall flood (below) is still on.

To run it as a service next to the alerter: `tapwatch service install --zeek-dir <dir> --syslog`
adds `tapwatch-syslog.service` to the other units (`--dry-run` prints them first).

## 2. Let the router reach it

- **Linux box:** nothing to do unless a host firewall is on (`sudo ufw allow from <router-ip> to any port 5514 proto udp`).
- **Windows + WSL (mirrored networking):** inbound LAN traffic to WSL needs **two** rules, one
  in the Hyper-V firewall (the WSL side) and one in Windows Defender Firewall (the host side).
  Both need admin, so run them yourself in an elevated PowerShell:

  ```powershell
  New-NetFirewallHyperVRule -Name tapwatch-syslog -DisplayName "tapwatch syslog" -Direction Inbound `
    -VMCreatorId '{40E0AC32-46A5-438D-A0A5-56A1FF8A6E6E}' -Protocol UDP -LocalPorts 5514 `
    -RemoteAddresses <router-ip> -Action Allow
  New-NetFirewallRule -DisplayName "tapwatch syslog" -Direction Inbound -Protocol UDP `
    -LocalPort 5514 -RemoteAddress <router-ip> -Action Allow
  ```

  With only the Hyper-V rule nothing arrives and nothing is logged anywhere; the router's
  syslog-ng just reports "connection broken" to itself and retries every 60 s.

## 3. Point the router at it

UniFi Network 10.x: **CyberSecure → Traffic Logging → Activity Logging (Syslog) → SIEM Server**.
Fill in **Server Address** (this machine) and **Port** (5514), then pick **Contents**.
Older releases had it under Settings → Control Plane → Integrations → Activity Logging; search
settings for "SIEM" if neither is there.

Contents to tick: **Admin Activity** (R11), **Security Detections** (`udm_ips`), **Critical**,
**Devices**, **Updates**, **VPN**, **Triggers**. **Clients** adds a CEF event per Wi-Fi join,
roam and leave (a few a minute in a busy house); `scan` uses the roam and leave events to hold a
client's failure burst to the digest, so tick it. Leave **Firewall
Default Policy** off unless you want the flood described below. Flow Logging ("Blocked Traffic
Only") is separate from the SIEM export.

Events start within a minute; check with `tail -f <dir>/udm.log`.

## What arrives

Measured on a UDM Pro, UniFi Network 10.6.106, UniFi OS 5.1.33, with all twelve content types on
(94 minutes on 2026-10-15: 35,301 datagrams, of which 11 were CEF events):

| Format | Looks like | Rate | tapwatch |
|---|---|---|---|
| CEF events | `Oct 15 19:29:37 gateway CEF:0\|Ubiquiti\|UniFi Network\|10.6.106\|401\|WiFi Client Disconnected\|2\|UNIFIcategory=Client Devices UNIFIhost=UDM Pro ...` (no `<PRI>`) | one per UniFi event | kept, one JSON record each |
| Firewall lines ("Firewall Default Policy") | `<13>Oct 15 19:25:16 gateway gateway [LAN_LOCAL-RET-2147483647] DESCR="no rule description" IN=br0 OUT= MAC=... SRC=192.168.50.18 DST=192.168.50.1 ... PROTO=UDP SPT=61975 DPT=53` | **290–670 a minute, median 360**, all but two of them default-policy accepts for LAN devices talking to the gateway (DNS, mDNS, UniFi discovery on udp/10001); the two drops were `WAN_LOCAL-D`, late packets of finished flows | drops and rejects (`-D-`, `-R-`) kept; accepts and chain returns (`-A-`, `-RET-`) counted and discarded |
| The gateway's own system log | `<30>Oct 15 19:28:01 gateway gateway earlyoom[1024]: mem avail: ...` (earlyoom, systemd, mcad, syslog-ng, dnsmasq, the AI and IDS daemons) | about 3 a minute | discarded |

The firewall lines are the whole cost of this feed: about 22k an hour, which is why the
listener counts them instead of writing them. Untick Firewall Default Policy in Contents and
they stop.

## What's verified

- **CEF parsing against real lines** (2026-10-15): Wi-Fi client connected / roamed /
  disconnected events (classes 400–402) from UniFi Network 10.6.106 parse with every
  `UNIFI*` key intact, including values with spaces (`UNIFIhost=UDM Pro`, `UNIFIduration=1d 11h`).
  Real lines carry no syslog `<PRI>`; the parser never needed one.
- **Firewall lines** (2026-10-15): the UDP, TCP and IPv6 accept shapes and the `WAN_LOCAL-D`
  drop shape parse to chain, action, rule, description, interfaces, addresses, protocol and
  ports. iptables truncates the description (`[WAN_LOCAL]Block All Other Tra`), so a rule's
  full name is not recoverable from the line.
- **IPS mapping (`udm_ips`)**: built against a real UDM line published in Graylog's UniFi
  content pack (`Threat Detected and Blocked`, `UNIFIrisk`, `UNIFIipsSignature`, `src`/`dst`).
  No Security Detections line has arrived from this router yet (it needs the router to block
  something), so the 10.x wording is unconfirmed.
- **Admin-login mapping (`udm_admin`)** (2026-10-15): a real admin event is CEF class 544
  `Network Accessed` with `UNIFIcategory=Audit`, `UNIFIadmin=<display name>`, `src=<ip>`,
  `UNIFIaccessMethod=web` and `msg=<name> accessed UniFi Network using the web. Source IP: <ip>`.
  The detector keys on `UNIFIadmin` and `src`, so it learns the (user, source) pair and alerts
  on a new one, as the test shows with the sanitized line. One event is sent per console
  page load, not per sign-in, so expect several a day from the same pair. **Not yet seen:**
  a failed login (the failure-burst branch still relies on "fail" wording), SSH logins and
  UniFi OS (not Network) sign-ins, which may not be in this export at all.

## Suricata vs the router's IPS

The router already runs signature IPS. tapwatch's optional Suricata (`docker compose --profile ids`)
only adds something when the router's IPS is off or memory-limited (some gateways cap their
signature count), or for traffic the router doesn't route (same-switch, which the mirror doesn't
see either). With UniFi CyberSecure on, leave Suricata off and use this syslog feed.
