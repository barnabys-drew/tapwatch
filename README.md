# tapwatch

**Network security monitoring for a home or small office, without a SIEM.**
Zeek watches a copy of your traffic, plain-code detectors find what's odd, an optional
small AI model ([Jev](https://docs.typesafe.ai)) helps decide what's worth interrupting you
for, and alerts reach your phone.

```
switch mirror port → Zeek → detectors (code) → Jev (optional) → router → ntfy / Discord / email / Teams
                                                                     └→ case desk (web UI)
```

- **Runs on one small box**: a mini PC on Linux, or the Windows PC you already have (via WSL).
- **Sees every device**: phones, TVs, cameras and IoT that can't run an agent, because it
  watches the network rather than the devices.
- **21 detection rules** built for homes: new devices, beaconing, DNS tunnelling, internet-exposed
  services, rogue DHCP, IoT devices talking somewhere new, exfiltration channels and more.
- **Quiet by design**: a night of real home traffic produced 8 digest items and no alerts.
  On public malware captures it alerted on 4 of 7 infected hosts ([results](eval/RESULTS.md)).
- **Private by design**: nothing leaves the network except optional AI summaries (no
  internal IPs, no packet contents) and your own notifications.

Status: **v0.1**. Running on a real home network. Expect rough edges.

## What it catches

| Detector | Finds |
|---|---|
| `new_device` | a device never seen before joins, keyed on its MAC: vendor, randomized MAC, night-time |
| `beaconing` | very regular repeat connections to one outside host (command-and-control heartbeat) |
| `dns_anomaly` | bursts of failed or random-looking lookups (DGA), and DNS tunnelling |
| `exposure` | a device answers a connection from the internet: port forward, UPnP (**always alerts**) |
| `mgmt_access` | a device tries the router's admin page or SSH/RDP/SMB/VNC/telnet on another device |
| `rogue_dhcp` | a DHCP server other than the router (**always alerts**) |
| `takeover` | webhook/callback catchers, paste and file-drop sites (**always alert**), tunnels and remote-control tools |
| `iot_drift` | a camera, TV, hub or other fixed-function device talks to new networks, countries or ports |
| `odd_port` | outbound on a port no device in the house uses, or an unusually long connection |
| `dns_bypass` | a device starts resolving names outside your resolver (plain, DoT, DoQ, DoH) |
| `upload_spike` | an hour of uploads far above that device's normal for that hour |
| `upload_stopped` | a steady uploader (a camera) goes quiet for hours |
| `off_hours` | a device busy at an hour it's normally idle |
| `tls_odd` | encrypted sessions stacking weak oddities (no name, unexplained IP, odd port, bad cert) |
| `cleartext_auth` | HTTP basic auth, FTP logins, telnet, POP3/IMAP or MQTT without encryption |
| `new_domain` | first contact with a rarely used domain (code-routed; mostly log-only) |
| `scan` | one host probing many hosts or ports |
| `udm_ips`, `udm_admin` | the router's own IPS verdicts and admin logins, from its syslog |
| `ioc_match`, `ids_alert` | your threat lists, and Suricata alerts if you run it |

Design notes and rule specs (Sigma and SQL): [docs/detections/](docs/detections/DESIGN.md).

## Set up

You need a managed switch that can **mirror** the port your router plugs into
([how](docs/setup/mirror-port.md)), and a machine with a second network port for the mirror.

**Linux box with Docker:**

```bash
git clone https://github.com/barnabys-drew/tapwatch && cd tapwatch
python3 -m venv .venv && .venv/bin/pip install -e .
.venv/bin/tapwatch init            # detects your router and interfaces, asks a few questions
.venv/bin/tapwatch update-feeds    # public lists: popular domains, MAC vendors, IP-to-network
TAP_IFACE=<mirror NIC> docker compose -f deploy/docker-compose.yml up -d --build
```

**Windows PC:** capture with Npcap, everything else in WSL. See [docs/setup/windows.md](docs/setup/windows.md).

`init` writes `config.yaml`, `assets.yaml` and `.env` (secrets live only in `.env`). Alerts can go
to **ntfy** (phone push; `init` makes a private topic), **Discord**, **Teams**, **email** or any
**webhook**. The first 24 hours are a learning period, so expect quiet before it settles.

Day to day:

```bash
tapwatch ui              # the case desk: http://127.0.0.1:8765/
tapwatch digest          # send the pending digest now (it also goes out daily)
tapwatch mark 42 fp      # close case 42 as a false positive
tapwatch update-feeds    # refresh the public lists (weekly is plenty)
```

Optional extras: [router syslog](docs/setup/router-syslog.md) for the router's own IPS and admin
logins, and [endpoint agents](agents/README.md) (osquery) to name the program behind a connection.

## The case desk

A small local web app (standard library only) on the same SQLite database: a queue you can
filter and sort, a case page with the Zeek evidence from ±5 minutes, status and disposition,
notes, an audit trail, "suppress similar" rules with a reason and expiry, and stats per detector.
Always-alert cases can't be suppressed. Everything from the network is escaped and never linked,
a strict CSP allows no scripts, and every change carries a CSRF token. It listens on 127.0.0.1;
for other devices, set `TAPWATCH_UI_TOKEN` and log in with it.

## AI triage (optional)

Code does everything a model is bad at: counting, timing, baselines, addresses. When enabled,
Jev reads a 3–4 line summary of a case in words and answers typed questions: what kind of
activity, how urgent, routine or not, worth interrupting you or not. The router then decides,
with guardrails:

- Always-alert cases never go to the AI and can't be lowered.
- Jev is never asked whether a domain is "normal": that's its measured weak spot, so
  first-seen domains are routed by code.
- Detectors attach code-proven ceilings (a popular service other devices already use, a known
  sync service) that the AI can't raise a case past.
- Jev needs high confidence (0.75) to alert on its own.

Without a key, tapwatch runs rules-only. On the [eval](eval/RESULTS.md), Jev's value was promotion:
it turned two real infections from digest items into alerts without adding false alerts.

## What leaves the network

- **AI summaries**, if enabled: the device's *name* from `assets.yaml` (never internal IPs), a
  description in words, and up to three domain names, quoted as untrusted data. About $0.02 a
  day at 1,000 cases.
- **Your notifications**, to the channels you configure. Domain names are defanged there.
- **Public list downloads** (`update-feeds`): downloads only, nothing is sent.

Packet contents, MAC addresses and internal addresses never leave.

## Architecture and development

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): the system and why it's shaped this way
- [docs/ROADMAP.md](docs/ROADMAP.md): what's built and what's next
- [CONTRIBUTING.md](CONTRIBUTING.md): set up, test, propose a detector

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
make test lint
# End to end on a synthetic capture (no real hosts, no malware):
python3 eval/make_synthetic_pcap.py eval/data/synthetic.pcap
eval/replay.sh eval/data/synthetic.pcap eval/out/synthetic        # Zeek in Docker, networking off
.venv/bin/tapwatch eval --zeek-dir eval/out/synthetic --labels eval/labels.example.yaml --warmup 0
```

## License

MIT. Malware captures used in the eval are from the
[Stratosphere Lab](https://www.stratosphereips.org/), CTU Prague; please cite them if you reuse them.
