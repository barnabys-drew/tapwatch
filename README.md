# tapwatch

[![Tests](https://github.com/barnabys-drew/tapwatch/actions/workflows/tests.yml/badge.svg?branch=dev)](https://github.com/barnabys-drew/tapwatch/actions/workflows/tests.yml)
[![SAST](https://github.com/barnabys-drew/tapwatch/actions/workflows/sast.yml/badge.svg)](https://github.com/barnabys-drew/tapwatch/actions/workflows/sast.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

**Network security monitoring for a home or small office: Zeek on a mirror port, readable
detection code, and AI triage that can't override the facts.**

tapwatch watches a copy of your router's traffic and finds what's odd: new devices, beaconing,
DNS tunnelling, exposed services, rogue DHCP, IoT devices talking somewhere new. An optional
small AI model ([Jev](https://docs.typesafe.ai)) helps decide what's worth interrupting you for,
and alerts reach your phone. One small box runs it all, with no SIEM and no cloud.

## Why this exists

- **Homes have no SOC.** Commercial NSM assumes an analyst reads alerts all day. tapwatch's job is
  to stay quiet: one real home night produced **8 digest items and 0 alerts**.
- **Most devices can't run an agent.** TVs, cameras, hubs and phones are only visible on the
  wire, so tapwatch watches the network first. Computers can optionally run an
  [osquery agent](agents/README.md) that names the program behind a connection.
- **LLM triage is useful but unsafe on its own.** Here, code does the counting, baselines and "is
  this domain normal?". The model only judges behaviour described in words, and code-proven
  facts set floors and ceilings it can't cross.
- **AI coding agents make network traffic too.** On the tapwatch machine, host context tells the
  owner's own agent work from an agent that's been prompt-injected or hijacked.

## How it works

```mermaid
flowchart LR
    M["Switch mirror port"] --> Z["Zeek<br/>JSON logs"]
    S["Router syslog<br/>(optional)"] --> Z
    Z --> D["Detectors<br/>(plain code)"]
    D --> H["Host context<br/>osquery + agent transcripts<br/>(optional)"]
    H --> J["Jev triage<br/>(optional)"]
    J --> R{"Router"}
    D -. "always-alert<br/>& code-only rules" .-> R
    R -->|alert| N["ntfy · Discord · Teams<br/>email · webhook"]
    R -->|digest| G["Daily digest"]
    R -->|log| DB[("SQLite")]
    DB --> UI["Case desk<br/>(web UI)"]
```

The full design, routing rules and trade-offs are in **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**.

## Highlights

- **21 case types from 19 detectors** tuned for homes (table below). Each is plain Python with
  tests and a written spec. Learned baselines survive restarts.
- **Guardrailed AI triage.** Always-alert rules never reach the model and can't be suppressed.
  "Is this domain normal?" is never asked (it's the model's measured weak spot). The model needs
  0.75 confidence to alert on its own. Without an API key, it runs rules-only.
- **Agent-aware host context.** For traffic from the tapwatch machine, osquery names the program
  and Claude Code session markers and transcripts show whether the owner asked for it. Process
  proof outranks transcript context.
- **A case desk with no JavaScript.** It's a queue, a case page with ±5 minutes of Zeek evidence,
  workflow, notes, an audit trail, expiring "suppress similar" rules and stats. The CSP allows no
  scripts, and every change carries a CSRF token.
- **Private by design.** The AI sees device *names*, never internal IPs, MACs or packet contents.
  Network strings are quoted as untrusted. A personal-data gate runs in CI.
- **Few dependencies.** Standard-library Python plus PyYAML, SQLite, and Zeek in Docker. Runs
  under Docker Compose or as systemd user services, on Linux or a Windows PC with WSL.

## The case desk

A triage queue, case pages with the evidence and what the AI was shown, workflow and notes,
expiring suppressions, and per-detector stats. It's server-rendered HTML with no JavaScript at all.

![The case desk queue: open cases with severity, device, route and status](docs/img/case-desk-queue.png)

<details>
<summary>A case page, stats and suppressions</summary>

![A beaconing case: details, host context, Jev's answers and what it was shown, notes](docs/img/case-desk-case.png)
![Stats: cases per hour and per detector, false-positive rates](docs/img/case-desk-stats.png)
![Suppressions: an expiring rule with its reason](docs/img/case-desk-suppressions.png)

</details>

Screenshots are of made-up data: `python3 tools/demo_desk.py` builds the same demo desk locally.

## Results

From [eval/RESULTS.md](eval/RESULTS.md): six public Stratosphere Lab malware captures, plus 14 hours
of a real ~20-device home network.

| | Rules only | With Jev |
|---|---|---|
| Infected hosts surfaced (alert or digest) | 4 / 7 | 4 / 7 |
| Infected hosts **alerted** | 2 / 7 | **4 / 7** |
| Home night: items to read | 8 | 8 |
| Home night: false alerts | 0 | **0** |
| Jev cost for everything above | | $0.0008 |

Jev's measured value is **promotion**: it turned two real infections (HtBot, FluBot) from digest
items into alerts without adding false alerts. Tuning took the home night from 26 items and 4 false
alerts down to 8 and 0. The sample is small, so treat it as a sanity check, not a benchmark.

## What it catches

| Detector | Finds |
|---|---|
| `new_device` | a device never seen before joins, keyed on its MAC (vendor, randomized MAC, night-time) |
| `beaconing` | very regular repeat connections to one outside host (command-and-control heartbeat) |
| `dns_anomaly` | bursts of failed or random-looking lookups (DGA), and DNS tunnelling |
| `exposure` | a device answers a connection from the internet: port forward, UPnP (**always alerts**) |
| `mgmt_access` | a device tries the router's admin page, or SSH/RDP/SMB/VNC/telnet on another device |
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
| `udm_ips`, `udm_admin` | the router's own IPS verdicts, and admin logins (new source or repeated failures **always alert**), from its syslog |
| `ioc_match`, `ids_alert` | your threat lists (**always alert**), and Suricata alerts if you run it |

Design notes and rule specs (Sigma and SQL) are in [docs/detections/](docs/detections/DESIGN.md).

## Quickstart

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

Add `--profile syslog` for the router syslog listener, or `--profile ids` for Suricata.

**Linux without Docker, or a Windows PC:** run tapwatch as systemd user services with
`tapwatch service install --zeek-dir <dir>`. On Windows, Npcap captures and everything else runs
in WSL (`--capture-iface` adds the capture service). See [docs/setup/windows.md](docs/setup/windows.md).

`init` writes `config.yaml`, `assets.yaml` and `.env` (secrets live only in `.env`). Alerts can go
to **ntfy** (phone push; `init` makes a private topic), **Discord**, **Teams**, **email** or any
**webhook**. The first 24 hours are a learning period, so expect it to be quiet before it settles.

**Try it without a network** (synthetic capture, no real hosts, no malware):

```bash
python3 eval/make_synthetic_pcap.py eval/data/synthetic.pcap
eval/replay.sh eval/data/synthetic.pcap eval/out/synthetic        # Zeek in Docker, networking off
.venv/bin/tapwatch eval --zeek-dir eval/out/synthetic --labels eval/labels.example.yaml --warmup 0
```

### Commands

| Command | Does |
|---|---|
| `tapwatch init` | detect the network, ask a few questions, write config, assets and `.env` |
| `tapwatch run --zeek-dir DIR` | the live alerter: follow Zeek logs, triage, route, notify |
| `tapwatch ui` | the case desk at http://127.0.0.1:8765/ (set `TAPWATCH_UI_TOKEN` for other devices) |
| `tapwatch digest` | send the pending digest now (it also goes out daily) |
| `tapwatch mark 42 fp` | close case 42 as a false (`fp`) or true (`tp`) positive |
| `tapwatch update-feeds` | refresh the public lists (weekly is plenty) |
| `tapwatch syslog` | receive the router's CEF syslog into `udm.log` |
| `tapwatch service install` | install systemd user services (alerter, case desk, watchdog, optional capture and syslog) |
| `tapwatch who 42 --zeek-dir DIR` | ask the PC (osquery and agent transcripts) who made case 42's traffic |
| `tapwatch explain [--apply]` | find repeat cases host context explains, and suggest or apply suppressions |
| `tapwatch replay` / `tapwatch eval` | push finished logs through the pipeline, or score rules-only vs Jev on labelled traffic |
| `tapwatch test-alert` / `tapwatch notify` | check your notification channels |

Optional extras: [router syslog](docs/setup/router-syslog.md) adds the router's own IPS verdicts
and admin logins, and the [endpoint agents](agents/README.md) (osquery) name the program behind a
connection.

## What leaves the network

- **AI summaries**, if enabled: the device's *name* from `assets.yaml` (never internal IPs), a
  description in words, and up to three domain names, quoted as untrusted data. With host context
  that adds program names and yes/no facts, but never transcript text, session IDs, paths or
  command lines. About $0.02 a day at 1,000 cases.
- **Your notifications**, to the channels you configure. They include the device name and its LAN
  address. Domain names in them are defanged.
- **Public list downloads** (`update-feeds`): downloads only, nothing is sent.

Packet contents and MAC addresses never leave, and internal addresses never reach the AI.

## Repository layout

```
src/tapwatch/        the package
  cli.py               subcommands, wiring
  zeek.py              log replay and live follower (rotation-safe)
  detectors.py         every detector, plus state encoding
  hostctx.py           osquery and agent-transcript host context
  summarizer.py        case -> short IP-free text for the AI
  triage.py            Jev client (typed questions, pinned model)
  router.py            alert / digest / log, with guardrails
  pipeline.py          detectors -> context -> triage -> route -> store -> notify
  store.py             SQLite schema, workflow, suppressions, learned state
  ui.py, evidence.py   case desk and Zeek evidence lookup
  notifiers.py         ntfy, Discord, Teams, email, webhook, Herdr
  syslogin.py          router CEF syslog listener
  wizard.py, service.py, feeds.py, explain.py, evaluate.py
tests/               pytest suite (synthetic data only)
deploy/              docker-compose, Zeek scripts, Windows keep-alive
agents/              osquery (and Sysmon) installers for endpoints
eval/                capture replay, public-capture fetcher, watchdog, RESULTS.md
docs/                architecture, detection design and rule specs, setup guides, roadmap
tools/               personal-data gate
```

## Documentation

| Doc | What's in it |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | data flow, components, routing guardrails, host context, security model, design decisions |
| [docs/detections/DESIGN.md](docs/detections/DESIGN.md) | the detection catalogue (R01–R16), with measured baselines and how Jev is used |
| [docs/detections/rules/](docs/detections/rules/README.md) | Sigma and DuckDB SQL versions of the rules |
| [eval/RESULTS.md](eval/RESULTS.md) | eval method, numbers, tuning history and caveats |
| [docs/setup/](docs/README.md#setup-guides) | mirror port, router syslog, Windows |
| [agents/README.md](agents/README.md) | endpoint agents (osquery, Sysmon) |
| [docs/ROADMAP.md](docs/ROADMAP.md) | what's built and what's planned |
| [CONTRIBUTING.md](CONTRIBUTING.md) · [SECURITY.md](SECURITY.md) | development, adding a detector, reporting vulnerabilities |

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
make test lint
python3 tools/check_personal_data.py     # no personal data in tracked files
```

CI runs the personal-data gate, ruff and pytest on every push to `dev`, and adds Semgrep and Trivy
on PRs into `main`.

## Status

**v0.1.1**, running on a real home network, so expect rough edges. Next up, per the
[roadmap](docs/ROADMAP.md): a long-running test of host context (in progress), a clean-machine
Windows test, basic macOS support, and endpoint rules from osquery process events.

## License

MIT. The malware captures used in the eval are from the
[Stratosphere Lab](https://www.stratosphereips.org/), CTU Prague. Please cite them if you reuse them.
