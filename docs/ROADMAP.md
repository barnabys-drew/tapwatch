# tapwatch: road to a public release

_v0.1.0 released 2026-10-13. Goal: something friends and co-workers can install on their own home
networks, on **both** a small Linux box and a Windows PC. Work goes `dev` → PR → `main`; each
item lands as its own PR with tests and the personal-data check._

Each milestone ends in something usable. Tick items as their PRs merge.

## M1 Foundation: trustworthy main

- [x] Fix the UI login crash. Two UI changes collided when merged: one checked `app.sessions`, the other had removed it.
- [x] CI runs `ruff` and `pytest` on every push to `dev` and every PR into `main` (`.github/workflows/tests.yml`)
- [x] The daily digest goes out on a quiet network: idle ticks from the follower, plus a once-a-day clock that still fires after a late start
- [x] Zeek log rotation on both capture paths (`deploy/zeek/tapwatch-live.zeek`, hourly), the follower survives it, evidence and replay read rotated files, and `zeek_retention_days` prunes old ones
- [x] "Small business, one IT person" wording becomes a config `audience: office | home`. Summaries and Jev's questions follow it; the default stays `office` (the measured wording) until M5

## M2 Detections: the rules people will judge it by

Specs are in `detections/DESIGN.md` and `detections/rules/`. Built: R01–R07, R09, R10, R12–R16, plus host context. R08 is `new_domain` (code-routed); R11 (`udm_admin`) landed with the syslog input in M3.

- [x] Detector state survives restarts: learned baselines are saved to SQLite every 10 min and on shutdown
- [x] R05 new device keyed on MAC (Zeek `mac-logging`), with vendor (OUI table) and randomized-MAC handling
- [x] R06 odd-port and long-lived outbound
- [x] R07 DNS bypass (plain/DoT/DoH/DoQ)
- [x] R09 upload drift against the same hour on earlier days, plus steady-upload-stopped (camera offline)
- [x] R12 off-hours activity (needs 7 nights of history per device)
- [x] R15 DNS tunnelling clause on `dns_anomaly`, plus a retry-loop guard (one dead name isn't DGA)
- [x] R02 IoT egress drift, using an offline ASN/country table (`tapwatch update-feeds`, download only)
- [x] R10 TLS weak-signal stack (JA4 left for later: needs a Zeek package)

## M3 Inputs beyond the mirror

- [x] Syslog listener (UDP) with a CEF parser, sender allow-list and hourly rotation (`tapwatch syslog`)
- [x] UniFi parser: IPS alerts (`udm_ips`) and admin logins (**R11** `udm_admin`). Admin mapping still to check against real events
- [ ] Port-forward and UPnP change events enrich R01 (needs real UDM samples)
- [x] Suricata stays optional: `docs/setup/router-syslog.md` says when it adds anything

## M4 Install and notify: someone else can set it up in an evening

- [x] `tapwatch init`: detects gateway, this machine, timezone and capture path; asks a few questions; writes `config.yaml`, `assets.yaml` and `.env` (600), never overwriting without `--force`
- [x] Notifiers: **ntfy**, **Discord**, generic webhook, alongside Teams, email and Herdr. Network strings are defanged; Discord mentions are off
- [x] **Linux path:** `docker compose up` runs Zeek, the alerter, the case desk and (profile) the syslog listener. Verified end to end on a live interface: logs flow, a CEF line becomes a case, the UI asks for its token, and stopping saves state. Mirror-port guide: `docs/setup/mirror-port.md`
- [x] **Windows path:** `docs/setup/windows.md`, WSL systemd services via `tapwatch service install --capture-iface`, `deploy/windows/keep-alive.ps1` (no admin). Not yet run on a clean machine
- [ ] Clean-machine test of the Windows path (a friend's PC, or a fresh Windows VM)
- [x] Services on both paths: compose restart policies (Linux + Docker); systemd user units for alerter, case desk, watchdog, capture, syslog (Linux without Docker, and WSL), checked with `systemd-analyze verify`

## M5 Proof: numbers for the README

- [x] Jev go/no-go on 6 public Stratosphere captures (`eval/public_captures.sh`), replayed in the network-less container: GO on promotion, 4/7 infected hosts alerted vs 2/7 rules-only
- [x] Benign noise from a home network, aggregates only: 14 h → 8 digest items, 0 alerts (was 26 and 4 before tuning)
- [x] `eval/RESULTS.md`: alerts and noise in rules-only vs Jev mode, cost, and caveats
- [ ] Jev with `audience: home` vs `office` wording on the same cases. Switch the default to `home` if it's no worse

## M6 Release

- [x] Personal-data gate: `tools/check_personal_data.py` (generic patterns in CI, plus a gitignored local denylist of household specifics). It caught a real household MAC in the tests
- [x] Public repo from a clean snapshot (the development history held household specifics, so it stays private)
- [x] README rewrite: what it is, what it catches, setup for each path, the case desk, AI triage and its guardrails, what leaves the network
- [ ] Screenshots of the case desk on synthetic data
- [x] LICENSE (MIT), CONTRIBUTING, SECURITY (private reporting), CODE_OF_CONDUCT, issue templates, package metadata
- [x] SAST, Trivy, tests and the personal-data gate on every PR; Dependabot to `dev`; private vulnerability reporting
- [x] Tagged `v0.1.0` with release notes

## Not in scope for v0.1

Fleet server, cloud hosting, multi-site, a mobile app.

## Next

The backlog lives in [GitHub issues](https://github.com/barnabys-drew/tapwatch/issues), by milestone:

- [v0.2](https://github.com/barnabys-drew/tapwatch/milestone/1): validate 0.1's experimental parts (long-running
  host-context test, Windows clean-machine test, real UniFi admin events), basic macOS support, case-desk
  screenshots, home vs office wording, CI on Python 3.10–3.13
- [v0.3: endpoint rules](https://github.com/barnabys-drew/tapwatch/milestone/3): osquery process events and
  living-off-the-land rules for Windows, Linux and macOS, correlated with network cases
- [Later](https://github.com/barnabys-drew/tapwatch/milestone/2): Fleet, Sysmon attribution, JA4, Public Suffix
  List, newly registered domains, IPv6 exposure, published image and package, and more
