# Rule files

SQL files are **DuckDB** over Zeek JSON logs. Run them with
`duckdb -c "SET VARIABLE zeek='eval/data/<dir>'; .read docs/detections/rules/R01-....sql"`.
Each reads `getvariable('zeek') || '/conn*.log*'`. Stateful rules compare a
**baseline** window with a **detection** window, both set at the top of the file.
In tapwatch the same logic runs as a streaming detector, and these files are the
batch/hunt equivalent and the spec.

**Not executed yet.** DuckDB isn't installed, and the design brief allowed no installs, so treat
the SQL as a reviewed spec. Expect small syntax fixes on the first run (DuckDB ≥ 1.1 for
`getvariable`). Variables to set: `zeek`, `assets` (CSV export of assets.yaml), `tranco`,
`nrd_30d`, `domain_allow`, `exposure_baseline`, and an `ip2asn` table for R02.

Sigma files (`.yml`) use `product: zeek`. Allowlists are config (`assets.yaml`
roles), never hardcoded IPs. The endpoint rules (R17–R21) use the standard Sigma
`product: windows` log sources (`process_creation`, `network_connection`) so they run as
written against Sysmon in any Sigma backend; tapwatch's streaming versions in
`src/tapwatch/hostrules.py` read osquery's reduced rows instead, where the command line is
already a set of yes/no signals (`agents/config/osquery.conf`), and the `CommandLine` regexes
in the files are the ones osquery applies.

| File | Rule | Format |
|---|---|---|
| R01-internet-exposed-service.sql | Internet-exposed service appears | SQL |
| R02-iot-egress-drift.sql | Fixed-function device egress drift | SQL |
| R03-mgmt-plane-access.yml | Management-plane / admin-port access | Sigma |
| R04-beaconing.sql | Beaconing (hunt version of the detector) | SQL |
| R05-new-device.sql | New MAC joins | SQL |
| R06-odd-port-long-lived.sql | Odd-port or long-lived outbound | SQL |
| R07-dns-bypass.yml | DNS bypass (plain / DoT / DoH / DoQ) | Sigma |
| R08-rare-new-domain.sql | Rare-in-household / newly registered domain | SQL |
| R09-upload-drift.sql | Upload drift and camera stop | SQL |
| R10-tls-weak-signals.sql | TLS weak-signal stack | SQL |
| R13-cleartext-credentials.yml | Cleartext credentials | Sigma |
| R14-rogue-dhcp.yml | Rogue DHCP server | Sigma |
| R16-takeover-channels.yml | Takeover channel: callback, file drop, tunnel, remote control | Sigma |
| R17-encoded-command.yml | Encoded or download-and-run command (endpoint) | Sigma |
| R18-app-spawns-shell.yml | Document app or browser starts a shell (endpoint) | Sigma |
| R19-temp-folder-connects.yml | Program in a temp or download folder connects out (endpoint) | Sigma |
| R20-lolbin-connects.yml | Built-in Windows tool connects to the internet (endpoint) | Sigma |
| R21-bad-signature-connects.yml | Program with a bad code signature connects out (endpoint) | Sigma |
| _common.sql | Shared macros and views; the SQL files `.read` it first | SQL |

**Every rule here is built** as a streaming detector: R01–R16 in `src/tapwatch/detectors.py`
(R01 `InternetExposure`, R03 `ManagementAccess`, R13 `CleartextAuth`, R14 `RogueDHCP` and the rest),
R17–R21 in `src/tapwatch/hostrules.py`. The later rules (R22 in `detectors.py`, R23–R29 and R36–R39 in
`hostrules.py`, R48 in `vulnkev.py`, R49–R51 in `hostrules.py`, v0.4's long-horizon R30–R34 in `longhaul.py`) have no file here;
their specs are in `../DESIGN.md`. The streaming versions differ from these specs in a few
places. R01 and R03 learn existing exposures and admin pairs during warmup. R01 skips flows
whose direction Zeek can't know: the first 2 min after start, TCP without the outside host's SYN,
and UDP replies to a remote the device contacted in the last 30 min. R13 also reads `ftp.log`.
`network.gateways` is optional: `Gateways` learns each /24's router from the logs (the first address
3 devices use for DNS, NAT-PMP or DHCP), and R14 then expects one DHCP server per LAN.

R11 (UDM admin login), R12 (off-hours drift) and R15 (DNS tunnelling) are built too and
specified only in `../DESIGN.md`. R11 reads the UDM syslog input (`udm.log`). R12 is part of
`HourlyProfile` with R09, and R15 is the tuned `SuspiciousDNS`.
