# tapwatch agents

The endpoint half of tapwatch: one-command installers that put [osquery](https://osquery.io) on every computer
in the house, through each platform's own package manager, and start it as a
service. Windows also gets [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon),
so you can always answer "which program made that connection?" when tapwatch
raises a network case. The agents don't depend on the rest of tapwatch; you can
install them on a machine that never runs Zeek or the alerter.

| OS | Installs with | Run |
|---|---|---|
| Windows 10/11 | winget (osquery) + Microsoft download (Sysmon, signature-checked) | double-click `install.cmd` |
| macOS | Homebrew (`brew install --cask osquery`) | `./install.sh` |
| Linux (Debian, Ubuntu, Fedora, RHEL, Rocky…) | osquery's official apt / dnf repo | `./install.sh` |

```bash
gh repo clone barnabys-drew/tapwatch && cd tapwatch/agents
./install.sh            # macOS / Linux
```

On Windows, clone or download the repo and double-click **agents\install.cmd**. It asks
for admin rights once.

## Two modes

**Standalone (default).** No server needed. osquery runs a set of scheduled
queries ([config/osquery.conf](config/osquery.conf)) and writes the results to
local logs, and you can ask it anything with `osqueryi`:

| Scheduled query | Every | Why |
|---|---|---|
| `listening_ports` | 1 h | services reachable from the network |
| `outbound_connections` | 5 min | which process holds which outside connection |
| `startup_items`, `launchd`, `crontab`, auto-start services, scheduled tasks | 1 h | persistence |
| `chrome_extensions` | 1 day | browser add-ons |
| `logged_in_users`, `system_info`, `os_version` | 1 h – 1 day | inventory |

Results go to `/var/log/osquery/osqueryd.results.log` (macOS and Linux) or
`C:\Program Files\osquery\log\osqueryd.results.log` (Windows).

**Fleet.** Point the agents at a [Fleet](https://fleetdm.com) server to query
every machine from one place. Put the settings in `agent.env` once (copy
[agent.env.example](agent.env.example)), and every install picks them up:

```bash
cp agent.env.example agent.env     # set FLEET_URL, ENROLL_SECRET, FLEET_CERT
./install.sh
```

or pass them directly: `./install.sh --fleet-url https://fleet.lan:8080 --enroll-secret XXXX --fleet-cert fleet.pem`
(Windows: `install.cmd -FleetUrl ... -EnrollSecret ... -FleetCert fleet.pem`).
Re-running the installer switches modes; `--standalone` forces standalone.

## Host context (tapwatch PC)

On Linux and macOS the agent also runs `outbound_connections_ctx`. It records whether a
**Claude Code session** started each connection's process, using environment markers
(`CLAUDE_CODE_SESSION_ID`, `CLAUDE_CODE_SESSION_ATTENDED`, `CLAUDE_CODE_ENTRYPOINT`), a Herdr
pane, or an SSH login. Markers survive reparenting, unlike the parent chain. Only those named
variables are read, never the rest of the environment (it holds tokens). Results are written
`0644` (`--logger_mode`), so tapwatch can read them without root. On the PC that runs tapwatch, install the
agent **inside WSL** too: Windows can't see Linux processes, and the coding agents run there.
See `tapwatch who <case>` and `host_context` in `config.example.yaml`.

### What tapwatch does with it

For each case on a machine with the agent, `tapwatch` assesses what ran:

| Assessment | When | Effect |
|---|---|---|
| **suspicious** | the program runs from `/tmp`, `/dev/shm` or similar; its file was deleted after it started; its command line downloads-and-runs or opens a raw shell; or an agent acted unattended, over SSH or after reading web content | always alerts, past suppressions and the AI |
| **likely benign** | an installed program (system or app folder) or a known user-installed tool, with none of the above, or your own agent work you asked for | capped at digest |
| **unclear** | anything else | normal routing |

Command lines are read only by the live check, as your user, and redacted in memory. They are never
written to the world-readable results log, and never sent to Jev (it reads the assessment only).

`tapwatch explain` groups repeat cases by detector, device, program and destination. Where every
case was assessed likely benign, it proposes a **program-scoped suppression** with the reason. A
different program talking to the same place still alerts. `--apply` creates it (30-day expiry) and
closes those cases as `benign_expected` with the explanation, all in the audit trail.

## Useful queries

```sql
-- what is listening, and which program
SELECT p.name, p.path, l.port, l.address FROM listening_ports l JOIN processes p USING (pid);

-- who is talking to a given outside address right now
SELECT p.name, p.path, s.remote_address, s.remote_port FROM process_open_sockets s
  JOIN processes p USING (pid) WHERE s.remote_address = '203.0.113.5';

-- Windows: network history with the program behind each connection (Sysmon event 3)
SELECT datetime, data FROM windows_eventlog
  WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND eventid = 3 LIMIT 50;
```

## Notes

- **macOS:** give osquery Full Disk Access (System Settings → Privacy & Security
  → Full Disk Access → add `/opt/osquery/lib/osquery.app`), or some tables come
  back empty. Run `install.sh` as your normal user; it asks for sudo itself.
- **Linux without systemd** (containers, some WSL setups): osquery is installed
  and configured, but you start `osqueryd` yourself; the installer prints the command.
- **Sysmon config** ([windows/sysmon.xml](windows/sysmon.xml)) logs process
  starts and ends, network connections and DNS queries, and keeps 256 MB of
  history. Skip it with `install.cmd -NoSysmon`.
- **Uninstall:** `./uninstall.sh`, or double-click `uninstall.cmd` on Windows.
- Re-running an installer is safe: it upgrades osquery and rewrites the config.
