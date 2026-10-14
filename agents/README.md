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
| `sysmon_events` (Windows) | 1 min | Sysmon, as it happens: every process start with its **command line** and parent, every outgoing connection and every DNS lookup, each with the program behind it |
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

On Windows, `sysmon_events` puts **command lines** in the results log, and command lines can hold passwords or
tokens. The installer restricts the log folder to SYSTEM, Administrators and the person who installed it (who
reads it from WSL for tapwatch), and tapwatch redacts command lines before storing them. They never go to Jev:
it sees facts such as "a document app started PowerShell", not the text.
See `tapwatch who <case>` and `host_context` in `config.example.yaml`.

### What tapwatch does with it

For each case on a machine with the agent, `tapwatch` assesses what ran:

| Assessment | When | Effect |
|---|---|---|
| **suspicious** | the program runs from `/tmp`, `/dev/shm` or similar; its file was deleted after it started; its command line downloads-and-runs or opens a raw shell; or an agent acted unattended, over SSH or after reading web content | always alerts, past suppressions and the AI |
| **likely benign** | an installed program (system or app folder) or a known user-installed tool, with none of the above, or your own agent work you asked for | capped at digest |
| **unclear** | anything else | normal routing |

On **Windows** there are no Claude Code markers, but osquery checks each program's code signature
(authenticode): signed by a trusted publisher, or installed under `Program Files`/`System32`, counts as likely
benign. Suspicious signs: running from `AppData\Local\Temp`, `Windows\Temp`, `Users\Public` or the Recycle Bin;
an invalid signature; a built-in tool attackers abuse (`rundll32`, `regsvr32`, `mshta`, `certutil`, `bitsadmin`,
`msbuild`...) connecting out; encoded or hidden PowerShell. On a Windows PC running tapwatch in WSL, the live check
asks both osquery installs, because Windows apps and WSL share one IP address.

Command lines are read only by the live check, as your user, and redacted in memory. They are never
written to the world-readable results log, and never sent to Jev (it reads the assessment only).

`tapwatch explain` groups repeat cases by detector, device, program and destination. Where every
case was assessed likely benign, it proposes a **program-scoped suppression** with the reason. A
different program talking to the same place still alerts. `--apply` creates it (30-day expiry) and
closes those cases as `benign_expected` with the explanation, all in the audit trail.

## Installing on someone else's computer

The agent records which programs run and what they connect to, including work apps and personal activity. On a
computer that isn't yours:

1. **Ask first**, and explain what it records: programs, their connections and DNS lookups and, on Windows, the
   command line of every program started (Sysmon). In standalone mode nothing leaves that computer.
2. **Check it isn't employer-managed.** Windows: Settings → Accounts → *Access work or school* shows no MDM or
   Intune connection, and `dsregcmd /status` doesn't say `AzureAdJoined : YES`. macOS: System Settings →
   *Profiles* is empty. A company security agent (Defender for Endpoint, CrowdStrike, SentinelOne...) is another
   sign. If it's managed, don't install: the employer decides what runs on it.
3. Show them how to remove it: `uninstall.cmd` (Windows) or `./uninstall.sh`.

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
