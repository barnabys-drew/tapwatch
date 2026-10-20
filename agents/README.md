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

On Linux and macOS the results log is readable only by root and the installing user's group (group-owned and
setgid, mode 0640), because it can hold a command line with a token when a signal fires; re-running the installer
applies this to an existing install. On Windows it stays readable by local accounts: osquery writes explicit
per-file permissions, and the mode that would hide it from other accounts also hides it from the user tapwatch
reads it as.

After pulling a new `config/osquery.conf` (a rule added a signal), re-run the installer or copy it over the
installed one and restart osqueryd: the flags a rule reads are computed inside these queries, so until then
the new rule has nothing to read.

| Scheduled query | Every | Why |
|---|---|---|
| `listening_ports` | 1 h | services reachable from the network |
| `outbound_connections` | 1 min | which process holds which outside connection, and its parent |
| `process_signatures` (Windows) | 5 min | the code signature of every program that holds an outside connection, once per program |
| `startup_items`, `launchd`, `crontab`, auto-start services, scheduled tasks | 1 h | persistence |
| `chrome_extensions` | 1 day | browser add-ons |
| `sysmon_events` (Windows) | 1 min | Sysmon, as it happens: every process start with its parent and **command-line signals**, every outgoing connection and every DNS lookup, each with the program behind it |
| `software_programs` (Windows), `software_deb` / `software_rpm` (Linux), `software_brew` (macOS) | 1 day | installed software and versions, for the known-exploited check (`tapwatch software`). Windows keeps name, version and publisher only: a per-user program's install path holds the user's name |
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

On Linux the installer also turns on osquery's **eBPF publisher** (`config/linux.flags`), and
`bpf_connections` records every outgoing connection as it happens, with the same markers, so a one-second
`git fetch` or API call isn't missed between snapshots. It needs a kernel with BPF and BTF (4.18 or later;
WSL2's has both). Linux DNS lookups from WSL reach Windows through WSL's DNS proxy, so tapwatch gives each
lookup to the program that connected to one of its answers right after. eBPF learns a program when it
starts, so processes already running when osqueryd (re)starts come through without a path; tapwatch skips
those rows and relies on the 1-minute snapshots for them. After a reboot osqueryd starts first.

The markers are read from `/proc/<pid>/environ` when the query runs, up to a minute after the connection. A
one-second `curl` from a Claude Code shell has exited by then, and so has the shell that ran it, so its
`bpf_connections` row arrives with no markers and no parent name (measured 2026-10-15). `bpf_process_events`
therefore logs every program start as it happens (pid, parent pid, program; **no command lines and no
working directory**, both can name private things), and tapwatch walks that parent chain from the gone process up to the long-lived `claude` process
whose own rows still carry the markers, and credits the connection to that session. Measured 2026-10-16: the eBPF rows
carry *thread* ids, the shell under `claude` is spawned by one of its threads, and `process_envs` has no row for a
thread, so the agent's own rows can arrive with empty markers too (the agent's environment never holds
`CLAUDE_CODE_SESSION_ID` in any case: only its child shells do). The chain ending at the `claude` binary still counts
as the agent; the session is then taken from the transcript that named the destination, and the case stays
uncorroborated (the router does not lower it on that alone).

On Windows, command lines can hold passwords or tokens, and osquery's results log is readable by every local
account (osquery sets the file's permissions itself, and tapwatch has to read it without admin rights). So
`sysmon_events` turns each command line into yes/no signals inside osquery (an encoded payload, base64
decoding, download-and-run, Invoke-Expression, a hidden window, an execution-policy bypass, a URL) and logs the
raw text **only when a suspicious one fires**: encoded, base64, download-and-run or Invoke-Expression. tapwatch
redacts what it does get before storing it, and Jev never sees command lines, only facts such as "a document
app started PowerShell".
The agent also reports the PC's own addresses every 5 minutes (`host_addresses`). When DHCP gives the PC a new
IP, tapwatch follows it, so cases on the new address still get host context.
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
