# Other computers: a Fleet server

tapwatch's endpoint rules (R17–R39, R48) read the osquery agent on the computer tapwatch runs on. To cover the
house's other computers, run [Fleet](https://fleetdm.com) (open source) next to tapwatch and enroll their agents in
it. Fleet hands every agent tapwatch's scheduled queries and writes all their results to one log on this computer.
tapwatch follows that log and reads each computer with its own set of host rules: its own address, its own first-day
inventory, its own learning week. Each computer's cases land in the case desk under its address, like any other
device's.

## 1. Run Fleet

On the computer that runs tapwatch, from the tapwatch checkout:

```bash
cp deploy/fleet/env.example deploy/fleet/.env      # fill in the two secrets: openssl rand -base64 32
mkdir -p deploy/fleet/logs                          # as you, first: Docker would create it owned by root
docker compose -f deploy/fleet/docker-compose.yml --env-file deploy/fleet/.env up -d
```

This starts Fleet, MySQL and Redis. Fleet listens on `127.0.0.1:8412` only. Its results log lands in
`FLEET_LOG_DIR` (default `deploy/fleet/logs`; if you set another, create that one first too). Fleet writes it as
`FLEET_UID`/`FLEET_GID` in `.env` (default 1000): if `id -u` and `id -g` say otherwise for the account tapwatch runs
as, set them, or tapwatch can't read the log.

## 2. HTTPS through Tailscale

The agents only talk to Fleet over HTTPS. The simplest certificate is Tailscale's. On the tapwatch computer
(Windows + WSL: the Windows `tailscale.exe`), pick a free port:

```bash
tailscale serve --bg --https=10004 http://127.0.0.1:8412
```

Fleet is now at `https://<this computer>.<tailnet>.ts.net:10004`, inside your tailnet only. Every computer that
reports to it needs Tailscale too. In return, laptops keep reporting away from home, and no certificate file has
to be copied anywhere. Put that address in `deploy/fleet/.env` as `FLEET_URL`.

**A computer that should only report.** If your tailnet policy allows everything (Tailscale's default), any
enrolled computer can also reach every other device on your tailnet. For one that only needs to report (a laptop
you look after, an office PC), give it a tag and replace the allow-all rule with grants, so the tag can reach
Fleet's port on this computer and nothing else. For example:

```json
"hosts": {"sensor": "<this computer's Tailscale IP>"},
"tagOwners": {"tag:report-only": ["autogroup:admin"]},
"grants": [
  {"src": ["autogroup:member"], "dst": ["*"], "ip": ["*"]},
  {"src": ["tag:report-only"], "dst": ["sensor"], "ip": ["tcp:10004"]}
]
```

Then give that computer the tag in Tailscale's admin console (Machines, the computer's menu, **Edit ACL tags**).
To check: from it, Fleet's address still opens and other tailnet devices no longer answer.

**The house's own public address.** Tailscale peers on the same LAN also try to reach each other through the
house's public address, about once a minute, which the network rules would otherwise read as beaconing to the
internet. Put that address in `config.yaml` under `network.public_ips` (see `config.example.yaml`; leave it empty
behind CGNAT), and update it if your ISP changes it.

## 3. First sign-in and tapwatch's queries

Open the address and create the admin account. Then, with
[fleetctl](https://fleetdm.com/docs/get-started/anatomy#fleetctl) logged in:

```bash
fleetctl config set --address http://127.0.0.1:8412 && fleetctl login
fleetctl apply -f deploy/fleet/tapwatch.yml      # tapwatch's queries and agent options
fleetctl user create --api-only --name tapwatch --email tapwatch@example.com --password '<long random>' --global-role admin
```

Put the token the last command prints in `deploy/fleet/.env` as `FLEET_API_TOKEN`. In Fleet's settings, it's worth
turning usage statistics off.

`deploy/fleet/tapwatch.yml` is generated from `agents/config/osquery.conf` (`tools/fleet_config.py`; a test keeps
the two the same). After an upgrade that changes the queries, apply it again: every agent picks the change up within
minutes, with no reinstall.

## 4. Point tapwatch at the results

In `config.yaml`:

```yaml
fleet:
  results_log: deploy/fleet/logs/osqueryd.results.log   # FLEET_LOG_DIR, plus the file name
```

Then `systemctl --user restart tapwatch-alerter`.

## 5. Add a computer

```bash
deploy/fleet/agent-bundle.sh          # writes ~/tapwatch-agent.zip
```

Not the computer tapwatch runs on: its agents stay standalone. An enrolled agent sends its results to Fleet
instead of its local log, and tapwatch's rules and host context for this PC read that log.

Copy the ZIP to the other computer (it holds the enroll secret, so copy it directly and delete it afterwards). Make
sure Tailscale is signed in there. Then unzip it and:

- **Windows:** double-click `tapwatch-agent\install.cmd`. It installs osquery and Sysmon with tapwatch's config and
  enrolls in Fleet. On Windows 11 26H2 and later it turns on Windows' built-in Sysmon, which needs one restart
  before its log starts; the installer says so.
- **Linux or macOS:** `tapwatch-agent/install.sh`.
- **Many Windows PCs, from Intune, an RMM or PDQ:** deploy the unzipped folder and run `install-silent.cmd` as
  SYSTEM. It installs without prompts, logs to `%ProgramData%\tapwatch\agent-install.log`, and returns 0, 1, 1618 or
  3010 (restart pending). An office behind a proxy adds `PROXY=host:port` to its `agent.env`. Details:
  [agents/README.md](../../agents/README.md#deploying-with-a-management-tool).

The computer shows up under Hosts in Fleet within a minute, and its rows in tapwatch's log soon after. Give it a
name in `assets.yaml` so its cases say which computer it is.

## What's different from the PC tapwatch runs on

- **Host context**, the "which program made this connection" on network cases, still covers only the tapwatch
  computer. Other computers get the endpoint rules; host context for them is the next step of #14.
- **Feed silence (R22) doesn't watch Fleet's agents.** A computer that's switched off isn't a broken feed. Fleet's
  Hosts page shows which ones are offline.
- **The eBPF queries can be skipped for a day.** Standalone, `bpf_connections` and `bpf_process_events` are never
  denylisted. Fleet's query settings have no such switch, so an agent restart that catches one mid-run can make
  osquery skip it for a day.
