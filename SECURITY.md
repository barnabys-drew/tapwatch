# Security policy

tapwatch handles hostile input (anything on the network) and runs with access to your network
traffic, so security reports are welcome.

## Reporting a vulnerability

Please **don't open a public issue**. Use GitHub's private reporting instead: the repository's
**Security** tab → **Report a vulnerability**. Include what an attacker controls (a domain, a DHCP
hostname, a syslog line...), what happens, and a minimal reproduction with synthetic data.

You'll get an acknowledgement within a week. Fixes for confirmed issues go out as a patch release
with credit, unless you'd rather stay anonymous.

## Especially interesting

- Text from the network that changes what Jev decides, beyond the case it describes (prompt injection)
- Escaping gaps in the case desk, notifications or email (links, script, markup)
- Ways around the case desk login or CSRF protection
- Spoofed router syslog that suppresses or downgrades a real alert
- A state file that makes `tapwatch import-state` write anything beyond the files it names
- Anything that sends internal addresses, MACs or packet contents off the network

## Supported versions

Only the latest release. `tapwatch update` (or `update-windows.cmd` on Windows) moves a checkout install to it;
with Docker, `git pull` and rebuild (`docker compose -f deploy/docker-compose.yml up -d --build`).
