# tapwatch docs

Start with the [project README](../README.md) for what tapwatch does and how to install it.

## Design

- [ARCHITECTURE.md](ARCHITECTURE.md): how it's built and why. Covers data flow, components,
  case routing and its guardrails, host context, state, the security and privacy model,
  deployment, testing, and the key design decisions.
- [detections/DESIGN.md](detections/DESIGN.md): the detection catalogue (R01–R16). Each rule has
  its threat, fields, logic, baseline, expected false positives and how Jev is (or isn't) used,
  with the home measurements behind the thresholds.
- [detections/rules/](detections/rules/README.md): Sigma and DuckDB SQL versions of the rules,
  for hunting and as specs.

## Setup guides

- [setup/mirror-port.md](setup/mirror-port.md): configure a managed switch to mirror the router port
- [setup/router-syslog.md](setup/router-syslog.md): send the router's IPS and admin events to tapwatch, and when Suricata adds anything
- [setup/windows.md](setup/windows.md): run tapwatch on a Windows PC (Npcap + WSL)
- [setup/omarchy.md](setup/omarchy.md): run tapwatch on an Omarchy (Arch Linux) computer, or move an install to one
- [../agents/README.md](../agents/README.md): endpoint agents (osquery, plus Sysmon on Windows) for host context

## Evidence and plans

- [../eval/RESULTS.md](../eval/RESULTS.md): eval method, numbers, tuning history and caveats
- [ROADMAP.md](ROADMAP.md): milestones built for v0.1, and what's planned next

## Project

- [../CONTRIBUTING.md](../CONTRIBUTING.md): development setup, the no-real-traffic rule, adding a detector
- [../SECURITY.md](../SECURITY.md): private vulnerability reporting
