# Results

_Measured 2026-10-13 with jev-1.13.0, `audience: office` wording. Reproduce the malware side with
`eval/public_captures.sh` and `tapwatch eval`._

## Summary

| | Rules only | With Jev |
|---|---|---|
| Infected hosts surfaced (alert or digest), 6 public captures | 4 / 7 | 4 / 7 |
| Infected hosts **alerted** | 2 / 7 | **4 / 7** |
| Home network, 14 h, all benign: items to read | 8 (digest) | 8 (digest) |
| Home network: false **alerts** | 0 | **0** |
| Jev cost for everything above | | $0.0008 |

Jev's measured value is **promotion**: it turned the FluBot and HtBot infections from digest items
into alerts, without adding false alerts at home. It did not reduce the number of items to read.
The eval's GO rule says so: Jev must cut noise *or* alert on more real threats, add no false
alerts, and lose no malicious host.

## Malware: Stratosphere Lab public captures

Real infections recorded by the Stratosphere Lab, CTU Prague (https://mcfp.felk.cvut.cz/publicDatasets/,
please cite them). Infected hosts come from each dataset's README. Only the `.pcap` files are
downloaded, and Zeek reads them in a container with networking off.

| Capture | Malware | Traffic from the infected host | Surfaced by | Rules only | Jev |
|---|---|---|---|---|---|
| CTU-297-1 | WannaCry (worm) | 9,900 conns in 16 min | `mgmt_access`: SMB to other hosts | alert | alert |
| CTU-373-1 | HtBot / Proxyback (proxy bot) | 10,900 conns over 33 days | `beaconing`: C2 every ~26 min | digest | **alert** (0.99) |
| CTU-407-1 | FluBot (Android banker) | 316 conns over 17 h | `beaconing`: 300 s keepalive¹ | digest | **alert** (0.78–0.82) |
| CTU-410-1 | Qakbot | 16 conns over 7 h | — | missed | missed |
| CTU-408-1 | (Android, fresco11) | 9 conns over 18 h | — | missed | missed |
| CTU-400-1 | Wacatac (trojan) | 55 conns over 53 h | — | missed | missed |

¹ FluBot's beat goes to a `www.facebook.com` address, more likely the phone's own keepalive than
FluBot's C2. It surfaces the infected phone, but the real C2 wasn't singled out.

The three misses have very small network footprints (9–55 connections in total). A network
sensor has little to work with there. That gap is what host context (osquery) is for.

## Home: one night of real household traffic (benign)

14 hours of a ~20-device home network, all hosts labelled benign. The first hour is warmup, a
deliberately harsh setting: production uses 24 hours.

| | Rules only | With Jev |
|---|---|---|
| Cases | 101 | 101 |
| Logged only | 93 | 93 |
| Digest | 8 | 8 |
| Alert | 0 | 0 |

The 8 digest items: 4 periodic connections (a game launcher, a smart-home hub, a work laptop's
web-host check, a OneDrive poll), one camera's vendor TLS pattern, one burst of failed WPAD lookups,
one new IoT device, and one work computer's 700 MB hour to its endpoint-security vendor.

### What tuning this took (same night, measured checkpoints)

| Checkpoint | Items to read | Jev false alerts |
|---|---|---|
| Before tuning | 26 | 4 |
| After four fixes together: numbered CDN hosts under popular domains aren't "random"; beaconing to a popular service other devices use → log; TLS oddities routed by code; uploads to cloud-sync services capped at digest | 8 | 1 |
| After counting devices by MAC (one machine's IPv4 + IPv6 had looked "shared") and capping uploads to endpoint-security vendors | 8 | 1–2 (a game launcher, borderline) |
| After requiring ≥ 0.75 confidence for Jev to alert on its own | 8 | **0** |

The last threshold comes from the data: real C2 scored 0.78–0.99 over three runs each, a game
launcher's update check 0.60–0.61. The margin above FluBot (0.78) is thin; it's configurable as
`thresholds.alert_confidence`.

## What to keep in mind

- **Small sample.** Six malware captures and one night at one home. Treat these as a sanity
  check, not a benchmark.
- **Sandbox captures start infected.** Rules that learn a baseline (new ports, IoT drift, TLS
  oddities, hourly profiles) learn the infection as normal on these captures, so they're
  under-represented here. In a real home the device is clean while tapwatch learns.
- **Jev isn't deterministic.** Borderline cases move between digest and alert across runs; the
  figures above are single runs, with three-run checks where a threshold depends on them.
- **Wording.** All Jev numbers use the `office` framing. `home` hasn't been measured yet.
