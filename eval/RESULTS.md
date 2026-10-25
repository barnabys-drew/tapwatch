# Results

_Measured 2026-10-13 with jev-1.13.0, `audience: office` wording (the default; see [Wording](#wording-office-vs-home)
for why). Reproduce the malware side with `eval/public_captures.sh` and `tapwatch eval`._

## Self-check (scripted, every run)

`tapwatch selfcheck` pushes synthetic shapes through the detectors built exactly as `run` builds them from the
box's config, rules only (37 today: 32 attack shapes and 5 quiet ones). It started with 18: 15 attack shapes the owner used to stage by hand (a 60 s heartbeat, a port scan, an
admin-port sweep, a DNS tunnel, internet exposure, a rogue DHCP server, a callback-catcher lookup, a cleartext FTP
login, DNS bypass, a bare-address TLS stack, and the five endpoint rules R17, R19, R20, R21 and R22) and 3
false-positive shapes whose detector must raise nothing (the split UDP voice call of #63 against beaconing,
WebRTC media of #417 against tls_odd, reset-after-data ad sessions of #363 against scan). It prints one line per
shape and a detection rate, and exits 1 on a regression; `tests/test_selfcheck.py` runs the same corpus on an
empty config in CI, so that number is comparable across machines, while the command's number reflects the box's
own tuning. Added 2026-10-17 at 15/15 detected, 3/3 quiet; 17/17 and 4/4 since R23 the same day, 19/19 since R24, 20/20 with the jitter tier (5 obscure jittered digest items in two days of home traffic), 22/22 with R25 and R26, 24/24 with R27, 25/25 with R28, 26/26 with R29, 27/27 with the Linux pass 2, 28/28 with R36, 30/30 with R37 and R38, 31/31 with R39, and 32/32 and 5/5 now, with R48 and its patched-browser quiet shape.

## Summary

_The running numbers (week-by-week noise rate, Jev agreement with the owner's dispositions, host-context
accuracy) come from `tapwatch benchmark`; the stats page shows the same tables._

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

## First week on a live network, and host context (#4): 2026-10-13 to 2026-10-20

One home network (a UniFi gateway, about 20 devices seen on the mirror), the alerter, router syslog and both endpoint agents (Windows
with Sysmon, Linux/WSL with eBPF) running all week; every case triaged by the owner. `tapwatch benchmark` on
2026-10-20:

| week | cases | alerts | decided | noise rate | true positives | Jev agreement |
|---|---|---|---|---|---|---|
| 2026-W42 | 868 | 337 | 868 | 100% | 2 | 26% (147) |
| 2026-W43 | 64 | 1 | 61 | 98% | 1 | 75% (20) |

Host context: 137 cases on the PC, 0 corroborated. Code said agent_unconfirmed 25, other_program 107, unknown 5.
Jev agreed with code on 74% of 136 it was asked; code made no benign-or-hostile claim, so there was nothing to
score against the owner's disposition (the command prints "– of 0").

**One day is a bug, not traffic.** 338 of W42's cases (252 of its alerts) are one detector on 2026-10-17: the
Windows agent's log rotates in place on the Windows drive (same inode), the follower re-read it from the start,
and every encoded PowerShell command already seen came back as new. Fixed the same day. Without it, the
week (2026-10-13 to 10-19) is **531 cases, 36 alerts (about 5 a day), all 531 decided: 529 noise, 2 true positives**:

| | cases | alerts |
|---|---|---|
| new_domain | 346 | 6 |
| beaconing | 62 | 5 |
| dns_anomaly | 22 | 2 |
| scan | 20 | 3 |
| tls_odd | 14 | 0 |
| upload_spike | 10 | 4 |
| endpoint rules (R17-R29: persistence 21, LOLBins, temp-folder and encoded commands, the Linux rules, a signature) | 34 | 11 |
| everything else (new device, cleartext login, DNS bypass, management access, router admin, takeover, feed silence) | 23 | 5 |

The two true positives both went to the digest, not an alert: a device polling one plain-HTTP server every
10 minutes (#395, beaconing), and the Linux agent's process feed going silent for 16 minutes (#890, R22). The
endpoint rules' 11 alerts include the live tests of R21-R29 run that week. Monday 10-19 had one alert.

**What host context did.** In the same week (to 10-19; the benchmark's 137 includes one case from 10-20), 136
cases on the PC got a host-context answer: 106 named a program other than the owner's coding agents as the one
holding the connection, 25 found an agent running but couldn't confirm it held the connection, 5 found nothing.
The owner closed all 136 as noise (118 expected, 18 false positive). The answers that make a
claim about intent, "the owner's agent did this" (benign) and "an agent was misused" (hostile), never fired on
real traffic, so **the verdict side has no measured accuracy yet**: there is nothing to have been wrong about,
and nothing proven right. No call was wrong, so #4 opened no issues.

**What this settles for #4.** Attribution, naming the program behind a connection, ran on every PC case for a week
and named one for most of them (106 of 136). It was checked against ground truth on staged shapes (a one-second
`curl` traced to the agent that ran it on 2026-10-16, a tampered binary's connection on 10-17); on this week's
real cases the owner's review found nothing that contradicted a named program, but didn't check each one, so
that is consistency, not measured accuracy. It is no longer labelled experimental (since 2026-10-17). The intent verdicts stay unmeasured until
a real agent-driven or hostile case happens; `tapwatch benchmark` will show the first one. Jev agreed with the
owner on 26% of decided W42 cases it categorised and 75% in W43, on small numbers (147, then 20).

## Daily summaries (#193): 12 days of home logs, measured 2026-10-25

`tapwatch summarize` over the home sensor's rotated Zeek logs of 2026-10-13 to 10-24 (4.8 GB, all logs; conn, dns
and ssl are 4.3 GB of it), into a copy of the alerter's database, on the old sensor PC (WSL, one core busy).
The first and last days are partial (the capture started and ended mid-day: 7 and 13 local hours).

| | Measured |
|---|---|
| Time per full day | 22–31 s (median 24 s) for 77k–146k internet connections; this includes reading the next day's conn logs for long connections |
| Nightly cost | about 1 min: the day just finished, and the day before built again once its long connections are logged |
| DB growth per day | 0.38–0.51 MB (about 2,400 destination rows and 21 devices a day); 90 days ≈ 36 MB |
| Peak memory | 163 MB, the IP-to-network table included |
| 30-day query per device (`device_day` + `device_day_dest`) | 12 real days: median 0.2 ms, worst 8.7 ms (6,700 rows). Padded to 30 days by repeating real days: median 0.6 ms, worst 21 ms (16,800 rows); the same with 90 days in the tables |
| Devices with ≥ 10 summarized days | 20 of 29 device keys (22 have ≥ 7) |

Stdlib SQLite is far inside the one-second budget, so DuckDB/Parquet is not needed. 29 keys for about 22 devices a day:
devices first seen under a MAC before their DHCP name was learned, and phones with private (rotating) MACs, each
count as a new device. The 14-day maturity the long-horizon rules wait for is reached by the devices present every
day.

**Long connections.** Zeek logs a connection when it ends, stamped with its start. Reading only 3 h past midnight
missed 0 to 31 connections a day (0.03% at most), but on 2026-10-20 one of them was a 1.5 GB session logged the next
day, 3% of that day's bytes, the kind of total R31 sums. So each day is built twice: the night after, and again once
24 h more of logs are in; with that, the 2026-10-20 totals match a direct pass over conn.log (136,422 connections).

**Log names.** 174 of the 266 conn files from before 2026-10-20 23:09 carry their close time four more times after the
open time (`conn.<open>.<close>.<close>.<close>.<close>.log`); `zeek.ROTATED` did not match them, so replay, the
evidence lookup and `prune` all skipped two thirds of those days. It reads the first stamp now.

## Long-horizon rules R30, R31 on 11 days of home summaries (2026-10-25)

`tapwatch summarize --from 2026-10-13 --to 2026-10-24` over the same home logs into a scratch database (10-13 was
skipped as the sensor's first, partial day), then `tapwatch longhaul --stats`, which stores nothing. Eleven days is
under the 14-day maturity, so the runs lower it with `--mature-days`. Nothing live was read or written: the scratch
database has no saved Beaconing state, so R30's "already reported by beaconing" skip never applied here.

| | Measured |
|---|---|
| Summarized days | 11, all watched (12+ local hours with traffic; the last day 13 hours, the rest 21–24) |
| Device keys | 31; 27 mature at `--mature-days 5`, 26 at 10 |
| Evaluation time | 0.25 s for both rules over 25,600 destination rows; 2.1 s more to load the popular list and the ASN table |
| R30 `slow_beacon`, timing test passed | 20 (device, destination) pairs on 9 devices, all steady (CV ≤ 0.2), none on the daily-at-the-same-time branch; median gaps 2–6 h: 5, 6–23 h: 5, 23–25 h: 5, over 25 h: 5 |
| R30 cases | **1** (same at maturity 5 and 10): the other 19 are popular destinations. The one left is an app's vendor check-in every 3 h, an expected false-positive class (vendor domain not on the popular list). Routed digest, unbacked |
| R31 `slow_upload`, as specified | **0** cases: 5 (device, destination) pairs pass the volume, steadiness and ratio tests, and all 5 are skipped because there are no days before a 14-day window to call a destination new. With that test switched off (`baseline_days: 0`), all 5 are popular destinations other devices also use |
| R31, scaled to the data | 7-day window, 4 days before it, ≥ 50 MB on ≥ 4 days: **1** case, one device's steady upload (about 240 MB in a week, 8× its download) to its vendor's cloud, popular but used by that device alone, digest; 6 more were skipped as already uploaded to before the window |

On this data both rules land inside their targets (#194: ≤ 3 digest items a week; #195: ≤ 2), and both cases found
are benign, of the classes the issues expected. It is not yet the issues' measure: that is 30 home days with each
case dispositioned, and R31's "new destination" test cannot be judged until the sensor has three weeks of
summaries. Re-run `tapwatch longhaul --stats` on the live sensor once it has 30 days.

## Long-horizon rules R32-R34, replayed over the same home days (2026-10-25)

The same 11 days of home summaries, rebuilt into a scratch database (nothing live read or written; deleted after),
then replayed night by night (`longhaul.evaluate(as_of=...)`, which `tapwatch longhaul --as-of` exposes), each day
judged once, with a case counted once per its rule's dedupe window. The scratch database has no saved identity
table, so the replay seeded one from the same logs' DHCP records; that also exercised the key aliases (one device's
`mac:` and `name:` histories merged). Evaluating all five rules takes 0.47 s over 25,600 destination rows.

| | Measured |
|---|---|
| As specified (maturity 14) | **0** cases from any rule: no device can have 14 watched days in 11 |
| R32 `rare_dest`, maturity 3, 8 nights (10-17..24) | 16 (device, network, day) contacts with no name to a network new to the device. 12 were to a network another device in the house also used. Of the 4 left: 1 reached by name the same day, 1 under 3 connections and 1 MB, 1 a call on FaceTime's ports (one long session to a home ISP address), 1 a peer-to-peer shape (470 connections on scattered high ports to one home ISP address). **0 cases.** The first replay, before the media list had FaceTime and before the P2P-shape skip, raised exactly those last two: both P2P/media, the class #196 expected |
| R32 peer variant | assets.yaml gives two peer groups of three (an "iot" and a "network gear" role); none of their devices reached a new country. The 14 new-country days on fixed-function devices were all on devices with fewer than two same-role peers. **0 cases** |
| R33 `dormant_wake` | **cannot be judged yet**: 14 active days plus 14 quiet ones need 28+ days. Scaled to 2 watched quiet days and 3 active days before: 2 dormancy returns, neither brought 3 new networks or a new port: **0 cases**. Scaled further (1 quiet day, 1 new network): 3 returns, 1 case. Before high UDP ports stopped counting as new ports, one return fired on seven of them (a P2P peer) |
| R34 `routine_shift`, maturity 5 | the 7-day baseline leaves 2 nights (10-23, 10-24) to score: 36 device-days, **0 cases** |
| R34, baseline lowered to 4 days | 99 device-days over 5 nights, **0 cases**. Before the fixed-function "new port every day" branch was limited to TCP and low UDP ports, it raised 1: a busy fixed-function device's P2P peer on one new high UDP port three days running |
| R34 score spread (99 device-days) | hours (Jaccard distance): median 0.0, p90 0.63, p99 1.0. New-port share: median 0.0, p90 0.005, p99 0.58. Bytes z (log10): median -0.05, p90 0.8, p99 3.1. The floors (0.6, 0.2, 3.0) sit between p90 and p99; each device's leave-one-out maximum raised them further for every device here |

So on this data all three rules stay inside their targets (#196: ≤ 3 a week after media; #198: ≤ 2 a week), and the
only things they raised before the skips were peer-to-peer and call traffic. That is a statement about 11 days and
a quiet house, not a validation: R32's "nobody in the house used it in 30 days" here means "in up to 10 days",
R33 has had no real dormancy to see, and R34's thresholds need the 30-day re-measure (#198 wants per-device
distributions over 30 days). The last day was only 13 hours watched, which is why the bytes median is below zero.

## Re-run 2026-10-15, after the noise review

Same captures, same home night, same model, after the day's detector changes (per-VLAN DHCP learning,
benign beacon classes and the popular-only cap, per-destination beacon reporting, UDP-aware scan,
outcome-based management-plane severity plus the admin-port sweep, device identity, and the rest).

| | 2026-10-13 rules / Jev | 2026-10-15 rules / Jev |
|---|---|---|
| Infected hosts surfaced (alert or digest), 7 labelled hosts | 4 / 4 | 4 / 4 |
| Infected hosts **alerted** | 2 / **4** | 1 / **2** |
| Home night: items to read | 8 / 8 | 10 / 10 |
| Home night: false alerts | 0 / 0 | 1 / 2 |
| WannaCry: cases raised | 86 | **10** |

What changed, and why each is kept:

- **WannaCry** went from 82 management-plane cases (each an alert) to one severity-5 **admin-port
  sweep** alert plus 4 digest probes: the worm shape is the signal, not each probe. Its second
  labelled host made one *accepted* SMB session, which is now severity 3 (digest); as a single
  event that is also what a PC opening a share on the NAS looks like. Jev no longer promotes it.
- **FluBot** lost Jev's promotion. Its beat goes to a `www.facebook.com` address, which the 10-13
  notes already called the phone's own keepalive rather than the C2; the popular-destination cap
  now holds it at digest by design (popular services are C2 channels too, so digest, never log).
  The infected phone still surfaces.
- **Home night**: 2 more digest items, because beaconing now reports per destination (a work
  laptop's two vendors on one port were one case before) and no longer silences a port forever.
  The rules-only "false alert" is `takeover`: TeamViewer present on a work laptop, seen over TLS.
  The labels call the whole night benign; the detector is right that a remote-control tool is
  there, and `takeover.expected` is how an owner declares it. Jev's second alert is a beaconing
  digest item it promoted.

The GO rule is unchanged and Jev still passes it on the captures where it mattered (HtBot).
The eval's own blind spot is that it scores labels, and this night's labels predate the
remote-control rule; the correct fix is a labelled `expected` entry, not a softer detector.

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

## Wording: office vs home

`audience` frames the case summaries and Jev's questions for an office ("how urgent is this for
the business?") or a home ("...for the household?"). Measured 2026-10-14: the six captures and
the home night, three runs per wording, identical configs otherwise.

| | `office` | `home` |
|---|---|---|
| Infected hosts **alerted** (of 7), each run | 4, 4, 4 | **2, 2, 2** |
| Infected hosts surfaced (alert or digest) | 4, 4, 4 | 4, 4, 4 |
| Home night: items to read | 8, 8, 8 | 7, 8, 8 |
| False alerts, all datasets | 1, 1, 1 | 1, 1, 1 |

`home` lost both of Jev's promotions in every run: FluBot and HtBot fell back to digest. Jev still
named them C2 beaconing; the household framing made it less willing to interrupt. Two runs per
case, FluBot / HtBot:

| Jev's answer | `office` | `home` |
|---|---|---|
| category confidence (c2_beaconing) | 0.78–0.79 / 0.99 | 0.67–0.69 / 0.96–0.98 |
| "page the owner now" | 0.78 / 0.85–0.87 | 0.55–0.57 / 0.64 |
| "routine activity" | 0.27–0.28 / 0.21 | 0.52–0.53 / 0.37–0.39 |
| route | alert / alert | digest / digest |

So the default stays `office`, even on home networks, and `tapwatch init` no longer asks (a home
user would answer "home"). The one false alert is a WannaCry-capture host that isn't in the
dataset's infected list; the rules alert on it without Jev too, so wording can't change it. Lowering the alert thresholds to
compensate for `home` would be tuning on two cases.

## The judge's guardrails on the live history (2026-10-25, #201)

`tapwatch judge backfill` then `tapwatch judge replay` on a copy of the live sensor's database: 1,205 cases from
2026-10-13 to 10-25. Each case is judged only with the closes made before it happened, and with today's facts, so
this is an estimate.

**Training set (#200).** The audit trail gave 1,199 examples. 715 count as precedent: 714 closes a triage session
made at the owner's request, and 1 made by the owner directly. 484 are kept but don't count: 380 closes an AI
session made on its own, and 104 of tapwatch's own (a suppression matched on arrival, or a patch resolved R48). The counted labels are 708 benign, 1 false
positive and 6 true positives, so the judge can learn "routine" and nothing about "dangerous". That's why it only
ever suggests closing.

**Eligible: 0 of 1,205, at both key widths** ("same device", and "any device", which needs precedent from at least
two devices with none giving more than half). **No true positive would have been eligible at either width.**

| Why not (same device) | Cases |
|---|---|
| No earlier owner close of the same host name, program or indicator on this device | 995 |
| A true positive on this device in the last 30 days | 126 |
| Only closes the owner didn't make (an AI on its own, tapwatch's own) | 22 |
| Critical code-only alert, code floor, always-alert, misused agent | 48 |
| Owner precedent, but on only 1–2 days (3 needed) | 14 |

Two shapes of the history explain the zero:
- **The owner closes in batches.** The median close came 12 hours after the case.
- **Repeats are bursts.** The biggest repeating key, one program's encoded commands, happened on essentially two
  days: a flood on 10-17 (partly the duplicate-alert bug fixed in #303) and a few on 10-24. Its 264 closes all came
  after the flood, so no case in it had precedent when it happened.

Loosening the rules shows how little exact precedent there is. Precedent over 2 days, with no week cap and no
labelling-day cap, made 2 cases eligible on the same device; any single day made 14 (3 at "any device"). No true
positive became eligible either way.

The shadow judge (#202) records both widths for every new case from now on, and the scorecard (#203) will show, per
detector, whether a wider key ever would have closed a real case.

**Two day caps, not one.** #201 asked for distinct *labelling* days, but the owner closes in batches, so a week of
cases counts as one day. Counting only the days the cases *happened* fixes that, but the review found it lets one
sitting teach the judge: an attacker chooses when its cases happen (a slow beacon once a day), and a single bulk
close, explain Apply or triage session would label them all at once. So precedent needs both: cases on 3 distinct
days, and owner closes on 2 distinct days.

**Narrow keys.** The key is the full host name, not the registrable domain, so one tenant of trycloudflare.com or
github.io doesn't vouch for another. A program is keyed by its full path when host context knows it. A true-positive
label on the same key blocks the judge from any source, including an AI's or tapwatch's own.

## What to keep in mind

- **Small sample.** Six malware captures and one night at one home. Treat these as a sanity
  check, not a benchmark.
- **Sandbox captures start infected.** Rules that learn a baseline (new ports, IoT drift, TLS
  oddities, hourly profiles) learn the infection as normal on these captures, so they're
  under-represented here. In a real home the device is clean while tapwatch learns.
- **Jev isn't deterministic.** Borderline cases move between digest and alert across runs; the
  figures above are single runs, with three-run checks where a threshold depends on them.
- **Wording.** All Jev numbers use the `office` framing, which measured better than `home`
  (see [Wording](#wording-office-vs-home)).
