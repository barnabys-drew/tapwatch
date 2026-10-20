# tapwatch home detections: design

_Written 2026-10-12 as a design, before the rules were built. Status as of v0.1: R01–R07 and R09–R16
are built in `src/tapwatch/detectors.py`, and R08 is the code-routed `new_domain`. See
[Built in M2](#built-in-m2-2026-10-13-what-changed-from-the-specs-above) for how the code differs
from these specs, and [ARCHITECTURE.md](../ARCHITECTURE.md) for how cases are routed. R17–R21, the
first [endpoint rules](#endpoint-rules-r17r21-what-the-pc-itself-says-built-2026-10-15-hostrulespy), were
designed and built 2026-10-15 in `src/tapwatch/hostrules.py` (issues #26, #27)._

**Scope.** This is a home network with limited telemetry. There is no EDR raw-event
feed (no CrowdStrike FDR or Sysmon pipeline) and no SaaS audit logs (no GitHub,
M365 or Google audit). The data is network-centric: **Zeek on the mirror port**
plus **UDM Pro syslog**. Those richer feeds normally supply judgment, such as
"which process opened this socket?" or "did the owner do this?". Here, code
computes the facts and **Jev** gives fast triage over them: `choice`, `score`
and `noul` questions on a short, IP-free summary. Each rule below says which Jev
questions it would ask, or why code alone should decide.

**Jev's measured weak spot** (2026-10-11/12): Jev cannot judge whether a *new
domain* is normal. It called herdr.dev, bleepingcomputer.com and
www.example.com `c2_beaconing` at 0.5–0.95 confidence. The rule that follows: **Jev never answers
"is this name, IP, ASN or country normal?"** Code answers those from Tranco,
household prevalence, newly-registered-domain lists and per-device history. Jev
gets the *outcome* as words ("the destination is new for this device, is not on
the popular-domain list, and no other household device uses it") and judges the
*behaviour*. It is used for the shape of the activity, the device role and its
urgency.

---

## 1. Measured baseline (read-only, `eval/data/home-mirror-20261012/`)

Measured with `docs/detections/baseline.py`, which prints aggregates and device
ranks only. **Caveat: the capture was still running.** These numbers cover
**0.82 h of a weekday evening** (about 16:23–17:12). Re-run the script on the full
14 h night and over 7 days before fixing any threshold. The overnight
first-seen rate is still unknown.

| Measure | Value |
|---|---|
| Devices originating traffic | 21 IPv4 (+14 rotating IPv6 link-local addresses, ignored). DHCP saw 5 MACs renew in this window |
| Devices with internet traffic | 16 |
| Outbound conns/h, whole house | ~4,800 |
| Outbound conns/h per device | median 67, max 2,075 (main PC) |
| Busiest uploader | cloud video camera, **~340 MB/h up**, steady; next is main PC at 23 MB/h |
| Busiest downloader | phone at 527 MB/h, main PC at 317 MB/h |
| Distinct outbound proto/port pairs | **14** for the whole house (tcp/443, udp/443, udp/3478, udp/123, tcp/80, tcp/1883, tcp/5223, tcp/5228, and a few vendor ports each used by **one** device) |
| Outbound duration | p50 0.5 s, p99 610 s, max 2,735 s; **0 connections > 1 h** |
| DNS (port 53) | ~6,700 queries/h; 12 clients use the UDM resolver; 584 distinct names; 138 NXDOMAIN |
| NXDOMAIN per device | max ~11 per 10 min (a remote-access agent retrying one dead name; WPAD lookups) |
| DNS bypassing the UDM | 24 queries, **1 device** (the cloud camera hardcodes a public resolver) |
| VPN resolvers | 12 queries from the work laptop to its corporate resolver |
| DoH/DoT by SNI or port 853 | **0** |
| TLS rows | 3,076; **22% have no SNI**, but only 43 of those completed a handshake |
| TLS cert "invalid" | 49 `unable to get local issuer certificate`, all from Windows hosts to big CDNs (Zeek's missing intermediates, not attacks) |
| JA3/JA4 | **not present** (the Zeek package isn't loaded) |
| Established outbound TCP to an IP no DNS answer explains | 17 of 2,303 (0.7%), from 4 devices |
| Cleartext auth | 0 HTTP auth, 0 ftp/telnet/pop3/imap; **cleartext MQTT to the internet** from the smart-home hub (tcp/1883) |
| Inbound internet → LAN | 3 rows, all unanswered P2P/STUN; 0 established services |
| UPnP/NAT-PMP to UDM | main PC: 155 NAT-PMP/PCP and 102 SSDP requests (games and chat apps asking for port maps) |
| UDM management plane (tcp/443, 22) | **only the main PC** touched it; UniFi gear uses 8080/7444/6666/5514 |
| First-seen (device, base domain) | 241 pairs, 167 base domains in 50 min. Per 10 min: **135, 35, 23, 28, 20** (the first bucket is warmup) |
| …of which in Tranco top-100k | 160 of 167. Only **7** base domains were off the popular list, and 124 were used by only one device |
| Zeek log volume | ~17 MB/h raw, about 0.4 GB/day, about 12 GB/month before compression |

What these numbers imply:
- **After warmup, an active evening makes ~20–35 first-seen domain pairs per 10 min, about 150/h.**
  First-seen domains cannot alert on their own. With Tranco plus household
  sharing, the residue is about 7 per hour. That residue is still too much to alert on, so it goes to the digest.
- **Port and duration profiles are very tight.** Fourteen proto/port pairs house-wide, and no
  connection over an hour. Odd-port and long-lived rules will be high-signal.
- **The cloud camera dominates uploads, and that is normal.** Per-device baselines are essential;
  one house-wide threshold would be wrong for every device.
- Correction to an earlier note: on the mirror, the **main PC does use plain DNS to the
  UDM** (about 1,200 queries in the window). The earlier "DNS blind" finding came from
  the WSL capture, not from the PC itself.
- Zeek analyzer noise to suppress: the IRC analyzer fires on UniFi's tcp/6666
  (`irc_*` weirds, IRC in known_services), and `SSL::Invalid_Server_Cert`
  fires on Windows CDN traffic.

---

## 2. Log-source inventory

| Source | Sees that others can't | Cost to collect | Rules it unlocks |
|---|---|---|---|
| **Zeek on the USW mirror (port 23 ← uplink port 1)** | Every LAN↔internet and inter-VLAN flow, pre-NAT (real device IPs). DNS to the UDM, TLS SNI and certs, HTTP, DHCP broadcasts, MQTT, SSDP/NAT-PMP requests | Already running. ~17 MB/h. One PC, Npcap and Docker; the PC must stay awake | R01–R10, R12–R15 |
| **UDM Pro syslog / SIEM (CEF)** | UDM's own events: admin and SSH logins, config changes (port forwards, firewall rules), UPnP mappings *granted*, IPS (Suricata) alerts, firewall drops, Wi-Fi client connect/disconnect with AP/SSID, DHCP leases (including devices on the UDM's own ports) | Free. One UDP listener in tapwatch plus a CEF parser. Tens of KB/h. Enable it under the UniFi Network SIEM/syslog integration (the menu moves between versions; verify) | R01 (mapping granted), R05 (Wi-Fi joins), R11, R14 (lease source), IPS pass-through |
| UDM NetFlow/IPFIX | Flows from devices **plugged into the UDM's own LAN ports** (not on the mirror) | Free, sampled, no names | Volume and port profiles for those few devices only. **Skip** unless something lives on a UDM port |
| Windows Security/Sysmon on the main PC | Process ↔ socket (which app beaconed), logons, new services, PowerShell | Sysmon install plus a forwarder; ~1 GB/day; covers **one** of 21 devices | Turns "the PC beacons" into "which process". **Defer:** it's EDR-lite for one box, which is out of the stated scope. _Superseded 2026-10-15: the endpoint agent reads Sysmon through osquery, with command lines reduced to signals on the PC; host context and R17–R21 run on those rows_ |
| UniFi Protect | Camera motion and stream events, NVR health | Webhooks or API | R09 context: upload stops while Protect says the camera is online. Low priority |
| Offline enrichment feeds (pull-only) | ASN and country per IP (iptoasn.com TSV or a GeoLite2 ASN DB), Tranco (already have it), daily newly-registered-domain (NRD) list, OUI vendor table | Daily download. **Nothing about the house is sent out** | R02, R08, R05 vendor, R10 |

**Blind spots (by design of the tap):**
- **IPv6 needs the LAN's prefix.** Private IPv4, link-local and unique-local IPv6 are built in; a device's
  *global* IPv6 address is "inside" only if `network.local_nets` lists the prefix (`tapwatch init`
  proposes this machine's /64). Phones and laptops prefer IPv6 when the router offers it, so without
  it that traffic is invisible to every detector (fixed 2026-10-15; the 14 rotating addresses above
  were link-local, which was always inside).
- **Same-switch east-west traffic isn't mirrored.** PC → NAS on the same USW, or
  Wi-Fi client → client on the same AP, never crosses port 1. Only 75 device→device
  rows were seen, all of them cross-VLAN/routed. Lateral movement is visible only
  when it touches the UDM, crosses VLANs or is broadcast. Fix later with VLANs per trust zone,
  so IoT→LAN is routed and therefore mirrored, or with a second mirror on the AP uplinks.
- **Devices on UDM Pro LAN ports** are invisible to the mirror. Use UDM syslog or
  NetFlow, or move them to the USW.
- **Encrypted DNS / ECH / QUIC:** no DoH was seen today, but browsers can switch any time.
  QUIC rows have no server name in this Zeek build. If a device moves to DoH, R07
  catches the switch, and SNI (or a DNS answer) remains the naming fallback.
- **No MAC in conn.log.** Load Zeek's `policy/protocols/conn/mac-logging`
  so per-device identity survives DHCP churn.
- **No JA3/JA4.** Add the FoxIO `ja4` Zeek package before R10's fingerprint clause.

---

## 3. Storage and query engine: recommendation

**Recommendation: stay inside tapwatch.** Streaming Python detectors keep
per-device state in SQLite, which is already there. Add **DuckDB** as the batch and
hunting engine: it queries rotated Zeek JSON (`read_json_auto('conn.*.log.gz')`) directly.
There are no services, and it needs about 200 MB RAM per query and ~0 when idle. Rotate Zeek
hourly and keep 30 days gzipped (about 1.5–2 GB). Optionally convert to daily Parquet
later.

| Option | RAM/CPU on one PC or mini laptop | Upkeep | Stateful rules (baselines, first-seen, per-device, sequences) | Verdict |
|---|---|---|---|---|
| **tapwatch + SQLite + DuckDB** | <0.5 GB; ~1 core during queries | pip packages, no daemons | **Best fit**: Python state machines for streaming, SQL window functions for baselines | **Chosen** |
| Grafana Loki | ~1 GB | Low | Poor: LogQL is aggregation over streams. Per-entity first-seen or baselines are awkward | Only if you want dashboards |
| Graylog | ~6–8 GB (needs OpenSearch and MongoDB) | Medium | Pipelines plus lookup tables; per-entity baselines are clunky | No |
| Wazuh all-in-one | ~8 GB, 4 cores | Medium-high (indexer, manager, dashboard) | Rules are per-event plus frequency; weak on baselines; endpoint-agent centric | No (that's the EDR-ish path this scope excludes) |
| ELK / OpenSearch | 8 GB+ (JVM heap) | High: upgrades, mappings, ILM | Sequences (EQL) are good; baselines need ML (paid in Elastic) or transforms | Overkill for one house |
| Security Onion | ~16–24 GB+, 4+ cores; wants a dedicated box | High | Excellent hunting UI; alerting is still Suricata/Sigma per-event | Wrong size for a mini laptop |

The reasons: this is an alerting tool. The hard rules here are stateful per
device, such as first-seen per device, hour-of-week profiles and "IoT device's port set changed".
Those are natural in Python plus SQL and painful in Lucene, LogQL or Wazuh XML.
Jev routing already lives in tapwatch. A SIEM would add an 8–24 GB service tier
and still need tapwatch beside it.

---

## 4. How Jev is used in these rules

Each rule's case is triaged with **its own small question set**, instead of the
current single generic set in `triage.py`. One HTTP call carries every question,
and they are evaluated in parallel, so this costs no extra latency. Contract:

1. **Code computes every fact.** Counts, times, bytes, "new for this device",
   household prevalence, Tranco, NRD and ASN novelty all come from code. The summary
   states them in words with comparisons ("about 30 times its normal for this hour").
2. **Jev judges behaviour, not identity.** Allowed questions are:
   - `choice` over activity categories or device roles
   - `score` for urgency for this household
   - `noul` for statements such as "consistent with routine updates/backups/sync", "the owner should be woken
     up for this", or "consistent with what a <role> normally does"

   Jev is **never** asked whether a domain, IP, ASN or country is normal or reputable.
3. **Code-only** where the fact itself is the verdict (rogue DHCP, admin login
   from a new source, internet-exposed service, cleartext creds), and where
   Jev is measured weak (domain normality). These go in `router.CODE_ONLY` or are `must_alert`.
4. Untrusted strings (DHCP hostnames, SNI, HTTP UA, MQTT topics) are quoted
   and labelled as data, as `summarizer.py` already does.
5. Reframe the prompt for home: "household", "the owner", "wake them up". Today's
   prompt says "small business with one IT person".

Shared question bank (referred to by key in the rules):

| Key | Type | Text |
|---|---|---|
| `Q-cat` | choice | What kind of activity is this most likely to be? (benign / c2_beaconing / malware_delivery / data_exfiltration / recon_scanning / remote_access / policy_violation / device_malfunction / unknown) |
| `Q-sev` | score | How urgent is this for a household? (0 informational … 4 act now) |
| `Q-routine` | noul | This is consistent with routine automatic activity such as updates, backups, cloud sync or streaming. |
| `Q-role-fit` | noul | This behaviour is consistent with what a {device role} normally does. |
| `Q-wake` | noul | The owner should be interrupted right now to look at this. |
| `Q-role` | choice | What kind of device is this most likely to be? (phone/tablet, computer, TV/streamer, camera, smart-home hub/sensor, printer, game console, network gear, audio/AV, unknown) |
| `Q-human` | noul | This looks like a person using the device interactively, not an automatic background task. |

Routing stays in `router.py`. ALERT needs `Q-wake ≥ 0.7` **and** `Q-sev ≥ 2.5`,
or a code-only alert. LOG needs `benign` at ≥ 0.8 and `Q-routine ≥ 0.8`. Anything unsure goes to DIGEST.

---

## 5. Detection catalog (ranked)

Ranking is household value × visibility on this tap × low noise. "Device role"
comes from `assets.yaml`, seeded by R05. **Fixed-function** means camera,
TV/streamer, hub, printer, network gear and audio/AV: their profiles are stable, so drift means something.

### R01 Internet-exposed service appears (`exposure`) — **built**
- **Threat:** a port forward, UPnP/NAT-PMP mapping or a compromised device opening a
  listener that the internet can reach. This is the classic home compromise path.
- **Data:** Zeek `conn`: external `id.orig_h` → internal `id.resp_h`, `conn_state` in
  `SF,S1,S2,S3,RSTO,RSTR`, `resp_bytes>0`. Zeek `conn` udp/5351 and SSDP/`http` POSTs to the UDM
  show mapping *requests*. UDM syslog shows port-forward and UPnP *changes*: verified 2026-10-18 on a UDM Pro
  (UniFi Network 10.6.106), CEF `Config Created` / `Config Modified` / `Config Removed` with
  `UNIFIsettingsSection` "Port forwarding" (entry name; `UNIFIsettingsChanges` "fwd: …; fwd_port: …; proto: …",
  only the changed keys on modify, all blank on remove) and "Internet" with `upnp_enabled: true|false`. The
  case carries `router_forward` (how many minutes before, the access method, the source address; never the
  admin's name) or `router_upnp_on`; with the feed live it says no forward was made "since the router's log
  began <date>" (one made before then is unknown). Disabled forwards, ranges and lists are handled.
- **Logic:** `rules/R01-internet-exposed-service.sql`. First time an (internal host, port)
  accepts an established inbound connection from the internet. Joined with any mapping
  request from that host in the previous 24 h.
- **Baseline:** none needed. Measured: **0 established inbound services**, 3 unanswered P2P probes.
  A port forward the owner declares (`detectors.exposure.expected`: host, proto, port) counts as
  known from the start, like one seen during warmup; it is config, so the rule stays `must_alert`.
- **Dedupe:** `exposure|host|proto/port`.
- **FPs:** game/voice P2P (STUN on udp ephemeral ports), the main PC's NAT-PMP chatter.
  Suppress UDP to ephemeral ports when the same host did STUN (udp/3478) within 60 s.
- **Route:** ALERT, code-only. The fact *is* the verdict. Jev adds nothing, and the port is an attacker-chosen value.
- **Jev:** none. Optionally add `Q-cat` text to the alert body for context. It never gates.
- **Safe test:** temporarily add a UDM port forward to a harmless listener on the PC
  (`python -m http.server 8000`), then fetch it from a phone **on cellular**. Remove the forward afterwards.

### R02 Fixed-function device egress drift (`iot_drift`) — **built**
- **Threat:** a compromised camera, TV or hub (botnet, proxyware, residential-proxy SDK)
  starts talking to new networks or ports.
- **Data:** `conn` (`id.orig_h`, `id.resp_h`, `id.resp_p`, `proto`, `orig_bytes`), `ssl.server_name`,
  `dns.answers`; offline ASN and country DB.
- **Logic:** `rules/R02-iot-egress-drift.sql`. Per fixed-function device, keep the set of
  (proto/port), ASN and country it used in the last 14 days. Raise when, within an hour, the device uses
  a **new port**, or **≥3 new ASNs**, or **a new country**.
- **Baseline:** 7-day learning per device, re-learned on firmware-update days (a burst of
  vendor-CDN SNI). Measured: the 8 quiet devices each used 1–5 distinct destination IPs in the window, and most used one or two ports.
- **Dedupe:** `iot_drift|host|new-dimension|value`, 24 h.
- **FPs:** firmware updates (CDN ASN churn) and vendor cloud migrations. Suppress ASN-only drift when every new
  IP's SNI or DNS name shares the device's existing base domains.
- **Route:** a new port or country → DIGEST by default, ALERT if Jev says so. ASN-only drift → LOG.
- **Jev:** **yes, on behaviour only.** Code states "a camera that has only ever used HTTPS
  and one vendor port now uses port 6881 to 14 new networks in 3 countries; uploads are
  normal". Questions: `Q-role-fit` (role = camera), `Q-cat`, `Q-wake`. Jev is **not** asked whether
  the ASN or country is OK. Code already said they are new for this device.
- **Safe test:** replay a synthetic pcap (`eval/make_synthetic_pcap.py` style) in which a host
  labelled "camera" in a test `assets.yaml` contacts TEST-NET addresses on a new port. Don't touch the real camera.

### R03 Device touches the management plane or other devices' admin ports (`mgmt_access`) — **built**
- **Threat:** lateral movement or reconnaissance against the UDM/UniFi admin interface, or against
  SSH/RDP/SMB/VNC/telnet on other devices.
- **Data:** `conn` internal → internal: `id.resp_p` in {22, 23, 443 or 8443 on the gateway, 445, 3389,
  5900, 8291}, `conn_state`.
- **Logic:** `rules/R03-mgmt-plane-access.yml` (Sigma, stateless with an admin-device allowlist).
- **Baseline:** none. Measured: **only the main PC** touched UDM tcp/443 or 22. UniFi gear uses
  8080/7444/6666/5514 (allowlisted).
- **Dedupe:** `mgmt|src|dst|port`, 24 h.
- **FPs:** Other admin devices of yours (phone app → UDM 443) belong in `admin_devices`;
  UniFi inform traffic.
- **Sweep:** new admin-port pairs from one source to 5+ devices within 10 minutes is one severity-5
  case ("Admin-port sweep"), once an hour per source; the probes it covers raise nothing more. This
  is the worm shape: WannaCry (CTU-297-1) made 9,900 SMB attempts in 16 minutes, which as single
  unanswered probes would be 80 digest items and no alert (eval re-run 2026-10-15).
- **Route:** code-only, by outcome: an accepted remote-control or router-admin session is severity 4
  (ALERT), accepted SMB 3 (DIGEST), an unanswered attempt 2 (DIGEST). Before 2026-10-15 every attempt
  was 4, so Windows discovery probing 445 across VLANs was a critical alert.
- **Jev:** none. Note: same-switch SMB/RDP between two PCs is **not visible** (§2 blind spots).
- **Safe test:** from a Windows laptop that isn't on the admin allowlist, open `https://<UDM>` in a
  browser. That's one harmless connection.

### R04 Beaconing, home-tuned (`beaconing`, existing)
- **Threat:** C2 heartbeat.
- **Data:** `conn` per (src, dst, port) inter-arrival times; `ssl.server_name`.
- **Logic:** existing `detectors.Beaconing` (CV ≤ 0.15, ≥10 hits, ≥10 min), plus code facts in
  the case: `sni_popular` (Tranco), `shared_by_n_devices`, `device_role`, `bytes_per_hit`.
- **Jitter tier** (#24, 2026-10-17): C2 frameworks add random sleep jitter, which the CV test misses (on
  synthetic 11-gap windows it caught 4/200 with Cobalt Strike-style 50% jitter, 0/200 at ±40%, 0/200 with two
  missed beats). `jitter_regular` folds gaps near 2× or 3× the median as missed beats, then needs the median
  absolute deviation ≤ 20% of the median, ≥ 90% of gaps within ±50% of it, and ≤ 20% of beats folded: 432/500,
  342/500 and 449/500 of those shapes, and 14/500 synthetic human-browsing windows. Measured on two days of home
  traffic (2.8M conn/ssl/dns rows) through this detector with the live config: 38 jittered cases next to 17
  regular ones; 26 popular and shared (logged), 7 popular but used by no other device, 5 to obscure
  destinations. So a jittered case to a popular or known-class service is logged, and the rest (5 in two days)
  reach the digest at most, with `regularity: jittered` and the folded median as the interval. Jittered cases
  keep their own reporting memory, so they never use a regular case's 7-day slot or fan-out budget (they hid 7
  of 20 regular cases before). Tighter limits (MAD ≤ 15%, 95% in band) cut the jittered cases to 21 but lost
  half the synthetic beacons. `detectors.beaconing.jitter: false` turns the tier off.
- **Baseline:** none for detection. Suppression learns which (role, base-domain) pairs are
  normal heartbeats after 7 days. The beat window (last 60 times per pair) is saved with the
  learned state, so a heartbeat slower than the gap between alerter restarts can still reach ten
  beats (2026-10-16: seven restarts in a day; a 12-beat test that straddled one raised no case).
  Each save first drops pairs quiet for a day and leaves single-beat pairs out of the copy.
- **Dedupe:** `base domain (or address):port`. One case per (device, port, destination) every
  `reported_days` (7), at most `fanout_per_day` (3) per (device, port) a day for clients that poll
  many servers the same way. Until 2026-10-15 it was one case per (device, port) forever, which
  silenced any later C2 on 443 once a benign heartbeat on 443 had been reported.
- **FPs:** the camera's vendor-port keepalive, UniFi inform, push services (5223/5228),
  NTP, the hub's MQTT keepalive. Suppress when SNI or base domain is popular **and**
  shared, or the role is fixed-function **and** the destination is in the device's 14-day set.
  A popular destination (Tranco) that no other household device uses is capped at digest, never
  log: popular services are C2 channels too (Discord, Telegram, GitHub), so it stays in the daily
  digest (owner decision, 2026-10-15).
  Services that are regular by design (`BEACON_CLASSES`: push notification, endpoint security
  agent, time sync, STUN/VPN relay; `detectors.beaconing.benign_classes` extends it) carry
  `known_class` and are capped at digest, never log: on a one-computer network nothing is ever
  "shared", so this is the only cap that can apply there. Measured 2026-10-15: a work laptop's
  Tanium check-in every 75 s, Jev c2 0.99, alerted.
- **Route:** Jev-routed (unchanged).
- **Jev:** **yes, its proven strength.** It alerted the synthetic C2 at 1.00 where rules-only
  only digested it. Questions: `Q-cat`, `Q-sev`, `Q-routine`, `Q-wake`, plus `Q-role-fit`.
- **Safe test:** existing synthetic pcap (`eval/replay.sh`), or a PC loop `curl https://example.com`
  every 60 s for 15 min. That's benign, but it exercises the timing logic, and you should expect `routine` to be high.

### R05 New device joins (`new_device`, extended) — **built**
- **Threat:** a rogue or unknown device (a neighbour on Wi-Fi, a drop box, a compromised guest) and asset hygiene.
- **Data:** `dhcp` (`mac`, `host_name`, `client_fqdn`, `msg_types`), OUI vendor table, first 10 min of
  `conn`/`ssl`/`http.user_agent` for that device; UDM syslog Wi-Fi connect (SSID, AP).
- **Logic:** tapwatch detector. Key on MAC, not IP. Fire on a MAC never seen. Collect 10 minutes
  of first behaviour, then emit one case with facts: vendor, locally-administered (randomized) MAC
  bit, hostname (untrusted), SSID, wired or Wi-Fi, services contacted, and whether the user agents
  look like a browser.
- **Baseline:** 7-day learning to enumerate the ~28 devices into `assets.yaml`. Measured: 5 MACs
  renewed DHCP in 50 min, all known.
- **Dedupe:** `new_device|mac`.
- **FPs:** phones and laptops rotating randomized MACs per SSID or per day. Suppress when the
  randomized MAC's DHCP hostname and first-services profile match an existing asset; guest SSID devices → LOG.
- **Route:** DIGEST. ALERT when it's wired (only family hardware should be wired), or appears
  01:00–06:00, or `Q-role` = computer/unknown with a non-randomized MAC on the main LAN.
- **Jev:** **yes, a semantic call that thin telemetry can't make.** `Q-role` labels the device from
  vendor, hostname and first services so it can seed `assets.yaml`. `Q-human` (someone browsing vs a
  headless box) and `Q-wake`. The hostname is untrusted, so the router ignores a role Jev reports below 0.6 confidence.
- **Safe test:** join a spare phone, or a phone with "private Wi-Fi address" toggled to a new
  value, to the guest SSID and then the main SSID.

### R06 Odd-port or long-lived outbound (`odd_port`) — **built**
- **Threat:** reverse shells, tunnels, personal VPNs and proxyware, which tend to use rare ports and long sessions.
- **Data:** `conn` (`proto`, `id.resp_p`, `duration`, `orig_bytes`, `resp_bytes`, `service`, `history`).
- **Logic:** `rules/R06-odd-port-long-lived.sql`. Raise on an outbound proto/port **never used by any
  household device in 14 days**, or not in the device's own set for fixed-function roles. Also raise on a single
  connection > 4 h, or a device with > 2 h cumulative to one dst in a day on a non-443 port.
- **Baseline:** 14 days. Measured: **14 proto/port pairs house-wide**, p99 duration 610 s,
  and **0 connections over 1 h**.
- **Dedupe:** `odd_port|host|proto/port`, 7 days.
  A (device, port, kind) is reported once every `reported_days` (7), not once forever (fixed 2026-10-15).
- **FPs:** new games or voice chat (udp ephemeral), work VPN (the work laptop's IPsec/WireGuard),
  Steam downloads. Allowlist per device. Zeek `service` lets "ssl on 4443" be treated as softer than "unknown on 4444".
- **Route:** Jev-routed. A floor of DIGEST for `service` unknown on fixed-function devices.
- **Jev:** **yes.** Code gives words like "TCP port 4444, protocol not recognized, 3 hours, 2 MB up,
  first use by any device in the house" and a code-side port hint ("often used by
  OpenVPN" or "no common use"). Questions: `Q-cat` (remote_access / policy_violation /
  c2), `Q-human`, `Q-wake`.
- **Safe test:** on the PC, `ssh -p 2222` to a host you control, such as a cloud VM, or connect to
  `portquiz.net:4444`, a public service built for outbound port tests, for 1 minute.

### R07 DNS bypass: plain, DoT, DoH or DoQ (`dns_bypass`) — **built**
- **Threat:** malware or apps bypassing the UDM resolver (and its future filtering/logging),
  and DNS tunnelling to a chosen resolver.
- **Data:** `conn` udp/tcp 53 to non-UDM, tcp/853, udp/853 and 8853 (DoQ); `ssl.server_name` in a
  DoH list (dns.google, cloudflare-dns.com, *.nextdns.io, dns.quad9.net, …); `conn` tcp/443 to
  well-known DoH anycast IPs without SNI.
- **Logic:** `rules/R07-dns-bypass.yml` (Sigma, with a per-device allowlist).
- **Baseline:** 3 days to learn which devices hardcode resolvers. Measured: **1 device** (the
  camera, 24 queries to public DNS in 50 min). The work laptop uses VPN resolvers. 0 DoH/DoT.
- **Dedupe:** `dns_bypass|host|resolver-kind`, 7 days.
- **FPs:** IoT devices that hardcode public DNS (allowlist per device), browsers' Secure DNS, Apple
  Private Relay (`mask.apple-dns.net`), and work VPN.
- **Route:** DIGEST. ALERT if a **computer** starts DoH/DoT to a non-mainstream resolver,
  or plain-53 bypass volume is > 10× its baseline.
- **Jev:** **code alone decides** whether it's a bypass. Optionally ask `Q-role-fit` ("a TV that
  hardcodes a public resolver"), but treat it as advisory until measured. The
  question is close to Jev's "is this normal" weak spot.
- **Safe test:** on the PC, `nslookup example.com 1.1.1.1`, then enable browser Secure DNS
  with Cloudflare for 1 minute.

### R08 Newly registered or rare-in-household domain (`new_domain`, refined, code-only)
- **Threat:** phishing, malware delivery and fresh C2 infrastructure.
- **Data:** `dns.query` (NOERROR), `ssl.server_name`, Tranco top-100k, daily NRD list (pull-only),
  per-device and household first-seen sets.
- **Logic:** `rules/R08-rare-new-domain.sql`. A base domain that is first-seen for the device,
  **not in Tranco**, and used by **no other household device**. Grade: NRD ≤ 30 days → high;
  random-looking → medium; else low.
- **Baseline:** 3-day warmup. Measured: **~150 first-seen pairs/h** on an active evening after
  warmup. Only **7 of 167** base domains were off the Tranco list, and 124 were single-device.
- **Dedupe:** `new_domain|host|base_domain`; window-grouped as now.
- **Popular-only windows (implemented 2026-10-19):** a window in which every name is on the
  Tranco list and none looks random opens no case; the names are still learned. Measured on the
  home install the week before: 285 of 342 `new_domain` cases were all-popular browsing (shopping,
  news, app telemetry), none ever a threat, and they were most of the triage queue. tapwatch looks
  for threats, not content: a site's kind never opens a case. `new_domain: {report_popular: true}`
  restores the old behaviour.
- **Category:** each name is looked up in the offline UT1 category list (`categories.py`, from
  `update-feeds`): the case carries the distinct kinds found (advertising, media, remote control,
  ...) as a fact for the summary. A fact only, not routing: measured first (2026-10-16, the day's
  false alarms were ad-tech, a security vendor and a video call), routing on it comes after.
  When the list has no answer and `categories: {ai: true}` is set, the registrable domain is put
  to a small model once: a closed classification over a fixed label set (the UT1 labels plus
  security vendor, conferencing, CDN, cloud infrastructure, SaaS, developer tools, telemetry,
  news, shopping, games, or `unknown`; measured 2026-10-16, the kinds the list lacked), parsed
  strictly, cached 30 days in `categories.learned.tsv`, capped per hour. The source travels with
  the fact (`category_sources`: `list`, `ai`) so the summary says a model classed it. It is never
  routing, and it is never the normalcy question ("is this domain normal?") that the triage model
  is measured to get wrong; that rule stands, and the triage model is not involved here at all.
- **FPs:** small business and personal sites, work domains and SaaS tenants (allowlist the
  work laptop's corporate suffixes in config, not in git), and fresh legit CDNs. Registrable domains come from
  the Public Suffix List's ICANN rules (`co.uk`, `com.au`, wildcards and exceptions) since 2026-10-18 (#17).
- **Route:** **code-only** (`router.CODE_ONLY`). NRD on a fixed-function device → ALERT; NRD on a
  computer → DIGEST; random-looking → DIGEST; else LOG.
- **Jev:** **none, deliberately.** This is the measured weak spot. Jev's answer here is
  noise. NRD age, Tranco and household prevalence are the judgment.
- **Safe test:** look up a domain you registered yourself in the last 30 days, and add it to a test
  NRD file. Or inject a synthetic DNS row in a replay.

### R09 Upload anomaly, camera and everything else (`upload_spike`, `upload_stopped`) — **built**
- **Threat:** exfiltration or a compromised device used as a proxy. For cameras: an upload to a **new
  destination** (stream hijack), or a **stop** (camera offline or jammed).
- **Data:** `conn.orig_bytes` per device per hour, by destination base domain/ASN; UniFi Protect events (optional).
- **Logic:** extend `OutboundVolume` to an hour-of-week baseline (median and MAD per device and hour). Raise on:
  bytes > 10× median **and** > 500 MB; or a camera sending > 50 MB/h to a destination
  outside its 14-day set; or a camera's hourly upload < 5% of median for 2 h.
- **Baseline:** 14 days for hour-of-week. Measured: the camera at **~340 MB/h** steady (it would trip
  any fixed threshold), the next device at 23 MB/h, and most devices ≈ 0.
- **Dedupe:** `upload|host|hour`.
- **Category:** `top_category`, the main destination's kind from the offline UT1 list (media, file
  hosting, ...); a fact for the summary, not routing.
- **Managed devices:** a device whose assets.yaml role says employer-managed or security agent / EDR
  (`MANAGED_ROLE_WORDS`) is capped at digest whatever the destination, the role in `managed_device`.
  Measured: the work laptop's EDR agent sends ~1 GB to plain AWS most mornings (#139, #325, EDR
  telemetry) and 1.5 GB to a Meet address on 2026-10-16 (#371); no destination cap fit, and Jev
  scored them exfiltration. Digest, not log: the employer's tooling watches that device, the digest
  keeps it visible.
- **FPs:** phone photo backup, PC cloud sync and game uploads. Code tags the destination as "known
  sync service" from a curated map. That's a lookup, not Jev's guess.
  When no name was visible (Apple relays, ECH), the destination's network owner from the offline ASN
  table stands in: Apple, Microsoft, Dropbox or Backblaze address space is `to_sync_network` and
  capped the same way (an iPhone's 2 GB to Apple's ASN, 2026-10-15; AWS/Google host everyone, so not them). Video calls: the hour is
  `symmetric` (upload 35-65% of the total) and capped at digest when mostly to one destination;
  measured 2026-10-14, an all-day Meet (2.17 GB up, about the same down) alerted as #82.
- **Route:** Jev-routed. A camera stop → DIGEST (code-only).
- **Jev:** **yes.** "The Windows laptop uploaded 4 GB in one hour, 40× its normal for a Tuesday
  20:00, mostly to one destination new to this device, not a known sync service." Questions:
  `Q-cat`, `Q-routine`, `Q-wake`.
- **Safe test:** upload a large, harmless file (`fallocate -l 3G`) to your own cloud storage from the PC.

### R10 TLS weak-signal stack (`tls_odd`) — **built**
- **Threat:** custom malware TLS, bare-IP C2 and self-signed infrastructure.
- **Data:** `ssl` (`server_name`, `established`, `validation_status`, `version`), `x509` (subject
  == issuer), `dns.answers` (was the IP named?), JA4 (needs the package).
- **Logic:** `rules/R10-tls-weak-signals.sql`. Score each established outbound TLS session:
  +1 no SNI, +1 IP not in any DNS answer within 1 h, +1 self-signed or expired, +1 JA4 never seen
  in the house, +1 non-443 port. Raise at ≥3. A DTLS session with a client certificate is the
  WebRTC media shape (DTLS-SRTP): no name and self-signed certificates on both ends are the
  protocol, so those two signs don't count for it; the port and the unexplained address still do,
  which leaves it at 2 until JA4 adds a sign. Measured 2026-10-17: the baby monitor streaming to a
  phone on cellular raised eight digest cases on eight ICE-chosen ports (#332-#417); the Mac on
  video calls has the same shape. This Zeek labels no STUN service (the monitor's flow: 149
  unlabelled UDP rows, 7 "dtls"), so the client certificate is the tell. Blind spot, chosen: a
  DTLS implant that presents a client certificate to a bare address on an odd port scores 2 and
  is not raised; no other rule covers it. Server-only DTLS and TLS with a client certificate (the
  hub's MQTT on 8883) score as before.
- **Baseline:** 7 days for household JA4 prevalence. Measured: 22% no-SNI but only 43 established,
  0.7% bare-IP TCP, and 49 "invalid cert" rows that were all Zeek missing intermediates.
- **Dedupe:** `tls_odd|host|dst`.
- **Category:** `category`, the server name's kind from the offline UT1 list when there is a name; a
  fact for the summary, not routing.
  Reported once per (device, port) every `reported_days` (7); a pair learned in warmup is kept for
  good. Until 2026-10-15 it was once forever, so a C2 on a port where the camera had once been
  learned was invisible.
- **FPs:** Windows CDN validation noise (ignore `unable to get local issuer` alone), UniFi gear's
  self-signed certs (internal; skip internal destinations), and Chrome/ECH no-SNI.
- **Route:** score 3 → DIGEST, ≥4 → Jev-routed.
- **Jev:** **light.** A combined case can ask `Q-cat` + `Q-wake`, but the score decides whether it
  becomes a case at all. Jev is never shown the certificate subject as evidence of legitimacy.
- **Safe test:** `openssl s_server -accept 8443` with a self-signed cert on a cloud VM you control;
  `curl -k https://<vm-ip>:8443` from the PC. That gives no SNI, a bare IP, a self-signed cert and a non-443 port.

### R11 UDM admin login from a new source (`udm_admin`, from UDM syslog) — **built**
- **Threat:** stolen UniFi credentials or a compromised admin device. The UDM controls everything else.
- **Data:** UDM syslog/CEF admin-login and SSH events (user, source IP, method, success/fail),
  config-change events. On UniFi Network 10.x these come from the SIEM export's **Admin Activity**
  content (CyberSecure → Traffic Logging → Activity Logging): CEF class 544 `Network Accessed` with
  `UNIFIadmin`, `src` and `UNIFIaccessMethod`, verified 2026-10-15. The same export also sends iptables
  firewall lines and the gateway's system log, which `syslogin.py` counts and drops (docs/setup/router-syslog.md).
- **Logic:** tapwatch detector on the syslog input. Raise on a (user, source) never seen in 30 days;
  ≥5 failures in 10 min; any SSH login; any config change within 30 min of a new-source login.
- **Baseline:** 30 days of admin sources (few).
- **Dedupe:** `udm_admin|user|source`.
- **FPs:** A new phone or laptop of yours, and UniFi cloud (remote management) logins. Tag "via UniFi
  cloud" separately.
- **Route:** ALERT, **code-only, `must_alert`.** Whether the owner did it is a fact only the
  owner knows. Jev can't supply it, and a wrong "routine" would hide the worst event in the house.
- **Jev:** none.
- **Safe test:** log into the UDM from a device you've never used for admin, and fail the password twice first.

### R12 Off-hours activity drift (`off_hours`) — **built**
- **Threat:** a compromised device active while the household sleeps (scheduled malware or proxyware).
- **Data:** `conn` per device per hour: outbound conns, distinct destinations and bytes.
- **Logic:** hour-of-week profile per device (14+ days). Raise when a device's conns in a "quiet"
  hour (its median < 5) exceed 20× median **and** ≥ 200, or it contacts ≥ 20 distinct new
  destinations in that hour.
- **Baseline:** **14–28 days**. Overnight numbers aren't measured yet; re-run `baseline.py` on the full night.
- **Dedupe:** `off_hours|host|date`.
- **FPs:** Windows Update and Patch Tuesday, phone overnight backups, TV firmware and console
  updates at 03:00. The code's curated update/sync map labels destinations.
- **Route:** Jev-routed, max DIGEST unless `Q-wake` is high.
- **Jev:** **yes, the core use case for thin telemetry.** Without EDR, "is this the OS
  updating?" is judged from code facts: destination categories, volume shape, whether other
  devices of the same role did the same tonight. Questions: `Q-routine`, `Q-human`, `Q-cat`.
- **Safe test:** schedule a Windows task at 03:00 that runs `curl` against 30 popular sites.

### R13 Cleartext credentials and protocols (`cleartext_auth`) — **built**
- **Threat:** credential exposure (and a sign of old or abandoned IoT).
- **Data:** `http` (`username`, plus `password` if `HTTP::default_capture_password` is on, which
  should stay off; log presence only), `ftp`, `conn` tcp/23, pop3/imap/smtp without STARTTLS, and MQTT
  CONNECT with a username on tcp/1883 to the internet.
- **Logic:** `rules/R13-cleartext-credentials.yml` (Sigma).
- **Baseline:** none. Measured: 0 HTTP auth and 0 ftp/telnet; **1 device** (the smart-home hub)
  uses cleartext MQTT to the internet.
- **Dedupe:** `proto|outside` for internet servers, `proto|dst` on the LAN; the server address is a fact.
  Each (device, server, protocol) is raised once; a device rule on `MQTT|outside` covers a cloud broker
  that rotates addresses (a photo frame's did, three AWS addresses in a day, 2026-10-15).
- **FPs:** LAN-only cleartext to printers or UniFi (internal → LOG), and known IoT MQTT once acknowledged.
- **Route:** internet-bound credentials → DIGEST (hygiene). Outbound **telnet/ftp from a computer** → ALERT.
- **Jev:** none. It's a protocol fact, and Jev adds no judgment.
- **Safe test:** `curl -u test:test http://httpbin.org/basic-auth/test/test`. Those are dummy
  credentials against a public test endpoint.

### R14 Rogue DHCP server (`rogue_dhcp`) — **built**
- **Threat:** a malicious or misconfigured device handing out a hostile gateway or DNS (an on-path attack).
- **Data:** `dhcp` (`server_addr`, `msg_types` OFFER/ACK), `conn` udp/67 responders; UDM syslog DHCP.
- **Logic:** `rules/R14-rogue-dhcp.yml` (Sigma). Raise on an OFFER or ACK from any server other than the UDM interfaces.
  A /24 whose gateway is in `network.gateways` is strict: any other server there is rogue. Every other /24 (the wizard
  writes one gateway; a VLAN'd router answers DHCP from an address per VLAN) gets one server: the router Gateways
  elects, the first server seen there, or anything seen during warmup. A second server on that /24 is rogue.
- **Baseline:** the per-/24 trusted server. Measured: **1 server** (the UDM).
- **Dedupe:** `rogue_dhcp|server`.
- **FPs:** a travel router or mesh node plugged in by family. Still worth an alert.
- **Route:** ALERT, code-only, `must_alert`.
- **Jev:** none. It's binary, and there's nothing to judge.
- **Safe test:** replay a pcap with a synthetic DHCPOFFER from a fake server (scapy offline).
  **Don't run a real DHCP server on the LAN.**

### R15 DNS anomaly and tunnelling (`dns_anomaly`, existing, tuned) — **built**
- **Threat:** DGA and DNS tunnelling.
- **Data:** `dns` (`query`, `qtype_name`, `rcode_name`, query length, TXT/NULL volume per base domain).
- **Logic:** existing NXDOMAIN and random-name thresholds, plus a tunnelling clause: ≥ 200
  queries to one non-Tranco base domain in 10 min with mean label length > 30, or TXT/NULL share > 50%.
- **Baseline:** measured NXDOMAIN max ~11 per 10 min per device (retry loops). The current threshold of 25 holds.
- **Dedupe:** existing cooldown per host.
- **FPs:** retry loops on a dead name (add a "one name, ≥ 90% of failures" clause → LOG), WPAD,
  DNS-SD `lb._dns-sd` lookups, and antivirus DNS-based reputation lookups (long hashed labels; allowlist vendors).
- **Route:** Jev-routed (existing).
- **Jev:** **yes, a known strength.** It alerted synthetic DGA at 1.00. `Q-cat`, `Q-sev`, `Q-wake`.
- **Safe test:** existing synthetic pcap; or `for i in $(seq 40); do nslookup $(openssl rand -hex 8).example.com; done`
  from the PC. These are NXDOMAINs under a reserved domain.

### R16 Takeover channel (`takeover`) — **built**
- **Threat:** account or machine takeover. Without EDR or SaaS audit logs, the takeover itself
  (a stolen GitHub or Anthropic token used from elsewhere) never crosses this network. What does
  cross it is the attacker's plumbing on this end: a webhook or callback catcher where a
  prompt-injected agent or token stealer posts secrets, a paste or file-drop site, a tunnel that
  opens a way in, or a remote-control tool.
- **Data:** `dns.query` (NOERROR only), `ssl.server_name`, `http.host`.
- **Logic:** `rules/R16-takeover-channels.yml`; `detectors.TakeoverChannel`, matching on label boundaries.
- **Baseline:** none. Measured: 1 hit in 2.9 h (TeamViewer on the Windows laptop).
- **Dedupe:** `takeover|host|service`.
- **Dev profile:** **does not apply.** Dev and agent work is exactly what an injected agent would hide behind.
- **Route:** a remote-control service seen only in a DNS lookup raises nothing (visiting the vendor's
  website resolves the same name): the case needs TLS/HTTP to the service, or a connection to one of
  the lookup's answers within 60 s. Callback and file drop → ALERT, `must_alert`. Tunnel and remote control → ALERT,
  code-only, suppressible per device for tools you installed on purpose.
- **Expected tools (`detectors.takeover.expected`):** a device plus a tunnel or remote-control service, with
  business `hours` and an optional `mac`. Sightings never raise a case, because the client polls all
  day when idle (measured: ~20 KB per 10 min on the work laptop). Outside `hours`, a live session
  (≥ 2 MB to the service's servers or its own port within 10 min) alerts once per day. If a DHCP lease
  gives the address to a different MAC, the entry stops applying. Callback and file-drop services
  can't be marked expected.
- **Jev:** none. The service's identity is the verdict, and judging domains is Jev's weak spot.
- **Safe test:** `nslookup webhook.site` from the PC (a lookup only, nothing is posted), or
  `ssh -R` to `localhost.run` with no local service behind it, then close it.


### Endpoint rules R17–R21: what the PC itself says (built 2026-10-15, `hostrules.py`)

The §2 inventory deferred Sysmon as "EDR-lite for one box". The endpoint agent ([agents/](../../agents/README.md))
changed the cost side: osquery's `sysmon_events` query reduces Sysmon's process starts (event 1), outgoing
connections (3) and DNS lookups (22) to rows tapwatch reads, and turns every command line into yes/no signals
**on the PC** (`cmd_enc`, `cmd_b64`, `cmd_dl`, `cmd_iex`, `cmd_hidden`, `cmd_bypass`, `cmd_url`), so nothing
readable reaches the world-readable results log. Host context uses those rows to explain network cases. The
rules below raise cases of their own, for living-off-the-land activity that never looks odd on the wire
(#26, #27). They read the osquery results and snapshots logs as a log source (`_type: osquery`, named in
`zeek.LOG_TYPES`; `run` follows their directories next to Zeek's, and a replay takes the directory as a
`--zeek-dir`). `run` survives osquery's rotation the way it survives Zeek's (the open handle is drained before
the new file is read); a replay reads only the live file, because osquery's rotated names (`.log.1`) are not
Zeek's dated pattern. Until an agent snapshot or `host_context.host` names the PC's address, a case names it
"this PC". This first set is Windows-only; Linux rules (#28) will reuse the same base over
`bpf_connections` and `bpf_process_events` rows.

Three rules hold for every one of them. **A case never carries a command line or a path**: it names the
program and the *class* of folder it runs from (a temp folder, an installed location), because a Windows path
holds the user's name and a command line holds tokens. **Program names are indicators**: attacker-chosen
strings, quoted and labelled untrusted for Jev, defanged in notifications, and the handle a suppression keys on.
**Code decides every route** (`router.CODE_ONLY`): "is this program normal?" is the same question as "is this
domain normal?", Jev's measured weak spot, and it is never asked. `must_alert` is reserved for the two shapes
with no benign reading on a home PC.

**Measured baseline** (2026-10-14/15, the main PC's agent log, 34.5 h; aggregates only):

| Measure | Value |
|---|---|
| Process starts (Sysmon 1) | 9,709 (197 distinct program names); outgoing connections (3): 108,423; DNS lookups (22): 7,423 |
| Command-line signals on starts | `url` 197; `enc` **1**, on msiexec passing a long base64-looking argument to itself (not a shell); `b64`, `dl`, `iex`, `hidden`, `bypass`: **0** |
| Shell or script host started by a browser | **37**, all `cmd.exe` from Chrome, none with a URL on the command line, **none that connected anywhere** (native-messaging hosts are often batch files) |
| …by a document, mail or PDF app | 0 (no Office on this PC) |
| …by WSL's host process, a game updater, coding agents | 134, 30, 7: ordinary parents, ignored by the rules |
| Built-in tools (LOLBins) connecting to the internet | **0** (rundll32 started 19 times, by svchost and msiexec, and never connected) |
| Connections from a temp, Downloads or shared folder | **0**; 6 process starts from a temp folder (installers unpacking), none connected |
| Shells connecting to the internet | 1 (`powershell.exe`) |
| Code signatures on the 1-minute socket snapshot (`outbound_connections`) | trusted for most; `missing` or unreadable: **7 distinct programs, all installed apps** (Program Files, AppData\Local\Programs); `untrusted`, `distrusted`: **0** |
| `tapwatch replay` of the five rules over the 34.5 h | **0 cases** |

The implications: the data supports strict rules with no learning period (every shape fires 0 times on a day
of a dev PC), a browser's child is not evidence until it connects, "unsigned" cannot be a rule while osquery
can't read a quarter of valid signatures, and the encoded-command signal must be scoped to shells.

### R17 Encoded or download-and-run command (`host_encoded_cmd`) — **built**
- **Threat:** a PowerShell, cmd or script-host payload that hides what it runs: `-EncodedCommand`,
  `FromBase64String`, `DownloadString`/`Start-BitsTransfer`/`certutil -urlcache`, `IEX`, usually with
  `-w hidden -ep bypass`. The first stage of most commodity malware and of macro and attachment payloads
  (T1059.001, T1027, T1105).
- **Data:** `sysmon_events` event 1: `path`, `parent_path`, and the signals `cmd_enc`, `cmd_b64`, `cmd_dl`,
  `cmd_iex`, `cmd_hidden`, `cmd_bypass`, `cmd_url`. The raw command line is never read by this rule.
- **Logic:** `rules/R17-encoded-command.yml`. The program is a shell or script host (`hostctx.WIN_SHELLS`:
  powershell, pwsh, cmd, wscript, cscript, mshta, rundll32, regsvr32, bitsadmin, certutil). An encoded payload
  with a second signal, any suspicious signal in a hidden window, or a document/mail/PDF app as the parent →
  severity 5, **must_alert**. Two signals (`dl` + `iex`, with or without a policy bypass), one strong signal
  alone (`enc`, `dl`), or any suspicious signal with a browser parent → severity 4, suppressible. `b64` or
  `iex` alone from any other parent → nothing. The must_alert bar stops below `dl` + `iex` on purpose:
  that is Chocolatey's documented install line, and must_alert can't be suppressed.
- **Baseline:** none. Measured: 0 on shells in 34.5 h. The one `enc` hit was msiexec; scoping to shells removed it.
- **Dedupe:** `host_encoded_cmd|pc|program`, the store's hour.
- **FPs:** installers run with `-ExecutionPolicy Bypass -w hidden` (measured on tapwatch's own installer:
  hidden and bypass alone raise nothing); dev tooling's `iex (irm https://...)` one-liners (nothing alone);
  Chocolatey's install command (`Set-ExecutionPolicy Bypass ...; iex (... DownloadString(...))`: a severity-4
  alert once, then a program-scoped suppression); a browser extension's helper that decodes base64 (alert,
  suppressible per program).
- **Route:** ALERT, code-only; must_alert for the combinations above.
- **Jev:** none.
- **Safe test:** `powershell -enc <base64 of "Write-Host hi">` from a terminal → severity 4 alert. Add
  `-w hidden` → must_alert and a Herdr pop-up. Both print a word and exit.

### R18 Document app or browser starts a shell (`host_app_shell`) — **built**
- **Threat:** the macro and attachment path: Word, Excel, Outlook or a PDF reader starting PowerShell, cmd,
  wscript, mshta, rundll32 or regsvr32 (T1204.002, T1566.001). A browser starting a shell that then calls home
  is the drive-by shape.
- **Data:** event 1 (`path`, `parent_path`); event 3 joined by `ProcessGuid` within 10 minutes for the browser clause.
- **Logic:** `rules/R18-app-spawns-shell.yml`. A document, mail or PDF parent (`hostctx.WIN_DOC_APPS`) → severity 4
  at the start. A browser parent → nothing at the start; severity 4 when that same child connects to the
  internet (not the LAN, not DNS). A suspicious command line on the child is R17's case: the browser parent
  lifts it to an alert there.
- **Baseline:** none. Measured: 37 Chrome → cmd.exe starts, none connected; 0 document-app children.
- **Dedupe:** `host_app_shell|pc|parent > child`. The indicator is the pair, so "chrome.exe > cmd.exe" can be
  muted for a browser helper that connects by design, without muting Word → PowerShell.
- **FPs:** Office add-ins and PDF readers' updaters that run scripts (alert once, suppress the pair);
  native-messaging batch files (raise nothing until they connect).
- **Route:** ALERT, code-only, suppressible. Not must_alert: Office automation exists.
- **Jev:** none.
- **Safe test:** in Word, Alt+F11 and run `Shell "cmd.exe /c echo hi"` → severity 4 alert. Harmless.

### R19 Program in a temp or download folder connects out (`host_temp_exec`) — **built**
- **Threat:** droppers and second stages run from `%TEMP%`, Downloads or `Users\Public` and call home
  (T1204, T1105, T1036).
- **Data:** event 3 (`path`, remote address, port), joined to its event 1 (parent, signals) by `ProcessGuid`.
- **Logic:** `rules/R19-temp-folder-connects.yml`. The folder class is temp (`AppData\Local\Temp`,
  `Windows\Temp`) or Downloads → severity 3, once per (program, folder) per 7 days. Shared (`Users\Public`,
  `$Recycle.Bin`, `PerfLogs`; nothing legitimate installs there) → 4. The start carried a suspicious signal or a
  document/mail parent (a dropper a document wrote and ran) → 4.
- **Baseline:** none. Measured: 0 connections from those folders; the 6 temp starts were installers.
- **Dedupe:** `host_temp_exec|pc|program`.
- **FPs:** installers unpacking to temp and fetching components (a digest item, by design); portable tools run
  from Downloads (once a week; suppress per program).
- **Route:** DIGEST, ALERT for the shared folders and the dropper shape. Code-only.
- **Jev:** none.
- **Safe test:** copy `curl.exe` from System32 into `%TEMP%` and fetch `https://example.com` → digest item;
  copy it into `C:\Users\Public` instead → alert. Delete the copies afterwards.

### R20 Built-in Windows tool connects to the internet (`host_lolbin`) — **built**
- **Threat:** LOLBins fetching or proxy-executing code: `certutil -urlcache -f`, `bitsadmin /transfer`,
  `mshta https://...`, `regsvr32 /i:http... scrobj.dll` (Squiblydoo), `rundll32 javascript:`, `msbuild` inline
  tasks, `wmic ... /format:https` (T1218, T1105, T1197).
- **Data:** event 3 (`path`, remote address, port); event 1 join for the parent and the `url` flag.
- **Logic:** `rules/R20-lolbin-connects.yml`. The program is in `hostctx.WIN_LOLBINS`, the remote is not the
  LAN or loopback, the port is not 53. certutil, bitsadmin, mshta and regsvr32 exist to fetch or run remote
  content and have no home use on the internet → severity 5, **must_alert**. The rest (rundll32, wmic, wscript,
  cscript, installutil, cmstp, regasm, regsvcs, odbcconf…) → 4, suppressible per program. `msbuild` → 3, once
  per 7 days: on a Visual Studio PC it connects out for every NuGet restore, so a severity-4 alert would
  repeat hourly there.
- **Baseline:** none. Measured: 0 in 108,423 connections.
- **Dedupe:** `host_lolbin|pc|program`.
- **FPs:** rundll32 hosting a vendor DLL that phones home (some driver installers): one alert, then a
  program-scoped suppression; MSBuild's NuGet restores (digest, by design); wmic in admin scripts (rare on a
  home PC).
- **Route:** ALERT, code-only; must_alert for the four downloaders. Critical (Herdr pop-up) at severity 4+.
- **Jev:** none.
- **Safe test:** `certutil -urlcache -split -f https://example.com/ %TEMP%\x.txt` → must_alert and a pop-up.
  It fetches a documentation page.

### R21 Program with a bad code signature connects out (`host_bad_sig`) — **built**
- **Threat:** a tampered or self-signed binary talking out: a patched updater, a repacked installer, a trusted
  program whose file no longer matches its signature (T1036.001, T1553.002).
- **Data:** the Windows agent's `outbound_connections` rows (every minute: `name`, `path`, `parent_name`, remote
  address, port) joined by path to its `process_signatures` snapshot (every 5 minutes: authenticode `signature`
  and `signer` per program that holds a socket). Until 2026-10-17 the socket query carried the signature, checked
  per socket: 15 s on a quiet PC, so osquery's watchdog killed it and denylisted it by name for 24 h (twice: 10-14
  and 10-16), leaving this rule and the Windows host context blind for a day each time. Per path it is 5.8 s.
  Either side can arrive first: a connection whose signature is known fires at once; a bad signature arriving
  within 10 minutes of the program's last connection fires then. Older agents' rows that carry `signature` work.
- **Logic:** `rules/R21-bad-signature-connects.yml`. osquery's authenticode reports four results: `trusted`,
  `missing`, `untrusted` and `distrusted`. A file changed after it was signed (a hash mismatch), a self-signed
  or self-built binary and an expired certificate all come back `untrusted`; `distrusted` is a publisher
  Windows blocks. Both → severity 4, suppressible per program: the tampered-binary case lives inside
  `untrusted`, and a dev build is a one-time suppression. `missing` and unreadable signatures raise
  **nothing**: all 7 measured were installed apps osquery couldn't read (the Signal Desktop case host context
  settles by asking Windows), and a standalone "unsigned program" rule waits until the stream carries
  PowerShell-verified results.
- **Baseline:** none. Measured: 0 bad signatures in 34.5 h.
- **Dedupe:** `host_bad_sig|pc|program`.
- **FPs:** self-built tools and dev builds, and old but legitimate software with an expired certificate (both
  `untrusted`: one alert, then a program-scoped suppression).
- **Route:** ALERT, code-only, suppressible.
- **Jev:** none (the summary stays on the box). The signer name is kept as a local fact, quoted like a program
  name: on a self-signed certificate it can be the owner's own name, so it is never a title or an indicator.
- **Safe test:** sign a copy of `curl.exe` with a test certificate (`New-SelfSignedCertificate` and
  `Set-AuthenticodeSignature`) and fetch example.com → `untrusted` → alert. Or flip one byte inside a copy of a
  signed program's body: osquery reports the hash mismatch as `untrusted` and the binary still runs. Appending
  bytes instead makes it say `missing`, which this rule ignores (measured 2026-10-17). The connection must be
  open when the 5-minute signature snapshot runs: fetch a large file from a host that tolerates throttling at
  about 50 KB/s (a 1 KB/s stream was reset by the server after 77 s and missed the snapshot by seconds).
- **Verified live 2026-10-17 12:44** (case #429): the flipped-byte curl copy, run from the Temp folder,
  raised the case one second after the signature snapshot named the file `untrusted` (signer "Microsoft 3rd
  Party Application Component"), joined to the socket rows the 1-minute query had logged since 12:41. Route
  alert, severity 4, no host-context facts, no command line. The osquery denylist that had hidden the first
  attempt was cleared by resetting osquery.db with osqueryd stopped; no old cases re-raised.

**Not built yet, deliberately:** a standalone unsigned-program rule (see R21) and the Linux rules (#28). The
persistence snapshots became R23 and the host ↔ network correlation is below, both on 2026-10-17; each builds on
the same `HostDetector` base and `EndpointState`.

### R22 A log feed has stopped arriving (`feed_silence`) — **built**
- **Threat:** the monitor going quiet without anyone noticing. Measured 2026-10-14 and 2026-10-16: osquery's
  watchdog denylisted the Windows socket query for 24 h each time, and R21 plus the Windows host context were
  blind for a day before a person went looking.
- **Data:** when each record *arrives*, by feed: Zeek's `conn` and `dns`; each endpoint agent's `outbound_connections`,
  `sysmon_events`, `host_addresses`, `process_signatures` (Windows) or `outbound_connections_ctx`,
  `bpf_process_events`, `bpf_connections`, `host_addresses` (Linux/WSL). The two agents share query names, so a
  feed is (log directory, query). Arrival time, not the row's timestamp: the agents and WSL keep different
  clocks, and a backlog catch-up delivers old timestamps live. `run` ticks every detector once a minute.
- **Logic:** `detectors.FeedSilence`. Silence runs from the feed's last arrival or tapwatch's own start, whichever
  is later, so a restart gives a full grace period and a feed already dead at start is still reported. Two ticks
  more than two minutes apart mean the monitor itself was away (the box slept): every clock shifts forward by the
  time away, so a feed nine minutes silent before the sleep is nine minutes silent after it and waking does not
  fire every feed at once. A reboot is a restart, so this rule cannot report it; it shows as the gap in the
  per-hour chart. Feeds of one agent going silent in the same tick make one
  case, the loudest feed first. Limits and severities from the measured gaps over 2026-10-15..17: conn and dns
  20 min, severity 4 (99.9th-percentile gap 0.1 min); Windows sockets 10 min, 4 (ran every 1.1 min until it
  stopped); Sysmon 15, 4 (1.3); the Windows snapshots 20, 3 (5.4); WSL socket history 30, 3 (8.1); eBPF execs
  15, 3 (2.1); eBPF connections 60, 3 (idles 16 min at night); its address snapshot 30, 3 (12.4). Inventory
  queries are too sparse to watch. The router syslog (178 kept rows in two days) is watched through a heartbeat:
  the listener writes a `stats` row to udm.log each 10 minutes it heard the router; once R22 has seen one the feed is
  armed (persisted) and 30 minutes without one is a severity-3 case (2026-10-17: 18.6 h of silence went unnoticed). Config `detectors.feed_silence`:
  `minutes: {feed: n}`, `ignore: [feed]`, `enabled: false`.
- **Baseline:** none; the limits are fixed and measured.
- **Dedupe:** `feed_silence|pc|<agent>:<feed>`; one case per silence, re-armed by the next row.
- **FPs:** osquery or Zeek restarting on their own. Each is worth knowing; suppress per feed if not.
- **Route:** severity 4 feeds ALERT (and the pop-up), severity 3 feeds DIGEST; code-only, no host context (the
  case is about tapwatch, not a connection; #427 was capped at digest by it before this was so), suppressible by the
  leading `<agent>:<feed>` (only feeds with equal limits can share a case; `ignore` drops a feed for good). Jev is
  not asked: nothing to weigh.
- **Safe test:** `Stop-Service osqueryd` (elevated) and wait eleven minutes: one case for the Windows agent
  naming `outbound_connections` first; `Start-Service osqueryd` re-arms it.

### R23 New persistence entry (`host_persist`) — **built**
- **Threat:** a program registering itself to run again (T1053 scheduled task, T1543 service, T1547 Run key or
  Startup folder, cron, launch agent): a dropper that sleeps until the next boot never trips R17–R21.
- **Data:** the agent's hourly differential queries `scheduled_tasks`, `auto_start_services`, `startup_items`,
  `crontab`, `launchd_run_at_load` (osquery.conf): `added` and `removed` rows per run.
- **Logic:** `hostrules.NewPersistence`. Rows are read per query run (same `unixTime`, two minutes' grace) so
  the run is judged as a batch: a key (entry name + what it runs) on both sides is a change, not a new entry; a
  run of five or more adds with no removes is osquery's first listing, an inventory; a key already in `known`
  (persisted) or seen during warm-up is learned silently, and so is a key seen in a `removed` row, so an
  entry that drops out of one run and is listed again at a later one is not new (2026-10-20, #911–#924:
  16 of WSL's package-owned `/etc/init.d` scripts did exactly that). What is left is scored by what the entry runs, with
  the script's folder when it runs one: a suspicious command line (encoded, download-and-run) or a temp,
  Downloads or shared folder → severity 4; a script, a shell or script host, a LOLBin, or a per-user folder →
  3; an installed program with none of those → learned, no case. Once per (PC, query, entry name with GUIDs,
  SIDs, versions and session suffixes stripped) per 7 days below alert.
- **Baseline:** `known`, per PC, learned from every row (bounded at 5,000, oldest forgotten).
- **Measured** 2026-10-16/17, 40 h of the main PC's log, 1,429 rows: 503 removed+added pairs (a task that ran:
  `last_run_time` changed), 3 inventories (36, 108 and 224 rows, after the agent's database was reset), 29
  genuinely new entries. Of those, 19 were Windows' own or an installed app's (per-user svchost services for a
  new logon session, Windows Update and SoftLanding tasks, TrustedInstaller, a sandbox service's version bump)
  and raise nothing; replaying the rows through the rule raised 6 digest items: the owner's two `.vbs` files in the
  Startup folder, OneDrive's three RunOnce entries that run `cmd.exe`, and its startup task under AppData. 0 alerts.
- **Dedupe:** `host_persist|pc|program`, and the 7-day key above for digest items.
- **FPs:** installers and updaters that register a RunOnce or a startup task (a digest line a week per app, by
  the stripped key); the owner's own startup scripts (suppress per program).
- **Route:** DIGEST; ALERT for the suspicious-command and temp/Downloads/shared shapes. Code-only. No path and
  no command line enter the case: the program, the entry name, the folder class and yes/no signals.
- **Jev:** none.
- **Safe test:** `schtasks /create /tn tapwatch-r23 /tr "wscript.exe %USERPROFILE%\Downloads\r23.vbs" /sc once
  /st 23:59` → alert within the hour (the query runs hourly); a `.vbs` copied into the Startup folder → digest.
  Delete both afterwards.
- **Blind spots:** WMI subscriptions, Office add-ins, browser extensions (#27 pass 2); a persistence entry
  pointing at an installed, signed program (an attacker who writes to Program Files is past this rule).

### R24 Backups, logs, protection or accounts changed (`host_destructive`) — **built**
- **Threat:** what ransomware runs before it encrypts and what an intruder runs to stay and hide: shadow
  copies, the backup catalog or recovery removed (T1490), event logs cleared (T1070.001), Defender turned off
  or given an exclusion (T1562.001), a local account or administrator added (T1136.001, T1098).
- **Data:** `sysmon_events` event 1 with the signals the agent computes on the PC: `cmd_shadow`
  (`vssadmin delete shadows`, `vssadmin resize shadowstorage`, `wbadmin delete catalog|systemstatebackup`,
  WMI `shadowcopy delete`, `Win32_ShadowCopy` from PowerShell), `cmd_recovery` (`bcdedit recoveryenabled no`,
  `bootstatuspolicy ignoreallfailures`), `cmd_logclear` (`wevtutil cl`, `Clear-EventLog`, `Limit-EventLog`),
  `cmd_defender` (`Set-MpPreference -Disable…`, `Add-MpPreference -Exclusion…`, `MpCmdRun -RemoveDefinitions`,
  `sc stop|config WinDefend`), `cmd_admin` (`net user … /add`, `net localgroup administrators … /add`,
  `Add-LocalGroupMember`, `New-LocalUser`). Each pattern also matches the tool's `.exe` or quoted-path form,
  which is how a program spawning it looks (7 of the 13 kept lines in the live log start that way). The raw
  command line is never read by this rule; the agent keeps it in its own log when one of these fires, as for
  R17, and a test holds the two clauses to the same five regexes.
- **Logic:** `hostrules.DestructiveCommand`. Any program: `vssadmin`'s command line is vssadmin's, the
  PowerShell forms are PowerShell's. Shadow or logs → severity 5, **must_alert** (no benign reading on a home
  PC; an administrator doing it on purpose knows the alert is coming). Recovery, Defender or accounts →
  severity 4, suppressible per program: `bcdedit recoveryenabled no` is the documented fix for an Automatic
  Repair loop, and an installer or the owner adding an exclusion or a user happens once. A shell chain
  (`cmd /c vssadmin …`) carries the same line on both starts milliseconds apart: the same harm on the same PC
  within a minute is one case, named after the first program seen.
- **Baseline:** none. Measured 2026-10-16/17, 40 h of the main PC's log, 15,389 process starts: vssadmin,
  wbadmin, bcdedit, wevtutil, net, net1 and wmic started 0 times (reg.exe 1,537, PowerShell 581, cmd 501,
  mpcmdrun 24 for Defender's own updates, none with `-RemoveDefinitions`, schtasks 15, sc 5); the 13 command
  lines the agent kept matched none of the patterns.
- **Dedupe:** `host_destructive|pc|program`, the store's hour, plus the one-minute same-harm rule above.
- **FPs:** an installer adding a Defender exclusion for its folder (severity 4, then a program suppression);
  re-enabling protection (`-DisableRealtimeMonitoring $false` matches too: severity 4, once); the owner
  creating a local account or repairing boot with bcdedit (once). None for the must_alert pair in the
  measured window.
- **Route:** ALERT, code-only; must_alert for shadow and logs. Host context does not apply: the command is
  the verdict, whoever typed it.
- **Jev:** none.
- **Safe test:** `cmd /c echo vssadmin delete shadows /all` from a terminal: the echo's command line carries
  the pattern, nothing runs, the agent flags it → one must_alert case (cmd and its echo are one chain) and a
  Herdr pop-up. `powershell -c "echo Add-MpPreference -ExclusionPath x"` → severity 4 alert. Needs the agent's
  updated `osquery.conf` (`agents/windows/install.ps1` copies it; or copy it by hand and restart osqueryd; see
  agents/README.md).
- **Blind spots:** the same actions through the registry or Group Policy without a command line
  (`DisableAntiSpyware` via `reg add`, which R24 does not read), WMI from a compiled binary (no command line),
  and log clearing by deleting the `.evtx` files; Sysmon 10 (LSASS access) is a separate rule.

### R25 Burst of discovery commands (`host_recon`) — **built**
- **Threat:** the first minutes on a foothold: who am I, what is this machine, what network and domain is it on
  (T1033, T1082, T1016, T1087).
- **Data:** `sysmon_events` event 1, program and parent names only.
- **Logic:** `hostrules.DiscoveryBurst`. One parent starts ≥ 3 different discovery tools within 5 minutes, ≥ 2 of
  them strong (`whoami`, `systeminfo`, `nltest`, `net`, `quser`, `query`, `klist`, `cmdkey`, `dsquery`, `arp`,
  `wmic`); the weak ones (`ipconfig`, `netstat`, `nslookup`, `route`, `hostname`, `tasklist`, `getmac`) count
  towards three but never make it alone. A shell as the parent (someone typing) → severity 3; anything else
  → 4. One case per burst.
- **Baseline:** measured 2026-10-16/18, 51.5 h, 17,577 starts: 37 discovery starts, all weak (ipconfig 27 from
  tailscaled, tasklist 10 from wslhost); no parent ever reached three tools in five minutes.
- **FPs:** an IT script or the owner diagnosing a domain problem (a digest item from a shell).
- **Route:** ALERT, DIGEST from a shell. Code-only. **Safe test:** `whoami`, `systeminfo` and `nltest
  /domain_trusts` typed in PowerShell within five minutes → one digest item (a shell parent); the alert shape
  needs a non-shell parent, which the selfcheck covers.

### R26 New browser extension with sensitive access (`host_extension`) — **built**
- **Threat:** a malicious or bought-out extension stealing cookies and sessions with nothing on disk (T1176).
- **Data:** the agent's daily `chrome_extensions` differential rows (every Chromium browser, every OS).
- **Logic:** `hostrules.BrowserExtension`, R23's batching, inventory and warm-up learning keyed on the
  extension's identifier (an update is a change). Debugger or proxy permission → severity 4; cookies, history,
  web requests, native messaging, management, clipboard or capture → 3; otherwise nothing. osquery's
  `permissions` column has API permissions, not Manifest V3 host permissions, so "every site" only counts where
  an extension lists `<all_urls>` there.
- **Baseline:** measured 2026-10-18: 1 added and 2 removed rows in 51.5 h; of 7 installed extensions, 4 ask for a
  digest-level API (two password managers, an ad blocker, a mouse vendor's), none for the debugger or proxy.
- **Route:** DIGEST, ALERT for the debugger or proxy. Code-only. **Safe test:** load an unpacked test extension
  whose manifest asks for `debugger`; the case arrives after the next daily run.

**R23 also reads WMI event subscriptions** (`wmi_persistence`: command-line and script consumers, hourly, Windows),
an alert whatever they run (T1546.003). Measured 2026-10-18: the only subscription on the main PC is Windows' own
SCM event-log filter, whose consumer is the built-in log kind, so 0 rows.

### R27 Linux program from a temporary folder or memory, or a shell, connects out (`host_linux_connect`) — **built**
- **Threat:** a dropped second stage run from `/tmp`, `/dev/shm`, `/var/tmp` or `/run/user`, a payload run from
  memory (memfd), and a reverse shell (`bash -i >& /dev/tcp/…`, `nc -e`, `socat exec:`) (T1059.004, T1105).
- **Data:** the agent's eBPF `bpf_connections` rows (every outgoing connection, however short; Linux and WSL).
- **Logic:** `hostrules.LinuxSuspiciousConnect`. An outside connection by a program whose path is in one of those
  folders or a memfd, or by a shell or netcat (`bash`, `sh`, `dash`, `zsh`, `ksh`, `nc`, `ncat`, `socat`,
  `telnet`) → severity 4, suppressible per program. A binary deleted while running is not counted.
- **Baseline:** measured 2026-10-16/18, 30.7 h of the WSL box: 49,975 outgoing connections, none from those folders
  or memory; shells started 78,967 times and held a connection 0 times; java, lua and python connected while
  deleted (package upgrades), hence no "deleted" clause.
- **Route:** ALERT, code-only. **Safe test:** `cp /usr/bin/curl /tmp/c && /tmp/c -s https://example.com >/dev/null;
  rm /tmp/c` → one alert. **Blind spots:** an interpreter (python, perl) holding the shell's socket; a payload
  under the home folder; the 26,447 of 49,975 eBPF rows with no path (the process had exited when osquery looked
  it up), so the measured zero covers the 47% that carry one. **FPs:** `go run` binaries under /tmp/go-build*,
  AppImages under /tmp/.mount_*, installers or test copies run from /tmp (suppress per program).

**R23 on Linux also reads** new SSH authorized keys (`authorized_keys`: the key type and its last 16 characters,
never the file path; an alert, T1098.004) and new systemd units (`systemd_units`: units outside the package
directories, snap mounts excluded, and every user unit file; a digest item, T1543.002). Measured 2026-10-18 on the
WSL box: 0 keys; 24 user unit files (13 files and 11 enablement links), which the first run after deploy lists at
once and R23 learns as an inventory. Any batch osquery marks as a query's first run (`counter` 0) is an inventory
whatever its size, so a machine with one or two existing keys does not alert on them. The same key added to a
second account is not seen again (the key identity has no account).

### R28 Suspicious command on Linux (`host_linux_cmd`) — **built**, baseline measured
- **Threat:** download-and-run (`curl … | sh`), reverse shells (`/dev/tcp/`, `nc -e`, `socat exec:`,
  `bash -i >&`, Python or Perl socket one-liners), base64 decoded into a shell, shell history switched off or
  cleared, a file in /tmp, /dev/shm or /var/tmp made executable (T1059.004, T1105, T1027, T1070.003).
- **Data:** the agent's `bpf_process_events` query computes `lcmd_dlrun`, `lcmd_revshell`, `lcmd_b64exec`,
  `lcmd_histclear`, `lcmd_tmpexec` from the command line on the PC and keeps the line itself only when one fires
  (the results log is mode 0644, readable by every local account); a test holds the two clauses to the same five
  patterns. The rule never reads the command line.
- **Logic:** `hostrules.LinuxCommand`. Any signal → severity 4, suppressible per program; the temp-folder chmod
  alone → 3. The same signals within a minute are one case (`sudo bash -c "…"` starts two processes with one line).
- **Baseline:** measured 2026-10-20 over the first two days with command lines on (from 2026-10-18), from the case
  store: two cases. One was the safe test below; the other a file in a temporary folder made executable during
  normal work (digest, closed as expected). That signal already routes to the digest on its own, so it stays
  there; nothing demoted. The four alert-level signals fired on nothing but the test.
  Each pattern was checked against matches and harmless neighbours (`curl -o`, `nc -zv`, `nc -l`, `base64 -d
  file`, `chmod 644 /tmp/…`, `grep -e`, `docker exec`), and the shipped SQL was run in osquery.
- **FPs (expected):** installers the owner or a coding agent runs with `curl … | sh` on request; netcat tests.
- **Route:** ALERT (chmod alone: DIGEST). Code-only. **Safe test:** `bash -c 'curl -s https://example.com | sh -s
  </dev/null'` (the page is HTML, `sh` reads nothing from stdin and exits) → one alert; `bash -c 'curl -s
  https://example.com | head -c0'` → nothing.
- **Blind spot:** a pipeline typed interactively is several execs, none with a `|` in its argv, and `history -c` /
  `unset HISTFILE` typed there are builtins: R28 sees `bash -c "…"` / `sh -c "…"` strings (scripts, cron, coding
  agents). The kept command line can hold a token and lands in a 0644 log, the same trade-off as Windows.

### R29 A program reads lsass memory (`host_lsass`) — **built**, baseline measured
- **Threat:** credential dumping from lsass.exe (mimikatz `sekurlsa`, `rundll32 comsvcs.dll, MiniDump`,
  `procdump -ma lsass`), T1003.001.
- **Data:** Sysmon event 10 (process access), now on in `agents/windows/sysmon.xml` for lsass.exe as the target,
  with Windows' own openers left out there (svchost, wininit, csrss, services, wmiprvse, the Defender and MDE
  engines); the agent's `sysmon_events` query carries `source_path`, `target_path` and `granted`.
- **Logic:** `hostrules.LsassAccess`. An access mask with PROCESS_VM_READ (0x10) → severity 4, suppressible per
  program (an EDR, a password manager); from a temp, Downloads or shared folder, or started by a document or mail
  app → severity 5, must_alert. Query-only masks (0x1000, 0x1400: Task Manager, monitors) → nothing.
- **Baseline:** measured 2026-10-19 (6 hours of event 10): 8,823 lsass opens, every one query-only (0x1000):
  powershell.exe 8,731, GamingServices 72, osqueryd 14, Edge's updater 6. None with VM_READ, so no case. The
  query-only masks are now dropped in `sysmon.xml` itself (about 35k rows a day of log volume, #183); a VM_READ
  opener that turns up later is added to the exclusions by folder, never by name alone, or suppressed.
- **Route:** ALERT, code-only. **Safe test:** in an admin PowerShell, `(Get-Process lsass).Modules | Select -First 1`
  lists one module of lsass (it opens lsass with VM_READ and reads nothing secret) → one severity-4 case for
  powershell.exe.

**R23 on Linux, pass 2 (#28, 2026-10-18)** adds five kinds from new agent queries, each checked with osqueryi first:
a new set-user-ID program (`suid_bin`; severity 4 from a home, temporary or unknown folder, 3 under the package
folders), a new kernel module (3), `/etc/ld.so.preload` with content (5, must_alert: every program loads it), a
privileged or Docker-socket container (3), and a new Linux listener outside loopback when it is a shell or netcat
(a bind shell) or runs from a home or temporary folder (4). Windows listeners are left out: 47 new ones in 21 h,
mostly svchost. Measured on the WSL box: 40 SUID programs, 23 modules, no preload, no such container, 11 stable
listeners, all learned as the first run's inventory. R28 gains `lcmd_miner` (stratum URLs, xmrig, `--donate-level`).

### R36 A remote-access tool starts on a PC (`host_rmm`) — designed (#39)
- **Threat:** remote monitoring and management tools used as a way in (T1219): tech-support scams talk the
  victim into AnyDesk or Quick Assist, and ransomware crews install ScreenConnect, AnyDesk or Atera because they
  are signed, trusted and allowed out. The network side is R16 (`takeover`, the tools' servers); this is the PC's
  side: which program, from which folder, started by what.
- **Data:** process starts already collected: Sysmon event 1 (`path`, `parent_path`) on Windows, eBPF
  `bpf_process_events` (`path`) on Linux. A built-in table maps program file names to a tool and its R16 service
  (`anydesk.exe` → anydesk.com; about 30 tools: AnyDesk, TeamViewer, RustDesk, ScreenConnect, Splashtop, Atera,
  LogMeIn, Ammyy, Supremo, SimpleHelp, MeshCentral, Tactical RMM, NetSupport, UltraViewer, DWService, Zoho Assist,
  Action1, NinjaOne, Kaseya, Pulseway, TightVNC/UltraVNC, Quick Assist). One agent change: Sysmon event 1's
  `OriginalFileName` (from the program's version resource) is collected too, so a renamed copy still matches.
- **Logic:** per (device, tool), the first start after the learning window is a case; later starts are not. The
  learning window is the rule's first 7 days on a box (persisted), so a company's own RMM on an office PC is
  learned, not reported forever; a start from Temp, a shared folder or a document app is never learned, even in
  that week. Known as well: `detectors.host_rmm.expected_tools` (tool names), and a `takeover.expected` entry for
  this PC and the tool's R16 service (only 14 of the tools have one). Severity from the folder class: an installed
  folder (Program Files, /usr, /opt) 3; a user folder (AppData, home) or Downloads 4, suppressible per (device,
  tool); Temp or a shared folder, or started by a document or mail app (`WIN_DOC_APPS`), 5 and must_alert. Quick
  Assist (built into Windows; System32 or the Store app's folder) is 4 wherever it runs.
- **Baseline:** measured 2026-10-19/20: 11,055 Windows process starts in 29 h and 288,764 Linux execs in two days,
  no remote-access tool among them.
- **FPs (expected):** the owner installing a tool to help family; an office's IT tool (learned, or an `expected`
  entry); a one-off Quick Assist session; a real installer that runs the tool from Temp once during setup (one
  must-alert per tool: risky starts are tracked apart from the learned tool, so a portable copy later is not missed).
- **Route:** as above, code-only; pairs with R16's network case through host ↔ network correlation.
  **Safe test:** copy `notepad.exe` to `%TEMP%\AnyDesk.exe`, run it and close it → one must-alert case (Temp is
  never learned, so it works in the first week too; a second run is not reported again).
- **Blind spot:** a renamed copy with no version resource, or a tool not in the table; R16 still sees its servers.

### R37 A tunnel is opened from a PC (`host_tunnel`) — designed (#39)
- **Threat:** a tunnel opens a way *in* to a PC from the internet, past the router (T1572): `ngrok`,
  `cloudflared tunnel`, `code tunnel`, `devtunnel host`, `tailscale funnel`, `ssh -R`, localtunnel, bore.
- **Data:** new command-line signals computed on the PC, as for R24 and R28: `cmd_tunnel` in the Windows
  `sysmon_events` query and `lcmd_tunnel` in the Linux `bpf_process_events` query. Unlike R24 and R28, the
  command line is **never kept** for this signal: a tunnel's line carries its token (`cloudflared --token`,
  `ngrok --authtoken`) and the results log is readable by every local account. On Linux, when it fires, the
  query also reads the Claude Code environment markers of the process and its parent (`process_envs`, as
  `bpf_connections` already does): a tunnel is long-lived, so the process is still there a minute later.
- **Logic:** severity 4, suppressible per (device, program); from Temp or a shared folder 5, must_alert. Started
  in an *attended* Claude Code session (the markers say so) → severity 3 and `agent_started`: the owner is at the
  keyboard and asked for it, so a digest item. An unattended or SSH-driven session stays an alert: a
  prompt-injected agent opening a tunnel is the threat itself.
- **Baseline:** no tunnel program started in the windows above; the signal's own baseline is the first day after
  the agent config is updated.
- **FPs (expected):** the owner's own dev tunnels and `ssh -R` for remote work (agent-started ones go to the
  digest; others are suppressed per program once).
- **Route:** as above, code-only. **Safe test:** `ssh -o BatchMode=yes -o ConnectTimeout=2 -R 9:localhost:9
  test@192.0.2.1` (TEST-NET, fails at once) → one case.

### R38 Files staged or sent somewhere new (`host_staging`) — designed (#39)
- **Threat:** exfiltration with trusted tools (T1567, T1560): `rclone`, `restic`, `megacmd`, cloud CLIs (`aws s3`,
  `az storage`/`azcopy`, `gsutil`/`gcloud storage`), WinSCP scripts; a password-protected archive of Documents or
  Desktop before the upload.
- **Data:** new signals `cmd_sync`/`lcmd_sync` (a copy or sync to a remote) and `cmd_archive_pw`/`lcmd_archive_pw`
  (7-Zip `-p`, RAR `-hp`/`-p`, `zip -e`/`-P`). The command line is **never kept** (an archive password or a
  `rest:https://user:pass@` repository would land in a world-readable log); the query extracts only the
  *destination* with a capture group (`regex_match(…, 1)`) into a `dest` column: the rclone remote name,
  `s3://bucket`, `gs://bucket`, the storage account, the restic repository host (`env` when it comes from the
  environment). The destination is an indicator.
- **Logic:** per (device, tool, destination): new after the 7-day learning window → severity 3 (digest); known →
  nothing. A password archive → 3; of Documents, Desktop or Pictures → 4. An `upload_spike` from the same device
  within five minutes pairs with it (host ↔ network correlation) and makes an alert. Agent-started on Linux (the
  markers, as R37; a short `rclone` run may be gone before the query reads them): `agent_started` fact, digest.
- **Baseline:** 2026-10-20: a nightly `restic` (3 execs) on the Linux box, learned in the window; 7-Zip twice from
  a hardware vendor's installer, no password.
- **FPs (expected):** the owner's backups to a new bucket; a new cloud CLI workflow; zipping a folder with a
  password to send it.
- **Route:** digest, alert when paired; code-only. **Safe test:** `rclone copy /etc/hostname testremote:` with a
  remote that doesn't exist (fails) → one digest item naming `testremote`.

### R39 A persistence or credential file changes (`host_fim`) — designed (#167)
- **Threat:** persistence and privilege through files rather than registered entries (T1546.004, T1574.006,
  T1548.003, T1547.001): a shell start-up file gaining a line, `/etc/ld.so.preload`, `sudoers`, a file dropped in
  a Windows Startup folder.
- **Data:** Linux: osquery `file_events` (inotify; `--enable_file_events=true` beside the existing
  `--disable_events=false`). `file_paths` watches *directories* (`/etc/`, `/etc/sudoers.d/`, `/etc/profile.d/`,
  each home and `/root/`, their `.config/autostart/`) and the query's WHERE picks the files (`ld.so.preload`,
  `sudoers`, anything in sudoers.d and profile.d, the shells' start-up files, autostart entries), leaving out
  `sed`'s and editors' temporary names. Measured with osqueryd 5.23.1: a watch on a single file misses a file that
  doesn't exist yet (ld.so.preload normally doesn't) and goes blind after the first save-by-rename (`sed -i`,
  visudo, editors); a directory watch sees a new file as CREATED and `sed -i` as MOVED_TO the real name, and keeps
  seeing later writes. Wildcards expand when the config loads, so a home created later needs a restart. The query
  strips `/home/<user>` to `~` in SQL. inotify works on WSL2's ext4, not on `/mnt/c`. Windows: Sysmon
  event 11 (file created), its "off" include removed and a `TargetFilename contains \Start Menu\Programs\Startup\`
  include added; `sysmon_events` gains event 11, filtered to Startup folders in its own WHERE too (so a fuller
  Sysmon config can't turn every file creation into a case), and keeps the file's base name and whether the folder is per-user
  or all-users, never the path (it holds the user name). Sysmon names the program that wrote it.
- **Logic:** `ld.so.preload` or sudoers written → 4 (R23 still reports preload *content* at 5). A shell start-up
  file changed → 3. A Startup-folder file created by a shell, script host, LOLBin, document or mail app, or from a
  temp folder → 4; by anything else (installers) → 3. Ships at digest for every kind until a week's volume is
  measured; then the 4s alert.
- **Baseline:** to measure: file-event volume on the dev PC (coding agents and editors touch dotfiles) and
  Startup-folder writes in a week.
- **Blind spot:** osquery's file monitoring can't say which program *read* a file, so "a credential file read by a
  program that doesn't own it" stays out (a later step, with an eBPF file-open query). WSL's inotify sees only
  Linux paths.

### Host ↔ network correlation (built 2026-10-17)
- **Idea:** a host case (R17–R23, what the PC's own agent saw) and a network case (what the wire saw) on the
  same device within five minutes are one story: `certutil` fetched something and a new domain was contacted;
  an encoded command ran and a first contact followed; a program in Temp connected and the sensor saw where.
- **Logic:** `pipeline.correlate`, when a case is handled: the store's cases on the same device (MAC when both
  sides know it, else the address) within ±300 s whose side differs (`source: endpoint` against the rest; R22's
  monitor cases pair with nothing), and only when the host rule names that network rule as part of its story
  (`hostrules.PAIRS`, checked from both sides): a program reaching out (R17–R21, R27, R28) pairs with first
  contacts, beacons, DNS and TLS oddities, takeover channels, odd ports, uploads and IDS verdicts (not DNS bypass); R36 remote-access tools and R37 tunnels with
  R16 only; R38 staging with upload_spike and R16; R39 file changes with nothing. Measured 2026-10-20: with any
  pairing allowed, every R36–R39 safe test was lifted to an alert by an unrelated dns_bypass digest item three
  minutes earlier (the dev PC has network digest items most hours). Up to three partners go into the case's `correlated` facts, newest first,
  with the loudest partner's route as `correlated_best`; the earlier case gets the same entry pointing back
  and a note on its page. The summary tells Jev in one sentence that the other side raised a case and what.
- **Routing** (`router.route`, applied after the code caps): next to an alert the other side is at least a
  digest item; two digest-or-louder sides make an alert. A suppression still wins, and so does the learning
  period; must-alert cases are untouched.
- **Measured** 2026-10-17 on the live case history, the 06:00 replay flood excluded: the pairs that were one
  story sat 0.0, 2.5, 3.7 and 4.4 minutes apart (a temp-folder curl and its new domain, #403/#405; a tampered
  binary and its new domain, #429/#430; a LOLBin and a new domain, #775/#776; a tls_odd item and the encoded
  command after it, #785/#786), and the nearest unrelated cases 6.2 and 11 minutes away: a five-minute window.
  The floor re-routes none of them: the three alert pairs are alerts already, and #786 was suppressed, which
  is why a suppressed case is not a partner at all. The floor is for the next real pair.
- **Not lifted:** a case code capped at digest (`host_max_route`, `max_route`: the PC's checks found the
  program clean) or read as the owner's agent work (`owner_likely`) stays at digest next to a digest partner;
  on the dev PC the agent spawning a shell and then connecting is the normal day.
- **FPs:** a dev PC raises a logged new-domain case every few minutes, so a host digest item will often find
  one; the pair then reads together in the digest, which is the point. Nothing is lifted above digest unless
  both sides were already digest or louder.
- **Fixed alongside:** the host rules' PC address. WSL in mirrored mode reports 10.255.255.254 next to the
  LAN address, and it sorted first, so three host cases carried a host no identity knew (#792–#794). The LAN
  address is now the one on a configured router's /24 (`network.gateways`), with the old order as the fallback.

### Dev-workstation profile (built)
`dev_profile.hosts` marks machines that run coding agents. For those hosts only, `beaconing`,
`dns_anomaly` and `new_domain` skip traffic **tied by name** (DNS query or TLS SNI) to a dev
service: model APIs, editors, GitHub, package and container registries, and the RDAP/VirusTotal
lookups the enrich-case skill makes (`detectors.DEV_DOMAINS` plus `dev_profile.domains`).
Unnamed traffic, other devices, scans, uploads, the home rules and R16 are judged as usual.
Trade-off: abuse that rides a dev service (exfil to a gist, C2 over a model API) is hidden from
those three detectors. R16 covers the dedicated exfil and tunnel channels instead. Measured on
2.9 h: the main PC's first-seen dev names (Copilot, Docker, PyPI, Trivy, GCR, Claude, RDAP,
VirusTotal) dropped out. What remains is browsing, which logs only.

### Summary

| Rank | Rule | Source | Route | Jev |
|---|---|---|---|---|
| 1 | R01 Internet-exposed service | Zeek + UDM | alert | code-only |
| 2 | R02 IoT egress drift | Zeek + ASN DB | digest→alert | `Q-role-fit` `Q-cat` `Q-wake` |
| 3 | R03 Management-plane access | Zeek | alert | code-only |
| 4 | R04 Beaconing (home-tuned) | Zeek | Jev | `Q-cat` `Q-sev` `Q-routine` `Q-wake` |
| 5 | R05 New device | Zeek DHCP + UDM | digest/alert | `Q-role` `Q-human` `Q-wake` |
| 6 | R06 Odd-port / long-lived | Zeek | Jev | `Q-cat` `Q-human` `Q-wake` |
| 7 | R07 DNS bypass | Zeek | digest | code (advisory `Q-role-fit`) |
| 8 | R08 Rare / NRD domain | Zeek + Tranco + NRD | code | **none (weak spot)** |
| 9 | R09 Upload drift / camera stop | Zeek | Jev | `Q-cat` `Q-routine` `Q-wake` |
| 10 | R10 TLS weak-signal stack | Zeek (+JA4) | digest/Jev | light `Q-cat` `Q-wake` |
| 11 | R11 UDM admin new source | UDM syslog | alert | code-only, must_alert |
| 12 | R12 Off-hours drift | Zeek | Jev | `Q-routine` `Q-human` `Q-cat` |
| 13 | R13 Cleartext credentials | Zeek | digest/alert | code-only |
| 14 | R14 Rogue DHCP | Zeek + UDM | alert | code-only, must_alert |
| 15 | R15 DNS anomaly / tunnelling | Zeek | Jev | `Q-cat` `Q-sev` `Q-wake` |
| — | R16 Takeover channel (built) | Zeek | alert | code-only; must_alert for exfil |
| — | R17 Encoded / download-and-run command (built) | osquery + Sysmon | alert | code-only; must_alert for combinations and document parents |
| — | R18 Document app or browser → shell (built) | osquery + Sysmon | alert | code-only |
| — | R19 Temp-folder program connects out (built) | osquery + Sysmon | digest / alert | code-only |
| — | R20 Built-in tool (LOLBin) connects out (built) | osquery + Sysmon | alert (msbuild: digest) | code-only; must_alert for the downloaders |
| — | R21 Bad code signature connects out (built) | osquery snapshot | alert | code-only |
| — | R23 New persistence entry (built) | osquery differential (tasks, services, startup, cron, launchd) | digest / alert | code-only |
| — | R24 Backups, logs, protection or accounts changed (built) | osquery + Sysmon | alert | code-only; must_alert for backups and logs |
| — | R25 Burst of discovery commands (built) | osquery + Sysmon | alert (shell: digest) | code-only |
| — | R26 New browser extension with sensitive access (built) | osquery differential | digest / alert | code-only |
| — | R27 Linux temp, memory or shell connection (built) | osquery eBPF | alert | code-only |
| — | R28 Suspicious command on Linux (built, baselined) | osquery eBPF exec + command-line signals | alert (temp chmod: digest) | code-only |
| — | R29 A program reads lsass memory (built, baselined) | osquery + Sysmon event 10 | alert (must for temp/document) | code-only |
| — | R36 A remote-access tool starts on a PC (designed) | Sysmon event 1, eBPF exec | digest (installed), alert, must for temp/document | code-only |
| — | R37 A tunnel is opened from a PC (designed) | command-line signals | alert (agent-started: digest; must from temp) | code-only |
| — | R38 Files staged or sent somewhere new (designed) | command-line signals, destination | digest, alert when paired with an upload | code-only |
| — | R39 A persistence or credential file changes (designed) | osquery file_events, Sysmon event 11 | digest until baselined | code-only |

## Host context: owner's agent, agent misused, or attacker (built)

Network data can't tell the owner's coding agent from an attacker. On the tapwatch PC,
`hostctx.py` asks the box. Every answer is a code fact:

| Fact | From |
|---|---|
| program holding the connection | live osquery (fresh cases) + agent's 1-min history |
| started by a Claude Code session? attended? interactive (`cli`)? | process environment markers |
| from the owner's Herdr terminal / an SSH login? | `HERDR_PANE_ID` / `SSH_CONNECTION` markers |
| agent ran a command naming the destination; minutes since owner's prompt | the session's transcript, matched by the destination's names; its addresses only when the case has no name (`host_matched_by`) |
| owner's prompt named the destination | the session's transcript |
| agent read web content between the prompt and the command | the session's transcript (WebFetch/WebSearch/browser tools) |

Code verdict: **agent_misused** (unattended or SSH-driven session, or web content then an unrequested
action) → ALERT past suppressions, and a Herdr pop-up. **owner_using_agent** only when an attended
interactive session made it and the owner's prompt named the destination → LOG. When the agent is known
only by its binary in the exec chain (no markers reached, so attendance unknown and the session a best guess),
the owner's own prompt naming the destination **by name**, with no outside content read in between, corroborates
it too → LOG unless Jev disagrees; "attendance could not be read" stays on the risk list, so Jev's misuse vote
can still alert it. Measured 2026-10-16/17: 84 cases with host context, 0 corroborated by markers, because the
markers live on the agent's child shells and never on the `claude` process, so this is the path real cases take.
Matched only by address (the case had no name; #379 matched a shared Cloudflare address to the wrong transcript),
or with outside content read first, the verdict is issued uncorroborated → normal routing. **other_program**
→ normal routing. **agent_unconfirmed** → normal routing. Jev (`WHO` choice question) can hold it to
DIGEST, never LOG. Must-alert cases are never lowered. Jev gets sentences only: no session ids,
paths, command lines or prompt text.

Measured live 2026-10-13: a `curl` this session started (then orphaned) was traced to its Claude
session, attended, inside Herdr, with the transcript entry. The first rule ("agent acted within
30 min of a prompt") wrongly confirmed it as owner work, because the owner had never named the
destination. Proof now requires the owner to have named it, since injected instructions can also
come from files and tool output.

## Built in M2 (2026-10-13): what changed from the specs above

- **State persistence.** Each detector declares what it has learned (`PERSIST`). The pipeline saves it to
  SQLite every 10 minutes and on shutdown, and `run` restores it. Before this, a restart wiped every
  baseline and restarted the 24 h warmup.
- **R05:** keyed on `orig_l2_addr` (Zeek `mac-logging`, loaded by `deploy/zeek/tapwatch.zeek`), with an
  IP fallback. A randomized MAC with a known DHCP hostname is the known device. Severity 3 at night (01–06).
- **R06:** learns the house's port set for `learn_days` (default 7). Skips UDP ≥ 1024, long sessions
  on 443, and new ports to a service the device already uses. A 14 h home replay with only 6 h of
  learning gave 3 cases in 8 h, all IoT first seen after the short window.
- **R07:** devices that bypass during warmup are learned (the camera's hardcoded resolver). Code-only routing.
- **R15:** ≥ 200 queries to one non-popular zone in 10 min with long first labels (> 30) or ≥ 50%
  TXT/NULL. NXDOMAIN bursts now need ≥ 5 distinct names, so one dead name retried in a loop
  (the remote-access agent measured above) no longer counts as DGA.

- **R09 + R12** are one detector, `HourlyProfile`. Every device's hour closes on the log clock, silent hours
  included, so a camera that stops sending is noticed. Baseline is the same hour on 3+ earlier days,
  else recent hours. `upload_stopped` (≥ 50 MB/h steady, then < 5% for 2 h) is code-only. Off-hours
  needs 7 nights. The overnight replay gave one case: the work laptop's 700 MB hour, the same one the
  old rule caught. `timezone` (config) drives every time-of-day rule.

- **R02** judges devices whose `assets.yaml` role marks them fixed-function (camera, TV, hub, printer,
  network gear…), each learning its own networks, countries and ports for 7 days. It skips NTP
  (volunteer pool servers worldwide gave the hub a "new country") and destinations whose name is a
  service the device already uses. **R10** learns per (device, port) during warmup, because the camera
  talks to its vendor with no name, hardcoded IPs and self-signed TLS on 32403, and it reports once
  per (device, port). Overnight replay with those two changes: 0 cases from either rule.
- `tapwatch update-feeds` downloads Tranco top-100k, the IEEE OUI registry and iptoasn's IPv4 table
  into `feeds_dir` over https. Unset list settings default to it.
- Vulnerability data for the agents' software inventory (#224/#225; `inventory.py`, `vulns.py`): `kev.json`
  (CISA KEV, 1,754 CVEs on 2026-10-20), `osv-<release>.tsv.gz` (OSV's dump for each Linux release an agent
  reports, filtered to that exact ecosystem, since Ubuntu 24.04's dump also carried 14.04 entries, and cut to the
  installed source packages: 142 MB zip to 5,252 ranges, 33 KB, in 7.6 s) and `nvd-ranges.json` (NVD version
  ranges for the KEV CVEs on the Windows products `inventory.WINDOWS_PRODUCTS` maps, at most 60 new records a
  run at NVD's public 5-per-30-s limit, kept 90 days). Debian versions compare with dpkg's ordering
  (`inventory.dpkg_compare`, checked against `dpkg --compare-versions` on 134 real pairs). A range with no
  fixed version yet is not a match: R48 needs something to upgrade to. Windows itself (patched by build through
  Windows Update) and Microsoft Office (Click-to-Run builds) are not covered; Edge is under-reported, because
  NVD files Chromium bugs against google:chrome and only sometimes against edge_chromium.
- `ioc_match` also reads the AdFection / Candiru indicators (The Citizen Lab's "Exposing AdFection",
  2026-10-15, with Confiant, Recorded Future and older Candiru reporting), as curated with a tier per
  line by the zero-breach project (CC0). `update-feeds` takes one pinned release and writes it only if
  its SHA-256 matches. The tier decides the route: `cc`, `validator`, `candiru` and `candiru-ip` are
  spyware infrastructure and always alert; `delivery` (Discover-Tech's ad servers, three of them in the
  Tranco top 20k) is severity 4 and `historical` (older campaigns, often a secondary source, names that
  may since have been re-registered) is severity 3, both routed like any other case. A bad upstream row
  can't page on LAN traffic: LAN, loopback and multicast addresses, dotless names and file hashes are
  dropped on load, and bare `adtimizer.co` is skipped as the list's own blocklist export skips it.
  Replayed against a week of the home mirror (2026-10-13 to 10-20): 0 hits.

## 6. Build order

_Status 2026-10-12: R01, R03, R13 and R14 are built into `detectors.py` (step 2). Replayed against
1.2 h of the mirror with `network.gateways` and the main PC as admin set, they produced 0 cases.
The first replay found a false positive. A VPN flow already running at capture start looked like an
inbound service, so R01 now skips the first 2 minutes, mid-stream TCP and UDP replies.
`network.gateways` is optional: the router is learned from the logs. With no network config, 2.5 h
of the mirror learned the UDM, produced 0 rogue-DHCP cases at warmup 0, 600 and 3600 s, and gave 1
correct R03 case at warmup 0 (the main PC opening the UDM admin page, not on an admin list)._

1. Zeek: add `mac-logging`, hourly rotation, and the `ja4` package. Re-run `baseline.py` on the full night.
2. Code-only, no-baseline rules first: R01, R03, R13, R14. They're cheap and need no learning period.
3. A per-device state table in SQLite (ports, ASNs, domains, hour-of-week counters). It unlocks R02, R06, R09 and R12.
4. Per-detector Jev question sets plus household framing in `triage.py`/`summarizer.py`. Re-run the eval,
   including a test that R02/R06 summaries don't push Jev into "is this domain normal" territory.
5. UDM syslog input (CEF) for R11 and to enrich R01, R05 and R14.
