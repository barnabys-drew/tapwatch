# tapwatch home detections: design

_Written 2026-10-12 as a design, before the rules were built. Status as of v0.1: R01–R07 and R09–R16
are built in `src/tapwatch/detectors.py`, and R08 is the code-routed `new_domain`. See
[Built in M2](#built-in-m2-2026-10-13-what-changed-from-the-specs-above) for how the code differs
from these specs, and [ARCHITECTURE.md](../ARCHITECTURE.md) for how cases are routed._

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
| Windows Security/Sysmon on the main PC | Process ↔ socket (which app beaconed), logons, new services, PowerShell | Sysmon install plus a forwarder; ~1 GB/day; covers **one** of 21 devices | Turns "the PC beacons" into "which process". **Defer:** it's EDR-lite for one box, which is out of the stated scope |
| UniFi Protect | Camera motion and stream events, NVR health | Webhooks or API | R09 context: upload stops while Protect says the camera is online. Low priority |
| Offline enrichment feeds (pull-only) | ASN and country per IP (iptoasn.com TSV or a GeoLite2 ASN DB), Tranco (already have it), daily newly-registered-domain (NRD) list, OUI vendor table | Daily download. **Nothing about the house is sent out** | R02, R08, R05 vendor, R10 |

**Blind spots (by design of the tap):**
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
  show mapping *requests*. UDM syslog shows port-forward and UPnP-mapping *changes* (code reads the event type).
- **Logic:** `rules/R01-internet-exposed-service.sql`. First time an (internal host, port)
  accepts an established inbound connection from the internet. Joined with any mapping
  request from that host in the previous 24 h.
- **Baseline:** none needed. Measured: **0 established inbound services**, 3 unanswered P2P probes.
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
- **Route:** ALERT, code-only. A non-admin device touching an admin port is the verdict.
- **Jev:** none. Note: same-switch SMB/RDP between two PCs is **not visible** (§2 blind spots).
- **Safe test:** from a Windows laptop that isn't on the admin allowlist, open `https://<UDM>` in a
  browser. That's one harmless connection.

### R04 Beaconing, home-tuned (`beaconing`, existing)
- **Threat:** C2 heartbeat.
- **Data:** `conn` per (src, dst, port) inter-arrival times; `ssl.server_name`.
- **Logic:** existing `detectors.Beaconing` (CV ≤ 0.15, ≥10 hits, ≥10 min), plus code facts in
  the case: `sni_popular` (Tranco), `shared_by_n_devices`, `device_role`, `bytes_per_hit`.
- **Baseline:** none for detection. Suppression learns which (role, base-domain) pairs are
  normal heartbeats after 7 days.
- **Dedupe:** existing `dst:port`.
- **FPs:** the camera's vendor-port keepalive, UniFi inform, push services (5223/5228),
  NTP, the hub's MQTT keepalive. Suppress when SNI or base domain is popular **and**
  shared, or the role is fixed-function **and** the destination is in the device's 14-day set.
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
- **FPs:** small business and personal sites, work domains and SaaS tenants (allowlist the
  work laptop's corporate suffixes in config, not in git), and fresh legit CDNs. Use the Public Suffix List
  (`co.uk`) instead of last-two-labels.
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
- **FPs:** phone photo backup, PC cloud sync and game uploads. Code tags the destination as "known
  sync service" from a curated map. That's a lookup, not Jev's guess.
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
  in the house, +1 non-443 port. Raise at ≥3.
- **Baseline:** 7 days for household JA4 prevalence. Measured: 22% no-SNI but only 43 established,
  0.7% bare-IP TCP, and 49 "invalid cert" rows that were all Zeek missing intermediates.
- **Dedupe:** `tls_odd|host|dst`.
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
  config-change events.
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
- **Dedupe:** `cleartext|host|proto|dst`, 30 days.
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
- **Route:** callback and file drop → ALERT, `must_alert`. Tunnel and remote control → ALERT,
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

## Host context: owner's agent, agent misused, or attacker (built)

Network data can't tell the owner's coding agent from an attacker. On the tapwatch PC,
`hostctx.py` asks the box. Every answer is a code fact:

| Fact | From |
|---|---|
| program holding the connection | live osquery (fresh cases) + agent's 1-min history |
| started by a Claude Code session? attended? interactive (`cli`)? | process environment markers |
| from the owner's Herdr terminal / an SSH login? | `HERDR_PANE_ID` / `SSH_CONNECTION` markers |
| agent ran a command naming the destination; minutes since owner's prompt | the session's transcript |
| owner's prompt named the destination | the session's transcript |
| agent read web content between the prompt and the command | the session's transcript (WebFetch/WebSearch/browser tools) |

Code verdict: **agent_misused** (unattended or SSH-driven session, or web content then an unrequested
action) → ALERT past suppressions, and a Herdr pop-up. **owner_using_agent** only when an attended
interactive session made it and the owner's prompt named the destination → LOG. **other_program**
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
