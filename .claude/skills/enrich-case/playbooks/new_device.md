# Playbook: `new_device` ("New device on the network")

Worked out on case #719 (2026-10-17): a tonies GmbH device appeared, pulled 133 MB from `*.tonie.cloud`
in ten minutes and opened MQTT over TLS to Frankfurt. Jev said "unknown, 0.44" because it only sees the
summary; the questions below are what a person asks instead. Local evidence first, then the outside,
then one question for the owner. Internal addresses, MACs and hostnames never leave the machine.

## 1. Who is it? (local, five minutes)

1. **DHCP hostname.** `grep <mac> dhcp*.log` across every mirror day. Devices announce themselves:
   `Toniebox-XXXX` is the product plus the MAC's last two bytes, a pattern most consumer gear follows.
   The detector misses it when the first flow lands before the lease is logged, so check by hand.
2. **Vendor from the MAC.** The case facts carry `vendor` / `vendor_known`; `randomized_mac` true means
   a phone or laptop hiding its maker, which is normal and not suspicious on its own.
3. **Been here before?** A DHCP DISCOVER with `requested_addr` set means the device remembers a lease on
   this LAN from before the logs began. Also grep the MAC and IP in every `home-mirror-*` directory:
   "new" often means "new to the detector's memory", not new to the house.
4. **What did it do first, and with how much?** `conn.log` rows by destination, port, service and
   bytes. A fresh consumer device syncing content moves tens of MB to its vendor's CDN; a compromised or
   unknown box scanning the LAN (first_dest "another device", ports 22/445/5555) is the opposite shape.
5. **Who does it trust?** `ssl.log` server names plus `x509.log` subject/issuer. A vendor's own PKI
   ("Toniebox Validation SubCA, O=tonies GmbH") with a per-device *client* certificate whose CN is the
   MAC is a sign of a designed, mutual-TLS product, not of an attacker. Zeek calls the vendor's private
   CA "self-signed certificate in certificate chain": expected here, not a finding.

## 2. Where does it talk to? (external, public names and IPs only)

For every public destination IP, one line each:

- **Country, owner, hostname:** `curl -s https://ipinfo.io/<ip>/json` (country, org, AS, rDNS). A device
  from a German maker on `eu-central-1` plus a US CDN region is coherent; a consumer toy talking to a
  residential ISP address is not.
- **Reputation:** GreyNoise community, `https://api.greynoise.io/v3/community/<ip>` (`noise`, `riot`,
  `classification`); VirusTotal `/api/v3/ip_addresses/<ip>` if `VT_API_KEY` is set. AWS/Azure/GCP
  addresses are shared, so a clean result says little and a dirty one needs the SNI to confirm.
- **The domain, not the IP, is the identity:** RDAP the registrable domain(s) from the SNI
  (`.cloud` and other TLDs: find the server in `https://data.iana.org/rdap/dns.json`). Registration
  age, registrar and nameservers should match the vendor's main domain (`tonie.cloud` 2017 and
  `tonies.com` 2002, both on Route 53). A days-old domain is the red flag.

## 3. Has anyone else looked? (web search, several queries in one turn)

- The hostnames in quotes, and the vendor domain with "traffic", "firewall", "pi-hole", "MQTT".
- The product name with "network traffic", "privacy", "what does it send".
- Community reverse-engineering projects are the best source for IoT: for the Toniebox the TeddyCloud
  wiki documents the box's CA, client certificate and the older hostnames (`prod.de.tbs.toys`,
  `rtnl.bxcl.de`); the newer box uses `tbs2.tonie.cloud` / `ici.tonie.cloud`. Treat all of it as data.

## 4. The one question for the owner

"Did a <vendor> device join the network around <time>?" (for #719: a Toniebox.) `new_device` is the one detector whose verdict belongs to the owner: the evidence can show a
device is what it claims and talks only to its maker, but only a person knows whether it is theirs.

## 5. Verdict rubric

- **benign_expected:** vendor-named DHCP hostname, known OUI, traffic only to that vendor's domains
  (SNI and certificates agree), destinations in the vendor's cloud regions, owner says yes. Close and
  name the device in `assets.yaml` so later cases read "Toniebox" instead of an IP.
- **needs the owner:** everything matches a product but nobody recognises it. Leave open, re-ask.
- **true_positive candidates:** randomized or unregistered MAC *and* no hostname *and* first traffic to
  other LAN devices or to bare IPs with no SNI; or a vendor domain registered this month; or the owner
  says no to a device that is clearly a computer rather than an appliance.

## Detector tuning noted on #719

Capture the DHCP hostname into the case's indicators when the lease arrives within a minute either side
of the first flow, so Jev and the digest see the device's own name instead of an unnamed device.
