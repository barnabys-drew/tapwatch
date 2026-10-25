# Getting a copy of your traffic (port mirroring)

tapwatch needs to *see* traffic without being in its path. A managed switch can copy
("mirror", "SPAN") every packet on one port to another port, where tapwatch listens.
Mirror the port that connects to your **router**: that's where every device's internet
traffic passes.

```
internet ── router ── [port 1] switch [port 23] ── tapwatch box (second NIC, no IP)
                          │  mirror: 1 → 23
                       your devices
```

## Switches

| Switch | Where |
|---|---|
| **UniFi** (USW) | UniFi Network → Devices → the switch → Ports → the port tapwatch is on → Port Profile / Operation: **Mirroring**, source = the router uplink port. The UDM Pro's own ports can't mirror (only Switching/Aggregating), so mirror on a USW behind it. |
| **TP-Link Omada / Easy Smart** | Switch settings → Port Mirror (Monitoring) → mirroring port = tapwatch, mirrored port = router uplink, both ingress and egress |
| **Netgear Plus / Smart** | Monitoring → Mirroring → enable, source port = router uplink, destination = tapwatch |
| **No managed switch** | A small 5- or 8-port managed switch with port mirroring (TP-Link TL-SG105E, Netgear GS305E, about $30) placed between the router and the rest of the network |

Mirror **both directions** (ingress and egress) of the source port.

## The tapwatch side

- **Linux box:** use a second NIC (USB Ethernet is fine) for the mirror, with no IP address
  (`tapwatch init` suggests the interface without one). Your normal connection carries
  alerts and the case desk.
- **Windows PC:** plug the mirror into a second Ethernet port. Npcap (from npcap.com; the
  Windows installer sets it up) captures it in promiscuous mode with Wireshark's dumpcap, and
  `eval/capture_mirror.sh` streams it into Zeek under WSL ([windows.md](windows.md)). WSL can't capture it directly: Windows drops frames addressed to other machines.

## What the mirror can't see

- Device-to-device traffic on the **same switch** (PC → NAS) never crosses the router port.
  Put untrusted devices (IoT) on their own VLAN so that traffic is routed, and so mirrored.
- Devices plugged straight into the **router's** own LAN ports.
- Wi-Fi client-to-client on the same access point.

Check it works: `tail -f logs/zeek/conn.log` (or `docker compose exec tapwatch tail -f /logs/conn.log`)
should show addresses of devices other than the tapwatch box.
