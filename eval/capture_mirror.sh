#!/usr/bin/env bash
# Whole-house capture on Windows+WSL: dumpcap (Npcap, promiscuous) on the mirror
# NIC streams pcap to Zeek in Docker, which writes JSON logs for tapwatch.
#   eval/capture_mirror.sh <out-dir> [hours] [npcap-interface-name]
# WSL can't capture the mirror itself: Windows drops frames for other MACs unless
# Npcap puts the NIC in promiscuous mode, so the capture must happen on Windows.
set -euo pipefail
out=$(realpath -m "$1"); hours=${2:-12}; iface=${3:-Ethernet}
dumpcap="/mnt/c/Program Files/Wireshark/dumpcap.exe"
idx=$("$dumpcap" -D | tr -d '\r' | awk -v n="($iface)" '$NF==n || substr($0, length($0)-length(n)+1)==n {sub(/\..*/,"",$1); print $1; exit}')
[ -n "$idx" ] || { echo "no Npcap interface named $iface" >&2; exit 1; }
mkdir -p "$out"
echo "capturing $iface (#$idx) for ${hours}h -> $out"
"$dumpcap" -i "$idx" -F pcap -a "duration:$((hours * 3600))" -q -w - \
  | docker run --rm -i --name tapwatch-mirror --network none -v "$out":/out \
      -v "$(dirname "$(realpath "$0")")/../deploy/zeek":/tapwatch:ro -w /out zeek/zeek:7.0.0 \
      zeek -C -r - /tapwatch/tapwatch-live.zeek
