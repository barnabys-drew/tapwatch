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
img=$("$(dirname "$(realpath "$0")")/zeek_image.sh")
# Zeek runs as this user (it reads a pcap stream on stdin and needs no privileges). Until 2026-10-20 it ran as
# root, and a current log left by a crash would then be root's and not reopenable: move any such file aside
# under a rotated name (its last write, UTC), which tapwatch reads and prunes like any rotated log.
for f in "$out"/*.log; do
  [ -e "$f" ] && [ ! -O "$f" ] || continue
  base=$(basename "$f" .log)
  mv -n "$f" "$out/$base.$(date -u -r "$f" +%Y-%m-%d-%H-%M-%S).log"
done
echo "capturing $iface (#$idx) for ${hours}h -> $out ($img)"
"$dumpcap" -i "$idx" -F pcap -a "duration:$((hours * 3600))" -q -w - \
  | docker run --rm -i --name tapwatch-mirror --network none --user "$(id -u):$(id -g)" -v "$out":/out \
      -v "$(dirname "$(realpath "$0")")/../deploy/zeek":/tapwatch:ro -w /out "$img" \
      zeek -C -r - /tapwatch/tapwatch-live.zeek
