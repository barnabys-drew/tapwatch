#!/usr/bin/env bash
# Download the public malware captures used in eval/RESULTS.md, convert them with Zeek, and
# write their labels. Stratosphere Lab, CTU Prague (https://mcfp.felk.cvut.cz): please cite them.
#   eval/public_captures.sh [dir]      (default eval/data/public)
# Only the .pcap traffic files are fetched, never the .zip next to them (that's the malware).
# Captures are hostile data: Zeek reads them inside a container with networking off (replay.sh).
set -euo pipefail
here=$(dirname "$(realpath "$0")"); out=${1:-$here/data/public}
#        dataset   pcap name                    short name    infected host(s), from the dataset README
caps=(
  "297-1 2017-07-13_capture-win24  wannacry     192.168.1.135,192.168.1.112"
  "410-1 2021-12-01_win4           qakbot       192.168.1.114"
  "408-1 2021-08-18_fresco11       fresco11     10.0.3.15"
  "407-1 2021-08-16_gmfresco10     flubot       10.0.3.15"
  "400-1 2021-03-12_win9           wacatac      192.168.1.119"
  "373-1 2018-12-09_capture-win7   htbot-proxy  192.168.1.117"
)
for c in "${caps[@]}"; do
  read -r id pcap name hosts <<< "$c"
  mkdir -p "$out/$name/pcap"
  f="$out/$name/pcap/$pcap.pcap"
  [ -s "$f" ] || curl -sSfL --max-time 900 -o "$f" "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-$id/$pcap.pcap"
  [ -s "$out/$name/zeek/conn.log" ] || "$here/replay.sh" "$f" "$out/$name/zeek" >/dev/null
  { echo "malicious_hosts:"; tr ',' '\n' <<< "$hosts" | sed 's/^/  - "/; s/$/"/'; } > "$out/$name/labels.yaml"
  echo "$name: $(wc -l < "$out/$name/zeek/conn.log") conn records"
done
echo "Run: tapwatch -c <config without household settings> eval --zeek-dir $out/<name>/zeek --labels $out/<name>/labels.yaml"
