#!/usr/bin/env bash
# Turn a PCAP into Zeek JSON logs using the same Zeek image the appliance runs.
#   eval/replay.sh <capture.pcap> <output-dir>
# Treat downloaded malware captures as hostile data: they are only read by Zeek
# inside the container (network disabled), never opened or executed on the host.
set -euo pipefail
pcap=$(realpath "$1"); out=$(realpath -m "$2")
mkdir -p "$out"
img=$("$(dirname "$(realpath "$0")")/zeek_image.sh")
docker run --rm --network none --user "$(id -u):$(id -g)" -v "$(dirname "$pcap")":/in:ro -v "$out":/out \
  -v "$(dirname "$(realpath "$0")")/../deploy/zeek":/tapwatch:ro -w /out "$img" \
  zeek -C -r "/in/$(basename "$pcap")" /tapwatch/tapwatch.zeek   # no rotation: one file per log
ls "$out"
