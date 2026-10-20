#!/usr/bin/env bash
# Print the Zeek image tapwatch runs, building it from deploy/zeek/Dockerfile first if this machine doesn't have
# it: the upstream LTS image with its Debian packages patched (see the Dockerfile). Sourced by the capture and
# replay scripts so all three run the same Zeek.
#   img=$(eval/zeek_image.sh)
#   eval/zeek_image.sh --rebuild     # pull the base again and re-apply Debian's fixes
set -euo pipefail
ZEEK_IMAGE=${ZEEK_IMAGE:-tapwatch-zeek:9.0.0}
dir="$(dirname "$(realpath "$0")")/../deploy/zeek"
if [ "${1:-}" = "--rebuild" ]; then
  docker build --pull --no-cache -q -t "$ZEEK_IMAGE" "$dir" >&2
elif ! docker image inspect "$ZEEK_IMAGE" >/dev/null 2>&1; then
  echo "building $ZEEK_IMAGE (first run, a few minutes)" >&2
  docker build -q -t "$ZEEK_IMAGE" "$dir" >&2
fi
echo "$ZEEK_IMAGE"
