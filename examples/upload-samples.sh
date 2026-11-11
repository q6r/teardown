#!/usr/bin/env bash
# Upload every file of examples/samples (and any extra files you pass) to a running
# `teardown serve` through the real HTTP API, so the dashboard has something to show.
#
#   teardown serve                                        # in another terminal
#   bash examples/upload-samples.sh                       # the committed samples
#   bash examples/upload-samples.sh http://127.0.0.1:9000 # another server
#   TEARDOWN_EXTRA="dropper.bin" bash examples/upload-samples.sh   # plus your own files
#
# Prints one line per file: HTTP status, analysis id, risk, name. Needs only curl.
set -euo pipefail

base="${1:-http://127.0.0.1:7777}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck disable=SC2206  # TEARDOWN_EXTRA is a space separated list of paths by design
files=("$here"/samples/* ${TEARDOWN_EXTRA:-})

status=0
for file in "${files[@]}"; do
  [ -f "$file" ] || continue
  # -D - dumps the response headers first (the Location header carries the id), the body follows.
  answer="$(curl -sS -D - -F "file=@${file}" "${base}/api/analyze")" || { echo "curl failed for ${file}" >&2; status=1; continue; }
  code="$(printf '%s' "$answer" | head -n 1 | tr -d '\r' | awk '{print $2}')"
  id="$(printf '%s' "$answer" | tr -d '\r' | sed -n 's|^[Ll]ocation: /api/analyses/||p')"
  risk="$(printf '%s' "$answer" | grep -o '"risk":{"score":[0-9]*,"label":"[a-z]*"' | head -n 1 | sed 's/"risk":{"score":\([0-9]*\),"label":"\([a-z]*\)"/\1 \2/')"
  printf '%s  %-16s risk %-12s %s\n' "${code:-???}" "${id:--}" "${risk:--}" "$(basename "$file")"
  [ "${code:-0}" = "201" ] || status=1
done
exit "$status"
