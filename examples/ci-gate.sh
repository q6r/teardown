#!/usr/bin/env bash
# CI gate: analyse a build artefact and fail the job when teardown finds something serious.
#
#   examples/ci-gate.sh build/app.exe            # fail on high or critical (default)
#   examples/ci-gate.sh build/app.apk medium     # stricter
#
# Exit status: 0 clean, 3 threshold reached (teardown's own code), anything else is an error.
set -uo pipefail

artefact="${1:?usage: ci-gate.sh <file> [info|low|medium|high|critical]}"
severity="${2:-high}"
report="${TEARDOWN_REPORT:-teardown-report.md}"

teardown analyze "$artefact" --md --output "$report" --fail-on "$severity"
status=$?

case "$status" in
  0) echo "teardown: no finding at or above '$severity' in $artefact" ;;
  3) echo "teardown: '$severity' threshold reached, see $report" >&2 ;;
  *) echo "teardown: analysis failed with status $status" >&2 ;;
esac
exit "$status"
