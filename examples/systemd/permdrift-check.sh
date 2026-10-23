#!/bin/sh
# Compare the newest snapshot in a directory with a baseline you chose.
# Exit status comes from permdrift diff: 0 no drift, 1 drift, 2 error.
#
# Usage: permdrift-check.sh [-q] BASELINE.json [SNAPSHOT_DIR]
#   -q  print nothing unless there is drift or an error (good for cron mail)
# SNAPSHOT_DIR defaults to /var/lib/permdrift. Set PERMDRIFT_BIN to use a
# binary that is not on PATH.
set -eu

quiet=0
if [ "${1:-}" = "-q" ]; then
	quiet=1
	shift
fi
baseline=${1:?usage: permdrift-check.sh [-q] BASELINE.json [SNAPSHOT_DIR]}
dir=${2:-/var/lib/permdrift}
bin=${PERMDRIFT_BIN:-permdrift}

newest=$(ls -1 "$dir"/snapshot-*.json 2>/dev/null | sort | tail -n 1)
if [ -z "$newest" ]; then
	echo "permdrift-check: no snapshots found in $dir" >&2
	exit 2
fi
if [ "$newest" = "$baseline" ]; then
	echo "permdrift-check: the newest snapshot is the baseline, nothing to compare" >&2
	exit 2
fi

rc=0
out=$("$bin" diff "$baseline" "$newest") || rc=$?
if [ "$rc" -ne 0 ] || [ "$quiet" -eq 0 ]; then
	echo "baseline: $baseline"
	echo "newest:   $newest"
	echo "$out"
fi
exit "$rc"
