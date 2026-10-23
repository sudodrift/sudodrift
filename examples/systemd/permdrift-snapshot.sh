#!/bin/sh
# Take a permdrift snapshot into a dated file and delete old ones.
# Install as /usr/local/sbin/permdrift-snapshot.sh (mode 0755).
#
# Environment (all optional):
#   PERMDRIFT_BIN   path to the permdrift binary (default: permdrift on PATH)
#   PERMDRIFT_DIR   where snapshots go (default: /var/lib/permdrift)
#   PERMDRIFT_KEEP  how many dated snapshots to keep (default: 26)
set -eu

bin=${PERMDRIFT_BIN:-permdrift}
dir=${PERMDRIFT_DIR:-/var/lib/permdrift}
keep=${PERMDRIFT_KEEP:-26}

umask 077
mkdir -p "$dir"
out="$dir/snapshot-$(date -u +%Y-%m-%d).json"

# Write to a temporary name first so a failed run never leaves a half file
# that looks like a snapshot.
trap 'rm -f -- "$out.tmp"' EXIT
"$bin" snapshot -o "$out.tmp"
mv "$out.tmp" "$out"

# Dated names sort in time order, so everything before the newest $keep goes.
count=$(ls -1 "$dir"/snapshot-*.json | wc -l)
if [ "$count" -gt "$keep" ]; then
	ls -1 "$dir"/snapshot-*.json | sort | head -n "$((count - keep))" | while read -r old; do
		rm -f -- "$old"
	done
fi
