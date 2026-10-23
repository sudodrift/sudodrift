#!/bin/sh
# Take a sudodrift snapshot into a dated file and delete old ones.
# Install as /usr/local/sbin/sudodrift-snapshot.sh (mode 0755).
#
# Environment (all optional):
#   SUDODRIFT_BIN   path to the sudodrift binary (default: sudodrift on PATH)
#   SUDODRIFT_DIR   where snapshots go (default: /var/lib/sudodrift)
#   SUDODRIFT_KEEP  how many dated snapshots to keep (default: 26)
set -eu

bin=${SUDODRIFT_BIN:-sudodrift}
dir=${SUDODRIFT_DIR:-/var/lib/sudodrift}
keep=${SUDODRIFT_KEEP:-26}

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
