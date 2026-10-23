# Changelog

## 0.2.0 (2026-10-23)

Added

- `permdrift diff --format text|json|csv`. Text is still the default. JSON has a `version` field, a summary and a list of changes. CSV has a header row and one row per change; cells that start with `=`, `+`, `-` or `@` get a leading single quote so spreadsheets do not run them as formulas. Exit codes (0 none, 1 drift, 2 error) are the same for every format.
- `permdrift evidence --base base.json --current now.json`: writes a zip (or a directory with `--dir`) with both snapshots, `diff.txt`, `diff.json`, `report.html`, `metadata.json`, a `REVIEW.md` form and a `MANIFEST.sha256` file. It gathers material for a review. It is not a signature and not a compliance result.
- Example files for running snapshots on a schedule: a systemd service and timer, a cron file, a snapshot script that keeps dated files in `/var/lib/permdrift/`, and a check script that diffs the newest snapshot against a baseline and exits non-zero on drift. New README section "Run it on a schedule".
- `examples/sample-diff.json` and `examples/sample-diff.csv`, produced by `scripts/demo.sh`, which now also builds and verifies an evidence bundle.

Changed

- The development version string is now `0.2.0-dev`, and any version ending in `-dev` falls back to the module version when installed with `go install`.
- README: usage, exit codes and the roadmap were updated.

Known limits

- The evidence manifest is a list of checksums, not a signature. Anyone who can rewrite the bundle can rewrite the manifest.
- The systemd units were checked with `systemd-analyze verify` but not run for a full week on a real server.

## 0.1.0

First release: snapshot, diff and HTML report for users, groups, SSH key fingerprints, sudo rules, SUID/SGID files and sensitive file permissions.
