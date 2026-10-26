# Changelog

## 0.4.0 (2026-10-26)

Added

- `sudodrift sudors-check [--root DIR] [--format text|json] [--target ubuntu-26.04|ubuntu-25.10|upstream] [--fail-on breaks|differs|info]`: reads `/etc/sudoers` and everything it includes and reports each line that sudo-rs (the default `sudo` on Ubuntu 25.10 and 26.04) rejects, ignores or handles differently from original sudo. Each finding has a severity (breaks, differs or info), file and line, an explanation, a suggested fix and a source link. Exit codes: 0 nothing at the `--fail-on` level (default breaks), 1 findings at that level, 2 error.
- `docs/sudo-rs.md`: every rule with the sudo-rs source code, README, FAQ, man page, Ubuntu document or USN it is based on.
- Test fixtures for every rule in `internal/sudors/testdata`, and `scripts/check-sudors-fixtures.py`, which compares the results with `visudo -c` from a real sudo-rs.
- `examples/sudors-check/` with sample output in `examples/sudors-check.txt` and `examples/sudors-check.json`.

Changed

- `snapshot.JoinContinuationsNumbered` keeps the starting line number of each continued sudoers line; `JoinContinuations` now uses it and behaves as before.

Known limits

- Aliases are not expanded. A rejected `Cmnd_Alias` is reported on the alias line, not on the rules that use it.
- The "breaks" results match `visudo -c` from the Ubuntu 26.04 and 25.10 packages and from upstream 0.2.8, 0.2.13 and 0.2.15 on all fixtures. The "differs" results come from reading the sudo-rs source and docs; they were not tested by running commands through sudo-rs.

## 0.3.0 (2026-10-26)

Added

- `sudodrift diff --fail-on low|medium|high`: print every change as before, but exit 1 only when at least one shown change is at that level or above. Without the flag the exit code is the same as before.

## 0.2.0 (2026-10-23)

This is the first release under the name sudodrift. The project was called permdrift in v0.1.0 and was renamed because another project already uses the name PermDrift. The v0.1.0 release was removed because its binaries carry the old name. The Go module path, the command, the default directory (`/var/lib/sudodrift`) and the environment variables (`SUDODRIFT_*`) all changed.

Added

- `sudodrift diff --format text|json|csv`. Text is still the default. JSON has a `version` field, a summary and a list of changes. CSV has a header row and one row per change; cells that start with `=`, `+`, `-` or `@` get a leading single quote so spreadsheets do not run them as formulas. Exit codes (0 none, 1 drift, 2 error) are the same for every format.
- `sudodrift evidence --base base.json --current now.json`: writes a zip (or a directory with `--dir`) with both snapshots, `diff.txt`, `diff.json`, `report.html`, `metadata.json`, a `REVIEW.md` form and a `MANIFEST.sha256` file. It gathers material for a review. It is not a signature and not a compliance result.
- Example files for running snapshots on a schedule: a systemd service and timer, a cron file, a snapshot script that keeps dated files in `/var/lib/sudodrift/`, and a check script that diffs the newest snapshot against a baseline and exits non-zero on drift. New README section "Run it on a schedule".
- `examples/sample-diff.json` and `examples/sample-diff.csv`, produced by `scripts/demo.sh`, which now also builds and verifies an evidence bundle.

Changed

- The development version string is now `0.2.0-dev`, and any version ending in `-dev` falls back to the module version when installed with `go install`.
- README: usage, exit codes and the roadmap were updated.

Known limits

- The evidence manifest is a list of checksums, not a signature. Anyone who can rewrite the bundle can rewrite the manifest.
- The systemd units were checked with `systemd-analyze verify` but not run for a full week on a real server.

## 0.1.0

Released as permdrift (the former name of this project). First release: snapshot, diff and HTML report for users, groups, SSH key fingerprints, sudo rules, SUID/SGID files and sensitive file permissions.
