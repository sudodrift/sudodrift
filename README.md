# permdrift

**Linux Permission Drift Detector.** Snapshot the security-relevant permission state of a host, then see *what changed* in plain English: "SSH key SHA256:… added for user bob", "NOPASSWD sudo rule added", "user alice added to group sudo", "/usr/bin/wall became SUID".

Single static Go binary, standard library only, no daemon, no network access, no root required (root just gives better coverage).

![permdrift demo: snapshot, tamper, diff](docs/demo.gif)

A larger sample run as a static screenshot:

![permdrift diff output in a terminal](docs/cli-demo.png)

The same run as an HTML report (`permdrift report`):

<img src="docs/report-screenshot.png" alt="permdrift HTML report" width="700">

> Status: early (v0.1.0). It works and has tests, but expect rough edges and some changes to the JSON schema and severity rules.

## The problem

Access on a Linux box quietly drifts: someone adds a "temporary" NOPASSWD rule, an extra SSH key lands in `authorized_keys`, a binary gains the SUID bit, `/etc/shadow` becomes group-readable. Config management tells you what *should* be there; auditors and incident responders need to know what *is* there and *when it changed*. permdrift gives you a small, diffable JSON baseline and a ranked list of access-relevant changes between two points in time.

## Install

Prebuilt static binaries for Linux (amd64 and arm64) are on the [releases page](https://github.com/permdrift/permdrift/releases/latest):

```sh
VER=v0.1.0; ARCH=amd64   # or arm64
curl -fsSLO https://github.com/permdrift/permdrift/releases/download/$VER/permdrift_${VER#v}_linux_$ARCH.tar.gz
curl -fsSLO https://github.com/permdrift/permdrift/releases/download/$VER/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
tar xzf permdrift_${VER#v}_linux_$ARCH.tar.gz
sudo install -m 0755 permdrift /usr/local/bin/
```

On Debian, Ubuntu, Fedora or RHEL style systems you can also build `.deb` and `.rpm` packages with `goreleaser release --snapshot --clean` (see `.goreleaser.yaml`). I have not attached packages to a release yet.

With Homebrew on Linux (the tool is Linux only, so this does nothing useful on macOS):

```sh
brew install permdrift/tap/permdrift
```

The formula lives in [permdrift/homebrew-tap](https://github.com/permdrift/homebrew-tap) and installs the v0.1.0 release binary.

### Docker

The image is a static binary on `scratch`. Mount the host's root filesystem read only and point `--root` at it:

```sh
docker run --rm -v /:/host:ro ghcr.io/permdrift/permdrift:latest snapshot --root /host > base.json
```

The snapshot goes to stdout, so the redirect happens on the host. It reads the hostname from `/host/etc/hostname`, so the baseline carries the host's name and not the container's. Run it as root (the default in the container) or shadow state and other users' `~/.ssh` will be missing. The image is published to ghcr.io when a version tag is pushed, so it will only exist after the next tag. Until then, build it yourself with `docker build -t permdrift .`. I could not test the Docker build on the machine where I wrote this, so tell me if it breaks.

### From source

To build from source you need Go 1.21+ (check with `go version`).

Quickest way:

```sh
go install github.com/permdrift/permdrift/cmd/permdrift@latest
```

Or build from a clone:

```sh
git clone https://github.com/permdrift/permdrift.git permdrift && cd permdrift
# option A (needs make): builds ./bin/permdrift, CGO disabled, static, version from git
make build
# option B (no make needed):
CGO_ENABLED=0 go build -trimpath -o bin/permdrift ./cmd/permdrift   # creates bin/ for you

./bin/permdrift version
```

To put it on your `PATH`, either `sudo install -m 0755 bin/permdrift /usr/local/bin/` or run `make install` / `go install ./cmd/permdrift` (installs to `$(go env GOPATH)/bin`, usually `~/go/bin`, which you may need to add to `PATH`). The examples below assume `permdrift` is on your `PATH`; otherwise use `./bin/permdrift`.

## Usage

```sh
# 1. baseline (run as root for full coverage: shadow state, all ~/.ssh, sudoers)
sudo permdrift snapshot -o base.json

# 2. later...
sudo permdrift snapshot -o now.json

# 3. text diff; exit code 1 if drift was found (handy for cron/CI)
permdrift diff base.json now.json

# 4. self-contained HTML report (inline CSS only, no external assets)
permdrift report base.json now.json -o report.html
```

Options:

| Flag | Applies to | Meaning |
|---|---|---|
| `-o FILE` | snapshot, report | output file (snapshot defaults to stdout) |
| `--root DIR` | snapshot | scan a fake root instead of `/` (tests, mounted images, backups) |
| `--include-home` | snapshot | also walk `/home` for SUID and world-writable files (skipped by default for speed) |
| `--exclude a,b` | snapshot | extra directories to skip while walking |
| `--ignore FILE` | diff, report | line-based ignore patterns (`.txt` or simple `.yaml` list) |
| `--min-severity low\|medium\|high` | diff, report | hide anything below this level |

Flags may be written with one or two dashes (`-o` / `--root`) and may come before or after the file arguments. `permdrift <command> --help` prints the options for each command, `permdrift version` the version.

Exit codes: `0` no drift (or snapshot/report written), `1` drift found (`diff` only), `2` error (bad arguments, unreadable/corrupt snapshot, unsupported schema version). `report` exits 0 even when drift is found; use `diff` for gating.

Snapshots taken as an unprivileged user are partial (unreadable paths such as `/etc/sudoers` or other users' `~/.ssh` become warnings inside the snapshot, and `diff` notes it). Don't diff a non-root snapshot against a root one: the difference will show up as spurious "added" changes. With `--root DIR`, symlinks are resolved inside `DIR` (an absolute link such as `etc/passwd -> /etc/passwd` is re-rooted), so a scan of a mounted image never reads the live host.

### Ignore file

One wildcard pattern per line (`*` matches anything, including `/` and `:`). Patterns match `category:subject` or just `subject`. `#` comments, and `- "pattern"` YAML-list style, are accepted.

```
# ignore.txt
suid:/usr/bin/sudo
ssh_key:deploy:*
/usr/lib/*
user:build?
```

Categories: `user`, `group`, `group_member`, `ssh_key`, `sudoers`, `suid`, `world_writable`, `file_perm`, `sshd`. Ignores are applied when diffing/reporting, never when snapshotting, so the raw evidence stays complete.

### Demo

`./scripts/demo.sh` (builds `bin/permdrift` first if missing; `make demo` does the same) creates a fake root, snapshots it, tampers with it, snapshots again, then runs `diff` and `report`. A pre-generated result is committed:

- `examples/sample-report.html`: open in any browser
- `examples/sample-diff.txt`: text output

Note: in the demo the fake files are owned by whoever runs the script (not root), so "new SUID file" shows as Medium there; a SUID file owned by root is High.

## What it collects

- **Users** (`/etc/passwd`): UID/GID, home, shell, whether the shell allows login, UID-0 accounts, password state (`locked`/`set`/`empty`, from `/etc/shadow` when readable; hashes are never stored).
- **Groups** (`/etc/group`): members; `sudo`, `wheel`, `admin`, `docker`, `lxd` flagged as privileged.
- **authorized_keys** per user (`.ssh/authorized_keys`, `authorized_keys2`): key type, SHA256 fingerprint, comment, options. Key material is never stored.
- **sudoers** + `sudoers.d/*`: parsed logical lines; flags `NOPASSWD` (and `Defaults !authenticate`) and `ALL=(ALL)`-style grants.
- **SUID/SGID files** with owner, mode and SHA-256 of contents (detects a SUID binary being swapped).
- **World-writable files/dirs** in `/etc`, `/usr/bin`, `/usr/sbin`, `/usr/local/bin`, `/usr/local/sbin` (and `/home` with `--include-home`). Sticky directories are not flagged.
- **Permissions/owners of sensitive files**: `/etc/passwd|group|shadow|gshadow|sudoers|sudoers.d/*`, `/etc/ssh/sshd_config`, SSH host private keys, and every user's `~/.ssh` directory and files.
- A few `sshd_config` directives (`PermitRootLogin`, `PasswordAuthentication`, `PermitEmptyPasswords`, `PubkeyAuthentication`).
- Metadata: hostname, UTC timestamp, tool version, and a content hash (excludes hostname/timestamp, so an unchanged host produces the same hash).

Severity (High/Medium/Low) is a heuristic, e.g. High: key added for root/sudo user, NOPASSWD or `ALL=(ALL)` rule added, member added to a privileged group, new UID-0 user, SUID gained, world-writable system file, `/etc/shadow` loosened, `PermitRootLogin yes`.

## What it does *not* do

- It is **not a real-time monitor** or IDS: no daemon, no inotify, no alerting. It compares two snapshots you take.
- **Not tamper-evident.** Snapshots are plain JSON; an attacker with root can edit the host *and* the baseline. Store baselines off-host.
- **No package, service, network, firewall, cron, kernel-module or process coverage.** Permissions and access paths only.
- Sudoers parsing is line-based: no alias expansion, no `#include` following beyond `sudoers.d`, no `visudo`-grade validation. PAM, LDAP/SSSD users, `AuthorizedKeysCommand`, custom `AuthorizedKeysFile` paths and ACLs/capabilities/xattrs are not inspected.
- "became SUID" can only be said when the file was already in the baseline as SGID; otherwise the message says "is now SUID (new file or mode change)", because permdrift does not inventory every file on disk.
- Unreadable paths become warnings in the snapshot; run as root for complete results.
- Linux only. Severity ratings are opinions, not verdicts.

## Similar projects (honest comparison)

permdrift is not novel. Related tools I found while building it:

- **[statedrift](https://github.com/statedrift/statedrift)**: also a single static, stdlib-only Go binary for Linux host-state drift. Much broader (packages, services, network, firewall, containers, hash-chained tamper-evident history, evidence bundles). If you want broad host drift with integrity guarantees, look there first. permdrift is narrower and focused on access/permission semantics and readable severity-ranked diffs.
- **[ProcDrift](https://github.com/Towelie/ProcDrift)**: Python tool that baselines execution, persistence and privilege state (processes, systemd units, cron, SUID/SGID, users/groups/sudo) and reports diffs for IR/threat hunting. Overlaps on privilege state; broader on execution/persistence.
- Others in the same space: `infradrift` (Python), `drift` (matthewvaishnav).

Heavier, more mature alternatives for the same job:

- **Wazuh**: full HIDS/SIEM platform with agents, file-integrity monitoring, rule sets, compliance dashboards.
- **osquery**: SQL over OS state. Query users, sudoers, SUID, authorized_keys and more at fleet scale (needs a daemon/fleet manager for history and diffing).
- **AIDE** (and Tripwire-style tools): file-integrity databases for content and permission changes. Very good, but gives byte-level deltas, not "this adds a NOPASSWD rule".

Pick permdrift if you want a tiny, dependency-free binary and a human-readable access-drift report; pick those if you need continuous monitoring, fleet scale, or tamper-evidence today.

## Development

```sh
make test     # go vet + go test -race ./...
make build    # bin/permdrift
```

Tests build temporary fake roots (passwd/group/shadow/sudoers/authorized_keys/SUID files) under `internal/fixture`; no root privileges needed. Layout:

```
cmd/permdrift/        CLI
internal/snapshot/    collectors + JSON model
internal/diff/        semantic comparison + severity
internal/ignore/      ignore-file matcher
internal/report/      text + HTML output
internal/fixture/     fake-root builders (tests/demos)
scripts/demo.sh       end-to-end demo
```

## Roadmap

Free / open-source:
- More collectors: cron/systemd timers, PAM config, `AuthorizedKeysFile` overrides, capabilities, ACLs, shell-init files.
- `permdrift check` against a policy file ("only these users may be UID 0 / in sudo").
- JSON/SARIF output for `diff`; `--fail-on high` for CI.
- Packaged releases (static binaries, deb/rpm), a `snapshot --since-last` workflow.

Possible paid / hosted ideas (not built):
- **Multi-host rollup**: central collection of snapshots, fleet-wide dashboard, "which hosts gained NOPASSWD this week".
- **Signed evidence bundles**: hash-chained, signed snapshots with offline verification for auditors.
- **SOC 2 / ISO 27001 mapping**: tie findings to controls (access control, change management, least privilege) and produce audit-ready reports.
- Scheduled scans with alerting (Slack/email/webhook) and approval workflows for expected changes.

## Services

Need help setting this up, collecting SOC 2 / ISO 27001 access review evidence, or integrating it with your fleet? Open an [issue](https://github.com/permdrift/permdrift/issues) or contact me through my GitHub profile.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the short version. Bug reports, false positives and missing-collector requests are welcome as [issues](https://github.com/permdrift/permdrift/issues). For code changes, open a pull request that includes a test (fake-root fixtures in `internal/fixture` make this easy), and run `gofmt`, `go vet ./...` and `go test -race ./...` first. Please keep the tool dependency-free (standard library only) and read-only: it must never modify the host it scans.

To report a security problem in permdrift itself, see [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
