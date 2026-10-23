# Security policy

## Reporting a vulnerability

Please do not open a public issue for security problems.

Use GitHub's private vulnerability reporting: go to the [Security tab](https://github.com/permdrift/permdrift/security) of this repository and choose "Report a vulnerability". Include the permdrift version (`permdrift version`), what you did, and what you expected to happen.

I will acknowledge a report within a few days and aim to ship a fix or a clear mitigation as soon as I can. This is a small personal project, so there is no formal SLA.

## Scope

permdrift only reads files on the host it scans and writes the snapshot or report you ask for. Things that count as vulnerabilities include:

- reading or writing files outside what the tool documents (for example via symlinks with `--root`)
- crashes or hangs on crafted input files or snapshots
- terminal or HTML injection through data taken from the scanned host
- secrets (password hashes, key material) ending up in snapshots

Snapshots are plain JSON and are not tamper-evident. That is documented behavior, not a vulnerability.

## Supported versions

Only the latest release gets fixes.
