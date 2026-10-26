# sudo-rs readiness check

`sudodrift sudors-check` reads `/etc/sudoers` and everything it includes, and lists the lines that sudo-rs rejects, ignores or handles differently from original sudo (sudo.ws). sudo-rs is the default `sudo` on Ubuntu 25.10 and 26.04 LTS.

This page lists every rule the check uses, the source each rule comes from, and how the rules were checked against real sudo-rs builds.

## Severities

| Severity | Meaning |
|---|---|
| breaks | sudo-rs rejects the line. It prints a syntax error and skips the whole line, so every rule or option on that line is lost. `visudo -c` from sudo-rs fails. |
| differs | sudo-rs accepts the line, but it does not do what it does in original sudo. |
| info | Worth knowing, usually no action needed. |

## Targets

The rules depend on the sudo-rs release. `--target` picks one:

| Target | sudo-rs | Why |
|---|---|---|
| `ubuntu-26.04` (default) | 0.2.13 | "The package in Ubuntu 26.04 LTS is based on v0.2.13 with additional bug fixes." ([sudo-rs README](https://github.com/trifectatechfoundation/sudo-rs/blob/v0.2.15/README.md#versions)). USN-8708-1 lists the current package as 0.2.13-0ubuntu1.2. |
| `ubuntu-25.10` | 0.2.8 | "The sudo-rs package in Ubuntu 25.10 is based on v0.2.8 with additional bug fixes backported from newer versions." (same README section) |
| `upstream` | 0.2.15 | Newest upstream release at the time of writing. |

## Rules and sources

Source code links point at the release tag, so line numbers stay valid.

| Rule | Severity on 26.04 | What it reports | Source |
|---|---|---|---|
| `arg-wildcard` | breaks (differs on 25.10) | A wildcard (`*` or `?`) in a command argument, other than one final standalone `*`. 0.2.13 rejects the line with "wildcards are not allowed in command arguments". 0.2.8 accepts it but compares arguments as plain text, and even a final `*` only matches a literal `*` there. | [README, differences](https://github.com/trifectatechfoundation/sudo-rs/blob/v0.2.15/README.md#differences-from-original-sudo), [sudoers man page, Wildcards](https://github.com/trifectatechfoundation/sudo-rs/blob/v0.2.13/docs/man/sudoers.5.md#wildcards), [tokens.rs v0.2.13](https://github.com/trifectatechfoundation/sudo-rs/blob/v0.2.13/src/sudoers/tokens.rs#L196-L228), [tokens.rs v0.2.8](https://github.com/trifectatechfoundation/sudo-rs/blob/v0.2.8/src/sudoers/tokens.rs#L176-L195), commit [0d3b7eac](https://github.com/trifectatechfoundation/sudo-rs/commit/0d3b7eac) (first in 0.2.13) |
| `arg-charclass` | differs | An argument with `[...]`. Original sudo treats it as a character class. sudo-rs compares arguments with plain string equality. | [mod.rs v0.2.13, argument match](https://github.com/trifectatechfoundation/sudo-rs/blob/v0.2.13/src/sudoers/mod.rs#L643-L644) |
| `regex` | breaks (args: differs on 25.10) | A command or argument list written as a regular expression (`^...$`), a sudo 1.9.10 feature. | [tokens.rs](https://github.com/trifectatechfoundation/sudo-rs/blob/v0.2.13/src/sudoers/tokens.rs#L200-L208), [FAQ: no regular expressions](https://github.com/trifectatechfoundation/sudo-rs/blob/v0.2.15/FAQ.md#is-there-a-reason-to-not-switch-to-sudo-rs), commit [cf833b39](https://github.com/trifectatechfoundation/sudo-rs/commit/cf833b39) (first in 0.2.11) |
| `illegal-escape` | breaks | A backslash escape in a command other than `\\`, `\,`, `\:`, `\=`, `\#` or `\ `. Original sudo lets `\*` stop wildcard matching; sudo-rs reports "illegal escape sequence". | [tokens.rs, SimpleCommand::escaped](https://github.com/trifectatechfoundation/sudo-rs/blob/v0.2.13/src/sudoers/tokens.rs#L306-L309) |
| `digest` | breaks | A `sha224:`/`sha256:`/`sha384:`/`sha512:` digest in front of a command. | [tokens.rs](https://github.com/trifectatechfoundation/sudo-rs/blob/v0.2.13/src/sudoers/tokens.rs#L267) |
| `sudoedit-files` | info | A `sudoedit` rule with file arguments. USN-8708-1 fixed a sudoedit race that only affects such rules; the fixed 26.04 package is 0.2.13-0ubuntu1.2. | [USN-8708-1](https://ubuntu.com/security/notices/USN-8708-1) |
| `tag-unsupported` | breaks | The `INTERCEPT:` tag. | [ast.rs](https://github.com/trifectatechfoundation/sudo-rs/blob/v0.2.13/src/sudoers/ast.rs#L350-L356), [README](https://github.com/trifectatechfoundation/sudo-rs/blob/v0.2.15/README.md#differences-from-original-sudo) |
| `tag-ignored` | differs | `LOG_INPUT`, `NOLOG_INPUT`, `LOG_OUTPUT`, `NOLOG_OUTPUT`, `MAIL`, `NOMAIL` and `FOLLOW` tags. The rule still works, the tag does nothing, and `visudo -c` reports it. | [ast.rs](https://github.com/trifectatechfoundation/sudo-rs/blob/v0.2.13/src/sudoers/ast.rs#L362-L371), [mod.rs](https://github.com/trifectatechfoundation/sudo-rs/blob/v0.2.13/src/sudoers/mod.rs#L754-L758), [Ubuntu docs: no I/O logging](https://ubuntu.com/server/docs/reference/other-tools/sudo-rs/) |
| `option-unsupported` | breaks | `CHROOT=`, `TIMEOUT=`, `NOTBEFORE=`, `NOTAFTER=`, `ROLE=`, `TYPE=`, `PRIVS=`, `LIMITPRIVS=`. | [ast.rs](https://github.com/trifectatechfoundation/sudo-rs/blob/v0.2.13/src/sudoers/ast.rs#L350-L361), [ast.rs, unknown modifier](https://github.com/trifectatechfoundation/sudo-rs/blob/v0.2.13/src/sudoers/ast.rs#L384-L387) |
| `netgroup` | breaks | A `+netgroup` in a user list, Runas list, host list, alias or Defaults scope. | [ast.rs](https://github.com/trifectatechfoundation/sudo-rs/blob/v0.2.13/src/sudoers/ast.rs#L256-L258) |
| `nonunix-group` | differs | A `%:group` (non-Unix group). The parser accepts it, but at run time sudo-rs prints "non-unix group ... was ignored". | [mod.rs](https://github.com/trifectatechfoundation/sudo-rs/blob/v0.2.13/src/sudoers/mod.rs#L594-L598) |
| `user-escaped-space` | (25.10 only) breaks | `\ ` inside a user or group name, for example `%Domain\ Admins`. Added in 0.2.9. | commit [474e1b51](https://github.com/trifectatechfoundation/sudo-rs/commit/474e1b51c041045b7693ee79ca339d8ce90665d2) |
| `host-wildcard` | breaks | A wildcard in a host name, such as `web*.example.com`. The parser only accepts letters, digits, `.`, `-` and `_` ("expected host name"). Note: the sudo-rs man page still says host names may use wildcards; the code and `visudo -c` say otherwise. | [tokens.rs, Hostname](https://github.com/trifectatechfoundation/sudo-rs/blob/v0.2.13/src/sudoers/tokens.rs#L80-L101) |
| `host-address` | breaks (IPv4: differs on 25.10) | An IP address or network used as a host. 0.2.13 rejects IPv4 addresses ("hosts cannot be specified using an IPv4 address"); networks and IPv6 addresses never parse. 0.2.8 reads a bare IPv4 address as a host name that never matches. | [tokens.rs](https://github.com/trifectatechfoundation/sudo-rs/blob/v0.2.13/src/sudoers/tokens.rs#L80-L101), commit [caa94407](https://github.com/trifectatechfoundation/sudo-rs/commit/caa94407) (first in 0.2.13) |
| `continuation-in-command` | breaks (fixed in 0.2.14) | A backslash line continuation between a command and its arguments. Older releases report "garbage at end of line". A continuation after a comma is fine. | commit [7780f593](https://github.com/trifectatechfoundation/sudo-rs/commit/7780f59392adeed49a0f4c60a2e15ec05f70c398), issue [#1571](https://github.com/trifectatechfoundation/sudo-rs/issues/1571), confirmed with visudo |
| `tab-in-command` | breaks (fixed in 0.2.15) | A tab between a command and its arguments. | commit [4df2904d](https://github.com/trifectatechfoundation/sudo-rs/commit/4df2904d960505a77e4166d0d4813cdbc7ed78ac), confirmed with visudo |
| `defaults-unknown` | breaks | A Defaults option sudo-rs does not know, for example `requiretty`, `logfile`, `sudoedit_checkdir`, `log_input`, `mailto`, `passprompt`. Options added in later releases (`noninteractive_auth` 0.2.9, `runcwd` 0.2.14, `log_allowed`, `log_denied` and `timestamp_type` 0.2.15) are reported with the release that added them. | [defaults/mod.rs v0.2.13](https://github.com/trifectatechfoundation/sudo-rs/blob/v0.2.13/src/defaults/mod.rs#L30-L82) (also [v0.2.8](https://github.com/trifectatechfoundation/sudo-rs/blob/v0.2.8/src/defaults/mod.rs), [v0.2.15](https://github.com/trifectatechfoundation/sudo-rs/blob/v0.2.15/src/defaults/mod.rs)), [ast.rs "unknown setting"](https://github.com/trifectatechfoundation/sudo-rs/blob/v0.2.13/src/sudoers/ast.rs#L756-L776), [README](https://github.com/trifectatechfoundation/sudo-rs/blob/v0.2.15/README.md#differences-from-original-sudo), [FAQ on requiretty](https://github.com/trifectatechfoundation/sudo-rs/blob/v0.2.15/FAQ.md#why-did-you-change-x) |
| `defaults-invalid` | breaks | A known option used the wrong way: negating an option that cannot be negated (`!passwd_tries`), `+=` on a non-list, a value on a flag (`use_pty=yes`, and `lecture=always` on 0.2.8 where `lecture` is a flag), a missing value (`Defaults secure_path`), or a value out of range (`passwd_tries` above 1000, `timestamp_type` other than `tty` or `ppid`). | [ast.rs](https://github.com/trifectatechfoundation/sudo-rs/blob/v0.2.13/src/sudoers/ast.rs#L736-L822), [defaults/mod.rs](https://github.com/trifectatechfoundation/sudo-rs/blob/v0.2.13/src/defaults/mod.rs#L30-L82), [README: timestamp_type](https://github.com/trifectatechfoundation/sudo-rs/blob/v0.2.15/README.md#differences-from-original-sudo) |
| `defaults-ignored` | differs or info | Options sudo-rs accepts and ignores. differs: `!env_reset`, `visiblepw`, `insults`, `lecture`, `fqdn`, `!ignore_dot`, `verifypw` other than `all`, `env_delete`, `!log_denied`. info: `env_reset`, `mail_badpass`, `mailerpath`, `always_set_home`, `always_query_group_plugin`, `match_group_by_gid`. | [README](https://github.com/trifectatechfoundation/sudo-rs/blob/v0.2.15/README.md#differences-from-original-sudo), entries marked `#ignored` in [defaults/mod.rs](https://github.com/trifectatechfoundation/sudo-rs/blob/v0.2.13/src/defaults/mod.rs#L30-L82) |
| `includedir-percent-h` | breaks | `@includedir` with `%h`. sudo-rs reports "percent escape %h in includedir is unsupported" and reads nothing from it. | [mod.rs](https://github.com/trifectatechfoundation/sudo-rs/blob/v0.2.13/src/sudoers/mod.rs#L795-L804) |
| `include-percent-h` | info | `@include` with `%h`. The sudo-rs manual does not describe `%h` for `@include`; not confirmed either way. | [sudoers man page, includes](https://github.com/trifectatechfoundation/sudo-rs/blob/v0.2.13/docs/man/sudoers.5.md#including-other-files-from-within-sudoers) |
| `include-missing` | info | An include that points at a missing file or directory. Both implementations report it. | same |
| `include-limit` | breaks | More than 128 nested includes. | same |
| `not-utf8` | breaks | A sudoers file that is not valid UTF-8. | [README](https://github.com/trifectatechfoundation/sudo-rs/blob/v0.2.15/README.md#differences-from-original-sudo) |
| `sudoers-rs-file` | info | `/etc/sudoers-rs` exists, so sudo-rs reads it instead of `/etc/sudoers`. The check then reads `/etc/sudoers-rs`. | [sudo/mod.rs](https://github.com/trifectatechfoundation/sudo-rs/blob/v0.2.13/src/sudo/mod.rs#L49-L62), [README](https://github.com/trifectatechfoundation/sudo-rs/blob/v0.2.15/README.md#installing-our-pre-compiled-x86-64-binaries) |
| `not-included` | info | A file in `/etc/sudoers.d` that no include line reaches. Neither implementation reads it. | [sudoers man page, includes](https://github.com/trifectatechfoundation/sudo-rs/blob/v0.2.13/docs/man/sudoers.5.md#including-other-files-from-within-sudoers) |

Other primary sources read for this page:

- Ubuntu Server docs, [System utility replacements: sudo-rs](https://ubuntu.com/server/docs/reference/other-tools/sudo-rs/): different password prompt, no I/O logging or `sudoreplay`, no `sudoers.ldap`.
- [USN-8708-1](https://ubuntu.com/security/notices/USN-8708-1) (1 September 2026): sudoedit time-of-check/time-of-use issue in sudo-rs on 26.04, fixed in 0.2.13-0ubuntu1.2. Only systems with fine-grained sudoedit rules are affected.

## Things the check does not cover

These are differences the sources mention that do not show up in a sudoers file, so the check cannot see them:

- The password prompt text (`[sudo: authenticate] Password:`), which can break Expect scripts (Ubuntu docs).
- No I/O logging, `sudoreplay`, `sudo_logsrvd` or `sudoers.ldap` (Ubuntu docs). If your setup stores rules in LDAP, there is no sudoers file to check.
- `sudo -E` is not supported (README).
- `use_pty` and `pwfeedback` are on by default in sudo-rs. `pwfeedback` was off by default in 0.2.8.
- Resource limits and umask from PAM (README).

It also does not expand aliases. If a `Cmnd_Alias` line is rejected, the rules that use that alias lose those commands; the finding is reported on the alias line.

## How it was checked

`scripts/check-sudors-fixtures.py` runs `sudors-check` and `visudo -c -f` from a real sudo-rs on every fixture file in `internal/sudors/testdata`, and compares the lines each one rejects. Include lines are commented out before visudo reads a file so it never touches the host's own `/etc`; includes are covered by the Go tests.

It was run against five visudo binaries on 2026-10-26:

| visudo from | Target | Result |
|---|---|---|
| Ubuntu package `sudo-rs_0.2.13-0ubuntu1.2_amd64.deb` (26.04, from archive.ubuntu.com) | `ubuntu-26.04` | 14 files agree, 0 differ |
| Ubuntu package `sudo-rs_0.2.8-1ubuntu5.3_amd64.deb` (25.10, from archive.ubuntu.com) | `ubuntu-25.10` | 14 files agree, 0 differ |
| `cargo install sudo-rs --version 0.2.13` | `ubuntu-26.04` | 14 files agree, 0 differ |
| `cargo install sudo-rs --version 0.2.8` | `ubuntu-25.10` | 14 files agree, 0 differ |
| `cargo install sudo-rs --version 0.2.15` | `upstream` | 14 files agree, 0 differ |

Output of the run against the Ubuntu 26.04 package:

```
OK   args/etc/sudoers: sudors-check breaks=[2, 5, 6, 7] visudo errors=[2, 5, 6, 7]
OK   clean/etc/sudoers: sudors-check breaks=[] visudo errors=[]
OK   clean/etc/sudoers.d/README: sudors-check breaks=[] visudo errors=[]
OK   commands/etc/sudoers: sudors-check breaks=[2, 3, 4] visudo errors=[2, 3, 4]
OK   defaults/etc/sudoers: sudors-check breaks=[2, 3, 5, 8, 9, 10, 11, 17, 18] visudo errors=[2, 3, 5, 8, 9, 10, 11, 17, 18]
OK   includes/etc/sudoers: sudors-check breaks=[] visudo errors=[]
OK   includes/etc/local/extra: sudors-check breaks=[1] visudo errors=[1]
OK   includes/etc/sudoers.d/10-ops: sudors-check breaks=[2] visudo errors=[2]
OK   not-included/etc/sudoers: sudors-check breaks=[] visudo errors=[]
OK   sudoers-rs/etc/sudoers-rs: sudors-check breaks=[2] visudo errors=[2]
OK   syntax/etc/sudoers: sudors-check breaks=[3, 10] visudo errors=[3, 10]
OK   tags/etc/sudoers: sudors-check breaks=[2, 5, 6, 7, 8] visudo errors=[2, 5, 6, 7, 8]
OK   users-hosts/etc/sudoers: sudors-check breaks=[2, 4, 5, 6, 7, 8, 9, 10, 13] visudo errors=[2, 4, 5, 6, 7, 8, 9, 10, 13]
OK   utf8/etc/sudoers: sudors-check breaks=[2] visudo errors=[2]

14 files agree, 0 differ
```

To repeat it, get a sudo-rs visudo (no root needed for `-c -f`) and run:

```sh
make build
scripts/check-sudors-fixtures.py bin/sudodrift /path/to/visudo ubuntu-26.04
```

What this does not prove: visudo only shows what is rejected. The "differs" rules come from reading the sudo-rs source and docs, not from running commands through sudo-rs.
