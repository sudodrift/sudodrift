# Contributing

Thanks for looking. This is a small project and I read everything, but I may be slow to answer.

## Before you start

For a bug or a false positive, open an issue first with the command you ran and `sudodrift version`. For anything bigger than a small fix, open an issue and say what you want to change so we do not waste your time.

Two rules I will not bend on:

1. Standard library only. No new dependencies.
2. sudodrift only reads. It must never change the host it scans.

## Setup

You need Go 1.21 or newer.

```sh
git clone https://github.com/sudodrift/sudodrift.git
cd sudodrift
make test
make build
```

No root needed. The tests build fake roots (passwd, group, sudoers, authorized_keys, SUID files) in a temp dir. See `internal/fixture`.

## Sending a pull request

Add a test for what you changed. Run these before you push:

```sh
gofmt -l .
go vet ./...
go test -race ./...
```

Keep the change small and the commit message plain: what changed and why, in a sentence or two.

Severity ratings (High, Medium, Low) are opinions. If you think one is wrong, say why in the issue and tell me what you would do on a real server.

## Good first issues

Look for the [good first issue](https://github.com/sudodrift/sudodrift/labels/good%20first%20issue) label. If you want one, say so in a comment so two people do not do the same thing.
