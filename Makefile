BINARY  := bin/permdrift
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.2.0-dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build install test vet fmt demo clean

all: test build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/permdrift

install:
	CGO_ENABLED=0 go install -trimpath -ldflags '$(LDFLAGS)' ./cmd/permdrift

test:
	go vet ./...
	go test -race ./...

fmt:
	gofmt -w .

demo: build
	./scripts/demo.sh

clean:
	rm -rf bin
