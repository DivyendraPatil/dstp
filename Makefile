.PHONY: build test vet install

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X github.com/DivyendraPatil/dstp/internal/version.Version=$(VERSION) -X github.com/DivyendraPatil/dstp/internal/version.Commit=$(COMMIT) -X github.com/DivyendraPatil/dstp/internal/version.Date=$(DATE)

build:
	go build -ldflags "$(LDFLAGS)" -o dstp ./cmd/dstp

install:
	GOBIN=$$(go env GOPATH)/bin go install -ldflags "$(LDFLAGS)" ./cmd/dstp

test:
	go test ./...

vet:
	go vet ./...
