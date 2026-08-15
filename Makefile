.PHONY: build test vet install fmt lint race integration cover vuln release-check check

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X github.com/DivyendraPatil/dstp/internal/version.Version=$(VERSION) -X github.com/DivyendraPatil/dstp/internal/version.Commit=$(COMMIT) -X github.com/DivyendraPatil/dstp/internal/version.Date=$(DATE)
GOBIN   ?= $(shell go env GOBIN)
ifeq ($(GOBIN),)
GOBIN := $(shell go env GOPATH)/bin
endif

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o dstp ./cmd/dstp

install:
	GOBIN=$(GOBIN) go install -trimpath -ldflags "$(LDFLAGS)" ./cmd/dstp

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './.git/*')

lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2 run --timeout=5m ./...

test:
	go test ./...

race:
	go test -race ./...

integration:
	go test -tags=integration ./pkg/dstp ./pkg/lookup

cover:
	go test -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -func=coverage.out | tail -1

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

release-check:
	go run github.com/goreleaser/goreleaser/v2@latest check
	go run github.com/goreleaser/goreleaser/v2@latest release --snapshot --clean --skip=publish,sign,sbom

vet:
	go vet ./...

check: fmt vet lint test race release-check
