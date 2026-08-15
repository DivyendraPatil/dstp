.PHONY: build test vet

build:
	go build -o dstp ./cmd/dstp

test:
	go test ./...

vet:
	go vet ./...
