.PHONY: build test lint install release-local

build:
	go build -o bin/hushed ./cmd/hushed

test:
	go test ./... -v

lint:
	golangci-lint run

install:
	go install ./cmd/hushed

release-local:
	goreleaser release --snapshot --clean
