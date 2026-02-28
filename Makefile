.PHONY: build build-mcp clean test vet lint run-checks docker snapshot-check tidy help

BINARY=closedsspm
MCP_BINARY=closedsspm-mcp
VERSION?=dev
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS=-ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)"

## build: Build the main CLI binary
build:
	go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/closedsspm

## build-mcp: Build the standalone MCP server binary
build-mcp:
	go build $(LDFLAGS) -o bin/$(MCP_BINARY) ./cmd/mcp

## all: Build all binaries
all: build build-mcp

## clean: Remove build artifacts
clean:
	rm -rf bin/ dist/

## test: Run all tests
test:
	go test -v -count=1 ./...

## vet: Run go vet
vet:
	go vet ./...

## lint: Run linter
lint:
	golangci-lint run ./...

## run-checks: List all available security checks
run-checks: build
	./bin/$(BINARY) checks list

## snapshot-check: Validate goreleaser config
snapshot-check:
	goreleaser check

## docker: Build Docker image locally
docker:
	docker build -t closedsspm:local .

## tidy: Clean up go.mod and go.sum
tidy:
	go mod tidy

## help: Show this help
help:
	@echo "ClosedSSPM - Open Source SaaS Security Posture Management"
	@echo ""
	@echo "Usage:"
	@sed -n 's/^## //p' $(MAKEFILE_LIST) | column -t -s ':'
