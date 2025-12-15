# vc-jump Makefile

.PHONY: all build test lint clean install-tools run coverage help

# Build variables
BINARY_NAME := vc-jump
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)"

# Go variables
GOCMD := go
GOBUILD := $(GOCMD) build
GOTEST := $(GOCMD) test
GOVET := $(GOCMD) vet
GOMOD := $(GOCMD) mod
GOFMT := gofmt

# Directories
DIST_DIR := dist
CMD_DIR := ./cmd/vc-jump

## help: Show this help message
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'

## all: Run tests and build
all: test build

## build: Build binary for current platform
build:
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME) $(CMD_DIR)

## build-all: Build binaries for all platforms
build-all: clean
	mkdir -p $(DIST_DIR)
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-linux-amd64 $(CMD_DIR)
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-linux-arm64 $(CMD_DIR)
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-darwin-amd64 $(CMD_DIR)
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-darwin-arm64 $(CMD_DIR)
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-windows-amd64.exe $(CMD_DIR)

## test: Run all tests
test:
	$(GOTEST) -v -race ./...

## test-short: Run short tests only
test-short:
	$(GOTEST) -v -short ./...

## coverage: Run tests with coverage
coverage:
	$(GOTEST) -v -race -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

## lint: Run linter
lint:
	golangci-lint run ./...

## lint-fix: Run linter with auto-fix
lint-fix:
	golangci-lint run --fix ./...

## fmt: Format code
fmt:
	$(GOFMT) -s -w .
	goimports -w .

## vet: Run go vet
vet:
	$(GOVET) ./...

## tidy: Tidy go modules
tidy:
	$(GOMOD) tidy

## verify: Verify dependencies
verify:
	$(GOMOD) verify

## security: Run security scan
security:
	gosec -exclude-dir=vendor ./...

## clean: Remove build artifacts
clean:
	rm -f $(BINARY_NAME)
	rm -rf $(DIST_DIR)
	rm -f coverage.out coverage.html

## install-tools: Install development tools
install-tools:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/securego/gosec/v2/cmd/gosec@latest
	go install github.com/goreleaser/goreleaser@latest
	@echo "Installing pre-commit..."
	@command -v pre-commit >/dev/null 2>&1 || pip install pre-commit
	pre-commit install
	pre-commit install --hook-type commit-msg

## pre-commit: Run pre-commit hooks
pre-commit:
	pre-commit run --all-files

## run: Build and run the server
run: build
	./$(BINARY_NAME)

## docker-build: Build Docker image
docker-build:
	docker build -t vc-jump:$(VERSION) .

## release-dry: Dry run release
release-dry:
	goreleaser release --snapshot --clean

## release: Create a new release (use: make release VERSION=v1.0.0)
release:
	@if [ -z "$(VERSION)" ]; then echo "VERSION is required. Usage: make release VERSION=v1.0.0"; exit 1; fi
	git tag -a $(VERSION) -m "Release $(VERSION)"
	git push origin $(VERSION)
