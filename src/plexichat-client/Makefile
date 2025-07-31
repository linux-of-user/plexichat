# PlexiChat Go Client Makefile

# Variables
BINARY_NAME=plexichat-client
MAIN_PACKAGE=.
BUILD_DIR=build
VERSION=1.0.0
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Get the current working directory
PWD=$(shell pwd)

# Build flags
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.Commit=$(COMMIT) -X main.BuildTime=$(BUILD_TIME)"

# Default target
.PHONY: all
all: clean deps build

# Install dependencies
.PHONY: deps
deps:
	$(GOMOD) download
	$(GOMOD) tidy

# Build the binary
.PHONY: build
build:
	mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PACKAGE)

# Build for multiple platforms
.PHONY: build-all
build-all: clean deps
	mkdir -p $(BUILD_DIR)
	# Linux
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(MAIN_PACKAGE)
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 $(MAIN_PACKAGE)
	# Windows
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe $(MAIN_PACKAGE)
	# macOS
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 $(MAIN_PACKAGE)
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 $(MAIN_PACKAGE)

# Run tests
.PHONY: test
test:
	$(GOTEST) -v ./...

# Run tests with coverage
.PHONY: test-coverage
test-coverage:
	$(GOTEST) -v -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

# Clean build artifacts
.PHONY: clean
clean:
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

# Install the binary
.PHONY: install
install: build
	cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/

# Run the binary
.PHONY: run
run: build
	./$(BUILD_DIR)/$(BINARY_NAME)

# Format code
.PHONY: fmt
fmt:
	$(GOCMD) fmt ./...

# Lint code
.PHONY: lint
lint:
	golangci-lint run

# Security scan
.PHONY: security
security:
	gosec ./...

# Generate documentation
.PHONY: docs
docs:
	$(GOCMD) doc -all > docs.txt

# Development setup
.PHONY: dev-setup
dev-setup:
	$(GOGET) -u github.com/golangci/golangci-lint/cmd/golangci-lint
	$(GOGET) -u github.com/securecodewarrior/gosec/v2/cmd/gosec

# Quick development build and run
.PHONY: dev
dev: build
	./$(BUILD_DIR)/$(BINARY_NAME) --help

# Example commands for testing
.PHONY: examples
examples: build
	@echo "Running example commands..."
	@echo "1. Health check:"
	./$(BUILD_DIR)/$(BINARY_NAME) health || true
	@echo ""
	@echo "2. Version info:"
	./$(BUILD_DIR)/$(BINARY_NAME) version || true
	@echo ""
	@echo "3. Help:"
	./$(BUILD_DIR)/$(BINARY_NAME) --help

# Package for distribution
.PHONY: package
package: build-all
	mkdir -p $(BUILD_DIR)/packages
	# Create tar.gz for Unix systems
	tar -czf $(BUILD_DIR)/packages/$(BINARY_NAME)-$(VERSION)-linux-amd64.tar.gz -C $(BUILD_DIR) $(BINARY_NAME)-linux-amd64 README.md
	tar -czf $(BUILD_DIR)/packages/$(BINARY_NAME)-$(VERSION)-linux-arm64.tar.gz -C $(BUILD_DIR) $(BINARY_NAME)-linux-arm64 README.md
	tar -czf $(BUILD_DIR)/packages/$(BINARY_NAME)-$(VERSION)-darwin-amd64.tar.gz -C $(BUILD_DIR) $(BINARY_NAME)-darwin-amd64 README.md
	tar -czf $(BUILD_DIR)/packages/$(BINARY_NAME)-$(VERSION)-darwin-arm64.tar.gz -C $(BUILD_DIR) $(BINARY_NAME)-darwin-arm64 README.md
	# Create zip for Windows
	cd $(BUILD_DIR) && zip packages/$(BINARY_NAME)-$(VERSION)-windows-amd64.zip $(BINARY_NAME)-windows-amd64.exe README.md

# Help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all          - Clean, install deps, and build"
	@echo "  deps         - Install Go dependencies"
	@echo "  build        - Build the binary"
	@echo "  build-all    - Build for all platforms"
	@echo "  test         - Run tests"
	@echo "  test-coverage- Run tests with coverage"
	@echo "  clean        - Clean build artifacts"
	@echo "  install      - Install binary to /usr/local/bin"
	@echo "  run          - Build and run the binary"
	@echo "  fmt          - Format Go code"
	@echo "  lint         - Run linter"
	@echo "  security     - Run security scan"
	@echo "  docs         - Generate documentation"
	@echo "  dev-setup    - Install development tools"
	@echo "  dev          - Quick development build"
	@echo "  examples     - Run example commands"
	@echo "  package      - Package for distribution"
	@echo "  help         - Show this help"
