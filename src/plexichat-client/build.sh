#!/bin/bash

# PlexiChat Go Client Build Script
# Comprehensive build script for cross-platform compilation

set -e

# Configuration
BINARY_NAME="plexichat-client"
VERSION="1.0.0"
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
BUILD_DIR="build"
PACKAGE_DIR="packages"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check dependencies
check_dependencies() {
    log_info "Checking dependencies..."
    
    if ! command -v go &> /dev/null; then
        log_error "Go is not installed or not in PATH"
        exit 1
    fi
    
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    log_info "Go version: $GO_VERSION"
    
    if ! command -v git &> /dev/null; then
        log_warning "Git is not installed - using default commit hash"
        COMMIT="unknown"
    fi
}

# Clean build directory
clean() {
    log_info "Cleaning build directory..."
    rm -rf "$BUILD_DIR"
    rm -rf "$PACKAGE_DIR"
    go clean
    log_success "Clean completed"
}

# Install dependencies
deps() {
    log_info "Installing dependencies..."
    go mod download
    go mod tidy
    log_success "Dependencies installed"
}

# Build for current platform
build() {
    log_info "Building for current platform..."
    mkdir -p "$BUILD_DIR"
    
    LDFLAGS="-ldflags \"-X main.Version=$VERSION -X main.Commit=$COMMIT -X main.BuildTime=$BUILD_TIME\""
    
    eval "go build $LDFLAGS -o $BUILD_DIR/$BINARY_NAME ."
    
    log_success "Build completed: $BUILD_DIR/$BINARY_NAME"
}

# Build for all platforms
build_all() {
    log_info "Building for all platforms..."
    mkdir -p "$BUILD_DIR"
    
    LDFLAGS="-ldflags \"-X main.Version=$VERSION -X main.Commit=$COMMIT -X main.BuildTime=$BUILD_TIME\""
    
    # Define platforms
    declare -a platforms=(
        "linux/amd64"
        "linux/arm64"
        "linux/386"
        "darwin/amd64"
        "darwin/arm64"
        "windows/amd64"
        "windows/386"
        "freebsd/amd64"
        "openbsd/amd64"
        "netbsd/amd64"
    )
    
    for platform in "${platforms[@]}"; do
        IFS='/' read -r -a array <<< "$platform"
        GOOS="${array[0]}"
        GOARCH="${array[1]}"
        
        output_name="$BINARY_NAME-$GOOS-$GOARCH"
        if [ "$GOOS" = "windows" ]; then
            output_name="$output_name.exe"
        fi
        
        log_info "Building for $GOOS/$GOARCH..."
        
        env GOOS="$GOOS" GOARCH="$GOARCH" eval "go build $LDFLAGS -o $BUILD_DIR/$output_name ."
        
        if [ $? -eq 0 ]; then
            log_success "Built: $BUILD_DIR/$output_name"
        else
            log_error "Failed to build for $GOOS/$GOARCH"
        fi
    done
}

# Run tests
test() {
    log_info "Running tests..."
    go test -v ./...
    log_success "Tests completed"
}

# Run tests with coverage
test_coverage() {
    log_info "Running tests with coverage..."
    go test -v -coverprofile=coverage.out ./...
    go tool cover -html=coverage.out -o coverage.html
    log_success "Coverage report generated: coverage.html"
}

# Format code
fmt() {
    log_info "Formatting code..."
    go fmt ./...
    log_success "Code formatted"
}

# Lint code
lint() {
    log_info "Linting code..."
    if command -v golangci-lint &> /dev/null; then
        golangci-lint run
        log_success "Linting completed"
    else
        log_warning "golangci-lint not found, skipping linting"
    fi
}

# Security scan
security() {
    log_info "Running security scan..."
    if command -v gosec &> /dev/null; then
        gosec ./...
        log_success "Security scan completed"
    else
        log_warning "gosec not found, skipping security scan"
    fi
}

# Package binaries
package() {
    log_info "Packaging binaries..."
    mkdir -p "$PACKAGE_DIR"
    
    # Copy documentation
    cp README.md "$BUILD_DIR/" 2>/dev/null || log_warning "README.md not found"
    cp LICENSE "$BUILD_DIR/" 2>/dev/null || log_warning "LICENSE not found"
    
    # Package Unix binaries
    for binary in "$BUILD_DIR"/*; do
        if [[ -f "$binary" && ! "$binary" == *.exe ]]; then
            binary_name=$(basename "$binary")
            if [[ "$binary_name" != "README.md" && "$binary_name" != "LICENSE" ]]; then
                log_info "Packaging $binary_name..."
                tar -czf "$PACKAGE_DIR/$binary_name.tar.gz" -C "$BUILD_DIR" "$binary_name" README.md LICENSE 2>/dev/null || \
                tar -czf "$PACKAGE_DIR/$binary_name.tar.gz" -C "$BUILD_DIR" "$binary_name"
            fi
        fi
    done
    
    # Package Windows binaries
    for binary in "$BUILD_DIR"/*.exe; do
        if [[ -f "$binary" ]]; then
            binary_name=$(basename "$binary" .exe)
            log_info "Packaging $binary_name.exe..."
            (cd "$BUILD_DIR" && zip "../$PACKAGE_DIR/$binary_name.zip" "$binary_name.exe" README.md LICENSE 2>/dev/null || \
             zip "../$PACKAGE_DIR/$binary_name.zip" "$binary_name.exe")
        fi
    done
    
    log_success "Packaging completed"
}

# Install binary
install() {
    if [[ ! -f "$BUILD_DIR/$BINARY_NAME" ]]; then
        log_error "Binary not found. Run 'build' first."
        exit 1
    fi
    
    log_info "Installing binary to /usr/local/bin..."
    sudo cp "$BUILD_DIR/$BINARY_NAME" /usr/local/bin/
    sudo chmod +x /usr/local/bin/$BINARY_NAME
    log_success "Binary installed to /usr/local/bin/$BINARY_NAME"
}

# Development setup
dev_setup() {
    log_info "Setting up development environment..."
    
    # Install development tools
    go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
    go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
    
    log_success "Development environment setup completed"
}

# Quick development build and test
dev() {
    clean
    deps
    fmt
    lint
    test
    build
    log_success "Development build completed"
}

# Release build
release() {
    log_info "Creating release build..."
    clean
    deps
    fmt
    lint
    test
    security
    build_all
    package
    log_success "Release build completed"
}

# Show help
help() {
    echo "PlexiChat Go Client Build Script"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  clean       - Clean build artifacts"
    echo "  deps        - Install dependencies"
    echo "  build       - Build for current platform"
    echo "  build-all   - Build for all platforms"
    echo "  test        - Run tests"
    echo "  test-cov    - Run tests with coverage"
    echo "  fmt         - Format code"
    echo "  lint        - Lint code"
    echo "  security    - Run security scan"
    echo "  package     - Package binaries"
    echo "  install     - Install binary to system"
    echo "  dev-setup   - Setup development environment"
    echo "  dev         - Quick development build"
    echo "  release     - Create release build"
    echo "  help        - Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 dev              # Quick development build"
    echo "  $0 release          # Full release build"
    echo "  $0 build-all        # Build for all platforms"
    echo "  $0 test-cov         # Run tests with coverage"
}

# Main script logic
main() {
    check_dependencies
    
    case "${1:-help}" in
        clean)
            clean
            ;;
        deps)
            deps
            ;;
        build)
            build
            ;;
        build-all)
            build_all
            ;;
        test)
            test
            ;;
        test-cov)
            test_coverage
            ;;
        fmt)
            fmt
            ;;
        lint)
            lint
            ;;
        security)
            security
            ;;
        package)
            package
            ;;
        install)
            install
            ;;
        dev-setup)
            dev_setup
            ;;
        dev)
            dev
            ;;
        release)
            release
            ;;
        help|--help|-h)
            help
            ;;
        *)
            log_error "Unknown command: $1"
            help
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
