#!/bin/bash

# PlexiChat Go Client Release Script
# Creates comprehensive release packages for distribution

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Release configuration
VERSION=${VERSION:-"1.0.0"}
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
RELEASE_DIR="release"
BINARY_NAME="plexichat-client"

# Platforms to build for
PLATFORMS=(
    "linux/amd64"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
)

echo -e "${BLUE}🚀 PlexiChat Go Client Release Builder${NC}"
echo -e "${BLUE}=====================================${NC}"
echo ""
echo -e "Version: ${GREEN}${VERSION}${NC}"
echo -e "Commit: ${GREEN}${COMMIT}${NC}"
echo -e "Build Time: ${GREEN}${BUILD_TIME}${NC}"
echo ""

# Function to print colored output
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

# Clean and prepare release directory
prepare_release() {
    log_info "Preparing release directory..."
    rm -rf "$RELEASE_DIR"
    mkdir -p "$RELEASE_DIR"
    log_success "Release directory prepared"
}

# Build for a specific platform
build_platform() {
    local platform=$1
    local os=$(echo $platform | cut -d'/' -f1)
    local arch=$(echo $platform | cut -d'/' -f2)
    
    local output_name="${BINARY_NAME}"
    if [ "$os" = "windows" ]; then
        output_name="${output_name}.exe"
    fi
    
    local build_dir="build"
    local output_path="${build_dir}/${output_name}-${os}-${arch}"
    if [ "$os" = "windows" ]; then
        output_path="${output_path}.exe"
    fi
    
    log_info "Building for ${os}/${arch}..."
    
    # Set build flags
    local ldflags="-s -w"
    ldflags="${ldflags} -X main.version=${VERSION}"
    ldflags="${ldflags} -X main.commit=${COMMIT}"
    ldflags="${ldflags} -X main.buildTime=${BUILD_TIME}"
    
    # Create output directory
    mkdir -p "$(dirname "$output_path")"
    
    # Build
    env GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build \
        -ldflags="${ldflags}" \
        -o "$output_path" \
        .
    
    if [ $? -eq 0 ]; then
        log_success "Built ${os}/${arch} -> ${output_path}"
        
        # Create release package
        create_release_package "$os" "$arch" "$output_path"
    else
        log_error "Failed to build for ${os}/${arch}"
        return 1
    fi
}

# Create release package for a platform
create_release_package() {
    local os=$1
    local arch=$2
    local binary_path=$3
    
    local package_name="${BINARY_NAME}-${VERSION}-${os}-${arch}"
    local package_dir="${RELEASE_DIR}/${package_name}"
    
    log_info "Creating release package for ${os}/${arch}..."
    
    # Create package directory
    mkdir -p "$package_dir"
    
    # Copy binary
    cp "$binary_path" "$package_dir/"
    
    # Copy documentation
    if [ -f "README.md" ]; then
        cp "README.md" "$package_dir/"
    fi
    
    if [ -f "LICENSE" ]; then
        cp "LICENSE" "$package_dir/"
    fi
    
    # Copy example configuration
    if [ -f ".plexichat-client.example.yaml" ]; then
        cp ".plexichat-client.example.yaml" "$package_dir/config.example.yaml"
    fi
    
    # Create installation script for Unix-like systems
    if [ "$os" != "windows" ]; then
        cat > "$package_dir/install.sh" << 'EOF'
#!/bin/bash
# PlexiChat Client Installation Script

set -e

BINARY_NAME="plexichat-client"
INSTALL_DIR="/usr/local/bin"

echo "Installing PlexiChat Client..."

# Check if running as root or with sudo
if [ "$EUID" -ne 0 ]; then
    echo "This script requires root privileges. Please run with sudo."
    exit 1
fi

# Copy binary
cp "$BINARY_NAME" "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/$BINARY_NAME"

echo "✓ PlexiChat Client installed to $INSTALL_DIR"
echo "You can now run: plexichat-client --help"
EOF
        chmod +x "$package_dir/install.sh"
    fi
    
    # Create Windows batch installer
    if [ "$os" = "windows" ]; then
        cat > "$package_dir/install.bat" << 'EOF'
@echo off
echo Installing PlexiChat Client...

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Running as administrator...
) else (
    echo This script requires administrator privileges.
    echo Please run as administrator.
    pause
    exit /b 1
)

REM Copy to Program Files
if not exist "C:\Program Files\PlexiChat" mkdir "C:\Program Files\PlexiChat"
copy "plexichat-client.exe" "C:\Program Files\PlexiChat\"

REM Add to PATH (requires restart)
setx /M PATH "%PATH%;C:\Program Files\PlexiChat"

echo PlexiChat Client installed successfully!
echo Please restart your command prompt to use the 'plexichat-client' command.
pause
EOF
    fi
    
    # Create quick start guide
    cat > "$package_dir/QUICKSTART.md" << EOF
# PlexiChat Client Quick Start

## Installation

### Linux/macOS
\`\`\`bash
sudo ./install.sh
\`\`\`

### Windows
Run \`install.bat\` as Administrator

## Configuration

\`\`\`bash
# Initialize configuration
plexichat-client config init

# Set server URL
plexichat-client config set url "https://your-plexichat-server.com"
\`\`\`

## Basic Usage

\`\`\`bash
# Check server health
plexichat-client health

# Login
plexichat-client auth login --username your-username

# Send a message
plexichat-client chat send --message "Hello, World!"

# Listen to chat
plexichat-client chat listen --room general
\`\`\`

## Help

\`\`\`bash
plexichat-client --help
plexichat-client [command] --help
\`\`\`
EOF
    
    # Create archive
    cd "$RELEASE_DIR"
    if [ "$os" = "windows" ]; then
        if command -v zip &> /dev/null; then
            zip -r "${package_name}.zip" "$package_name" > /dev/null
            log_success "Created ${package_name}.zip"
        else
            tar -czf "${package_name}.tar.gz" "$package_name"
            log_success "Created ${package_name}.tar.gz"
        fi
    else
        tar -czf "${package_name}.tar.gz" "$package_name"
        log_success "Created ${package_name}.tar.gz"
    fi
    cd - > /dev/null
    
    # Remove temporary directory
    rm -rf "$package_dir"
}

# Build all platforms
build_all_platforms() {
    log_info "Building for all platforms..."
    
    local failed_builds=()
    
    for platform in "${PLATFORMS[@]}"; do
        if ! build_platform "$platform"; then
            failed_builds+=("$platform")
        fi
    done
    
    if [ ${#failed_builds[@]} -eq 0 ]; then
        log_success "All builds completed successfully"
    else
        log_warning "Some builds failed: ${failed_builds[*]}"
    fi
}

# Generate checksums
generate_checksums() {
    log_info "Generating checksums..."
    
    cd "$RELEASE_DIR"
    
    # Generate SHA256 checksums
    if command -v sha256sum &> /dev/null; then
        sha256sum *.tar.gz *.zip 2>/dev/null > checksums.sha256 || true
    elif command -v shasum &> /dev/null; then
        shasum -a 256 *.tar.gz *.zip 2>/dev/null > checksums.sha256 || true
    fi
    
    # Generate MD5 checksums
    if command -v md5sum &> /dev/null; then
        md5sum *.tar.gz *.zip 2>/dev/null > checksums.md5 || true
    elif command -v md5 &> /dev/null; then
        md5 *.tar.gz *.zip 2>/dev/null > checksums.md5 || true
    fi
    
    cd - > /dev/null
    
    log_success "Checksums generated"
}

# Show release summary
show_release_summary() {
    log_success "Release build completed!"
    echo ""
    echo -e "${BLUE}Release Information:${NC}"
    echo -e "  Version: ${VERSION}"
    echo -e "  Commit: ${COMMIT}"
    echo -e "  Build Time: ${BUILD_TIME}"
    echo ""
    
    if [ -d "$RELEASE_DIR" ]; then
        echo -e "${BLUE}Release packages:${NC}"
        find "$RELEASE_DIR" -name "*.tar.gz" -o -name "*.zip" | while read -r file; do
            local size=$(du -h "$file" | cut -f1)
            echo -e "  ${file} (${size})"
        done
        echo ""
        
        if [ -f "$RELEASE_DIR/checksums.sha256" ]; then
            echo -e "${BLUE}Checksums available:${NC}"
            echo -e "  ${RELEASE_DIR}/checksums.sha256"
            echo -e "  ${RELEASE_DIR}/checksums.md5"
            echo ""
        fi
    fi
    
    echo -e "${GREEN}Ready for distribution!${NC}"
}

# Main execution
main() {
    prepare_release
    build_all_platforms
    generate_checksums
    show_release_summary
}

# Run main function
main "$@"
