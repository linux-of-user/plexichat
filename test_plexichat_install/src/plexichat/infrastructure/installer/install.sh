#!/bin/bash
# PlexiChat Installer for Linux/macOS
# Downloads and installs PlexiChat from GitHub

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Print colored output
print_color() {
    echo -e "${1}${2}${NC}"
}

print_header() {
    echo "============================================================"
    print_color $CYAN "🚀 PlexiChat Installer"
    print_color $CYAN "Modern Distributed Communication Platform"
    echo "============================================================"
    echo
}

check_requirements() {
    print_color $BLUE "📋 Checking system requirements..."
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        print_color $RED "❌ Python 3 not found. Please install Python 3.8+"
        exit 1
    fi
    
    PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    print_color $GREEN "✅ Python $PYTHON_VERSION found"
    
    # Check pip
    if ! python3 -m pip --version &> /dev/null; then
        print_color $RED "❌ pip not found. Please install pip"
        exit 1
    fi
    
    print_color $GREEN "✅ pip found"
    
    # Check internet connection
    if ! curl -s --head https://github.com > /dev/null; then
        print_color $RED "❌ No internet connection"
        exit 1
    fi
    
    print_color $GREEN "✅ Internet connection available"
}

download_installer() {
    print_color $BLUE "⬇️  Downloading PlexiChat installer..."
    
    # Create temporary directory
    TEMP_DIR=$(mktemp -d)
    INSTALLER_PATH="$TEMP_DIR/install.py"
    
    # Download installer
    if curl -s -L "https://raw.githubusercontent.com/linux-of-user/plexichat/main/installer/install.py" -o "$INSTALLER_PATH"; then
        print_color $GREEN "✅ Installer downloaded"
        echo "$INSTALLER_PATH"
    else
        print_color $RED "❌ Failed to download installer"
        exit 1
    fi
}

main() {
    print_header
    
    check_requirements
    
    # Download and run installer
    INSTALLER_PATH=$(download_installer)
    
    print_color $BLUE "🚀 Starting PlexiChat installation..."
    echo
    
    # Run Python installer
    python3 "$INSTALLER_PATH" "$@"
    
    # Cleanup
    rm -rf "$(dirname "$INSTALLER_PATH")"
    
    print_color $GREEN "🎉 Installation process completed!"
}

# Handle Ctrl+C
trap 'echo; print_color $YELLOW "🛑 Installation cancelled"; exit 1' INT

# Run main function
main "$@"
