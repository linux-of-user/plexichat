#!/bin/bash

# PlexiChat Go Client - Comprehensive Demo Script
# This script demonstrates every major feature of the PlexiChat Go Client

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
CLIENT="./plexichat-client"
SERVER_URL="http://localhost:8000"
TEST_USERNAME="demo-user"
TEST_PASSWORD="demo-password"
TEST_EMAIL="demo@example.com"

# Helper functions
log_section() {
    echo -e "\n${CYAN}=== $1 ===${NC}"
}

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

# Check if client exists
if [ ! -f "$CLIENT" ]; then
    log_error "PlexiChat client not found at $CLIENT"
    log_info "Please build the client first: make build"
    exit 1
fi

log_section "PlexiChat Go Client - Comprehensive Demo"
echo "This demo showcases every major feature of the PlexiChat Go Client"
echo "Server URL: $SERVER_URL"
echo "Press Enter to continue or Ctrl+C to exit..."
read

# 1. Configuration Management
log_section "1. Configuration Management"

log_info "Initializing configuration..."
$CLIENT config init --force || log_warning "Config already exists"

log_info "Setting server URL..."
$CLIENT config set url "$SERVER_URL"

log_info "Configuring client settings..."
$CLIENT config set timeout "30s"
$CLIENT config set verbose true
$CLIENT config set color true

log_info "Showing current configuration..."
$CLIENT config show

log_success "Configuration management complete"

# 2. Health and Version Checks
log_section "2. Health and Version Checks"

log_info "Checking client version..."
$CLIENT version

log_info "Checking server health..."
$CLIENT health || log_warning "Server may not be running"

log_success "Health checks complete"

# 3. Authentication
log_section "3. Authentication"

log_info "Registering demo user..."
$CLIENT auth register \
    --username "$TEST_USERNAME" \
    --email "$TEST_EMAIL" \
    --password "$TEST_PASSWORD" \
    --type user || log_warning "User may already exist"

log_info "Logging in..."
$CLIENT auth login --username "$TEST_USERNAME" --password "$TEST_PASSWORD" || {
    log_error "Login failed - server may not be running"
    log_info "Continuing with demo (some features may not work)"
}

log_info "Checking current user..."
$CLIENT auth whoami || log_warning "Not authenticated"

log_success "Authentication complete"

# 4. Chat Operations
log_section "4. Chat Operations"

log_info "Listing chat rooms..."
$CLIENT chat rooms || log_warning "Could not fetch rooms"

log_info "Sending test messages..."
for i in {1..3}; do
    $CLIENT chat send --room 1 --message "Demo message $i from comprehensive test" || log_warning "Could not send message $i"
    sleep 1
done

log_info "Getting chat history..."
$CLIENT chat history --room 1 --limit 10 || log_warning "Could not fetch history"

log_success "Chat operations complete"

# 5. File Operations
log_section "5. File Operations"

log_info "Creating test file..."
echo "This is a test file for PlexiChat demo" > demo-test-file.txt
echo "Generated at: $(date)" >> demo-test-file.txt
echo "Client version: $($CLIENT version | head -1)" >> demo-test-file.txt

log_info "Uploading test file..."
$CLIENT files upload --file demo-test-file.txt || log_warning "Could not upload file"

log_info "Listing files..."
$CLIENT files list || log_warning "Could not list files"

log_info "Cleaning up test file..."
rm -f demo-test-file.txt

log_success "File operations complete"

# 6. Testing Framework
log_section "6. Testing Framework"

log_info "Running connection tests..."
$CLIENT test connection --timeout 5 || log_warning "Connection tests failed"

log_info "Running comprehensive test suite..."
$CLIENT test all --verbose || log_warning "Some tests may have failed"

log_success "Testing framework complete"

# 7. Security Testing
log_section "7. Security Testing"

log_info "Running basic security tests..."
$CLIENT security test --endpoint "/api/v1/health" --type "basic" || log_warning "Security tests may not be available"

log_info "Note: Full security scanning requires appropriate permissions"
log_info "Example: $CLIENT security scan --all"

log_success "Security testing complete"

# 8. Performance Testing
log_section "8. Performance Testing"

log_info "Running performance tests..."
$CLIENT benchmark response --endpoint "/api/v1/health" --samples 50 --target 100ms || log_warning "Performance tests may not be available"

log_info "Running light load test..."
$CLIENT benchmark load --endpoint "/api/v1/health" --concurrent 5 --duration 10s || log_warning "Load tests may not be available"

log_success "Performance testing complete"

# 9. Monitoring (Brief Demo)
log_section "9. Monitoring Capabilities"

log_info "Monitoring features available:"
echo "  - Real-time system monitoring: $CLIENT monitor system"
echo "  - Chat activity monitoring: $CLIENT monitor chat"
echo "  - User activity monitoring: $CLIENT monitor users"
echo "  - Alert monitoring: $CLIENT monitor alerts"
echo "  - Analytics generation: $CLIENT analytics"

log_info "Note: Monitoring requires active server connection"

log_success "Monitoring demo complete"

# 10. Automation and Scripting
log_section "10. Automation and Scripting"

log_info "Creating demo script..."
mkdir -p scripts

cat > scripts/demo-script.json << 'EOF'
{
  "name": "Demo Script",
  "description": "Demonstration automation script",
  "version": "1.0.0",
  "author": "PlexiChat Demo",
  "variables": {
    "room": "1",
    "message": "Automated message from demo script"
  },
  "commands": [
    {
      "type": "log",
      "command": "info",
      "args": ["Starting demo script execution"],
      "description": "Log script start"
    },
    {
      "type": "api",
      "command": "health",
      "description": "Check server health"
    },
    {
      "type": "wait",
      "command": "sleep",
      "args": ["2s"],
      "description": "Wait 2 seconds"
    },
    {
      "type": "log",
      "command": "info",
      "args": ["Demo script completed successfully"],
      "description": "Log script completion"
    }
  ]
}
EOF

log_info "Running demo script..."
$CLIENT script run scripts/demo-script.json || log_warning "Script execution may require authentication"

log_info "Listing available scripts..."
$CLIENT script list

log_success "Automation and scripting complete"

# 11. Plugin System
log_section "11. Plugin System"

log_info "Listing available plugins..."
$CLIENT plugins list || log_warning "Plugin system demo"

log_info "Plugin system features:"
echo "  - Install plugins: $CLIENT plugins install <plugin-name>"
echo "  - Enable/disable: $CLIENT plugins enable/disable <plugin-name>"
echo "  - Search plugins: $CLIENT plugins search <query>"
echo "  - Plugin info: $CLIENT plugins info <plugin-name>"

log_success "Plugin system demo complete"

# 12. Documentation Generation
log_section "12. Documentation Generation"

log_info "Generating documentation..."
$CLIENT docs generate --format markdown --output demo-docs || log_warning "Documentation generation demo"

log_info "Documentation features:"
echo "  - Generate docs: $CLIENT docs generate"
echo "  - Create examples: $CLIENT docs examples"
echo "  - Serve docs: $CLIENT docs serve"

if [ -d "demo-docs" ]; then
    log_info "Generated documentation in demo-docs/"
    ls -la demo-docs/ || true
fi

log_success "Documentation generation complete"

# 13. Configuration Management (Advanced)
log_section "13. Advanced Configuration"

log_info "Configuration management features:"
echo "  - Backup config: $CLIENT config backup"
echo "  - Restore config: $CLIENT config restore <backup-file>"
echo "  - Validate config: $CLIENT config validate"
echo "  - Edit config: $CLIENT config edit"

log_info "Validating current configuration..."
$CLIENT config validate || log_warning "Configuration validation"

log_success "Advanced configuration complete"

# 14. Interactive Mode Demo
log_section "14. Interactive Mode"

log_info "Interactive mode features:"
echo "  - Start interactive shell: $CLIENT interactive"
echo "  - Command history and auto-completion"
echo "  - Built-in help and shortcuts"
echo "  - Real-time chat interface"

log_info "Note: Interactive mode provides a shell-like experience"
log_info "Try: $CLIENT interactive"

log_success "Interactive mode demo complete"

# Final Summary
log_section "Demo Complete - Summary"

echo -e "${GREEN}✅ Configuration Management${NC} - Initialize, set, validate, backup/restore"
echo -e "${GREEN}✅ Health & Version Checks${NC} - Server connectivity and version info"
echo -e "${GREEN}✅ Authentication${NC} - Register, login, logout, user management"
echo -e "${GREEN}✅ Chat Operations${NC} - Send messages, history, real-time listening"
echo -e "${GREEN}✅ File Operations${NC} - Upload, download, list, manage files"
echo -e "${GREEN}✅ Testing Framework${NC} - Connection, auth, chat, stress testing"
echo -e "${GREEN}✅ Security Testing${NC} - Vulnerability scanning, penetration testing"
echo -e "${GREEN}✅ Performance Testing${NC} - Load testing, response time validation"
echo -e "${GREEN}✅ Monitoring${NC} - Real-time system, chat, user, alert monitoring"
echo -e "${GREEN}✅ Automation${NC} - Scripting, workflows, scheduling"
echo -e "${GREEN}✅ Plugin System${NC} - Install, manage, extend functionality"
echo -e "${GREEN}✅ Documentation${NC} - Auto-generated docs, examples, API reference"
echo -e "${GREEN}✅ Interactive Mode${NC} - Shell-like interface with advanced features"
echo -e "${GREEN}✅ Advanced Config${NC} - Comprehensive configuration management"

echo ""
log_success "PlexiChat Go Client comprehensive demo completed!"
echo ""
echo -e "${CYAN}Next Steps:${NC}"
echo "1. Explore interactive mode: $CLIENT interactive"
echo "2. Set up monitoring: $CLIENT monitor system"
echo "3. Create custom scripts: $CLIENT script create"
echo "4. Run security scans: $CLIENT security scan --all"
echo "5. Generate documentation: $CLIENT docs generate"
echo ""
echo -e "${YELLOW}For more information:${NC}"
echo "- Read the documentation: docs/README.md"
echo "- Check examples: examples/"
echo "- View configuration: $CLIENT config show"
echo "- Get help: $CLIENT --help"

# Cleanup
log_info "Cleaning up demo files..."
rm -rf scripts/demo-script.json demo-docs/ 2>/dev/null || true

log_success "Demo cleanup complete"
echo ""
echo -e "${CYAN}Thank you for trying the PlexiChat Go Client!${NC}"
