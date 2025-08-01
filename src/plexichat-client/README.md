# PlexiChat Go Client

🚀 **The Ultimate PlexiChat Command-Line Interface**

A comprehensive, production-ready command-line client for PlexiChat written in Go. This client provides access to **EVERY** PlexiChat feature and serves as a complete reference implementation showcasing modern Go development practices, advanced CLI design, and comprehensive API integration.

[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)](build.sh)

## 🌟 **Why This Client is Special**

This isn't just another API client - it's a **complete ecosystem** that demonstrates:
- **Every PlexiChat Feature** - From basic chat to advanced security testing
- **Production-Ready Architecture** - Modular, extensible, and maintainable
- **Advanced CLI Patterns** - Interactive mode, plugins, automation, and more
- **Comprehensive Testing** - Built-in testing framework with stress testing
- **Developer Experience** - Rich documentation, examples, and tooling

## 🎯 **Complete Feature Matrix**

| Category | Features | Status |
|----------|----------|--------|
| **🔐 Authentication** | Login, Logout, Registration, Token Management, Bot Accounts | ✅ Complete |
| **💬 Real-time Chat** | Send Messages, WebSocket Listening, History, Multi-room | ✅ Complete |
| **📁 File Operations** | Upload, Download, List, Delete, Progress Tracking | ✅ Complete |
| **👑 Administration** | User Management, System Stats, Configuration | ✅ Complete |
| **🛡️ Security Testing** | Penetration Testing, Vulnerability Scanning, Reports | ✅ Complete |
| **⚡ Performance Testing** | Load Testing, Response Time, Microsecond Validation | ✅ Complete |
| **🔍 Monitoring** | Real-time Monitoring, Analytics, Alerts | ✅ Complete |
| **🤖 Automation** | Scripting, Workflows, Scheduling | ✅ Complete |
| **🔧 Configuration** | Config Management, Validation, Backup/Restore | ✅ Complete |
| **🧩 Plugin System** | Plugin Management, Extensions, Custom Commands | ✅ Complete |
| **🎮 Interactive Mode** | Shell-like Interface, Command History, Auto-completion | ✅ Complete |
| **🧪 Testing Framework** | Unit Tests, Integration Tests, Stress Testing | ✅ Complete |
| **📚 Documentation** | Auto-generated Docs, Examples, API Reference | ✅ Complete |

## 🚀 **Advanced Features**

### 🎮 **Interactive Mode**
```bash
# Start interactive shell with command history and auto-completion
./plexichat-client interactive
plexichat> login
plexichat> chat 1
chat> Hello, World!
chat> /history
chat> /exit
plexichat> files list
plexichat> exit
```

### 🧩 **Plugin System**
```bash
# Manage plugins like a package manager
./plexichat-client plugins list
./plexichat-client plugins install security-scanner
./plexichat-client plugins enable performance-monitor
./plexichat-client plugins search "chat bot"
```

### 🤖 **Automation & Scripting**
```bash
# Create and run automation scripts
./plexichat-client script create monitoring-bot --template monitoring
./plexichat-client script run scripts/daily-checks.json
./plexichat-client automate schedule --cron "0 */6 * * *" --script monitoring.json
```

### 🔍 **Real-time Monitoring**
```bash
# Monitor everything in real-time
./plexichat-client monitor system --interval 5s
./plexichat-client monitor chat --all
./plexichat-client monitor users
./plexichat-client monitor alerts --level critical
```

### 🛡️ **Advanced Security Testing**
```bash
# Comprehensive security testing
./plexichat-client security test --full-scan
./plexichat-client security scan --all --severity critical
./plexichat-client security report --format html --detailed
```

### ⚡ **Performance & Load Testing**
```bash
# Microsecond-level performance testing
./plexichat-client benchmark microsecond --endpoint /api/v1/health --samples 10000
./plexichat-client benchmark load --concurrent 100 --duration 300s
./plexichat-client test stress --concurrent 50 --duration 60s
```

## Installation

### Prerequisites
- Go 1.21 or later
- Access to a PlexiChat server

### Build from Source
```bash
git clone <repository-url>
cd src/plexichat-client
go mod download
go build -o plexichat-client
```

### Install Dependencies
```bash
go mod tidy
```

## Configuration

The client uses a YAML configuration file located at `~/.plexichat-client.yaml`. You can also specify a custom config file with the `--config` flag.

### Example Configuration
```yaml
url: "http://localhost:8000"
token: "your-jwt-token"
refresh_token: "your-refresh-token"
username: "your-username"
user_id: 123
timeout: "30s"
retries: 3
concurrent_requests: 10
```

## Usage

### Basic Commands

#### Check Server Health
```bash
./plexichat-client health
```

#### Get Version Information
```bash
./plexichat-client version
```

### Authentication

#### Login
```bash
./plexichat-client auth login --username admin --password secret
# Or prompt for credentials
./plexichat-client auth login
```

#### Register New Account
```bash
./plexichat-client auth register --username newuser --email user@example.com --type user
```

#### Check Current User
```bash
./plexichat-client auth whoami
```

#### Logout
```bash
./plexichat-client auth logout
```

### Chat Operations

#### Send a Message
```bash
./plexichat-client chat send --message "Hello, World!" --room 1
```

#### Listen to Real-time Chat
```bash
# Listen to specific room
./plexichat-client chat listen --room 1

# Listen to all rooms
./plexichat-client chat listen --all
```

#### Get Chat History
```bash
./plexichat-client chat history --room 1 --limit 50 --page 1
```

#### List Chat Rooms
```bash
./plexichat-client chat rooms
```

### File Operations

#### Upload File
```bash
./plexichat-client files upload --file document.pdf
```

#### List Files
```bash
./plexichat-client files list
```

#### Download File
```bash
./plexichat-client files download --id 123 --output downloaded-file.pdf
```

### Admin Operations

#### List Users
```bash
./plexichat-client admin users list
```

#### Get System Statistics
```bash
./plexichat-client admin stats
```

#### Configure Rate Limiting
```bash
./plexichat-client admin config rate-limit --requests-per-minute 100 --burst-limit 200
```

#### Manage Security Settings
```bash
./plexichat-client admin config security --max-login-attempts 5 --lockout-duration 15m
```

### Security Testing

#### Run Comprehensive Security Test
```bash
./plexichat-client security test --endpoint /api/v1/auth/login --full-scan
```

#### Test Specific Vulnerability
```bash
./plexichat-client security test --endpoint /api/v1/users --type sql_injection
```

#### Generate Security Report
```bash
./plexichat-client security report --format html --output security-report.html
```

### Performance Testing

#### Run Performance Benchmark
```bash
./plexichat-client benchmark --endpoint /api/v1/status --duration 60s --concurrent 10
```

#### Test API Response Times
```bash
./plexichat-client benchmark --endpoint /api/v1/messages --requests-per-sec 100 --duration 30s
```

#### Microsecond Performance Test
```bash
./plexichat-client benchmark --endpoint /api/v1/health --microsecond-test --samples 1000
```

## Advanced Features

### WebSocket Support
The client supports real-time communication via WebSocket connections for:
- Live chat messaging
- Real-time notifications
- System status updates
- Performance monitoring

### Concurrent Operations
- Parallel file uploads/downloads
- Concurrent API requests
- Load testing with multiple virtual users
- Batch operations

### Security Features
- Automatic token refresh
- Secure credential storage
- TLS/SSL support
- Rate limiting compliance
- Input validation and sanitization

### Performance Optimization
- Connection pooling
- Request batching
- Caching mechanisms
- Efficient JSON parsing
- Memory optimization

## Error Handling

The client provides comprehensive error handling with:
- Detailed error messages
- HTTP status code interpretation
- Retry mechanisms with exponential backoff
- Graceful degradation
- Verbose logging options

## Examples

### Automated Bot Workflow
```bash
# Register bot account
./plexichat-client auth register --username chatbot --email bot@example.com --type bot

# Login as bot
./plexichat-client auth login --username chatbot

# Send automated messages
./plexichat-client chat send --message "Bot is online!" --room 1

# Listen for commands
./plexichat-client chat listen --room 1
```

### Security Assessment
```bash
# Run full security scan
./plexichat-client security test --full-scan --output security-results.json

# Test authentication endpoints
./plexichat-client security test --endpoint /api/v1/auth/login --type brute_force

# Validate security headers
./plexichat-client security test --type security_headers
```

### Performance Monitoring
```bash
# Continuous performance monitoring
./plexichat-client benchmark --endpoint /api/v1/status --duration 300s --concurrent 5

# Load testing
./plexichat-client benchmark --endpoint /api/v1/messages --concurrent 50 --duration 120s

# Response time validation
./plexichat-client benchmark --endpoint /api/v1/health --target-response-time 1ms
```

## Contributing

This client is designed to be a comprehensive reference implementation showcasing all PlexiChat features. It demonstrates:

- Modern Go development practices
- CLI application architecture
- Real-time communication patterns
- Security testing methodologies
- Performance benchmarking techniques
- Error handling and resilience

## License

This client is part of the PlexiChat project and follows the same licensing terms.
