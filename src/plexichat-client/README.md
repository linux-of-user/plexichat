# PlexiChat Go Client

A comprehensive, feature-rich command-line client for PlexiChat written in Go. This client provides access to all PlexiChat features including real-time messaging, file management, admin operations, security testing, and performance benchmarking.

## Features

### 🔐 Authentication & User Management
- User login/logout with token management
- User registration (including bot accounts)
- Profile management and user information
- Secure token storage and automatic refresh

### 💬 Real-time Chat
- Send messages to chat rooms
- Real-time message listening via WebSocket
- Chat history retrieval with pagination
- Room management and discovery
- Multi-room support

### 📁 File Management
- File upload with progress tracking
- File download and management
- Bulk file operations
- File metadata and permissions

### 👑 Admin Operations
- User management (list, create, modify, delete)
- System statistics and monitoring
- Configuration management
- Rate limiting configuration
- Security settings management

### 🛡️ Security Testing
- Comprehensive penetration testing
- Vulnerability scanning
- Security assessment reports
- Attack vector testing (SQL injection, XSS, etc.)
- Security configuration validation

### ⚡ Performance Testing
- API response time benchmarking
- Load testing with concurrent users
- Throughput measurement
- Performance regression testing
- Microsecond-level performance validation

### 🤖 Bot Account Support
- Special bot account registration
- Higher rate limits for bots
- Automated messaging capabilities
- Bot-specific API endpoints

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
