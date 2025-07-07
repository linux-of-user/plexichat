# NetLink Comprehensive Logging System

A world-class logging system with structured logging, performance monitoring, security event tracking, real-time streaming, and enterprise-grade features.

## Features

### Core Logging
- **Structured JSON Logging** - Machine-readable logs with context
- **Multi-Level Filtering** - TRACE, DEBUG, INFO, WARNING, ERROR, CRITICAL, SECURITY, AUDIT
- **Category-Based Organization** - System, Security, Performance, API, Database, etc.
- **Real-Time Log Streaming** - WebSocket-based live log viewing
- **Colorized Console Output** - Enhanced readability for development

### Performance Monitoring
- **Real-Time Metrics Collection** - CPU, memory, disk, network usage
- **Response Time Tracking** - Automatic timing of operations
- **Custom Metric Recording** - Application-specific metrics
- **Performance Alerts** - Configurable thresholds and notifications
- **Trend Analysis** - Historical performance data

### Security Logging
- **Tamper-Resistant Storage** - Cryptographic integrity verification
- **Security Event Classification** - Login attempts, access violations, etc.
- **Threat Detection** - Pattern-based suspicious activity detection
- **Audit Trail Management** - Compliance-ready audit logs
- **Zero-Knowledge Architecture** - Client-side encryption support

### Advanced Features
- **Log Compression & Rotation** - Automatic file management
- **Export Capabilities** - JSON, CSV, TXT formats
- **WebSocket Streaming** - Real-time log delivery to web clients
- **REST API** - Comprehensive log management endpoints
- **Configuration Profiles** - Development, testing, production presets
- **Third-Party Integration** - Silence noisy external libraries

## Quick Start

### Basic Usage

```python
from netlink.core.logging import get_logger, LogCategory

# Get a logger
logger = get_logger("my_module")

# Basic logging
logger.info("Application started")
logger.warning("Configuration file not found, using defaults")
logger.error("Database connection failed")

# Structured logging with context
logger.info("User login", extra={
    "category": LogCategory.SECURITY,
    "context": {
        "user_id": "user123",
        "ip_address": "192.168.1.100"
    },
    "metadata": {
        "login_method": "password",
        "success": True
    }
})
```

### Performance Monitoring

```python
from netlink.core.logging.performance_logger import timer, record_metric, time_function

# Time operations with context manager
with timer("database_query", tags={"table": "users"}):
    result = database.query("SELECT * FROM users")

# Record custom metrics
record_metric("active_users", 1250, "count")
record_metric("response_size", 2048, "bytes", tags={"endpoint": "/api/users"})

# Automatic function timing
@time_function("user_authentication")
def authenticate_user(username, password):
    # Function implementation
    pass
```

### Security Event Logging

```python
from netlink.core.logging.security_logger import get_security_logger, SecurityEvent, SecurityEventType, SecuritySeverity

security_logger = get_security_logger()

# Log security events
event = SecurityEvent(
    event_type=SecurityEventType.LOGIN_FAILURE,
    severity=SecuritySeverity.MEDIUM,
    timestamp=datetime.now(timezone.utc),
    user_id="user123",
    ip_address="192.168.1.100",
    details={"reason": "invalid_password", "attempts": 3}
)

security_logger.log_security_event(event)
```

## Configuration

### Environment Variables

```bash
# Basic settings
export NETLINK_LOG_LEVEL=INFO
export NETLINK_LOG_DIRECTORY=logs
export NETLINK_LOG_CONSOLE_ENABLED=true
export NETLINK_LOG_FILE_ENABLED=true

# Performance monitoring
export NETLINK_LOG_PERFORMANCE_ENABLED=true
export NETLINK_LOG_PERFORMANCE_INTERVAL=30

# Security logging
export NETLINK_LOG_SECURITY_ENABLED=true
export NETLINK_LOG_AUDIT_ENABLED=true

# Alerts
export NETLINK_LOG_ALERTS_ENABLED=true
export NETLINK_LOG_ALERT_EMAIL=admin@example.com
```

### Configuration File (YAML)

```yaml
# logging_config.yaml
directory: "logs"
level: "INFO"
console_enabled: true
console_colors: true
file_enabled: true
structured_enabled: true
performance_enabled: true
security_enabled: true
audit_enabled: true
alerts_enabled: true
compression_enabled: true
```

### Programmatic Configuration

```python
from netlink.core.logging.config import get_logging_config, set_logging_profile

# Use predefined profiles
set_logging_profile("development")  # Debug-friendly settings
set_logging_profile("production")   # Production-optimized settings
set_logging_profile("testing")      # Minimal logging for tests

# Get current configuration
config = get_logging_config()
print(f"Log level: {config.level}")
print(f"Log directory: {config.directory}")
```

## API Endpoints

### REST API

```bash
# Get log entries with filtering
GET /api/v2/logs/entries?level=ERROR&limit=100&search_query=database

# Get performance metrics
GET /api/v2/logs/performance/metrics?metric_names=response_time,cpu_usage

# Get security events
GET /api/v2/logs/security/events?severity=HIGH&start_time=2024-01-01T00:00:00Z

# Export logs
POST /api/v2/logs/export
{
  "format": "json",
  "level": "WARNING",
  "start_time": "2024-01-01T00:00:00Z",
  "end_time": "2024-01-31T23:59:59Z"
}

# Get logging statistics
GET /api/v2/logs/stats
```

### WebSocket Streaming

```javascript
// Connect to real-time log stream
const ws = new WebSocket('ws://localhost:8000/api/v2/logs/stream?level=INFO');

ws.onmessage = function(event) {
    const logEntry = JSON.parse(event.data);
    console.log('New log entry:', logEntry);
};

// Update filter dynamically
ws.send(JSON.stringify({
    type: 'update_filter',
    filter: {
        level: 'ERROR',
        category: 'security'
    }
}));
```

## Log Formats

### Structured JSON Format

```json
{
  "timestamp": "2024-01-15T10:30:45.123Z",
  "level": "INFO",
  "category": "api",
  "message": "User authenticated successfully",
  "module": "auth_service",
  "function": "authenticate_user",
  "line": 142,
  "context": {
    "request_id": "req_123456",
    "user_id": "user_789",
    "ip_address": "192.168.1.100"
  },
  "metadata": {
    "auth_method": "password",
    "duration_ms": 45
  },
  "performance_data": {
    "response_time": 0.045,
    "memory_usage": 128.5
  }
}
```

### Console Format

```
[2024-01-15 10:30:45] [INFO    ] auth_service: User authenticated successfully
[2024-01-15 10:30:46] [WARNING ] database: Connection pool exhausted, creating new connection
[2024-01-15 10:30:47] [ERROR   ] api_handler: Request validation failed: missing required field 'email'
```

## Performance Monitoring

### Built-in Metrics

- **System Metrics**: CPU usage, memory usage, disk I/O, network I/O
- **Application Metrics**: Response times, request counts, error rates
- **Database Metrics**: Query execution times, connection pool status
- **Custom Metrics**: Application-specific measurements

### Performance Alerts

```python
from netlink.core.logging.performance_logger import PerformanceAlert

# Configure custom alerts
alert = PerformanceAlert(
    metric_name="response_time",
    threshold=2.0,  # 2 seconds
    comparison="gt",  # greater than
    duration=60,  # sustained for 60 seconds
    callback=lambda metric: send_slack_alert(f"Slow response: {metric.value}s")
)

performance_logger.add_alert(alert)
```

## Security Features

### Tamper-Resistant Logging

- **Cryptographic Hashing**: Each log entry is cryptographically signed
- **Chain Verification**: Log entries are linked to prevent tampering
- **Integrity Checking**: Built-in verification of log file integrity

### Security Event Types

- Login/logout events
- Permission violations
- Suspicious activity detection
- Brute force attack detection
- Data access/modification tracking
- Configuration changes
- Malware detection alerts

### Compliance Support

- **Audit Trails**: Comprehensive activity logging
- **Data Retention**: Configurable retention policies
- **Export Capabilities**: Compliance-ready export formats
- **Access Controls**: Role-based log access

## Integration Examples

### Flask Integration

```python
from flask import Flask, request
from netlink.core.logging import get_logger, LogCategory

app = Flask(__name__)
logger = get_logger("flask_app")

@app.before_request
def log_request():
    logger.info("Request received", extra={
        "category": LogCategory.API,
        "context": {
            "method": request.method,
            "path": request.path,
            "ip_address": request.remote_addr
        }
    })
```

### FastAPI Integration

```python
from fastapi import FastAPI, Request
from netlink.core.logging import get_logger
from netlink.core.logging.performance_logger import timer

app = FastAPI()
logger = get_logger("fastapi_app")

@app.middleware("http")
async def logging_middleware(request: Request, call_next):
    with timer("request_processing", tags={"endpoint": request.url.path}):
        response = await call_next(request)
        
        logger.info("Request processed", extra={
            "context": {
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code
            }
        })
        
        return response
```

## Best Practices

### Development
- Use DEBUG level for detailed troubleshooting
- Enable console colors for better readability
- Use structured logging with context
- Monitor performance metrics during development

### Production
- Use INFO or WARNING level to reduce noise
- Enable file logging with rotation
- Configure alerts for critical events
- Enable security and audit logging
- Use compression and archival for storage efficiency

### Security
- Enable tamper-resistant logging for sensitive applications
- Monitor security events in real-time
- Configure appropriate retention policies
- Regularly verify log integrity
- Implement proper access controls

## Troubleshooting

### Common Issues

1. **High Memory Usage**: Reduce buffer sizes or enable compression
2. **Slow Performance**: Disable console logging in production
3. **Missing Logs**: Check file permissions and disk space
4. **Configuration Errors**: Validate configuration with built-in validation

### Debug Mode

```python
from netlink.core.logging.config import set_logging_profile

# Enable debug mode for troubleshooting
set_logging_profile("debug")
```

## Architecture

The logging system is built with a modular architecture:

- **Core Module** (`__init__.py`): Base classes and logging manager
- **Security Logger** (`security_logger.py`): Security event handling
- **Performance Logger** (`performance_logger.py`): Performance monitoring
- **Configuration** (`config.py`): Configuration management
- **API** (`log_api.py`): REST and WebSocket endpoints

This design ensures scalability, maintainability, and extensibility for enterprise applications.
