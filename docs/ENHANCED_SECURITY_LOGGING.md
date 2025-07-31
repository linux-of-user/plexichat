# Enhanced Security and Logging System

This document describes the enhanced security and logging systems implemented in PlexiChat, providing comprehensive endpoint protection and detailed monitoring capabilities.

## Overview

The enhanced security and logging system provides:

- **Comprehensive Endpoint Security**: Rate limiting, input validation, threat detection, and access control
- **Advanced Logging**: Structured JSON logging with contextual information and performance metrics
- **Security Monitoring**: Real-time threat detection and security event tracking
- **Audit Trails**: Complete audit logging for compliance and security analysis
- **Performance Monitoring**: Detailed performance metrics and tracking

## Enhanced Security System

### Security Levels

The system defines several security levels for endpoints:

```python
class SecurityLevel(Enum):
    PUBLIC = 0          # No authentication required
    BASIC = 1           # Basic authentication required
    AUTHENTICATED = 2   # Valid user session required
    ELEVATED = 3        # Enhanced privileges required
    ADMIN = 4           # Admin access required
    SYSTEM = 5          # System-level access required
```

### Security Features

#### 1. Rate Limiting

Advanced rate limiting with adaptive controls:

```python
# Default rate limits
rate_limit_rules = {
    "default": RateLimitRule(60, 1000, 10),  # 60/min, 1000/hour, burst 10
    "/api/v1/auth/login": RateLimitRule(10, 100, 3),
    "/api/v1/files/upload": RateLimitRule(20, 200, 5),
}
```

#### 2. Input Validation

Comprehensive input validation against common attacks:

- SQL injection detection
- XSS prevention
- Path traversal protection
- Command injection detection
- File size and type validation

#### 3. Threat Detection

Real-time threat analysis including:

- IP reputation checking
- User behavior analysis
- Request pattern anomaly detection
- Geolocation-based anomaly detection

#### 4. Security Headers

Automatic security headers added to all responses:

```python
security_headers = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'...",
}
```

## Enhanced Logging System

### Log Levels

Extended log levels for comprehensive logging:

```python
class LogLevel(Enum):
    TRACE = 5
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50
    SECURITY = 60      # Security-related events
    AUDIT = 70         # Audit trail events
    PERFORMANCE = 80   # Performance monitoring
```

### Log Categories

Organized logging by category:

```python
class LogCategory(Enum):
    SYSTEM = "system"
    SECURITY = "security"
    PERFORMANCE = "performance"
    API = "api"
    DATABASE = "database"
    AUTH = "auth"
    AUDIT = "audit"
    # ... more categories
```

### Structured Logging

All logs are structured with contextual information:

```json
{
    "timestamp": "2024-01-15T10:30:45.123Z",
    "level": "INFO",
    "category": "api",
    "message": "GET /api/v1/users -> 200",
    "module": "user_router",
    "function": "get_users",
    "context": {
        "request_id": "req_1234567890",
        "user_id": "user_123",
        "ip_address": "192.168.1.100",
        "endpoint": "/api/v1/users",
        "method": "GET"
    },
    "performance": {
        "duration_ms": 45.2,
        "database_queries": 2,
        "cache_hits": 1
    },
    "metadata": {
        "status_code": 200,
        "response_size": 1024
    },
    "tags": ["api_request", "success"]
}
```

## Security Decorators

The system provides powerful decorators for endpoint security:

### Basic Authentication

```python
@require_auth(SecurityLevel.AUTHENTICATED)
async def get_user_profile(request: Request, current_user: Dict = None):
    return {"profile": current_user}
```

### Admin Access

```python
@require_admin(permissions=[RequiredPermission.ADMIN])
async def admin_action(request: Request, current_user: Dict = None):
    return {"status": "admin action completed"}
```

### Rate Limiting

```python
@rate_limit(requests_per_minute=30, burst=5)
async def upload_file(request: Request):
    return {"status": "file uploaded"}
```

### Input Validation

```python
@validate_input(
    max_size=10*1024*1024,  # 10MB
    allowed_content_types=["application/json"],
    validate_json=True
)
async def create_resource(request: Request, data: ResourceData):
    return {"status": "resource created"}
```

### Audit Logging

```python
@audit_access(
    action="delete_user",
    resource_type="user",
    include_request_body=True
)
async def delete_user(request: Request, user_id: str):
    return {"status": "user deleted"}
```

### Comprehensive Security

```python
@secure_endpoint(
    auth_level=SecurityLevel.ELEVATED,
    permissions=[RequiredPermission.WRITE],
    rate_limit_rpm=20,
    audit_action="create_resource",
    validate_input_size=1024*1024  # 1MB
)
async def secure_create(request: Request, data: ResourceData, current_user: Dict = None):
    return {"status": "securely created"}
```

## Performance Tracking

### Manual Performance Tracking

```python
from plexichat.core.logging_advanced import PerformanceTracker

async def complex_operation():
    with PerformanceTracker("complex_operation", logger) as tracker:
        tracker.add_metadata(operation_type="data_processing")
        
        # Your operation here
        result = await process_data()
        
        return result
```

### Decorator-based Performance Tracking

```python
@track_performance("database_query")
async def fetch_user_data(user_id: str):
    # Database operation
    return user_data
```

## Middleware Integration

The enhanced security middleware is automatically integrated:

```python
# In main.py
security_config = {
    "enabled": True,
    "log_all_requests": True,
    "block_suspicious_requests": True
}
setup_security_middleware(app, security_config)
```

## Configuration

### Security Configuration

```python
# Security settings
SECURITY_CONFIG = {
    "enabled": True,
    "rate_limiting": {
        "enabled": True,
        "default_rpm": 60,
        "burst_limit": 10
    },
    "input_validation": {
        "enabled": True,
        "max_request_size": 10 * 1024 * 1024,  # 10MB
        "block_suspicious": True
    },
    "threat_detection": {
        "enabled": True,
        "threat_threshold": 0.7,
        "block_high_threats": True
    }
}
```

### Logging Configuration

```python
# Logging settings
LOGGING_CONFIG = {
    "level": "INFO",
    "structured_logging": True,
    "buffer_size": 50000,
    "file_rotation": {
        "max_size": "100MB",
        "backup_count": 10,
        "compress": True
    },
    "performance_tracking": True,
    "security_logging": True
}
```

## Monitoring and Metrics

### Security Metrics

The system provides comprehensive security metrics:

```python
# Get security metrics (admin endpoint)
@router.get("/admin/security-metrics")
@admin_endpoint()
async def get_security_metrics():
    return {
        "total_requests": 1000,
        "blocked_requests": 25,
        "threat_detections": 10,
        "rate_limit_violations": 15,
        "security_events": {...},
        "threat_levels": {...}
    }
```

### Performance Metrics

Performance tracking provides detailed insights:

```python
# Performance statistics
{
    "operation": "database_query",
    "count": 1000,
    "avg_duration": 23.5,
    "min_duration": 5.2,
    "max_duration": 156.7,
    "p95": 87.3,
    "p99": 134.8
}
```

### Log Analysis

The system supports advanced log analysis:

```python
# Search logs
logs = logging_system.search_logs(
    query="authentication failed",
    level=LogLevel.WARNING,
    category=LogCategory.SECURITY,
    start_time=datetime.now() - timedelta(hours=24),
    limit=100
)

# Export logs
json_export = logging_system.export_logs(
    start_time=start_time,
    end_time=end_time,
    format='json'
)
```

## Best Practices

### 1. Endpoint Security

- Always use appropriate security levels for endpoints
- Implement rate limiting for all public endpoints
- Validate all input data
- Use audit logging for sensitive operations

### 2. Logging

- Use structured logging with contextual information
- Include performance metrics for monitoring
- Tag logs appropriately for easy searching
- Set appropriate log levels

### 3. Error Handling

- Log security events appropriately
- Don't expose sensitive information in error responses
- Implement proper error recovery mechanisms

### 4. Performance

- Use performance tracking for critical operations
- Monitor and alert on performance degradation
- Implement caching where appropriate

## Example Implementation

See `enhanced_secure_example.py` for a complete example showing:

- Public endpoints with rate limiting
- Authenticated endpoints with security validation
- Admin endpoints with elevated permissions
- System endpoints with maximum security
- Performance monitoring and metrics
- Comprehensive audit logging

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure all dependencies are installed
2. **Middleware Not Loading**: Check middleware order in main.py
3. **Rate Limiting Too Strict**: Adjust rate limit rules
4. **Performance Overhead**: Configure logging levels appropriately

### Debug Mode

Enable debug mode for detailed logging:

```python
LOGGING_CONFIG = {
    "level": "DEBUG",
    "debug_mode": True,
    "verbose_security_logging": True
}
```

This enhanced security and logging system provides enterprise-grade protection and monitoring capabilities for PlexiChat, ensuring secure operations while maintaining comprehensive visibility into system behavior.