# PlexiChat WAF Rules Documentation

This document provides comprehensive documentation for PlexiChat's Web Application Firewall (WAF) rules, configuration options, and operational procedures. The WAF is implemented as middleware in `src/plexichat/core/security/waf_middleware.py` and provides multi-layered protection against common web application attacks.

## Table of Contents

1. [Overview](#overview)
2. [Rule Categories](#rule-categories)
3. [Rule Configuration](#rule-configuration)
4. [SQL Injection Rules](#sql-injection-rules)
5. [XSS Protection Rules](#xss-protection-rules)
6. [Command Injection Rules](#command-injection-rules)
7. [Path Traversal Rules](#path-traversal-rules)
8. [LDAP Injection Rules](#ldap-injection-rules)
9. [XXE Protection Rules](#xxe-protection-rules)
10. [SSRF Protection Rules](#ssrf-protection-rules)
11. [IP Reputation Rules](#ip-reputation-rules)
12. [Rate Limiting Rules](#rate-limiting-rules)
13. [Payload Validation Rules](#payload-validation-rules)
14. [Header Validation Rules](#header-validation-rules)
15. [Custom Rule Development](#custom-rule-development)
16. [Rule ID Reference](#rule-id-reference)
17. [Severity Classifications](#severity-classifications)
18. [Action Types](#action-types)
19. [Deployment Modes](#deployment-modes)
20. [Troubleshooting](#troubleshooting)
21. [Performance Considerations](#performance-considerations)
22. [Maintenance Procedures](#maintenance-procedures)

## Overview

PlexiChat's WAF provides comprehensive protection against web application attacks through pattern-based detection, behavioral analysis, and threat intelligence integration. The WAF operates as FastAPI middleware and can be configured for different deployment scenarios.

### Key Features

- **Real-time Protection**: Analyzes requests in real-time before they reach the application
- **Pattern Matching**: Uses regex patterns to detect known attack signatures
- **IP Reputation**: Integrates with threat intelligence feeds for IP-based blocking
- **Rate Limiting**: Prevents abuse through configurable rate limiting
- **Learning Mode**: Allows tuning without blocking legitimate traffic
- **Comprehensive Logging**: Provides detailed audit trails for security analysis

### Architecture Integration

The WAF middleware integrates with PlexiChat's security architecture as the first line of defense:

```
Internet → CDN/Load Balancer → WAF Middleware → Application Logic
```

## Rule Categories

The WAF organizes rules into the following categories:

| Category | Purpose | Rule Count | Default Action |
|----------|---------|------------|----------------|
| SQL Injection | Detect SQL injection attempts | 7 | BLOCK |
| XSS Protection | Prevent cross-site scripting | 10 | SANITIZE |
| Command Injection | Block command execution attempts | 4 | BLOCK |
| Path Traversal | Prevent directory traversal | 4 | BLOCK |
| LDAP Injection | Detect LDAP injection | 2 | BLOCK |
| XXE Protection | Prevent XML external entity attacks | 3 | BLOCK |
| SSRF Protection | Block server-side request forgery | 3 | BLOCK |
| IP Reputation | Block malicious IPs | Dynamic | BLOCK |
| Rate Limiting | Prevent abuse | 1 | THROTTLE |
| Payload Validation | Enforce size limits | 1 | BLOCK |
| Header Validation | Detect suspicious headers | 5 | MONITOR |

## Rule Configuration

### Basic Configuration

WAF rules are configured through the `WAFConfig` class:

```python
from plexichat.core.security.waf_middleware import WAFConfig, WAFMiddleware

config = WAFConfig(
    enabled=True,
    max_payload_size=10 * 1024 * 1024,  # 10MB
    ip_reputation_enabled=True,
    ip_reputation_threshold=50,
    rate_limiting_enabled=True,
    rate_limit_requests=100,
    rate_limit_window=60,
    block_malicious_ips=True,
    log_all_requests=False,
    enable_learning_mode=False
)
```

### Environment-Based Configuration

```bash
# Core WAF settings
PLEXICHAT_WAF_ENABLED=true
PLEXICHAT_WAF_MODE=blocking
PLEXICHAT_WAF_MAX_PAYLOAD_SIZE=10485760
PLEXICHAT_WAF_LEARNING_MODE=false

# IP Reputation
PLEXICHAT_WAF_IP_REPUTATION_ENABLED=true
PLEXICHAT_WAF_IP_REPUTATION_THRESHOLD=50
PLEXICHAT_WAF_THREAT_INTEL_API_KEY=your_api_key

# Rate Limiting
PLEXICHAT_WAF_RATE_LIMITING_ENABLED=true
PLEXICHAT_WAF_RATE_LIMIT_REQUESTS=100
PLEXICHAT_WAF_RATE_LIMIT_WINDOW=60

# Logging
PLEXICHAT_WAF_LOG_ALL_REQUESTS=false
```

## SQL Injection Rules

SQL injection rules detect attempts to manipulate database queries through user input.

### Rule Patterns

| Rule ID | Pattern | Description | Confidence |
|---------|---------|-------------|------------|
| SQLI-001 | `(?i)(union\s+select\|select\s+\*\s+from\|drop\s+table\|delete\s+from)` | Basic SQL keywords | 90% |
| SQLI-002 | `(?i)(insert\s+into\|update\s+\w+\s+set\|alter\s+table)` | Data manipulation | 90% |
| SQLI-003 | `(?i)(\'\s*or\s*\'\s*=\s*\'\|\'\s*or\s*1\s*=\s*1)` | Boolean-based injection | 95% |
| SQLI-004 | `(?i)(--\|\#\|\/\*\|\*\/)` | SQL comments | 80% |
| SQLI-005 | `(?i)(exec\s*\(\|sp_\|xp_)` | Stored procedures | 85% |
| SQLI-006 | `(?i)(information_schema\|sysobjects\|syscolumns)` | Schema enumeration | 90% |
| SQLI-007 | `(?i)(load_file\|into\s+outfile\|into\s+dumpfile)` | File operations | 95% |

### Example Detections

```sql
-- SQLI-001: Union-based injection
' UNION SELECT username, password FROM users--

-- SQLI-003: Boolean-based injection
admin' OR '1'='1

-- SQLI-006: Schema enumeration
' AND 1=1 UNION SELECT table_name FROM information_schema.tables--
```

### Configuration Example

```python
sql_injection_config = {
    "enabled": True,
    "action": "block",
    "log_level": "high",
    "confidence_threshold": 0.8,
    "custom_patterns": [
        r"(?i)(waitfor\s+delay|benchmark\s*\()",  # Time-based injection
        r"(?i)(pg_sleep|sleep\s*\()"              # Database-specific delays
    ]
}
```

## XSS Protection Rules

Cross-site scripting (XSS) rules detect and sanitize malicious JavaScript and HTML content.

### Rule Patterns

| Rule ID | Pattern | Description | Action |
|---------|---------|-------------|--------|
| XSS-001 | `(?i)<script[^>]*>.*?</script>` | Script tags | SANITIZE |
| XSS-002 | `(?i)<iframe[^>]*>.*?</iframe>` | Iframe tags | SANITIZE |
| XSS-003 | `(?i)on\w+\s*=\s*[\"']?[^\"'>]*[\"']?` | Event handlers | SANITIZE |
| XSS-004 | `(?i)javascript\s*:` | JavaScript URLs | SANITIZE |
| XSS-005 | `(?i)vbscript\s*:` | VBScript URLs | SANITIZE |
| XSS-006 | `(?i)data\s*:\s*text/html` | Data URLs | SANITIZE |
| XSS-007 | `(?i)<object[^>]*>.*?</object>` | Object tags | SANITIZE |
| XSS-008 | `(?i)<embed[^>]*>` | Embed tags | SANITIZE |
| XSS-009 | `(?i)<applet[^>]*>.*?</applet>` | Applet tags | SANITIZE |
| XSS-010 | `(?i)expression\s*\(` | CSS expressions | SANITIZE |

### Sanitization Strategies

1. **Tag Stripping**: Remove dangerous HTML tags entirely
2. **Attribute Filtering**: Remove dangerous attributes while preserving safe content
3. **Entity Encoding**: Convert special characters to HTML entities
4. **Content Security Policy**: Add CSP headers to prevent execution

### Example Detections

```html
<!-- XSS-001: Script injection -->
<script>alert('XSS')</script>

<!-- XSS-003: Event handler injection -->
<img src="x" onerror="alert('XSS')">

<!-- XSS-004: JavaScript URL -->
<a href="javascript:alert('XSS')">Click me</a>
```

## Command Injection Rules

Command injection rules prevent execution of system commands through user input.

### Rule Patterns

| Rule ID | Pattern | Description | Severity |
|---------|---------|-------------|----------|
| CMD-001 | `(?i)(\|\s*\w+\|\&\&\s*\w+\|\;\s*\w+)` | Command chaining | CRITICAL |
| CMD-002 | `(?i)(nc\s+-\|netcat\|wget\s+\|curl\s+)` | Network tools | HIGH |
| CMD-003 | `(?i)(bash\|sh\|cmd\|powershell\|python\|perl\|ruby)\s` | Shell interpreters | CRITICAL |
| CMD-004 | `(?i)(\`\|\$\(\|\$\{)` | Command substitution | HIGH |

### Example Detections

```bash
# CMD-001: Command chaining
; cat /etc/passwd

# CMD-003: Shell execution
bash -c "rm -rf /"

# CMD-004: Command substitution
$(whoami)
```

## Path Traversal Rules

Path traversal rules prevent access to files outside the intended directory structure.

### Rule Patterns

| Rule ID | Pattern | Description | Examples |
|---------|---------|-------------|----------|
| PT-001 | `(?i)(\.\.\/\|\.\.\\)` | Directory traversal | `../../../etc/passwd` |
| PT-002 | `(?i)(%2e%2e%2f\|%2e%2e%5c)` | URL-encoded traversal | `%2e%2e%2f%2e%2e%2f` |
| PT-003 | `(?i)(\/etc\/passwd\|\/etc\/shadow\|\/windows\/system32)` | Sensitive files | `/etc/passwd` |
| PT-004 | `(?i)(\.\.%2f\|\.\.%5c)` | Mixed encoding | `..%2f..%2f` |

## LDAP Injection Rules

LDAP injection rules detect attempts to manipulate LDAP queries.

### Rule Patterns

| Rule ID | Pattern | Description |
|---------|---------|-------------|
| LDAP-001 | `(?i)(\*\)\|\(\|\|\)\(\|\&\()` | LDAP operators |
| LDAP-002 | `(?i)(objectclass=\*\|cn=\*)` | Wildcard queries |

## XXE Protection Rules

XML External Entity (XXE) rules prevent XML-based attacks.

### Rule Patterns

| Rule ID | Pattern | Description |
|---------|---------|-------------|
| XXE-001 | `(?i)<!entity` | Entity declarations |
| XXE-002 | `(?i)<!doctype.*\[` | DOCTYPE declarations |
| XXE-003 | `(?i)system\s+[\"'][^\"']*[\"']` | System entities |

## SSRF Protection Rules

Server-Side Request Forgery (SSRF) rules prevent unauthorized internal requests.

### Rule Patterns

| Rule ID | Pattern | Description |
|---------|---------|-------------|
| SSRF-001 | `(?i)(localhost\|127\.0\.0\.1\|0\.0\.0\.0)` | Local addresses |
| SSRF-002 | `(?i)(169\.254\.\|192\.168\.\|10\.\|172\.(1[6-9]\|2[0-9]\|3[01])\.)` | Private networks |
| SSRF-003 | `(?i)(file://\|ftp://\|gopher://\|dict://)` | Dangerous protocols |

## IP Reputation Rules

IP reputation rules block requests from known malicious IP addresses.

### Configuration

```python
ip_reputation_config = {
    "enabled": True,
    "threshold": 50,  # 0-100 scale
    "cache_ttl": 3600,  # 1 hour
    "whitelist": ["192.168.1.0/24", "10.0.0.0/8"],
    "blacklist": ["203.0.113.0/24"],
    "threat_intel_sources": [
        {
            "name": "abuseipdb",
            "api_key": "your_api_key",
            "endpoint": "https://api.abuseipdb.com/api/v2/check"
        }
    ]
}
```

### Threat Intelligence Integration

The WAF integrates with external threat intelligence sources:

1. **AbuseIPDB**: Community-driven IP reputation database
2. **Custom Feeds**: Internal threat intelligence
3. **GeoIP**: Geographic blocking capabilities

## Rate Limiting Rules

Rate limiting prevents abuse by limiting request frequency per client.

### Configuration Options

```python
rate_limiting_config = {
    "enabled": True,
    "requests_per_window": 100,
    "window_seconds": 60,
    "burst_allowance": 20,
    "identifier": "ip",  # ip, user_id, api_key
    "storage": "memory",  # memory, redis
    "actions": {
        "warning_threshold": 80,  # % of limit
        "block_threshold": 100
    }
}
```

### Rate Limiting Strategies

1. **Fixed Window**: Simple time-based windows
2. **Sliding Window**: More accurate but resource-intensive
3. **Token Bucket**: Allows burst traffic within limits

## Payload Validation Rules

Payload validation enforces size and format restrictions.

### Size Limits

| Content Type | Default Limit | Configurable |
|--------------|---------------|--------------|
| JSON Body | 10MB | Yes |
| Form Data | 10MB | Yes |
| File Upload | 50MB | Yes |
| Query String | 8KB | Yes |
| Headers | 32KB | Yes |

### Validation Rules

```python
payload_validation = {
    "max_body_size": 10 * 1024 * 1024,
    "max_file_size": 50 * 1024 * 1024,
    "allowed_content_types": [
        "application/json",
        "application/x-www-form-urlencoded",
        "multipart/form-data"
    ],
    "file_type_validation": True,
    "virus_scanning": False  # Requires external integration
}
```

## Header Validation Rules

Header validation detects suspicious or malformed HTTP headers.

### Suspicious Headers

| Header | Risk Level | Action |
|--------|------------|--------|
| X-Forwarded-Host | Medium | Monitor |
| X-Original-URL | High | Monitor |
| X-Rewrite-URL | High | Monitor |
| X-Real-IP | Medium | Monitor |
| X-Cluster-Client-IP | Medium | Monitor |

## Custom Rule Development

### Creating Custom Rules

```python
from plexichat.core.security.waf_middleware import AttackType, ThreatLevel

class CustomRule:
    def __init__(self, rule_id: str, pattern: str, attack_type: AttackType):
        self.rule_id = rule_id
        self.pattern = re.compile(pattern, re.IGNORECASE)
        self.attack_type = attack_type
        self.threat_level = ThreatLevel.HIGH
        
    def check(self, content: str) -> bool:
        return bool(self.pattern.search(content))

# Example: Custom rule for detecting specific application attacks
custom_rule = CustomRule(
    rule_id="CUSTOM-001",
    pattern=r"(?i)(admin_backdoor|secret_function)",
    attack_type=AttackType.SUSPICIOUS_HEADERS
)
```

### Rule Testing Framework

```python
def test_rule(rule, test_cases):
    """Test a WAF rule against test cases"""
    results = []
    for case in test_cases:
        result = {
            "input": case["input"],
            "expected": case["expected"],
            "actual": rule.check(case["input"]),
            "passed": rule.check(case["input"]) == case["expected"]
        }
        results.append(result)
    return results

# Example test cases
test_cases = [
    {"input": "SELECT * FROM users", "expected": True},
    {"input": "Hello world", "expected": False},
    {"input": "' OR 1=1--", "expected": True}
]
```

## Rule ID Reference

### Complete Rule Reference Table

| Rule ID | Category | Pattern Summary | Severity | Default Action |
|---------|----------|-----------------|----------|----------------|
| SQLI-001 | SQL Injection | Basic SQL keywords | HIGH | BLOCK |
| SQLI-002 | SQL Injection | Data manipulation | HIGH | BLOCK |
| SQLI-003 | SQL Injection | Boolean injection | CRITICAL | BLOCK |
| SQLI-004 | SQL Injection | SQL comments | MEDIUM | BLOCK |
| SQLI-005 | SQL Injection | Stored procedures | HIGH | BLOCK |
| SQLI-006 | SQL Injection | Schema enumeration | HIGH | BLOCK |
| SQLI-007 | SQL Injection | File operations | CRITICAL | BLOCK |
| XSS-001 | XSS | Script tags | HIGH | SANITIZE |
| XSS-002 | XSS | Iframe tags | HIGH | SANITIZE |
| XSS-003 | XSS | Event handlers | HIGH | SANITIZE |
| XSS-004 | XSS | JavaScript URLs | HIGH | SANITIZE |
| XSS-005 | XSS | VBScript URLs | HIGH | SANITIZE |
| XSS-006 | XSS | Data URLs | MEDIUM | SANITIZE |
| XSS-007 | XSS | Object tags | HIGH | SANITIZE |
| XSS-008 | XSS | Embed tags | HIGH | SANITIZE |
| XSS-009 | XSS | Applet tags | HIGH | SANITIZE |
| XSS-010 | XSS | CSS expressions | MEDIUM | SANITIZE |
| CMD-001 | Command Injection | Command chaining | CRITICAL | BLOCK |
| CMD-002 | Command Injection | Network tools | HIGH | BLOCK |
| CMD-003 | Command Injection | Shell interpreters | CRITICAL | BLOCK |
| CMD-004 | Command Injection | Command substitution | HIGH | BLOCK |
| PT-001 | Path Traversal | Directory traversal | HIGH | BLOCK |
| PT-002 | Path Traversal | URL-encoded traversal | HIGH | BLOCK |
| PT-003 | Path Traversal | Sensitive files | CRITICAL | BLOCK |
| PT-004 | Path Traversal | Mixed encoding | HIGH | BLOCK |
| LDAP-001 | LDAP Injection | LDAP operators | HIGH | BLOCK |
| LDAP-002 | LDAP Injection | Wildcard queries | MEDIUM | BLOCK |
| XXE-001 | XXE | Entity declarations | HIGH | BLOCK |
| XXE-002 | XXE | DOCTYPE declarations | HIGH | BLOCK |
| XXE-003 | XXE | System entities | HIGH | BLOCK |
| SSRF-001 | SSRF | Local addresses | HIGH | BLOCK |
| SSRF-002 | SSRF | Private networks | HIGH | BLOCK |
| SSRF-003 | SSRF | Dangerous protocols | HIGH | BLOCK |
| IP-001 | IP Reputation | Malicious IP | HIGH | BLOCK |
| RATE-001 | Rate Limiting | Exceeded limits | MEDIUM | THROTTLE |
| SIZE-001 | Payload | Size exceeded | MEDIUM | BLOCK |
| HDR-001 | Headers | Suspicious headers | LOW | MONITOR |

## Severity Classifications

### Severity Levels

| Level | Score | Description | Response Time | Escalation |
|-------|-------|-------------|---------------|------------|
| LOW | 1-25 | Suspicious activity | 24 hours | Monitor |
| MEDIUM | 26-50 | Potential threat | 4 hours | Alert |
| HIGH | 51-75 | Active attack | 1 hour | Immediate |
| CRITICAL | 76-100 | Severe threat | 15 minutes | Emergency |

### Severity Calculation

```python
def calculate_severity(threat_detection):
    base_score = {
        AttackType.SQL_INJECTION: 80,
        AttackType.XSS: 70,
        AttackType.COMMAND_INJECTION: 90,
        AttackType.PATH_TRAVERSAL: 75,
        AttackType.MALICIOUS_IP: 60,
        AttackType.RATE_LIMIT_EXCEEDED: 40
    }
    
    confidence_multiplier = threat_detection.confidence
    repeat_offender_bonus = get_repeat_offender_score(threat_detection.client_ip)
    
    final_score = (base_score.get(threat_detection.attack_type, 50) * 
                   confidence_multiplier + repeat_offender_bonus)
    
    return min(100, final_score)
```

## Action Types

### Available Actions

| Action | Description | Use Case | Configuration |
|--------|-------------|----------|---------------|
| BLOCK | Reject request with 403 | High-confidence threats | `action: "block"` |
| SANITIZE | Clean malicious content | XSS, input validation | `action: "sanitize"` |
| MONITOR | Log but allow | Learning mode, low confidence | `action: "monitor"` |
| THROTTLE | Rate limit client | Abuse prevention | `action: "throttle"` |
| CAPTCHA | Challenge user | Suspicious behavior | `action: "captcha"` |

### Action Configuration

```python
action_config = {
    "default_action": "block",
    "learning_mode": False,
    "action_overrides": {
        "XSS": "sanitize",
        "RATE_LIMIT": "throttle",
        "SUSPICIOUS_HEADERS": "monitor"
    },
    "escalation_rules": {
        "repeat_offender_threshold": 5,
        "escalation_action": "block_ip"
    }
}
```

## Deployment Modes

### Available Modes

1. **Learning Mode**: Log all detections without blocking
2. **Monitor Mode**: Log threats, allow requests
3. **Blocking Mode**: Actively block threats
4. **Hybrid Mode**: Different actions per rule category

### Mode Configuration

```python
# Learning Mode - Tune rules without impact
config = WAFConfig(
    enabled=True,
    enable_learning_mode=True,
    log_all_requests=True
)

# Production Mode - Active protection
config = WAFConfig(
    enabled=True,
    enable_learning_mode=False,
    block_malicious_ips=True,
    rate_limiting_enabled=True
)

# Hybrid Mode - Selective enforcement
config = WAFConfig(
    enabled=True,
    rule_actions={
        "SQL_INJECTION": "block",
        "XSS": "sanitize",
        "SUSPICIOUS_HEADERS": "monitor"
    }
)
```

## Troubleshooting

### Common Issues

#### False Positives

**Symptoms**: Legitimate requests being blocked

**Diagnosis**:
```bash
# Check WAF logs for blocked requests
grep "WAF THREAT DETECTED" /var/log/plexichat/security.log

# Analyze specific request
grep "request_id:abc123" /var/log/plexichat/security.log
```

**Resolution**:
1. Review the triggering rule pattern
2. Add exception for legitimate pattern
3. Tune rule confidence threshold
4. Add IP to whitelist if appropriate

#### Performance Issues

**Symptoms**: High latency, CPU usage

**Diagnosis**:
```python
# Enable performance monitoring
config.performance_monitoring = True

# Check rule execution times
grep "rule_execution_time" /var/log/plexichat/performance.log
```

**Resolution**:
1. Optimize regex patterns
2. Reduce rule complexity
3. Implement rule caching
4. Consider rule prioritization

#### Configuration Errors

**Symptoms**: WAF not starting, configuration errors

**Diagnosis**:
```python
# Validate configuration
from plexichat.core.security.waf_middleware import validate_config

try:
    validate_config(config)
except ConfigurationError as e:
    print(f"Configuration error: {e}")
```

### Debugging Tools

#### Request Analysis

```python
def analyze_request(request_id):
    """Analyze a specific request for debugging"""
    logs = get_request_logs(request_id)
    
    analysis = {
        "request_details": logs.get("request"),
        "rules_triggered": logs.get("rules"),
        "execution_time": logs.get("timing"),
        "final_action": logs.get("action")
    }
    
    return analysis
```

#### Rule Testing

```python
def test_rule_against_request(rule_id, request_content):
    """Test a specific rule against request content"""
    rule = get_rule_by_id(rule_id)
    result = rule.check(request_content)
    
    return {
        "rule_id": rule_id,
        "content": request_content[:100],
        "matched": result,
        "confidence": rule.confidence if result else 0
    }
```

### Log Analysis

#### Security Event Logs

```json
{
  "timestamp": "2025-01-27T12:00:00Z",
  "level": "WARNING",
  "component": "waf.middleware",
  "event": {
    "type": "threat_detected",
    "request_id": "req_abc123",
    "client_ip": "203.0.113.10",
    "attack_type": "sql_injection",
    "rule_id": "SQLI-003",
    "confidence": 0.95,
    "action_taken": "block",
    "payload_preview": "' OR 1=1--"
  }
}
```

#### Performance Logs

```json
{
  "timestamp": "2025-01-27T12:00:00Z",
  "component": "waf.performance",
  "metrics": {
    "request_id": "req_abc123",
    "total_execution_time_ms": 15,
    "rules_evaluated": 25,
    "rules_matched": 1,
    "ip_reputation_time_ms": 5,
    "pattern_matching_time_ms": 8
  }
}
```

## Performance Considerations

### Optimization Strategies

1. **Rule Ordering**: Place high-confidence, fast rules first
2. **Pattern Optimization**: Use efficient regex patterns
3. **Caching**: Cache IP reputation and rule results
4. **Async Processing**: Use async operations for external calls

### Performance Metrics

| Metric | Target | Monitoring |
|--------|--------|------------|
| Request Processing Time | < 50ms | Real-time |
| Rule Evaluation Time | < 10ms | Per-rule |
| Memory Usage | < 100MB | Continuous |
| CPU Usage | < 5% | Continuous |
| False Positive Rate | < 0.1% | Daily |

### Scaling Considerations

```python
# High-traffic configuration
high_traffic_config = WAFConfig(
    enabled=True,
    max_payload_size=1024 * 1024,  # Smaller limit
    ip_reputation_enabled=True,
    cache_size=10000,  # Larger cache
    async_processing=True,
    rule_timeout_ms=5  # Faster timeout
)
```

## Maintenance Procedures

### Regular Maintenance Tasks

#### Daily Tasks
- Review security event logs
- Check false positive reports
- Monitor performance metrics
- Update threat intelligence feeds

#### Weekly Tasks
- Analyze attack trends
- Review and tune rule thresholds
- Update IP reputation databases
- Performance optimization review

#### Monthly Tasks
- Comprehensive rule effectiveness review
- Update attack patterns
- Security posture assessment
- Documentation updates

### Rule Updates

#### Adding New Rules

```python
def add_custom_rule(rule_id, pattern, attack_type, severity):
    """Add a new custom rule to the WAF"""
    new_rule = {
        "id": rule_id,
        "pattern": re.compile(pattern, re.IGNORECASE),
        "attack_type": attack_type,
        "severity": severity,
        "enabled": True,
        "action": "block"
    }
    
    # Validate rule
    validate_rule(new_rule)
    
    # Add to rule set
    custom_rules.append(new_rule)
    
    # Log change
    log_rule_change("ADD", rule_id)
```

#### Disabling Rules

```python
def disable_rule(rule_id, reason):
    """Temporarily disable a rule"""
    rule = get_rule_by_id(rule_id)
    rule.enabled = False
    rule.disabled_reason = reason
    rule.disabled_timestamp = time.time()
    
    log_rule_change("DISABLE", rule_id, reason)
```

### Backup and Recovery

#### Configuration Backup

```python
def backup_waf_config():
    """Backup WAF configuration"""
    config_data = {
        "timestamp": time.time(),
        "version": get_waf_version(),
        "rules": export_rules(),
        "settings": export_settings(),
        "whitelists": export_whitelists(),
        "blacklists": export_blacklists()
    }
    
    backup_file = f"waf_config_backup_{int(time.time())}.json"
    with open(backup_file, 'w') as f:
        json.dump(config_data, f, indent=2)
    
    return backup_file
```

#### Recovery Procedures

```python
def restore_waf_config(backup_file):
    """Restore WAF configuration from backup"""
    with open(backup_file, 'r') as f:
        config_data = json.load(f)
    
    # Validate backup
    validate_backup(config_data)
    
    # Restore configuration
    restore_rules(config_data["rules"])
    restore_settings(config_data["settings"])
    restore_lists(config_data["whitelists"], config_data["blacklists"])
    
    # Restart WAF
    restart_waf()
    
    log_config_restore(backup_file)
```

---

This comprehensive WAF rules documentation provides the foundation for secure operation of PlexiChat's Web Application Firewall. Regular review and updates of these rules ensure continued protection against evolving threats.

For additional security information, see:
- [Security Guide](SECURITY.md) - Overall security architecture
- [Incident Response](INCIDENT_RESPONSE.md) - Security incident procedures
- [API Documentation](API.md) - Security-related API endpoints

For operational support:
- Monitor WAF logs in real-time
- Set up alerting for high-severity events
- Maintain regular backup schedules
- Keep threat intelligence feeds updated