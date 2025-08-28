# PlexiChat Security Guide

PlexiChat implements government-level security with quantum-resistant encryption, zero-trust architecture, and comprehensive threat protection. This guide covers all security features, best practices, configuration options, implementation details for the built-in Web Application Firewall (WAF), standardized error handling, monitoring capabilities, and operational threat response procedures.

## Table of Contents

1. [Security Overview](#security-overview)
2. [Quantum-Resistant Encryption](#quantum-resistant-encryption)
3. [Authentication & Authorization](#authentication--authorization)
4. [Network Security](#network-security)
   - [Web Application Firewall (WAF)](#web-application-firewall-waf)
   - [WAF Implementation Details](#waf-implementation-details)
   - [WAF Rules & Examples](#waf-rules--examples)
   - [WAF Deployment Modes & Tuning](#waf-deployment-modes--tuning)
5. [Data Protection](#data-protection)
6. [Threat Detection](#threat-detection)
7. [Compliance & Auditing](#compliance--auditing)
8. [Error Handling & Standardized Error Codes](#error-handling--standardized-error-codes)
9. [Security Configuration](#security-configuration)
10. [Best Practices](#best-practices)
11. [Security Monitoring](#security-monitoring)
    - [Integration with Logging & SIEM](#integration-with-logging--siem)
    - [Alerting & Playbooks](#alerting--playbooks)
    - [Automated API Documentation for Security Endpoints](#automated-api-documentation-for-security-endpoints)
12. [Threat Response Procedures](#threat-response-procedures)

## Security Overview

PlexiChat's security architecture follows a **defense-in-depth** strategy with multiple layers of protection:

```
┌─────────────────────────────────────────────────────────────┐
│                    Physical Security                        │
├─────────────────────────────────────────────────────────────┤
│                    Network Security                         │
│  WAF │ DDoS Protection │ Rate Limiting │ Intrusion Detection│
├─────────────────────────────────────────────────────────────┤
│                  Application Security                       │
│  Input Validation │ CSRF Protection │ XSS Prevention       │
├─────────────────────────────────────────────────────────────┤
│                    Data Security                            │
│  E2E Encryption │ Database Encryption │ Key Management      │
├─────────────────────────────────────────────────────────────┤
│                   Identity Security                         │
│  MFA │ Biometrics │ Zero-Trust │ Behavioral Analysis        │
└─────────────────────────────────────────────────────────────┘
```

### Security Principles

1. **Zero Trust**: Never trust, always verify
2. **Least Privilege**: Minimum necessary access
3. **Defense in Depth**: Multiple security layers
4. **Quantum Resistance**: Future-proof cryptography
5. **Continuous Monitoring**: Real-time threat detection
6. **Privacy by Design**: Built-in privacy protection

## Quantum-Resistant Encryption

(unchanged; see original content for algorithms, E2E encryption flow, and key management configuration examples)

## Authentication & Authorization

(unchanged; see original content for MFA, RBAC, OAuth/OIDC examples and configs)

## Network Security

### Web Application Firewall (WAF)

PlexiChat includes a built-in WAF middleware designed to be deployed as the first application-layer defense. The WAF focuses on blocking, rate-limiting, and sanitizing malicious traffic while providing observability for security operations.

Protection Features
- SQL Injection detection and mitigation
- Cross-Site Scripting (XSS) detection and sanitization
- CSRF prevention through token validation and same-site cookies
- Path traversal prevention and strict path normalization
- Payload size validation and file-type enforcement
- IP reputation checks and geofencing (Geo-blocking)
- Rate limiting integration and burst control
- Threat intelligence feed integration (IP/TTP feeds)
- Context-aware anomaly detection (behavioral heuristics)
- Audit logging and structured security events

High-level WAF configuration (example)
```yaml
waf:
  enabled: true
  mode: "blocking"         # "blocking" | "monitor" | "sanitize"
  ip_reputation:
    enabled: true
    block_threshold_score: 80
    allow_list: []
    deny_list: []
  rules:
    sql_injection:
      enabled: true
      action: "block"
      log: true
    xss_protection:
      enabled: true
      action: "sanitize"
      log: true
    payload_limits:
      max_body_bytes: 1048576    # 1 MB default
      max_file_size_bytes: 52428800  # 50 MB for uploads
    rate_limiting:
      enabled: true
      requests_per_minute: 120
      burst_limit: 20
      client_identifier: "ip"    # ip | api_key | user_id
```

Note: For complete, versioned rule sets, operational examples, and rule lifecycle guidance see the WAF Rules document: [WAF Rules](WAF_RULES.md).

### WAF Implementation Details

This section describes the internal behavior and recommended operational settings for PlexiChat's WAF middleware.

Core components
- Request pre-processor: Normalizes paths, decodes percent-encoding, enforces UTF-8, and strips null bytes to prevent bypasses.
- Signature engine: Uses curated regex signatures and OWASP Core Rule Set (CRS)-like rules for common exploits (SQLi, XSS, LFI/RFI).
- Heuristics engine: Monitors frequency, payload entropy, input shapes, and unusual header patterns to detect anomalies not matched by signatures.
- Reputation & threat intelligence: Enriches IPs and indicators with external reputation feeds and local allow/deny lists.
- Response actions: block (return 403/429), sanitize (strip/escape inputs), or monitor (log only for tuning).
- Logging & telemetry: Structured security events (JSON) are emitted to the unified logging system and optionally forwarded to a SIEM.
- Rate limiting adapter: Integrates with the rate limit store (in-memory, Redis) to correctly apply quotas across distributed deployments.

Attack surface controls
- Strict input validation: Enforce schema-based validation for all API endpoints (recommended).
- Body size limits: Deny requests larger than configured max_body_bytes before parsing.
- Upload restrictions: Enforce allowed MIME types and scanning on uploads.
- Header validation: Reject suspicious or malformed headers; normalize header capitalization to reduce ambiguity.

Performance considerations
- Signature matching optimized with compiled regex and a fast-path for benign requests.
- CPU-expensive checks (deep regex, ML scoring) are only performed when heuristics indicate abnormality.
- Caching of IP reputation lookups to reduce external calls.

Integration points
- First middleware: Deploy WAF as first layer in the middleware chain to observe raw client requests. The WAF middleware implementation lives in the source tree at src/plexichat/core/security/waf_middleware.py — refer to that implementation for configuration primitives and extension points.
- Unified logging: Emit events via setup_logging/get_logger for audit and SIEM ingestion.
- Error handling: Map WAF actions to standardized error codes (see Error Handling section) and provide clear request IDs for incident correlation.

### WAF Rules & Examples

Examples of actionable WAF rules, ready for configuration:

Block classic SQLi patterns (signature example)
```yaml
waf.rules.sql_injection:
  - id: sqli-001
    description: "Basic SQL injection pattern detection (UNION/SELECT/--)"
    pattern: "(\\b(select|union|insert|update|delete)\\b.*\\b(from|into|where)\\b|--|;|/\\*|\\*/)"
    flags: ["i"]
    action: block
    score: 80
```

XSS sanitization example
```yaml
waf.rules.xss:
  - id: xss-001
    description: "Inline script tags and event handlers"
    pattern: "<(script|img|iframe)[\\s>]|on\\w+\\s*=\\s*['\\\"]"
    action: sanitize
    sanitize_strategy: "strip_tags_and_escape"
```

IP reputation example
```yaml
waf.ip_reputation:
  feeds:
    - name: "internal_blocklist"
      type: "local"
      source: [ "203.0.113.10", "198.51.100.0/24" ]
    - name: "realtime_threat_feed"
      type: "remote"
      url: "https://threat-feed.example/v1/list"
      refresh_interval_minutes: 15
  block_threshold_score: 85
```

Rate limiting example
```yaml
waf.rate_limiting:
  - name: "global_api_limit"
    identifier: "ip"
    requests: 100
    window_seconds: 60
    burst: 20
    action: "throttle"
```

Custom rule example (path traversal)
```yaml
waf.rules.path_traversal:
  - id: pt-001
    pattern: "(\\.{2}/|/\\.{2})"
    action: block
    log: true
```

For the canonical, version-controlled rule catalog, testing guidance, and rule ID references see: [WAF Rules](WAF_RULES.md).

### WAF Deployment Modes & Tuning

Deployment modes
- Monitor mode: WAF logs events without blocking. Use during tuning to identify false positives.
- Blocking mode: Active enforcement; blocks deliveries that exceed configured thresholds.
- Sanitize mode: Cleans or escapes detected payloads before application processing.

Tuning guidance
1. Start in monitor mode for a minimum of 7 days in production to build baseline behavior.
2. Enable logging and review top offenders before switching to "block".
3. Gradually enable blocking for specific rule sets (e.g., enable SQLi blocking first).
4. Maintain an allow-list for internal service IPs and trusted CDNs.
5. Use rate-limiting metrics to define realistic thresholds for traffic patterns and business workflows.
6. Provide an incident override mechanism and a "panic button" to toggle WAF behavior during incidents.

False positives handling
- Create a feedback loop where blocked requests are reviewed and rules adjusted.
- Attach request IDs to logs and provide Secure Channels (email/SIEM ticket) for developers to report false positives with request context.
- Rule exceptions should be time-boxed and recorded in the change management system.

## Data Protection

(unchanged; see original content for database & file encryption, backup security features)

## Threat Detection

(unchanged; behavioral analysis, intrusion detection, vulnerability management sections retained and extended by later monitoring content)

## Compliance & Auditing

(unchanged; supported standards and audit logging details remain relevant)

## Error Handling & Standardized Error Codes

PlexiChat adopts a centralized error code system to ensure consistent client behavior and observable telemetry. All errors emitted by core services and middleware (including WAF) should use standardized error codes with HTTP status mappings and structured messages.

Error code structure
- Category prefix (AUTH, VALIDATION, SECURITY, SYSTEM, WAF, BACKUP)
- Unique numeric code per error
- Machine-readable key and human-friendly message
- Suggested remediation and severity

Example error code definitions (YAML)
```yaml
error_codes:
  - code: "SEC-1001"
    http_status: 403
    key: "waf_blocked_request"
    message: "Request blocked by WAF rule"
    severity: "high"
    details_required: true
  - code: "AUTH-2001"
    http_status: 401
    key: "auth_mfa_required"
    message: "Multi-factor authentication required"
    severity: "medium"
  - code: "VALID-3001"
    http_status: 400
    key: "validation_payload_too_large"
    message: "Payload exceeds allowed size"
    severity: "low"
```

Recommended API error response shape
```json
{
  "error": {
    "code": "SEC-1001",
    "http_status": 403,
    "message": "Request blocked by WAF rule",
    "request_id": "req_1234567890",
    "timestamp": "2025-08-27T12:00:00Z",
    "details": {
      "rule_id": "sqli-001",
      "rule_name": "SQL Injection Basic Pattern",
      "client_ip": "198.51.100.23"
    }
  }
}
```

Guidelines
- Include a request_id for every error for cross-system correlation.
- Avoid leaking sensitive information in error messages (no stack traces or secrets).
- Map WAF and security events to severity levels for alerting thresholds.
- Emit errors to unified logging with structured fields for SIEM ingestion.

Error codes, their mappings to HTTP status codes, and the suggested remediation steps are used by incident responders and reflected in the Incident Response runbooks. See the Incident Response guide for standardized triage, escalation, and post-incident workflows: [Incident Response](INCIDENT_RESPONSE.md). The runbooks in that document reference the error code categories described here and include sample queries for locating related logs and request_ids.

## Security Configuration

### Environment Variables

(unchanged variable list; expanded examples below)

Expanded environment-driven WAF and error handling configuration
```bash
# Core security settings
PLEXICHAT_SECURITY_ENCRYPTION_KEY=your-256-bit-encryption-key
PLEXICHAT_SECURITY_JWT_SECRET=your-jwt-secret-key

# WAF and security middleware
PLEXICHAT_WAF_ENABLED=true
PLEXICHAT_WAF_MODE=blocking           # monitor | blocking | sanitize
PLEXICHAT_WAF_MAX_BODY_BYTES=1048576  # 1MB
PLEXICHAT_WAF_RATE_LIMIT_RPM=120
PLEXICHAT_WAF_REPUTATION_FEED_URL=https://threat-feed.example/v1/list

# Error handling
PLEXICHAT_ERROR_CODES_PATH=/etc/plexichat/error_codes.yaml
PLEXICHAT_REQUEST_ID_HEADER=X-Request-ID

# Logging & monitoring
PLEXICHAT_LOG_LEVEL=info
PLEXICHAT_SIEM_ENDPOINT=https://siem.example/ingest
```

### Security Headers

(unchanged; strong security headers examples included)

## Best Practices

(keep original best practices with additional WAF and error-handling-specific practices below)

Additional best practices related to WAF and error handling
- Validate inputs with strict JSON/schema validators (e.g., JSON Schema, pydantic) rather than relying on WAF for business validation.
- Keep WAF rules in version control and apply change-review processes.
- Rotate threat intelligence feeds and monitor feed health and false positive rates.
- Use well-defined error codes so operators can tune alerts and playbooks by code severity.
- Protect logging pipelines: ensure logs are tamper-evident and use signed/immutable storage for critical audit trails.

## Security Monitoring

PlexiChat supports multi-layered monitoring of security signals and integrates with logging, alerting, and SIEM solutions.

### Real-time Monitoring

(unchanged list of monitored metrics; expand to include WAF-specific monitoring)

WAF-specific monitored metrics
- Number of blocked requests per rule and per time window
- Rate limiting triggers and throttle counts
- Top offending IPs and request paths
- Reputation feed hits and enrichment latency
- False positive reports and exemption rates

### Integration with Logging & SIEM

PlexiChat's unified logging system should be configured to emit structured security events. Events include fields such as request_id, user_id (if available), client_ip, rule_id, rule_name, action (block/sanitize/monitor), severity, and raw request context (with sensitive fields redacted).

Structured event example
```json
{
  "timestamp": "2025-08-27T12:00:00Z",
  "component": "waf.middleware",
  "level": "warning",
  "event": {
    "type": "waf.block",
    "code": "SEC-1001",
    "request_id": "req_1234567890",
    "client_ip": "198.51.100.23",
    "rule_id": "sqli-001",
    "rule_name": "SQL Injection Basic Pattern",
    "path": "/api/message/send",
    "method": "POST",
    "user_id": null
  }
}
```

SIEM integration
- Forward structured logs to SIEM (Splunk/ELK/QRadar) for advanced correlation and long-term retention.
- Tag events with environment and deployment metadata for multi-tenant visibility.
- Use SIEM to define detection rules (e.g., repeated WAF blocks from single IP across multiple endpoints) and trigger orchestration workflows.

### Alerting & Playbooks

(unchanged alert channels; add playbook examples below)

Sample alerting playbook for WAF blocks
- Severity: High — >100 unique blocked requests from an IP within 10 minutes
  - Notify: Email + SMS + SIEM webhook
  - Action: Auto-block IP at edge/ACL for 60 minutes; escalate to security ops
- Severity: Medium — 20-100 blocks in 10 minutes
  - Notify: Email + SIEM webhook
  - Action: Throttle and monitor; create ticket for review
- Severity: Low — single or sporadic blocks
  - Notify: SIEM (for trend analysis)
  - Action: Log and monitor

### Automated API Documentation for Security Endpoints

PlexiChat uses automated API documentation generation to ensure the API reference is up-to-date for developers and security operators. Key points:

- The FastAPI application exposes interactive documentation at the runtime endpoints /docs (Swagger UI) and /redoc (ReDoc). These can be used during development and testing to review security-related endpoints (authentication, token management, rate-limit controls, WAF tuning endpoints, etc.).
- For documentation builds and CI, the OpenAPI schema is exported and persisted as JSON. The generated schema location used by the documentation pipeline is docs/_generated/openapi.json (this is produced by a utility script in scripts/dump_openapi.py in the repository root).
- When updating security-related endpoints or error code schemas, regenerate the OpenAPI schema (e.g., run scripts/dump_openapi.py) and rebuild the docs so that the API reference and security pages reflect the current runtime behavior.
- The canonical API reference (developer-facing) is at [API Reference](API.md) in the docs directory. Automated builds (mkdocs + openapi plugins) pick up docs/_generated/openapi.json to render endpoint details.
- For security reviewers: ensure WAF-related endpoints, admin controls, and error code responses are documented in the OpenAPI schema and validated by CI gates prior to merging changes.

## Threat Response Procedures

PlexiChat maintains documented procedures for triage and response to security incidents. These runbooks are intended for incident responders and on-call engineers.

Initial triage checklist
1. Identify and record request_id(s) and correlated log entries.
2. Classify alert severity using standardized error code severity mapping.
3. Capture a snapshot of affected systems (logs, metrics, process lists).
4. If active attack (DDoS or credential stuffing), activate network-level mitigations (IP block, rate-limit at CDN).
5. If data exposure suspected, isolate affected service and preserve forensic artifacts.

Runbook: Responding to WAF-suspected SQL Injection
1. Determine extent:
   - Query logs for rule_id and request_ids.
   - Identify user_ids and client IPs.
2. Contain:
   - If high severity, block offending IPs at the edge and revoke any session tokens if session abuse detected.
3. Investigate:
   - Analyze application logs, database slow queries, and error traces.
   - Check for unusual DB query patterns or unexpected data exfiltration.
4. Eradicate:
   - Patch the exploited endpoint (input validation, parameterized queries).
   - Apply additional WAF rules to block the payload variants.
5. Recover:
   - Restore integrity of affected data from verified backups if necessary.
   - Rotate credentials/keys if compromise is suspected.
6. Post-incident:
   - Update rules and signatures to capture variants.
   - Update playbooks and notify stakeholders.
   - Perform a retrospective and apply lessons learned.

Runbook: Handling False Positives
1. Triage using request_id to inspect raw request and WAF rule match context.
2. If false positive, create a scoped exception (with expiration) or tune the rule pattern.
3. Re-run the request in a safe staging environment with debug logging enabled.
4. Record the exception in change control and track metrics to avoid regression.

Forensic preservation
- Preserve logs, request bodies, and database transaction logs in immutable storage for the investigation timeframe.
- Export SIEM correlation searches and snapshots that indicate attack chronology.

Communication & escalation
- Notify security stakeholders according to severity.
- For data breaches, follow legal and compliance requirements for disclosure (e.g., GDPR notification timelines).
- Maintain a centralized incident ticket with timeline, actions taken, and artifacts.

---

PlexiChat's comprehensive security framework provides enterprise-grade protection suitable for the most demanding security requirements. Regular security assessments, code reviews, rule tuning, and updates to threat intelligence feeds ensure continued protection against evolving threats.

If you are operationalizing PlexiChat in production, follow deployment checklists:
- Start WAF in monitor mode and tune rules before switching to blocking.
- Configure unified logging and SIEM forwarding prior to enabling automated blocking.
- Define and test incident response playbooks and communication channels.
- Keep error codes and runbooks up-to-date in version control and accessible to on-call teams.

For detailed configuration templates, rule sets, and playbooks, see the docs directory:
- WAF Rules: [WAF Rules](WAF_RULES.md)
- Backup System: [Backup System](BACKUP_SYSTEM.md)
- Incident Response: [Incident Response](INCIDENT_RESPONSE.md)
- API Reference (automated): [API Reference](API.md) — the generated OpenAPI schema used by the docs pipeline is located at docs/_generated/openapi.json (regenerate with scripts/dump_openapi.py).