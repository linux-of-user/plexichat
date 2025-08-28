# API Reference (Rendered) — Extended Manual

This document supplements the generated OpenAPI schema located at `_generated/openapi.json` and provides expanded, human-readable guidance for the new and enhanced PlexiChat APIs: clustering, backup management, enhanced security (including quantum-ready encryption), client settings, plugin management, and voice/video calling.

If the generated OpenAPI schema is out of date, regenerate it with:

```
python scripts/dump_openapi.py
```

The generated schema lives in `docs/_generated/openapi.json`. This page documents semantics, security considerations, examples, and operational guidance beyond the raw OpenAPI file.

---

Table of Contents

- Overview
- Authentication & Scopes
- Global Headers & Response Codes
- Rate Limiting & DDoS Protections
- Clustering APIs
  - Node Registration & Lifecycle
  - Topology & Metrics
  - Failover & Config Sync
- Backup Management APIs
  - Create / Restore / List / Verify
  - Scheduling & Retention
  - Encryption and Sharded Storage
- Enhanced Security APIs
  - DDoS Management & Events
  - Audit Logs & Security Events
  - Key Management & Quantum-Ready Encryption
- Client Settings APIs
  - CRUD, Bulk Update, Image Storage
  - Validation & Quotas
- Plugin Management APIs
  - Install / Uninstall / Enable / Disable
  - Permission Requests & Admin Approval
  - Sandboxing Configuration & Security Status
- Voice & Video (Calling) APIs
  - Signaling, WebSocket Endpoints, STUN/TURN, Recording
- Security Considerations & Best Practices
- Examples (curl / wscat)
- Error Codes & Meaning
- Appendix: Important Paths & Files

---

Overview

The PlexiChat API suite is organized around clear responsibilities:

- Clustering APIs manage node registration, health, topology and failover.
- Backup APIs manage backups, verification, scheduling and distributed shard storage.
- Security APIs provide DDoS controls, audit events, key and encryption management (including post-quantum techniques).
- Client Settings APIs are user-scoped and store profile/client UI settings and images.
- Plugin APIs provide lifecycle and security controls for third-party plugins, including permission approval workflows and sandbox management.
- Voice/Video APIs provide real-time signaling and management for WebRTC sessions, including STUN/TURN configuration and optional encrypted recording.

Most endpoints require an authenticated bearer token. Administrative operations require admin-scoped tokens and are rate-limited more strictly unless whitelisted.

---

Authentication & Scopes

All protected endpoints use bearer token authentication via the Authorization header:

- Header: Authorization: Bearer <token>
- Tokens must be issued by the PlexiChat auth service and include necessary scopes.

Common scopes:
- profile — Read/update own profile and client settings.
- cluster — Node registration and cluster operations (node tokens).
- cluster.admin — Admin-only cluster operations (failover, topology changes).
- backups — Create/list backups (service accounts may use this).
- backups.admin — Admin privileges for backup restore and retention changes.
- security.admin — Configure DDoS, rotate keys, access audit logs.
- plugins.manage — Install/uninstall plugins and view their status (per-user).
- plugins.admin — Approve plugin permission requests and change sandbox policies.
- calls — Initiate/receive calls and manage call resources (user-level).
- calls.admin — Admin operations for global call policies and recordings.

Token types:
- User token — regular user token, limited to user-scoped resources (client-settings, initiating plugin installs limited by policy).
- Admin token — platform administrator token, full access to management endpoints (requires stricter issuance procedures).
- Node token — short-lived token for cluster nodes to register and heartbeat; scoped to cluster endpoints.
- Service account token — tokens used by internal services (backup engine, plugin registry) with scoped privileges and rotation policies.

Authentication examples and best practices:
- Use short-lived tokens for nodes and long-lived refreshable tokens for admin UI only when necessary.
- Node tokens should be rotated regularly via the key management endpoints.
- Audit and limit token creation; restrict admin tokens to a minimal set of operator accounts.

---

Global Headers & Response Codes

Common headers:
- Authorization: Bearer <token>
- X-Request-ID: Optional client-generated UUID for tracing
- Accept: application/json
- Content-Type: application/json

Common response codes and semantics:
- 200 OK — Successful read actions
- 201 Created — Resource creation succeeded
- 202 Accepted — Action accepted for async processing (backup start, restore)
- 204 No Content — Successful deletion
- 400 Bad Request — Validation error or malformed payload
- 401 Unauthorized — Missing or invalid token
- 403 Forbidden — Insufficient scope, admin privileges, or resource-level denial
- 404 Not Found — Resource missing
- 409 Conflict — Resource conflict (duplicate node id, backup id collision)
- 413 Payload Too Large — Uploaded object exceeds allowed size or quota
- 422 Unprocessable Entity — Semantically invalid (e.g., invalid SDP offer)
- 429 Too Many Requests — Rate limiting or DDoS mitigation
- 500 Internal Server Error — Server errors or unexpected exceptions
- 503 Service Unavailable — Critical subsystem unavailable (e.g., key vault, DB maintenance)

Error responses commonly include:
- code — short error code string (e.g., "quota_exceeded", "invalid_token")
- detail — human-readable description
- request_id — echo of X-Request-ID if provided
- info — optional object with remediation steps

---

Rate Limiting & DDoS Protections

PlexiChat employs a dynamic, system-resource-aware rate limiting and DDoS protection stack. It adapts to CPU, memory, and network load while allowing per-user-tier adjustments.

Tiered baseline limits (configurable via config manager):
- Anonymous / unauthenticated: 10 req/min per IP for public endpoints
- Authenticated user: 60 req/min
- Premium/trusted user: 600 req/min
- Admin: 120 req/min (configurable, lower for destructive ops)
- Node tokens: heartbeat endpoints get a higher allowance (configurable)

Dynamic behavior:
- When system load (CPU or memory) exceeds configured thresholds (e.g., 80% CPU), the middleware lowers global limits to protect stability.
- Suspicious IPs or request patterns cause temporary throttles or blacklists; these are visible in /security/events.
- Redis-backed counters support distributed rate limiting across cluster nodes; fallback to in-memory when Redis is unavailable (with appropriate warning).

Integration with DDoS system:
- The DDoS subsystem can enforce global drops, IP blocks, and automated countermeasures.
- Rate-limiter exposes metrics (allowed/blocked counts) for monitoring.

Operational notes:
- Clients should honor Retry-After header on 429 responses.
- Use idempotency keys for retrying mutating endpoints to avoid accidental duplication.

---

Clustering APIs

Purpose: Manage cluster nodes, topology, health monitoring and failover.

Base path: /cluster

1) Register Node
- Method: POST
- Path: /cluster/nodes
- Auth: Bearer token with cluster or node scope
- Payload:
  {
    "node_id": "string",
    "address": "ip:port",
    "type": "general|networking|endpoint",
    "capabilities": ["cache","backup_storage","webrtc"],
    "metadata": { ... }
  }
- Response: 201 Created { "node_id": "...", "registered_at": "ISO8601" }
- Rate limit: node tokens have higher allowance; user tokens limited.
- Notes: Node must present a valid node token. Node registration triggers cluster-wide config sync if enabled.

2) Heartbeat / Update Node
- Method: PUT
- Path: /cluster/nodes/{node_id}/heartbeat
- Auth: Node token
- Payload:
  {
    "uptime_seconds": 12345,
    "metrics": { "cpu_pct": 12.3, "mem_mb": 512 },
    "status": "healthy"
  }
- Response: 200 OK { "status": "ok", "next_heartbeat_ms": 30000 }
- Rate limit: high frequency allowed but with resource-aware throttles.

3) Get Nodes / Topology
- Method: GET
- Path: /cluster/nodes
- Auth: cluster or cluster.admin scope
- Response: 200 OK array of nodes with status and last_heartbeat
- Use: Topology dashboard. Values include role, load_score, metrics.

4) Get Node Details
- Method: GET
- Path: /cluster/nodes/{node_id}
- Auth: cluster.admin
- Response: 200 with ClusterNode object
- Security: Node metadata may contain sensitive keys (do not expose unless admin).

5) Failover Test
- Method: POST
- Path: /cluster/failover/test
- Auth: cluster.admin
- Payload: { "target_node": "node_id", "simulate": true }
- Response: 202 Accepted { "task_id": "..." }
- Notes: Triggers a simulated failover and returns a task to poll.

6) Metrics / Health Dashboard
- Method: GET
- Path: /cluster/metrics
- Auth: cluster.admin
- Query params: timeframe, node_id
- Response: aggregated cluster health metrics (latency, errors, memory, CPU).

7) Config Sync
- Method: POST
- Path: /cluster/config/sync
- Auth: cluster.admin
- Payload: { "config_hash": "sha256", "changes": {...} }
- Response: 202 Accepted
- Notes: Cluster manager coordinates rolling config deployments.

Security & Notes:
- Node authentication uses node tokens; mutual TLS is supported for higher security.
- Nodes should not self-promote to admin; all admin operations require explicit admin scope.
- All node registration and heartbeats are audited and visible in security events.

---

Backup Management APIs

Purpose: Manage backups with encryption, distributed shard storage and recovery.

Base path: /backups

1) Create Backup
- Method: POST
- Path: /backups/create
- Auth: backups or backups.admin
- Payload:
  {
    "type": "full|incremental",
    "include": ["db", "attachments"],
    "encryption": { "algorithm": "PQ-Kyber-AES-hybrid", "key_rotation": "auto" },
    "destination": { "type": "distributed", "replication": 3 }
  }
- Response: 202 Accepted { "backup_id": "...", "status": "started" }
- Notes: Backups are async. Encryption performed prior to shard distribution.

2) List Backups
- Method: GET
- Path: /backups
- Auth: backups or backups.admin
- Response: 200 list of backups with metadata and verification status

3) Get Backup Metadata
- Method: GET
- Path: /backups/{backup_id}
- Auth: backups or backups.admin

4) Verify Backup Integrity
- Method: POST
- Path: /backups/{backup_id}/verify
- Auth: backups.admin
- Response: verification report (checksums match, shard status)

5) Restore Backup
- Method: POST
- Path: /backups/{backup_id}/restore
- Auth: backups.admin
- Payload:
  {
    "target_node_id": "node_id (optional)",
    "restore_options": { "overwrite": false, "merge": true }
  }
- Response: 202 Accepted { "task_id": "..." }

6) Delete Backup
- Method: DELETE
- Path: /backups/{backup_id}
- Auth: backups.admin
- Response: 204 No Content

7) Schedule Backup
- Method: POST
- Path: /backups/schedule
- Auth: backups.admin

Encryption & Shard Storage:
- Uses hybrid PQ KEMs combined with symmetric bulk encryption.
- Key material is referenced via key IDs in the key vault; rotations are supported with historical wrapped keys for recovery.
- Shards distributed across cluster nodes with replication policies to avoid SPOFs.

---

Enhanced Security APIs

Purpose: Manage DDoS settings, view events, rotate keys and manage quantum-ready encryption features.

Base path: /security

1) Get DDoS Configuration
- Method: GET
- Path: /security/ddos
- Auth: security.admin
- Response: configuration object with thresholds, tiers, and behavior

2) Update DDoS Configuration
- Method: PUT
- Path: /security/ddos
- Auth: security.admin
- Payload:
  {
    "enabled": true,
    "thresholds": { "requests_per_minute": 10000 },
    "auto_block_duration_minutes": 60,
    "aggressive_mode": false
  }

3) Block IP / Unblock IP
- Method: POST
- Path: /security/ddos/block
- Auth: security.admin
- Payload: { "ip": "1.2.3.4", "reason": "suspicious" }

4) Get Security Events / Audit Logs
- Method: GET
- Path: /security/events
- Auth: security.admin
- Query: start, end, severity, type
- Response: paginated events (login failures, unusual traffic spikes, plugin permission approvals)

5) Key Management & Rotation
- Method: GET / POST / DELETE
- Path: /security/keys
- Auth: security.admin
- Endpoints:
  - GET /security/keys — list key IDs and metadata
  - POST /security/keys/rotate — rotate a key (support for scheduled rotation)
  - GET /security/keys/{key_id} — key metadata
- Notes: Keys are never returned in plaintext. Use key IDs for encryption references. Rotation follows the policy in the configuration.

6) Quantum-Ready Encryption Status
- Method: GET
- Path: /security/quantum/status
- Auth: security.admin
- Response: which components are using PQ algorithms and last rotation times.

Security Considerations:
- Only admin tokens with security.admin scope may change DDoS or key configuration.
- Changes are audited. Key rotation produces events in the security event log.
- Prefer hybrid PQ+classical algorithms to retain compatibility while improving resilience.

---

Client Settings APIs

These are user-scoped settings used by clients such as UI preferences, avatars, theme choices, and other per-user configuration.

Base path: /client-settings

1) Get all settings
- Method: GET
- Path: /client-settings/
- Auth: user token (profile scope)
- Response: 200 list of settings:
  [
    { "setting_key": "theme", "setting_value": "dark", "updated_at": "..." },
    ...
  ]

2) Get specific setting
- Method: GET
- Path: /client-settings/{setting_key}
- Auth: user token
- Response: 200 { setting_key, setting_value, updated_at } or 404

3) Set or update a setting
- Method: PUT
- Path: /client-settings/{setting_key}
- Auth: user token
- Payload: { "setting_key": "theme", "setting_value": "light" }
- Response: 200 with stored value
- Validation: Keys validated against allowed patterns; known keys enforced with schemas (e.g., theme, language, notifications.*).

4) Delete a setting
- Method: DELETE
- Path: /client-settings/{setting_key}
- Auth: user token
- Response: 200 or 404 if not found

5) Bulk update settings
- Method: POST
- Path: /client-settings/bulk-update
- Auth: user token
- Payload: { "settings": { "theme": "dark", "language": "en-US" } }
- Response: updated_count summary and per-key errors if any
- Constraints: Server-side limits on number of items per bulk request and schema validation per key.

6) Upload image (avatar or image-based setting)
- Method: POST
- Path: /client-settings/images/{setting_key}
- Auth: user token
- Body: multipart/form-data with file (UploadFile)
- Response: 201 with image metadata (internal path, content-type, size and hash)
- Constraints: Quota per user enforced; maximum file size enforced by unified config; allowed MIME types configured.
- Security: Uploaded images are virus-scanned (if scanning engine available) and sanitized. Filenames and paths are safe and stored under per-user directories.

7) Serve image (secure)
- Method: GET
- Path: /client-settings/images/{setting_key}
- Auth: user token
- Response: File stream with proper content-type
- Access control: Only the owning user (or an authorized share endpoint) can access stored images.

Validation & Quotas:
- Each user has configurable storage limits for images and settings. Exceeding storage returns a clear error:
  - 413 Payload Too Large (single file exceeds configured MAX_IMAGE_SIZE)
  - 403 Forbidden (quota_exceeded) when aggregate storage would be exceeded
- Audit trail logging for create/update/delete actions is available and should be used for debugging and compliance.

Repository / Implementation pointers:
- API implementation reference: src/plexichat/interfaces/api/v1/client_settings.py
- Backend service for client settings: src/plexichat/infrastructure/services/client_settings_service.py

---

Plugin Management APIs

Purpose: Manage plugin lifecycle and plugin security permissions. Plugins run in sandboxed environments and must request permissions for elevated capabilities. Plugins may be installed from registries or uploaded packages.

Base path: /plugins

1) List plugins
- Method: GET
- Path: /plugins
- Auth: plugins.manage (for user's plugins) or plugins.admin for global listing
- Response: list of installed plugins with: plugin_id, name, version, enabled, sandbox_status, requested_permissions, approved_permissions, last_audit

2) Install plugin
- Method: POST
- Path: /plugins/install
- Auth: plugins.manage
- Payload:
  {
    "source": "url_or_registry",
    "version": "1.2.3",
    "requested_permissions": ["filesystem_read","network_outbound"]
  }
- Response: 202 Accepted { "plugin_id": "..." }
- Notes: Installing a plugin triggers:
  - package fetch and integrity checks,
  - static policy/security assessment,
  - creation of an initial permission request record.
- Plugins requesting high-risk capabilities (filesystem, subprocess, raw sockets, or broad admin scopes) are installed into a disabled state pending admin review.

3) Enable plugin
- Method: POST
- Path: /plugins/{plugin_id}/enable
- Auth:
  - If plugin only requested low-risk permissions: plugins.manage may enable for own scope.
  - If plugin requested admin-only permissions: plugins.admin required.
- Response: 200
- Notes: Enabling enforces sandbox config and starts plugin runtime in isolated environment.

4) Disable plugin
- Method: POST
- Path: /plugins/{plugin_id}/disable
- Auth: plugins.manage or plugins.admin
- Response: 200
- Notes: Graceful unload with state snapshot if supported.

5) Uninstall plugin
- Method: DELETE
- Path: /plugins/{plugin_id}
- Auth: plugins.manage / plugins.admin
- Response: 204 No Content
- Notes: Triggers cleanup (filesystem, DB entries) and audit entries.

6) Get plugin permissions and status
- Method: GET
- Path: /plugins/{plugin_id}/permissions
- Auth: plugins.manage or plugins.admin
- Response: requested permissions, approved permissions, sandbox status, audit trail

7) Approve plugin permission request
- Method: POST
- Path: /plugins/{plugin_id}/permissions/approve
- Auth: plugins.admin
- Payload: { "approved_permissions": ["filesystem_read"], "granted_until": "ISO8601 optional", "note": "reason" }
- Response: 200
- Notes: Admins may grant temporary permissions; approvals create audit entries and can be revoked.

8) Sandbox configuration
- Method: POST
- Path: /plugins/{plugin_id}/sandbox/config
- Auth: plugins.admin
- Payload:
  {
    "cpu_limit_percent": 20,
    "memory_limit_mb": 256,
    "allowed_modules": ["json","math"],
    "allow_network": false,
    "allow_filesystem": false
  }
- Response: 200
- Notes: Sandbox settings control builtins, whitelisted modules, and are enforced by the plugin runtime.

9) Plugin logs & audit
- Method: GET
- Path: /plugins/{plugin_id}/audit
- Auth: plugins.admin / plugin owner
- Response: list of plugin actions, permission requests, and sandbox violations.

Security & Audit:
- All permission approvals, denials, and sandbox config changes are logged.
- Plugin code executes in a restricted interpreter that filters builtins and modules; network and filesystem access is brokered and audited when permitted.
- Admin UI exposes pending permission requests and includes warnings and risk descriptions.

Suggested Workflow:
- Developer: submit plugin package requesting minimal permissions and include explicit rationale for any additional permission.
- Admin: review requested permissions, run static analysis, and selectively approve with expiration if needed.
- Operator: monitor plugin runtime metrics and revoke permissions or disable plugins on suspicious behavior.

---

Voice & Video (Calling) APIs

Purpose: Provide signaling and control APIs for real-time communication using WebRTC and optional recording and encryption features.

Base path: /calls (control) and ws(s) endpoints for signaling

Key Concepts:
- Signaling: Exchange of SDP offers/answers and ICE candidates via WebSocket or REST when required.
- STUN/TURN: Servers configured and provided to clients to ensure connectivity behind NATs.
- Recording: Optional encrypted call recording stored via the backup engine or object storage.
- Presence: Call presence (online/offline/in-call) propagated via WebSocket.

1) Initiate Call (control)
- Method: POST
- Path: /calls/initiate
- Auth: calls scope (user token)
- Payload:
  {
    "to_user_id": "user-123",
    "media": { "audio": true, "video": true, "data": false },
    "preferred_codecs": ["opus", "vp8"]
  }
- Response: 202 Accepted { "call_id": "..." }
- Notes: Server creates call record and notifies callee via presence or push notification. Actual SDP exchange is performed over WebSocket for real-time flow.

2) Signaling WebSocket
- Endpoint: wss://api.plexichat.local/calls/ws
- Auth: initial HTTP upgrade with Authorization header (Bearer <token>) and a short-lived signaling token may be issued.
- Messages:
  - "join": { "call_id": "...", "role": "offerer|answerer" }
  - "sdp:offer": { "sdp": "..." }
  - "sdp:answer": { "sdp": "..." }
  - "ice:candidate": { "candidate": "..." }
  - "hangup": { "reason": "..." }
  - "control": e.g., "mute", "hold"
- Notes: Server validates SDP for malformed content and enforces rate limits on signaling messages.

3) STUN/TURN Configuration
- Method: GET
- Path: /calls/ice-config
- Auth: calls scope
- Response: STUN/TURN servers list with creds and TTL
- Notes: TURN credentials are short-lived and bound to the calling session. Health checks and automatic failover are supported.

4) Recording Control
- Method: POST
- Path: /calls/{call_id}/record
- Auth: calls.admin or calls scope depending on policy
- Payload: { "enable": true, "encryption_key_id": "keyId", "store": "backup|object_storage" }
- Response: 202 Accepted { "task_id": "..." }
- Notes: Recordings are encrypted (optionally with PQ-wrapped keys) and stored securely. Access to recordings requires admin or explicit permission.

5) Presence & Status
- Method: GET
- Path: /calls/presence/{user_id}
- Auth: calls scope
- Response: { "user_id": "...", "status": "online|offline|busy", "last_seen": "..." }

6) Call Metrics
- Method: GET
- Path: /calls/{call_id}/metrics
- Auth: calls.admin or call owner
- Response: metrics for packet loss, jitter, bitrate adaptation, codec negotiation.

Security & Quality:
- SDP and media flows should be validated to avoid injection or resource exhaustion.
- Use end-to-end application-layer encryption for extra privacy when required.
- Adaptive bitrate and codec negotiation is supported: server can suggest codec fallbacks based on device capability and network conditions.
- Rate-limit call initiation per user to prevent abuse.
- For enterprise deployments, enable post-quantum DTLS/SRTP hybrids if supported by client stacks.

Implementation notes:
- The signaling WebSocket requires proper authentication and authorization checks: ensure the token used has the calls scope and the user is permitted to join the call.
- Use STUN/TURN credentials issued per-session to avoid credential reuse abuse.

---

Security Considerations & Best Practices

- Principle of least privilege: tokens and plugin permission grants should be narrowly scoped and time-limited.
- Use admin accounts sparingly. Admin operations are audited and rate-limited more strictly.
- Rotate keys regularly; use the /security/keys endpoints. Key rotation for node tokens and backup keys is recommended.
- Monitor DDoS events and configure thresholds suitable for your deployment. Enable auto-block only if you have a robust false-positive mitigation plan.
- For plugin development: request only the permissions you need; prefer brokered services (microservice APIs) over granting direct filesystem or network access to plugins.
- For backups: ensure key vault access is secured and that you test restore procedures regularly.
- For clustering: ensure mutual TLS between nodes when operating across untrusted networks.
- For voice/video: validate SDP offers and apply size limits on signaling messages. Limit frequency of offer/answer exchanges per call session.

---

Examples (curl / wscat)

1) Register a node (node token)
```
curl -X POST "https://api.plexichat.local/cluster/nodes" \
  -H "Authorization: Bearer NODE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "node_id": "node-01",
    "address": "10.10.0.5:8000",
    "type": "networking",
    "capabilities": ["cache","webrtc"],
    "metadata": {"zone": "us-east-1a"}
  }'
```

2) Start a backup (admin)
```
curl -X POST "https://api.plexichat.local/backups/create" \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "incremental",
    "include": ["db", "attachments"],
    "encryption": {"algorithm": "PQ-Kyber-AES-hybrid"},
    "destination": {"type": "distributed", "replication": 3}
  }'
```

3) Install a plugin (user)
```
curl -X POST "https://api.plexichat.local/plugins/install" \
  -H "Authorization: Bearer USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "https://plugins.example.com/myplugin-1.0.0.zip",
    "version": "1.0.0",
    "requested_permissions": ["network_outbound", "filesystem_read"]
  }'
```

4) Approve plugin permission (admin)
```
curl -X POST "https://api.plexichat.local/plugins/plugin-123/permissions/approve" \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"approved_permissions":["network_outbound"], "granted_until":"2025-12-31T23:59:59Z", "note":"Temporary external API access"}'
```

5) Upload client image (user) with curl (multipart)
```
curl -X POST "https://api.plexichat.local/client-settings/images/avatar" \
  -H "Authorization: Bearer USER_TOKEN" \
  -F "file=@/path/to/avatar.png;type=image/png"
```

6) Bulk update client settings
```
curl -X POST "https://api.plexichat.local/client-settings/bulk-update" \
  -H "Authorization: Bearer USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"settings": {"theme": "dark", "language": "en-US", "notifications.enabled": true}}'
```

7) WebSocket signaling example (wscat)
- Connect:
  wscat -c "wss://api.plexichat.local/calls/ws" -H "Authorization: Bearer USER_TOKEN"
- Join a call:
  {"type":"join","call_id":"call-123","role":"offerer"}
- Send offer:
  {"type":"sdp:offer","sdp":"v=0\r\n..."}

Operational notes:
- For large file uploads prefer chunked or resumable upload endpoints if provided by your deployment.
- Inspect the response body for code and request_id to aid in troubleshooting support tickets.

---

Error Codes & Meaning

Generic HTTP errors are augmented by structured error objects. Typical error response JSON:

{
  "code": "quota_exceeded",
  "detail": "User storage quota exceeded",
  "request_id": "uuid",
  "info": {"quota_bytes": 52428800, "current_usage": 55000000}
}

Common error codes and descriptions:
- invalid_token — Token missing or invalid (401). Remedy: obtain a new token.
- insufficient_scope — Token lacks required scope (403). Remedy: request proper scope.
- quota_exceeded — Operation would exceed user quota (403 or 413). Remedy: free up space or request quota increase.
- too_many_requests — Rate-limited (429). See Retry-After header.
- plugin_pending_approval — Plugin installed but requires admin permission (409 or 202). Remedy: contact admin or await auto-approval.
- invalid_payload — Schema validation failed (400). Remedy: correct payload per OpenAPI.
- sdp_invalid — Failed SDP validation (422). Remedy: verify offer/answer content.
- virus_detected — Uploaded file failed virus scan (400). Remedy: use a clean file or contact admin.
- service_unavailable — Critical subsystem down (503). Remedy: retry later and check status page.
- backup_in_progress — Resource busy with backup/restore operation (409 or 202). Remedy: poll task status or wait.

Auditing & troubleshooting:
- Always include X-Request-ID header to correlate logs.
- For 500/503, include request_id when filing support tickets.
- Admin endpoints often return additional info indicating which subsystem failed (e.g., "key_vault_unreachable").

---

Appendix: Important Paths & Files

- Generated OpenAPI schema: docs/_generated/openapi.json
- Client Settings API implementation reference:
  - src/plexichat/interfaces/api/v1/client_settings.py
- Plugin API access rules and guidance:
  - docs/PLUGIN_API_ACCESS.md
- Plugin runtime and sandbox manager:
  - src/plexichat/core/plugins/manager.py
  - src/plexichat/core/plugins/security_manager.py
- Key Vault and security implementation:
  - src/plexichat/core/security/key_vault.py
  - src/plexichat/core/security/security_manager.py
- Cluster API router reference:
  - src/plexichat/interfaces/web/routers/cluster.py
- Backup engine reference:
  - src/plexichat/features/backup/backup_engine.py
- Rate limiter middleware:
  - src/plexichat/core/middleware/rate_limiter.py

---

Changelog & Versioning Notes

This extended reference documents new and enhanced endpoints introduced in the recent platform update. Refer to the OpenAPI JSON for exact request/response schemas. Use this document for operational context, examples, security guidance, and best practices.

If you notice missing endpoints in the generated OpenAPI schema, run the schema dump script and regenerate your docs:

```
python scripts/dump_openapi.py
```

For questions about operational configuration (clustering, DDoS thresholds, key rotation policy), consult the configuration manager definitions in `src/plexichat/core/config_manager.py` or the legacy `src/plexichat/core/unified_config.py` if present in older deployments.

---

End of API Reference (Extended)