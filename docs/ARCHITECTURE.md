# PlexiChat Architecture Overview

PlexiChat is built with a modern, modular enterprise architecture designed for scalability, security, and maintainability. This document provides a comprehensive overview of the system architecture, design patterns, and component interactions. It has been updated to reflect recent consolidation of cross-cutting systems (notably logging), introduction of an application-level WAF, improvements to the backup system (1MB shard size), and the addition of a centralized error code and handling system.

## Table of Contents

1. [High-Level Architecture](#high-level-architecture)
2. [Core System Components](#core-system-components)
3. [Feature Modules](#feature-modules)
4. [Interface Layers](#interface-layers)
5. [Infrastructure Services](#infrastructure-services)
6. [Data Flow](#data-flow)
7. [Security Architecture](#security-architecture)
8. [Centralized Error Handling](#centralized-error-handling)
9. [Deployment Architecture](#deployment-architecture)
10. [Diagrams and Component Relationships](#diagrams-and-component-relationships)
11. [Documentation Generation & Developer Infrastructure](#documentation-generation--developer-infrastructure)

## High-Level Architecture

PlexiChat follows a layered, microservices-inspired architecture with clear separation of concerns. Cross-cutting concerns are consolidated into single, unified subsystems for consistency and maintainability:

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Interface Layer                              │
├─────────────────┬─────────────────┬───────────────────────────────────┤
│   Web UI        │   REST API      │   CLI Interface                   │
│   (React/Vue)   │   (FastAPI)     │   (Click/Typer)                   │
└─────────────────┴─────────────────┴───────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────────┐
│                         Feature Layer                                │
├─────────────────┬─────────────────┬───────────────────────────────────┤
│   AI Integration│   Backup System │   Clustering                      │
│   Security      │   Messaging     │   File Management                  │
└─────────────────┴─────────────────┴───────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────────┐
│                         Core System Layer                            │
├─────────────────┬─────────────────┬───────────────────────────────────┤
│   Authentication│   Database      │   Configuration                    │
│   Security      │   Logging (Unified) │ Error Codes & Handling         │
└─────────────────┴─────────────────┴───────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────────┐
│                       Infrastructure Layer                           │
├─────────────────┬─────────────────┬───────────────────────────────────┤
│   Services      │   Modules       │   Performance (Latency Optimizer)  │
│   Monitoring    │   Caching       │   Load Balancing                   │
└─────────────────┴─────────────────┴───────────────────────────────────┘
```

Notes:
- The logging subsystem has been unified into a single "logging_unified" interface providing structured logs, performance metrics, async contexts, directory management, and backwards-compatible APIs.
- A centralized error code system provides canonical error codes and mappings to HTTP responses, enabling consistent handling across modules.
- The WAF (Web Application Firewall) middleware is implemented as the first request-processing component in the API stack.

## Core System Components

### 1. Authentication System (`core_system/auth/`)

Unified Authentication Manager
- Multi-factor authentication (TOTP, hardware keys, biometrics)
- OAuth 2.0 / OpenID Connect integration
- Session management with secure tokens
- Role-based access control (RBAC)
- Device management and trust

```python
# Authentication flow
UnifiedAuthManager
├── AuthenticationProvider (base)
├── PasswordAuthProvider
├── MFAAuthProvider
├── OAuthProvider
├── BiometricProvider
└── DeviceAuthProvider
```

### 2. Security System (`core_system/security/`)

Security Manager (application-level)
- Threat detection engine and behavioral analysis
- Integration points for WAF decisions, DDoS protection, and rate limiting
- Certificate management and TLS automation
- Audit logging and SIEM integration (logs routed through the unified logger)

```python
# Security architecture
SecurityManager
├── ThreatDetectionEngine
├── RateLimitIntegration
├── WAFCoordinator
├── CertificateManager
└── SecurityMonitor
```

### 3. Database System (`core_system/database/`)

Multi-Database Support
- Database abstraction layer with SQLAlchemy (or comparable ORM)
- Support for PostgreSQL, MySQL, SQLite
- Automatic migrations and schema management
- Connection pooling and optimization
- Database encryption and backup integration

```python
# Database architecture
DatabaseManager
├── ConnectionManager
├── MigrationManager
├── EncryptionLayer
├── BackupIntegration
└── PerformanceOptimizer
```

### 4. Configuration System (`core_system/config/`)

Dynamic Configuration Management
- Environment-based configuration
- Hot-reload capabilities
- Validation and type checking
- Secrets management integration
- Configuration versioning

### 5. Logging System (`core_system/logging/`)

Unified Logging and Performance Observability
- Single source-of-truth: logging_unified provides setup_logging, get_logger, get_directory_manager, and performance logging APIs
- Structured logging (JSON-compatible)
- Centralized performance metrics (microsecond timing, aggregated metrics)
- Support for async contexts and task-scoped logging
- Directory management used by backup and other subsystems to persist logs, shards, and artifacts
- Backward-compatible re-exports to preserve existing import paths

Features:
- Log aggregation sink adapters (stdout, file, external services)
- Pluggable formatters and categorization
- Correlation IDs and request tracing
- Audit trail support for security-sensitive actions

## Feature Modules

### 1. AI Integration (`features/ai/`)

Multi-Provider AI System
- Provider abstraction layer (OpenAI, Anthropic, Google, local models)
- Intelligent content processing and analysis
- Semantic search capabilities
- Content moderation and safety
- AI-powered insights and recommendations

```python
# AI architecture
AICoordinator
├── ProviderManager
│   ├── OpenAIProvider
│   ├── AnthropicProvider
│   ├── GoogleAIProvider
│   └── LocalModelProvider
├── ContentProcessor
├── SemanticSearch
├── ContentModerator
└── InsightsEngine
```

### 2. Backup System (`features/backup/`)

Improved Distributed Backup (1MB Shards)
- Shard size standardized to 1 MB (configurable per deployment via configuration)
- ShardingManager produces 1MB shards and coordinates metadata
- EncryptionLayer ensures quantum-resistant or AES-based encryption depending on configuration
- StorageManager supports local and cloud storage with retry logic and async implementations for cloud providers (S3, GCS, Azure)
- DirectoryManager (exposed via unified logging subsystem) used for local staging and shard management
- SchedulingEngine manages incremental/differential backups and snapshotting
- RecoveryManager handles reassembly, validation, and decryption of shard sets

Key improvements:
- SHARD_SIZE default = 1 * 1024 * 1024 (1MB) but overridable via config
- All cloud store/delete functions implement retries, exponential backoff, and idempotency checks
- Async APIs standardized (store_shards_async, delete_shards_async, list_shards_async)
- Robust validation and manifesting to avoid partial restores

```python
# Backup architecture
QuantumBackupSystem
├── ShardingManager (1MB default shard)
├── EncryptionLayer
├── StorageManager (async cloud adapters with retries)
├── SchedulingEngine
└── RecoveryManager
```

### 3. Clustering System (`features/clustering/`)

Multi-Node Clustering
- Automatic node discovery and registration
- Load balancing and traffic distribution
- Health monitoring and failover
- Data synchronization across nodes
- Horizontal scaling capabilities

```python
# Clustering architecture
ClusterManager
├── NodeManager
├── LoadBalancer
├── HealthMonitor
├── SyncManager
└── ScalingController
```

### 4. Security Features (`features/security/`)

Advanced Security Features
- Web Application Firewall (WAF) implemented as middleware with:
  - IP reputation checks and allow/block lists
  - SQL injection and payload pattern detection
  - XSS detection and input sanitization hooks
  - Payload size validation and enforcement
  - Integration points for rate limiting and threat intelligence feeds
- DDoS protection and rate limiting
- Vulnerability scanning and penetration testing pipelines
- SIEM-compatible audit and telemetry export
- Bug bounty and responsible disclosure orchestration

## Interface Layers

### 1. REST API (`interfaces/api/`)

Versioned RESTful API
- API versioning with backward compatibility
- OpenAPI/Swagger documentation
- WAF runs as the first middleware for all API request processing
- Rate limiting and throttling
- Authentication and authorization
- Real-time WebSocket support

```python
# API structure
/api/v1/
├── auth/          # Authentication endpoints
├── users/         # User management
├── messages/      # Messaging functionality
├── files/         # File operations (storage/backup integration)
├── admin/         # Administrative functions
├── ai/            # AI integration endpoints
└── system/        # System management
```

### 2. Web Interface (`interfaces/web/`)

Modern Web Application
- Responsive design with mobile support
- Real-time updates with WebSockets
- Progressive Web App (PWA) capabilities
- Accessibility compliance (WCAG 2.1)
- Multi-language support

### 3. CLI Interface (`cli/`)

Command-Line Administration
- Comprehensive system management
- Batch operations and automation
- Configuration management
- Monitoring and diagnostics
- Backup and recovery operations

## Infrastructure Services

### 1. Service Management (`infrastructure/services/`)

Microservices Architecture
- Service discovery and registration
- Inter-service communication
- Circuit breaker patterns
- Service mesh integration
- Health checks and monitoring

### 2. Module System (`infrastructure/modules/`)

Plugin Architecture
- Dynamic module loading
- Secure plugin sandboxing
- Plugin marketplace integration
- Version management
- Dependency resolution

### 3. Performance Optimization (`infrastructure/performance/`)

Latency Optimizer and Performance Layer
- Request preprocessing and lightweight validation to reduce downstream load
- Response compression and efficient serialization
- Multi-layer caching (edge, CDN, Redis, in-memory)
- Database query optimization and prepared statement reuse
- Integration with unified logging for capturing latency metrics and traces

## Data Flow

### Message Processing Flow

```mermaid
graph TD
    A[Client Request] --> B[API Gateway]
    B --> WAF[WAF Middleware (first)]
    WAF --> C[Authentication]
    C --> D[Authorization]
    D --> E[Rate Limiting]
    E --> F[Message Service]
    F --> G[AI Processing]
    G --> H[Security Scan]
    H --> I[Database Storage]
    I --> J[Real-time Broadcast]
    J --> K[Client Response]
    subgraph Observability
      B --> LU[Unified Logger & Metrics]
      F --> LU
      G --> LU
      I --> LU
    end
```

Notes:
- The WAF is explicitly placed before authentication/authorization so that malicious or malformed requests can be dropped early.
- Unified logging collects telemetry from each stage for tracing and performance analysis.

### Backup Operation Flow

```mermaid
graph TD
    U[Backup Request] --> SM[ShardingManager (1MB shards)]
    SM --> EL[EncryptionLayer]
    EL --> DM[DirectoryManager (staging)]
    DM --> SMgr[StorageManager (async cloud/adapters)]
    SMgr --> Manifest[Manifest Service]
    Manifest --> RM[RecoveryManager]
    subgraph Observability
      SM --> LU[Unified Logger]
      SMgr --> LU
      RM --> LU
    end
```

### Security Processing Flow

```mermaid
graph TD
    R[Incoming Request] --> WAF[WAF Middleware]
    WAF --> DDoS[DDoS Protection & Rate Limiter]
    DDoS --> BA[Behavioral Analysis]
    BA --> TD[Threat Detection Engine]
    TD --> SA[Security Action (block/allow/challenge)]
    SA --> AL[Audit Log (Unified Logger)]
    AL --> RESP[Response]
```

## Security Architecture

### Defense in Depth

1. Network Security
   - WAF and DDoS protection implemented at application layer and integrated with upstream network-level controls
   - Network segmentation
   - VPN and secure tunnels

2. Application Security
   - Input validation and sanitization at the edge (WAF) and service boundaries
   - SQL injection prevention via parametrized queries and WAF pattern checks
   - XSS and CSRF protection via sanitization and token patterns

3. Data Security
   - End-to-end encryption (transport + application)
   - Database encryption and per-field encryption for sensitive information
   - Secure key management and rotation

4. Identity Security
   - Multi-factor authentication
   - Zero-trust principles for inter-service communication
   - Behavioral analytics for anomaly detection

### WAF Overview

The Web Application Firewall (WAF) is implemented as middleware with the following capabilities:
- IP reputation checks and dynamic allow/deny lists
- Pattern-based detection for SQLi, XSS, command injection, and common exploit payloads
- Rate limiting integration and early request rejection
- Payload size enforcement and file-type checks for uploads
- Threat intelligence feed integration to update signatures dynamically
- Logging and telemetry to the unified logging subsystem (structured events and alerts)
- Configurable policies per route or service (allowlist for internal APIs)

For rule definitions, operational guidance, rule ID references, and tuning examples, see the WAF documentation: [WAF Rules](WAF_RULES.md).

## Centralized Error Handling

To ensure consistent error semantics across the system, PlexiChat exposes a centralized error codes module:

- Error Codes and Categories:
  - AUTH_* : Authentication and authorization errors
  - VALIDATION_* : User/input validation errors
  - STORAGE_* : Backup/storage-related errors
  - NETWORK_* : Network & transport errors
  - SECURITY_* : WAF/security actions and detections
  - SYSTEM_* : Internal system and unexpected errors

- Features:
  - Canonical error codes mapped to HTTP status codes
  - Machine-readable error payloads with error_code, message, details, and correlation_id
  - Helper functions to generate safe client messages while preserving internal diagnostics in logs
  - Integration with unified logging to emit consistent structured error events and alerting hooks
  - Error translation layers for internal services and external API surface

Example response:
```json
{
  "error_code": "STORAGE_SHARD_MISSING",
  "http_status": 500,
  "message": "Backup shard validation failed",
  "details": "Manifest missing shard: shard-2025-08-26-0003",
  "correlation_id": "req-3f2a..."
}
```

See also operational runbooks and incident response procedures: [Incident Response](INCIDENT_RESPONSE.md).

## Diagrams and Component Relationships

- Unified Logging: Serves as the single telemetry and logging sink across the application. It provides:
  - setup_logging() to configure global sinks and formats
  - get_logger(name) for module-level loggers
  - get_directory_manager() to provide standardized local directory paths for subsystems (e.g., backups)
  - performance logging APIs (microsecond timers, histograms)

- Latency Optimizer: Placed in the infrastructure/performance layer to perform request preprocessing, apply caches, and coordinate compression.

- Error Handling: Central error manager is wired into middleware and service boundaries so that all uncaught exceptions are normalized into the centralized error response format and recorded in the unified logs.

High-level component relationship:

```
[Client] -> [Load Balancer] -> [API Gateway] -> [WAF] -> [Latency Optimizer] -> [Auth / Business Services] -> [Database / Storage]
                                   |                                         ^
                                   V                                         |
                           [Unified Logging & Metrics] -----------------------
                                   |
                           [Central Error Manager]
```

Notes on relationships:
- Services emit structured logs and metrics to Unified Logging rather than writing to ad-hoc files.
- Backup subsystem uses the DirectoryManager provided by Unified Logging for local staging of shards.
- WAF consults Security/Threat services and produces structured security events routed to the same logging pipeline.

## Deployment Architecture

### Single Node Deployment

```
┌─────────────────────────────────────┐
│            Load Balancer            │
├─────────────────────────────────────┤
│          PlexiChat App              │
│   (WAF -> API -> Services -> DB)    │
├─────────────────────────────────────┤
│          Database                   │
├─────────────────────────────────────┤
│          Redis Cache                │
└─────────────────────────────────────┘
```

### Multi-Node Cluster

```
┌─────────────────────────────────────┐
│         External Load Balancer      │
└─────────────┬───────────────────────┘
              │
    ┌─────────┼─────────┐
    │         │         │
┌───▼───┐ ┌───▼───┐ ┌───▼───┐
│Node 1 │ │Node 2 │ │Node 3 │
│ App   │ │ App   │ │ App   │
│ (WAF) │ │ (WAF) │ │ (WAF) │
│Cache  │ │Cache  │ │Cache  │
└───┬───┘ └───┬───┘ └───┬───┘
    │         │         │
    └─────────┼─────────┘
              │
    ┌─────────▼─────────┐
    │  Shared Database  │
    │   (PostgreSQL)    │
    └───────────────────┘
```

### Cloud Deployment

```
┌─────────────────────────────────────┐
│              CDN                    │
├─────────────────────────────────────┤
│         Load Balancer               │
├─────────────────────────────────────┤
│      Container Orchestration        │
│         (Kubernetes)                │
├─────────────────────────────────────┤
│        Managed Database             │
│      (RDS/Cloud SQL)                │
├─────────────────────────────────────┤
│         Object Storage              │
│        (S3/GCS/Azure)               │
└─────────────────────────────────────┘
```

## Design Patterns

1. Dependency Injection
- Service container for dependency management
- Interface-based programming
- Testability and modularity

2. Event-Driven Architecture
- Asynchronous event processing
- Loose coupling between components
- Scalable message handling

3. Repository Pattern
- Data access abstraction
- Database independence
- Testable data layer

4. Factory Pattern
- Dynamic object creation
- Provider abstraction
- Plugin system support

5. Observer Pattern
- Real-time notifications
- Event broadcasting
- State change monitoring

## Performance Considerations

1. Caching Strategy
- Multi-level caching (Redis, in-memory, CDN)
- Cache invalidation strategies
- Performance optimization

2. Database Optimization
- Connection pooling
- Query optimization
- Indexing strategies

3. Asynchronous Processing
- Background task processing
- Non-blocking I/O operations
- Concurrent request handling

4. Resource Management
- Memory optimization
- CPU utilization
- Network bandwidth management

5. Observability & Instrumentation
- Unified logging and performance metrics for tracing and alerting
- Microsecond timers for latency-sensitive paths
- Histogram and percentile reporting for SLA tracking

---

This updated architecture reflects the consolidation of previously duplicated cross-cutting systems into unified subsystems, the introduction of a robust WAF and security pipeline, the standardization of backup shard sizing (1MB default with configuration), and the addition of a centralized error handling system to provide consistent client-facing and machine-readable error responses. These changes aim to reduce complexity, improve maintainability, and strengthen security and operational observability across PlexiChat.

## Documentation Generation & Developer Infrastructure

PlexiChat includes a lightweight, reproducible documentation pipeline designed to keep API reference material synchronized with the running application and to provide a clear process for maintaining site content.

- Documentation conventions and locations
  - All canonical documentation pages live under the docs/ directory of the repository and use consistent uppercase file names with underscores, for example:
    - docs/GETTING_STARTED.md
    - docs/ARCHITECTURE.md
    - docs/SECURITY.md
    - docs/WAF_RULES.md
    - docs/INCIDENT_RESPONSE.md
    - docs/BACKUP_SYSTEM.md
    - docs/API.md
    - docs/MAINTAINING_DOCUMENTATION.md
    - docs/PLUGIN_DEVELOPMENT.md
  - Generated artifacts (OpenAPI schema, generated API reference) are placed under docs/_generated/ and are excluded from source control via docs/_generated/.gitignore.

- Automated API documentation generation
  - The FastAPI application exposes an OpenAPI schema programmatically via app.openapi(). To keep docs in sync, the repository includes a script (scripts/dump_openapi.py) which:
    - Imports the FastAPI app (from src/plexichat/main.py)
    - Calls app.openapi() to obtain the current schema
    - Writes docs/_generated/openapi.json (and creates the target directory if needed)
  - The MkDocs configuration (mkdocs.yml) is configured to process docs/_generated/openapi.json with an OpenAPI plugin to render the API Reference under the site navigation.
  - Primary API reference: docs/API.md (human-written material) and generated API reference under docs/_generated/ (machine-generated OpenAPI output).

- Local build and preview
  - Developers can generate the OpenAPI schema and build the site locally:
    - python3 scripts/dump_openapi.py
    - mkdocs build    # or mkdocs serve for local preview
  - A convenience build script (scripts/build_docs.sh) and Makefile targets (docs, docs-serve, docs-lint, docs-clean, docs-install) are provided to standardize developer workflows.

- CI integration
  - A GitHub Actions workflow (/.github/workflows/docs.yml) is included to:
    - Run the OpenAPI dump script
    - Lint Markdown files (markdown-lint)
    - Build the MkDocs site
    - Optionally deploy to GitHub Pages or another hosting target
  - CI uses caching for Python dependencies and fails fast on lint/build errors to prevent documentation drift.

- Naming and cross-reference standards
  - Use relative links to docs files, for example: [WAF Rules](WAF_RULES.md).
  - Filenames use UPPERCASE_WITH_UNDERSCORES.md for major topics to improve discoverability and consistency.
  - When referencing generated API documentation, link to the human-facing docs/API.md and to the generated path (docs/_generated/openapi.json) only where necessary.

- How to update documentation
  1. Add or edit markdown files under docs/ using the naming conventions above.
  2. Update or add examples, diagrams, and runbooks as needed. Prefer small, focused pages rather than very large monoliths.
  3. If API endpoints changed, run python3 scripts/dump_openapi.py and commit docs/_generated/openapi.json (if your repo policy requires generated artifacts; otherwise CI will generate it).
  4. Run mkdocs build locally or mkdocs serve to preview.
  5. Open a pull request with documentation changes and request review from the documentation maintainers.
  6. The CI workflow will run documentation linting and build checks; address any failures before merging.

- Quick references
  - WAF rules and configuration: docs/WAF_RULES.md
  - Incident response runbooks: docs/INCIDENT_RESPONSE.md
  - API documentation and generation: docs/API.md and docs/_generated/openapi.json
  - Maintaining documentation and contribution guidelines: docs/MAINTAINING_DOCUMENTATION.md

By integrating documentation generation into the normal development lifecycle and standardizing naming and linking conventions, PlexiChat reduces the risk of outdated documentation and ensures operators and developers have clear, up-to-date guidance for deployment, security, and incident response.