# NetLink API Documentation

## Overview

NetLink provides comprehensive REST API endpoints for backup management, clustering operations, and system administration. All endpoints require proper authentication and follow RESTful conventions.

## Authentication

### API Key Authentication
```http
Authorization: Bearer <api-key>
```

### Admin Authentication
```http
Authorization: Basic <base64-encoded-credentials>
```

## Base URLs

- **Production**: `https://your-domain.com/api/v1`
- **Development**: `http://localhost:8000/api/v1`

## Backup System API

### System Health

#### Get Backup System Health
```http
GET /backup/health
```

**Response:**
```json
{
  "status": "HEALTHY|WARNING|CRITICAL",
  "total_shards": 1250,
  "active_nodes": 5,
  "coverage_percentage": 98.5,
  "last_backup": "2025-07-03T10:30:00Z",
  "proxy_mode_active": false,
  "encryption_status": "ENABLED",
  "redundancy_level": 3
}
```

### Backup Operations

#### Create Backup
```http
POST /backup/create
```

**Request Body:**
```json
{
  "name": "Daily Backup",
  "backup_type": "full|incremental|differential",
  "description": "Automated daily backup",
  "encryption_enabled": true,
  "compression_enabled": true,
  "created_by": "admin",
  "schedule": {
    "enabled": true,
    "cron_expression": "0 2 * * *"
  }
}
```

**Response:**
```json
{
  "operation_id": "backup-op-123456",
  "status": "PENDING",
  "created_at": "2025-07-03T10:30:00Z",
  "estimated_completion": "2025-07-03T11:00:00Z"
}
```

#### List Backup Operations
```http
GET /backup/operations?limit=10&offset=0&status=completed
```

**Query Parameters:**
- `limit`: Number of results (default: 10, max: 100)
- `offset`: Pagination offset (default: 0)
- `status`: Filter by status (pending|running|completed|failed)
- `backup_type`: Filter by type (full|incremental|differential)

**Response:**
```json
{
  "operations": [
    {
      "operation_id": "backup-op-123456",
      "name": "Daily Backup",
      "status": "COMPLETED",
      "backup_type": "full",
      "created_at": "2025-07-03T02:00:00Z",
      "completed_at": "2025-07-03T02:45:00Z",
      "size_bytes": 1073741824,
      "shard_count": 42
    }
  ],
  "total": 150,
  "has_more": true
}
```

#### Get Backup Operation Details
```http
GET /backup/operations/{operation_id}
```

**Response:**
```json
{
  "operation_id": "backup-op-123456",
  "name": "Daily Backup",
  "status": "COMPLETED",
  "progress_percentage": 100,
  "created_by": "admin",
  "shards": [
    {
      "shard_id": "shard-abc123",
      "size_bytes": 25165824,
      "checksum": "sha512:abc123...",
      "encrypted": true,
      "location_nodes": ["node-1", "node-2", "node-3"]
    }
  ],
  "logs": [
    {
      "timestamp": "2025-07-03T02:00:00Z",
      "level": "INFO",
      "message": "Backup operation started"
    }
  ]
}
```

### Shard Management

#### Get Shard Distribution
```http
GET /backup/shards/distribution
```

**Response:**
```json
{
  "total_shards": 1250,
  "distribution": {
    "node-1": {
      "shard_count": 420,
      "total_size_bytes": 10737418240,
      "health_status": "HEALTHY"
    },
    "node-2": {
      "shard_count": 415,
      "total_size_bytes": 10485760000,
      "health_status": "HEALTHY"
    }
  },
  "redundancy_stats": {
    "min_copies": 2,
    "max_copies": 5,
    "average_copies": 3.2
  }
}
```

#### Redistribute Shards
```http
POST /backup/shards/redistribute
```

**Request Body:**
```json
{
  "strategy": "balanced|performance|security",
  "target_redundancy": 3,
  "exclude_nodes": ["node-3"],
  "dry_run": false
}
```

#### Verify Shard Integrity
```http
GET /backup/shards/{shard_id}/verify
```

**Response:**
```json
{
  "shard_id": "shard-abc123",
  "integrity_status": "VALID|CORRUPTED|MISSING",
  "checksum_match": true,
  "last_verified": "2025-07-03T10:00:00Z",
  "verification_details": {
    "expected_checksum": "sha512:abc123...",
    "actual_checksum": "sha512:abc123...",
    "size_match": true
  }
}
```

### Backup Node Management

#### List Backup Nodes
```http
GET /backup/nodes
```

**Response:**
```json
{
  "nodes": [
    {
      "node_id": "node-1",
      "name": "Primary Backup Node",
      "address": "192.168.1.100:8080",
      "status": "ACTIVE",
      "storage_capacity_gb": 1000,
      "storage_used_gb": 650,
      "shard_count": 420,
      "last_heartbeat": "2025-07-03T10:29:00Z"
    }
  ]
}
```

#### Add Backup Node
```http
POST /backup/nodes/add
```

**Request Body:**
```json
{
  "name": "New Backup Node",
  "address": "192.168.1.105:8080",
  "storage_capacity_gb": 2000,
  "node_type": "backup",
  "encryption_enabled": true,
  "api_key": "generated-api-key"
}
```

#### Generate API Key
```http
POST /backup/nodes/api-keys/generate
```

**Request Body:**
```json
{
  "node_name": "backup-node-01",
  "permissions": ["READ_ONLY", "WRITE_ONLY", "FULL_ACCESS"],
  "expires_in_days": 365,
  "description": "API key for backup node 01"
}
```

**Response:**
```json
{
  "api_key": "bk_1234567890abcdef...",
  "node_name": "backup-node-01",
  "permissions": ["FULL_ACCESS"],
  "expires_at": "2026-07-03T10:30:00Z",
  "created_at": "2025-07-03T10:30:00Z"
}
```

### User Backup Preferences

#### Get User Preferences
```http
GET /backup/user-preferences
```

**Response:**
```json
{
  "user_id": "user-123",
  "preferences": {
    "backup_messages": true,
    "backup_profile": true,
    "backup_files": false,
    "backup_settings": true,
    "backup_chat_history": true
  },
  "updated_at": "2025-07-03T10:00:00Z"
}
```

#### Update User Preferences
```http
PUT /backup/user-preferences
```

**Request Body:**
```json
{
  "backup_messages": false,
  "backup_profile": true,
  "backup_files": true,
  "backup_settings": true
}
```

## Clustering System API

### Cluster Overview

#### Get Cluster Status
```http
GET /clustering/overview
```

**Response:**
```json
{
  "total_nodes": 8,
  "active_nodes": 7,
  "cluster_load": 65.2,
  "performance_gain": 245.8,
  "failover_events": 2,
  "last_failover": "2025-07-03T08:15:00Z",
  "cluster_health": "HEALTHY",
  "uptime_percentage": 99.95
}
```

### Node Management

#### List Cluster Nodes
```http
GET /clustering/nodes?type=main&status=active
```

**Query Parameters:**
- `type`: Filter by node type (main|gateway|antivirus|backup)
- `status`: Filter by status (active|inactive|maintenance)

**Response:**
```json
{
  "nodes": [
    {
      "node_id": "node-main-01",
      "name": "Main Node 01",
      "type": "main",
      "address": "192.168.1.10:8000",
      "status": "ACTIVE",
      "capacity": 100,
      "current_connections": 45,
      "cpu_usage": 65.2,
      "memory_usage": 78.1,
      "last_heartbeat": "2025-07-03T10:29:30Z"
    }
  ]
}
```

#### Add Cluster Node
```http
POST /clustering/nodes/add
```

**Request Body:**
```json
{
  "name": "Gateway Node 02",
  "type": "gateway",
  "address": "192.168.1.25:8000",
  "capacity": 150,
  "encryption_enabled": true,
  "ssl_termination": true,
  "max_connections": 200
}
```

### Load Balancer Configuration

#### Get Load Balancer Config
```http
GET /clustering/load-balancer/config
```

**Response:**
```json
{
  "algorithm": "ai_optimized",
  "health_check_enabled": true,
  "health_check_interval": 30,
  "timeout_seconds": 10,
  "retry_attempts": 3,
  "sticky_sessions": false
}
```

#### Update Load Balancer Algorithm
```http
PUT /clustering/load-balancer/algorithm
```

**Request Body:**
```json
{
  "algorithm": "round_robin|weighted_round_robin|least_connections|ai_optimized",
  "weights": {
    "node-main-01": 100,
    "node-main-02": 150
  }
}
```

#### Get Load Balancer Statistics
```http
GET /clustering/load-balancer/stats
```

**Response:**
```json
{
  "total_requests": 1000000,
  "requests_per_second": 150.5,
  "average_response_time": 45.2,
  "error_rate": 0.05,
  "node_distribution": {
    "node-main-01": 45.2,
    "node-main-02": 54.8
  }
}
```

### Performance Monitoring

#### Get Performance Metrics
```http
GET /clustering/performance/metrics?node_id=node-main-01&time_range=1h
```

**Query Parameters:**
- `node_id`: Specific node ID (optional)
- `time_range`: Time range (1h|6h|24h|7d|30d)

**Response:**
```json
{
  "metrics": [
    {
      "timestamp": "2025-07-03T10:30:00Z",
      "node_id": "node-main-01",
      "response_time_ms": 45.2,
      "throughput_rps": 150.0,
      "cpu_usage": 65.2,
      "memory_usage": 78.1,
      "error_rate": 0.05
    }
  ],
  "summary": {
    "avg_response_time": 45.2,
    "max_response_time": 89.5,
    "avg_throughput": 150.0,
    "total_requests": 540000
  }
}
```

### Failover Management

#### Get Failover Configuration
```http
GET /clustering/failover/config
```

**Response:**
```json
{
  "detection_timeout_seconds": 5,
  "recovery_timeout_seconds": 30,
  "max_failover_attempts": 3,
  "auto_failback_enabled": true,
  "notification_enabled": true
}
```

#### Update Failover Thresholds
```http
PUT /clustering/failover/thresholds
```

**Request Body:**
```json
{
  "response_time_threshold_ms": 1000,
  "error_rate_threshold": 5.0,
  "cpu_threshold": 90.0,
  "memory_threshold": 95.0
}
```

## Error Responses

### Standard Error Format
```json
{
  "error": {
    "code": "BACKUP_OPERATION_FAILED",
    "message": "Backup operation failed due to insufficient storage",
    "details": {
      "operation_id": "backup-op-123456",
      "required_space_gb": 100,
      "available_space_gb": 50
    },
    "timestamp": "2025-07-03T10:30:00Z"
  }
}
```

### HTTP Status Codes
- `200 OK`: Successful request
- `201 Created`: Resource created successfully
- `400 Bad Request`: Invalid request parameters
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: Insufficient permissions
- `404 Not Found`: Resource not found
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server error
- `503 Service Unavailable`: Service temporarily unavailable

## Rate Limiting

All API endpoints are subject to rate limiting:
- **Standard endpoints**: 1000 requests per hour
- **Backup operations**: 10 operations per hour
- **Clustering operations**: 100 requests per hour

Rate limit headers are included in responses:
```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1625097600
```
