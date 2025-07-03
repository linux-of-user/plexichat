# NetLink Complete API Reference

Comprehensive API documentation with all endpoints, examples, and interactive testing.

## Base Configuration

**Default Base URL**: `http://localhost:8000`
**API Version**: v1
**Authentication**: JWT Bearer tokens or session cookies

## Quick Test Setup

```bash
# Set base URL for easy testing
export NETLINK_URL="http://localhost:8000"

# Login and get token
TOKEN=$(curl -s -X POST "$NETLINK_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}' | \
  jq -r '.access_token')

# Use token in subsequent requests
curl -H "Authorization: Bearer $TOKEN" "$NETLINK_URL/api/v1/system/status"
```

## Authentication Endpoints

### 🔐 Login
**Endpoint**: `POST /api/auth/login`

**Description**: Authenticate user and get access token

**Request**:
```bash
curl -X POST "$NETLINK_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin123",
    "remember_me": false
  }'
```

**Response**:
```json
{
  "success": true,
  "message": "Login successful",
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "session_id": "abc123...",
  "token_type": "bearer",
  "user": {
    "username": "admin",
    "email": "admin@netlink.local",
    "is_admin": true
  }
}
```

**Test Script**:
```bash
#!/bin/bash
# Test login endpoint
response=$(curl -s -X POST "$NETLINK_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}')

if echo "$response" | jq -e '.success' > /dev/null; then
  echo "✅ Login successful"
  echo "$response" | jq '.user'
else
  echo "❌ Login failed"
  echo "$response" | jq '.message'
fi
```

### 🔓 Logout
**Endpoint**: `POST /api/auth/logout`

**Description**: Logout user and invalidate session

**Request**:
```bash
curl -X POST "$NETLINK_URL/api/auth/logout" \
  -H "Authorization: Bearer $TOKEN"
```

**Response**:
```json
{
  "success": true,
  "message": "Logged out successfully"
}
```

### 👤 Get Current User
**Endpoint**: `GET /api/auth/me`

**Description**: Get current authenticated user information

**Request**:
```bash
curl -X GET "$NETLINK_URL/api/auth/me" \
  -H "Authorization: Bearer $TOKEN"
```

**Response**:
```json
{
  "username": "admin",
  "email": "admin@netlink.local",
  "is_active": true,
  "is_admin": true,
  "created_at": "2024-01-01T00:00:00Z",
  "last_login": "2024-01-01T12:00:00Z"
}
```

### ✅ Validate Session
**Endpoint**: `POST /api/auth/validate`

**Description**: Validate session token

**Request**:
```bash
curl -X POST "$NETLINK_URL/api/auth/validate" \
  -H "Content-Type: application/json" \
  -d '{"session_id": "your-session-id"}'
```

## System Endpoints

### 🏥 Health Check
**Endpoint**: `GET /api/v1/system/health`

**Description**: Quick system health check

**Request**:
```bash
curl -X GET "$NETLINK_URL/api/v1/system/health"
```

**Response**:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime": 3600,
  "timestamp": "2024-01-01T12:00:00Z",
  "checks": {
    "database": "connected",
    "cluster": "active",
    "memory": "ok",
    "disk": "ok"
  }
}
```

**Test Script**:
```bash
#!/bin/bash
# Health check with status validation
health=$(curl -s "$NETLINK_URL/api/v1/system/health")
status=$(echo "$health" | jq -r '.status')

case $status in
  "healthy")
    echo "✅ System is healthy"
    ;;
  "degraded")
    echo "⚠️  System is degraded"
    ;;
  "unhealthy")
    echo "❌ System is unhealthy"
    ;;
  *)
    echo "❓ Unknown status: $status"
    ;;
esac

echo "$health" | jq '.checks'
```

### 📊 System Status
**Endpoint**: `GET /api/v1/system/status`

**Description**: Detailed system status and metrics

**Request**:
```bash
curl -X GET "$NETLINK_URL/api/v1/system/status" \
  -H "Authorization: Bearer $TOKEN"
```

**Response**:
```json
{
  "server": {
    "status": "running",
    "version": "1.0.0",
    "uptime": "2h 15m 30s",
    "memory_usage": "128.5 MB",
    "cpu_usage": "15.2%",
    "load_average": [0.5, 0.3, 0.2]
  },
  "database": {
    "status": "connected",
    "type": "sqlite",
    "size": "2.1 MB",
    "connections": 5
  },
  "cluster": {
    "status": "active",
    "node_count": 3,
    "is_leader": true,
    "leader_id": "node-abc123"
  },
  "features": {
    "authentication": true,
    "clustering": true,
    "hot_updates": true,
    "https": false
  }
}
```

### ℹ️ System Information
**Endpoint**: `GET /api/v1/system/info`

**Description**: System configuration and build information

**Request**:
```bash
curl -X GET "$NETLINK_URL/api/v1/system/info"
```

**Response**:
```json
{
  "app_name": "NetLink",
  "version": "1.0.0",
  "build_date": "2024-01-01",
  "python_version": "3.9.7",
  "platform": "linux",
  "architecture": "x86_64",
  "host": "0.0.0.0",
  "port": 8000,
  "debug": false,
  "environment": "production",
  "features": {
    "clustering": true,
    "hot_updates": true,
    "authentication": true,
    "analytics": true,
    "https": false
  },
  "limits": {
    "max_connections": 1000,
    "max_file_size": "10MB",
    "rate_limit": "100/min"
  }
}
```

### 🔄 System Restart
**Endpoint**: `POST /api/v1/system/restart`

**Description**: Restart the NetLink server (admin only)

**Request**:
```bash
curl -X POST "$NETLINK_URL/api/v1/system/restart" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"confirm": true, "delay": 5}'
```

**Response**:
```json
{
  "success": true,
  "message": "Server restart initiated",
  "restart_in": 5,
  "estimated_downtime": "30 seconds"
}
```

### 🛑 System Shutdown
**Endpoint**: `POST /api/v1/system/shutdown`

**Description**: Shutdown the NetLink server (admin only)

**Request**:
```bash
curl -X POST "$NETLINK_URL/api/v1/system/shutdown" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"confirm": true, "delay": 10}'
```

## User Management Endpoints

### 👥 List Users
**Endpoint**: `GET /api/v1/users`

**Description**: Get list of all users (admin only)

**Request**:
```bash
curl -X GET "$NETLINK_URL/api/v1/users?limit=50&offset=0" \
  -H "Authorization: Bearer $TOKEN"
```

**Response**:
```json
{
  "users": [
    {
      "id": 1,
      "username": "admin",
      "email": "admin@netlink.local",
      "is_active": true,
      "is_admin": true,
      "created_at": "2024-01-01T00:00:00Z",
      "last_login": "2024-01-01T12:00:00Z",
      "login_count": 25
    },
    {
      "id": 2,
      "username": "user1",
      "email": "user1@example.com",
      "is_active": true,
      "is_admin": false,
      "created_at": "2024-01-02T00:00:00Z",
      "last_login": "2024-01-02T10:00:00Z",
      "login_count": 5
    }
  ],
  "total": 2,
  "limit": 50,
  "offset": 0,
  "has_more": false
}
```

### ➕ Create User
**Endpoint**: `POST /api/v1/users`

**Description**: Create a new user (admin only)

**Request**:
```bash
curl -X POST "$NETLINK_URL/api/v1/users" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newuser",
    "email": "newuser@example.com",
    "password": "securepassword123",
    "is_admin": false,
    "is_active": true
  }'
```

**Response**:
```json
{
  "success": true,
  "message": "User created successfully",
  "user": {
    "id": 3,
    "username": "newuser",
    "email": "newuser@example.com",
    "is_active": true,
    "is_admin": false,
    "created_at": "2024-01-01T12:30:00Z"
  }
}
```

### 👤 Get User
**Endpoint**: `GET /api/v1/users/{user_id}`

**Description**: Get specific user information

**Request**:
```bash
curl -X GET "$NETLINK_URL/api/v1/users/1" \
  -H "Authorization: Bearer $TOKEN"
```

### ✏️ Update User
**Endpoint**: `PUT /api/v1/users/{user_id}`

**Description**: Update user information (admin only)

**Request**:
```bash
curl -X PUT "$NETLINK_URL/api/v1/users/2" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "updated@example.com",
    "is_active": true,
    "is_admin": false
  }'
```

### 🗑️ Delete User
**Endpoint**: `DELETE /api/v1/users/{user_id}`

**Description**: Delete a user (admin only)

**Request**:
```bash
curl -X DELETE "$NETLINK_URL/api/v1/users/2" \
  -H "Authorization: Bearer $TOKEN"
```

**Response**:
```json
{
  "success": true,
  "message": "User deleted successfully"
}
```

## Messaging Endpoints

### 💬 Send Message
**Endpoint**: `POST /api/v1/messages`

**Description**: Send a new message

**Request**:
```bash
curl -X POST "$NETLINK_URL/api/v1/messages" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "content": "Hello, world! 👋",
    "channel_id": "general",
    "message_type": "text",
    "metadata": {
      "priority": "normal",
      "tags": ["announcement"]
    }
  }'
```

**Response**:
```json
{
  "success": true,
  "message": {
    "id": 123,
    "content": "Hello, world! 👋",
    "author": "admin",
    "channel_id": "general",
    "message_type": "text",
    "timestamp": "2024-01-01T12:00:00Z",
    "edited": false,
    "metadata": {
      "priority": "normal",
      "tags": ["announcement"]
    }
  }
}
```

### 📜 Get Messages
**Endpoint**: `GET /api/v1/messages`

**Description**: Retrieve messages with filtering and pagination

**Request**:
```bash
# Get recent messages
curl -X GET "$NETLINK_URL/api/v1/messages?channel_id=general&limit=50" \
  -H "Authorization: Bearer $TOKEN"

# Get messages with filters
curl -X GET "$NETLINK_URL/api/v1/messages?author=admin&message_type=text&since=2024-01-01T00:00:00Z" \
  -H "Authorization: Bearer $TOKEN"
```

**Response**:
```json
{
  "messages": [
    {
      "id": 123,
      "content": "Hello, world! 👋",
      "author": "admin",
      "channel_id": "general",
      "message_type": "text",
      "timestamp": "2024-01-01T12:00:00Z",
      "edited": false,
      "reactions": [
        {"emoji": "👍", "count": 5, "users": ["user1", "user2"]},
        {"emoji": "❤️", "count": 2, "users": ["user3"]}
      ]
    }
  ],
  "total": 1,
  "limit": 50,
  "offset": 0,
  "has_more": false,
  "channel_info": {
    "id": "general",
    "name": "General",
    "description": "General discussion"
  }
}
```

### ✏️ Edit Message
**Endpoint**: `PUT /api/v1/messages/{message_id}`

**Description**: Edit an existing message (author only)

**Request**:
```bash
curl -X PUT "$NETLINK_URL/api/v1/messages/123" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "content": "Hello, updated world! 🌍",
    "edit_reason": "Fixed typo"
  }'
```

### 🗑️ Delete Message
**Endpoint**: `DELETE /api/v1/messages/{message_id}`

**Description**: Delete a message (author or admin only)

**Request**:
```bash
curl -X DELETE "$NETLINK_URL/api/v1/messages/123" \
  -H "Authorization: Bearer $TOKEN"
```

### 👍 Add Reaction
**Endpoint**: `POST /api/v1/messages/{message_id}/reactions`

**Description**: Add reaction to a message

**Request**:
```bash
curl -X POST "$NETLINK_URL/api/v1/messages/123/reactions" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"emoji": "👍"}'
```

## File Management Endpoints

### 📁 Upload File
**Endpoint**: `POST /api/v1/files/upload`

**Description**: Upload a file with metadata

**Request**:
```bash
curl -X POST "$NETLINK_URL/api/v1/files/upload" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@document.pdf" \
  -F "channel_id=general" \
  -F "description=Important document" \
  -F "tags=document,important"
```

**Response**:
```json
{
  "success": true,
  "file": {
    "id": "file_abc123",
    "filename": "document.pdf",
    "original_name": "document.pdf",
    "size": 1024000,
    "content_type": "application/pdf",
    "url": "/api/v1/files/file_abc123",
    "download_url": "/api/v1/files/file_abc123/download",
    "thumbnail_url": "/api/v1/files/file_abc123/thumbnail",
    "uploaded_by": "admin",
    "uploaded_at": "2024-01-01T12:00:00Z",
    "channel_id": "general",
    "description": "Important document",
    "tags": ["document", "important"],
    "virus_scan": "clean"
  }
}
```

### 📥 Download File
**Endpoint**: `GET /api/v1/files/{file_id}/download`

**Description**: Download a file

**Request**:
```bash
curl -X GET "$NETLINK_URL/api/v1/files/file_abc123/download" \
  -H "Authorization: Bearer $TOKEN" \
  -o "downloaded_file.pdf"
```

### 📋 List Files
**Endpoint**: `GET /api/v1/files`

**Description**: List uploaded files with filtering

**Request**:
```bash
# List all files
curl -X GET "$NETLINK_URL/api/v1/files?limit=20" \
  -H "Authorization: Bearer $TOKEN"

# Filter by channel and type
curl -X GET "$NETLINK_URL/api/v1/files?channel_id=general&content_type=image/*" \
  -H "Authorization: Bearer $TOKEN"
```

**Response**:
```json
{
  "files": [
    {
      "id": "file_abc123",
      "filename": "document.pdf",
      "size": 1024000,
      "content_type": "application/pdf",
      "uploaded_by": "admin",
      "uploaded_at": "2024-01-01T12:00:00Z",
      "download_count": 5
    }
  ],
  "total": 1,
  "total_size": 1024000,
  "limit": 20,
  "offset": 0
}
```

### 🗑️ Delete File
**Endpoint**: `DELETE /api/v1/files/{file_id}`

**Description**: Delete a file (uploader or admin only)

**Request**:
```bash
curl -X DELETE "$NETLINK_URL/api/v1/files/file_abc123" \
  -H "Authorization: Bearer $TOKEN"
```

## Cluster Management Endpoints

### 🌐 Cluster Status
**Endpoint**: `GET /api/cluster/status`

**Description**: Get comprehensive cluster status

**Request**:
```bash
curl -X GET "$NETLINK_URL/api/cluster/status"
```

**Response**:
```json
{
  "node_id": "node-abc123",
  "is_leader": true,
  "leader_node_id": "node-abc123",
  "total_nodes": 3,
  "alive_nodes": 3,
  "cluster_health": "healthy",
  "last_updated": "2024-01-01T12:00:00Z",
  "nodes": [
    {
      "node_id": "node-abc123",
      "host": "192.168.1.100",
      "port": 8000,
      "version": "1.0.0",
      "status": "active",
      "load": 15.5,
      "connections": 45,
      "is_leader": true,
      "last_seen": "2024-01-01T12:00:00Z",
      "uptime": "2h 15m",
      "memory_usage": "128MB"
    },
    {
      "node_id": "node-def456",
      "host": "192.168.1.101",
      "port": 8000,
      "version": "1.0.0",
      "status": "active",
      "load": 8.2,
      "connections": 23,
      "is_leader": false,
      "last_seen": "2024-01-01T12:00:00Z",
      "uptime": "1h 45m",
      "memory_usage": "95MB"
    }
  ]
}
```

### 📋 List Cluster Nodes
**Endpoint**: `GET /api/cluster/nodes`

**Description**: List all nodes in the cluster

**Request**:
```bash
curl -X GET "$NETLINK_URL/api/cluster/nodes"
```

**Response**:
```json
{
  "nodes": [
    {
      "node_id": "node-abc123",
      "host": "192.168.1.100",
      "port": 8000,
      "version": "1.0.0",
      "status": "active",
      "load": 15.5,
      "connections": 45,
      "is_leader": true,
      "is_alive": true,
      "last_seen": "2024-01-01T12:00:00Z",
      "url": "http://192.168.1.100:8000",
      "capabilities": ["messaging", "file_storage", "analytics"]
    }
  ],
  "total_count": 3,
  "alive_count": 3,
  "leader_count": 1
}
```

### ⚖️ Get Load Balanced Node
**Endpoint**: `GET /api/cluster/load-balance`

**Description**: Get the best node for load balancing

**Request**:
```bash
curl -X GET "$NETLINK_URL/api/cluster/load-balance"
```

**Response**:
```json
{
  "node": {
    "node_id": "node-def456",
    "host": "192.168.1.101",
    "port": 8000,
    "load": 8.2,
    "connections": 23,
    "url": "http://192.168.1.101:8000",
    "response_time": 45,
    "score": 92.5
  },
  "recommended_url": "http://192.168.1.101:8000",
  "algorithm": "least_connections",
  "alternatives": [
    {
      "node_id": "node-ghi789",
      "url": "http://192.168.1.102:8000",
      "score": 88.2
    }
  ]
}
```

### 🤝 Join Cluster
**Endpoint**: `POST /api/cluster/join`

**Description**: Manually join a node to the cluster

**Request**:
```bash
curl -X POST "$NETLINK_URL/api/cluster/join" \
  -H "Content-Type: application/json" \
  -d '{
    "node_id": "node-new123",
    "host": "192.168.1.103",
    "port": 8000,
    "version": "1.0.0",
    "capabilities": ["messaging", "file_storage"]
  }'
```

**Response**:
```json
{
  "success": true,
  "message": "Node joined cluster successfully",
  "node_id": "node-new123",
  "cluster_size": 4,
  "leader_election_triggered": false
}
```

### 👋 Leave Cluster
**Endpoint**: `DELETE /api/cluster/leave/{node_id}`

**Description**: Remove a node from the cluster

**Request**:
```bash
curl -X DELETE "$NETLINK_URL/api/cluster/leave/node-def456" \
  -H "Authorization: Bearer $TOKEN"
```

### 📢 Broadcast Message
**Endpoint**: `POST /api/cluster/broadcast`

**Description**: Broadcast message to all cluster nodes

**Request**:
```bash
curl -X POST "$NETLINK_URL/api/cluster/broadcast" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "maintenance",
    "data": {
      "message": "Scheduled maintenance in 30 minutes",
      "scheduled_time": "2024-01-01T13:00:00Z"
    },
    "priority": "high"
  }'
```

**Response**:
```json
{
  "success": true,
  "message": "Message broadcasted successfully",
  "successful_nodes": ["node-def456", "node-ghi789"],
  "failed_nodes": [],
  "total_nodes": 2,
  "broadcast_id": "broadcast-abc123"
}
```

## Configuration Endpoints

### ⚙️ Get Configuration
**Endpoint**: `GET /api/v1/config`

**Description**: Get current system configuration (admin only)

**Request**:
```bash
curl -X GET "$NETLINK_URL/api/v1/config" \
  -H "Authorization: Bearer $TOKEN"
```

**Response**:
```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 8000,
    "workers": 4,
    "debug": false,
    "environment": "production"
  },
  "database": {
    "type": "sqlite",
    "url": "sqlite:///./data/netlink.db",
    "pool_size": 10,
    "echo": false
  },
  "security": {
    "secret_key_set": true,
    "jwt_expire_minutes": 30,
    "password_min_length": 8,
    "max_login_attempts": 5,
    "https_enabled": false,
    "cors_enabled": true
  },
  "features": {
    "clustering": true,
    "hot_updates": true,
    "file_uploads": true,
    "analytics": true,
    "rate_limiting": true
  },
  "limits": {
    "max_file_size": "10MB",
    "max_message_length": 2000,
    "rate_limit_requests": 100,
    "rate_limit_window": 60
  }
}
```

### 🔧 Update Configuration
**Endpoint**: `PUT /api/v1/config`

**Description**: Update system configuration (admin only)

**Request**:
```bash
curl -X PUT "$NETLINK_URL/api/v1/config" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "server": {
      "workers": 6,
      "debug": false
    },
    "security": {
      "jwt_expire_minutes": 60,
      "https_enabled": true
    },
    "limits": {
      "max_file_size": "20MB",
      "rate_limit_requests": 200
    }
  }'
```

**Response**:
```json
{
  "success": true,
  "message": "Configuration updated successfully",
  "changes": [
    "server.workers: 4 → 6",
    "security.jwt_expire_minutes: 30 → 60",
    "security.https_enabled: false → true",
    "limits.max_file_size: 10MB → 20MB",
    "limits.rate_limit_requests: 100 → 200"
  ],
  "restart_required": true,
  "validation_errors": []
}

## Analytics Endpoints

### 📊 Get Analytics Overview
**Endpoint**: `GET /api/v1/analytics`

**Description**: Get comprehensive analytics dashboard data

**Request**:
```bash
curl -X GET "$NETLINK_URL/api/v1/analytics?period=24h" \
  -H "Authorization: Bearer $TOKEN"
```

**Response**:
```json
{
  "period": "24h",
  "generated_at": "2024-01-01T12:00:00Z",
  "overview": {
    "total_users": 150,
    "active_users": 45,
    "total_messages": 5420,
    "messages_today": 234,
    "total_files": 89,
    "storage_used": "2.1GB"
  },
  "performance": {
    "avg_response_time": 45,
    "requests_per_minute": 120,
    "error_rate": 0.02,
    "uptime_percentage": 99.95
  },
  "system": {
    "cpu_usage": 15.5,
    "memory_usage": 67.2,
    "disk_usage": 23.1,
    "network_io": {
      "bytes_in": 1024000,
      "bytes_out": 2048000
    }
  },
  "cluster": {
    "total_nodes": 3,
    "healthy_nodes": 3,
    "total_load": 31.2,
    "load_distribution": [15.5, 8.2, 7.5]
  }
}
```

### 📈 Get Metrics
**Endpoint**: `GET /api/v1/analytics/metrics`

**Description**: Get detailed metrics with time series data

**Request**:
```bash
curl -X GET "$NETLINK_URL/api/v1/analytics/metrics?metric=cpu_usage&period=1h&interval=5m" \
  -H "Authorization: Bearer $TOKEN"
```

**Response**:
```json
{
  "metric": "cpu_usage",
  "period": "1h",
  "interval": "5m",
  "unit": "percentage",
  "data_points": [
    {"timestamp": "2024-01-01T11:00:00Z", "value": 12.5},
    {"timestamp": "2024-01-01T11:05:00Z", "value": 15.2},
    {"timestamp": "2024-01-01T11:10:00Z", "value": 18.7},
    {"timestamp": "2024-01-01T11:15:00Z", "value": 14.3}
  ],
  "summary": {
    "min": 12.5,
    "max": 18.7,
    "avg": 15.2,
    "current": 14.3
  }
}
```

### 🔍 Search Analytics
**Endpoint**: `GET /api/v1/analytics/search`

**Description**: Search and filter analytics data

**Request**:
```bash
curl -X GET "$NETLINK_URL/api/v1/analytics/search?query=error&type=logs&since=1h" \
  -H "Authorization: Bearer $TOKEN"
```

## Testing & Validation Endpoints

### 🧪 Run System Tests
**Endpoint**: `POST /api/v1/test/system`

**Description**: Run comprehensive system tests (admin only)

**Request**:
```bash
curl -X POST "$NETLINK_URL/api/v1/test/system" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "test_suites": ["database", "authentication", "clustering", "performance"],
    "verbose": true,
    "timeout": 300
  }'
```

**Response**:
```json
{
  "test_run_id": "test-abc123",
  "status": "completed",
  "started_at": "2024-01-01T12:00:00Z",
  "completed_at": "2024-01-01T12:02:30Z",
  "duration": 150,
  "summary": {
    "total_tests": 25,
    "passed": 23,
    "failed": 2,
    "skipped": 0,
    "success_rate": 92.0
  },
  "results": [
    {
      "suite": "database",
      "tests": 8,
      "passed": 8,
      "failed": 0,
      "status": "passed"
    },
    {
      "suite": "authentication",
      "tests": 6,
      "passed": 6,
      "failed": 0,
      "status": "passed"
    },
    {
      "suite": "clustering",
      "tests": 7,
      "passed": 5,
      "failed": 2,
      "status": "failed",
      "failures": [
        {
          "test": "node_discovery",
          "error": "Timeout waiting for node response",
          "details": "Node 192.168.1.103 did not respond within 30 seconds"
        }
      ]
    }
  ]
}
```

### 🏥 Health Check (Detailed)
**Endpoint**: `GET /api/v1/test/health`

**Description**: Detailed health check with component testing

**Request**:
```bash
curl -X GET "$NETLINK_URL/api/v1/test/health?deep=true" \
  -H "Authorization: Bearer $TOKEN"
```

**Response**:
```json
{
  "overall_status": "healthy",
  "timestamp": "2024-01-01T12:00:00Z",
  "checks": {
    "database": {
      "status": "healthy",
      "response_time": 5,
      "details": {
        "connection_pool": "8/10 connections active",
        "last_query": "2024-01-01T11:59:58Z"
      }
    },
    "authentication": {
      "status": "healthy",
      "response_time": 12,
      "details": {
        "active_sessions": 15,
        "token_validation": "working"
      }
    },
    "clustering": {
      "status": "degraded",
      "response_time": 45,
      "details": {
        "nodes_reachable": 2,
        "nodes_total": 3,
        "leader_election": "stable"
      }
    },
    "file_storage": {
      "status": "healthy",
      "response_time": 8,
      "details": {
        "disk_space": "77% available",
        "write_test": "successful"
      }
    }
  }
}
```

## Interactive Testing Tools

### 🎮 API Explorer
**Endpoint**: `GET /docs/explorer`

**Description**: Interactive API testing interface

Access the interactive API explorer at: `http://localhost:8000/docs/explorer`

Features:
- **Live Testing**: Test any endpoint directly from the browser
- **Authentication**: Built-in login and token management
- **Request Builder**: Visual request construction
- **Response Viewer**: Formatted response display
- **Code Generation**: Generate curl commands automatically
- **History**: Track your API testing history

### 📚 API Documentation
**Endpoint**: `GET /docs`

**Description**: Comprehensive API documentation

Access the full documentation at: `http://localhost:8000/docs`

Features:
- **OpenAPI/Swagger**: Standard API documentation
- **Try It Out**: Test endpoints directly
- **Schema Browser**: Explore data models
- **Authentication**: Built-in auth testing
- **Examples**: Real request/response examples

## Batch Testing Scripts

### Complete API Test Suite
```bash
#!/bin/bash
# Complete NetLink API test suite

NETLINK_URL="http://localhost:8000"
TEST_USER="testuser_$(date +%s)"
TEST_EMAIL="test@example.com"

echo "🧪 NetLink API Test Suite"
echo "=========================="

# 1. Health Check
echo "1. Testing health endpoint..."
health=$(curl -s "$NETLINK_URL/api/v1/system/health")
if echo "$health" | jq -e '.status == "healthy"' > /dev/null; then
    echo "✅ Health check passed"
else
    echo "❌ Health check failed"
    exit 1
fi

# 2. Authentication
echo "2. Testing authentication..."
login_response=$(curl -s -X POST "$NETLINK_URL/api/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"admin123"}')

if echo "$login_response" | jq -e '.success' > /dev/null; then
    TOKEN=$(echo "$login_response" | jq -r '.access_token')
    echo "✅ Login successful"
else
    echo "❌ Login failed"
    exit 1
fi

# 3. System Status
echo "3. Testing system status..."
status=$(curl -s -H "Authorization: Bearer $TOKEN" "$NETLINK_URL/api/v1/system/status")
if echo "$status" | jq -e '.server.status == "running"' > /dev/null; then
    echo "✅ System status OK"
else
    echo "❌ System status failed"
fi

# 4. User Management
echo "4. Testing user management..."
create_user=$(curl -s -X POST "$NETLINK_URL/api/v1/users" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$TEST_USER\",\"email\":\"$TEST_EMAIL\",\"password\":\"testpass123\"}")

if echo "$create_user" | jq -e '.success' > /dev/null; then
    echo "✅ User creation successful"
    USER_ID=$(echo "$create_user" | jq -r '.user.id')
else
    echo "❌ User creation failed"
fi

# 5. Messaging
echo "5. Testing messaging..."
send_message=$(curl -s -X POST "$NETLINK_URL/api/v1/messages" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"content":"Test message from API test","channel_id":"general"}')

if echo "$send_message" | jq -e '.success' > /dev/null; then
    echo "✅ Message sending successful"
    MESSAGE_ID=$(echo "$send_message" | jq -r '.message.id')
else
    echo "❌ Message sending failed"
fi

# 6. File Upload (if test file exists)
if [ -f "test_file.txt" ]; then
    echo "6. Testing file upload..."
    upload_response=$(curl -s -X POST "$NETLINK_URL/api/v1/files/upload" \
        -H "Authorization: Bearer $TOKEN" \
        -F "file=@test_file.txt" \
        -F "channel_id=general")

    if echo "$upload_response" | jq -e '.success' > /dev/null; then
        echo "✅ File upload successful"
        FILE_ID=$(echo "$upload_response" | jq -r '.file.id')
    else
        echo "❌ File upload failed"
    fi
fi

# 7. Cluster Status
echo "7. Testing cluster status..."
cluster_status=$(curl -s "$NETLINK_URL/api/cluster/status")
if echo "$cluster_status" | jq -e '.cluster_health' > /dev/null; then
    echo "✅ Cluster status OK"
else
    echo "❌ Cluster status failed"
fi

# 8. Analytics
echo "8. Testing analytics..."
analytics=$(curl -s -H "Authorization: Bearer $TOKEN" "$NETLINK_URL/api/v1/analytics")
if echo "$analytics" | jq -e '.overview' > /dev/null; then
    echo "✅ Analytics OK"
else
    echo "❌ Analytics failed"
fi

# Cleanup
echo "9. Cleanup..."
if [ ! -z "$USER_ID" ]; then
    curl -s -X DELETE "$NETLINK_URL/api/v1/users/$USER_ID" \
        -H "Authorization: Bearer $TOKEN" > /dev/null
    echo "✅ Test user cleaned up"
fi

if [ ! -z "$MESSAGE_ID" ]; then
    curl -s -X DELETE "$NETLINK_URL/api/v1/messages/$MESSAGE_ID" \
        -H "Authorization: Bearer $TOKEN" > /dev/null
    echo "✅ Test message cleaned up"
fi

echo "=========================="
echo "🎉 API test suite completed!"
```

### Performance Test Script
```bash
#!/bin/bash
# NetLink API performance test

NETLINK_URL="http://localhost:8000"
CONCURRENT_USERS=10
REQUESTS_PER_USER=100

echo "🚀 NetLink Performance Test"
echo "Concurrent Users: $CONCURRENT_USERS"
echo "Requests per User: $REQUESTS_PER_USER"

# Login and get token
TOKEN=$(curl -s -X POST "$NETLINK_URL/api/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"admin123"}' | \
    jq -r '.access_token')

# Performance test function
performance_test() {
    local user_id=$1
    local start_time=$(date +%s)

    for i in $(seq 1 $REQUESTS_PER_USER); do
        curl -s -H "Authorization: Bearer $TOKEN" \
            "$NETLINK_URL/api/v1/system/health" > /dev/null
    done

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    echo "User $user_id: $REQUESTS_PER_USER requests in ${duration}s"
}

# Run concurrent tests
echo "Starting performance test..."
for i in $(seq 1 $CONCURRENT_USERS); do
    performance_test $i &
done

wait
echo "Performance test completed!"
```

---

## Quick Reference

### Authentication
```bash
# Login
curl -X POST "$NETLINK_URL/api/auth/login" -H "Content-Type: application/json" -d '{"username":"admin","password":"admin123"}'

# Use token
curl -H "Authorization: Bearer $TOKEN" "$NETLINK_URL/api/endpoint"
```

### Common Endpoints
```bash
# Health check
curl "$NETLINK_URL/api/v1/system/health"

# System status
curl -H "Authorization: Bearer $TOKEN" "$NETLINK_URL/api/v1/system/status"

# Send message
curl -X POST "$NETLINK_URL/api/v1/messages" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"content":"Hello","channel_id":"general"}'

# Upload file
curl -X POST "$NETLINK_URL/api/v1/files/upload" -H "Authorization: Bearer $TOKEN" -F "file=@filename.txt"

# Cluster status
curl "$NETLINK_URL/api/cluster/status"
```

### Interactive Tools
- **API Explorer**: http://localhost:8000/docs/explorer
- **API Documentation**: http://localhost:8000/docs
- **Admin Panel**: http://localhost:8000/admin
- **Web Interface**: http://localhost:8000

---

**Need help?** Visit the interactive documentation at http://localhost:8000/docs or run the test scripts above!
```