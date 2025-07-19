# PlexiChat API Reference

Complete API documentation for PlexiChat's RESTful API with examples, authentication, and integration guides.

## Table of Contents

1. [API Overview](#api-overview)
2. [Authentication](#authentication)
3. [Core Endpoints](#core-endpoints)
4. [WebSocket API](#websocket-api)
5. [Error Handling](#error-handling)
6. [Rate Limiting](#rate-limiting)
7. [SDKs and Libraries](#sdks-and-libraries)
8. [Examples](#examples)

## API Overview

### Base Information

- **Base URL**: `http://localhost:8000` (development) / `https://your-domain.com` (production)
- **API Version**: v1
- **Current Version**: a.1.1-1
- **Protocol**: HTTPS (production), HTTP (development)
- **Data Format**: JSON
- **Authentication**: JWT Bearer tokens, Session cookies, API keys

### API Versioning

PlexiChat uses URL-based versioning:

```
/api/v1/    # Current stable version
/api/v2/    # Future version (when available)
```

### Interactive Documentation

- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

## Authentication

### Authentication Methods

#### 1. JWT Bearer Tokens (Recommended)

```bash
# Login to get token
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin123"
  }'

# Response
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 1800,
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}

# Use token in subsequent requests
curl -X GET "http://localhost:8000/api/v1/users/me" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

#### 2. API Keys

```bash
# Create API key
curl -X POST "http://localhost:8000/api/v1/auth/api-keys" \
  -H "Authorization: Bearer your-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My API Key",
    "permissions": ["read", "write"],
    "expires_at": "2025-12-31T23:59:59Z"
  }'

# Use API key
curl -X GET "http://localhost:8000/api/v1/users/me" \
  -H "X-API-Key: plx_your_api_key_here"
```

#### 3. Session Cookies

```bash
# Login with session
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{
    "username": "admin",
    "password": "admin123"
  }'

# Use session cookie
curl -X GET "http://localhost:8000/api/v1/users/me" \
  -b cookies.txt
```

### Multi-Factor Authentication

```bash
# Login with MFA
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin123",
    "mfa_code": "123456"
  }'

# If MFA required but not provided
{
  "error": "mfa_required",
  "message": "Multi-factor authentication required",
  "mfa_methods": ["totp", "sms"],
  "temp_token": "temp_token_for_mfa"
}

# Complete MFA
curl -X POST "http://localhost:8000/api/v1/auth/mfa/verify" \
  -H "Content-Type: application/json" \
  -d '{
    "temp_token": "temp_token_for_mfa",
    "mfa_code": "123456",
    "method": "totp"
  }'
```

## Core Endpoints

### Authentication Endpoints

#### POST /api/v1/auth/login
Login with username/password

```bash
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin123",
    "remember_me": true
  }'
```

#### POST /api/v1/auth/logout
Logout and invalidate token

```bash
curl -X POST "http://localhost:8000/api/v1/auth/logout" \
  -H "Authorization: Bearer your-token"
```

#### POST /api/v1/auth/refresh
Refresh access token

```bash
curl -X POST "http://localhost:8000/api/v1/auth/refresh" \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "your-refresh-token"
  }'
```

### User Management

#### GET /api/v1/users/me
Get current user profile

```bash
curl -X GET "http://localhost:8000/api/v1/users/me" \
  -H "Authorization: Bearer your-token"

# Response
{
  "id": "user_123",
  "username": "admin",
  "email": "admin@example.com",
  "display_name": "Administrator",
  "avatar_url": "https://example.com/avatar.jpg",
  "roles": ["admin"],
  "permissions": ["system.manage", "users.create"],
  "created_at": "2025-01-01T00:00:00Z",
  "last_login": "2025-01-15T10:30:00Z",
  "is_active": true,
  "preferences": {
    "theme": "dark",
    "language": "en",
    "notifications": true
  }
}
```

#### PUT /api/v1/users/me
Update current user profile

```bash
curl -X PUT "http://localhost:8000/api/v1/users/me" \
  -H "Authorization: Bearer your-token" \
  -H "Content-Type: application/json" \
  -d '{
    "display_name": "New Display Name",
    "email": "newemail@example.com",
    "preferences": {
      "theme": "light",
      "language": "es"
    }
  }'
```

#### GET /api/v1/users
List users (admin only)

```bash
curl -X GET "http://localhost:8000/api/v1/users?page=1&limit=20&search=john" \
  -H "Authorization: Bearer your-admin-token"
```

#### POST /api/v1/users
Create new user (admin only)

```bash
curl -X POST "http://localhost:8000/api/v1/users" \
  -H "Authorization: Bearer your-admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newuser",
    "email": "newuser@example.com",
    "password": "securepassword123",
    "display_name": "New User",
    "roles": ["user"]
  }'
```

### Messaging

#### GET /api/v1/messages
Get messages from a channel

```bash
curl -X GET "http://localhost:8000/api/v1/messages?channel_id=channel_123&limit=50&before=msg_456" \
  -H "Authorization: Bearer your-token"

# Response
{
  "messages": [
    {
      "id": "msg_123",
      "channel_id": "channel_123",
      "user_id": "user_456",
      "content": "Hello, world!",
      "content_type": "text",
      "created_at": "2025-01-15T10:30:00Z",
      "updated_at": null,
      "attachments": [],
      "mentions": [],
      "reactions": [],
      "thread_id": null,
      "reply_to": null,
      "is_edited": false,
      "is_deleted": false
    }
  ],
  "pagination": {
    "has_more": true,
    "next_cursor": "msg_122",
    "total_count": 1250
  }
}
```

#### POST /api/v1/messages
Send a new message

```bash
curl -X POST "http://localhost:8000/api/v1/messages" \
  -H "Authorization: Bearer your-token" \
  -H "Content-Type: application/json" \
  -d '{
    "channel_id": "channel_123",
    "content": "Hello, everyone!",
    "content_type": "text",
    "mentions": ["user_456"],
    "reply_to": "msg_789"
  }'
```

#### PUT /api/v1/messages/{message_id}
Edit a message

```bash
curl -X PUT "http://localhost:8000/api/v1/messages/msg_123" \
  -H "Authorization: Bearer your-token" \
  -H "Content-Type: application/json" \
  -d '{
    "content": "Updated message content"
  }'
```

#### DELETE /api/v1/messages/{message_id}
Delete a message

```bash
curl -X DELETE "http://localhost:8000/api/v1/messages/msg_123" \
  -H "Authorization: Bearer your-token"
```

### File Management

#### POST /api/v1/files/upload
Upload a file

```bash
curl -X POST "http://localhost:8000/api/v1/files/upload" \
  -H "Authorization: Bearer your-token" \
  -F "file=@document.pdf" \
  -F "channel_id=channel_123" \
  -F "description=Important document"

# Response
{
  "id": "file_123",
  "filename": "document.pdf",
  "original_filename": "document.pdf",
  "size": 1048576,
  "content_type": "application/pdf",
  "url": "https://example.com/files/file_123/document.pdf",
  "thumbnail_url": "https://example.com/files/file_123/thumbnail.jpg",
  "channel_id": "channel_123",
  "uploaded_by": "user_456",
  "uploaded_at": "2025-01-15T10:30:00Z",
  "description": "Important document",
  "is_public": false,
  "virus_scan_status": "clean",
  "metadata": {
    "pages": 10,
    "author": "John Doe"
  }
}
```

#### GET /api/v1/files/{file_id}
Get file information

```bash
curl -X GET "http://localhost:8000/api/v1/files/file_123" \
  -H "Authorization: Bearer your-token"
```

#### GET /api/v1/files/{file_id}/download
Download a file

```bash
curl -X GET "http://localhost:8000/api/v1/files/file_123/download" \
  -H "Authorization: Bearer your-token" \
  -o downloaded_file.pdf
```

### AI Integration

#### POST /api/v1/ai/chat
Chat with AI assistant

```bash
curl -X POST "http://localhost:8000/api/v1/ai/chat" \
  -H "Authorization: Bearer your-token" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Summarize the latest project updates",
    "context": {
      "channel_id": "channel_123",
      "include_files": true,
      "time_range": "7d"
    },
    "provider": "openai",
    "model": "gpt-4"
  }'

# Response
{
  "response": "Based on the recent messages and files in this channel...",
  "provider": "openai",
  "model": "gpt-4",
  "usage": {
    "prompt_tokens": 150,
    "completion_tokens": 200,
    "total_tokens": 350
  },
  "created_at": "2025-01-15T10:30:00Z"
}
```

#### POST /api/v1/ai/search
Semantic search

```bash
curl -X POST "http://localhost:8000/api/v1/ai/search" \
  -H "Authorization: Bearer your-token" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "machine learning tutorials",
    "content_types": ["messages", "files"],
    "channels": ["channel_123", "channel_456"],
    "similarity_threshold": 0.7,
    "limit": 10
  }'
```

### System Administration

#### GET /api/v1/admin/system/status
Get system status (admin only)

```bash
curl -X GET "http://localhost:8000/api/v1/admin/system/status" \
  -H "Authorization: Bearer your-admin-token"

# Response
{
  "status": "healthy",
  "version": "a.1.1-1",
  "uptime": 86400,
  "database": {
    "status": "connected",
    "connections": 5,
    "pool_size": 10
  },
  "cache": {
    "status": "connected",
    "memory_usage": "45%",
    "hit_rate": 0.95
  },
  "security": {
    "encryption_status": "active",
    "threat_level": "low",
    "last_security_scan": "2025-01-15T09:00:00Z"
  },
  "performance": {
    "cpu_usage": 25.5,
    "memory_usage": 60.2,
    "disk_usage": 45.8,
    "response_time_ms": 120
  }
}
```

#### GET /api/v1/admin/users
Advanced user management (admin only)

```bash
curl -X GET "http://localhost:8000/api/v1/admin/users?include_inactive=true&role=admin" \
  -H "Authorization: Bearer your-admin-token"
```

#### POST /api/v1/admin/backup
Create system backup (admin only)

```bash
curl -X POST "http://localhost:8000/api/v1/admin/backup" \
  -H "Authorization: Bearer your-admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "include_files": true,
    "include_database": true,
    "compression": "gzip",
    "encryption": true
  }'
```

## WebSocket API

### Connection

```javascript
// Connect to WebSocket
const ws = new WebSocket('ws://localhost:8000/ws');

// With authentication
const ws = new WebSocket('ws://localhost:8000/ws?token=your-jwt-token');

// Connection events
ws.onopen = function(event) {
    console.log('Connected to PlexiChat WebSocket');
    
    // Subscribe to channels
    ws.send(JSON.stringify({
        type: 'subscribe',
        channels: ['channel_123', 'channel_456']
    }));
};

ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    console.log('Received:', data);
};

ws.onclose = function(event) {
    console.log('WebSocket connection closed');
};
```

### Message Types

#### Real-time Messages

```javascript
// Incoming message
{
  "type": "message",
  "data": {
    "id": "msg_123",
    "channel_id": "channel_123",
    "user_id": "user_456",
    "content": "Hello, world!",
    "created_at": "2025-01-15T10:30:00Z"
  }
}

// Send message via WebSocket
ws.send(JSON.stringify({
  type: 'send_message',
  data: {
    channel_id: 'channel_123',
    content: 'Hello from WebSocket!'
  }
}));
```

#### Typing Indicators

```javascript
// Start typing
ws.send(JSON.stringify({
  type: 'typing_start',
  channel_id: 'channel_123'
}));

// Stop typing
ws.send(JSON.stringify({
  type: 'typing_stop',
  channel_id: 'channel_123'
}));

// Receive typing indicator
{
  "type": "typing",
  "data": {
    "channel_id": "channel_123",
    "user_id": "user_456",
    "is_typing": true
  }
}
```

#### Presence Updates

```javascript
// User online/offline status
{
  "type": "presence",
  "data": {
    "user_id": "user_456",
    "status": "online",
    "last_seen": "2025-01-15T10:30:00Z"
  }
}
```

## Error Handling

### Error Response Format

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input data",
    "details": {
      "field": "email",
      "reason": "Invalid email format"
    },
    "request_id": "req_123456789",
    "timestamp": "2025-01-15T10:30:00Z"
  }
}
```

### Common Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `AUTHENTICATION_REQUIRED` | 401 | Authentication required |
| `INVALID_CREDENTIALS` | 401 | Invalid username/password |
| `TOKEN_EXPIRED` | 401 | JWT token expired |
| `INSUFFICIENT_PERMISSIONS` | 403 | Insufficient permissions |
| `RESOURCE_NOT_FOUND` | 404 | Resource not found |
| `VALIDATION_ERROR` | 422 | Input validation failed |
| `RATE_LIMIT_EXCEEDED` | 429 | Rate limit exceeded |
| `INTERNAL_SERVER_ERROR` | 500 | Internal server error |

## Rate Limiting

### Rate Limit Headers

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1642248000
X-RateLimit-Window: 60
```

### Rate Limits by Endpoint

| Endpoint Category | Limit | Window |
|------------------|-------|--------|
| Authentication | 10 requests | 1 minute |
| Messages | 100 requests | 1 minute |
| File Upload | 20 requests | 1 minute |
| Search | 50 requests | 1 minute |
| Admin | 200 requests | 1 minute |

### Rate Limit Exceeded Response

```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Rate limit exceeded",
    "retry_after": 60
  }
}
```

## SDKs and Libraries

### Python SDK

```python
from plexichat import PlexiChatClient

# Initialize client
client = PlexiChatClient(
    base_url="http://localhost:8000",
    api_key="your-api-key"
)

# Send message
message = client.messages.send(
    channel_id="channel_123",
    content="Hello from Python!"
)

# Upload file
with open("document.pdf", "rb") as f:
    file = client.files.upload(
        file=f,
        channel_id="channel_123",
        filename="document.pdf"
    )

# AI chat
response = client.ai.chat(
    message="Summarize recent activity",
    context={"channel_id": "channel_123"}
)
```

### JavaScript SDK

```javascript
import { PlexiChatClient } from '@plexichat/sdk';

// Initialize client
const client = new PlexiChatClient({
  baseUrl: 'http://localhost:8000',
  apiKey: 'your-api-key'
});

// Send message
const message = await client.messages.send({
  channelId: 'channel_123',
  content: 'Hello from JavaScript!'
});

// Real-time connection
const ws = client.connect();
ws.on('message', (message) => {
  console.log('New message:', message);
});
```

## Examples

### Complete Chat Application

```python
import asyncio
import websockets
import json
from plexichat import PlexiChatClient

class ChatApp:
    def __init__(self, api_key):
        self.client = PlexiChatClient(
            base_url="http://localhost:8000",
            api_key=api_key
        )
        self.ws = None
    
    async def connect(self):
        # Connect to WebSocket
        self.ws = await websockets.connect(
            f"ws://localhost:8000/ws?token={self.client.api_key}"
        )
        
        # Subscribe to channels
        await self.ws.send(json.dumps({
            "type": "subscribe",
            "channels": ["general"]
        }))
        
        # Listen for messages
        async for message in self.ws:
            data = json.loads(message)
            await self.handle_message(data)
    
    async def handle_message(self, data):
        if data["type"] == "message":
            msg = data["data"]
            print(f"{msg['user_id']}: {msg['content']}")
    
    async def send_message(self, content):
        await self.ws.send(json.dumps({
            "type": "send_message",
            "data": {
                "channel_id": "general",
                "content": content
            }
        }))

# Usage
app = ChatApp("your-api-key")
asyncio.run(app.connect())
```

---

This API reference provides comprehensive documentation for integrating with PlexiChat. For more examples and advanced usage, see the interactive documentation at `/docs`.
