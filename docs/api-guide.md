# PlexiChat API Guide

PlexiChat provides a comprehensive RESTful API for all administrative functions. This guide covers practical examples and best practices for using the PlexiChat API va.1.1-1.

## API Versioning

PlexiChat provides three API endpoints:

- **Stable API** (`/api`) - Production-ready, version r.1.0-1
- **Current API** (`/api/v1`) - Latest features, version a.1.1-1
- **Beta API** (`/api/beta`) - Experimental features, version b.1.2-1

Choose the appropriate endpoint based on your needs:
- Use `/api` for production applications requiring stability
- Use `/api/v1` for access to latest features
- Use `/api/beta` for experimental features (may change)

## Authentication

All API endpoints require authentication using session cookies or API keys.

### Login
```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "your_password",
  "remember_me": false,
  "device_info": {
    "device_type": "web",
    "user_agent": "Mozilla/5.0..."
  }
}
```

**Response:**
```json
{
  "success": true,
  "message": "Login successful",
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600,
  "user": {
    "id": 1,
    "username": "admin",
    "email": "admin@plexichat.local",
    "is_admin": true,
    "is_active": true
  },
  "session_id": "session_1_1720540800"
}
```

## Enhanced API Endpoints

### Messages (Enhanced)

#### Send Message
```http
POST /api/v1/messages
Authorization: Bearer {token}
Content-Type: application/json

{
  "recipient_id": 2,
  "content": "Hello, world! 👋",
  "message_type": "DEFAULT"
}
```

#### List Messages with Advanced Filtering
```http
GET /api/v1/messages?limit=20&conversation_with=2&search=hello&since=2025-07-01T00:00:00Z
Authorization: Bearer {token}
```

**Response:**
```json
{
  "messages": [
    {
      "id": 123,
      "sender_id": 1,
      "recipient_id": 2,
      "content": "Hello, world! 👋",
      "timestamp": "2025-07-09T12:00:00Z",
      "edited_timestamp": null
    }
  ],
  "total": 1250,
  "limit": 20,
  "offset": 0,
  "has_more": true,
  "next_cursor": "2025-07-09T12:00:00Z_123",
  "filters_applied": {
    "conversation_with": 2,
    "search": "hello"
  }
}
```

#### Search Messages
```http
GET /api/v1/messages/search?q=hello%20world&limit=10
Authorization: Bearer {token}
```

#### Message Statistics
```http
GET /api/v1/messages/stats
Authorization: Bearer {token}
```

**Response:**
```json
{
  "total_messages": 1250,
  "messages_sent": 800,
  "messages_received": 450,
  "today_count": 25,
  "this_week_count": 180,
  "this_month_count": 750,
  "average_per_day": 25.0,
  "most_active_hour": 14
}
```

### Collaboration Features

#### Update Presence Status
```http
POST /api/v1/collaboration/presence/status
Authorization: Bearer {token}
Content-Type: application/json

{
  "status": "online",
  "custom_message": "Working on PlexiChat",
  "activity": {
    "type": "editing",
    "context": "api_documentation"
  }
}
```

#### Typing Indicators
```http
POST /api/v1/collaboration/presence/typing
Authorization: Bearer {token}
Content-Type: application/json

{
  "conversation_id": "conv_123",
  "is_typing": true
}
```

### Updates System

#### Check for Updates
```http
GET /api/v1/updates/check
Authorization: Bearer {admin_token}
```

**Response:**
```json
{
  "update_available": true,
  "current_version": "a.1.1-1",
  "latest_version": "a.1.2-1",
  "release_notes": "Enhanced collaboration features...",
  "published_at": "2025-07-09T12:00:00Z",
  "is_major_update": false,
  "is_security_update": false,
  "download_url": "https://github.com/linux-of-user/plexichat/archive/a.1.2-1.zip",
  "file_size": 15728640
}
```

#### Install Update
```http
POST /api/v1/updates/install
Authorization: Bearer {admin_token}
```

### Admin Accounts
- `GET /api/v1/admin/accounts` - List all admin accounts
- `POST /api/v1/admin/accounts` - Create new admin account
- `GET /api/v1/admin/accounts/{username}` - Get specific account
- `PUT /api/v1/admin/accounts/{username}` - Update account
- `DELETE /api/v1/admin/accounts/{username}` - Delete account

### System Management
- `GET /api/v1/admin/system/status` - Get system status
- `POST /api/v1/admin/system/command` - Execute system command
- `GET /api/v1/admin/config` - Get configuration
- `PUT /api/v1/admin/config` - Update configuration

### User Profile
- `GET /api/v1/admin/profile` - Get current user profile
- `PUT /api/v1/admin/profile` - Update profile
- `POST /api/v1/admin/profile/change-password` - Change password

## Response Format

All API responses follow this format:

```json
{
  "success": true,
  "data": {...},
  "message": "Operation completed successfully",
  "timestamp": "2025-06-29T12:00:00Z"
}
```

## Error Handling

Error responses include detailed error information:

```json
{
  "success": false,
  "error": "Invalid credentials",
  "error_code": "AUTH_FAILED",
  "details": {...}
}
```

## Rate Limiting

API endpoints are rate limited:
- 100 requests per minute for authenticated users
- 10 requests per minute for unauthenticated requests

## Examples

### Create Admin Account
```bash
curl -X POST "http://localhost:8000/api/v1/admin/accounts" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newadmin",
    "email": "admin@example.com",
    "password": "SecurePassword123!",
    "role": "admin",
    "permissions": ["view", "manage_users"]
  }'
```

### Get System Status
```bash
curl -X GET "http://localhost:8000/api/v1/admin/system/status" \
  -H "Authorization: Bearer your_session_token"
```
