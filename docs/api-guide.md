# API Guide

NetLink provides a comprehensive RESTful API for all administrative functions.

## Authentication

All API endpoints require authentication using session cookies or API keys.

### Login
```http
POST /auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "your_password"
}
```

## API Endpoints

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
