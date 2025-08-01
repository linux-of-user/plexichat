# PlexiChat Client Settings Management

## Overview

The Client Settings Management system provides a flexible, secure way for users to store and manage their application preferences, configuration data, and images. It supports both key-value settings and file uploads with comprehensive validation and security features.

## Features

- **Key-Value Storage**: Store user preferences as key-value pairs
- **Image Management**: Upload and manage user images (avatars, backgrounds, etc.)
- **Bulk Operations**: Update multiple settings in a single request
- **Validation**: Comprehensive input validation and sanitization
- **Security**: User isolation, authentication, and authorization
- **Limits**: Configurable storage and usage limits
- **Statistics**: Usage tracking and reporting

## Configuration Limits

The system enforces the following default limits:

| Setting | Default Value | Description |
|---------|---------------|-------------|
| `max_key_value_pairs` | 100 | Maximum number of settings per user |
| `max_key_length` | 255 | Maximum length of setting keys |
| `max_value_length` | 10,000 | Maximum length of setting values |
| `max_images_per_user` | 5 | Maximum number of images per user |
| `max_image_size_mb` | 10.0 | Maximum size per image in MB |
| `max_total_storage_mb` | 50.0 | Maximum total storage per user in MB |
| `allowed_image_types` | JPEG, PNG, GIF | Supported image formats |

## API Usage Examples

### Basic Settings Management

```bash
# Get configuration limits
curl -X GET http://localhost:8000/api/v1/client-settings/config/limits

# List all user settings (requires authentication)
curl -X GET http://localhost:8000/api/v1/client-settings/ \
  -H "Authorization: Bearer YOUR_TOKEN"

# Set a single setting
curl -X PUT http://localhost:8000/api/v1/client-settings/theme \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"value": "dark"}'

# Get a specific setting
curl -X GET http://localhost:8000/api/v1/client-settings/theme \
  -H "Authorization: Bearer YOUR_TOKEN"

# Delete a setting
curl -X DELETE http://localhost:8000/api/v1/client-settings/theme \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Bulk Operations

```bash
# Update multiple settings at once
curl -X POST http://localhost:8000/api/v1/client-settings/bulk-update \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "settings": {
      "theme": "dark",
      "notifications": "enabled",
      "language": "en",
      "font_size": "14"
    }
  }'
```

### Image Management

```bash
# Upload an image
curl -X POST http://localhost:8000/api/v1/client-settings/images/ \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "file=@avatar.jpg" \
  -F "description=User avatar"

# List all images
curl -X GET http://localhost:8000/api/v1/client-settings/images/ \
  -H "Authorization: Bearer YOUR_TOKEN"

# Download an image
curl -X GET http://localhost:8000/api/v1/client-settings/images/img_123 \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -o downloaded_image.jpg

# Delete an image
curl -X DELETE http://localhost:8000/api/v1/client-settings/images/img_123 \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Statistics

```bash
# Get usage statistics
curl -X GET http://localhost:8000/api/v1/client-settings/stats/ \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## Common Use Cases

### User Preferences
Store application preferences like theme, language, notification settings:

```json
{
  "theme": "dark",
  "language": "en",
  "notifications": "enabled",
  "sound_enabled": "true",
  "auto_save": "true"
}
```

### UI Configuration
Store interface layout and customization:

```json
{
  "sidebar_collapsed": "false",
  "font_size": "14",
  "layout_mode": "grid",
  "show_timestamps": "true"
}
```

### Application State
Store user-specific application state:

```json
{
  "last_active_chat": "chat_123",
  "draft_message": "Hello, how are you?",
  "selected_filters": "unread,important"
}
```

## Security Features

- **User Isolation**: Each user can only access their own settings
- **Authentication Required**: All endpoints except config limits require valid JWT tokens
- **Input Validation**: All inputs are validated and sanitized
- **File Type Validation**: Only allowed image types can be uploaded
- **Size Limits**: Enforced limits prevent abuse and resource exhaustion
- **SQL Injection Protection**: Parameterized queries prevent SQL injection

## Error Handling

The API returns appropriate HTTP status codes and error messages:

- `200 OK`: Successful operation
- `201 Created`: Resource created successfully
- `400 Bad Request`: Invalid input or validation error
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: Access denied
- `404 Not Found`: Resource not found
- `413 Payload Too Large`: File or data too large
- `422 Unprocessable Entity`: Validation error
- `500 Internal Server Error`: Server error

Example error response:
```json
{
  "error": {
    "code": 400,
    "message": "Setting key too long",
    "details": "Key length must be 255 characters or less",
    "api_version": "v1",
    "timestamp": "2025-07-27T15:30:00Z"
  }
}
```

## Testing

The system includes comprehensive test coverage:

```bash
# Run client settings tests
python run.py test run_tests --categories client_settings

# Run all API tests
python run.py test run_tests --categories api

# Run integration tests
python run.py test run_tests --categories integration
```

## Implementation Details

The Client Settings system is implemented with:

- **FastAPI**: Modern, fast web framework for building APIs
- **Pydantic**: Data validation and settings management
- **SQLAlchemy**: Database ORM for data persistence
- **JWT Authentication**: Secure token-based authentication
- **File Upload Handling**: Secure file upload with validation
- **Fallback Support**: Graceful degradation when dependencies are missing

## Future Enhancements

Planned improvements include:

- **Encryption**: End-to-end encryption for sensitive settings
- **Versioning**: Setting history and rollback capabilities
- **Sharing**: Share settings between users or devices
- **Backup**: Automatic backup and restore functionality
- **Templates**: Predefined setting templates for common use cases
- **Real-time Sync**: Real-time synchronization across devices
