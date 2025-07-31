# PlexiChat API Reference

## Overview

PlexiChat provides a comprehensive REST API for managing users, messages, files, and client settings. The API follows RESTful conventions and uses JSON for data exchange.

**Base URL:** `http://localhost:8000/api/v1/`
**Authentication:** Bearer token (JWT)
**Content-Type:** `application/json`

## API Endpoints Summary

| Category | Endpoint | Description |
|----------|----------|-------------|
| **Core** | `/api/v1/` | API information and available endpoints |
| **Authentication** | `/api/v1/auth/` | User authentication and token management |
| **Users** | `/api/v1/users/` | User management and profiles |
| **Messages** | `/api/v1/messages/` | Messaging functionality |
| **Files** | `/api/v1/files/` | File upload and management |
| **Client Settings** | `/api/v1/client-settings/` | User preferences and configuration |
| **Admin** | `/api/v1/admin/` | Administrative functions |
| **System** | `/api/v1/system/` | System status and monitoring |

## Client Settings API

The Client Settings API provides flexible key-value storage for user preferences, configuration data, and images.

### Configuration Limits

#### GET `/api/v1/client-settings/config/limits`
Get configuration limits and allowed values.

**Authentication:** None required
**Response:**
```json
{
  "max_key_value_pairs": 100,
  "max_key_length": 255,
  "max_value_length": 10000,
  "max_images_per_user": 5,
  "max_image_size_mb": 10.0,
  "max_total_storage_mb": 50.0,
  "allowed_image_types": ["image/jpeg", "image/png", "image/gif"]
}
```

### Settings Management

#### GET `/api/v1/client-settings/`
List all settings for the authenticated user.

**Authentication:** Required
**Response:**
```json
{
  "settings": {
    "theme": "dark",
    "notifications": "enabled",
    "language": "en"
  },
  "count": 3,
  "last_updated": "2025-07-27T15:30:00Z"
}
```

#### GET `/api/v1/client-settings/{setting_key}`
Get a specific setting value.

**Authentication:** Required
**Parameters:**
- `setting_key` (path): The setting key to retrieve

**Response:**
```json
{
  "key": "theme",
  "value": "dark",
  "created_at": "2025-07-27T15:30:00Z",
  "updated_at": "2025-07-27T15:30:00Z"
}
```

#### PUT `/api/v1/client-settings/{setting_key}`
Create or update a setting.

**Authentication:** Required
**Parameters:**
- `setting_key` (path): The setting key to update

**Request Body:**
```json
{
  "value": "light"
}
```

**Response:**
```json
{
  "key": "theme",
  "value": "light",
  "created_at": "2025-07-27T15:30:00Z",
  "updated_at": "2025-07-27T15:35:00Z"
}
```

#### DELETE `/api/v1/client-settings/{setting_key}`
Delete a specific setting.

**Authentication:** Required
**Parameters:**
- `setting_key` (path): The setting key to delete

**Response:**
```json
{
  "message": "Setting deleted successfully",
  "key": "theme"
}
```

### Bulk Operations

#### POST `/api/v1/client-settings/bulk-update`
Update multiple settings in a single request.

**Authentication:** Required
**Request Body:**
```json
{
  "settings": {
    "theme": "dark",
    "notifications": "enabled",
    "language": "en",
    "font_size": "14"
  }
}
```

**Response:**
```json
{
  "updated": 4,
  "failed": 0,
  "settings": {
    "theme": "dark",
    "notifications": "enabled",
    "language": "en",
    "font_size": "14"
  }
}
```

### Image Management

#### GET `/api/v1/client-settings/images/`
List all images for the authenticated user.

**Authentication:** Required
**Response:**
```json
{
  "images": [
    {
      "id": "img_123",
      "filename": "avatar.jpg",
      "size_mb": 2.5,
      "content_type": "image/jpeg",
      "uploaded_at": "2025-07-27T15:30:00Z"
    }
  ],
  "count": 1,
  "total_size_mb": 2.5
}
```

#### POST `/api/v1/client-settings/images/`
Upload a new image.

**Authentication:** Required
**Content-Type:** `multipart/form-data`
**Form Data:**
- `file`: Image file (JPEG, PNG, or GIF)
- `description` (optional): Image description

**Response:**
```json
{
  "id": "img_124",
  "filename": "profile.png",
  "size_mb": 1.8,
  "content_type": "image/png",
  "uploaded_at": "2025-07-27T15:35:00Z",
  "url": "/api/v1/client-settings/images/img_124"
}
```

#### GET `/api/v1/client-settings/images/{image_id}`
Retrieve a specific image.

**Authentication:** Required
**Parameters:**
- `image_id` (path): The image ID to retrieve

**Response:** Binary image data with appropriate Content-Type header

#### DELETE `/api/v1/client-settings/images/{image_id}`
Delete a specific image.

**Authentication:** Required
**Parameters:**
- `image_id` (path): The image ID to delete

**Response:**
```json
{
  "message": "Image deleted successfully",
  "id": "img_124"
}
```

### Statistics

#### GET `/api/v1/client-settings/stats/`
Get usage statistics for the authenticated user.

**Authentication:** Required
**Response:**
```json
{
  "total_settings": 5,
  "total_images": 2,
  "storage_used_mb": 4.3,
  "storage_limit_mb": 50.0,
  "last_activity": "2025-07-27T15:35:00Z"
}
```

## Setup Wizard Endpoints

### GET /setup/
- **Description:** Setup home page (HTML)
- **Auth:** Admin token required

### GET /setup/database
- **Description:** Database setup page (HTML)
- **Auth:** Admin token required

### POST /setup/database
- **Description:** Submit database configuration
- **Auth:** None
- **Form fields:** db_type, db_host, db_port, db_name, db_username, db_password

### GET /setup/admin
- **Description:** Admin account setup page (HTML)
- **Auth:** None

### POST /setup/admin
- **Description:** Create admin account
- **Auth:** None
- **Form fields:** username, password, confirm_password, email

### GET /setup/complete
- **Description:** Setup completion page (HTML)
- **Auth:** None

## SSL/HTTPS Endpoints

### GET /setup/ssl/check_software
- **Description:** Check if certbot is installed
- **Auth:** None

### POST /setup/ssl/generate_self_signed
- **Description:** Generate a self-signed certificate
- **Form fields:** domain

### POST /setup/ssl/lets_encrypt
- **Description:** Request a Let's Encrypt certificate
- **Form fields:** domain, email

### POST /setup/ssl/upload
- **Description:** Upload custom certificate and key
- **Form fields:** cert_file, key_file, domain

### GET /setup/ssl/list
- **Description:** List all managed certificates

### POST /setup/ssl/renew
- **Description:** Renew a Let's Encrypt certificate
- **Form fields:** domain

## Custom Field Endpoints

### POST /setup/user/{user_id}/custom_field
- **Description:** Add or update a custom field for a user
- **Body:** field_name, field_value, field_type

### GET /setup/user/{user_id}/custom_fields
- **Description:** Get all custom fields for a user

### DELETE /setup/user/{user_id}/custom_field
- **Description:** Remove a custom field from a user
- **Query:** field_name

### GET /setup/user/{user_id}
- **Description:** Get user info with type-safe custom fields

### POST /setup/message/{message_id}/custom_field
- **Description:** Add or update a custom field for a message
- **Body:** field_name, field_value, field_type

### GET /setup/message/{message_id}/custom_fields
- **Description:** Get all custom fields for a message

### DELETE /setup/message/{message_id}/custom_field
- **Description:** Remove a custom field from a message
- **Query:** field_name

### GET /setup/message/{message_id}
- **Description:** Get message info with type-safe custom fields

## Custom Field Type Management (Admin)

### GET /setup/admin/custom_field_types/user
- **Description:** List allowed user custom field types

### POST /setup/admin/custom_field_types/user
- **Description:** Add a user custom field type
- **Body:** field_type

### DELETE /setup/admin/custom_field_types/user
- **Description:** Remove a user custom field type
- **Query:** field_type

### GET /setup/admin/custom_field_types/message
- **Description:** List allowed message custom field types

### POST /setup/admin/custom_field_types/message
- **Description:** Add a message custom field type
- **Body:** field_type

### DELETE /setup/admin/custom_field_types/message
- **Description:** Remove a message custom field type
- **Query:** field_type

## Secure Admin Endpoint

### POST /setup/admin/secure
- **Description:** Example secure admin endpoint (encrypted payload)
- **Body:** Encrypted JSON
