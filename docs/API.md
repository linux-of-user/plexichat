# PlexiChat Setup API Reference

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
