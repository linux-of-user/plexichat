-- PlexiChat Client Settings Tables Migration
-- ============================================
-- 
-- This migration adds tables for the client settings system:
-- - client_settings: Key-value storage for user settings
-- - client_setting_images: Image storage for user settings

-- Create client_settings table
CREATE TABLE IF NOT EXISTS client_settings (
    user_id VARCHAR(36) NOT NULL,
    setting_key VARCHAR(255) NOT NULL,
    setting_value TEXT,
    setting_type VARCHAR(50) DEFAULT 'text',
    description VARCHAR(500),
    is_encrypted BOOLEAN DEFAULT FALSE,
    is_public BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    PRIMARY KEY (user_id, setting_key),
    INDEX idx_client_settings_user_id (user_id),
    INDEX idx_client_settings_type (setting_type),
    INDEX idx_client_settings_public (is_public)
);

-- Create client_setting_images table
CREATE TABLE IF NOT EXISTS client_setting_images (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    setting_key VARCHAR(255),
    original_filename VARCHAR(255) NOT NULL,
    stored_filename VARCHAR(255) NOT NULL,
    file_path VARCHAR(500) NOT NULL,
    mime_type VARCHAR(100) NOT NULL,
    file_size INTEGER NOT NULL,
    width INTEGER,
    height INTEGER,
    status VARCHAR(20) DEFAULT 'active',
    description VARCHAR(500),
    alt_text VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    INDEX idx_client_images_user_id (user_id),
    INDEX idx_client_images_setting_key (setting_key),
    INDEX idx_client_images_status (status)
);

-- Add foreign key constraints if users table exists
-- Note: These will be added conditionally based on existing schema

-- Insert default configuration settings
INSERT IGNORE INTO client_settings (user_id, setting_key, setting_value, setting_type, description, is_public) VALUES
('system', 'max_key_value_pairs', '100', 'number', 'Maximum number of key-value pairs per user', TRUE),
('system', 'max_key_length', '255', 'number', 'Maximum length of setting keys', TRUE),
('system', 'max_value_length', '10000', 'number', 'Maximum length of setting values', TRUE),
('system', 'max_images_per_user', '5', 'number', 'Maximum number of images per user', TRUE),
('system', 'max_image_size_mb', '10.0', 'number', 'Maximum image size in MB', TRUE),
('system', 'max_total_storage_mb', '50.0', 'number', 'Maximum total storage per user in MB', TRUE);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_client_settings_updated_at ON client_settings(updated_at);
CREATE INDEX IF NOT EXISTS idx_client_images_created_at ON client_setting_images(created_at);

-- Add comments to tables
ALTER TABLE client_settings COMMENT = 'Flexible key-value storage for client settings';
ALTER TABLE client_setting_images COMMENT = 'Image storage for client settings';

-- Migration complete
SELECT 'Client settings tables created successfully' AS migration_status;
