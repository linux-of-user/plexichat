"""
Additional migrations for typing indicator optimizations.

This module contains database migrations to optimize typing indicator performance.
"""

from plexichat.core.database.migrations import create_migration

# Migration to add performance indexes for typing indicators
create_migration(
    "003_optimize_typing_indexes",
    "Add performance indexes for typing indicator queries",
    """
    -- Add composite index for channel + started_at queries (used in get_typing_users)
    CREATE INDEX IF NOT EXISTS idx_typing_status_channel_started ON typing_status(channel_id, started_at);

    -- Add composite index for user + channel + expires_at queries (used in _get_user_typing_status)
    CREATE INDEX IF NOT EXISTS idx_typing_status_user_channel_expires ON typing_status(user_id, channel_id, expires_at);

    -- Add index for cleanup queries that filter by expires_at
    CREATE INDEX IF NOT EXISTS idx_typing_status_cleanup ON typing_status(expires_at, id);

    -- Add partial index for active typing statuses only
    CREATE INDEX IF NOT EXISTS idx_typing_status_active ON typing_status(channel_id, started_at)
    WHERE expires_at > datetime('now');
    """,
    """
    DROP INDEX IF EXISTS idx_typing_status_channel_started;
    DROP INDEX IF EXISTS idx_typing_status_user_channel_expires;
    DROP INDEX IF EXISTS idx_typing_status_cleanup;
    DROP INDEX IF EXISTS idx_typing_status_active;
    """,
)


# Migration to add background cleanup scheduling
create_migration(
    "004_add_typing_cleanup_scheduler",
    "Add scheduler table for typing cleanup tasks",
    """
    CREATE TABLE IF NOT EXISTS typing_cleanup_schedule (
        id TEXT PRIMARY KEY,
        last_run TEXT,
        next_run TEXT,
        interval_seconds INTEGER DEFAULT 30,
        enabled BOOLEAN DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );

    -- Insert default cleanup schedule (runs every 30 seconds)
    INSERT OR IGNORE INTO typing_cleanup_schedule
    (id, last_run, next_run, interval_seconds, enabled, created_at, updated_at)
    VALUES (
        'default_cleanup',
        NULL,
        datetime('now'),
        30,
        1,
        datetime('now'),
        datetime('now')
    );

    CREATE INDEX IF NOT EXISTS idx_typing_cleanup_schedule_next_run ON typing_cleanup_schedule(next_run);
    """,
    """
    DROP TABLE IF EXISTS typing_cleanup_schedule;
    """,
)


# Migration to add typing configuration table
create_migration(
    "005_add_typing_configuration",
    "Add configuration table for typing indicator settings",
    """
    CREATE TABLE IF NOT EXISTS typing_config (
        id TEXT PRIMARY KEY,
        key TEXT UNIQUE NOT NULL,
        value TEXT NOT NULL,
        description TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );

    -- Insert default configuration values
    INSERT OR IGNORE INTO typing_config (id, key, value, description, created_at, updated_at)
    VALUES
        ('timeout', 'TYPING_TIMEOUT_SECONDS', '3.0', 'Default typing timeout in seconds', datetime('now'), datetime('now')),
        ('cleanup_interval', 'CLEANUP_INTERVAL_SECONDS', '30', 'Background cleanup interval in seconds', datetime('now'), datetime('now')),
        ('max_concurrent_typing', 'MAX_CONCURRENT_TYPING', '100', 'Maximum concurrent typing users per channel', datetime('now'), datetime('now')),
        ('debounce_delay', 'TYPING_DEBOUNCE_DELAY', '0.5', 'Debounce delay for typing events in seconds', datetime('now'), datetime('now'));

    CREATE INDEX IF NOT EXISTS idx_typing_config_key ON typing_config(key);
    """,
    """
    DROP TABLE IF EXISTS typing_config;
    """,
)


# Migration to add typing cache table
create_migration(
    "006_add_typing_cache",
    "Add cache table for frequently accessed typing data",
    """
    CREATE TABLE IF NOT EXISTS typing_cache (
        cache_key TEXT PRIMARY KEY,
        cache_value TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL,
        hits INTEGER DEFAULT 0,
        last_accessed TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_typing_cache_expires ON typing_cache(expires_at);
    CREATE INDEX IF NOT EXISTS idx_typing_cache_hits ON typing_cache(hits DESC, last_accessed);
    """,
    """
    DROP TABLE IF EXISTS typing_cache;
    """,
)


# Migration to add typing metrics table for monitoring
create_migration(
    "007_add_typing_metrics",
    "Add metrics table for typing indicator monitoring",
    """
    CREATE TABLE IF NOT EXISTS typing_metrics (
        id TEXT PRIMARY KEY,
        metric_type TEXT NOT NULL,
        channel_id TEXT,
        user_id TEXT,
        value INTEGER,
        timestamp TEXT NOT NULL,
        metadata TEXT DEFAULT '{}'
    );

    CREATE INDEX IF NOT EXISTS idx_typing_metrics_type_timestamp ON typing_metrics(metric_type, timestamp);
    CREATE INDEX IF NOT EXISTS idx_typing_metrics_channel ON typing_metrics(channel_id, timestamp);
    """,
    """
    DROP TABLE IF EXISTS typing_metrics;
    """,
)
