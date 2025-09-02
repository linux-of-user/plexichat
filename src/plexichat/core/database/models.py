"""
Database Models

Base model classes and table management utilities.
"""

import logging
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4

from plexichat.core.database.manager import database_manager

logger = logging.getLogger(__name__)


@dataclass
class BaseModel:
    """Base model for database entities."""
    id: str = field(default_factory=lambda: str(uuid4()))
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def update_timestamp(self):
        """Update the updated_at timestamp."""
        self.updated_at = datetime.now(timezone.utc)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary."""
        result = {}
        for key, value in self.__dict__.items():
            if isinstance(value, datetime):
                result[key] = value.isoformat()
            else:
                result[key] = value
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]):
        """Create model from dictionary."""
        # Convert datetime strings back to datetime objects
        for key, value in data.items():
            if key.endswith('_at') and isinstance(value, str):
                try:
                    data[key] = datetime.fromisoformat(value.replace('Z', '+00:00'))
                except ValueError:
                    pass
        
        return cls(**data)


# Common table schemas
USER_SCHEMA = {
    "id": "TEXT PRIMARY KEY",
    "username": "TEXT UNIQUE NOT NULL",
    "email": "TEXT UNIQUE NOT NULL",
    "display_name": "TEXT",
    "password_hash": "TEXT",
    "is_active": "BOOLEAN DEFAULT TRUE",
    "is_admin": "BOOLEAN DEFAULT FALSE",
    "status": "TEXT DEFAULT 'offline'",
    "status_updated_at": "TEXT",
    "custom_status": "TEXT",
    "created_at": "TEXT NOT NULL",
    "updated_at": "TEXT NOT NULL",
    "last_login": "TEXT",
    "preferences": "TEXT DEFAULT '{}'",
    "metadata": "TEXT DEFAULT '{}'"
}

MESSAGE_SCHEMA = {
    "id": "TEXT PRIMARY KEY",
    "content": "TEXT NOT NULL",
    "user_id": "TEXT NOT NULL",
    "channel_id": "TEXT",
    "message_type": "TEXT DEFAULT 'text'",
    "attachments": "TEXT DEFAULT '[]'",
    "reactions": "TEXT DEFAULT '{}'",
    "thread_id": "TEXT",
    "reply_to": "TEXT",
    "created_at": "TEXT NOT NULL",
    "updated_at": "TEXT NOT NULL",
    "edited_at": "TEXT",
    "deleted_at": "TEXT",
    "metadata": "TEXT DEFAULT '{}'"
}
THREAD_SCHEMA = {
    "id": "TEXT PRIMARY KEY",
    "title": "TEXT NOT NULL",
    "channel_id": "TEXT NOT NULL",
    "creator_id": "TEXT NOT NULL",
    "parent_message_id": "TEXT",
    "is_resolved": "BOOLEAN DEFAULT FALSE",
    "participant_count": "INTEGER DEFAULT 1",
    "message_count": "INTEGER DEFAULT 0",
    "last_message_at": "TEXT",
    "created_at": "TEXT NOT NULL",
    "updated_at": "TEXT NOT NULL",
    "metadata": "TEXT DEFAULT '{}'"
}


CHANNEL_SCHEMA = {
    "id": "TEXT PRIMARY KEY",
    "name": "TEXT NOT NULL",
    "description": "TEXT",
    "channel_type": "TEXT DEFAULT 'public'",
    "owner_id": "TEXT NOT NULL",
    "members": "TEXT DEFAULT '[]'",
    "settings": "TEXT DEFAULT '{}'",
    "is_archived": "BOOLEAN DEFAULT FALSE",
    "created_at": "TEXT NOT NULL",
    "updated_at": "TEXT NOT NULL",
    "metadata": "TEXT DEFAULT '{}'"
}

SESSION_SCHEMA = {
    "id": "TEXT PRIMARY KEY",
    "user_id": "TEXT NOT NULL",
    "session_token": "TEXT UNIQUE NOT NULL",
    "expires_at": "TEXT NOT NULL",
    "ip_address": "TEXT",
    "user_agent": "TEXT",
    "is_active": "BOOLEAN DEFAULT TRUE",
    "last_activity": "TEXT NOT NULL",
    "created_at": "TEXT NOT NULL",
    "updated_at": "TEXT NOT NULL",
    "metadata": "TEXT DEFAULT '{}'",
    "permissions": "TEXT DEFAULT '[]'",
    "roles": "TEXT DEFAULT '[]'",
    "device_info": "TEXT DEFAULT '{}'",
    "auth_provider": "TEXT DEFAULT 'local'",
    "mfa_verified": "BOOLEAN DEFAULT FALSE",
    "risk_score": "REAL DEFAULT 0.0"
}

DEVICE_SCHEMA = {
    "id": "TEXT PRIMARY KEY",
    "device_id": "TEXT UNIQUE NOT NULL",
    "user_id": "TEXT NOT NULL",
    "device_type": "TEXT NOT NULL",
    "os": "TEXT",
    "browser": "TEXT",
    "version": "TEXT",
    "is_trusted": "BOOLEAN DEFAULT FALSE",
    "first_seen": "TEXT NOT NULL",
    "last_seen": "TEXT NOT NULL",
    "created_at": "TEXT NOT NULL",
    "updated_at": "TEXT NOT NULL",
    "metadata": "TEXT DEFAULT '{}'"
}

MFA_CHALLENGE_SCHEMA = {
    "id": "TEXT PRIMARY KEY",
    "challenge_id": "TEXT UNIQUE NOT NULL",
    "user_id": "TEXT NOT NULL",
    "method": "TEXT NOT NULL",
    "code": "TEXT",
    "expires_at": "TEXT NOT NULL",
    "attempts": "INTEGER DEFAULT 0",
    "max_attempts": "INTEGER DEFAULT 3",
    "is_verified": "BOOLEAN DEFAULT FALSE",
    "created_at": "TEXT NOT NULL",
    "updated_at": "TEXT NOT NULL",
    "metadata": "TEXT DEFAULT '{}'"
}

PLUGIN_SCHEMA = {
    "id": "TEXT PRIMARY KEY",
    "name": "TEXT UNIQUE NOT NULL",
    "version": "TEXT NOT NULL",
    "description": "TEXT",
    "author": "TEXT",
    "plugin_type": "TEXT DEFAULT 'feature'",
    "security_level": "TEXT DEFAULT 'sandboxed'",
    "status": "TEXT DEFAULT 'discovered'",
    "config": "TEXT DEFAULT '{}'",
    "dependencies": "TEXT DEFAULT '[]'",
    "permissions": "TEXT DEFAULT '[]'",
    "created_at": "TEXT NOT NULL",
    "updated_at": "TEXT NOT NULL",
    "installed_at": "TEXT",
    "last_error": "TEXT",
    "metadata": "TEXT DEFAULT '{}'"
}

EVENT_SCHEMA = {
    "id": "TEXT PRIMARY KEY",
    "event_type": "TEXT NOT NULL",
    "source": "TEXT NOT NULL",
    "priority": "TEXT DEFAULT 'medium'",
    "status": "TEXT DEFAULT 'pending'",
    "data": "TEXT DEFAULT '{}'",
    "results": "TEXT DEFAULT '[]'",
    "processed": "BOOLEAN DEFAULT FALSE",
    "created_at": "TEXT NOT NULL",
    "updated_at": "TEXT NOT NULL",
    "processed_at": "TEXT",
    "metadata": "TEXT DEFAULT '{}'"
}

# New Schemas

CLIENT_SETTINGS_SCHEMA = {
    "id": "TEXT PRIMARY KEY",
    "user_id": "TEXT NOT NULL",
    "setting_key": "TEXT NOT NULL",
    "setting_value": "TEXT",
    "value_type": "TEXT DEFAULT 'json'",
    "is_encrypted": "BOOLEAN DEFAULT FALSE",
    "image_refs": "TEXT DEFAULT '[]'",
    "size_bytes": "INTEGER DEFAULT 0",
    "created_at": "TEXT NOT NULL",
    "updated_at": "TEXT NOT NULL",
    "metadata": "TEXT DEFAULT '{}'"
}

PLUGIN_PERMISSIONS_SCHEMA = {
    "id": "TEXT PRIMARY KEY",
    "plugin_id": "TEXT NOT NULL",
    "permission": "TEXT NOT NULL",
    "requested_by": "TEXT",
    "requested_at": "TEXT",
    "approved_by": "TEXT",
    "approved_at": "TEXT",
    "is_approved": "BOOLEAN DEFAULT FALSE",
    "scopes": "TEXT DEFAULT '[]'",
    "reason": "TEXT",
    "created_at": "TEXT NOT NULL",
    "updated_at": "TEXT NOT NULL",
    "metadata": "TEXT DEFAULT '{}'"
}

CLUSTER_NODES_SCHEMA = {
    "id": "TEXT PRIMARY KEY",
    "node_id": "TEXT UNIQUE NOT NULL",
    "hostname": "TEXT",
    "ip_address": "TEXT",
    "port": "INTEGER",
    "node_type": "TEXT DEFAULT 'general'",
    "status": "TEXT DEFAULT 'online'",
    "last_heartbeat": "TEXT",
    "metrics": "TEXT DEFAULT '{}'",
    "capabilities": "TEXT DEFAULT '[]'",
    "is_leader": "BOOLEAN DEFAULT FALSE",
    "created_at": "TEXT NOT NULL",
    "updated_at": "TEXT NOT NULL",
    "metadata": "TEXT DEFAULT '{}'"
}

BACKUP_METADATA_SCHEMA = {
    "id": "TEXT PRIMARY KEY",
    "backup_id": "TEXT UNIQUE NOT NULL",
    "node_id": "TEXT",
    "status": "TEXT DEFAULT 'pending'",
    "backup_type": "TEXT DEFAULT 'incremental'",
    "started_at": "TEXT",
    "completed_at": "TEXT",
    "size_bytes": "INTEGER DEFAULT 0",
    "shards": "TEXT DEFAULT '[]'",
    "encryption_algo": "TEXT DEFAULT 'aes-256-gcm'",
    "key_version": "TEXT",
    "checksum": "TEXT",
    "storage_location": "TEXT",
    "retention_days": "INTEGER DEFAULT 30",
    "verified": "BOOLEAN DEFAULT FALSE",
    "created_at": "TEXT NOT NULL",
    "updated_at": "TEXT NOT NULL",
    "metadata": "TEXT DEFAULT '{}'"
}
# Performance Monitoring Schemas
PERFORMANCE_METRICS_SCHEMA = {
    "id": "TEXT PRIMARY KEY",
    "metric_name": "TEXT NOT NULL",
    "metric_value": "REAL NOT NULL",
    "unit": "TEXT",
    "timestamp": "TEXT NOT NULL",
    "tags": "TEXT DEFAULT '{}'",
    "source": "TEXT DEFAULT 'system'",
    "retention_days": "INTEGER DEFAULT 30",
    "created_at": "TEXT NOT NULL",
    "updated_at": "TEXT NOT NULL",
    "metadata": "TEXT DEFAULT '{}'"
}

ALERT_RULES_SCHEMA = {
    "id": "TEXT PRIMARY KEY",
    "rule_name": "TEXT UNIQUE NOT NULL",
    "metric_name": "TEXT NOT NULL",
    "threshold": "REAL NOT NULL",
    "operator": "TEXT NOT NULL",
    "enabled": "BOOLEAN DEFAULT TRUE",
    "cooldown_seconds": "INTEGER DEFAULT 300",
    "severity": "TEXT DEFAULT 'warning'",
    "description": "TEXT",
    "notification_channels": "TEXT DEFAULT '[]'",
    "created_at": "TEXT NOT NULL",
    "updated_at": "TEXT NOT NULL",
    "metadata": "TEXT DEFAULT '{}'"
}

ALERTS_SCHEMA = {
    "id": "TEXT PRIMARY KEY",
    "rule_id": "TEXT NOT NULL",
    "rule_name": "TEXT NOT NULL",
    "metric_name": "TEXT NOT NULL",
    "metric_value": "REAL NOT NULL",
    "threshold": "REAL NOT NULL",
    "operator": "TEXT NOT NULL",
    "severity": "TEXT NOT NULL",
    "message": "TEXT NOT NULL",
    "status": "TEXT DEFAULT 'active'",
    "acknowledged": "BOOLEAN DEFAULT FALSE",
    "acknowledged_by": "TEXT",
    "acknowledged_at": "TEXT",
    "resolved_at": "TEXT",
    "notification_sent": "BOOLEAN DEFAULT FALSE",
    "created_at": "TEXT NOT NULL",
    "updated_at": "TEXT NOT NULL",
    "metadata": "TEXT DEFAULT '{}'"
}

PERFORMANCE_DASHBOARDS_SCHEMA = {
    "id": "TEXT PRIMARY KEY",
    "dashboard_name": "TEXT UNIQUE NOT NULL",
    "description": "TEXT",
    "config": "TEXT NOT NULL",
    "is_public": "BOOLEAN DEFAULT FALSE",
    "owner_id": "TEXT",
    "tags": "TEXT DEFAULT '[]'",
    "created_at": "TEXT NOT NULL",
    "updated_at": "TEXT NOT NULL",
    "metadata": "TEXT DEFAULT '{}'"
}

RESOURCE_TRACKING_SCHEMA = {
    "id": "TEXT PRIMARY KEY",
    "resource_type": "TEXT NOT NULL",
    "resource_name": "TEXT NOT NULL",
    "current_value": "REAL",
    "max_value": "REAL",
    "min_value": "REAL",
    "avg_value": "REAL",
    "unit": "TEXT",
    "timestamp": "TEXT NOT NULL",
    "period_seconds": "INTEGER DEFAULT 60",
    "created_at": "TEXT NOT NULL",
    "updated_at": "TEXT NOT NULL",
    "metadata": "TEXT DEFAULT '{}'"
}

# Typing Status Schema
TYPING_STATUS_SCHEMA = {
    "id": "TEXT PRIMARY KEY",
    "user_id": "TEXT NOT NULL",
    "channel_id": "TEXT NOT NULL",
    "started_at": "TEXT NOT NULL",
    "expires_at": "TEXT NOT NULL",
    "created_at": "TEXT NOT NULL",
    "updated_at": "TEXT NOT NULL",
    "metadata": "TEXT DEFAULT '{}'"
}
# Keyboard Shortcuts Schema
KEYBOARD_SHORTCUTS_SCHEMA = {
    "id": "TEXT PRIMARY KEY",
    "user_id": "TEXT NOT NULL",
    "shortcut_key": "TEXT NOT NULL",
    "action": "TEXT NOT NULL",
    "description": "TEXT",
    "is_custom": "BOOLEAN DEFAULT TRUE",
    "created_at": "TEXT NOT NULL",
    "updated_at": "TEXT NOT NULL",
    "metadata": "TEXT DEFAULT '{}'"
}


async def create_tables() -> bool:
    """Create all standard tables."""
    tables = {
        "users": USER_SCHEMA,
        "messages": MESSAGE_SCHEMA,
        "threads": THREAD_SCHEMA,
        "channels": CHANNEL_SCHEMA,
        "sessions": SESSION_SCHEMA,
        "devices": DEVICE_SCHEMA,
        "mfa_challenges": MFA_CHALLENGE_SCHEMA,
        "plugins": PLUGIN_SCHEMA,
        "events": EVENT_SCHEMA,
        # New tables
        "client_settings": CLIENT_SETTINGS_SCHEMA,
        "plugin_permissions": PLUGIN_PERMISSIONS_SCHEMA,
        "cluster_nodes": CLUSTER_NODES_SCHEMA,
        # Performance monitoring tables
        "performance_metrics": PERFORMANCE_METRICS_SCHEMA,
        "alert_rules": ALERT_RULES_SCHEMA,
        "alerts": ALERTS_SCHEMA,
        "performance_dashboards": PERFORMANCE_DASHBOARDS_SCHEMA,
        "resource_tracking": RESOURCE_TRACKING_SCHEMA,
        "backup_metadata": BACKUP_METADATA_SCHEMA,
        # Typing status table
        # Keyboard shortcuts table
        "keyboard_shortcuts": KEYBOARD_SHORTCUTS_SCHEMA,
        "typing_status": TYPING_STATUS_SCHEMA,
    }
    
    try:
        for table_name, schema in tables.items():
            success = await database_manager.ensure_table_exists(table_name, schema)
            if not success:
                logger.error(f"Failed to create table: {table_name}")
                return False
        
        logger.info("All tables created successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to create tables: {e}")
        return False


async def drop_tables(table_names: Optional[List[str]] = None) -> bool:
    """Drop specified tables or all tables."""
    if table_names is None:
        table_names = [
            "threads",
            "users",
            "messages",
            "channels",
            "sessions",
            "devices",
            "client_settings",
            "plugin_permissions",
            "cluster_nodes",
            "backup_metadata",
            # Performance monitoring tables
            "performance_metrics",
            "alert_rules",
            "alerts",
            "performance_dashboards",
            "resource_tracking",
            "mfa_challenges",
            "plugins",
            "events",
            "client_settings",
            "plugin_permissions",
            "cluster_nodes",
            "backup_metadata",
        ]
    
    try:
        async with database_manager.get_session() as session:
            for table_name in table_names:
                await session.execute(f"DROP TABLE IF EXISTS {table_name}")
            await session.commit()
        
        logger.info(f"Dropped tables: {', '.join(table_names)}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to drop tables: {e}")
        return False
    "CLIENT_SETTINGS_SCHEMA",
    "PLUGIN_PERMISSIONS_SCHEMA",
    "CLUSTER_NODES_SCHEMA",
    "BACKUP_METADATA_SCHEMA",
    "PERFORMANCE_METRICS_SCHEMA",
    "ALERT_RULES_SCHEMA",
    "ALERTS_SCHEMA",
    "PERFORMANCE_DASHBOARDS_SCHEMA",
    "RESOURCE_TRACKING_SCHEMA",


__all__ = [
    "BaseModel",
    "THREAD_SCHEMA",
    "USER_SCHEMA",
    "MESSAGE_SCHEMA",
    "CHANNEL_SCHEMA",
    "SESSION_SCHEMA",
    "DEVICE_SCHEMA",
    "MFA_CHALLENGE_SCHEMA",
    "PLUGIN_SCHEMA",
    "EVENT_SCHEMA",
    "CLIENT_SETTINGS_SCHEMA",
    "PLUGIN_PERMISSIONS_SCHEMA",
    "TYPING_STATUS_SCHEMA",
    "KEYBOARD_SHORTCUTS_SCHEMA",
    "CLUSTER_NODES_SCHEMA",
    "BACKUP_METADATA_SCHEMA",
    "TYPING_STATUS_SCHEMA",
    "create_tables",
    "drop_tables",
]
