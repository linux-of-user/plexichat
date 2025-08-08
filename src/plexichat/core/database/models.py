"""
Database Models

Base model classes and table management utilities.
"""

import logging
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4

from .manager import database_manager

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


async def create_tables() -> bool:
    """Create all standard tables."""
    tables = {
        "users": USER_SCHEMA,
        "messages": MESSAGE_SCHEMA,
        "channels": CHANNEL_SCHEMA,
        "sessions": SESSION_SCHEMA,
        "plugins": PLUGIN_SCHEMA,
        "events": EVENT_SCHEMA,
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
        table_names = ["users", "messages", "channels", "sessions", "plugins", "events"]
    
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


__all__ = [
    "BaseModel",
    "USER_SCHEMA",
    "MESSAGE_SCHEMA", 
    "CHANNEL_SCHEMA",
    "SESSION_SCHEMA",
    "PLUGIN_SCHEMA",
    "EVENT_SCHEMA",
    "create_tables",
    "drop_tables",
]
