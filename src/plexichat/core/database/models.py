from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Dict, List, Optional
from uuid import uuid4
from . import db
from ..logging import get_logger

logger = get_logger(__name__)

@dataclass
class BaseModel:
    """Base model for database entities."""
    id: str = field(default_factory=lambda: str(uuid4()))
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> Dict[str, Any]:
        result = {}
        for key, value in self.__dict__.items():
            if isinstance(value, datetime):
                result[key] = value.isoformat()
            else:
                result[key] = value
        return result

# Schema Definitions
USER_SCHEMA = {
    "id": "TEXT PRIMARY KEY",
    "username": "TEXT UNIQUE NOT NULL",
    "email": "TEXT UNIQUE NOT NULL",
    "password_hash": "TEXT",
    "created_at": "TEXT NOT NULL",
    "updated_at": "TEXT NOT NULL"
}

# ... (We can add more schemas here as needed, keeping it simple for now)

def create_tables():
    """Create tables based on schemas."""
    # Simple implementation for now
    try:
        # Users
        columns = ", ".join([f"{k} {v}" for k, v in USER_SCHEMA.items()])
        db.execute(f"CREATE TABLE IF NOT EXISTS users ({columns})")
        logger.info("Tables created successfully.")
    except Exception as e:
        logger.error(f"Error creating tables: {e}")

