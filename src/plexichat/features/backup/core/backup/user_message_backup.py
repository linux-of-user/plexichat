# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

import aiosqlite


"""
import time
Universal Backup Manager

Manages backup of user messages and data with opt-out capabilities
and comprehensive data type support.
"""

logger = logging.getLogger(__name__)


class BackupOptStatus(Enum):
    """User backup opt status."""

    OPTED_IN = "opted-in"
    OPTED_OUT = "opted-out"
    PARTIAL = "partial"
    DEFAULT = "default"


class BackupDataType(Enum):
    """Types of data that can be backed up."""

    MESSAGES = "messages"
    FILES = "files"
    PROFILES = "profiles"
    SETTINGS = "settings"
    METADATA = "metadata"
    ALL = "all"


@dataclass
class UserBackupPreferences:
    """User backup preferences."""

    user_id: int
    opt_status: BackupOptStatus
    data_types: List[BackupDataType]
    retention_days: int
    encryption_level: str
    created_at: datetime
    updated_at: datetime


class UniversalBackupManager:
    """
    Universal Backup Manager

    Manages backup of user data with:
    - Comprehensive opt-out capabilities
    - Multiple data type support
    - User preference management
    - Privacy-preserving backup options
    """

    def __init__(self, backup_manager):
        """Initialize the universal backup manager."""
        self.backup_manager = backup_manager
        self.user_backup_dir = backup_manager.backup_dir / "user_data"
        self.user_backup_dir.mkdir(parents=True, exist_ok=True)

        # User preferences
        self.user_preferences: Dict[int, UserBackupPreferences] = {}

        # Configuration
        self.config = {
            "default_opt_status": BackupOptStatus.DEFAULT,
            "default_retention_days": 90,
            "default_encryption_level": "standard",
            "supported_data_types": [
                BackupDataType.MESSAGES,
                BackupDataType.FILES,
                BackupDataType.PROFILES,
                BackupDataType.SETTINGS,
            ],
        }

        # Database
        self.user_backup_db_path = backup_manager.databases_dir / "user_backup.db"

        logger.info("Universal Backup Manager initialized")

    async def initialize(self):
        """Initialize the universal backup manager."""
        await self._initialize_database()
        await self._load_user_preferences()

        logger.info("Universal Backup Manager initialized successfully")

    async def _initialize_database(self):
        """Initialize the user backup database."""
        async with aiosqlite.connect(self.user_backup_db_path) as db:
            await db.execute()
                """
                CREATE TABLE IF NOT EXISTS user_backup_preferences ()
                    user_id INTEGER PRIMARY KEY,
                    opt_status TEXT NOT NULL,
                    data_types TEXT NOT NULL,
                    retention_days INTEGER NOT NULL,
                    encryption_level TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """
            )

            await db.execute()
                """
                CREATE TABLE IF NOT EXISTS user_backup_history ()
                    backup_id TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    data_type TEXT NOT NULL,
                    backup_size INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT
                )
            """
            )

            await db.commit()

    async def _load_user_preferences(self):
        """Load user backup preferences from database."""
        async with aiosqlite.connect(self.user_backup_db_path) as db:
            async with db.execute("SELECT * FROM user_backup_preferences") as cursor:
                async for row in cursor:
                    preferences = UserBackupPreferences()
                        user_id=row[0],
                        opt_status=BackupOptStatus(row[1]),
                        data_types=[BackupDataType(dt) for dt in json.loads(row[2])],
                        retention_days=row[3],
                        encryption_level=row[4],
                        created_at=datetime.fromisoformat(row[5]),
                        updated_at=datetime.fromisoformat(row[6]),
                    )
                    self.user_preferences[preferences.user_id] = preferences

    async def set_user_backup_preferences()
        self,
        user_id: int,
        opt_status: BackupOptStatus,
        data_types: Optional[List[BackupDataType]] = None,
        retention_days: Optional[int] = None,
        encryption_level: Optional[str] = None,
    ):
        """Set backup preferences for a user."""
        data_types = data_types or self.config["supported_data_types"]
        retention_days = retention_days or self.config["default_retention_days"]
        encryption_level = encryption_level or self.config["default_encryption_level"]

        now = datetime.now(timezone.utc)

        if user_id in self.user_preferences:
            # Update existing preferences
            preferences = self.user_preferences[user_id]
            preferences.opt_status = opt_status
            preferences.data_types = data_types
            preferences.retention_days = retention_days
            preferences.encryption_level = encryption_level
            preferences.updated_at = now
        else:
            # Create new preferences
            preferences = UserBackupPreferences()
                user_id=user_id,
                opt_status=opt_status,
                data_types=data_types,
                retention_days=retention_days,
                encryption_level=encryption_level,
                created_at=now,
                updated_at=now,
            )
            self.user_preferences[user_id] = preferences

        # Save to database
        await self._save_user_preferences(preferences)

        logger.info()
            f"Updated backup preferences for user {user_id}: {opt_status.value}"
        )

    async def _save_user_preferences(self, preferences: UserBackupPreferences):
        """Save user preferences to database."""
        async with aiosqlite.connect(self.user_backup_db_path) as db:
            await db.execute()
                """
                INSERT OR REPLACE INTO user_backup_preferences
                (user_id, opt_status, data_types, retention_days, encryption_level,)
                 created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                ()
                    preferences.user_id,
                    preferences.opt_status.value,
                    json.dumps([dt.value for dt in preferences.data_types]),
                    preferences.retention_days,
                    preferences.encryption_level,
                    preferences.created_at.isoformat(),
                    preferences.updated_at.isoformat(),
                ),
            )
            await db.commit()

    async def should_backup_user_data()
        self, user_id: int, data_type: BackupDataType
    ) -> bool:
        """Check if user data should be backed up."""
        if user_id not in self.user_preferences:
            # Use default behavior
            return self.config["default_opt_status"] != BackupOptStatus.OPTED_OUT

        preferences = self.user_preferences[user_id]

        # Check opt status
        if preferences.opt_status == BackupOptStatus.OPTED_OUT:
            return False
        elif preferences.opt_status == BackupOptStatus.OPTED_IN:
            return data_type in preferences.data_types
        elif preferences.opt_status == BackupOptStatus.PARTIAL:
            return data_type in preferences.data_types
        else:
            # Default behavior
            return True

    async def backup_user_data()
        self, user_id: int, data_type: BackupDataType, data: Any
    ) -> Optional[str]:
        """Backup user data if allowed."""
        if not await self.should_backup_user_data(user_id, data_type):
            logger.debug()
                f"Skipping backup for user {user_id}, data type {data_type.value} (opted out)"
            )
            return None

        # Serialize data
        if isinstance(data, (dict, list)):
            serialized_data = json.dumps(data).encode()
        elif isinstance(data, str):
            serialized_data = data.encode()
        elif isinstance(data, bytes):
            serialized_data = data
        else:
            serialized_data = str(data).encode()

        # Create backup through main backup system
        backup_id = f"user_{user_id}_{data_type.value}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"

        # Use the main backup manager to create the backup
        await self.backup_manager.create_backup()
            backup_id=backup_id,
            data=serialized_data,
            backup_type="user_data",
            metadata={
                "user_id": user_id,
                "data_type": data_type.value,
                "size": len(serialized_data),
            },
        )

        # Record backup history
        await self._record_backup_history()
            user_id, data_type, backup_id, len(serialized_data)
        )

        logger.info()
            f"Backed up {data_type.value} data for user {user_id}: {len(serialized_data)} bytes"
        )
        return backup_id

    async def _record_backup_history()
        self, user_id: int, data_type: BackupDataType, backup_id: str, backup_size: int
    ):
        """Record backup in history."""
        preferences = self.user_preferences.get(user_id)
        retention_days = ()
            preferences.retention_days
            if preferences
            else self.config["default_retention_days"]
        )

        expires_at = datetime.now(timezone.utc) + timedelta(days=retention_days)

        async with aiosqlite.connect(self.user_backup_db_path) as db:
            await db.execute()
                """
                INSERT INTO user_backup_history
                (backup_id, user_id, data_type, backup_size, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                ()
                    backup_id,
                    user_id,
                    data_type.value,
                    backup_size,
                    datetime.now(timezone.utc).isoformat(),
                    expires_at.isoformat(),
                ),
            )
            await db.commit()

    async def get_user_backup_status(self, user_id: int) -> Dict[str, Any]:
        """Get backup status for a user."""
        preferences = self.user_preferences.get(user_id)

        if not preferences:
            return {
                "user_id": user_id,
                "opt_status": self.config["default_opt_status"].value,
                "data_types": [dt.value for dt in self.config["supported_data_types"]],
                "retention_days": self.config["default_retention_days"],
                "backup_count": 0,
            }

        # Count backups
        async with aiosqlite.connect(self.user_backup_db_path) as db:
            async with db.execute()
                "SELECT COUNT(*) FROM user_backup_history WHERE user_id = ?", (user_id,)
            ) as cursor:
                backup_count = (await cursor.fetchone())[0]

        return {
            "user_id": user_id,
            "opt_status": preferences.opt_status.value,
            "data_types": [dt.value for dt in preferences.data_types],
            "retention_days": preferences.retention_days,
            "encryption_level": preferences.encryption_level,
            "backup_count": backup_count,
            "created_at": preferences.created_at.isoformat(),
            "updated_at": preferences.updated_at.isoformat(),
        }

    async def cleanup_expired_backups(self):
        """Clean up expired user backups."""
        now = datetime.now(timezone.utc)

        async with aiosqlite.connect(self.user_backup_db_path) as db:
            # Find expired backups
            async with db.execute()
                "SELECT backup_id FROM user_backup_history WHERE expires_at < ?",
                (now.isoformat(),),
            ) as cursor:
                expired_backups = [row[0] async for row in cursor]

            if expired_backups:
                # Delete expired backup records
                placeholders = ",".join("?" * len(expired_backups))
                await db.execute()
                    f"DELETE FROM user_backup_history WHERE backup_id IN ({placeholders})",
                    expired_backups,
                )
                await db.commit()

                logger.info(f"Cleaned up {len(expired_backups)} expired user backups")

                # TODO: Also delete the actual backup data through backup manager


# Global instance will be created by backup manager
universal_backup_manager = None
