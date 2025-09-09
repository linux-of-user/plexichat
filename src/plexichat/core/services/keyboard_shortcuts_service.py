"""
Keyboard Shortcuts Service for PlexiChat

Provides comprehensive keyboard shortcuts management including:
- User-specific shortcut storage and retrieval
- Default shortcuts configuration
- Shortcut conflict detection and validation
- Platform-specific key mappings
"""

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from plexichat.core.database import execute_query, execute_transaction
from plexichat.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class KeyboardShortcut:
    """Represents a keyboard shortcut configuration."""

    id: Optional[int] = None
    user_id: str = ""
    shortcut_key: str = ""
    action: str = ""
    description: str = ""
    is_custom: bool = False
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "shortcut_key": self.shortcut_key,
            "action": self.action,
            "description": self.description,
            "is_custom": self.is_custom,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class KeyboardShortcutsService:
    """Service for managing keyboard shortcuts."""

    def __init__(self):
        self._default_shortcuts = self._get_default_shortcuts()

    def _get_default_shortcuts(self) -> Dict[str, Dict[str, str]]:
        """Get default keyboard shortcuts configuration."""
        return {
            "send_message": {
                "key": "Enter",
                "description": "Send message",
                "platform_variants": {
                    "mac": "Return",
                    "windows": "Enter",
                    "linux": "Enter",
                },
            },
            "new_line": {
                "key": "Shift+Enter",
                "description": "Insert new line",
                "platform_variants": {
                    "mac": "Shift+Return",
                    "windows": "Shift+Enter",
                    "linux": "Shift+Enter",
                },
            },
            "channel_search": {
                "key": "Ctrl+K",
                "description": "Search channels",
                "platform_variants": {
                    "mac": "Cmd+K",
                    "windows": "Ctrl+K",
                    "linux": "Ctrl+K",
                },
            },
            "user_search": {
                "key": "Ctrl+U",
                "description": "Search users",
                "platform_variants": {
                    "mac": "Cmd+U",
                    "windows": "Ctrl+U",
                    "linux": "Ctrl+U",
                },
            },
            "toggle_theme": {
                "key": "Ctrl+T",
                "description": "Toggle theme",
                "platform_variants": {
                    "mac": "Cmd+T",
                    "windows": "Ctrl+T",
                    "linux": "Ctrl+T",
                },
            },
            "show_shortcuts": {
                "key": "Ctrl+/",
                "description": "Show keyboard shortcuts",
                "platform_variants": {
                    "mac": "Cmd+/",
                    "windows": "Ctrl+/",
                    "linux": "Ctrl+/",
                },
            },
            "focus_message_input": {
                "key": "Ctrl+L",
                "description": "Focus message input",
                "platform_variants": {
                    "mac": "Cmd+L",
                    "windows": "Ctrl+L",
                    "linux": "Ctrl+L",
                },
            },
            "previous_channel": {
                "key": "Alt+Left",
                "description": "Previous channel",
                "platform_variants": {
                    "mac": "Option+Left",
                    "windows": "Alt+Left",
                    "linux": "Alt+Left",
                },
            },
            "next_channel": {
                "key": "Alt+Right",
                "description": "Next channel",
                "platform_variants": {
                    "mac": "Option+Right",
                    "windows": "Alt+Right",
                    "linux": "Alt+Right",
                },
            },
            "channel_1": {
                "key": "Alt+1",
                "description": "Switch to channel 1",
                "platform_variants": {
                    "mac": "Option+1",
                    "windows": "Alt+1",
                    "linux": "Alt+1",
                },
            },
            "channel_2": {
                "key": "Alt+2",
                "description": "Switch to channel 2",
                "platform_variants": {
                    "mac": "Option+2",
                    "windows": "Alt+2",
                    "linux": "Alt+2",
                },
            },
            "channel_3": {
                "key": "Alt+3",
                "description": "Switch to channel 3",
                "platform_variants": {
                    "mac": "Option+3",
                    "windows": "Alt+3",
                    "linux": "Alt+3",
                },
            },
        }

    async def get_shortcuts(self, user_id: str) -> List[KeyboardShortcut]:
        """Get all shortcuts for a user, including defaults."""
        # Use a single database session for all operations to ensure visibility
        from plexichat.core.database.manager import database_manager

        async with database_manager.get_session() as session:
            try:
                # Get user-specific shortcuts
                user_shortcuts_result = await session.fetchall(
                    """
                    SELECT id, user_id, shortcut_key, action, description, is_custom,
                           created_at, updated_at
                    FROM keyboard_shortcuts
                    WHERE user_id = :user_id
                    ORDER BY action
                    """,
                    {"user_id": user_id},
                )

                shortcuts = []
                user_shortcut_actions = set()

                # Convert user shortcuts to objects
                for row in user_shortcuts_result:
                    shortcut = KeyboardShortcut(
                        id=row[0],
                        user_id=row[1],
                        shortcut_key=row[2],
                        action=row[3],
                        description=row[4],
                        is_custom=row[5],
                        created_at=row[6],
                        updated_at=row[7],
                    )
                    shortcuts.append(shortcut)
                    user_shortcut_actions.add(row[3])

                # Add default shortcuts that user hasn't customized
                for action, default_config in self._default_shortcuts.items():
                    if action not in user_shortcut_actions:
                        shortcut = KeyboardShortcut(
                            user_id=user_id,
                            shortcut_key=default_config["key"],
                            action=action,
                            description=default_config["description"],
                            is_custom=False,
                        )
                        shortcuts.append(shortcut)

                return shortcuts

            except Exception as e:
                logger.error(f"Failed to get shortcuts for user {user_id}: {e}")
                return []

    async def add_shortcut(
        self, user_id: str, shortcut_data: Dict[str, Any]
    ) -> Optional[KeyboardShortcut]:
        """Add a new shortcut for a user."""
        # Use a single database session for both INSERT and SELECT operations
        from plexichat.core.database.manager import database_manager

        async with database_manager.get_session() as session:
            try:
                # Validate shortcut doesn't conflict
                conflict = await self.validate_shortcut_conflicts(
                    shortcut_data["shortcut_key"], user_id, shortcut_data.get("action")
                )
                if conflict:
                    logger.warning(
                        f"Shortcut conflict detected for user {user_id}: {conflict}"
                    )
                    return None

                # Insert new shortcut
                now = datetime.now(timezone.utc)
                await session.execute(
                    """
                    INSERT INTO keyboard_shortcuts
                    (user_id, shortcut_key, action, description, is_custom, created_at, updated_at)
                    VALUES (:user_id, :shortcut_key, :action, :description, :is_custom, :created_at, :updated_at)
                    """,
                    {
                        "user_id": user_id,
                        "shortcut_key": shortcut_data["shortcut_key"],
                        "action": shortcut_data["action"],
                        "description": shortcut_data["description"],
                        "is_custom": True,  # is_custom
                        "created_at": now,
                        "updated_at": now,
                    },
                )

                # Get the last inserted row ID for SQLite
                last_id_result = await session.fetchall(
                    "SELECT last_insert_rowid() as id", {}
                )
                if last_id_result and last_id_result[0]:
                    shortcut_id = last_id_result[0]["id"]
                    return KeyboardShortcut(
                        id=shortcut_id,
                        user_id=user_id,
                        shortcut_key=shortcut_data["shortcut_key"],
                        action=shortcut_data["action"],
                        description=shortcut_data["description"],
                        is_custom=True,
                        created_at=now,
                        updated_at=now,
                    )

                return None

            except Exception as e:
                logger.error(f"Failed to add shortcut for user {user_id}: {e}")
                return None

    async def update_shortcut(
        self, user_id: str, shortcut_id: int, shortcut_data: Dict[str, Any]
    ) -> bool:
        """Update an existing shortcut."""
        try:
            # Validate shortcut doesn't conflict
            conflict = await self.validate_shortcut_conflicts(
                shortcut_data["shortcut_key"],
                user_id,
                shortcut_data.get("action"),
                shortcut_id,
            )
            if conflict:
                logger.warning(
                    f"Shortcut conflict detected for user {user_id}: {conflict}"
                )
                return False

            # Update shortcut
            now = datetime.now(timezone.utc)
            await execute_query(
                """
                UPDATE keyboard_shortcuts
                SET shortcut_key = :shortcut_key, action = :action, description = :description, updated_at = :updated_at
                WHERE id = :id AND user_id = :user_id
                """,
                {
                    "shortcut_key": shortcut_data["shortcut_key"],
                    "action": shortcut_data["action"],
                    "description": shortcut_data["description"],
                    "updated_at": now,
                    "id": shortcut_id,
                    "user_id": user_id,
                },
            )

            return True

        except Exception as e:
            logger.error(
                f"Failed to update shortcut {shortcut_id} for user {user_id}: {e}"
            )
            return False

    async def remove_shortcut(self, user_id: str, shortcut_id: int) -> bool:
        """Remove a custom shortcut."""
        try:
            await execute_query(
                """
                DELETE FROM keyboard_shortcuts
                WHERE id = :id AND user_id = :user_id AND is_custom = 1
                """,
                {"id": shortcut_id, "user_id": user_id},
            )
            return True

        except Exception as e:
            logger.error(
                f"Failed to remove shortcut {shortcut_id} for user {user_id}: {e}"
            )
            return False

    async def get_default_shortcuts(self) -> Dict[str, Dict[str, str]]:
        """Get default shortcuts configuration."""
        return self._default_shortcuts

    async def validate_shortcut_conflicts(
        self,
        shortcut_key: str,
        user_id: str,
        exclude_action: Optional[str] = None,
        exclude_id: Optional[int] = None,
    ) -> Optional[str]:
        """Validate if a shortcut key conflicts with existing shortcuts."""
        # Use a single database session for all operations to ensure visibility
        from plexichat.core.database.manager import database_manager

        async with database_manager.get_session() as session:
            try:
                # Check user shortcuts
                query = """
                    SELECT action FROM keyboard_shortcuts
                    WHERE user_id = :user_id AND shortcut_key = :shortcut_key
                """
                params = {"user_id": user_id, "shortcut_key": shortcut_key}

                if exclude_action:
                    query += " AND action != :exclude_action"
                    params["exclude_action"] = exclude_action

                if exclude_id:
                    query += " AND id != :exclude_id"
                    params["exclude_id"] = exclude_id

                conflicts_result = await session.fetchall(query, params)

                if conflicts_result:
                    return f"Shortcut '{shortcut_key}' conflicts with action '{conflicts_result[0][0]}'"

                # Check default shortcuts
                for action, config in self._default_shortcuts.items():
                    if config["key"] == shortcut_key and action != exclude_action:
                        return f"Shortcut '{shortcut_key}' conflicts with default action '{action}'"

                return None

            except Exception as e:
                logger.error(f"Failed to validate shortcut conflicts: {e}")
                return f"Validation error: {str(e)}"

    async def get_shortcut_by_action(
        self, user_id: str, action: str
    ) -> Optional[KeyboardShortcut]:
        """Get a specific shortcut by action."""
        # Use a single database session for all operations to ensure visibility
        from plexichat.core.database.manager import database_manager

        async with database_manager.get_session() as session:
            try:
                # Check user shortcuts first
                user_shortcut_result = await session.fetchall(
                    """
                    SELECT id, user_id, shortcut_key, action, description, is_custom,
                           created_at, updated_at
                    FROM keyboard_shortcuts
                    WHERE user_id = :user_id AND action = :action
                    """,
                    {"user_id": user_id, "action": action},
                )

                if user_shortcut_result:
                    row = user_shortcut_result[0]
                    return KeyboardShortcut(
                        id=row[0],
                        user_id=row[1],
                        shortcut_key=row[2],
                        action=row[3],
                        description=row[4],
                        is_custom=row[5],
                        created_at=row[6],
                        updated_at=row[7],
                    )

                # Return default shortcut
                if action in self._default_shortcuts:
                    config = self._default_shortcuts[action]
                    return KeyboardShortcut(
                        user_id=user_id,
                        shortcut_key=config["key"],
                        action=action,
                        description=config["description"],
                        is_custom=False,
                    )

                return None

            except Exception as e:
                logger.error(f"Failed to get shortcut for action {action}: {e}")
                return None


# Global service instance
_keyboard_shortcuts_service = None


def get_keyboard_shortcuts_service() -> KeyboardShortcutsService:
    """Get the global keyboard shortcuts service instance."""
    global _keyboard_shortcuts_service
    if _keyboard_shortcuts_service is None:
        _keyboard_shortcuts_service = KeyboardShortcutsService()
    return _keyboard_shortcuts_service


# Global service instance for direct import
keyboard_shortcuts_service = get_keyboard_shortcuts_service()
