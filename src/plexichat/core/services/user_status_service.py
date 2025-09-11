"""
User Status Service

Manages user status functionality including validation, persistence, and real-time updates.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
import logging
from typing import Any

from plexichat.core.database.manager import database_manager
from plexichat.core.websocket.websocket_manager import websocket_manager

logger = logging.getLogger(__name__)

VALID_STATUSES = ["online", "away", "busy", "offline"]


@dataclass
class UserStatus:
    """User status data structure."""

    user_id: str
    status: str
    custom_status: str | None = None
    status_updated_at: datetime = None

    def __post_init__(self):
        if self.status_updated_at is None:
            self.status_updated_at = datetime.now(UTC)


class UserStatusService:
    """Service for managing user status operations."""

    def __init__(self):
        self.db_manager = database_manager
        self.websocket_manager = websocket_manager

    async def get_user_status(self, user_id: str) -> UserStatus | None:
        """Get current status for a user."""
        try:
            if not self.db_manager:
                logger.warning("Database manager not available")
                return None

            query = """
                SELECT status, custom_status, status_updated_at
                FROM users
                WHERE id = ?
            """
            result = await self.db_manager.execute_query(query, (user_id,))

            if not result or not result[0]:
                return None

            row = result[0]
            return UserStatus(
                user_id=user_id,
                status=row.get("status", "offline"),
                custom_status=row.get("custom_status"),
                status_updated_at=row.get("status_updated_at"),
            )

        except Exception as e:
            logger.error(f"Error getting user status for {user_id}: {e}")
            return None

    async def update_user_status(
        self, user_id: str, status: str, custom_status: str | None = None
    ) -> bool:
        """Update user status."""
        try:
            # Validate status
            if status not in VALID_STATUSES:
                logger.error(f"Invalid status: {status}")
                return False

            if not self.db_manager:
                logger.warning("Database manager not available")
                return False

            # Update database
            update_time = datetime.now(UTC)
            query = """
                UPDATE users
                SET status = ?, custom_status = ?, status_updated_at = ?, updated_at = ?
                WHERE id = ?
            """
            params = (
                status,
                custom_status,
                update_time.isoformat(),
                update_time.isoformat(),
                user_id,
            )

            result = await self.db_manager.execute_query(query, params)

            if result:
                # Broadcast status change
                await self._broadcast_status_change(
                    user_id, status, custom_status, update_time
                )

                logger.info(f"Updated status for user {user_id} to {status}")
                return True
            else:
                logger.error(f"Failed to update status for user {user_id}")
                return False

        except Exception as e:
            logger.error(f"Error updating user status for {user_id}: {e}")
            return False

    async def get_online_users(self) -> list[dict[str, Any]]:
        """Get list of online users."""
        try:
            if not self.db_manager:
                logger.warning("Database manager not available")
                return []

            query = """
                SELECT id, username, display_name, status, custom_status, status_updated_at
                FROM users
                WHERE status IN ('online', 'away', 'busy') AND is_active = 1
                ORDER BY status_updated_at DESC
            """
            result = await self.db_manager.execute_query(query)

            if not result:
                return []

            users = []
            for row in result:
                users.append(
                    {
                        "id": row.get("id"),
                        "username": row.get("username"),
                        "display_name": row.get("display_name"),
                        "status": row.get("status", "offline"),
                        "custom_status": row.get("custom_status"),
                        "status_updated_at": row.get("status_updated_at"),
                    }
                )

            return users

        except Exception as e:
            logger.error(f"Error getting online users: {e}")
            return []

    async def set_user_online(self, user_id: str) -> bool:
        """Set user status to online."""
        return await self.update_user_status(user_id, "online")

    async def set_user_away(self, user_id: str) -> bool:
        """Set user status to away."""
        return await self.update_user_status(user_id, "away")

    async def set_user_busy(self, user_id: str) -> bool:
        """Set user status to busy."""
        return await self.update_user_status(user_id, "busy")

    async def set_user_offline(self, user_id: str) -> bool:
        """Set user status to offline."""
        return await self.update_user_status(user_id, "offline")

    async def _broadcast_status_change(
        self,
        user_id: str,
        status: str,
        custom_status: str | None,
        update_time: datetime,
    ):
        """Broadcast status change to connected clients."""
        try:
            if not self.websocket_manager:
                return

            message = {
                "type": "user_status_change",
                "user_id": user_id,
                "status": status,
                "custom_status": custom_status,
                "timestamp": update_time.isoformat(),
            }

            # Broadcast to all connected clients
            await self.websocket_manager.broadcast_to_all(message)

        except Exception as e:
            logger.error(f"Error broadcasting status change: {e}")

    def validate_status(self, status: str) -> bool:
        """Validate status value."""
        return status in VALID_STATUSES

    def get_valid_statuses(self) -> list[str]:
        """Get list of valid status values."""
        return VALID_STATUSES.copy()


# Global service instance
user_status_service = UserStatusService()


# Convenience functions
async def get_user_status(user_id: str) -> UserStatus | None:
    """Get user status via global service."""
    return await user_status_service.get_user_status(user_id)


async def update_user_status(
    user_id: str, status: str, custom_status: str | None = None
) -> bool:
    """Update user status via global service."""
    return await user_status_service.update_user_status(user_id, status, custom_status)


async def get_online_users() -> list[dict[str, Any]]:
    """Get online users via global service."""
    return await user_status_service.get_online_users()
