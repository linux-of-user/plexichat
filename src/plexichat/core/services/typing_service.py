"""
Typing Service

Manages typing indicators with database persistence and real-time broadcasting.
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import logging
from typing import Any
from uuid import uuid4

from plexichat.core.config import get_setting
from plexichat.core.database.manager import database_manager
from plexichat.core.services.optimized_websocket_service import (
    optimized_websocket_service,
)
from plexichat.core.websocket.websocket_manager import websocket_manager

logger = logging.getLogger(__name__)


@dataclass
class TypingStatus:
    """Typing status data structure."""

    id: str
    user_id: str
    channel_id: str
    started_at: datetime
    expires_at: datetime
    created_at: datetime
    updated_at: datetime
    metadata: dict[str, Any]

    def __post_init__(self):
        if isinstance(self.started_at, str):
            self.started_at = datetime.fromisoformat(
                self.started_at.replace("Z", "+00:00")
            )
        if isinstance(self.expires_at, str):
            self.expires_at = datetime.fromisoformat(
                self.expires_at.replace("Z", "+00:00")
            )
        if isinstance(self.created_at, str):
            self.created_at = datetime.fromisoformat(
                self.created_at.replace("Z", "+00:00")
            )
        if isinstance(self.updated_at, str):
            self.updated_at = datetime.fromisoformat(
                self.updated_at.replace("Z", "+00:00")
            )

    def is_expired(self) -> bool:
        """Check if typing status has expired."""
        return datetime.now(UTC) > self.expires_at

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "channel_id": self.channel_id,
            "started_at": self.started_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "metadata": self.metadata,
        }


class TypingService:
    """Service for managing typing indicators."""

    def __init__(self):
        self.db_manager = database_manager
        self.websocket_manager = websocket_manager
        self.typing_timeout = get_setting("typing.timeout_seconds", 3.0)
        self.debounce_delay = get_setting("typing.debounce_delay_seconds", 0.5)
        self.max_concurrent_users = get_setting(
            "typing.max_concurrent_typing_users", 100
        )
        self.enable_debug_logging = get_setting("typing.enable_debug_logging", False)

    async def start_typing(self, user_id: str, channel_id: str) -> bool:
        """Start typing indicator for user in channel."""
        try:
            # Validate inputs
            if not user_id or not channel_id:
                logger.error("Invalid user_id or channel_id")
                return False

            # Check if user has permission for channel
            if not await self._check_channel_access(user_id, channel_id):
                logger.warning(
                    f"User {user_id} does not have access to channel {channel_id}"
                )
                return False

            current_time = datetime.now(UTC)
            expires_at = current_time + timedelta(seconds=self.typing_timeout)

            # Check if user is already typing in this channel
            existing = await self._get_user_typing_status(user_id, channel_id)
            if existing:
                # Update existing record
                return await self._update_typing_status(existing.id, expires_at)
            else:
                # Create new typing status
                typing_id = str(uuid4())
                typing_status = TypingStatus(
                    id=typing_id,
                    user_id=user_id,
                    channel_id=channel_id,
                    started_at=current_time,
                    expires_at=expires_at,
                    created_at=current_time,
                    updated_at=current_time,
                    metadata={},
                )

                success = await self._save_typing_status(typing_status)
                if success:
                    # Broadcast typing start
                    await self._broadcast_typing_start(
                        user_id, channel_id, current_time
                    )
                    logger.info(
                        f"Started typing for user {user_id} in channel {channel_id}"
                    )
                    return True

            return False

        except Exception as e:
            logger.error(f"Error starting typing for user {user_id}: {e}")
            return False

    async def stop_typing(self, user_id: str, channel_id: str) -> bool:
        """Stop typing indicator for user in channel."""
        try:
            # Validate inputs
            if not user_id or not channel_id:
                logger.error("Invalid user_id or channel_id")
                return False

            # Find and remove typing status
            existing = await self._get_user_typing_status(user_id, channel_id)
            if existing:
                success = await self._delete_typing_status(existing.id)
                if success:
                    # Broadcast typing stop
                    await self._broadcast_typing_stop(
                        user_id, channel_id, datetime.now(UTC)
                    )
                    logger.info(
                        f"Stopped typing for user {user_id} in channel {channel_id}"
                    )
                    return True

            return False

        except Exception as e:
            logger.error(f"Error stopping typing for user {user_id}: {e}")
            return False

    async def get_typing_users(self, channel_id: str) -> list[str]:
        """Get list of users currently typing in channel."""
        try:
            # Validate input
            if not channel_id:
                logger.error("Invalid channel_id")
                return []

            # Clean up expired states first
            await self.cleanup_expired_states()

            # Query active typing users
            query = """
                SELECT user_id FROM typing_status
                WHERE channel_id = ? AND expires_at > ?
                ORDER BY started_at ASC
            """
            current_time = datetime.now(UTC).isoformat()
            result = await self.db_manager.execute_query(
                query, (channel_id, current_time)
            )

            if result:
                return [row.get("user_id") for row in result if row.get("user_id")]
            else:
                return []

        except Exception as e:
            logger.error(f"Error getting typing users for channel {channel_id}: {e}")
            return []

    async def cleanup_expired_states(self) -> int:
        """Clean up expired typing states from database."""
        try:
            current_time = datetime.now(UTC).isoformat()

            # Get expired records
            query = """
                SELECT id, user_id, channel_id FROM typing_status
                WHERE expires_at <= ?
            """
            result = await self.db_manager.execute_query(query, (current_time,))

            if not result:
                return 0

            expired_count = len(result)

            # Delete expired records
            delete_query = "DELETE FROM typing_status WHERE expires_at <= ?"
            await self.db_manager.execute_query(delete_query, (current_time,))

            # Broadcast stop events for expired typings
            for row in result:
                user_id = row.get("user_id")
                channel_id = row.get("channel_id")
                if user_id and channel_id:
                    await self._broadcast_typing_stop(
                        user_id, channel_id, datetime.now(UTC)
                    )

            logger.info(f"Cleaned up {expired_count} expired typing states")
            return expired_count

        except Exception as e:
            logger.error(f"Error cleaning up expired typing states: {e}")
            return 0

    async def _get_user_typing_status(
        self, user_id: str, channel_id: str
    ) -> TypingStatus | None:
        """Get typing status for user in channel."""
        try:
            query = """
                SELECT * FROM typing_status
                WHERE user_id = ? AND channel_id = ? AND expires_at > ?
                LIMIT 1
            """
            current_time = datetime.now(UTC).isoformat()
            result = await self.db_manager.execute_query(
                query, (user_id, channel_id, current_time)
            )

            if result and result[0]:
                return TypingStatus(**result[0])

            return None

        except Exception as e:
            logger.error(f"Error getting typing status for user {user_id}: {e}")
            return None

    async def _save_typing_status(self, typing_status: TypingStatus) -> bool:
        """Save typing status to database."""
        try:
            query = """
                INSERT INTO typing_status
                (id, user_id, channel_id, started_at, expires_at, created_at, updated_at, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """
            params = (
                typing_status.id,
                typing_status.user_id,
                typing_status.channel_id,
                typing_status.started_at.isoformat(),
                typing_status.expires_at.isoformat(),
                typing_status.created_at.isoformat(),
                typing_status.updated_at.isoformat(),
                str(typing_status.metadata),
            )

            result = await self.db_manager.execute_query(query, params)
            return result is not None

        except Exception as e:
            logger.error(f"Error saving typing status: {e}")
            return False

    async def _update_typing_status(self, typing_id: str, expires_at: datetime) -> bool:
        """Update typing status expiration."""
        try:
            query = """
                UPDATE typing_status
                SET expires_at = ?, updated_at = ?
                WHERE id = ?
            """
            current_time = datetime.now(UTC).isoformat()
            params = (expires_at.isoformat(), current_time, typing_id)

            result = await self.db_manager.execute_query(query, params)
            return result is not None

        except Exception as e:
            logger.error(f"Error updating typing status {typing_id}: {e}")
            return False

    async def _delete_typing_status(self, typing_id: str) -> bool:
        """Delete typing status from database."""
        try:
            query = "DELETE FROM typing_status WHERE id = ?"
            result = await self.db_manager.execute_query(query, (typing_id,))
            return result is not None

        except Exception as e:
            logger.error(f"Error deleting typing status {typing_id}: {e}")
            return False

    async def _check_channel_access(self, user_id: str, channel_id: str) -> bool:
        """Check if user has access to channel."""
        try:
            # For now, allow access if user exists and channel exists
            # In a real implementation, this would check channel membership/permissions
            user_query = "SELECT id FROM users WHERE id = ?"
            channel_query = "SELECT id FROM channels WHERE id = ?"

            user_result = await self.db_manager.execute_query(user_query, (user_id,))
            channel_result = await self.db_manager.execute_query(
                channel_query, (channel_id,)
            )

            return bool(user_result and channel_result)

        except Exception as e:
            logger.error(f"Error checking channel access: {e}")
            return False

    async def _broadcast_typing_start(
        self, user_id: str, channel_id: str, timestamp: datetime
    ):
        """Broadcast typing start event."""
        try:
            if not self.websocket_manager:
                return

            message = {
                "type": "typing_start",
                "channel_id": channel_id,
                "user_id": user_id,
                "timestamp": timestamp.isoformat(),
            }

            await self.websocket_manager.send_to_channel(channel_id, message)

        except Exception as e:
            logger.error(f"Error broadcasting typing start: {e}")

    async def _broadcast_typing_stop(
        self, user_id: str, channel_id: str, timestamp: datetime
    ):
        """Broadcast typing stop event."""
        try:
            if not self.websocket_manager:
                return

            message = {
                "type": "typing_stop",
                "channel_id": channel_id,
                "user_id": user_id,
                "timestamp": timestamp.isoformat(),
            }

            await self.websocket_manager.send_to_channel(channel_id, message)

        except Exception as e:
            logger.error(f"Error broadcasting typing stop: {e}")
        except Exception as e:
            logger.error(f"Error broadcasting typing stop: {e}")


# Global service instance
typing_service = TypingService()

# Initialize optimized WebSocket service for the typing service
typing_service.optimized_websocket = optimized_websocket_service


# Convenience functions
async def start_typing(user_id: str, channel_id: str) -> bool:
    """Start typing via global service."""
    return await typing_service.start_typing(user_id, channel_id)


async def stop_typing(user_id: str, channel_id: str) -> bool:
    """Stop typing via global service."""
    return await typing_service.stop_typing(user_id, channel_id)


async def get_typing_users(channel_id: str) -> list[str]:
    """Get typing users via global service."""
    return await typing_service.get_typing_users(channel_id)


async def cleanup_expired_states() -> int:
    """Clean up expired states via global service."""
    return await typing_service.cleanup_expired_states()


# Global service instance
typing_service = TypingService()


# Convenience functions
async def start_typing(user_id: str, channel_id: str) -> bool:
    """Start typing via global service."""
    return await typing_service.start_typing(user_id, channel_id)


async def stop_typing(user_id: str, channel_id: str) -> bool:
    """Stop typing via global service."""
    return await typing_service.stop_typing(user_id, channel_id)


async def get_typing_users(channel_id: str) -> list[str]:
    """Get typing users via global service."""
    return await typing_service.get_typing_users(channel_id)


async def cleanup_expired_states() -> int:
    """Clean up expired states via global service."""
    return await typing_service.cleanup_expired_states()
