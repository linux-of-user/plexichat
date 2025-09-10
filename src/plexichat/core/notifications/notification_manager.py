
import socket
import threading

"""
PlexiChat Notification Manager

Notification management with threading and performance optimization.
"""


import asyncio
import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from uuid import uuid4

try:
    from plexichat.core.database.manager import database_manager
except ImportError:
    database_manager = None

try:
    from plexichat.core.threading.thread_manager import (
        async_thread_manager,
        submit_task,
    )
except ImportError:
    async_thread_manager = None
    submit_task = None

try:
    from plexichat.core.caching.unified_cache_integration import (
        CacheKeyBuilder,
        cache_delete,
        cache_get,
        cache_set,
    )
except ImportError:
    cache_get = None
    cache_set = None

try:
    from plexichat.core.websocket.websocket_manager import send_to_user
except ImportError:
    send_to_user = None

try:
    from plexichat.core.notifications.email_service import send_notification_email
except ImportError:
    send_notification_email = None

try:
    from plexichat.core.notifications.push_service import send_push_notification
except ImportError:
    send_push_notification = None

try:
    from plexichat.core.logging import get_performance_logger
    from plexichat.core.performance.optimization_engine import (
        PerformanceOptimizationEngine,
    )
except ImportError:
    PerformanceOptimizationEngine = None
    get_performance_logger = None

logger = logging.getLogger(__name__)
performance_logger = get_performance_logger() if get_performance_logger else None


class NotificationType(Enum):
    """Notification types."""

    MESSAGE = "message"
    MENTION = "mention"
    FRIEND_REQUEST = "friend_request"
    SYSTEM = "system"
    WARNING = "warning"
    ERROR = "error"
    INFO = "info"


class NotificationPriority(Enum):
    """Notification priorities."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


@dataclass
class Notification:
    """Notification data structure."""

    notification_id: str
    user_id: int
    notification_type: NotificationType
    title: str
    message: str
    priority: NotificationPriority
    created_at: datetime
    read_at: Optional[datetime]
    data: Dict[str, Any]
    expires_at: Optional[datetime]


class NotificationManager:
    """Notification manager with threading support."""

    def __init__(self):
        self.db_manager = database_manager
        self.performance_logger = performance_logger
        self.async_thread_manager = async_thread_manager

        # Notification queue
        self.notification_queue = asyncio.Queue()
        self.processing = False

        # User preferences cache
        self.user_preferences = {}

        # Statistics
        self.notifications_sent = 0
        self.notifications_read = 0
        self.notifications_expired = 0

    async def start_processing(self):
        """Start notification processing loop."""
        if self.processing:
            return

        self.processing = True
        asyncio.create_task(self._processing_loop())
        logger.info("Notification processor started")

    async def stop_processing(self):
        """Stop notification processing."""
        self.processing = False
        logger.info("Notification processor stopped")

    async def _processing_loop(self):
        """Main notification processing loop."""
        while self.processing:
            try:
                # Get notification from queue with timeout
                notification = await asyncio.wait_for(
                    self.notification_queue.get(), timeout=1.0
                )

                # Process notification
                if self.async_thread_manager:
                    await self.async_thread_manager.run_in_thread(
                        self._process_notification_sync, notification
                    )
                else:
                    await self._process_notification(notification)

                self.notification_queue.task_done()

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Notification processing error: {e}")

    def _process_notification_sync(self, notification: Notification):
        """Process notification synchronously for threading."""
        try:
            asyncio.create_task(self._process_notification(notification))
        except Exception as e:
            logger.error(f"Error in sync notification processing: {e}")

    async def _process_notification(self, notification: Notification):
        """Process individual notification."""
        try:
            start_time = time.time()

            # Check user preferences
            preferences = await self._get_user_preferences(notification.user_id)
            if not self._should_send_notification(notification, preferences):
                return

            # Store notification in database
            await self._store_notification(notification)

            # Send real-time notification via WebSocket
            if send_to_user:
                await send_to_user(
                    notification.user_id,
                    {
                        "type": "notification",
                        "notification": {
                            "id": notification.notification_id,
                            "type": notification.notification_type.value,
                            "title": notification.title,
                            "message": notification.message,
                            "priority": notification.priority.value,
                            "created_at": notification.created_at.isoformat(),
                            "data": notification.data,
                        },
                    },
                )

            # Send push notification if enabled
            if preferences.get("push_notifications", True):
                await self._send_push_notification(notification)

            # Send email notification if enabled
            if preferences.get("email_notifications", False):
                await self._send_email_notification(notification)

            # Performance tracking
            if self.performance_logger:
                duration = time.time() - start_time
                self.performance_logger.record_metric(
                    "notification_processing_duration", duration, "seconds"
                )
                self.performance_logger.increment_counter("notifications_processed", 1)

            self.notifications_sent += 1

        except Exception as e:
            logger.error(
                f"Error processing notification {notification.notification_id}: {e}"
            )
            if self.performance_logger:
                self.performance_logger.increment_counter(
                    "notification_processing_errors", 1
                )

    def _should_send_notification(
        self, notification: Notification, preferences: Dict[str, Any]
    ) -> bool:
        """Check if notification should be sent based on user preferences."""
        try:
            # Check if notifications are enabled
            if not preferences.get("notifications_enabled", True):
                return False

            # Check notification type preferences
            type_key = f"{notification.notification_type.value}_notifications"
            if not preferences.get(type_key, True):
                return False

            # Check priority preferences
            min_priority = preferences.get("min_priority", "low")
            priority_levels = {"low": 0, "normal": 1, "high": 2, "urgent": 3}

            if priority_levels.get(
                notification.priority.value, 0
            ) < priority_levels.get(min_priority, 0):
                return False

            # Check quiet hours
            quiet_hours = preferences.get("quiet_hours")
            if quiet_hours and self._is_quiet_hours(quiet_hours):
                return notification.priority == NotificationPriority.URGENT

            return True

        except Exception as e:
            logger.error(f"Error checking notification preferences: {e}")
            return True  # Default to sending

    def _is_quiet_hours(self, quiet_hours: Dict[str, Any]) -> bool:
        """Check if current time is within quiet hours."""
        try:
            if not quiet_hours.get("enabled", False):
                return False

            now = datetime.now().time()
            start_time = datetime.strptime(
                quiet_hours.get("start", "22:00"), "%H:%M"
            ).time()
            end_time = datetime.strptime(
                quiet_hours.get("end", "08:00"), "%H:%M"
            ).time()

            if start_time <= end_time:
                return start_time <= now <= end_time
            else:  # Crosses midnight
                return now >= start_time or now <= end_time

        except Exception as e:
            logger.error(f"Error checking quiet hours: {e}")
            return False

    async def _get_user_preferences(self, user_id: int) -> Dict[str, Any]:
        """Get user notification preferences."""
        try:
            # Check cache first
            cache_key = f"notification_prefs_{user_id}"
            if cache_get:
                cached_prefs = await cache_get(cache_key)
                if cached_prefs:
                    return cached_prefs

            # Get from database
            if self.db_manager:
                query = "SELECT preferences FROM user_notification_preferences WHERE user_id = ?"
                result = await self.db_manager.execute_query(query, (user_id,))

                if result:
                    preferences = json.loads(result[0][0])
                else:
                    # Default preferences
                    preferences = {
                        "notifications_enabled": True,
                        "message_notifications": True,
                        "mention_notifications": True,
                        "friend_request_notifications": True,
                        "system_notifications": True,
                        "push_notifications": True,
                        "email_notifications": False,
                        "min_priority": "normal",
                        "quiet_hours": {
                            "enabled": False,
                            "start": "22:00",
                            "end": "08:00",
                        },
                    }

                # Cache preferences
                if cache_set:
                    await cache_set(cache_key, preferences, ttl=3600)

                return preferences

            # Return default preferences if no database
            return {
                "notifications_enabled": True,
                "message_notifications": True,
                "mention_notifications": True,
                "friend_request_notifications": True,
                "system_notifications": True,
                "push_notifications": True,
                "email_notifications": False,
                "min_priority": "normal",
            }

        except Exception as e:
            logger.error(f"Error getting user preferences: {e}")
            return {"notifications_enabled": True}

    async def _store_notification(self, notification: Notification):
        """Store notification in database."""
        try:
            if self.db_manager:
                async with self.db_manager.get_session() as session:
                    await session.execute(
                        """
                        INSERT INTO notifications (
                            notification_id, user_id, notification_type, title,
                            message