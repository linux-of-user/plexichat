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
                            message, priority, created_at, data, expires_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                        (
                            notification.notification_id,
                            notification.user_id,
                            notification.notification_type.value,
                            notification.title,
                            notification.message,
                            notification.priority.value,
                            notification.created_at,
                            json.dumps(notification.data),
                            notification.expires_at,
                        ),
                    )
                    await session.commit()
        except Exception as e:
            logger.error(f"Error storing notification: {e}")

    async def _send_push_notification(self, notification: Notification):
        """Send push notification using push service."""
        try:
            if not send_push_notification:
                logger.warning("Push service not available")
                return

            # Prepare push message data
            data = {
                "notification_id": notification.notification_id,
                "type": notification.notification_type.value,
                "priority": notification.priority.value,
                "message_id": notification.data.get("message_id"),
                "channel_id": notification.data.get("channel_id"),
                "thread_id": notification.data.get("thread_id"),
                "sender_id": notification.data.get("sender_id"),
            }

            # Send push notification
            results = await send_push_notification(
                user_id=notification.user_id,
                title=notification.title,
                body=notification.message,
                data=data,
            )

            successful_sends = sum(1 for success in results.values() if success)
            if successful_sends > 0:
                logger.info(
                    f"Push notification sent to user {notification.user_id}: {notification.title} ({successful_sends} devices)"
                )
            else:
                logger.warning(
                    f"Failed to send push notification to user {notification.user_id}"
                )

        except Exception as e:
            logger.error(f"Error sending push notification: {e}")

    async def _send_email_notification(self, notification: Notification):
        """Send email notification using email service."""
        try:
            if not send_notification_email:
                logger.warning("Email service not available")
                return

            # Get user email from database (this would need to be implemented)
            user_email = await self._get_user_email(notification.user_id)
            if not user_email:
                logger.warning(f"No email found for user {notification.user_id}")
                return

            # Determine template based on notification type
            template_id = self._get_email_template_for_notification(notification)

            # Prepare template variables
            variables = {
                "sender_name": notification.data.get("sender_name", "System"),
                "channel_name": notification.data.get("channel_id", "Unknown Channel"),
                "message_content": notification.message,
                "title": notification.title,
                "message_url": f"https://plexichat.com/messages/{notification.data.get('message_id', '')}",
                "unsubscribe_url": f"https://plexichat.com/settings/notifications?user={notification.user_id}",
                "action_url": f"https://plexichat.com/messages/{notification.data.get('message_id', '')}",
            }

            # Send email
            success = await send_notification_email(user_email, template_id, variables)
            if success:
                logger.info(
                    f"Email notification sent to user {notification.user_id}: {notification.title}"
                )
            else:
                logger.error(
                    f"Failed to send email notification to user {notification.user_id}"
                )

        except Exception as e:
            logger.error(f"Error sending email notification: {e}")

    def _get_email_template_for_notification(self, notification: Notification) -> str:
        """Get appropriate email template for notification type."""
        type_mapping = {
            NotificationType.MENTION: "mention_notification",
            NotificationType.MESSAGE: "message_notification",
            NotificationType.SYSTEM: "system_notification",
            NotificationType.WARNING: "system_notification",
            NotificationType.ERROR: "system_notification",
        }
        return type_mapping.get(notification.notification_type, "system_notification")

    async def _get_user_email(self, user_id: int) -> Optional[str]:
        """Get user email address from database."""
        try:
            if self.db_manager:
                query = "SELECT email FROM users WHERE id = ?"
                result = await self.db_manager.execute_query(query, (user_id,))
                if result and result[0]:
                    return result[0][0]
            return None
        except Exception as e:
            logger.error(f"Error getting user email for {user_id}: {e}")
            return None

    async def create_notification(
        self,
        user_id: int,
        notification_type: NotificationType,
        title: str,
        message: str,
        priority: NotificationPriority = NotificationPriority.NORMAL,
        data: Dict[str, Any] = None,
        expires_in_hours: Optional[int] = None,
    ) -> str:
        """Create and queue notification."""
        try:
            notification_id = str(uuid4())
            expires_at = None

            if expires_in_hours:
                expires_at = datetime.now() + timedelta(hours=expires_in_hours)

            notification = Notification(
                notification_id=notification_id,
                user_id=user_id,
                notification_type=notification_type,
                title=title,
                message=message,
                priority=priority,
                created_at=datetime.now(),
                read_at=None,
                data=data or {},
                expires_at=expires_at,
            )

            # Queue for processing
            await self.notification_queue.put(notification)

            # Performance tracking
            if self.performance_logger:
                self.performance_logger.increment_counter("notifications_created", 1)

            return notification_id

        except Exception as e:
            logger.error(f"Error creating notification: {e}")
            raise

    async def mark_as_read(self, notification_id: str, user_id: int) -> bool:
        """Mark notification as read."""
        try:
            if self.db_manager:
                async with self.db_manager.get_session() as session:
                    result = await session.execute(
                        """
                        UPDATE notifications
                        SET read_at = ?
                        WHERE notification_id = ? AND user_id = ? AND read_at IS NULL
                    """,
                        (datetime.now(), notification_id, user_id),
                    )
                    await session.commit()

                if result.rowcount > 0:
                    self.notifications_read += 1
                    if self.performance_logger:
                        self.performance_logger.increment_counter(
                            "notifications_read", 1
                        )
                    return True

            return False

        except Exception as e:
            logger.error(f"Error marking notification as read: {e}")
            return False

    async def get_user_notifications(
        self, user_id: int, limit: int = 50, unread_only: bool = False
    ) -> List[Dict[str, Any]]:
        """Get user notifications."""
        try:
            if not self.db_manager:
                return []

            query = """
                SELECT notification_id, notification_type, title, message,
                    priority, created_at, read_at, data
                FROM notifications
                WHERE user_id = ? AND (expires_at IS NULL OR expires_at > ?)
            """

            if unread_only:
                query += " AND read_at IS NULL"

            query += " ORDER BY created_at DESC LIMIT ?"

            params = {"user_id": user_id, "expires_at": datetime.now(), "limit": limit}

            result = await self.db_manager.execute_query(query, params)

            notifications = []
            for row in result:
                notifications.append(
                    {
                        "id": row[0],
                        "type": row[1],
                        "title": row[2],
                        "message": row[3],
                        "priority": row[4],
                        "created_at": row[5].isoformat() if row[5] else None,
                        "read_at": row[6].isoformat() if row[6] else None,
                        "data": json.loads(row[7]) if row[7] else {},
                    }
                )

            return notifications

        except Exception as e:
            logger.error(f"Error getting user notifications: {e}")
            return []

    async def get_unread_count(self, user_id: int) -> int:
        """Get unread notification count for user."""
        try:
            if not self.db_manager:
                return 0

            query = """
                SELECT COUNT(*) FROM notifications
                WHERE user_id = ? AND read_at IS NULL
                AND (expires_at IS NULL OR expires_at > ?)
            """
            params = {"user_id": user_id, "expires_at": datetime.now()}

            result = await self.db_manager.execute_query(query, params)
            return result[0][0] if result else 0

        except Exception as e:
            logger.error(f"Error getting unread count: {e}")
            return 0

    async def cleanup_expired_notifications(self):
        """Clean up expired notifications."""
        try:
            if self.db_manager:
                query = "DELETE FROM notifications WHERE expires_at IS NOT NULL AND expires_at <= ?"
                params = {"expires_at": datetime.now()}

                result = await self.db_manager.execute_query(query, params)

                if result:
                    self.notifications_expired += len(result)
                    if self.performance_logger:
                        self.performance_logger.record_metric(
                            "notifications_expired", len(result), "count"
                        )

                    logger.info(f"Cleaned up {len(result)} expired notifications")

        except Exception as e:
            logger.error(f"Error cleaning up expired notifications: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Get notification statistics."""
        return {
            "notifications_sent": self.notifications_sent,
            "notifications_read": self.notifications_read,
            "notifications_expired": self.notifications_expired,
            "queue_size": self.notification_queue.qsize(),
            "processing": self.processing,
        }


# Global notification manager
notification_manager = NotificationManager()


# Convenience functions
async def send_notification(
    user_id: int, notification_type: str, title: str, message: str, **kwargs
) -> str:
    """Send notification using global manager."""
    try:
        ntype = NotificationType(notification_type)
    except ValueError:
        ntype = NotificationType.INFO

    priority = NotificationPriority.NORMAL
    if "priority" in kwargs:
        try:
            priority = NotificationPriority(kwargs["priority"])
        except ValueError:
            pass

    return await notification_manager.create_notification(
        user_id,
        ntype,
        title,
        message,
        priority,
        data=kwargs.get("data"),
        expires_in_hours=kwargs.get("expires_in_hours"),
    )


async def mark_notification_read(notification_id: str, user_id: int) -> bool:
    """Mark notification as read using global manager."""
    return await notification_manager.mark_as_read(notification_id, user_id)


async def get_notifications(
    user_id: int, limit: int = 50, unread_only: bool = False
) -> List[Dict[str, Any]]:
    """Get notifications using global manager."""
    return await notification_manager.get_user_notifications(
        user_id, limit, unread_only
    )


async def get_unread_notification_count(user_id: int) -> int:
    """Get unread count using global manager."""
    return await notification_manager.get_unread_count(user_id)
