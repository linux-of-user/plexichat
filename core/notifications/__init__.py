"""Core notifications module with fallback implementations."""

from plexichat.core.utils.fallbacks import (
    Notification,
    NotificationManager,
    NotificationPriority,
    NotificationType,
    get_fallback_instance,
    get_module_version,
    get_notifications,
    send_notification,
)

__version__ = get_module_version()
__all__ = [
    "NotificationManager",
    "Notification",
    "NotificationType",
    "NotificationPriority",
    "notification_manager",
    "send_notification",
]

notification_manager = get_fallback_instance("NotificationManager")
