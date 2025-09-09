"""Core notifications module with fallback implementations."""
try:
    from plexichat.core.utils.fallbacks import (
        NotificationManager, Notification, NotificationType, NotificationPriority,
        send_notification, get_notifications, get_fallback_instance, get_module_version
    )
except ImportError:
    # Retain old fallbacks
    pass

__version__ = get_module_version()
__all__ = ["NotificationManager", "Notification", "NotificationType", "NotificationPriority", "notification_manager", "send_notification"]

notification_manager = get_fallback_instance('NotificationManager')