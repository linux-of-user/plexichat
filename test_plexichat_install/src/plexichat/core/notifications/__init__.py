"""PlexiChat Notifications"""

import logging
from typing import Any, Dict, List, Optional

try:
    from .notification_manager import ()
        NotificationManager, Notification, NotificationType, NotificationPriority,
        notification_manager, send_notification, mark_notification_read,
        get_notifications, get_unread_notification_count
    )
    logger = logging.getLogger(__name__)
    logger.info("Notification modules imported")
except ImportError as e:
    logger = logging.getLogger(__name__)
    logger.warning(f"Could not import notification modules: {e}")

__all__ = [
    "NotificationManager",
    "Notification",
    "NotificationType",
    "NotificationPriority",
    "notification_manager",
    "send_notification",
    "mark_notification_read",
    "get_notifications",
    "get_unread_notification_count",
]

__version__ = "1.0.0"
