"""PlexiChat Notifications"""

import logging
from typing import Any, Dict, List, Optional

# Use shared fallback implementations
logger = logging.getLogger(__name__)

try:
    from plexichat.core.utils.fallbacks import (
        Notification,
        NotificationManager,
        NotificationPriority,
        NotificationType,
        get_fallback_instance,
        get_notifications,
        get_unread_notification_count,
        mark_notification_read,
        send_notification,
    )

    USE_SHARED_FALLBACKS = True
    logger.info("Using shared fallback implementations for notifications")
except ImportError:
    # Fallback to local definitions if shared fallbacks unavailable
    USE_SHARED_FALLBACKS = False
    logger.warning("Shared fallbacks unavailable, using local implementations")

if USE_SHARED_FALLBACKS:
    notification_manager = get_fallback_instance("NotificationManager")
else:
    # Local fallbacks (preserved for compatibility)
    class NotificationManager:  # type: ignore
        def __init__(self) -> None:
            pass

    class Notification:  # type: ignore
        def __init__(self, **kwargs: Any) -> None:
            self.__dict__.update(kwargs)

    class NotificationType:  # type: ignore
        INFO = "info"
        WARNING = "warning"
        ERROR = "error"
        SUCCESS = "success"

    class NotificationPriority:  # type: ignore
        LOW = "low"
        NORMAL = "normal"
        HIGH = "high"
        URGENT = "urgent"

    notification_manager = None

    def send_notification(*args: Any, **kwargs: Any) -> None:  # type: ignore
        return None

    def mark_notification_read(*args: Any, **kwargs: Any) -> bool:  # type: ignore
        return False

    def get_notifications(*args: Any, **kwargs: Any) -> list[Any]:  # type: ignore
        return []

    def get_unread_notification_count(*args: Any, **kwargs: Any) -> int:  # type: ignore
        return 0


__all__ = [
    "Notification",
    "NotificationManager",
    "NotificationPriority",
    "NotificationType",
    "get_notifications",
    "get_unread_notification_count",
    "mark_notification_read",
    "notification_manager",
    "send_notification",
]

try:
    from plexichat.core.utils.fallbacks import get_module_version

    __version__ = get_module_version()
except ImportError:
    __version__ = "1.0.0"
