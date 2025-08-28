"""PlexiChat Notifications"""

import logging
from typing import Any, Dict, List, Optional

# Use fallback implementations to avoid import issues
logger = logging.getLogger(__name__)
logger.warning("Using fallback notification implementations")

# Fallback implementations
class NotificationManager:  # type: ignore
    def __init__(self):
        pass

class Notification:  # type: ignore
    def __init__(self, **kwargs):
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

def send_notification(*args, **kwargs):  # type: ignore
    return None

def mark_notification_read(*args, **kwargs):  # type: ignore
    return False

def get_notifications(*args, **kwargs):  # type: ignore
    return []

def get_unread_notification_count(*args, **kwargs):  # type: ignore
    return 0

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

from plexichat.src.plexichat.core.config_manager import get_config

__version__ = get_config("system.version", "0.0.0")
