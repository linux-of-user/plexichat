"""Core notifications module with fallback implementations."""

from .notification_manager import NotificationManager, NotificationPriority
from .base_sender import NotificationSender

__version__ = "1.0.0"
__all__ = [
    "NotificationManager",
    "NotificationPriority",
    "NotificationSender",
]
