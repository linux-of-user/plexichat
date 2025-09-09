"""Core notifications module with fallback implementations."""
__version__ = "0.0.0"
__all__ = ["NotificationManager", "Notification", "NotificationType", "NotificationPriority", "notification_manager", "send_notification"]

class NotificationManager:
    def __init__(self):
        pass

class Notification:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

class NotificationType:
    EMAIL = 1
    SMS = 2
    PUSH = 3

class NotificationPriority:
    LOW = 1
    MEDIUM = 2
    HIGH = 3

notification_manager = None

def send_notification(*args, **kwargs):
    pass

def get_notifications(*args, **kwargs):
    pass