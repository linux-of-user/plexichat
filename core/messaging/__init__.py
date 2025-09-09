"""Core messaging module with fallback implementations."""
__version__ = "0.0.0"
__all__ = ["UnifiedMessagingManager", "MessageEncryption", "MessageValidator", "MessageType", "ChannelType", "unified_messaging_manager", "send_message"]

class UnifiedMessagingManager:
    def __init__(self):
        pass

class MessageEncryption:
    def __init__(self):
        pass

class MessageValidator:
    def __init__(self):
        pass

class MessageType:
    TEXT = 1
    IMAGE = 2
    FILE = 3

class ChannelType:
    DIRECT = 1
    GROUP = 2

unified_messaging_manager = None

async def send_message(*args, **kwargs):
    pass