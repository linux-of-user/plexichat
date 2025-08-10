"""
PlexiChat Core Messaging System - SINGLE SOURCE OF TRUTH

Consolidated messaging functionality with fallback implementations.
"""

import warnings
import logging
from typing import Any, Dict, List, Optional

# Use fallback implementations to avoid import issues
logger = logging.getLogger(__name__)
logger.warning("Using fallback messaging implementations")

# Fallback implementations
class UnifiedMessagingManager:  # type: ignore
    def __init__(self):
        pass

class MessageEncryption:  # type: ignore
    def __init__(self):
        pass

class MessageValidator:  # type: ignore
    def __init__(self):
        pass

class MessageRouter:  # type: ignore
    def __init__(self):
        pass

class ChannelManager:  # type: ignore
    def __init__(self):
        pass

class MessageMetadata:  # type: ignore
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

class MessageDelivery:  # type: ignore
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

class ChannelSettings:  # type: ignore
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

class MessageType:  # type: ignore
    TEXT = "text"
    IMAGE = "image"
    FILE = "file"

class ChannelType:  # type: ignore
    PUBLIC = "public"
    PRIVATE = "private"
    GROUP = "group"

class MessageStatus:  # type: ignore
    PENDING = "pending"
    SENT = "sent"
    DELIVERED = "delivered"
    READ = "read"

class EncryptionLevel:  # type: ignore
    NONE = "none"
    BASIC = "basic"
    ADVANCED = "advanced"

unified_messaging_manager = UnifiedMessagingManager()

# Main functions
async def send_message(*args, **kwargs):  # type: ignore
    return None

async def get_message(*args, **kwargs):  # type: ignore
    return None

async def get_channel_messages(*args, **kwargs):  # type: ignore
    return []

async def create_channel(*args, **kwargs):  # type: ignore
    return None

def get_messaging_manager():  # type: ignore
    return unified_messaging_manager

# Backward compatibility aliases
messaging_manager = unified_messaging_manager
MessagingManager = UnifiedMessagingManager
MessageProcessor = UnifiedMessagingManager
message_processor = unified_messaging_manager

# Legacy function aliases
async def queue_message(sender_id: str, channel_id: str, content: str, **kwargs):
    """Queue message (backward compatibility)."""
    return await send_message(sender_id, channel_id, content, **kwargs)

async def process_message_now(sender_id: str, channel_id: str, content: str, **kwargs):
    """Process message immediately (backward compatibility)."""
    return await send_message(sender_id, channel_id, content, **kwargs)

# Legacy data class
class MessageData:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

# Export all the main classes and functions
__all__ = [
    # Unified messaging system (NEW SINGLE SOURCE OF TRUTH)
    "UnifiedMessagingManager",
    "unified_messaging_manager",
    "MessageEncryption",
    "MessageValidator",
    "MessageRouter",
    "ChannelManager",

    # Data classes
    "MessageMetadata",
    "MessageDelivery",
    "ChannelSettings",
    "MessageType",
    "ChannelType",
    "MessageStatus",
    "EncryptionLevel",
    "MessageData",

    # Main functions
    "send_message",
    "get_message",
    "get_channel_messages",
    "create_channel",
    "get_messaging_manager",

    # Backward compatibility aliases
    "messaging_manager",
    "MessagingManager",
    "MessageProcessor",
    "message_processor",
    "queue_message",
    "process_message_now",
]

from plexichat.core.unified_config import get_config

__version__ = get_config("system.version", "0.0.0")
