"""
PlexiChat Core Messaging System

Consolidated messaging functionality.
"""

import logging

# Import from the new messaging system
from plexichat.core.messaging.system import (
    Channel,
    ChannelManager,
    ChannelType,
    EncryptionLevel,
    Message,
    MessageEncryption,
    MessageMetadata,
    MessageRouter,
    MessageStatus,
    MessageType,
    MessageValidator,
    MessagingSystem,
    Thread,
    get_messaging_system,
    initialize_messaging_system,
    shutdown_messaging_system,
)

logger = logging.getLogger(__name__)

# Initialize the global instance
messaging_system = get_messaging_system()

# Backward compatibility aliases
UnifiedMessagingManager = MessagingSystem
unified_messaging_manager = messaging_system
messaging_manager = messaging_system
MessagingManager = MessagingSystem
MessageProcessor = MessagingSystem
message_processor = messaging_system


# Legacy function aliases
async def send_message(*args, **kwargs):
    """Send message (proxy to messaging system)."""
    return await messaging_system.send_message(*args, **kwargs)


async def get_message(*args, **kwargs):
    """Get message (proxy to messaging system)."""
    # Note: get_message is not directly exposed in MessagingSystem, 
    # usually retrieved via get_channel_messages or internal storage
    # This is a stub for backward compatibility if needed
    return None


async def get_channel_messages(*args, **kwargs):
    """Get channel messages (proxy to messaging system)."""
    return await messaging_system.get_channel_messages(*args, **kwargs)


async def create_channel(*args, **kwargs):
    """Create channel (proxy to messaging system)."""
    return messaging_system.channel_manager.create_channel(*args, **kwargs)


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
    # Messaging system
    "MessagingSystem",
    "messaging_system",
    "MessageEncryption",
    "MessageValidator",
    "MessageRouter",
    "ChannelManager",
    "Thread",
    # Data classes
    "Message",
    "MessageMetadata",
    "Channel",
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
    "get_messaging_system",
    "initialize_messaging_system",
    "shutdown_messaging_system",
    # Backward compatibility aliases
    "UnifiedMessagingManager",
    "unified_messaging_manager",
    "messaging_manager",
    "MessagingManager",
    "MessageProcessor",
    "message_processor",
    "queue_message",
    "process_message_now",
]

from plexichat.core.utils.fallbacks import get_module_version

__version__ = get_module_version()
