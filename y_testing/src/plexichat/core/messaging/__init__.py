"""
PlexiChat Core Messaging System - SINGLE SOURCE OF TRUTH

Consolidates ALL messaging functionality from:
- core/messaging/message_processor.py - INTEGRATED
- features/messaging/ (all modules) - INTEGRATED
- infrastructure/messaging/ - INTEGRATED

Provides a single, unified interface for all messaging operations with:
- Message routing and delivery
- End-to-end encryption
- Real-time messaging
- Message persistence
- Group messaging
- Voice/video channels
- Business automation
"""

import warnings
import logging
from typing import Any, Dict, List, Optional

# Import unified messaging system (NEW SINGLE SOURCE OF TRUTH)
try:
    from .unified_messaging_system import ()
        # Main classes
        UnifiedMessagingManager,
        unified_messaging_manager,
        MessageEncryption,
        MessageValidator,
        MessageRouter,
        ChannelManager,

        # Data classes
        MessageMetadata,
        MessageDelivery,
        ChannelSettings,
        MessageType,
        ChannelType,
        MessageStatus,
        EncryptionLevel,

        # Main functions
        send_message,
        get_message,
        get_channel_messages,
        create_channel,
        get_messaging_manager,
    )

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

    logger = logging.getLogger(__name__)
    logger.info("Unified messaging system imported successfully")

except ImportError as e:
    # Fallback definitions if unified messaging system fails to import
    import logging

    warnings.warn()
        f"Failed to import unified messaging system: {e}. Using fallback messaging.",
        ImportWarning,
        stacklevel=2
    )

    logger = logging.getLogger(__name__)

    class MessageData:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    class UnifiedMessagingManager:
        def __init__(self):
            self.initialized = False

        async def initialize(self) -> bool:
            logger.warning("Using fallback messaging manager")
            self.initialized = True
            return True

    unified_messaging_manager = UnifiedMessagingManager()
    messaging_manager = unified_messaging_manager
    MessagingManager = UnifiedMessagingManager
    MessageProcessor = UnifiedMessagingManager
    message_processor = unified_messaging_manager

    async def send_message(sender_id: str, channel_id: str, content: str, **kwargs):
        logger.warning("Message sending not available in fallback mode")
        return None

    async def queue_message(sender_id: str, channel_id: str, content: str, **kwargs):
        return await send_message(sender_id, channel_id, content, **kwargs)

    async def process_message_now(sender_id: str, channel_id: str, content: str, **kwargs):
        return await send_message(sender_id, channel_id, content, **kwargs)

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

__version__ = "3.0.0"
