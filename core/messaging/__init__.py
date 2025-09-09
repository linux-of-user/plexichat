"""Core messaging module with fallback implementations."""
try:
    from plexichat.core.utils.fallbacks import (
        UnifiedMessagingManager, MessageEncryption, MessageValidator,
        MessageType, ChannelType, send_message, get_fallback_instance,
        get_module_version
    )
except ImportError:
    # Retain old fallbacks
    pass

__version__ = get_module_version()
__all__ = ["UnifiedMessagingManager", "MessageEncryption", "MessageValidator", "MessageType", "ChannelType", "unified_messaging_manager", "send_message"]

unified_messaging_manager = get_fallback_instance('UnifiedMessagingManager')