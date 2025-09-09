"""Core messaging module with fallback implementations."""

try:
    from plexichat.core.utils.fallbacks import (  # type: ignore[attr-defined]
        ChannelType,
        MessageEncryption,
        MessageType,
        MessageValidator,
        UnifiedMessagingManager,
        get_fallback_instance,
        get_module_version,
        send_message,
    )
except ImportError:
    # Retain old fallbacks if utils not available
    pass

__version__ = get_module_version()
__all__ = [
    "UnifiedMessagingManager",
    "MessageEncryption",
    "MessageValidator",
    "MessageType",
    "ChannelType",
    "unified_messaging_manager",
    "send_message",
]

unified_messaging_manager = get_fallback_instance("UnifiedMessagingManager")
