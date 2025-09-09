"""Core events module with fallback implementations."""

try:
    from plexichat.core.utils.fallbacks import (  # type: ignore[attr-defined]
        Event,
        EventHandler,
        EventManager,
        EventPriority,
        emit_event,
        get_fallback_instance,
        get_module_version,
        register_event_handler,
    )
except ImportError:
    # Retain old fallbacks if utils not available
    pass

__version__ = get_module_version()
__all__ = [
    "EventManager",
    "Event",
    "EventHandler",
    "EventPriority",
    "event_manager",
    "emit_event",
    "register_event_handler",
    "global_event_handler",
]

event_manager = get_fallback_instance("EventManager")
global_event_handler = get_fallback_instance("EventHandler")
