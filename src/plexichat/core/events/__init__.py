"""PlexiChat Events"""

import logging

# Typing imports not used

# Use shared fallback implementations
logger = logging.getLogger(__name__)

try:
    from plexichat.core.utils.fallbacks import (
        Event,
        EventHandler,
        EventManager,
        EventPriority,
        emit_event,
        event_handler,
        get_events,
        get_fallback_instance,
        register_event_handler,
        unregister_event_handler,
    )

    USE_SHARED_FALLBACKS = True
    logger.info("Using shared fallback implementations for events")
except ImportError:
    # Fallback to local definitions if shared fallbacks unavailable
    USE_SHARED_FALLBACKS = False
    logger.warning("Shared fallbacks unavailable, using local implementations")

if USE_SHARED_FALLBACKS:
    event_manager = get_fallback_instance("EventManager")
    global_event_handler = None
else:
    # Local fallbacks (preserved for compatibility)
    class EventManager:  # type: ignore
        def __init__(self):
            pass

    class Event:  # type: ignore
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    class EventHandler:  # type: ignore
        def __init__(self):
            pass

    class EventPriority:  # type: ignore
        HIGH = "high"
        NORMAL = "normal"
        LOW = "low"

    event_manager = None
    global_event_handler = None

    def emit_event(*args, **kwargs):  # type: ignore
        pass

    def register_event_handler(*args, **kwargs):  # type: ignore
        pass

    def unregister_event_handler(*args, **kwargs):  # type: ignore
        pass

    def get_events(*args, **kwargs):  # type: ignore
        return []

    def event_handler(*args, **kwargs):  # type: ignore
        def decorator(func):
            return func

        return decorator


__all__ = [
    "Event",
    "EventHandler",
    "EventManager",
    "EventPriority",
    "emit_event",
    "event_handler",
    "event_manager",
    "get_events",
    "global_event_handler",
    "register_event_handler",
    "unregister_event_handler",
]

from plexichat.core.utils.fallbacks import get_module_version

__version__ = get_module_version()
