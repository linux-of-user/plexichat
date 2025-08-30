"""PlexiChat Events"""

import logging
# Typing imports not used

# Use fallback implementations to avoid import issues
logger = logging.getLogger(__name__)
logger.warning("Using fallback event implementations")

# Fallback implementations
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

global_event_handler = None

__all__ = [
    "EventManager",
    "Event",
    "EventHandler",
    "EventPriority",
    "event_manager",
    "emit_event",
    "register_event_handler",
    "unregister_event_handler",
    "get_events",
    "event_handler",
    "global_event_handler",
]

from plexichat.core.config_manager import get_config

__version__ = get_config("system.version", "0.0.0")
