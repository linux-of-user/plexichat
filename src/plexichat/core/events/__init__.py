"""PlexiChat Events"""

import logging
from typing import Any, Callable, Dict, List, Optional

try:
    from .event_manager import ()
        EventManager, Event, EventHandler, EventPriority,
        event_manager, emit_event, register_event_handler,
        unregister_event_handler, get_events, event_handler, global_event_handler
    )
    logger = logging.getLogger(__name__)
    logger.info("Event modules imported")
except ImportError as e:
    logger = logging.getLogger(__name__)
    logger.warning(f"Could not import event modules: {e}")

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

__version__ = "1.0.0"
