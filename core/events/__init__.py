"""Core events module with fallback implementations."""
__version__ = "0.0.0"
__all__ = ["EventManager", "Event", "EventHandler", "EventPriority", "event_manager", "emit_event", "register_event_handler", "global_event_handler"]

class EventManager:
    def __init__(self):
        pass

class Event:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

class EventHandler:
    def __init__(self):
        pass

class EventPriority:
    LOW = 1
    MEDIUM = 2
    HIGH = 3

event_manager = None
global_event_handler = None

def emit_event(*args, **kwargs):
    pass

def register_event_handler(*args, **kwargs):
    pass