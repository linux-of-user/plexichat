"""PlexiChat WebSocket"""

import logging
from typing import Any, Dict, Optional, TYPE_CHECKING

logger = logging.getLogger(__name__)

# Try to import from websocket_manager, fall back to local implementations
try:
    from plexichat.core.websocket.websocket_manager import WebSocketManager as _WebSocketManager
    from plexichat.core.websocket.websocket_manager import WebSocketConnection as _WebSocketConnection

    # Use the imported classes
    WebSocketManager = _WebSocketManager  # type: ignore
    WebSocketConnection = _WebSocketConnection  # type: ignore

except ImportError:
    logger.warning("Using fallback WebSocket implementations")

    # Fallback classes
    class WebSocketManager:  # type: ignore
        def __init__(self):
            pass

    class WebSocketConnection:  # type: ignore
        def __init__(self):
            pass

# Set to None to indicate unavailable
websocket_manager = None
connect_websocket = None
disconnect_websocket = None
send_to_user = None
send_to_channel = None
broadcast_message = None

__all__ = [
    "WebSocketManager",
    "WebSocketConnection",
    "websocket_manager",
    "connect_websocket",
    "disconnect_websocket",
    "send_to_user",
    "send_to_channel",
    "broadcast_message",
]

from plexichat.src.plexichat.core.config_manager import get_config

__version__ = get_config("system.version", "0.0.0")
