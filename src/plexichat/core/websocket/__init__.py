"""PlexiChat WebSocket"""

import logging
from typing import Any, Dict, Optional

try:
    from .websocket_manager import (
        WebSocketManager, WebSocketConnection,
        websocket_manager, connect_websocket, disconnect_websocket,
        send_to_user, send_to_channel, broadcast_message
    )
    logger = logging.getLogger(__name__)
    logger.info("WebSocket modules imported")
except ImportError as e:
    logger = logging.getLogger(__name__)
    logger.warning(f"Could not import websocket modules: {e}")

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

__version__ = "1.0.0"
