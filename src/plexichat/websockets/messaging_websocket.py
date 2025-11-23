"""
Messaging WebSocket Manager
===========================

Handles WebSocket connections for real-time messaging.
"""

import json
import logging
from typing import Any, Dict, Set

from fastapi import WebSocket

from plexichat.core.logging import get_logger

logger = get_logger(__name__)

class MessagingWebSocketManager:
    """Manages WebSocket connections and message broadcasting."""

    def __init__(self):
        # active_connections: user_id -> set(WebSocket)
        self.active_connections: Dict[str, Set[WebSocket]] = {}
        # channel_subscriptions: channel_id -> set(WebSocket)
        self.channel_subscriptions: Dict[int, Set[WebSocket]] = {}
        # guild_subscriptions: guild_id -> set(WebSocket)
        self.guild_subscriptions: Dict[int, Set[WebSocket]] = {}
        
        # Map websocket to user_id for cleanup
        self.socket_to_user: Dict[WebSocket, str] = {}

    async def connect(self, websocket: WebSocket, user: Any):
        """Connect a user via WebSocket."""
        await websocket.accept()
        user_id = str(getattr(user, "id", getattr(user, "user_id", "unknown")))
        
        if user_id not in self.active_connections:
            self.active_connections[user_id] = set()
        
        self.active_connections[user_id].add(websocket)
        self.socket_to_user[websocket] = user_id
        
        logger.info(f"User {user_id} connected via WebSocket")

    async def disconnect(self, websocket: WebSocket):
        """Disconnect a WebSocket."""
        user_id = self.socket_to_user.get(websocket)
        
        # Remove from active connections
        if user_id and user_id in self.active_connections:
            self.active_connections[user_id].discard(websocket)
            if not self.active_connections[user_id]:
                del self.active_connections[user_id]
        
        # Remove from channel subscriptions
        for subscribers in self.channel_subscriptions.values():
            subscribers.discard(websocket)
            
        # Remove from guild subscriptions
        for subscribers in self.guild_subscriptions.values():
            subscribers.discard(websocket)
            
        if websocket in self.socket_to_user:
            del self.socket_to_user[websocket]
            
        logger.info(f"User {user_id} disconnected")

    async def handle_message(self, websocket: WebSocket, message_data: str):
        """Handle incoming WebSocket message."""
        try:
            data = json.loads(message_data)
            msg_type = data.get("type")
            
            # Basic echo/broadcast logic for now
            # In a real system, this would dispatch to services
            logger.debug(f"Received message: {msg_type}")
            
            # Example: Echo back
            await websocket.send_text(json.dumps({
                "type": "ack",
                "reply_to": msg_type,
                "status": "received"
            }))
            
        except json.JSONDecodeError:
            logger.warning("Invalid JSON received")
        except Exception as e:
            logger.error(f"Error handling message: {e}")

    async def subscribe_to_channel(self, websocket: WebSocket, channel_id: int):
        """Subscribe websocket to a channel."""
        if channel_id not in self.channel_subscriptions:
            self.channel_subscriptions[channel_id] = set()
        self.channel_subscriptions[channel_id].add(websocket)

    async def subscribe_to_guild(self, websocket: WebSocket, guild_id: int):
        """Subscribe websocket to a guild."""
        if guild_id not in self.guild_subscriptions:
            self.guild_subscriptions[guild_id] = set()
        self.guild_subscriptions[guild_id].add(websocket)

    async def get_connection_stats(self) -> Dict[str, Any]:
        """Get connection statistics."""
        return {
            "total_connections": len(self.socket_to_user),
            "active_users": len(self.active_connections),
            "active_channels": len(self.channel_subscriptions),
            "active_guilds": len(self.guild_subscriptions)
        }

# Global instance
messaging_websocket_manager = MessagingWebSocketManager()
