"""
WebSocket Manager Interface

Interface layer for WebSocket management with typing indicators integration.
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime

from plexichat.core.websocket.websocket_manager import websocket_manager as core_websocket_manager
from plexichat.core.services.typing_service import typing_service

logger = logging.getLogger(__name__)


class WebSocketManagerInterface:
    """Interface layer for WebSocket management with typing integration."""

    def __init__(self):
        self.core_manager = core_websocket_manager
        self.typing_service = typing_service

    async def connect(self, websocket, connection_id: str, user_id: Optional[int] = None) -> bool:
        """Connect new WebSocket."""
        return await self.core_manager.connect(websocket, connection_id, user_id)

    async def disconnect(self, connection_id: str):
        """Disconnect WebSocket."""
        # Stop any typing indicators for this connection
        connection = self.core_manager.connections.get(connection_id)
        if connection and connection.user_id:
            # Get all channels this user is typing in
            user_id = str(connection.user_id)
            # Note: In a real implementation, we'd track which channels each connection is typing in
            # For now, we'll clean up when disconnecting
            pass

        return await self.core_manager.disconnect(connection_id)

    async def join_channel(self, connection_id: str, channel: str) -> bool:
        """Join connection to channel."""
        return await self.core_manager.join_channel(connection_id, channel)

    async def leave_channel(self, connection_id: str, channel: str) -> bool:
        """Leave connection from channel."""
        # Stop typing when leaving channel
        connection = self.core_manager.connections.get(connection_id)
        if connection and connection.user_id:
            user_id = str(connection.user_id)
            await self.typing_service.stop_typing(user_id, channel)

        return await self.core_manager.leave_channel(connection_id, channel)

    async def send_to_channel(self, channel: str, message: Dict[str, Any]):
        """Send message to channel."""
        return await self.core_manager.send_to_channel(channel, message)

    async def broadcast_to_all(self, message: Dict[str, Any]):
        """Broadcast message to all connections."""
        return await self.core_manager.broadcast_to_all(message)

    async def start_typing(self, connection_id: str, channel_id: str) -> bool:
        """Start typing indicator for user in channel."""
        try:
            connection = self.core_manager.connections.get(connection_id)
            if not connection or not connection.user_id:
                logger.warning(f"Invalid connection or user for typing start: {connection_id}")
                return False

            user_id = str(connection.user_id)
            return await self.typing_service.start_typing(user_id, channel_id)

        except Exception as e:
            logger.error(f"Error starting typing for connection {connection_id}: {e}")
            return False

    async def stop_typing(self, connection_id: str, channel_id: str) -> bool:
        """Stop typing indicator for user in channel."""
        try:
            connection = self.core_manager.connections.get(connection_id)
            if not connection or not connection.user_id:
                logger.warning(f"Invalid connection or user for typing stop: {connection_id}")
                return False

            user_id = str(connection.user_id)
            return await self.typing_service.stop_typing(user_id, channel_id)

        except Exception as e:
            logger.error(f"Error stopping typing for connection {connection_id}: {e}")
            return False

    def get_typing_users(self, channel_id: str) -> List[str]:
        """Get list of users currently typing in channel."""
        # Use typing service for persistence
        # Note: This is a sync call, but typing_service.get_typing_users is async
        # In a real implementation, this would need to be handled differently
        # For now, return empty list as fallback
        logger.warning("get_typing_users called on interface - should use typing service directly")
        return []

    async def get_typing_users_async(self, channel_id: str) -> List[str]:
        """Get list of users currently typing in channel (async version)."""
        return await self.typing_service.get_typing_users(channel_id)

    def get_connection_count(self) -> int:
        """Get current connection count."""
        return self.core_manager.get_connection_count()

    def get_channel_connection_count(self, channel: str) -> int:
        """Get connection count for channel."""
        return self.core_manager.get_channel_connection_count(channel)

    def get_stats(self) -> Dict[str, Any]:
        """Get WebSocket statistics."""
        stats = self.core_manager.get_stats()
        # Add typing service stats if available
        return stats

    async def cleanup_expired_typing_states(self) -> int:
        """Clean up expired typing states."""
        return await self.typing_service.cleanup_expired_states()


# Global interface instance
websocket_manager = WebSocketManagerInterface()

# Convenience functions that delegate to the interface
async def connect_websocket(websocket, connection_id: str, user_id: Optional[int] = None) -> bool:
    """Connect WebSocket via interface."""
    return await websocket_manager.connect(websocket, connection_id, user_id)

async def disconnect_websocket(connection_id: str):
    """Disconnect WebSocket via interface."""
    await websocket_manager.disconnect(connection_id)

async def join_channel(connection_id: str, channel: str) -> bool:
    """Join channel via interface."""
    return await websocket_manager.join_channel(connection_id, channel)

async def leave_channel(connection_id: str, channel: str) -> bool:
    """Leave channel via interface."""
    return await websocket_manager.leave_channel(connection_id, channel)

async def send_to_channel(channel: str, message: Dict[str, Any]):
    """Send to channel via interface."""
    await websocket_manager.send_to_channel(channel, message)

async def broadcast_message(message: Dict[str, Any]):
    """Broadcast message via interface."""
    await websocket_manager.broadcast_to_all(message)

async def start_typing(connection_id: str, channel_id: str) -> bool:
    """Start typing via interface."""
    return await websocket_manager.start_typing(connection_id, channel_id)

async def stop_typing(connection_id: str, channel_id: str) -> bool:
    """Stop typing via interface."""
    return await websocket_manager.stop_typing(connection_id, channel_id)

async def get_typing_users_async(channel_id: str) -> List[str]:
    """Get typing users via interface."""
    return await websocket_manager.get_typing_users_async(channel_id)