"""
PlexiChat - Real-time Communication Platform
Copyright (C) 2025 PlexiChat Contributors

WebSocket Manager
"""

import asyncio
from typing import Dict, Set, Optional
from datetime import datetime, timezone

from plexichat.core.logging import get_logger

logger = get_logger(__name__)

class WebSocketManager:
    """
    Manages WebSocket connections and broadcasting.
    """
    def __init__(self):
        self._connections: Dict[str, Set] = {}
        self._cleanup_task: Optional[asyncio.Task] = None
        
    async def connect(self, client_id: str, websocket):
        """Register a new WebSocket connection."""
        if client_id not in self._connections:
            self._connections[client_id] = set()
        self._connections[client_id].add(websocket)
        logger.info(f"WebSocket connected: {client_id}")
        
    async def disconnect(self, client_id: str, websocket):
        """Unregister a WebSocket connection."""
        if client_id in self._connections:
            self._connections[client_id].discard(websocket)
            if not self._connections[client_id]:
                del self._connections[client_id]
        logger.info(f"WebSocket disconnected: {client_id}")
        
    async def broadcast(self, message: Dict):
        """Broadcast message to all connected clients."""
        for client_connections in self._connections.values():
            for websocket in client_connections:
                try:
                    await websocket.send_json(message)
                except Exception as e:
                    logger.error(f"WebSocket broadcast error: {e}")
                    
    async def send_to_user(self, client_id: str, message: Dict):
        """Send message to a specific user."""
        if client_id in self._connections:
            for websocket in self._connections[client_id]:
                try:
                    await websocket.send_json(message)
                except Exception as e:
                    logger.error(f"WebSocket send error: {e}")
                    
    async def start_cleanup_task(self):
        """Start background cleanup task."""
        if not self._cleanup_task:
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
            
    async def stop_cleanup_task(self):
        """Stop background cleanup task."""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            self._cleanup_task = None
            
    async def _cleanup_loop(self):
        """Background cleanup of stale connections."""
        while True:
            try:
                await asyncio.sleep(60)  # Cleanup every minute
                # Placeholder for actual cleanup logic
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Cleanup loop error: {e}")

# Global instance
websocket_manager = WebSocketManager()
