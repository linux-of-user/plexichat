"""
PlexiChat - Real-time Communication Platform
Copyright (C) 2025 PlexiChat Contributors

Channel Service
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from plexichat.core.database.manager import database_manager
from plexichat.core.logging import get_logger

logger = get_logger(__name__)

class ChannelService:
    """
    Service for channel management.
    """
    
    async def create_channel(
        self, 
        name: str, 
        description: Optional[str] = None,
        is_private: bool = False
    ) -> Dict[str, Any]:
        """Create a new channel."""
        query = """
        INSERT INTO channels (name, description, is_private, created_at)
        VALUES (:name, :description, :is_private, :created_at)
        """
        params = {
            "name": name,
            "description": description,
            "is_private": is_private,
            "created_at": datetime.now(timezone.utc)
        }
        
        async with database_manager.get_session() as session:
            await session.execute(query, params)
            
        logger.info(f"Channel created: {name}")
        
        return {
            "name": name,
            "description": description,
            "is_private": is_private,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        
    async def get_channels(self, is_private: Optional[bool] = None) -> List[Dict[str, Any]]:
        """Get list of channels."""
        if is_private is not None:
            query = "SELECT * FROM channels WHERE is_private = :is_private"
            params = {"is_private": is_private}
        else:
            query = "SELECT * FROM channels"
            params = {}
            
        async with database_manager.get_session() as session:
            rows = await session.fetch_all(query, params)
            
        return [dict(row) for row in rows]
        
    async def get_channel(self, channel_id: int) -> Optional[Dict[str, Any]]:
        """Get a specific channel."""
        query = "SELECT * FROM channels WHERE id = :channel_id"
        
        async with database_manager.get_session() as session:
            row = await session.fetch_one(query, {"channel_id": channel_id})
            
        return dict(row) if row else None
        
    async def delete_channel(self, channel_id: int) -> bool:
        """Delete a channel."""
        query = "DELETE FROM channels WHERE id = :channel_id"
        
        async with database_manager.get_session() as session:
            await session.execute(query, {"channel_id": channel_id})
            
        logger.info(f"Channel {channel_id} deleted")
        return True

# Global instance
channel_service = ChannelService()
