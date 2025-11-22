"""
PlexiChat - Real-time Communication Platform
Copyright (C) 2025 PlexiChat Contributors

Messaging Service
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from plexichat.core.database.manager import database_manager
from plexichat.core.logging import get_logger

logger = get_logger(__name__)

class MessagingService:
    """
    Service for message management.
    """
    
    async def send_message(
        self, 
        user_id: int, 
        channel_id: int, 
        content: str
    ) -> Dict[str, Any]:
        """Send a message to a channel."""
        query = """
        INSERT INTO messages (user_id, channel_id, content, created_at)
        VALUES (:user_id, :channel_id, :content, :created_at)
        """
        params = {
            "user_id": user_id,
            "channel_id": channel_id,
            "content": content,
            "created_at": datetime.now(timezone.utc)
        }
        
        async with database_manager.get_session() as session:
            await session.execute(query, params)
            
        logger.info(f"Message sent by user {user_id} to channel {channel_id}")
        
        return {
            "user_id": user_id,
            "channel_id": channel_id,
            "content": content,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        
    async def get_messages(
        self, 
        channel_id: int, 
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Get messages for a channel."""
        query = """
        SELECT * FROM messages 
        WHERE channel_id = :channel_id 
        ORDER BY created_at DESC 
        LIMIT :limit
        """
        params = {"channel_id": channel_id, "limit": limit}
        
        async with database_manager.get_session() as session:
            rows = await session.fetch_all(query, params)
            
        return [dict(row) for row in rows]
        
    async def edit_message(
        self, 
        message_id: int, 
        new_content: str
    ) -> bool:
        """Edit a message."""
        query = """
        UPDATE messages 
        SET content = :content, edited_at = :edited_at 
        WHERE id = :message_id
        """
        params = {
            "content": new_content,
            "edited_at": datetime.now(timezone.utc),
            "message_id": message_id
        }
        
        async with database_manager.get_session() as session:
            await session.execute(query, params)
            
        logger.info(f"Message {message_id} edited")
        return True
        
    async def delete_message(self, message_id: int) -> bool:
        """Delete a message."""
        query = "DELETE FROM messages WHERE id = :message_id"
        
        async with database_manager.get_session() as session:
            await session.execute(query, {"message_id": message_id})
            
        logger.info(f"Message {message_id} deleted")
        return True

# Global instance
messaging_service = MessagingService()
