"""
Session Service
===============

Manages user sessions, including creation, validation, and revocation.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

from plexichat.core.database.manager import database_manager
from plexichat.core.logging import get_logger
from plexichat.core.config import get_config

logger = get_logger(__name__)
config = get_config()

class SessionService:
    """
    Service for managing user sessions.
    """

    async def create_session(self, user_id: int, user_agent: str, ip_address: str) -> str:
        """
        Create a new session for a user.
        Returns the session ID (token).
        """
        session_id = str(uuid.uuid4())
        expires_at = datetime.now(timezone.utc) + timedelta(days=7) # Default 7 days
        
        query = """
        INSERT INTO sessions (session_id, user_id, user_agent, ip_address, expires_at, created_at)
        VALUES (:session_id, :user_id, :user_agent, :ip_address, :expires_at, :created_at)
        """
        params = {
            "session_id": session_id,
            "user_id": user_id,
            "user_agent": user_agent,
            "ip_address": ip_address,
            "expires_at": expires_at,
            "created_at": datetime.now(timezone.utc)
        }
        
        async with database_manager.get_session() as session:
            await session.execute(query, params)
            
        logger.info(f"Created session {session_id} for user {user_id}")
        return session_id

    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a session by ID.
        """
        query = "SELECT * FROM sessions WHERE session_id = :session_id"
        async with database_manager.get_session() as session:
            result = await session.fetch_one(query, {"session_id": session_id})
            
        if not result:
            return None
            
        # Check expiry
        if result["expires_at"] < datetime.now(timezone.utc):
            await self.revoke_session(session_id)
            return None
            
        return result

    async def revoke_session(self, session_id: str):
        """
        Revoke (delete) a session.
        """
        query = "DELETE FROM sessions WHERE session_id = :session_id"
        async with database_manager.get_session() as session:
            await session.execute(query, {"session_id": session_id})
        logger.info(f"Revoked session {session_id}")

    async def cleanup_expired_sessions(self):
        """
        Remove all expired sessions.
        """
        query = "DELETE FROM sessions WHERE expires_at < :now"
        async with database_manager.get_session() as session:
            await session.execute(query, {"now": datetime.now(timezone.utc)})
        logger.info("Cleaned up expired sessions")

# Global instance
session_service = SessionService()
