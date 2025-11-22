"""
PlexiChat - Real-time Communication Platform
Copyright (C) 2025 PlexiChat Contributors

User Service
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from plexichat.core.database.manager import database_manager
from plexichat.core.logging import get_logger
from plexichat.core.auth.services.authentication import AuthenticationService

logger = get_logger(__name__)
auth_service = AuthenticationService()

class UserService:
    """
    Service for user management.
    """
    
    async def create_user(
        self, 
        username: str, 
        email: str,
        password: str,
        is_admin: bool = False
    ) -> Dict[str, Any]:
        """Create a new user."""
        hashed_password = auth_service.get_password_hash(password)
        
        query = """
        INSERT INTO users (username, email, hashed_password, is_admin, is_active, created_at)
        VALUES (:username, :email, :hashed_password, :is_admin, :is_active, :created_at)
        """
        params = {
            "username": username,
            "email": email,
            "hashed_password": hashed_password,
            "is_admin": is_admin,
            "is_active": True,
            "created_at": datetime.now(timezone.utc)
        }
        
        async with database_manager.get_session() as session:
            await session.execute(query, params)
            
        logger.info(f"User created: {username}")
        
        return {
            "username": username,
            "email": email,
            "is_admin": is_admin,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        
    async def get_user(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get a user by ID."""
        query = "SELECT * FROM users WHERE id = :user_id"
        
        async with database_manager.get_session() as session:
            row = await session.fetch_one(query, {"user_id": user_id})
            
        return dict(row) if row else None
        
    async def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Get a user by username."""
        query = "SELECT * FROM users WHERE username = :username"
        
        async with database_manager.get_session() as session:
            row = await session.fetch_one(query, {"username": username})
            
        return dict(row) if row else None
        
    async def update_user(
        self, 
        user_id: int, 
        **kwargs
    ) -> bool:
        """Update user fields."""
        allowed_fields = ["username", "email", "is_admin", "is_active"]
        updates = {k: v for k, v in kwargs.items() if k in allowed_fields}
        
        if not updates:
            return False
            
        set_clause = ", ".join([f"{k} = :{k}" for k in updates.keys()])
        query = f"UPDATE users SET {set_clause}, updated_at = :updated_at WHERE id = :user_id"
        
        params = {**updates, "updated_at": datetime.now(timezone.utc), "user_id": user_id}
        
        async with database_manager.get_session() as session:
            await session.execute(query, params)
            
        logger.info(f"User {user_id} updated")
        return True
        
    async def delete_user(self, user_id: int) -> bool:
        """Delete a user."""
        query = "DELETE FROM users WHERE id = :user_id"
        
        async with database_manager.get_session() as session:
            await session.execute(query, {"user_id": user_id})
            
        logger.info(f"User {user_id} deleted")
        return True
        
    async def list_users(self, limit: int = 100) -> List[Dict[str, Any]]:
        """List all users."""
        query = "SELECT * FROM users LIMIT :limit"
        
        async with database_manager.get_session() as session:
            rows = await session.fetch_all(query, {"limit": limit})
            
        return [dict(row) for row in rows]

# Global instance
user_service = UserService()
