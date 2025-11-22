"""
Authentication Service
======================

Handles user authentication, password hashing, and token generation.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
import logging

from passlib.context import CryptContext
from jose import jwt, JWTError

from plexichat.core.config import get_config
from plexichat.core.logging import get_logger
from plexichat.core.database.manager import database_manager
from plexichat.core.auth.exceptions_auth import AuthenticationError, InvalidCredentialsError

logger = get_logger(__name__)
config = get_config()

# Password hashing context
pwd_context = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")

class AuthenticationService:
    """
    Service for handling authentication logic.
    """
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify a password against a hash."""
        return pwd_context.verify(plain_password, hashed_password)

    @staticmethod
    def get_password_hash(password: str) -> str:
        """Generate a password hash."""
        return pwd_context.hash(password)

    @staticmethod
    def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Create a JWT access token."""
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=config.security.access_token_expire_minutes)
        
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, config.security.secret_key, algorithm=config.security.algorithm)
        return encoded_jwt

    async def authenticate_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """
        Authenticate a user against the database.
        Returns the user dict if successful, None otherwise.
        """
        query = "SELECT * FROM users WHERE username = :username"
        async with database_manager.get_session() as session:
            user = await session.fetch_one(query, {"username": username})
            
        if not user:
            return None
            
        if not self.verify_password(password, user["hashed_password"]):
            return None
            
        return user

    async def get_current_user(self, token: str) -> Dict[str, Any]:
        """
        Validate and decode a token to get the current user.
        """
        try:
            payload = jwt.decode(token, config.security.secret_key, algorithms=[config.security.algorithm])
            username: str = payload.get("sub")
            if username is None:
                raise AuthenticationError("Could not validate credentials")
        except JWTError:
            raise AuthenticationError("Could not validate credentials")
            
        async with database_manager.get_session() as session:
            user = await session.fetch_one("SELECT * FROM users WHERE username = :username", {"username": username})
            
        if user is None:
            raise AuthenticationError("User not found")
            
        return user

# Global instance
auth_service = AuthenticationService()
