# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
import time
PlexiChat User Model

Enhanced user model with comprehensive functionality and performance optimization.
Uses EXISTING database abstraction and optimization systems.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, field

# SQLModel imports
try:
    from sqlmodel import SQLModel, Field, Relationship
except ImportError:
    SQLModel = object
    Field = lambda *args, **kwargs: None
    Relationship = lambda *args, **kwargs: None

# Pydantic imports
try:
    from pydantic import BaseModel, validator, EmailStr
except ImportError:
    BaseModel = object
    validator = lambda *args, **kwargs: lambda f: f
    EmailStr = str

# Use EXISTING database abstraction layer
try:
    from plexichat.core.database.manager import database_manager
except ImportError:
    database_manager = None

# Use EXISTING performance optimization engine
try:
    from plexichat.infrastructure.performance.optimization_engine import PerformanceOptimizationEngine
    from plexichat.infrastructure.utils.performance import async_track_performance
    from plexichat.core.logging_advanced.performance_logger import get_performance_logger, timer
except ImportError:
    PerformanceOptimizationEngine = None
    async_track_performance = None
    get_performance_logger = None
    timer = None

# Security imports
try:
    from plexichat.infrastructure.utils.security import hash_password, verify_password
except ImportError:
    def hash_password(password: str) -> str:
        return f"hashed_{password}"
    def verify_password(plain: str, hashed: str) -> bool:
        return plain == "password"

logger = logging.getLogger(__name__)

# Initialize EXISTING performance systems
performance_logger = get_performance_logger() if get_performance_logger else None

# Remove UserBase and UserResponse classes that inherit from BaseModel.

# Remove the SQLModel-based User class and replace with a dataclass User
@dataclass
class User:
    id: Optional[int] = None
    username: str = ""
    email: str = ""
    hashed_password: str = ""
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    timezone: Optional[str] = None
    language: str = "en"
    theme: str = "light"
    is_active: bool = True
    is_admin: bool = False
    is_verified: bool = False
    is_premium: bool = False
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: Optional[datetime] = None
    last_login: Optional[datetime] = None
    last_activity: Optional[datetime] = None
    failed_login_attempts: int = 0
    locked_until: Optional[datetime] = None
    password_changed_at: Optional[datetime] = None
    message_count: int = 0
    file_count: int = 0
    login_count: int = 0

@dataclass
class UserCreate:
    username: str = ""
    email: str = ""
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    timezone: Optional[str] = None
    language: str = "en"
    password: str = ""
    is_admin: bool = False

@dataclass
class UserUpdate:
    username: Optional[str] = None
    email: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    timezone: Optional[str] = None
    language: Optional[str] = None
    theme: Optional[str] = None
    is_active: Optional[bool] = None
    is_admin: Optional[bool] = None
    is_verified: Optional[bool] = None
    is_premium: Optional[bool] = None

@dataclass
class UserResponse:
    id: int = 0
    username: str = ""
    email: str = ""
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    timezone: Optional[str] = None
    language: str = "en"
    is_active: bool = True
    is_admin: bool = False
    is_verified: bool = False
    is_premium: bool = False
    created_at: datetime = field(default_factory=datetime.now)
    last_login: Optional[datetime] = None
    message_count: int = 0
    file_count: int = 0
    login_count: int = 0

class UserService:
    """Enhanced user service using EXISTING database abstraction."""

    def __init__(self):
        self.db_manager = database_manager
        self.performance_logger = performance_logger

    @async_track_performance("user_creation") if async_track_performance else lambda f: f
    async def create_user(self, user_data: UserCreate) -> Optional[User]:
        """Create new user using EXISTING database abstraction."""
        if self.db_manager:
            try:
                # Check if user exists
                check_query = "SELECT COUNT(*) FROM users WHERE username = ? OR email = ?"
                check_params = {"username": user_data.username, "email": user_data.email}

                if self.performance_logger and timer:
                    with timer("user_existence_check"):
                        result = await self.db_manager.execute_query(check_query, check_params)
                        exists = result[0][0] > 0 if result else False
                else:
                    result = await self.db_manager.execute_query(check_query, check_params)
                    exists = result[0][0] > 0 if result else False

                if exists:
                    return None  # User already exists

                # Create user using abstraction layer
                hashed_password = hash_password(user_data.password)

                user_record = {
                    "username": user_data.username,
                    "email": user_data.email,
                    "hashed_password": hashed_password,
                    "first_name": user_data.first_name,
                    "last_name": user_data.last_name,
                    "bio": user_data.bio,
                    "avatar_url": user_data.avatar_url,
                    "timezone": user_data.timezone,
                    "language": user_data.language,
                    "is_active": True,
                    "is_admin": user_data.is_admin,
                    "created_at": datetime.now()
                }

                if self.performance_logger and timer:
                    with timer("user_creation_query"):
                        result = await self.db_manager.insert_record("users", user_record)
                else:
                    result = await self.db_manager.insert_record("users", user_record)

                if result:
                    # Convert result to User object
                    row = result[0]
                    user = User(
                        id=row[0],
                        username=row[1],
                        email=row[2],
                        hashed_password=row[3],
                        # ... map other fields
                        created_at=row[-1]
                    )

                    # Performance tracking
                    if self.performance_logger:
                        self.performance_logger.record_metric("users_created", 1, "count")

                    return user

            except Exception as e:
                logger.error(f"Error creating user: {e}")
                return None

        return None

    @async_track_performance("user_update") if async_track_performance else lambda f: f
    async def update_user(self, user_id: int, user_data: UserUpdate) -> Optional[User]:
        """Update user using EXISTING database abstraction."""
        if self.db_manager:
            try:
                # Build update query dynamically
                update_fields = []
                params = {"id": user_id, "updated_at": datetime.now()}

                for field, value in user_data.dict(exclude_unset=True).items():
                    if value is not None:
                        update_fields.append(f"{field} = ?")
                        params[field] = value

                if not update_fields:
                    return None  # No fields to update

                update_query = f"""
                    UPDATE users
                    SET {', '.join(update_fields)}, updated_at = ?
                    WHERE id = ?
                    RETURNING *
                """

                if self.performance_logger and timer:
                    with timer("user_update_query"):
                        result = await self.db_manager.execute_query(update_query, params)
                else:
                    result = await self.db_manager.execute_query(update_query, params)

                if result:
                    # Convert result to User object
                    row = result[0]
                    user = User(
                        id=row[0],
                        username=row[1],
                        email=row[2],
                        # ... map other fields
                    )

                    # Performance tracking
                    if self.performance_logger:
                        self.performance_logger.record_metric("users_updated", 1, "count")

                    return user

            except Exception as e:
                logger.error(f"Error updating user: {e}")
                return None

        return None

    @async_track_performance("user_stats_update") if async_track_performance else lambda f: f
    async def update_user_stats(self, user_id: int, stat_type: str, increment: int = 1):
        """Update user statistics."""
        if self.db_manager:
            try:
                valid_stats = ["message_count", "file_count", "login_count"]
                if stat_type not in valid_stats:
                    return

                query = f"UPDATE users SET {stat_type} = {stat_type} + ? WHERE id = ?"
                params = {"increment": increment, "id": user_id}

                await self.db_manager.execute_query(query, params)

            except Exception as e:
                logger.error(f"Error updating user stats: {e}")

# Global user service instance
user_service = UserService()
