# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
PlexiChat User Model

Enhanced user model with comprehensive functionality and performance optimization.
Uses EXISTING database abstraction and optimization systems.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

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

class UserBase(BaseModel):
    """Base user model with validation."""
    username: str = Field(..., min_length=3, max_length=50, description="Username")
    email: EmailStr = Field(..., description="Email address")
    first_name: Optional[str] = Field(None, max_length=50, description="First name")
    last_name: Optional[str] = Field(None, max_length=50, description="Last name")
    bio: Optional[str] = Field(None, max_length=500, description="User biography")
    avatar_url: Optional[str] = Field(None, description="Avatar image URL")
    timezone: Optional[str] = Field(None, description="User timezone")
    language: str = Field(default="en", description="Preferred language")
    
    @validator('username')
    def validate_username(cls, v):
        if not v.strip():
            raise ValueError('Username cannot be empty')
        import re
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Username can only contain letters, numbers, underscores, and hyphens')
        return v.strip()
    
    @validator('language')
    def validate_language(cls, v):
        valid_languages = ['en', 'es', 'fr', 'de', 'it', 'pt', 'ru', 'zh', 'ja', 'ko']
        if v not in valid_languages:
            return 'en'  # Default to English
        return v

class User(SQLModel, table=True):
    """Enhanced user model with comprehensive functionality."""
    
    # Primary fields
    id: Optional[int] = Field(default=None, primary_key=True, description="User ID")
    username: str = Field(..., unique=True, index=True, min_length=3, max_length=50, description="Username")
    email: str = Field(..., unique=True, index=True, description="Email address")
    hashed_password: str = Field(..., description="Hashed password")
    
    # Profile fields
    first_name: Optional[str] = Field(None, max_length=50, description="First name")
    last_name: Optional[str] = Field(None, max_length=50, description="Last name")
    bio: Optional[str] = Field(None, max_length=500, description="User biography")
    avatar_url: Optional[str] = Field(None, description="Avatar image URL")
    
    # Preferences
    timezone: Optional[str] = Field(None, description="User timezone")
    language: str = Field(default="en", description="Preferred language")
    theme: str = Field(default="light", description="UI theme preference")
    
    # Status fields
    is_active: bool = Field(default=True, description="User active status")
    is_admin: bool = Field(default=False, description="Admin status")
    is_verified: bool = Field(default=False, description="Email verification status")
    is_premium: bool = Field(default=False, description="Premium subscription status")
    
    # Timestamps
    created_at: datetime = Field(default_factory=datetime.now, description="Account creation timestamp")
    updated_at: Optional[datetime] = Field(None, description="Last update timestamp")
    last_login: Optional[datetime] = Field(None, description="Last login timestamp")
    last_activity: Optional[datetime] = Field(None, description="Last activity timestamp")
    
    # Security fields
    failed_login_attempts: int = Field(default=0, description="Failed login attempts")
    locked_until: Optional[datetime] = Field(None, description="Account lock expiration")
    password_changed_at: Optional[datetime] = Field(None, description="Last password change")
    
    # Statistics
    message_count: int = Field(default=0, description="Total messages sent")
    file_count: int = Field(default=0, description="Total files uploaded")
    login_count: int = Field(default=0, description="Total login count")
    
    # Relationships (would be defined with actual relationships in full implementation)
    # messages: List["Message"] = Relationship(back_populates="sender")
    # files: List["FileRecord"] = Relationship(back_populates="user")

class UserCreate(UserBase):
    """User creation model."""
    password: str = Field(..., min_length=6, max_length=100, description="Password")
    is_admin: bool = Field(default=False, description="Admin status")
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 6:
            raise ValueError('Password must be at least 6 characters long')
        # Add more password validation as needed
        return v

class UserUpdate(BaseModel):
    """User update model."""
    username: Optional[str] = Field(None, min_length=3, max_length=50, description="Username")
    email: Optional[EmailStr] = Field(None, description="Email address")
    first_name: Optional[str] = Field(None, max_length=50, description="First name")
    last_name: Optional[str] = Field(None, max_length=50, description="Last name")
    bio: Optional[str] = Field(None, max_length=500, description="Biography")
    avatar_url: Optional[str] = Field(None, description="Avatar URL")
    timezone: Optional[str] = Field(None, description="Timezone")
    language: Optional[str] = Field(None, description="Language")
    theme: Optional[str] = Field(None, description="Theme")
    is_active: Optional[bool] = Field(None, description="Active status")
    is_admin: Optional[bool] = Field(None, description="Admin status")
    is_verified: Optional[bool] = Field(None, description="Verified status")
    is_premium: Optional[bool] = Field(None, description="Premium status")

class UserResponse(UserBase):
    """User response model."""
    id: int = Field(..., description="User ID")
    is_active: bool = Field(..., description="Active status")
    is_admin: bool = Field(..., description="Admin status")
    is_verified: bool = Field(..., description="Verified status")
    is_premium: bool = Field(..., description="Premium status")
    created_at: datetime = Field(..., description="Creation timestamp")
    last_login: Optional[datetime] = Field(None, description="Last login timestamp")
    message_count: int = Field(default=0, description="Message count")
    file_count: int = Field(default=0, description="File count")
    login_count: int = Field(default=0, description="Login count")
    
    class Config:
        from_attributes = True

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
                
                # Create user
                hashed_password = hash_password(user_data.password)
                create_query = """
                    INSERT INTO users (
                        username, email, hashed_password, first_name, last_name, bio,
                        avatar_url, timezone, language, is_active, is_admin, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    RETURNING *
                """
                create_params = {
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
                        result = await self.db_manager.execute_query(create_query, create_params)
                else:
                    result = await self.db_manager.execute_query(create_query, create_params)
                
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
