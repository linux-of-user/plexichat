"""
NetLink Users Module

Feature-based module for user management functionality.
Follows domain-driven design principles.
"""

from .models import User, UserProfile, UserPreferences
from .schemas import UserCreate, UserUpdate, UserResponse
from .service import UserService, user_service
from .router import router as users_router

__version__ = "1.0.0"
__all__ = [
    # Models
    "User",
    "UserProfile", 
    "UserPreferences",
    
    # Schemas
    "UserCreate",
    "UserUpdate",
    "UserResponse",
    
    # Services
    "UserService",
    "user_service",
    
    # Router
    "users_router"
]
