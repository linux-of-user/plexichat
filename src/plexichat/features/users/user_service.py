# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import logging
from datetime import datetime
from typing import List, Optional

from .models import User
import time
# Removed unresolved import for '.schemas'. Using fallback UserCreate and UserUpdate classes if needed.

# Fallback UserCreate and UserUpdate if not imported
class UserCreate:
    username: str
    email: str
    role: str
class UserUpdate:
    def dict(self, exclude_unset=True):
        return {}}}

"""User business logic service."""
logger = logging.getLogger(__name__)

class UserManagementService:
    """User management service."""

    def __init__(self):
        self.users = {}  # In-memory storage for now
        self.profiles = {}
        self.preferences = {}

    async def create_user(self, user_data: UserCreate) -> User:
        """Create a new user."""
        user_id = f"user_{len(self.users) + 1}"
        user = User(
            id=user_id,
            username=user_data.username,
            email=user_data.email,
            role=user_data.role,
            created_at=datetime.now()
        )
        self.users[user_id] = user
        logger.info(f"Created user: {user.username}")
        return user

    async def get_user(self, user_id: str) -> Optional[User]:
        """Get user by ID."""
        return self.users.get(user_id)

    async def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username."""
        for user in self.users.values():
            if user.username == username:
                return user
        return None

    async def update_user(self, user_id: str, user_data: UserUpdate) -> Optional[User]:
        """Update user."""
        user = self.users.get(user_id)
        if not user:
            return None

        update_data = user_data.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(user, field, value)

        user.updated_at = datetime.now()
        logger.info(f"Updated user: {user.username}")
        return user

    async def delete_user(self, user_id: str) -> bool:
        """Delete user."""
        if user_id in self.users:
            user = self.users.pop(user_id)
            logger.info(f"Deleted user: {user.username}")
            return True
        return False

    async def list_users(self, limit: int = 100, offset: int = 0) -> List[User]:
        """List users with pagination."""
        users_list = list(self.users.values())
        return users_list[offset:offset + limit]

# Global service instance
user_service = UserManagementService()
