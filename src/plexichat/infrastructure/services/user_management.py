# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import hashlib
import io
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import bcrypt
try:
    from PIL import Image  # type: ignore
except ImportError:
    Image = None
from sqlmodel import Session, select
from fastapi import HTTPException, status

from plexichat.core.logging.logger import get_logger
from plexichat.core.authentication import get_auth_manager, AccountType, BotType, EnhancedUser, BotAccount, Friendship, FriendshipStatus, UserStatus

logger = get_logger(__name__)


class UserManagementService:
    """Service for comprehensive user management operations."""
    def __init__(self):
        self.auth_manager = get_auth_manager()

    async def create_user(
        self,
        username: str,
        email: str,
        password: str,
        display_name: Optional[str] = None,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        bio: Optional[str] = None,
        tags: Optional[List[str]] = None
    ) -> EnhancedUser:
        """Create a new user with comprehensive profile information."""
        user = self.auth_manager.create_user(
            username=username,
            password=password,
            email=email,
            permissions=[] # default no permissions
        )
        return user

    async def create_bot_account(
        self,
        owner_id: int,
        bot_name: str,
        bot_description: str,
        bot_type: BotType = BotType.GENERAL,
        permissions: Optional[Dict[str, Any]] = None,
        rate_limits: Optional[Dict[str, Any]] = None
    ) -> Tuple[EnhancedUser, BotAccount]:
        """Create a new bot account with regulation and advanced features."""
        return self.auth_manager.create_bot_account(
            owner_id=owner_id,
            bot_name=bot_name,
            bot_description=bot_description,
            bot_type=bot_type,
            permissions=permissions,
            rate_limits=rate_limits
        )

    async def update_bot_permissions(
        self,
        bot_id: int,
        owner_id: int,
        permissions: Dict[str, Any]
    ) -> BotAccount:
        """Update bot permissions with owner verification."""
        return self.auth_manager.update_bot_permissions(
            bot_id=bot_id,
            owner_id=owner_id,
            permissions=permissions
        )

    async def get_user_bots(self, owner_id: int) -> List[Dict[str, Any]]:
        """Get all bots owned by a user."""
        return self.auth_manager.get_user_bots(owner_id)

    async def delete_bot_account(self, bot_id: int, owner_id: int) -> bool:
        """Delete a bot account with owner verification."""
        return self.auth_manager.delete_bot_account(bot_id=bot_id, owner_id=owner_id)

    async def update_user_profile(
        self,
        user_id: int,
        updates: Dict[str, Any]
    ) -> EnhancedUser:
        """Update user profile information."""
        return self.auth_manager.update_user_profile(user_id=user_id, updates=updates)

    async def update_user_email(
        self,
        user_id: int,
        new_email: str,
        password: str
    ) -> bool:
        """Update user email with password verification."""
        return self.auth_manager.update_user_email(user_id=user_id, new_email=new_email, password=password)

    async def change_password(
        self,
        user_id: int,
        current_password: str,
        new_password: str
    ) -> bool:
        """Change user password with current password verification."""
        return self.auth_manager.change_password(user_id=user_id, current_password=current_password, new_password=new_password)

    async def upload_profile_picture(
        self,
        user_id: int,
        file_data: bytes,
        filename: str,
        mime_type: str
    ) -> Optional[str]:
        """Upload and set user profile picture."""
        return self.auth_manager.upload_profile_picture(user_id, file_data, filename, mime_type)

    async def delete_user_account(
        self,
        user_id: int,
        password: str,
        hard_delete: bool = False
    ) -> bool:
        """Delete user account (soft delete by default)."""
        return self.auth_manager.delete_user_account(user_id, password, hard_delete)

    async def get_user_profile(
        self,
        user_id: int,
        include_private: bool = False
    ) -> Optional[Dict[str, Any]]:
        """Get user profile information."""
        return self.auth_manager.get_user_profile(user_id, include_private)

    # Friend Management Methods
    async def send_friend_request(
        self,
        requester_id: int,
        addressee_id: int,
        message: Optional[str] = None
    ) -> bool:
        """Send a friend request."""
        return self.auth_manager.send_friend_request(requester_id, addressee_id, message)

    async def respond_to_friend_request(
        self,
        friendship_id: int,
        user_id: int,
        accept: bool
    ) -> bool:
        """Accept or decline a friend request."""
        return self.auth_manager.respond_to_friend_request(friendship_id, user_id, accept)

    async def remove_friend(
        self,
        user_id: int,
        friend_id: int
    ) -> bool:
        """Remove a friend (delete friendship)."""
        return self.auth_manager.remove_friend(user_id, friend_id)

    async def block_user(
        self,
        blocker_id: int,
        blocked_id: int
    ) -> bool:
        """Block a user."""
        return self.auth_manager.block_user(blocker_id, blocked_id)

    async def get_friends_list(
        self,
        user_id: int
    ) -> List[Dict[str, Any]]:
        """Get user's friends list."""
        return self.auth_manager.get_friends_list(user_id)

    async def get_pending_friend_requests(
        self,
        user_id: int,
        sent: bool = False
    ) -> List[Dict[str, Any]]:
        """Get pending friend requests (received or sent)."""
        return self.auth_manager.get_pending_friend_requests(user_id, sent)

    async def search_users(
        self,
        query: str,
        limit: int = 20,
        exclude_user_id: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Search for users by username or display name."""
        return self.auth_manager.search_users(query, limit, exclude_user_id)

    async def get_user_statistics(
        self,
        user_id: int
    ) -> Optional[Dict[str, Any]]:
        """Get user statistics and activity metrics."""
        return self.auth_manager.get_user_statistics(user_id)

    async def update_user_activity(
        self,
        user_id: int
    ) -> bool:
        """Update user's last activity timestamp."""
        return self.auth_manager.update_user_activity(user_id)
