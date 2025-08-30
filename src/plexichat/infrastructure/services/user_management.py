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
from typing import Any, Dict, List, Optional, Tuple, Set

import bcrypt
try:
    from PIL import Image  # type: ignore
except ImportError:
    Image = None
from sqlmodel import Session, select
from fastapi import HTTPException, status

# Use the centralized logging compatibility shim which re-exports the unified logger.
from plexichat.core.logging import get_logger

# Use only the unified auth manager getter; delegate all operations to it.
from plexichat.core.authentication import get_auth_manager

logger = get_logger(__name__)


class UserManagementService:
    """Service for comprehensive user management operations that delegates to the UnifiedAuthManager."""

    def __init__(self):
        # UnifiedAuthManager instance responsible for all authentication & user operations.
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
    ) -> Dict[str, Any]:
        """Create a new user by delegating to UnifiedAuthManager.register_user.

        The UnifiedAuthManager currently exposes register_user(username, password, permissions).
        We will use this and return a minimal representation. Additional profile data (email,
        display_name, etc.) should be stored by profile management APIs if supported by the
        UnifiedAuthManager; if not supported, this endpoint will still register the user account.
        """
        try:
            # Register the core account using the unified auth manager
            # The register_user method is synchronous in the UnifiedAuthManager implementation.
            success = self.auth_manager.register_user(username=username, password=password, permissions=set())

            if not success:
                logger.warning(f"Failed to register user: {username}")
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User registration failed")

            # If the auth manager exposes profile update, attempt to set profile info
            if hasattr(self.auth_manager, "update_user_profile"):
                try:
                    # Some auth managers expect a user_id (string) same as username
                    awaitable = self.auth_manager.update_user_profile(username, {
                        "email": email,
                        "display_name": display_name,
                        "first_name": first_name,
                        "last_name": last_name,
                        "bio": bio,
                        "tags": tags or []
                    })
                    # update_user_profile may be sync or async
                    if hasattr(awaitable, "__await__"):
                        await awaitable
                except Exception as e:
                    # Non-fatal: registration succeeded but profile update failed
                    logger.debug(f"Profile update after registration failed for {username}: {e}")

            logger.info(f"User registered: {username}")
            return {"success": True, "username": username, "email": email}
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error creating user {username}: {e}")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")

    async def authenticate_user(
        self,
        username: str,
        password: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Any:
        """Authenticate a user using UnifiedAuthManager.authenticate_user.

        Returns the AuthResult object provided by the UnifiedAuthManager.
        """
        try:
            # The UnifiedAuthManager.authenticate_user is async and returns an AuthResult-like object
            auth_result = await self.auth_manager.authenticate_user(username=username, password=password, ip_address=ip_address, user_agent=user_agent)

            # Log security event
            try:
                logger.security(f"Authentication attempt for user {username}", user_id=username)
            except Exception:
                # If unified logger lacks security method for some reason, fallback to info
                logger.info(f"Authentication attempt for user {username}")

            return auth_result
        except Exception as e:
            logger.error(f"Authentication error for user {username}: {e}")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Authentication failed")

    async def create_bot_account(
        self,
        owner_id: Any,
        bot_name: str,
        bot_description: str,
        bot_type: Optional[Any] = None,
        permissions: Optional[Dict[str, Any]] = None,
        rate_limits: Optional[Dict[str, Any]] = None
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Create a new bot account.

        If the UnifiedAuthManager exposes bot management APIs, delegate to them. Otherwise,
        return a Not Implemented response.
        """
        if hasattr(self.auth_manager, "create_bot_account"):
            try:
                result = self.auth_manager.create_bot_account(
                    owner_id=owner_id,
                    bot_name=bot_name,
                    bot_description=bot_description,
                    bot_type=bot_type,
                    permissions=permissions,
                    rate_limits=rate_limits
                )
                # Support async or sync implementations
                if hasattr(result, "__await__"):
                    result = await result
                return result
            except Exception as e:
                logger.error(f"Error creating bot account for owner {owner_id}: {e}")
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create bot account")
        else:
            logger.warning("create_bot_account called but UnifiedAuthManager does not support bot accounts")
            raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Bot accounts are not supported by the UnifiedAuthManager")

    async def update_bot_permissions(
        self,
        bot_id: Any,
        owner_id: Any,
        permissions: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update bot permissions with owner verification by delegating to UnifiedAuthManager."""
        if hasattr(self.auth_manager, "update_bot_permissions"):
            try:
                result = self.auth_manager.update_bot_permissions(bot_id=bot_id, owner_id=owner_id, permissions=permissions)
                if hasattr(result, "__await__"):
                    result = await result
                return result
            except Exception as e:
                logger.error(f"Error updating bot permissions for bot {bot_id}: {e}")
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update bot permissions")
        else:
            raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Bot permission management is not supported")

    async def get_user_bots(self, owner_id: Any) -> List[Dict[str, Any]]:
        """Get all bots owned by a user via UnifiedAuthManager, if supported."""
        if hasattr(self.auth_manager, "get_user_bots"):
            result = self.auth_manager.get_user_bots(owner_id)
            if hasattr(result, "__await__"):
                result = await result
            return result
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Bot listing not supported")

    async def delete_bot_account(self, bot_id: Any, owner_id: Any) -> bool:
        """Delete a bot account with owner verification via UnifiedAuthManager."""
        if hasattr(self.auth_manager, "delete_bot_account"):
            result = self.auth_manager.delete_bot_account(bot_id=bot_id, owner_id=owner_id)
            if hasattr(result, "__await__"):
                result = await result
            return bool(result)
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Bot deletion not supported")

    async def update_user_profile(
        self,
        user_id: Any,
        updates: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update user profile information by delegating to UnifiedAuthManager if supported."""
        if hasattr(self.auth_manager, "update_user_profile"):
            result = self.auth_manager.update_user_profile(user_id=user_id, updates=updates)
            if hasattr(result, "__await__"):
                result = await result
            return result
        else:
            logger.warning("update_user_profile called but UnifiedAuthManager does not provide profile management")
            raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Profile updates not supported")

    async def update_user_email(
        self,
        user_id: Any,
        new_email: str,
        password: str
    ) -> bool:
        """Update user email with password verification via UnifiedAuthManager."""
        if hasattr(self.auth_manager, "update_user_email"):
            result = self.auth_manager.update_user_email(user_id=user_id, new_email=new_email, password=password)
            if hasattr(result, "__await__"):
                result = await result
            return bool(result)
        else:
            raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Email updates not supported")

    async def change_password(
        self,
        user_id: Any,
        current_password: str,
        new_password: str
    ) -> bool:
        """Change user password with current password verification via UnifiedAuthManager."""
        if hasattr(self.auth_manager, "change_password"):
            result = self.auth_manager.change_password(user_id=user_id, current_password=current_password, new_password=new_password)
            if hasattr(result, "__await__"):
                result = await result
            return bool(result)
        else:
            raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Password changes not supported")

    async def upload_profile_picture(
        self,
        user_id: Any,
        file_data: bytes,
        filename: str,
        mime_type: str
    ) -> Optional[str]:
        """Upload and set user profile picture via UnifiedAuthManager if supported."""
        if hasattr(self.auth_manager, "upload_profile_picture"):
            result = self.auth_manager.upload_profile_picture(user_id, file_data, filename, mime_type)
            if hasattr(result, "__await__"):
                result = await result
            return result
        else:
            raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Profile picture uploads not supported")

    async def delete_user_account(
        self,
        user_id: Any,
        password: str,
        hard_delete: bool = False
    ) -> bool:
        """Delete user account (soft delete by default) via UnifiedAuthManager."""
        if hasattr(self.auth_manager, "delete_user_account"):
            result = self.auth_manager.delete_user_account(user_id=user_id, password=password, hard_delete=hard_delete)
            if hasattr(result, "__await__"):
                result = await result
            return bool(result)
        else:
            raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Account deletion not supported")

    async def get_user_profile(
        self,
        user_id: Any,
        include_private: bool = False
    ) -> Optional[Dict[str, Any]]:
        """Get user profile information via UnifiedAuthManager if supported."""
        if hasattr(self.auth_manager, "get_user_profile"):
            result = self.auth_manager.get_user_profile(user_id, include_private)
            if hasattr(result, "__await__"):
                result = await result
            return result
        else:
            raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Profile retrieval not supported")

    # Permission Management
    async def get_user_permissions(self, user_id: Any) -> Set[str]:
        """Get user permissions from UnifiedAuthManager.get_user_permissions()."""
        try:
            perms = self.auth_manager.get_user_permissions(user_id)
            # Support async getters
            if hasattr(perms, "__await__"):
                perms = await perms
            # Ensure a set is returned
            if perms is None:
                return set()
            if isinstance(perms, (list, tuple, set)):
                return set(perms)
            # If permissions are stored in a dict or other structure, attempt to extract keys
            if isinstance(perms, dict):
                return set(perms.keys())
            return set()
        except Exception as e:
            logger.error(f"Error getting permissions for user {user_id}: {e}")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Could not retrieve permissions")

    async def update_user_permissions(self, user_id: Any, permissions: Set[str]) -> bool:
        """Update user permissions via UnifiedAuthManager.update_user_permissions()."""
        try:
            result = self.auth_manager.update_user_permissions(user_id, permissions)
            if hasattr(result, "__await__"):
                result = await result
            return bool(result)
        except Exception as e:
            logger.error(f"Error updating permissions for user {user_id}: {e}")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Could not update permissions")

    # Friend Management Methods - delegate if supported, otherwise mark as not implemented
    async def send_friend_request(
        self,
        requester_id: Any,
        addressee_id: Any,
        message: Optional[str] = None
    ) -> bool:
        """Send a friend request via UnifiedAuthManager if supported."""
        if hasattr(self.auth_manager, "send_friend_request"):
            result = self.auth_manager.send_friend_request(requester_id, addressee_id, message)
            if hasattr(result, "__await__"):
                result = await result
            return bool(result)
        else:
            raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Friend requests not supported")

    async def respond_to_friend_request(
        self,
        friendship_id: Any,
        user_id: Any,
        accept: bool
    ) -> bool:
        """Accept or decline a friend request via UnifiedAuthManager if supported."""
        if hasattr(self.auth_manager, "respond_to_friend_request"):
            result = self.auth_manager.respond_to_friend_request(friendship_id, user_id, accept)
            if hasattr(result, "__await__"):
                result = await result
            return bool(result)
        else:
            raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Friend responses not supported")

    async def remove_friend(
        self,
        user_id: Any,
        friend_id: Any
    ) -> bool:
        """Remove a friend (delete friendship) via UnifiedAuthManager if supported."""
        if hasattr(self.auth_manager, "remove_friend"):
            result = self.auth_manager.remove_friend(user_id, friend_id)
            if hasattr(result, "__await__"):
                result = await result
            return bool(result)
        else:
            raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Removing friends not supported")

    async def block_user(
        self,
        blocker_id: Any,
        blocked_id: Any
    ) -> bool:
        """Block a user via UnifiedAuthManager if supported."""
        if hasattr(self.auth_manager, "block_user"):
            result = self.auth_manager.block_user(blocker_id, blocked_id)
            if hasattr(result, "__await__"):
                result = await result
            return bool(result)
        else:
            raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Blocking users not supported")

    async def get_friends_list(
        self,
        user_id: Any
    ) -> List[Dict[str, Any]]:
        """Get user's friends list via UnifiedAuthManager if supported."""
        if hasattr(self.auth_manager, "get_friends_list"):
            result = self.auth_manager.get_friends_list(user_id)
            if hasattr(result, "__await__"):
                result = await result
            return result or []
        else:
            raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Friends list not supported")

    async def get_pending_friend_requests(
        self,
        user_id: Any,
        sent: bool = False
    ) -> List[Dict[str, Any]]:
        """Get pending friend requests via UnifiedAuthManager if supported."""
        if hasattr(self.auth_manager, "get_pending_friend_requests"):
            result = self.auth_manager.get_pending_friend_requests(user_id, sent)
            if hasattr(result, "__await__"):
                result = await result
            return result or []
        else:
            raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Pending friend requests not supported")

    async def search_users(
        self,
        query: str,
        limit: int = 20,
        exclude_user_id: Optional[Any] = None
    ) -> List[Dict[str, Any]]:
        """Search for users by username or display name via UnifiedAuthManager if supported."""
        if hasattr(self.auth_manager, "search_users"):
            result = self.auth_manager.search_users(query, limit, exclude_user_id)
            if hasattr(result, "__await__"):
                result = await result
            return result or []
        else:
            raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="User search not supported")

    async def get_user_statistics(
        self,
        user_id: Any
    ) -> Optional[Dict[str, Any]]:
        """Get user statistics and activity metrics via UnifiedAuthManager if supported."""
        if hasattr(self.auth_manager, "get_user_statistics"):
            result = self.auth_manager.get_user_statistics(user_id)
            if hasattr(result, "__await__"):
                result = await result
            return result
        else:
            raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="User statistics not supported")

    async def update_user_activity(
        self,
        user_id: Any
    ) -> bool:
        """Update user's last activity timestamp via UnifiedAuthManager if supported."""
        if hasattr(self.auth_manager, "update_user_activity"):
            result = self.auth_manager.update_user_activity(user_id)
            if hasattr(result, "__await__"):
                result = await result
            return bool(result)
        else:
            # We can still accept this as a noop with a logged warning to maintain compatibility
            logger.debug(f"update_user_activity called for {user_id} but UnifiedAuthManager does not support it")
            return False
