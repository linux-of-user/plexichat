"""
PlexiChat API v1 - Admin Endpoints

Simple admin functionality with:
- System statistics
- User management
- Message moderation
- File management
- System health
"""

from datetime import datetime
import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from plexichat.core.authentication import get_auth_manager
from plexichat.interfaces.api.v1.auth import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/admin", tags=["Admin"])

# Admin user IDs (in production, use proper role system)
ADMIN_USERS = set()


# Models
class SystemStats(BaseModel):
    total_users: int
    active_sessions: int
    total_messages: int
    total_files: int
    system_uptime: str
    timestamp: datetime


class UserAdmin(BaseModel):
    id: str
    username: str
    email: str
    display_name: str
    created_at: datetime
    is_active: bool
    last_login: datetime | None = None


# Utility functions
async def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    """Require admin privileges."""
    if current_user["id"] not in ADMIN_USERS and current_user["username"] != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return current_user


def make_user_admin(user_id: str):
    """Make a user an admin."""
    ADMIN_USERS.add(user_id)


# Endpoints
@router.get("/stats", response_model=SystemStats)
async def get_system_stats(admin_user: dict = Depends(require_admin)):
    """Get system statistics."""
    try:
        auth_manager = get_auth_manager()

        # Get basic stats from auth manager
        total_users = getattr(auth_manager, "get_user_count", lambda: 0)()
        active_sessions = getattr(auth_manager, "get_active_session_count", lambda: 0)()

        return SystemStats(
            total_users=total_users or 0,
            active_sessions=active_sessions or 0,
            total_messages=0,  # Not available in current system
            total_files=0,  # Not available in current system
            system_uptime="N/A",  # Would calculate actual uptime in production
            timestamp=datetime.now(),
        )

    except Exception as e:
        logger.error(f"Get system stats error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get system stats")


@router.get("/users")
async def list_all_users(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    search: str | None = None,
    admin_user: dict = Depends(require_admin),
):
    """List all users with admin details."""
    try:
        auth_manager = get_auth_manager()

        # Get users from auth manager if available
        users_list = []
        try:
            all_users = getattr(auth_manager, "get_all_users", lambda: [])()
            if all_users:
                # Apply search filter
                if search:
                    search_lower = search.lower()
                    all_users = [
                        user
                        for user in all_users
                        if (
                            search_lower in user.get("username", "").lower()
                            or search_lower in user.get("email", "").lower()
                            or search_lower in user.get("display_name", "").lower()
                        )
                    ]

                # Sort by creation date (newest first)
                all_users.sort(
                    key=lambda x: x.get("created_at", datetime.now()), reverse=True
                )

                # Apply pagination
                total = len(all_users)
                paginated_users = all_users[offset : offset + limit]

                # Format response
                for user in paginated_users:
                    users_list.append(
                        UserAdmin(
                            id=user.get("id", ""),
                            username=user.get("username", ""),
                            email=user.get("email", ""),
                            display_name=user.get("display_name", ""),
                            created_at=user.get("created_at", datetime.now()),
                            is_active=user.get("is_active", True),
                            last_login=user.get("last_login"),
                        )
                    )
            else:
                # Return empty list if no users available
                total = 0
        except Exception:
            # Return empty list if method not available
            total = 0

        return {
            "users": users_list,
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": offset + limit < total,
        }

    except Exception as e:
        logger.error(f"List all users error: {e}")
        raise HTTPException(status_code=500, detail="Failed to list users")


@router.post("/users/{user_id}/deactivate")
async def deactivate_user(user_id: str, admin_user: dict = Depends(require_admin)):
    """Deactivate a user account."""
    try:
        auth_manager = get_auth_manager()

        if user_id == admin_user.get("id"):
            raise HTTPException(
                status_code=400, detail="Cannot deactivate your own account"
            )

        # Try to deactivate user using auth manager
        success = getattr(auth_manager, "deactivate_user", lambda uid: False)(user_id)

        if success:
            logger.info(
                f"User deactivated: {user_id} by admin {admin_user.get('username', 'unknown')}"
            )
            return {
                "success": True,
                "message": f"User {user_id} deactivated successfully",
            }
        else:
            raise HTTPException(
                status_code=404, detail="User not found or deactivation failed"
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Deactivate user error: {e}")
        raise HTTPException(status_code=500, detail="Failed to deactivate user")


@router.post("/users/{user_id}/activate")
async def activate_user(user_id: str, admin_user: dict = Depends(require_admin)):
    """Activate a user account."""
    try:
        auth_manager = get_auth_manager()

        # Try to activate user using auth manager
        success = getattr(auth_manager, "activate_user", lambda uid: False)(user_id)

        if success:
            logger.info(
                f"User activated: {user_id} by admin {admin_user.get('username', 'unknown')}"
            )
            return {
                "success": True,
                "message": f"User {user_id} activated successfully",
            }
        else:
            raise HTTPException(
                status_code=404, detail="User not found or activation failed"
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Activate user error: {e}")
        raise HTTPException(status_code=500, detail="Failed to activate user")


@router.delete("/users/{user_id}")
async def delete_user_admin(user_id: str, admin_user: dict = Depends(require_admin)):
    """Delete a user account (admin only)."""
    try:
        auth_manager = get_auth_manager()

        if user_id == admin_user.get("id"):
            raise HTTPException(
                status_code=400, detail="Cannot delete your own account"
            )

        # Try to delete user using auth manager
        success = getattr(auth_manager, "delete_user", lambda uid: False)(user_id)

        if success:
            logger.info(
                f"User deleted by admin: {user_id} by {admin_user.get('username', 'unknown')}"
            )
            return {"success": True, "message": f"User {user_id} deleted successfully"}
        else:
            raise HTTPException(
                status_code=404, detail="User not found or deletion failed"
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Delete user admin error: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete user")


@router.get("/messages/recent")
async def get_recent_messages(
    limit: int = Query(50, ge=1, le=200), admin_user: dict = Depends(require_admin)
):
    """Get recent messages for moderation."""
    try:
        # Return empty list as messaging system integration is not available
        return {
            "messages": [],
            "count": 0,
            "total_active_messages": 0,
            "note": "Message moderation not available in current system configuration",
        }

    except Exception as e:
        logger.error(f"Get recent messages error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get recent messages")


@router.delete("/messages/{message_id}")
async def delete_message_admin(
    message_id: str,
    reason: str = Query(..., min_length=1),
    admin_user: dict = Depends(require_admin),
):
    """Delete a message (admin moderation)."""
    try:
        # Return not implemented as messaging system integration is not available
        raise HTTPException(
            status_code=501,
            detail="Message moderation not implemented in current system",
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Delete message admin error: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete message")


@router.post("/make-admin/{user_id}")
async def make_admin(user_id: str, admin_user: dict = Depends(require_admin)):
    """Make a user an admin."""
    try:
        auth_manager = get_auth_manager()

        # Try to make user admin using auth manager
        success = getattr(auth_manager, "make_admin", lambda uid: False)(user_id)

        if success:
            logger.info(
                f"User made admin: {user_id} by {admin_user.get('username', 'unknown')}"
            )
            return {"success": True, "message": f"User {user_id} is now an admin"}
        else:
            raise HTTPException(
                status_code=404, detail="User not found or operation failed"
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Make admin error: {e}")
        raise HTTPException(status_code=500, detail="Failed to make user admin")


@router.get("/health")
async def admin_health_check(admin_user: dict = Depends(require_admin)):
    """Admin health check with detailed system info."""
    try:
        auth_manager = get_auth_manager()

        # Get basic stats from auth manager if available
        total_users = getattr(auth_manager, "get_user_count", lambda: 0)()
        active_sessions = getattr(auth_manager, "get_active_session_count", lambda: 0)()

        return {
            "status": "healthy",
            "timestamp": datetime.now(),
            "system": {
                "users": total_users or 0,
                "active_sessions": active_sessions or 0,
                "messages": 0,  # Not available in current system
                "files": 0,  # Not available in current system
                "admins": 0,  # Not tracked in current system
            },
            "admin_user": admin_user.get("username", "unknown"),
        }

    except Exception as e:
        logger.error(f"Admin health check error: {e}")
        raise HTTPException(status_code=500, detail="Health check failed")
