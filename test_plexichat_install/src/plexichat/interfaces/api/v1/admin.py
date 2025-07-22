"""
PlexiChat Admin API Endpoints

Administrative API endpoints for system management and user administration.
"""

from fastapi import APIRouter, HTTPException, Depends, status, Query
from pydantic import BaseModel, EmailStr
from typing import Optional, Dict, Any, List
import asyncio

try:
    from plexichat.core.auth.admin_manager import admin_manager
    from plexichat.core.auth.auth_manager import auth_manager
    from plexichat.interfaces.api.v1.auth import get_current_user
    from plexichat.app.logger_config import get_logger
    from plexichat.core.config import settings
except ImportError:
    admin_manager = None
    auth_manager = None
    get_current_user = lambda: {}
    get_logger = lambda name: print
    settings = {}

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1/admin", tags=["admin"])

# Request/Response Models
class CreateUserRequest(BaseModel):
    username: str
    email: EmailStr
    password: str
    roles: List[str] = []
    is_admin: bool = False

class UpdateUserRequest(BaseModel):
    email: Optional[EmailStr] = None
    roles: Optional[List[str]] = None
    is_active: Optional[bool] = None
    is_admin: Optional[bool] = None

class UserResponse(BaseModel):
    user_id: str
    username: str
    email: str
    roles: List[str]
    is_active: bool
    is_admin: bool
    created_at: str
    last_login: Optional[str] = None

class SystemStatsResponse(BaseModel):
    total_users: int
    active_users: int
    admin_users: int
    total_messages: int
    system_uptime: str
    memory_usage: Dict[str, Any]
    disk_usage: Dict[str, Any]

class ConfigUpdateRequest(BaseModel):
    key: str
    value: Any

# Admin permission check
async def require_admin(current_user: Dict = Depends(get_current_user)):
    """Require admin permissions."""
    if not current_user.get("is_admin", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return current_user

@router.get("/users", response_model=List[UserResponse])
async def list_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    search: Optional[str] = None,
    admin_user: Dict = Depends(require_admin)
):
    """List all users with pagination and search."""
    try:
        if not auth_manager:
            raise HTTPException(status_code=503, detail="User service unavailable")

        users = await auth_manager.list_users(
            skip=skip,
            limit=limit,
            search=search
        )

        return [
            UserResponse(
                user_id=user["user_id"],
                username=user["username"],
                email=user["email"],
                roles=user.get("roles", []),
                is_active=user.get("is_active", True),
                is_admin=user.get("is_admin", False),
                created_at=user.get("created_at", ""),
                last_login=user.get("last_login")
            )
            for user in users
        ]

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"List users error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/users", response_model=UserResponse)
async def create_user(
    request: CreateUserRequest,
    admin_user: Dict = Depends(require_admin)
):
    """Create a new user account."""
    try:
        if not auth_manager:
            raise HTTPException(status_code=503, detail="User service unavailable")

        result = await auth_manager.create_user(
            username=request.username,
            email=request.email,
            password=request.password,
            roles=request.roles,
            is_admin=request.is_admin
        )

        if not result.success:
            raise HTTPException(status_code=400, detail=result.message)

        return UserResponse(
            user_id=result.user_id,
            username=request.username,
            email=request.email,
            roles=request.roles,
            is_active=True,
            is_admin=request.is_admin,
            created_at=result.created_at or ""
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Create user error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/users/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    admin_user: Dict = Depends(require_admin)
):
    """Get user by ID."""
    try:
        if not auth_manager:
            raise HTTPException(status_code=503, detail="User service unavailable")

        user = await auth_manager.get_user_by_id(user_id)

        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        return UserResponse(
            user_id=user["user_id"],
            username=user["username"],
            email=user["email"],
            roles=user.get("roles", []),
            is_active=user.get("is_active", True),
            is_admin=user.get("is_admin", False),
            created_at=user.get("created_at", ""),
            last_login=user.get("last_login")
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get user error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.put("/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    request: UpdateUserRequest,
    admin_user: Dict = Depends(require_admin)
):
    """Update user information."""
    try:
        if not auth_manager:
            raise HTTPException(status_code=503, detail="User service unavailable")

        # Get current user data
        user = await auth_manager.get_user_by_id(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Update user
        update_data = request.dict(exclude_unset=True)
        result = await auth_manager.update_user(user_id, update_data)

        if not result.success:
            raise HTTPException(status_code=400, detail=result.message)

        # Get updated user data
        updated_user = await auth_manager.get_user_by_id(user_id)

        return UserResponse(
            user_id=updated_user["user_id"],
            username=updated_user["username"],
            email=updated_user["email"],
            roles=updated_user.get("roles", []),
            is_active=updated_user.get("is_active", True),
            is_admin=updated_user.get("is_admin", False),
            created_at=updated_user.get("created_at", ""),
            last_login=updated_user.get("last_login")
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Update user error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.delete("/users/{user_id}")
async def delete_user(
    user_id: str,
    admin_user: Dict = Depends(require_admin)
):
    """Delete user account."""
    try:
        if not auth_manager:
            raise HTTPException(status_code=503, detail="User service unavailable")

        # Prevent self-deletion
        if user_id == admin_user.get("user_id"):
            raise HTTPException(status_code=400, detail="Cannot delete your own account")

        result = await auth_manager.delete_user(user_id)

        if not result.success:
            raise HTTPException(status_code=400, detail=result.message)

        return {"message": "User deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Delete user error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/users/{user_id}/reset-password")
async def admin_reset_password(
    user_id: str,
    admin_user: Dict = Depends(require_admin)
):
    """Reset user password (admin only)."""
    try:
        if not auth_manager:
            raise HTTPException(status_code=503, detail="User service unavailable")

        result = await auth_manager.admin_reset_password(user_id)

        if not result.success:
            raise HTTPException(status_code=400, detail=result.message)

        return {
            "message": "Password reset successfully",
            "temporary_password": result.temporary_password
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Admin password reset error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/stats", response_model=SystemStatsResponse)
async def get_system_stats(admin_user: Dict = Depends(require_admin)):
    """Get system statistics."""
    try:
        stats = {}

        if auth_manager:
            user_stats = await auth_manager.get_user_statistics()
            stats.update(user_stats)

        # Add system stats
        import psutil
        import time

        stats.update({
            "system_uptime": str(time.time()),
            "memory_usage": {
                "total": psutil.virtual_memory().total,
                "available": psutil.virtual_memory().available,
                "percent": psutil.virtual_memory().percent
            },
            "disk_usage": {
                "total": psutil.disk_usage('/').total,
                "free": psutil.disk_usage('/').free,
                "percent": psutil.disk_usage('/').percent
            }
        })

        return SystemStatsResponse(**stats)

    except Exception as e:
        logger.error(f"Get system stats error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/config")
async def get_config(admin_user: Dict = Depends(require_admin)):
    """Get system configuration."""
    try:
        # Return sanitized config (remove sensitive data)
        config = dict(settings)

        # Remove sensitive keys
        sensitive_keys = ["database_url", "secret_key", "api_keys", "passwords"]
        for key in sensitive_keys:
            config.pop(key, None)

        return config

    except Exception as e:
        logger.error(f"Get config error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.put("/config")
async def update_config(
    request: ConfigUpdateRequest,
    admin_user: Dict = Depends(require_admin)
):
    """Update system configuration."""
    try:
        # Validate that key is allowed to be updated
        allowed_keys = ["max_file_size", "session_timeout", "rate_limits"]

        if request.key not in allowed_keys:
            raise HTTPException(
                status_code=400,
                detail=f"Configuration key '{request.key}' cannot be updated via API"
            )

        # Update configuration
        settings[request.key] = request.value

        return {"message": f"Configuration '{request.key}' updated successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Update config error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/maintenance/start")
async def start_maintenance(admin_user: Dict = Depends(require_admin)):
    """Start maintenance mode."""
    try:
        # This would integrate with the actual maintenance system
        return {"message": "Maintenance mode started"}

    except Exception as e:
        logger.error(f"Start maintenance error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/maintenance/stop")
async def stop_maintenance(admin_user: Dict = Depends(require_admin)):
    """Stop maintenance mode."""
    try:
        # This would integrate with the actual maintenance system
        return {"message": "Maintenance mode stopped"}

    except Exception as e:
        logger.error(f"Stop maintenance error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/logs")
async def get_logs(
    lines: int = Query(100, ge=1, le=10000),
    level: Optional[str] = Query(None),
    admin_user: Dict = Depends(require_admin)
):
    """Get system logs."""
    try:
        # This would integrate with the actual logging system
        logs = [
            {"timestamp": "2024-01-01T00:00:00Z", "level": "INFO", "message": "System started"},
            {"timestamp": "2024-01-01T00:01:00Z", "level": "DEBUG", "message": "Debug message"},
        ]

        return {"logs": logs[-lines:]}

    except Exception as e:
        logger.error(f"Get logs error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/status")
async def admin_status():
    """Get admin service status."""
    return {
        "service": "admin",
        "status": "online",
        "admin_manager": admin_manager is not None,
        "auth_manager": auth_manager is not None
    }
