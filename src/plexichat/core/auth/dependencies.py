import logging
from typing import Any, Dict, HTTPException, List, Optional, status


from .manager_auth import auth_manager


from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

"""
Authentication Dependencies
FastAPI dependency functions for authentication and authorization.
"""

logger = logging.getLogger(__name__)

# Security scheme
security = HTTPBearer()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    """Get current authenticated user."""
    try:
        # Import here to avoid circular imports
        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Validate token
        user_data = await auth_manager.validate_token(credentials.credentials)
        if not user_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return user_data

    except ImportError:
        # Fallback if auth manager not available
        logger.warning("Auth manager not available, using mock user")
        return {
            "id": 1,
            "username": "admin",
            "email": "admin@plexichat.local",
            "is_admin": True,
            "is_active": True,
            "permissions": ["admin", "read", "write"]
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_current_admin_user(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """Get current user with admin privileges."""
    if not current_user.get("is_admin", False):
        raise HTTPException()
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return current_user

async def get_current_active_user(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """Get current active user."""
    if not current_user.get("is_active", True):
        raise HTTPException()
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    return current_user

def require_permission(permission: str):
    """Dependency factory for requiring specific permissions."""
    async def permission_dependency(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
        user_permissions = current_user.get("permissions", [])
        if permission not in user_permissions and not current_user.get("is_admin", False):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permission}' required"
            )
        return current_user
    return permission_dependency

def require_permissions(*permissions):
    """Dependency factory for requiring multiple permissions."""
    async def permissions_dependency(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
        user_permissions = current_user.get("permissions", [])
        is_admin = current_user.get("is_admin", False)

        for permission in permissions:
            if permission not in user_permissions and not is_admin:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission '{permission}' required"
                )
        return current_user
    return permissions_dependency

# Optional authentication (doesn't raise exception if no token)
async def get_current_user_optional(credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False))) -> Optional[Dict[str, Any]]:
    """Get current user if authenticated, None otherwise."""
    if not credentials:
        return None

    try:
        return await get_current_user(credentials)
    except HTTPException:
        return None
    except Exception:
        return None

# Legacy compatibility
get_current_admin_user_legacy = get_current_admin_user
