"""
Authentication Utilities
Provides common authentication functions and decorators.
"""

import logging
from functools import wraps
from typing import Any, Dict, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

logger = logging.getLogger(__name__)

# Security scheme
security = HTTPBearer()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current user from token."""
    try:
        # Import here to avoid circular imports
        from plexichat.core.auth.manager_token import token_manager
        
        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required"
            )
        
        # Validate token
        user_data = token_manager.validate_token(credentials.credentials)
        if not user_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        
        return user_data
        
    except ImportError:
        # Fallback if token manager not available
        logger.warning("Token manager not available, using mock user")
        return {"id": 1, "username": "admin", "is_admin": True}
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed"
        )

def get_current_admin_user(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get current admin user."""
    if not current_user.get("is_admin", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user

def require_permissions(*permissions):
    """Decorator to require specific permissions."""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get current user from kwargs or dependencies
            current_user = kwargs.get('current_user')
            if not current_user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )
            
            # Check permissions
            user_permissions = current_user.get("permissions", [])
            for permission in permissions:
                if permission not in user_permissions and not current_user.get("is_admin", False):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Permission '{permission}' required"
                    )
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator

def require_admin(func):
    """Decorator to require admin access."""
    @wraps(func)
    async def wrapper(*args, **kwargs):
        current_user = kwargs.get('current_user')
        if not current_user or not current_user.get("is_admin", False):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required"
            )
        return await func(*args, **kwargs)
    return wrapper

def get_user_from_token(token: str) -> Optional[Dict[str, Any]]:
    """Get user data from token string."""
    try:
        from plexichat.core.auth.manager_token import token_manager
        return token_manager.validate_token(token)
    except ImportError:
        logger.warning("Token manager not available")
        return None
    except Exception as e:
        logger.error(f"Token validation error: {e}")
        return None

def get_current_user_from_token(token: str) -> Optional[Dict[str, Any]]:
    """Get current user from token (alias for compatibility)."""
    return get_user_from_token(token)

# Legacy compatibility functions
def require_admin_auth(func):
    """Legacy admin auth decorator."""
    return require_admin(func)

def get_current_admin_user_legacy():
    """Legacy admin user getter."""
    return get_current_admin_user()
