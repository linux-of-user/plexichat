"""
FastAPI Authentication Adapter for PlexiChat
Provides FastAPI dependencies that integrate with UnifiedAuthManager.
This is the single point where FastAPI integrates with the unified authentication system.
"""

import inspect
import logging
from datetime import timedelta
from functools import wraps
from typing import Any, Callable, Dict, Optional, Set, Union

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from plexichat.core.authentication import get_auth_manager
from plexichat.core.security import RateLimitRequest, get_network_protection

logger = logging.getLogger(__name__)

# Security scheme for FastAPI
security = HTTPBearer()


class FastAPIAuthAdapter:
    """
    FastAPI authentication adapter that provides dependencies for FastAPI routers.
    All authentication operations delegate to UnifiedAuthManager.
    """

    def __init__(self) -> None:
        self.auth_manager = get_auth_manager()

    async def get_current_user(
        self, credentials: HTTPAuthorizationCredentials = Depends(security)
    ) -> Dict[str, Any]:
        """
        Get current authenticated user from JWT token.

        Args:
            credentials: HTTP Bearer token credentials

        Returns:
            Dict containing user information and permissions

        Raises:
            HTTPException: If token is invalid or user not found
        """
        try:
            token = credentials.credentials

            # Validate token using UnifiedAuthManager
            valid, payload = await self.auth_manager.validate_token(token)

            if not valid or not payload:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authentication credentials",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            # Extract user information from token payload
            user_id = payload.get("user_id") or payload.get("sub")
            if not user_id:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token payload",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            # Get user permissions from UnifiedAuthManager
            permissions = self.auth_manager.get_user_permissions(user_id)

            # Build user context
            user_context: Dict[str, Any] = {
                "id": user_id,
                "user_id": user_id,
                "permissions": permissions,
                "is_active": True,
                "is_admin": "admin" in permissions,
                "token_type": payload.get("token_type", "access"),
                "jti": payload.get("jti"),
                "exp": payload.get("exp"),
                "iat": payload.get("iat"),
            }

            return user_context

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error validating user token: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication error",
                headers={"WWW-Authenticate": "Bearer"},
            )

    async def get_optional_user(
        self,
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(
            HTTPBearer(auto_error=False)
        ),
    ) -> Optional[Dict[str, Any]]:
        """
        Get current user if token is provided, otherwise return None.
        Useful for endpoints that can work with or without authentication.

        Args:
            credentials: Optional HTTP Bearer token credentials

        Returns:
            User dict if authenticated, None otherwise
        """
        if not credentials:
            return None

        try:
            # Create a mock credentials object for get_current_user
            mock_credentials = HTTPAuthorizationCredentials(
                scheme="Bearer", credentials=credentials.credentials
            )
            return await self.get_current_user(mock_credentials)
        except HTTPException:
            # Return None for invalid tokens instead of raising
            return None
        except Exception as e:
            logger.debug(f"Optional authentication failed: {e}")
            return None

    async def require_admin(
        self,
        current_user: Dict[str, Any] = Depends(get_current_user),
    ) -> Dict[str, Any]:
        """
        Require admin privileges for the current user.

        Args:
            current_user: Current authenticated user

        Returns:
            User dict if user has admin privileges

        Raises:
            HTTPException: If user lacks admin privileges
        """
        if not current_user.get("is_admin", False):
            logger.warning(
                f"Unauthorized admin access attempt by user {current_user.get('id')}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin privileges required",
            )

        return current_user

    def require_user_or_admin(
        self, target_user_id: Union[str, int]
    ) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
        """
        Create a dependency that requires user to be the target user or an admin.

        Args:
            target_user_id: The user ID that should have access

        Returns:
            FastAPI dependency function
        """

        async def _require_user_or_admin(
            current_user: Dict[str, Any] = Depends(get_current_user),
        ) -> Dict[str, Any]:
            current_user_id = current_user.get("id") or current_user.get("user_id")

            # Convert to string for comparison
            if str(current_user_id) != str(target_user_id) and not current_user.get(
                "is_admin", False
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied: insufficient privileges",
                )

            return current_user

        return _require_user_or_admin

    async def get_user_permissions(
        self,
        current_user: Dict[str, Any] = Depends(get_current_user),
    ) -> Set[str]:
        """
        Get permissions for the current user.

        Args:
            current_user: Current authenticated user

        Returns:
            Set of permission strings
        """
        return current_user.get("permissions", set())

    async def validate_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """
        Validate API key using UnifiedAuthManager.

        Args:
            api_key: API key to validate

        Returns:
            User dict if API key is valid, None otherwise
        """
        try:
            user_data = await self.auth_manager.validate_api_key(api_key)

            if user_data:
                # Ensure consistent format
                return {
                    "id": user_data.get("user_id"),
                    "user_id": user_data.get("user_id"),
                    "permissions": user_data.get("permissions", set()),
                    "is_active": user_data.get("is_active", True),
                    "is_admin": "admin" in user_data.get("permissions", set()),
                    "auth_method": "api_key",
                }

            return None

        except Exception as e:
            logger.error(f"Error validating API key: {e}")
            return None

    def rate_limit(
        self, action: str, limit: int, window_seconds: int = 60
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """
        Rate limiting decorator that integrates with NetworkProtection.

        Args:
            action: Action identifier for rate limiting
            limit: Maximum number of requests allowed
            window_seconds: Time window in seconds (default: 60)

        Returns:
            Decorator function
        """

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            @wraps(func)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                # Extract Request object from function arguments
                request: Optional[Request] = None
                for arg in args:
                    if isinstance(arg, Request):
                        request = arg
                        break
                if not request:
                    for kwarg_val in kwargs.values():
                        if isinstance(kwarg_val, Request):
                            request = kwarg_val
                            break

                if not request:
                    logger.warning(
                        "Rate limiting decorator could not find Request object. Skipping rate limit check."
                    )
                    if inspect.iscoroutinefunction(func):
                        return await func(*args, **kwargs)
                    else:
                        return func(*args, **kwargs)

                network_protection = get_network_protection()
                if not network_protection:
                    logger.warning(
                        "Network protection not available for rate limiting. Skipping rate limit check."
                    )
                    if inspect.iscoroutinefunction(func):
                        return await func(*args, **kwargs)
                    else:
                        return func(*args, **kwargs)

                rate_request = RateLimitRequest()
                rate_request.ip_address = (
                    request.client.host if request.client else "unknown"
                )
                rate_request.endpoint = request.url.path
                rate_request.method = request.method
                rate_request.user_agent = request.headers.get("user-agent", "unknown")
                rate_request.size_bytes = int(request.headers.get("content-length", 0))
                rate_request.action = action
                rate_request.limit = limit
                rate_request.window_seconds = window_seconds

                allowed, _ = await network_protection.check_request(rate_request)

                if not allowed:
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail=f"Rate limit exceeded for action: {action}",
                        headers={"Retry-After": str(window_seconds)},
                    )

                # Call the original function
                if inspect.iscoroutinefunction(func):
                    return await func(*args, **kwargs)
                else:
                    return func(*args, **kwargs)

            return wrapper

        return decorator

    async def create_access_token(
        self,
        user_id: str,
        permissions: Set[str],
        expires_delta: Optional[timedelta] = None,
    ) -> str:
        """
        Create access token using UnifiedAuthManager.

        Args:
            user_id: User identifier
            permissions: User permissions
            expires_delta: Token expiration time

        Returns:
            JWT access token
        """
        try:
            return self.auth_manager.create_access_token(
                user_id, permissions, expires_delta
            )
        except Exception as e:
            logger.error(f"Error creating access token: {e}")
            return ""

    async def create_refresh_token(self, user_id: str) -> str:
        """
        Create refresh token using UnifiedAuthManager.

        Args:
            user_id: User identifier

        Returns:
            JWT refresh token
        """
        try:
            return self.auth_manager.create_refresh_token(user_id)
        except Exception as e:
            logger.error(f"Error creating refresh token: {e}")
            return ""

    async def revoke_token(self, token: str) -> bool:
        """
        Revoke token using UnifiedAuthManager.

        Args:
            token: Token to revoke

        Returns:
            True if token was revoked successfully
        """
        try:
            return await self.auth_manager.revoke_token(token)
        except Exception as e:
            logger.error(f"Error revoking token: {e}")
            return False

    async def invalidate_user_sessions(self, user_id: str) -> int:
        """
        Invalidate all sessions for a user.

        Args:
            user_id: User identifier

        Returns:
            Number of sessions invalidated
        """
        try:
            return await self.auth_manager.invalidate_user_sessions(user_id)
        except Exception as e:
            logger.error(f"Error invalidating user sessions: {e}")
            return 0


# Global adapter instance
_auth_adapter: Optional[FastAPIAuthAdapter] = None


def get_auth_adapter() -> FastAPIAuthAdapter:
    """Get the global FastAPI auth adapter instance."""
    global _auth_adapter
    if _auth_adapter is None:
        _auth_adapter = FastAPIAuthAdapter()
    return _auth_adapter


# Convenience dependency functions that use the global adapter
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> Dict[str, Any]:
    """FastAPI dependency to get current authenticated user."""
    adapter = get_auth_adapter()
    return await adapter.get_current_user(credentials)


async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(
        HTTPBearer(auto_error=False)
    ),
) -> Optional[Dict[str, Any]]:
    """FastAPI dependency to get optional authenticated user."""
    adapter = get_auth_adapter()
    return await adapter.get_optional_user(credentials)


async def require_admin(
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """FastAPI dependency that requires admin privileges."""
    adapter = get_auth_adapter()
    return await adapter.require_admin(current_user)


def require_user_or_admin(
    target_user_id: Union[str, int]
) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
    """Create FastAPI dependency that requires user to be target user or admin."""
    adapter = get_auth_adapter()
    return adapter.require_user_or_admin(target_user_id)


async def get_user_permissions(
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Set[str]:
    """FastAPI dependency to get current user permissions."""
    adapter = get_auth_adapter()
    return await adapter.get_user_permissions(current_user)


def rate_limit(
    action: str, limit: int, window_seconds: int = 60
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Rate limiting decorator for FastAPI endpoints."""
    adapter = get_auth_adapter()
    return adapter.rate_limit(action, limit, window_seconds)


# Additional utility functions
async def get_current_user_with_permissions(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> Dict[str, Any]:
    """
    Get current user with permissions included in the response.
    Useful for endpoints that need both user info and permissions.
    """
    user = await get_current_user(credentials)
    # Permissions are already included in the user dict from get_current_user
    return user


async def validate_api_key_dependency(api_key: str) -> Dict[str, Any]:
    """
    FastAPI dependency for API key validation.

    Args:
        api_key: API key to validate

    Returns:
        User dict if valid

    Raises:
        HTTPException: If API key is invalid
    """
    adapter = get_auth_adapter()
    user_data = await adapter.validate_api_key(api_key)

    if not user_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key"
        )

    return user_data


__all__ = [
    "FastAPIAuthAdapter",
    "get_auth_adapter",
    "get_current_user",
    "get_optional_user",
    "require_admin",
    "require_user_or_admin",
    "get_user_permissions",
    "get_current_user_with_permissions",
    "validate_api_key_dependency",
    "rate_limit",
]