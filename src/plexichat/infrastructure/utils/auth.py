# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
import time
PlexiChat Authentication Utilities

Enhanced authentication utilities with comprehensive security and performance optimization.
Uses EXISTING database abstraction and optimization systems.
"""

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

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

# Core auth imports
try:
    from plexichat.core.auth.auth_core import auth_core
except ImportError:
    auth_core = None

logger = logging.getLogger(__name__)

# Initialize EXISTING performance systems
performance_logger = get_performance_logger() if get_performance_logger else None

# Security scheme
security = HTTPBearer()

class AuthenticationUtilities:
    """Enhanced authentication utilities using EXISTING systems."""

    def __init__(self):
        self.db_manager = database_manager
        self.performance_logger = performance_logger
        self.auth_core = auth_core

    @async_track_performance("token_validation") if async_track_performance else lambda f: f
    async def get_current_user(self, credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
        """Get current user from token using EXISTING authentication core."""
        try:
            token = credentials.credentials

            if self.auth_core:
                if self.performance_logger and timer:
                    with timer("token_verification"):
                        user = await self.auth_core.get_current_user(token)
                else:
                    user = await self.auth_core.get_current_user(token)

                if user:
                    # Performance tracking
                    if self.performance_logger:
                        self.performance_logger.record_metric("successful_token_validations", 1, "count")

                    return user

            # Performance tracking for failed validations
            if self.performance_logger:
                self.performance_logger.record_metric("failed_token_validations", 1, "count")

            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication credentials", headers={"WWW-Authenticate": "Bearer"})

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error validating token: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication error", headers={"WWW-Authenticate": "Bearer"})

    async def get_current_active_user(self, current_user: Dict[str, Any] = Depends(lambda: auth_utils.get_current_user)) -> Dict[str, Any]:
        """Get current active user."""
        if not current_user.get("is_active", False):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")
        return current_user

    async def require_admin(self, current_user: Dict[str, Any] = Depends(lambda: auth_utils.get_current_user)) -> Dict[str, Any]:
        """Require admin privileges."""
        if not current_user.get("is_admin", False):
            # Log unauthorized admin access attempt
            logger.warning(f"Unauthorized admin access attempt by user {current_user.get('id')}")

            # Performance tracking
            if self.performance_logger:
                self.performance_logger.record_metric("unauthorized_admin_attempts", 1, "count")

            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")

        # Performance tracking
        if self.performance_logger:
            self.performance_logger.record_metric("admin_access_granted", 1, "count")

        return current_user

    async def require_user_or_admin(self, user_id: int, current_user: Dict[str, Any] = Depends(lambda: auth_utils.get_current_user)) -> Dict[str, Any]:
        """Require user to be the owner or admin."""
        if current_user.get("id") != user_id and not current_user.get("is_admin", False):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
        return current_user

    @async_track_performance("api_key_validation") if async_track_performance else lambda f: f
    async def validate_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Validate API key using EXISTING authentication core."""
        try:
            if self.auth_core:
                if self.performance_logger and timer:
                    with timer("api_key_validation"):
                        user = await self.auth_core.validate_api_key(api_key)
                else:
                    user = await self.auth_core.validate_api_key(api_key)

                if user:
                    # Performance tracking
                    if self.performance_logger:
                        self.performance_logger.record_metric("successful_api_key_validations", 1, "count")

                    return user

            # Performance tracking for failed validations
            if self.performance_logger:
                self.performance_logger.record_metric("failed_api_key_validations", 1, "count")

            return None

        except Exception as e:
            logger.error(f"Error validating API key: {e}")
            return None

    def create_access_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Create access token using EXISTING authentication core."""
        if self.auth_core:
            return self.auth_core.create_access_token(data, expires_delta)

        # Fallback token creation
        import jwt
        import secrets

        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=30)

        to_encode.update({"exp": expire})
        secret_key = secrets.token_hex(32)
        encoded_jwt = jwt.encode(to_encode, secret_key, algorithm="HS256")
        return encoded_jwt

    def create_refresh_token(self, data: Dict[str, Any]) -> str:
        """Create refresh token using EXISTING authentication core."""
        if self.auth_core:
            return self.auth_core.create_refresh_token(data)

        # Fallback token creation
        import jwt
        import secrets

        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(days=7)
        to_encode.update({"exp": expire, "type": "refresh"})
        secret_key = secrets.token_hex(32)
        encoded_jwt = jwt.encode(to_encode, secret_key, algorithm="HS256")
        return encoded_jwt

# Global authentication utilities instance
auth_utils = AuthenticationUtilities()

# Convenience dependency functions
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    """Get current user dependency."""
    return await auth_utils.get_current_user(credentials)

async def get_current_active_user(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """Get current active user dependency."""
    return await auth_utils.get_current_active_user(current_user)

async def require_admin(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """Require admin privileges dependency."""
    return await auth_utils.require_admin(current_user)

def require_user_or_admin(user_id: int):
    """Create dependency that requires user to be owner or admin."""
    async def _require_user_or_admin(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
        return await auth_utils.require_user_or_admin(user_id, current_user)
    return _require_user_or_admin

# Optional authentication (for public endpoints that can benefit from user context)
async def get_optional_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False))) -> Optional[Dict[str, Any]]:
    """Get optional user (doesn't raise error if no token)."""
    if not credentials:
        return None

    try:
        return await auth_utils.get_current_user(credentials)
    except HTTPException:
        return None
    except Exception as e:
        logger.error(f"Error in optional authentication: {e}")
        return None

# Rate limiting helpers
class RateLimitChecker:
    """Rate limiting checker using EXISTING systems."""

    def __init__(self):
        self.db_manager = database_manager
        self.performance_logger = performance_logger

    async def check_rate_limit(self, user_id: int, action: str, limit: int, window: int) -> bool:
        """Check if user has exceeded rate limit."""
        if self.db_manager:
            try:
                window_start = datetime.now() - timedelta(seconds=window)

                query = """
                    SELECT COUNT(*) FROM rate_limit_log
                    WHERE user_id = ? AND action = ? AND timestamp > ?
                """
                params = {
                    "user_id": user_id,
                    "action": action,
                    "timestamp": window_start
                }

                result = await self.db_manager.execute_query(query, params)
                current_count = result[0][0] if result else 0

                if current_count >= limit:
                    # Performance tracking
                    if self.performance_logger:
                        self.performance_logger.record_metric("rate_limit_exceeded", 1, "count")

                    return False

                # Log this action
                await self._log_action(user_id, action)
                return True

            except Exception as e:
                logger.error(f"Error checking rate limit: {e}")
                return True  # Allow on error

        return True  # Allow if no database

    async def _log_action(self, user_id: int, action: str):
        """Log user action for rate limiting."""
        if self.db_manager:
            try:
                query = """
                    INSERT INTO rate_limit_log (user_id, action, timestamp)
                    VALUES (?, ?, ?)
                """
                params = {
                    "user_id": user_id,
                    "action": action,
                    "timestamp": datetime.now()
                }

                await self.db_manager.execute_query(query, params)

            except Exception as e:
                logger.error(f"Error logging action: {e}")

# Global rate limit checker
rate_limit_checker = RateLimitChecker()

def rate_limit(action: str, limit: int, window: int = 60):
    """Rate limiting decorator."""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Extract user from kwargs or args
            current_user = kwargs.get('current_user')
            if not current_user:
                # Try to find user in args
                for arg in args:
                    if isinstance(arg, dict) and 'id' in arg:
                        current_user = arg
                        break

            if current_user:
                user_id = current_user.get('id')
                if user_id:
                    allowed = await rate_limit_checker.check_rate_limit(user_id, action, limit, window)
                    if not allowed:
                        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=f"Rate limit exceeded for {action}")

            return await func(*args, **kwargs)
        return wrapper
    return decorator
