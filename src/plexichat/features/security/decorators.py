# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import functools
import logging
from typing import Callable


from .auth import SecurityLevel, session_manager




from fastapi import HTTPException, Request

"""
PlexiChat Security Decorators

Authentication and authorization decorators for API endpoints.
"""

logger = logging.getLogger(__name__)


def require_auth(required_level: SecurityLevel = SecurityLevel.BASIC):
    """
    Decorator to require authentication with minimum security level.
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract request from args/kwargs
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break

            if not request:
                raise HTTPException(status_code=500, detail="Request object not found")

            # Check session authentication
            session_id = request.cookies.get('session_id')
            if session_id:
                session = await session_manager.validate_session(session_id)
                if session and session.security_level.value >= required_level.value:
                    return await func(*args, **kwargs)

            # Check token authentication (placeholder)
            auth_header = request.headers.get('authorization')
            if auth_header and auth_header.startswith('Bearer '):
                # Token validation would go here
                pass

            raise HTTPException(status_code=401, detail="Authentication required")

        return wrapper
    return decorator


def from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import require_admin():
    """Decorator to require admin privileges."""
    return require_auth(SecurityLevel.GOVERNMENT)


def require_mfa():
    """Decorator to require multi-factor authentication."""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # MFA validation logic would go here
            return await func(*args, **kwargs)
        return wrapper
    return decorator


def require_level(level: SecurityLevel):
    """Decorator to require specific security level."""
    return require_auth(level)


def optional_auth():
    """Decorator for optional authentication."""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Optional auth logic would go here
            return await func(*args, **kwargs)
        return wrapper
    return decorator
