import asyncio
import functools
from typing import Callable, List, Optional

from .auth_manager import auth_manager
from .exceptions import AuthenticationError, AuthorizationError


"""
PlexiChat Authentication Decorators

Decorators for protecting functions and endpoints with authentication requirements.
"""

def require_auth(security_level: str = "BASIC", scopes: Optional[List[str]] = None):
    """
    Decorator to require authentication with optional security level and scopes.

    Args:
        security_level: Minimum security level required
        scopes: Required scopes for authorization
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            # Extract token from kwargs or request context
            token = kwargs.get('token') or getattr(kwargs.get('request'), 'token', None)

            if not token:
                raise AuthenticationError("Authentication token required")

            # Validate authentication
            auth_result = await auth_manager.require_authentication(token, security_level)

            # Check scopes if provided
            if scopes:
                user_scopes = auth_result.get('scopes', [])
                if not all(scope in user_scopes for scope in scopes):
                    raise AuthorizationError(f"Insufficient scopes. Required: {scopes}")

            # Add auth context to kwargs
            kwargs['auth_context'] = auth_result

            return await func(*args, **kwargs)

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            # For sync functions, run async validation in event loop
            loop = asyncio.get_event_loop()

            token = kwargs.get('token') or getattr(kwargs.get('request'), 'token', None)

            if not token:
                raise AuthenticationError("Authentication token required")

            # Validate authentication
            auth_result = loop.run_until_complete(
                auth_manager.require_authentication(token, security_level)
            )

            # Check scopes if provided
            if scopes:
                user_scopes = auth_result.get('scopes', [])
                if not all(scope in user_scopes for scope in scopes):
                    raise AuthorizationError(f"Insufficient scopes. Required: {scopes}")

            # Add auth context to kwargs
            kwargs['auth_context'] = auth_result

            return func(*args, **kwargs)

        # Return appropriate wrapper based on function type
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator


def from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import require_admin(func: Callable) -> Callable:
    """Decorator to require admin privileges."""
    return require_auth(security_level="GOVERNMENT")(func)


def require_mfa(func: Callable) -> Callable:
    """Decorator to require multi-factor authentication."""
    return require_auth(security_level="ENHANCED")(func)


def require_level(level: str):
    """Decorator to require specific security level."""
    return require_auth(security_level=level)


def optional_auth(func: Callable) -> Callable:
    """
    Decorator for optional authentication.
    Adds auth context if token is present, but doesn't require it.
    """
    @functools.wraps(func)
    async def async_wrapper(*args, **kwargs):
        token = kwargs.get('token') or getattr(kwargs.get('request'), 'token', None)

        if token:
            try:
                auth_result = await auth_manager.require_authentication(token, "BASIC")
                kwargs['auth_context'] = auth_result
            except (AuthenticationError, AuthorizationError):
                kwargs['auth_context'] = None
        else: Optional[kwargs['auth_context']] = None

        return await func(*args, **kwargs)

    @functools.wraps(func)
    def sync_wrapper(*args, **kwargs):
        loop = asyncio.get_event_loop()
        token = kwargs.get('token') or getattr(kwargs.get('request'), 'token', None)

        if token:
            try:
                auth_result = loop.run_until_complete(
                    auth_manager.require_authentication(token, "BASIC")
                )
                kwargs['auth_context'] = auth_result
            except (AuthenticationError, AuthorizationError):
                kwargs['auth_context'] = None
        else:
            kwargs['auth_context'] = None

        return func(*args, **kwargs)

    if asyncio.iscoroutinefunction(func):
        return async_wrapper
    else:
        return sync_wrapper
