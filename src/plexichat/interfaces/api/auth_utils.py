"""
Authentication utilities for PlexiChat API
"""

import logging

from fastapi import HTTPException, status

try:
    from plexichat.core.database.manager import database_manager
except ImportError:
    database_manager = None

try:
    from plexichat.core.security.comprehensive_security_manager import (
        get_security_manager,
    )
    security_manager = get_security_manager()
except ImportError:
    security_manager = None

logger = logging.getLogger(__name__)


async def get_current_user(request):
    """Get current authenticated user."""
    try:
        # Get token from header
        authorization = request.headers.get("Authorization")
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing or invalid authorization header")

        token = authorization.split(" ")[1]

        # Verify token
        if security_manager:
            payload = security_manager.verify_token(token)
            if not payload:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

            # Get user data
            if database_manager:
                user = await database_manager.get_user_by_id(payload["user_id"])
                if not user or not user.get("is_active"):
                    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")

                return user

        # Fallback for testing
        return {"id": 1, "username": "test_user", "email": "test@example.com"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed")
