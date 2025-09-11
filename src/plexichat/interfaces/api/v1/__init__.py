"""
PlexiChat API v1 - Clean and Simple Implementation

This is the main v1 API module with a clean, organized structure.
Every file in this module is working and used.

Structure:
- auth.py: Authentication endpoints (register, login, logout)
- users.py: User management endpoints
- messages.py: Messaging endpoints
- files.py: File management endpoints
- admin.py: Admin endpoints
- system.py: System information endpoints
- router.py: Main router that combines all endpoints
"""

import logging

from fastapi import APIRouter

logger = logging.getLogger(__name__)

# Import all routers
from plexichat.interfaces.api.v1 import (
    admin,
    auth,
    files,
    messages,
    rate_limits,
    system,
    threads,
    users,
)

# Import Easter eggs router
try:
    from plexichat.interfaces.api.routers.easter_eggs import (
        router as easter_eggs_router,
    )
    easter_eggs_available = True
except ImportError as e:
    logger.warning(f"Easter eggs router not available: {e}")
    easter_eggs_router = None
    easter_eggs_available = False

# Create main v1 router
v1_router = APIRouter(prefix="/api/v1", tags=["v1"])

# Include all sub-routers
v1_router.include_router(auth.router)
v1_router.include_router(users.router)
v1_router.include_router(messages.router)
v1_router.include_router(files.router)
v1_router.include_router(admin.router)
v1_router.include_router(system.router)
v1_router.include_router(threads.router)
v1_router.include_router(rate_limits.router)

# Include Easter eggs router if available
if easter_eggs_available and easter_eggs_router:
    v1_router.include_router(easter_eggs_router)
    logger.info("Easter eggs router included in API v1")

logger.info("PlexiChat API v1 routers loaded successfully")

# Export the main router
__all__ = ["v1_router"]
