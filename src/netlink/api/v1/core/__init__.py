"""
Core API endpoints - Essential system functionality.
"""

from .auth import router as auth_router
from .health import router as health_router
from .system import router as system_router

__all__ = ["auth_router", "health_router", "system_router"]
