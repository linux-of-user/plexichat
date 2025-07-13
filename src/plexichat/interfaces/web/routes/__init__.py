"""
PlexiChat Web Routes

Web route modules for the PlexiChat web interface.
"""

from .collaboration_routes import router as collaboration_router
from .dashboard_routes import router as dashboard_router
from .performance_routes import router as performance_router

__all__ = ["dashboard_router", "performance_router", "collaboration_router"]
