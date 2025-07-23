# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
from .collaboration_routes import router as collaboration_router
from .dashboard_routes import router as dashboard_router
from .performance_routes import router as performance_router
from typing import Optional


"""
PlexiChat Web Routes

Web route modules for the PlexiChat web interface.:
"""

__all__ = ["dashboard_router", "performance_router", "collaboration_router"]
