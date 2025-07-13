from .presence import router as presence_router
from .real_time import router as real_time_router
from .teams import router as teams_router
from .workspaces import router as workspaces_router


"""
Collaboration API endpoints - Real-time collaboration features.
"""

__all__ = ["presence_router", "workspaces_router", "real_time_router", "teams_router"]
