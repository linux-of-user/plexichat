# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
from typing import Optional

from plexichat.interfaces.web.routes.collaboration_routes import (
    router as collaboration_router,
)
from plexichat.interfaces.web.routes.dashboard_routes import router as dashboard_router
from plexichat.interfaces.web.routes.performance_routes import (
    router as performance_router,
)

"""
PlexiChat Web Routes

Web route modules for the PlexiChat web interface.
"""

__all__ = ["collaboration_router", "dashboard_router", "performance_router"]
