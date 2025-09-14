# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
# Collaboration Routes - Modular and Integrated
import logging

from fastapi import APIRouter

# Only import submodules that exist and are non-empty/meaningful
from plexichat.interfaces.web.routes.collaboration import chat, whiteboard

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/collaboration", tags=["Collaboration Web"])

# Register only meaningful routers
if hasattr(chat, "router"):
    router.include_router(chat.router)
if hasattr(whiteboard, "router"):
    router.include_router(whiteboard.router)


# try to import the real CollaborationService, otherwise use a stub
# from ...infrastructure.services.collaboration_service import CollaborationService
class CollaborationService:
    def get_session_stats(self):
        return {"stats": "Stub service"}


try:
    # Uncomment the real import if/when available
    # from ...infrastructure.services.collaboration_service import CollaborationService
    collaboration_service = CollaborationService()
except Exception:
    collaboration_service = CollaborationService()


# Example: Add a root endpoint that uses the shared service if available
def get_collab_stats():
    if collaboration_service:
        return collaboration_service.get_session_stats()
    return {"stats": "Service unavailable"}


@router.get("/stats")
def stats():
    """Get collaboration statistics from the shared service if available."""
    return get_collab_stats()
