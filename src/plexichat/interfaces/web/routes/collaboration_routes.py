from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from ...core.auth.dependencies import require_auth
from ...core.logging import get_logger
from ...services.collaboration_service import CollaborationType, get_collaboration_service

"""
PlexiChat Collaboration Web Routes

Web routes for collaboration dashboard and interfaces providing
access to real-time collaboration features through web interface.
"""

# Initialize router and templates
router = APIRouter(prefix="/collaboration", tags=["Collaboration Web"])
templates = Jinja2Templates(directory=from pathlib import Path
Path(__file__).parent.parent / "templates")
logger = get_logger(__name__)

@router.get("/", response_class=HTMLResponse)
async def collaboration_dashboard(
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """Main collaboration dashboard."""
    try:
        collaboration_service = await get_collaboration_service()
        
        # Get user's sessions
        user_sessions = collaboration_service.get_user_sessions(current_user["user_id"])
        
        # Get collaboration statistics
        stats = collaboration_service.get_session_stats()
        
        return templates.TemplateResponse("collaboration_dashboard.html", {
            "request": request,
            "user": current_user,
            "user_sessions": user_sessions,
            "stats": stats,
            "collaboration_types": [ctype.value for ctype in CollaborationType],
            "page_title": "Collaboration Dashboard",
            "current_time": datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        logger.error(f"Collaboration dashboard error: {e}")
        raise HTTPException(status_code=500, detail=f"Dashboard error: {str(e)}")

@router.get("/editor/{session_id}", response_class=HTMLResponse)
async def collaboration_editor(
    request: Request,
    session_id: str,
    current_user: dict = Depends(require_auth)
):
    """Collaboration editor interface."""
    try:
        collaboration_service = await get_collaboration_service()
        
        # Get session
        session = collaboration_service.get_session(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        
        # Check if user has access
        if current_user["user_id"] not in session.users:
            raise HTTPException(status_code=403, detail="Access denied")
        
        return templates.TemplateResponse("collaboration_editor.html", {
            "request": request,
            "user": current_user,
            "session": session,
            "session_users": list(session.users.values()),
            "page_title": f"Editing: {session.title}",
            "current_time": datetime.now(timezone.utc).isoformat()
        })
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Collaboration editor error: {e}")
        raise HTTPException(status_code=500, detail=f"Editor error: {str(e)}")

@router.get("/whiteboard/{session_id}", response_class=HTMLResponse)
async def collaboration_whiteboard(
    request: Request,
    session_id: str,
    current_user: dict = Depends(require_auth)
):
    """Collaboration whiteboard interface."""
    try:
        collaboration_service = await get_collaboration_service()
        
        # Get session
        session = collaboration_service.get_session(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        
        # Check if user has access
        if current_user["user_id"] not in session.users:
            raise HTTPException(status_code=403, detail="Access denied")
        
        # Check if session is whiteboard type
        if session.collaboration_type != CollaborationType.WHITEBOARD:
            raise HTTPException(status_code=400, detail="Session is not a whiteboard")
        
        return templates.TemplateResponse("collaboration_whiteboard.html", {
            "request": request,
            "user": current_user,
            "session": session,
            "session_users": list(session.users.values()),
            "page_title": f"Whiteboard: {session.title}",
            "current_time": datetime.now(timezone.utc).isoformat()
        })
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Collaboration whiteboard error: {e}")
        raise HTTPException(status_code=500, detail=f"Whiteboard error: {str(e)}")

@router.get("/screen-share/{session_id}", response_class=HTMLResponse)
async def collaboration_screen_share(
    request: Request,
    session_id: str,
    current_user: dict = Depends(require_auth)
):
    """Collaboration screen sharing interface."""
    try:
        collaboration_service = await get_collaboration_service()
        
        # Get session
        session = collaboration_service.get_session(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        
        # Check if user has access
        if current_user["user_id"] not in session.users:
            raise HTTPException(status_code=403, detail="Access denied")
        
        # Check if session is screen share type
        if session.collaboration_type != CollaborationType.SCREEN_SHARE:
            raise HTTPException(status_code=400, detail="Session is not a screen share")
        
        return templates.TemplateResponse("collaboration_screen_share.html", {
            "request": request,
            "user": current_user,
            "session": session,
            "session_users": list(session.users.values()),
            "page_title": f"Screen Share: {session.title}",
            "current_time": datetime.now(timezone.utc).isoformat()
        })
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Collaboration screen share error: {e}")
        raise HTTPException(status_code=500, detail=f"Screen share error: {str(e)}")

@router.get("/presentation/{session_id}", response_class=HTMLResponse)
async def collaboration_presentation(
    request: Request,
    session_id: str,
    current_user: dict = Depends(require_auth)
):
    """Collaboration presentation interface."""
    try:
        collaboration_service = await get_collaboration_service()
        
        # Get session
        session = collaboration_service.get_session(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        
        # Check if user has access
        if current_user["user_id"] not in session.users:
            raise HTTPException(status_code=403, detail="Access denied")
        
        # Check if session is presentation type
        if session.collaboration_type != CollaborationType.PRESENTATION:
            raise HTTPException(status_code=400, detail="Session is not a presentation")
        
        return templates.TemplateResponse("collaboration_presentation.html", {
            "request": request,
            "user": current_user,
            "session": session,
            "session_users": list(session.users.values()),
            "page_title": f"Presentation: {session.title}",
            "current_time": datetime.now(timezone.utc).isoformat()
        })
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Collaboration presentation error: {e}")
        raise HTTPException(status_code=500, detail=f"Presentation error: {str(e)}")

@router.get("/sessions", response_class=HTMLResponse)
async def collaboration_sessions_list(
    request: Request,
    current_user: dict = Depends(require_auth),
    session_type: Optional[str] = Query(None, description="Filter by session type")
):
    """List collaboration sessions."""
    try:
        collaboration_service = await get_collaboration_service()
        
        # Get user's sessions
        user_sessions = collaboration_service.get_user_sessions(current_user["user_id"])
        
        # Filter by type if specified
        if session_type:
            try:
                filter_type = CollaborationType(session_type)
                user_sessions = [s for s in user_sessions if s.collaboration_type == filter_type]
            except ValueError:
                pass  # Invalid type, ignore filter
        
        return templates.TemplateResponse("collaboration_sessions_list.html", {
            "request": request,
            "user": current_user,
            "sessions": user_sessions,
            "session_type_filter": session_type,
            "collaboration_types": [ctype.value for ctype in CollaborationType],
            "page_title": "My Collaboration Sessions",
            "current_time": datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        logger.error(f"Collaboration sessions list error: {e}")
        raise HTTPException(status_code=500, detail=f"Sessions list error: {str(e)}")

@router.get("/help", response_class=HTMLResponse)
async def collaboration_help(
    request: Request,
    current_user: dict = Depends(require_auth)
):
    """Collaboration help and documentation."""
    try:
        return templates.TemplateResponse("collaboration_help.html", {
            "request": request,
            "user": current_user,
            "collaboration_types": [ctype.value for ctype in CollaborationType],
            "page_title": "Collaboration Help",
            "current_time": datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        logger.error(f"Collaboration help error: {e}")
        raise HTTPException(status_code=500, detail=f"Help error: {str(e)}")

# Helper functions for templates
def _format_session_type(session_type: CollaborationType) -> str:
    """Format session type for display."""
    return session_type.value.replace('_', ' ').title()

def _get_session_icon(session_type: CollaborationType) -> str:
    """Get icon for session type."""
    icons = {
        CollaborationType.DOCUMENT: "fas fa-file-alt",
        CollaborationType.CODE: "fas fa-code",
        CollaborationType.WHITEBOARD: "fas fa-chalkboard",
        CollaborationType.SCREEN_SHARE: "fas fa-desktop",
        CollaborationType.PRESENTATION: "fas fa-presentation"
    }
    return icons.get(session_type, "fas fa-users")

def _get_user_role_badge(role: str) -> str:
    """Get badge class for user role."""
    badges = {
        "owner": "badge bg-primary",
        "editor": "badge bg-success",
        "viewer": "badge bg-secondary",
        "commenter": "badge bg-info"
    }
    return badges.get(role, "badge bg-secondary")

# Add template functions
templates.env.globals.update({
    "format_session_type": _format_session_type,
    "get_session_icon": _get_session_icon,
    "get_user_role_badge": _get_user_role_badge
})

# Export router
__all__ = ["router"]
