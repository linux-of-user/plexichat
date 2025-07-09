"""
NetLink Login Router
Handles login/logout functionality for web UI and desktop app.
"""

from fastapi import APIRouter, HTTPException, Depends, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Optional
from pathlib import Path

# Import login manager
try:
    from app.auth.login_manager import login_manager
except ImportError:
    login_manager = None

router = APIRouter(tags=["login"])

# Templates
templates_dir = Path(__file__).parent.parent / "web" / "templates"
templates = Jinja2Templates(directory=str(templates_dir))

# Pydantic models
class LoginRequest(BaseModel):
    username: str
    password: str
    remember_me: bool = False

class LoginResponse(BaseModel):
    success: bool
    message: str
    access_token: Optional[str] = None
    session_id: Optional[str] = None
    token_type: Optional[str] = None
    user: Optional[dict] = None

class SessionValidationRequest(BaseModel):
    session_id: str

class SessionValidationResponse(BaseModel):
    valid: bool
    user: Optional[dict] = None

# Authentication dependency
def get_current_user(request: Request):
    """Get current authenticated user."""
    if not login_manager:
        raise HTTPException(status_code=500, detail="Authentication not available")
    
    # Check for session in cookies
    session_id = request.cookies.get("netlink_session")
    if not session_id:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    session = login_manager.validate_session(session_id)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    
    return session

# Web routes
@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Serve login page."""
    return templates.TemplateResponse("login.html", {"request": request})

@router.get("/logout")
async def logout_page(request: Request):
    """Handle logout and redirect."""
    session_id = request.cookies.get("netlink_session")
    
    if session_id and login_manager:
        login_manager.logout(session_id)
    
    # Redirect to login page
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("netlink_session")
    response.delete_cookie("netlink_token")
    
    return response

# API endpoints
@router.post("/api/auth/login", response_model=LoginResponse)
async def api_login(login_request: LoginRequest, response: Response):
    """API login endpoint."""
    if not login_manager:
        raise HTTPException(status_code=500, detail="Authentication not available")
    
    result = login_manager.login(login_request.username, login_request.password)
    
    if result["success"]:
        # Set cookies for web UI
        max_age = 1800 if not login_request.remember_me else 86400 * 7  # 30 min or 7 days
        
        response.set_cookie(
            key="netlink_session",
            value=result["session_id"],
            max_age=max_age,
            httponly=True,
            secure=False,  # Set to True in production with HTTPS
            samesite="lax"
        )
        response.set_cookie(
            key="netlink_token",
            value=result["access_token"],
            max_age=max_age,
            httponly=True,
            secure=False,
            samesite="lax"
        )
    
    return LoginResponse(**result)

@router.post("/api/auth/validate", response_model=SessionValidationResponse)
async def validate_session(validation_request: SessionValidationRequest):
    """Validate session endpoint."""
    if not login_manager:
        return SessionValidationResponse(valid=False)
    
    session = login_manager.validate_session(validation_request.session_id)
    
    if session:
        user_info = login_manager.get_user_info(session["username"])
        return SessionValidationResponse(valid=True, user=user_info)
    
    return SessionValidationResponse(valid=False)

@router.post("/api/auth/logout")
async def api_logout(request: Request, response: Response):
    """API logout endpoint."""
    if not login_manager:
        return {"success": True, "message": "Logged out"}
    
    session_id = request.cookies.get("netlink_session")
    
    if session_id:
        result = login_manager.logout(session_id)
    else:
        result = {"success": True, "message": "No active session"}
    
    # Clear cookies
    response.delete_cookie("netlink_session")
    response.delete_cookie("netlink_token")
    
    return result

@router.get("/api/auth/me")
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """Get current user info."""
    if not login_manager:
        raise HTTPException(status_code=500, detail="Authentication not available")
    
    user_info = login_manager.get_user_info(current_user["username"])
    if not user_info:
        raise HTTPException(status_code=404, detail="User not found")
    
    return user_info

@router.get("/api/auth/health")
async def auth_health():
    """Authentication system health check."""
    if not login_manager:
        return {
            "status": "error",
            "message": "Authentication system not available",
            "available": False
        }
    
    try:
        # Test basic functionality
        users = login_manager.list_users()
        return {
            "status": "healthy",
            "message": "Authentication system operational",
            "available": True,
            "user_count": len(users),
            "default_credentials": "admin / admin123"
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Authentication system error: {str(e)}",
            "available": False
        }
