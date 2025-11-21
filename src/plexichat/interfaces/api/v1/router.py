"""
PlexiChat API v1 - Main Router

This is the main router that combines all v1 API endpoints.
It provides a single entry point for all v1 functionality.
"""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from plexichat.core.authentication import get_auth_manager
from plexichat.core.logging.unified_logger import get_logger

security = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """Get current authenticated user from token."""
    token = credentials.credentials

    auth_manager = get_auth_manager()
    valid, payload = await auth_manager.validate_token(token)

    if not valid or not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return {
        "id": payload.get("user_id"),
        "username": payload.get("username", ""),
        "permissions": payload.get("permissions", []),
        "roles": payload.get("roles", []),
    }


async def require_admin(current_user: dict = Depends(get_current_user)):
    """Require admin privileges."""
    if "admin" not in current_user.get(
        "permissions", []
    ) and "super_admin" not in current_user.get("roles", []):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required"
        )
    return current_user


async def get_optional_user(token: str = None):
    """Get user if authenticated, None otherwise."""
    try:
        return await get_current_user(token)
    except HTTPException:
        return None


logger = get_logger(__name__)

# Import all endpoint routers
from plexichat.interfaces.api.v1.admin import router as admin_router
from plexichat.interfaces.api.v1.auth import router as auth_router
from plexichat.interfaces.api.v1.backups import router as backups_router
from plexichat.interfaces.api.v1.export import router as export_router
from plexichat.interfaces.api.v1.files import router as files_router
from plexichat.interfaces.api.v1.groups import router as groups_router
from plexichat.interfaces.api.v1.keyboard import router as keyboard_router
from plexichat.interfaces.api.v1.messages import router as messages_router
from plexichat.interfaces.api.v1.notifications import router as notifications_router
from plexichat.interfaces.api.v1.realtime import router as realtime_router
from plexichat.interfaces.api.v1.search import router as search_router
from plexichat.interfaces.api.v1.shards import router as shards_router
from plexichat.interfaces.api.v1.system import router as system_router
from plexichat.interfaces.api.v1.threads import router as threads_router
from plexichat.interfaces.api.v1.users import router as users_router

# Try to import enhanced file sharing router with fallback
try:
    from plexichat.interfaces.api.routers.file_sharing_router import (
        router as file_sharing_router,
    )

    file_sharing_available = True
except ImportError as e:
    logger.warning(f"Enhanced file sharing router not available: {e}")
    file_sharing_router = None
    file_sharing_available = False

# Try to import user_settings router with fallback
try:
    from plexichat.interfaces.api.v1.user_settings import router as user_settings_router

    user_settings_available = True
except ImportError as e:
    logger.warning(f"User settings router not available: {e}")
    user_settings_router = None
    user_settings_available = False

# Try to import client_settings router with fallback
try:
    from plexichat.interfaces.api.v1.client_settings import (
        router as client_settings_router,
    )

    client_settings_available = True
except ImportError as e:
    logger.warning(f"Client settings router not available: {e}")
    client_settings_router = None
    client_settings_available = False

# Create main router
router = APIRouter(prefix="/api/v1", tags=["PlexiChat API v1"])


# Include all sub-routers
# Apply authentication dependencies at the inclusion level where appropriate so
# the unified FastAPI auth adapter is consistently used.

# Authentication endpoints must remain public
router.include_router(auth_router)

# User-related endpoints require an authenticated user
router.include_router(users_router, dependencies=[Depends(get_current_user)])

# Messaging requires authentication
# Threads require authentication
router.include_router(threads_router, dependencies=[Depends(get_current_user)])
router.include_router(messages_router, dependencies=[Depends(get_current_user)])
# Export requires authentication
# Keyboard shortcuts require authentication
router.include_router(keyboard_router, dependencies=[Depends(get_current_user)])
router.include_router(export_router, dependencies=[Depends(get_current_user)])

# Files require authentication (uploads/downloads)
router.include_router(files_router, dependencies=[Depends(get_current_user)])
# Include enhanced file sharing router if available (requires authentication)
if file_sharing_available and file_sharing_router:
    router.include_router(file_sharing_router, dependencies=[Depends(get_current_user)])

# Admin routes should be restricted to admins

# Admin routes should be restricted to admins
router.include_router(admin_router, dependencies=[Depends(require_admin)])

# System router may have public health endpoints; include without forcing auth here
# Individual endpoints inside system_router should enforce their own auth as needed.
router.include_router(system_router)

# Realtime websocket / WS endpoints should validate users
router.include_router(realtime_router, dependencies=[Depends(get_current_user)])

# Groups and channels require authentication
router.include_router(groups_router, dependencies=[Depends(get_current_user)])

# Search endpoints generally require authentication to access user-scoped data
router.include_router(search_router, dependencies=[Depends(get_current_user)])

# Notifications require authentication
router.include_router(notifications_router, dependencies=[Depends(get_current_user)])

# Backups require authentication
router.include_router(backups_router, dependencies=[Depends(get_current_user)])

# Shards require authentication (P2P distribution endpoints)
router.include_router(shards_router, dependencies=[Depends(get_current_user)])

# Include user settings router if available (requires authentication)
if user_settings_available and user_settings_router:
    router.include_router(
        user_settings_router, dependencies=[Depends(get_current_user)]
    )

# Include client settings router if available (may require admin or user depending on endpoint,
# Performance monitoring requires authentication
# router.include_router(performance_router, dependencies=[Depends(get_current_user)])
# but most client settings are per-user)
if client_settings_available and client_settings_router:
    router.include_router(
        client_settings_router, dependencies=[Depends(get_current_user)]
    )


# Root endpoint
@router.get("/")
async def api_root():
    """API v1 root endpoint with information."""
    return {
        "name": "PlexiChat API",
        "version": "v1",
        "description": "Simple, secure messaging API",
        "timestamp": datetime.now(),
        "endpoints": {
            "threads": "/api/v1/threads",
            "authentication": "/api/v1/auth",
            "users": "/api/v1/users",
            "messages": "/api/v1/messages",
            "files": "/api/v1/files",
            "admin": "/api/v1/admin",
            "system": "/api/v1/system",
            "realtime": "/api/v1/realtime",
            "groups": "/api/v1/groups",
            "search": "/api/v1/search",
            "notifications": "/api/v1/notifications",
            "backups": "/api/v1/backups",
            "performance": "/api/v1/performance",
            "keyboard": "/api/v1/keyboard",
            "shards": "/api/v1/shards",
        },
        "documentation": "/docs",
        "status": "online",
    }


# API information endpoint
@router.get("/info")
async def api_info():
    """Get detailed API information."""
    return {
        "api": {
            "name": "PlexiChat API",
            "version": "v1",
            "description": "Simple, secure messaging API with file sharing",
            "build_date": "2024-07-26",
            "environment": "development",
        },
        "features": [
            "User authentication and registration",
            "Direct messaging with encryption",
            "File upload and sharing",
            "User management",
            "Admin panel",
            "System monitoring",
            "Real-time messaging with WebSocket",
            "Groups and channels management",
            "Advanced search and analytics",
            "Comprehensive notification system",
        ],
        "endpoints": {
            "auth": {
                "prefix": "/api/v1/auth",
                "endpoints": [
                    "POST /register - Register new user",
                    "POST /login - Login user",
                    "POST /logout - Logout user",
                    "GET /me - Get current user info",
                    "GET /status - Auth service status",
                ],
            },
            "users": {
                "prefix": "/api/v1/users",
                "endpoints": [
                    "GET /me - Get my profile",
                    "PUT /me - Update my profile",
                    "GET /search - Search users",
                    "GET /{user_id} - Get user profile",
                    "GET / - List users",
                    "DELETE /me - Delete my account",
                ],
            },
            "messages": {
                "prefix": "/api/v1/messages",
                "endpoints": [
                    "POST /send - Send message",
                    "GET /conversations - Get conversations",
                    "GET /conversation/{user_id} - Get conversation",
                    "DELETE /{message_id} - Delete message",
                    "GET /stats - Message statistics",
                ],
            },
            "files": {
                "prefix": "/api/v1/files",
                "endpoints": [
                    "POST /upload - Upload file",
                    "GET /{file_id}/download - Download file",
                    "GET /{file_id}/info - Get file info",
                    "GET / - List my files",
                    "POST /{file_id}/share - Share file",
                    "DELETE /{file_id} - Delete file",
                ],
            },
            "admin": {
                "prefix": "/api/v1/admin",
                "endpoints": [
                    "GET /stats - System statistics",
                    "GET /users - List all users",
                    "POST /users/{user_id}/deactivate - Deactivate user",
                    "POST /users/{user_id}/activate - Activate user",
                    "DELETE /users/{user_id} - Delete user",
                    "GET /messages/recent - Recent messages",
                    "DELETE /messages/{message_id} - Delete message",
                ],
            },
            "system": {
                "prefix": "/api/v1/system",
                "endpoints": [
                    "GET /health - Health check",
                    "GET /info - System information",
                    "GET /metrics - Performance metrics",
                    "GET /status - Detailed status",
                    "GET /version - Version info",
                    "GET /ping - Simple ping",
                ],
            },
            "realtime": {
                "prefix": "/api/v1/realtime",
                "endpoints": [
                    "WS /ws/{user_id} - WebSocket connection",
                    "GET /connections - Active connections info",
                    "POST /broadcast - Broadcast message",
                    "POST /send/{user_id} - Send direct message",
                    "GET /status - Real-time system status",
                ],
            },
            "groups": {
                "prefix": "/api/v1/groups",
                "endpoints": [
                    "POST /create - Create group/channel",
                    "GET / - List groups",
                    "GET /{group_id} - Get group details",
                    "PUT /{group_id} - Update group",
                    "DELETE /{group_id} - Delete group",
                    "POST /{group_id}/join - Join group",
                    "POST /{group_id}/leave - Leave group",
                    "POST /{group_id}/invite - Invite users",
                    "GET /{group_id}/members - Get members",
                    "GET /my/groups - My groups",
                    "GET /stats - Groups statistics",
                ],
            },
            "search": {
                "prefix": "/api/v1/search",
                "endpoints": [
                    "POST / - Comprehensive search",
                    "GET /suggestions - Search suggestions",
                    "GET /analytics/overview - Analytics overview",
                    "GET /analytics/trends - Search trends",
                    "GET /status - Search system status",
                ],
            },
            "notifications": {
                "prefix": "/api/v1/notifications",
                "endpoints": [
                    "POST /send - Send notification",
                    "POST /broadcast - Broadcast notification",
                    "GET / - Get notifications",
                    "GET /{notification_id} - Get specific notification",
                    "PUT /{notification_id} - Update notification",
                    "POST /mark-all-read - Mark all as read",
                    "DELETE /{notification_id} - Delete notification",
                    "GET /settings - Get notification settings",
                    "PUT /settings - Update notification settings",
                    "GET /stats - Notification statistics",
                    "GET /unread/count - Unread count",
                    "POST /test - Send test notification",
                ],
            },
            "shards": {
                "prefix": "/api/v1/shards",
                "endpoints": [
                    "POST /request - Request shard for P2P distribution",
                    "POST /upload - Upload shard for P2P distribution",
                    "GET /download/{backup_id}/{shard_index} - Download shard",
                    "POST /verify/{backup_id}/{shard_index} - Verify shard integrity",
                    "GET /list/{backup_id} - List all shards for backup",
                ],
            },
        },
        "authentication": {
            "type": "Bearer Token",
            "header": "Authorization: Bearer <token>",
            "expiry": "24 hours",
            "note": "Get token from /api/v1/auth/login",
        },
        "limits": {
            "max_file_size": "10MB",
            "max_message_length": 10000,
            "token_expiry": "24 hours",
        },
    }


logger.info("PlexiChat API v1 main router initialized")

# Additional lightweight endpoints retained for compatibility and to replace
# a few common legacy router entries that should exist at the v1 root.


@router.get("/status")
async def status():
    """Lightweight public status endpoint."""
    return {
        "status": "ok",
        "service": "plexichat",
        "version": "v1",
        "timestamp": datetime.now(),
    }


@router.get("/admin/status", dependencies=[Depends(require_admin)])
async def admin_status():
    """Admin-only status endpoint that provides basic system health for admins."""
    # Minimal info returned here; admin_router likely provides more detailed endpoints.
    return {
        "status": "ok",
        "service": "plexichat",
        "role": "admin",
        "timestamp": datetime.now(),
    }


# Export router as root_router for compatibility
root_router = router
