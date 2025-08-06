"""
PlexiChat API v1 - Main Router

This is the main router that combines all v1 API endpoints.
It provides a single entry point for all v1 functionality.
"""

from fastapi import APIRouter
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

# Import all endpoint routers
from .auth import router as auth_router
from .users import router as users_router
from .messages import router as messages_router
from .files import router as files_router
from .admin import router as admin_router
from .system import router as system_router
from .realtime import router as realtime_router
from .groups import router as groups_router
from .search import router as search_router
from .notifications import router as notifications_router

# Try to import user_settings router with fallback
try:
    from .user_settings import router as user_settings_router
    user_settings_available = True
except ImportError as e:
    logger.warning(f"User settings router not available: {e}")
    user_settings_router = None
    user_settings_available = False

# Try to import client_settings router with fallback
try:
    from .client_settings import router as client_settings_router
    client_settings_available = True
except ImportError as e:
    logger.warning(f"Client settings router not available: {e}")
    client_settings_router = None
    client_settings_available = False

# Create main router
router = APIRouter(prefix="/api/v1", tags=["PlexiChat API v1"])

# Include all sub-routers
router.include_router(auth_router)
router.include_router(users_router)
router.include_router(messages_router)
router.include_router(files_router)
router.include_router(admin_router)
router.include_router(system_router)
router.include_router(realtime_router)
router.include_router(groups_router)
router.include_router(search_router)
router.include_router(notifications_router)

# Include user settings router if available
if user_settings_available and user_settings_router:
    router.include_router(user_settings_router)

# Include client settings router if available
if client_settings_available and client_settings_router:
    router.include_router(client_settings_router)

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
            "authentication": "/api/v1/auth",
            "users": "/api/v1/users",
            "messages": "/api/v1/messages",
            "files": "/api/v1/files",
            "admin": "/api/v1/admin",
            "system": "/api/v1/system",
            "realtime": "/api/v1/realtime",
            "groups": "/api/v1/groups",
            "search": "/api/v1/search",
            "notifications": "/api/v1/notifications"
        },
        "documentation": "/docs",
        "status": "online"
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
            "environment": "development"
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
            "Comprehensive notification system"
        ],
        "endpoints": {
            "auth": {
                "prefix": "/api/v1/auth",
                "endpoints": [
                    "POST /register - Register new user",
                    "POST /login - Login user",
                    "POST /logout - Logout user",
                    "GET /me - Get current user info",
                    "GET /status - Auth service status"
                ]
            },
            "users": {
                "prefix": "/api/v1/users",
                "endpoints": [
                    "GET /me - Get my profile",
                    "PUT /me - Update my profile",
                    "GET /search - Search users",
                    "GET /{user_id} - Get user profile",
                    "GET / - List users",
                    "DELETE /me - Delete my account"
                ]
            },
            "messages": {
                "prefix": "/api/v1/messages",
                "endpoints": [
                    "POST /send - Send message",
                    "GET /conversations - Get conversations",
                    "GET /conversation/{user_id} - Get conversation",
                    "DELETE /{message_id} - Delete message",
                    "GET /stats - Message statistics"
                ]
            },
            "files": {
                "prefix": "/api/v1/files",
                "endpoints": [
                    "POST /upload - Upload file",
                    "GET /{file_id}/download - Download file",
                    "GET /{file_id}/info - Get file info",
                    "GET / - List my files",
                    "POST /{file_id}/share - Share file",
                    "DELETE /{file_id} - Delete file"
                ]
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
                    "DELETE /messages/{message_id} - Delete message"
                ]
            },
            "system": {
                "prefix": "/api/v1/system",
                "endpoints": [
                    "GET /health - Health check",
                    "GET /info - System information",
                    "GET /metrics - Performance metrics",
                    "GET /status - Detailed status",
                    "GET /version - Version info",
                    "GET /ping - Simple ping"
                ]
            },
            "realtime": {
                "prefix": "/api/v1/realtime",
                "endpoints": [
                    "WS /ws/{user_id} - WebSocket connection",
                    "GET /connections - Active connections info",
                    "POST /broadcast - Broadcast message",
                    "POST /send/{user_id} - Send direct message",
                    "GET /status - Real-time system status"
                ]
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
                    "GET /stats - Groups statistics"
                ]
            },
            "search": {
                "prefix": "/api/v1/search",
                "endpoints": [
                    "POST / - Comprehensive search",
                    "GET /suggestions - Search suggestions",
                    "GET /analytics/overview - Analytics overview",
                    "GET /analytics/trends - Search trends",
                    "GET /status - Search system status"
                ]
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
                    "POST /test - Send test notification"
                ]
            }
        },
        "authentication": {
            "type": "Bearer Token",
            "header": "Authorization: Bearer <token>",
            "expiry": "24 hours",
            "note": "Get token from /api/v1/auth/login"
        },
        "limits": {
            "max_file_size": "10MB",
            "max_message_length": 10000,
            "token_expiry": "24 hours"
        }
    }

logger.info("PlexiChat API v1 main router initialized")

# Export router as root_router for compatibility
root_router = router
