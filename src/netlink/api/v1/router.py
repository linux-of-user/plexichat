"""
NetLink API v1 Router

Consolidated router that includes all feature-based API endpoints.
"""

from fastapi import APIRouter

# Import feature routers
from ...users.router import router as users_router
from ...security.auth import auth_manager
from ...backups.manager import backup_manager
from ...clustering import cluster_manager
from ...ai import ai_router, moderation_router, monitoring_router, provider_router
from ...plugins.router import router as plugins_router

# Create main v1 router
router = APIRouter(prefix="/api/v1", tags=["v1"])

# Include feature routers
router.include_router(users_router, prefix="/users", tags=["users"])
router.include_router(plugins_router, prefix="/plugins", tags=["plugins"])

# AI routers
router.include_router(ai_router, prefix="/ai", tags=["ai"])
router.include_router(moderation_router, prefix="/moderation", tags=["moderation"])
router.include_router(monitoring_router, prefix="/monitoring", tags=["monitoring"])
router.include_router(provider_router, prefix="/providers", tags=["providers"])

# Health check endpoint
@router.get("/health")
async def health_check():
    """API health check."""
    return {
        "status": "healthy",
        "version": "1.0.0",
        "services": {
            "auth": "initialized" if auth_manager.initialized else "not_initialized",
            "backup": "initialized" if backup_manager.initialized else "not_initialized",
            "clustering": "available",
            "ai": "available",
            "plugins": "available"
        }
    }

# System info endpoint
@router.get("/info")
async def system_info():
    """Get system information."""
    return {
        "name": "NetLink",
        "version": "3.0.0",
        "api_version": "1.0.0",
        "features": {
            "users": True,
            "security": True,
            "backups": True,
            "clustering": True,
            "ai": True,
            "plugins": True
        }
    }
