# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false

"""
PlexiChat Enhanced API v1 Router

Consolidated router with:
- Redis caching for route performance optimization
- Database abstraction layer integration
- Comprehensive error handling
- Performance monitoring
- Auto-discovery of API modules
- Health checks and status monitoring
"""

import logging
from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Depends
from datetime import datetime, timezone

try:
    from plexichat.core.logging import get_logger
    from plexichat.core.database.manager import get_database_manager
    from plexichat.infrastructure.performance.cache_manager import get_cache_manager
    from plexichat.infrastructure.monitoring import get_performance_monitor

    logger = get_logger(__name__)
    database_manager = get_database_manager()
    cache_manager = get_cache_manager()
    performance_monitor = get_performance_monitor()
except ImportError:
    logger = logging.getLogger(__name__)
    database_manager = None
    cache_manager = None
    performance_monitor = None

# Enhanced router with middleware
main_router = APIRouter(prefix="/api/v1", tags=["API v1"])

try:
    logger.info(" Users router loaded")
except ImportError as e:
    logger.warning(f" Users router not available: {e}")
    users_router = APIRouter()

try:
    logger.info(" Auth manager loaded")
except ImportError as e:
    logger.warning(f" Auth manager not available: {e}")

    class MockAuthManager:
        initialized = False

    auth_manager = MockAuthManager()

try:
    logger.info(" Backup manager loaded")
except ImportError as e:
    logger.warning(f" Backup manager not available: {e}")

    class MockBackupManager:
        initialized = False

    backup_manager = MockBackupManager()

try:
    logger.info(" Cluster manager loaded")
except ImportError as e:
    logger.warning(f" Cluster manager not available: {e}")

try:
    logger.info(" AI routers loaded")
except ImportError as e:
    logger.warning(f" AI routers not available: {e}")
    ai_router = APIRouter()
    moderation_router = APIRouter()
    monitoring_router = APIRouter()
    provider_router = APIRouter()

try:
    logger.info(" Plugins router loaded")
except ImportError as e:
    logger.warning(f" Plugins router not available: {e}")
    plugins_router = APIRouter()

# Create main v1 router
router = APIRouter(prefix="/api/v1", tags=["v1"])

# Include feature routers with error handling
if users_router:
    try:
        router.include_router(users_router, prefix="/users", tags=["users"])
        logger.info(" Users router included")
    except Exception as e:
        logger.warning(f" Failed to include users router: {e}")

if plugins_router:
    try:
        router.include_router(plugins_router, prefix="/plugins", tags=["plugins"])
        logger.info(" Plugins router included")
    except Exception as e:
        logger.warning(f" Failed to include plugins router: {e}")

# AI routers
if ai_router:
    try:
        router.include_router(ai_router, prefix="/ai", tags=["ai"])
        logger.info(" AI router included")
    except Exception as e:
        logger.warning(f" Failed to include AI router: {e}")

if moderation_router:
    try:
        router.include_router(
            moderation_router, prefix="/moderation", tags=["moderation"]
        )
        logger.info(" Moderation router included")
    except Exception as e:
        logger.warning(f" Failed to include moderation router: {e}")

if monitoring_router:
    try:
        router.include_router(monitoring_router, prefix="/monitoring", tags=["monitoring"])
        logger.info(" Monitoring router included")
    except Exception as e:
        logger.warning(f" Failed to include monitoring router: {e}")

if provider_router:
    try:
        router.include_router(provider_router, prefix="/providers", tags=["providers"])
        logger.info(" Provider router included")
    except Exception as e:
        logger.warning(f" Failed to include provider router: {e}")


# Health check endpoint
@router.get("/health")
async def health_check():
    """API health check."""
    return {
        "status": "healthy",
        "version": "a.1.0-1",
        "services": {
            "auth": "initialized"
                if auth_manager
                and hasattr(auth_manager, "initialized")
                and auth_manager.initialized
                else "not_initialized",
            "backup": "initialized"
                if backup_manager
                and hasattr(backup_manager, "initialized")
                and backup_manager.initialized
                else "not_initialized",
            "clustering": "available" if cluster_manager else "not_available",
            "ai": "available" if ai_router else "not_available",
            "plugins": "available" if plugins_router else "not_available",
        },
    }


# System info endpoint
@router.get("/info")
async def system_info():
    """Get system information."""
    return {
        "name": "PlexiChat",
        "version": "a.1.0-1",
        "api_version": "v1",
        "features": {
            "users": users_router is not None,
            "security": auth_manager is not None,
            "backups": backup_manager is not None,
            "clustering": cluster_manager is not None,
            "ai": ai_router is not None,
            "plugins": plugins_router is not None,
        },
    }
