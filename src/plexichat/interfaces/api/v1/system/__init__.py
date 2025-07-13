    from .backup import router as backup_router
    from .backup_endpoints import router as backup_endpoints_router
    from .database import router as database_router
    from .database_setup import router as database_setup_router
    from .enhanced_backup import router as enhanced_backup_router

"""
PlexiChat API v1 - System Module

System management, backup, database, and administrative features.
"""

try:
except ImportError:
    backup_router = None

try:
except ImportError:
    backup_endpoints_router = None

try:
except ImportError:
    enhanced_backup_router = None

try:
except ImportError:
    database_router = None

try:
except ImportError:
    database_setup_router = None

__all__ = [
    "backup_router",
    "backup_endpoints_router", 
    "enhanced_backup_router",
    "database_router",
    "database_setup_router"
]
