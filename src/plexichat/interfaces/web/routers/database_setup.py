
"""
PlexiChat Database Setup Router

Enhanced database setup and management with performance optimization.
Uses EXISTING database abstraction and optimization systems.
"""

import logging
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from colorama import Fore, Style

# Use EXISTING database abstraction layer
try:
    from plexichat.core.database.manager import database_manager
    from plexichat.core.database import initialize_database_system
except ImportError:
    database_manager = None
    initialize_database_system = None

# Use EXISTING performance optimization engine
try:
    from plexichat.core.performance.optimization_engine import PerformanceOptimizationEngine
    from plexichat.infrastructure.utils.performance import async_track_performance
    from plexichat.core.logging_advanced.performance_logger import get_performance_logger
except ImportError:
    PerformanceOptimizationEngine = None
    async_track_performance = None
    get_performance_logger = None

# Authentication imports
try:
    from plexichat.infrastructure.utils.auth import require_admin
except ImportError:
    def require_admin():
        return {"id": 1, "username": "admin", "is_admin": True}

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/database", tags=["database"])

# Initialize EXISTING performance systems
performance_logger = get_performance_logger() if get_performance_logger else None

# Pydantic models
class DatabaseStatus(BaseModel):
    """Database status information."""
    connected: bool
    database_type: str
    version: Optional[str] = None
    tables_count: int
    last_backup: Optional[datetime] = None
    health_score: float

class DatabaseConfig(BaseModel):
    """Database configuration."""
    database_type: str
    host: str
    port: int
    database_name: str
    ssl_enabled: bool
    connection_pool_size: int

class DatabaseService:
    """Service class for database operations using EXISTING systems."""
    def __init__(self):
        self.db_manager = database_manager
        self.performance_logger = performance_logger

    @async_track_performance("database_status") if async_track_performance else lambda f: f
    async def get_database_status(self) -> DatabaseStatus:
        """Get database status using EXISTING database manager."""
        try:
            if self.db_manager:
                status_data = await self.db_manager.get_status()
                return DatabaseStatus(
                    connected=status_data.get("connected", False),
                    database_type=status_data.get("type", "unknown"),
                    version=status_data.get("version"),
                    tables_count=status_data.get("tables_count", 0),
                    last_backup=status_data.get("last_backup"),
                    health_score=status_data.get("health_score", 0.0)
                )
            else:
                return DatabaseStatus(
                    connected=False,
                    database_type="not_configured",
                    version=None,
                    tables_count=0,
                    last_backup=None,
                    health_score=0.0
                )
        except Exception as e:
            logger.error(f"Error getting database status: {e}")
            return DatabaseStatus(
                connected=False,
                database_type="error",
                version=None,
                tables_count=0,
                last_backup=None,
                health_score=0.0
            )

    async def initialize_database(self) -> Dict[str, Any]:
        """Initialize database using EXISTING initialization system."""
        try:
            if initialize_database_system:
                result = await initialize_database_system()
                return {
                    "success": True,
                    "message": "Database initialized successfully",
                    "details": result
                }
            else:
                return {
                    "success": False,
                    "message": "Database initialization system not available",
                    "details": {}
                }
        except Exception as e:
            logger.error(f"Error initializing database: {e}")
            return {
                "success": False,
                "message": f"Database initialization failed: {str(e)}",
                "details": {}
            }

# Initialize service
database_service = DatabaseService()

@router.get("/status", response_model=DatabaseStatus, summary="Get database status")
async def get_database_status(request: Request, current_user: Dict[str, Any] = Depends(require_admin)):
    """Get comprehensive database status (admin only)."""
    client_ip = request.client.host if request.client else "unknown"
    logger.info(Fore.CYAN + f"[DB] Status requested by admin {current_user.get('username')} from {client_ip}" + Style.RESET_ALL)

    # Performance tracking
    if performance_logger:
        performance_logger.record_metric("database_status_requests", 1, "count")
        logger.debug(Fore.GREEN + "[DB] Status performance metric recorded" + Style.RESET_ALL)

    return await database_service.get_database_status()

@router.post("/initialize", summary="Initialize database")
async def initialize_database(request: Request, current_user: Dict[str, Any] = Depends(require_admin)):
    """Initialize database schema and tables (admin only)."""
    client_ip = request.client.host if request.client else "unknown"
    logger.info(Fore.CYAN + f"[DB] Initialization requested by admin {current_user.get('username')} from {client_ip}" + Style.RESET_ALL)

    # Performance tracking
    if performance_logger:
        performance_logger.record_metric("database_init_requests", 1, "count")
        logger.debug(Fore.GREEN + "[DB] Init performance metric recorded" + Style.RESET_ALL)

    result = await database_service.initialize_database()

    if not result["success"]:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=result["message"]
        )

    return result

@router.post("/migrate", summary="Run database migrations")
async def run_migrations(request: Request, current_user: Dict[str, Any] = Depends(require_admin)):
    """Run database migrations (admin only)."""
    client_ip = request.client.host if request.client else "unknown"
    logger.info(Fore.CYAN + f"[DB] Migration requested by admin {current_user.get('username')} from {client_ip}" + Style.RESET_ALL)

    # Performance tracking
    if performance_logger:
        performance_logger.record_metric("database_migration_requests", 1, "count")
        logger.debug(Fore.GREEN + "[DB] Migration performance metric recorded" + Style.RESET_ALL)

    try:
        if database_service.db_manager:
            result = await database_service.db_manager.run_migrations()
            return {
                "success": True,
                "message": "Migrations completed successfully",
                "migrations_applied": result.get("migrations_applied", [])
            }
        else:
            return {
                "success": False,
                "message": "Database manager not available"
            }
    except Exception as e:
        logger.error(f"Error running migrations: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to run migrations"
        )

@router.post("/backup", summary="Create database backup")
async def create_backup(request: Request, current_user: Dict[str, Any] = Depends(require_admin)):
    """Create database backup (admin only)."""
    client_ip = request.client.host if request.client else "unknown"
    logger.info(Fore.CYAN + f"[DB] Backup requested by admin {current_user.get('username')} from {client_ip}" + Style.RESET_ALL)

    # Performance tracking
    if performance_logger:
        performance_logger.record_metric("database_backup_requests", 1, "count")
        logger.debug(Fore.GREEN + "[DB] Backup performance metric recorded" + Style.RESET_ALL)

    try:
        if database_service.db_manager:
            result = await database_service.db_manager.create_backup()
            return {
                "success": True,
                "message": "Backup created successfully",
                "backup_path": result.get("backup_path"),
                "backup_size": result.get("backup_size"),
                "timestamp": datetime.now().isoformat()
            }
        else:
            return {
                "success": False,
                "message": "Database manager not available"
            }
    except Exception as e:
        logger.error(f"Error creating backup: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create backup"
        )

@router.get("/health", summary="Database health check")
async def database_health_check(request: Request, current_user: Dict[str, Any] = Depends(require_admin)):
    """Perform database health check (admin only)."""
    client_ip = request.client.host if request.client else "unknown"
    logger.info(Fore.CYAN + f"[DB] Health check requested by admin {current_user.get('username')} from {client_ip}" + Style.RESET_ALL)

    # Performance tracking
    if performance_logger:
        performance_logger.record_metric("database_health_checks", 1, "count")
        logger.debug(Fore.GREEN + "[DB] Health check performance metric recorded" + Style.RESET_ALL)

    try:
        if database_service.db_manager:
            health_data = await database_service.db_manager.health_check()
            return {
                "healthy": health_data.get("healthy", False),
                "response_time_ms": health_data.get("response_time_ms", 0),
                "connection_count": health_data.get("connection_count", 0),
                "last_query_time": health_data.get("last_query_time"),
                "timestamp": datetime.now().isoformat()
            }
        else:
            return {
                "healthy": False,
                "response_time_ms": 0,
                "connection_count": 0,
                "last_query_time": None,
                "timestamp": datetime.now().isoformat(),
                "error": "Database manager not available"
            }
    except Exception as e:
        logger.error(f"Error in health check: {e}")
        return {
            "healthy": False,
            "response_time_ms": 0,
            "connection_count": 0,
            "last_query_time": None,
            "timestamp": datetime.now().isoformat(),
            "error": str(e)
        }
