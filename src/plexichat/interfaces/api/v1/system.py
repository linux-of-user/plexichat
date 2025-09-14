"""
PlexiChat API v1 - System Endpoints

System information and health checks:
- Health status
- System information
- Performance metrics
- Version information
- Service status
"""

from datetime import datetime
import logging
import platform

from fastapi import APIRouter, HTTPException
import psutil
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/system", tags=["System"])


# Models
class HealthStatus(BaseModel):
    status: str
    timestamp: datetime
    uptime: str
    version: str


class SystemInfo(BaseModel):
    platform: str
    python_version: str
    cpu_count: int
    memory_total: int
    disk_total: int


class PerformanceMetrics(BaseModel):
    cpu_percent: float
    memory_percent: float
    disk_percent: float
    network_sent: int
    network_recv: int


# from plexichat.core.versioning.changelog_manager import get_version, get_version_info  # Disabled due to missing functions

# Import mock databases from other modules
try:
    from plexichat.interfaces.api.v1.auth import sessions_db, users_db
except ImportError:
    users_db = {}
    sessions_db = {}

try:
    from plexichat.interfaces.api.v1.messages import messages_db
except ImportError:
    messages_db = {}

try:
    from plexichat.interfaces.api.v1.files import _fallback_files_db as files_db
except ImportError:
    files_db = {}

# System startup time
STARTUP_TIME = datetime.now()


# Endpoints
@router.get("/health", response_model=HealthStatus)
async def health_check():
    """Basic health check endpoint."""
    try:
        # Try to get version from versioning module
        try:
            from plexichat.core.versioning.changelog_manager import get_version

            version = get_version()
        except (ImportError, AttributeError):
            version = "1.0.0"
    except Exception:
        version = "1.0.0"

    try:
        uptime = datetime.now() - STARTUP_TIME
        uptime_str = str(uptime).split(".")[0]  # Remove microseconds

        return HealthStatus(
            status="healthy",
            timestamp=datetime.now(),
            uptime=uptime_str,
            version=version,
        )

    except Exception as e:
        logger.error(f"Health check error: {e}")
        raise HTTPException(status_code=500, detail="Health check failed")


@router.get("/info", response_model=SystemInfo)
async def system_info():
    """Get system information."""
    try:
        # Get system info
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage("/")

        return SystemInfo(
            platform=f"{platform.system()} {platform.release()}",
            python_version=platform.python_version(),
            cpu_count=psutil.cpu_count(),
            memory_total=memory.total,
            disk_total=disk.total,
        )

    except Exception as e:
        logger.error(f"System info error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get system info")


@router.get("/metrics", response_model=PerformanceMetrics)
async def performance_metrics():
    """Get current performance metrics."""
    try:
        # Get performance metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        network = psutil.net_io_counters()

        return PerformanceMetrics(
            cpu_percent=cpu_percent,
            memory_percent=memory.percent,
            disk_percent=(disk.used / disk.total) * 100,
            network_sent=network.bytes_sent,
            network_recv=network.bytes_recv,
        )

    except Exception as e:
        logger.error(f"Performance metrics error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get performance metrics")


@router.get("/status")
async def detailed_status():
    """Get detailed system status."""
    try:
        # Calculate uptime
        uptime = datetime.now() - STARTUP_TIME
        uptime_str = str(uptime).split(".")[0]

        # Get system metrics
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage("/")

        # Calculate application stats
        active_messages = len([m for m in messages_db.values() if not m.get("deleted")])

        return {
            "status": "online",
            "timestamp": datetime.now(),
            "uptime": uptime_str,
            "version": "1.0.0",
            "system": {
                "platform": f"{platform.system()} {platform.release()}",
                "python_version": platform.python_version(),
                "cpu_count": psutil.cpu_count(),
                "cpu_percent": cpu_percent,
                "memory_total": memory.total,
                "memory_used": memory.used,
                "memory_percent": memory.percent,
                "disk_total": disk.total,
                "disk_used": disk.used,
                "disk_percent": (disk.used / disk.total) * 100,
            },
            "application": {
                "total_users": len(users_db),
                "active_sessions": len(sessions_db),
                "total_messages": active_messages,
                "total_files": len(files_db),
            },
            "services": {
                "authentication": "online",
                "messaging": "online",
                "file_storage": "online",
                "admin": "online",
            },
        }

    except Exception as e:
        logger.error(f"Detailed status error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get detailed status")


@router.get("/version")
async def version_info():
    """Get version information."""
    try:
        # Try to get version info from versioning module
        try:
            from plexichat.core.versioning.changelog_manager import get_version_info

            version_data = get_version_info()
        except (ImportError, AttributeError):
            version_data = {
                "version": "1.0.0",
                "api_version": "v1",
                "build_date": "2025-09-01",
            }

        # Add additional system info
        version_data.update(
            {
                "environment": "development",
                "features": [
                    "authentication",
                    "messaging",
                    "file_storage",
                    "admin_panel",
                    "system_monitoring",
                ],
            }
        )
        return version_data
    except Exception:
        return {
            "version": "1.0.0",
            "api_version": "v1",
            "build_date": "2025-09-01",
            "environment": "development",
            "features": [
                "authentication",
                "messaging",
                "file_storage",
                "admin_panel",
                "system_monitoring",
            ],
        }


@router.get("/ping")
async def ping():
    """Simple ping endpoint."""
    return {"message": "pong", "timestamp": datetime.now(), "status": "ok"}


@router.get("/time")
async def server_time():
    """Get server time."""
    return {
        "server_time": datetime.now(),
        "timezone": "UTC",
        "timestamp": datetime.now().timestamp(),
    }


@router.get("/capabilities")
async def api_capabilities():
    """Get API capabilities."""
    return {
        "version": "v1",
        "capabilities": {
            "authentication": {
                "registration": True,
                "login": True,
                "logout": True,
                "token_based": True,
            },
            "messaging": {
                "direct_messages": True,
                "encryption": True,
                "file_attachments": False,  # Not implemented in this simple version
                "group_chat": False,  # Not implemented in this simple version
                "message_history": True,
                "message_deletion": True,
            },
            "file_management": {
                "upload": True,
                "download": True,
                "sharing": True,
                "metadata": True,
                "deletion": True,
                "max_file_size": 10485760,  # 10MB
            },
            "administration": {
                "user_management": True,
                "message_moderation": True,
                "system_stats": True,
                "health_monitoring": True,
            },
            "system": {
                "health_checks": True,
                "performance_metrics": True,
                "system_info": True,
                "version_info": True,
            },
        },
        "limits": {
            "max_file_size": 10485760,  # 10MB
            "max_message_length": 10000,
            "rate_limiting": False,  # Not implemented in this simple version
        },
        "security": {
            "https_required": False,  # Development mode
            "token_expiry": 86400,  # 24 hours
            "password_hashing": True,
            "encryption": "basic",  # Simple encryption for demo
        },
    }


@router.get("/stats/summary")
async def stats_summary():
    """Get quick stats summary."""
    try:
        # Calculate basic stats
        active_messages = len([m for m in messages_db.values() if not m.get("deleted")])
        total_file_size = sum(f.get("size", 0) for f in files_db.values())

        return {
            "users": len(users_db),
            "sessions": len(sessions_db),
            "messages": active_messages,
            "files": len(files_db),
            "total_file_size": total_file_size,
            "uptime": str(datetime.now() - STARTUP_TIME).split(".")[0],
            "timestamp": datetime.now(),
        }

    except Exception as e:
        logger.error(f"Stats summary error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get stats summary")
