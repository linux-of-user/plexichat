# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
"""
import time
PlexiChat Status Router

Simple health check and status endpoints for monitoring and load balancing.
Optimized for performance using EXISTING systems.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, Any

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel

# Use EXISTING database abstraction layer
try:
    from plexichat.core.database.manager import database_manager
except ImportError:
    database_manager = None

# Use EXISTING performance optimization engine
try:
    from plexichat.infrastructure.performance.optimization_engine import PerformanceOptimizationEngine
    from plexichat.infrastructure.utils.performance import async_track_performance
    from plexichat.core.logging_advanced.performance_logger import get_performance_logger, timer
except ImportError:
    PerformanceOptimizationEngine = None
    async_track_performance = None
    get_performance_logger = None
    timer = None

# Configuration imports
try:
    from plexichat.core.config import settings
except ImportError:
    class MockSettings:
        API_VERSION = "1.0.0"
    settings = MockSettings()

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/status", tags=["status"])

# Initialize EXISTING performance systems
performance_logger = get_performance_logger() if get_performance_logger else None
optimization_engine = PerformanceOptimizationEngine() if PerformanceOptimizationEngine else None

# Track server start time
server_start_time = datetime.now(timezone.utc)

# Pydantic models
class HealthResponse(BaseModel):
    status: str
    timestamp: str

class UptimeResponse(BaseModel):
    status: str
    uptime_seconds: int
    uptime_readable: str

class MetricsResponse(BaseModel):
    users: int
    messages: int
    files: int
    version: str
    timestamp: str
    performance_score: float = None

class StatusService:
    """Service class for status operations using EXISTING database abstraction layer."""

    def __init__(self):
        # Use EXISTING database manager
        self.db_manager = database_manager
        self.performance_logger = performance_logger
        self.optimization_engine = optimization_engine

    @async_track_performance("health_check") if async_track_performance else lambda f: f
    async def get_health_status(self) -> HealthResponse:
        """Get health status with performance tracking."""
        # Performance tracking
        if self.performance_logger:
            self.performance_logger.record_metric("health_check_requests", 1, "count")

        return HealthResponse()
            status="ok",
            timestamp=datetime.now().isoformat() + "Z"
        )

    @async_track_performance("uptime_check") if async_track_performance else lambda f: f
    async def get_uptime(self) -> UptimeResponse:
        """Get uptime information with performance tracking."""
        # Performance tracking
        if self.performance_logger:
            self.performance_logger.record_metric("uptime_requests", 1, "count")

        now = datetime.now(timezone.utc)
        uptime_duration = now - server_start_time

        return UptimeResponse()
            status="ok",
            uptime_seconds=int(uptime_duration.total_seconds()),
            uptime_readable=str(uptime_duration)
        )

    @async_track_performance("metrics_collection") if async_track_performance else lambda f: f
    async def get_metrics(self) -> MetricsResponse:
        """Get system metrics using EXISTING database abstraction layer."""
        try:
            user_count = 0
            message_count = 0
            file_count = 0
            performance_score = None

            if self.db_manager:
                # Use EXISTING database manager for metrics
                try:
                    # Get user count
                    if self.performance_logger and timer:
                        with timer("user_count_query"):
                            result = await self.db_manager.execute_query("SELECT COUNT(*) FROM users", {})
                            user_count = result[0][0] if result else 0
                    else:
                        result = await self.db_manager.execute_query("SELECT COUNT(*) FROM users", {})
                        user_count = result[0][0] if result else 0

                    # Get message count
                    if self.performance_logger and timer:
                        with timer("message_count_query"):
                            result = await self.db_manager.execute_query("SELECT COUNT(*) FROM messages", {})
                            message_count = result[0][0] if result else 0
                    else:
                        result = await self.db_manager.execute_query("SELECT COUNT(*) FROM messages", {})
                        message_count = result[0][0] if result else 0

                    # Get file count
                    if self.performance_logger and timer:
                        with timer("file_count_query"):
                            result = await self.db_manager.execute_query("SELECT COUNT(*) FROM files", {})
                            file_count = result[0][0] if result else 0
                    else:
                        result = await self.db_manager.execute_query("SELECT COUNT(*) FROM files", {})
                        file_count = result[0][0] if result else 0

                except Exception as e:
                    logger.error(f"Error getting database metrics: {e}")

            # Get performance score if available
            if self.optimization_engine:
                try:
                    report = self.optimization_engine.get_comprehensive_performance_report()
                    performance_score = report.get("performance_summary", {}).get("overall_score", 0)
                except Exception:
                    pass

            # Performance tracking
            if self.performance_logger:
                self.performance_logger.record_metric("metrics_requests", 1, "count")

            return MetricsResponse()
                users=user_count,
                messages=message_count,
                files=file_count,
                version=getattr(settings, 'API_VERSION', '1.0.0'),
                timestamp=datetime.now().isoformat() + "Z",
                performance_score=performance_score
            )

        except Exception as e:
            logger.error(f"Error getting metrics: {e}")
            raise HTTPException()
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to fetch metrics"
            )

# Initialize service
status_service = StatusService()

@router.get()
    "/health",
    response_model=HealthResponse,
    responses={429: {"description": "Rate limit exceeded"}}
)
async def health_check(request: Request):
    """Simple health check endpoint with performance optimization."""
    client_ip = request.client.host if request.client else "unknown"
    logger.debug(f"Health check endpoint called from {client_ip}")

    return await status_service.get_health_status()

@router.get()
    "/uptime",
    response_model=UptimeResponse,
    responses={429: {"description": "Rate limit exceeded"}}
)
async def get_uptime(request: Request):
    """Get system uptime with performance optimization."""
    client_ip = request.client.host if request.client else "unknown"
    logger.debug(f"Uptime check endpoint called from {client_ip}")

    return await status_service.get_uptime()

@router.get()
    "/metrics",
    response_model=MetricsResponse,
    responses={429: {"description": "Rate limit exceeded"}}
)
async def get_metrics(request: Request):
    """Get system metrics with performance optimization."""
    client_ip = request.client.host if request.client else "unknown"
    logger.debug(f"Metrics endpoint called from {client_ip}")

    return await status_service.get_metrics()

@router.get()
    "/",
    response_model=Dict[str, Any],
    summary="Get comprehensive status"
)
async def get_comprehensive_status(request: Request):
    """Get comprehensive system status including health, uptime, and metrics."""
    client_ip = request.client.host if request.client else "unknown"
    logger.info(f"Comprehensive status requested from {client_ip}")

    try:
        # Get all status information
        health = await status_service.get_health_status()
        uptime = await status_service.get_uptime()
        metrics = await status_service.get_metrics()

        # Combine into comprehensive response
        comprehensive_status = {
            "health": health.model_dump(),
            "uptime": uptime.model_dump(),
            "metrics": metrics.model_dump(),
            "timestamp": datetime.now().isoformat() + "Z"
        }

        # Performance tracking
        if performance_logger:
            performance_logger.record_metric("comprehensive_status_requests", 1, "count")

        return comprehensive_status

    except Exception as e:
        logger.error(f"Error getting comprehensive status: {e}")
        raise HTTPException()
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to retrieve comprehensive system status"
        )
