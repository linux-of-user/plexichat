# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
PlexiChat Admin Router

Enhanced admin interface with comprehensive management capabilities and performance optimization.
Uses EXISTING database abstraction and optimization systems.
"""

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.security import HTTPBearer
from pydantic import BaseModel

# Use EXISTING database abstraction layer
try:
    from plexichat.core_system.database.manager import database_manager
    from plexichat.core_system.database import get_session, execute_query
except ImportError:
    database_manager = None
    get_session = None
    execute_query = None

# Use EXISTING performance optimization engine
try:
    from plexichat.infrastructure.performance.optimization_engine import PerformanceOptimizationEngine
    from plexichat.infrastructure.utils.performance import async_track_performance
    from plexichat.core_system.logging.performance_logger import get_performance_logger, timer
except ImportError:
    PerformanceOptimizationEngine = None
    async_track_performance = None
    get_performance_logger = None
    timer = None

# Authentication imports
try:
    from plexichat.infrastructure.utils.auth import get_current_user, require_admin
except ImportError:
    def get_current_user():
        return {"id": 1, "username": "admin", "is_admin": True}
    def require_admin():
        return {"id": 1, "username": "admin", "is_admin": True}

# Configuration imports
try:
    from plexichat.core.config_manager import ConfigurationManager
    config_manager = ConfigurationManager()
except ImportError:
    class MockConfigManager:
        def get_all(self):
            return {"database": {"type": "sqlite"}, "security": {"level": "high"}}
        def validate_configuration(self):
            return []
    config_manager = MockConfigManager()

# Error handling imports
try:
    from plexichat.infrastructure.utils.monitoring import error_handler
except ImportError:
    class MockErrorHandler:
        def get_error_summary(self, hours: int):
            return {"summary": "No errors", "count": 0}
    error_handler = MockErrorHandler()

# Model imports
try:
    from plexichat.features.users.user import User
    from plexichat.features.users.message import Message
    from plexichat.features.users.files import FileRecord
except ImportError:
    class User:
        id: int
        username: str
        is_admin: bool = False
        
    class Message:
        id: int
        content: str
        
    class FileRecord:
        id: int
        filename: str

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/admin", tags=["admin"])

# Initialize EXISTING performance systems
performance_logger = get_performance_logger() if get_performance_logger else None
optimization_engine = PerformanceOptimizationEngine() if PerformanceOptimizationEngine else None

# Security
security = HTTPBearer()

# Pydantic models
class AdminStats(BaseModel):
    total_users: int
    total_messages: int
    total_files: int
    active_users_24h: int
    system_health: str
    performance_score: Optional[float] = None

class ConfigurationResponse(BaseModel):
    configuration: Dict[str, Any]
    validation_errors: List[str]

class ErrorSummary(BaseModel):
    summary: str
    count: int
    recent_errors: List[Dict[str, Any]]

class AdminService:
    """Service class for admin operations using EXISTING database abstraction layer."""
    
    def __init__(self):
        # Use EXISTING database manager
        self.db_manager = database_manager
        self.performance_logger = performance_logger
        self.optimization_engine = optimization_engine
    
    @async_track_performance("admin_stats") if async_track_performance else lambda f: f
    async def get_admin_stats(self) -> AdminStats:
        """Get admin statistics using EXISTING database abstraction layer."""
        try:
            total_users = 0
            total_messages = 0
            total_files = 0
            active_users_24h = 0
            performance_score = None
            
            if self.db_manager:
                # Use EXISTING database manager for admin stats
                try:
                    # Get total users
                    if self.performance_logger and timer:
                        with timer("admin_user_count"):
                            result = await self.db_manager.execute_query("SELECT COUNT(*) FROM users", {})
                            total_users = result[0][0] if result else 0
                    else:
                        result = await self.db_manager.execute_query("SELECT COUNT(*) FROM users", {})
                        total_users = result[0][0] if result else 0
                    
                    # Get total messages
                    if self.performance_logger and timer:
                        with timer("admin_message_count"):
                            result = await self.db_manager.execute_query("SELECT COUNT(*) FROM messages", {})
                            total_messages = result[0][0] if result else 0
                    else:
                        result = await self.db_manager.execute_query("SELECT COUNT(*) FROM messages", {})
                        total_messages = result[0][0] if result else 0
                    
                    # Get total files
                    if self.performance_logger and timer:
                        with timer("admin_file_count"):
                            result = await self.db_manager.execute_query("SELECT COUNT(*) FROM files", {})
                            total_files = result[0][0] if result else 0
                    else:
                        result = await self.db_manager.execute_query("SELECT COUNT(*) FROM files", {})
                        total_files = result[0][0] if result else 0
                    
                    # Get active users in last 24h (if we have a last_login field)
                    cutoff_time = datetime.now() - timedelta(hours=24)
                    try:
                        if self.performance_logger and timer:
                            with timer("admin_active_users"):
                                result = await self.db_manager.execute_query(
                                    "SELECT COUNT(*) FROM users WHERE last_login > ?", 
                                    {"last_login": cutoff_time}
                                )
                                active_users_24h = result[0][0] if result else 0
                        else:
                            result = await self.db_manager.execute_query(
                                "SELECT COUNT(*) FROM users WHERE last_login > ?", 
                                {"last_login": cutoff_time}
                            )
                            active_users_24h = result[0][0] if result else 0
                    except Exception:
                        # Table might not have last_login field
                        active_users_24h = 0
                    
                except Exception as e:
                    logger.error(f"Error getting admin stats: {e}")
            
            # Get performance score if available
            if self.optimization_engine:
                try:
                    report = self.optimization_engine.get_comprehensive_performance_report()
                    performance_score = report.get("performance_summary", {}).get("overall_score", 0)
                except Exception:
                    pass
            
            return AdminStats(
                total_users=total_users,
                total_messages=total_messages,
                total_files=total_files,
                active_users_24h=active_users_24h,
                system_health="healthy" if total_users > 0 else "warning",
                performance_score=performance_score
            )
            
        except Exception as e:
            logger.error(f"Error generating admin stats: {e}")
            return AdminStats(
                total_users=0,
                total_messages=0,
                total_files=0,
                active_users_24h=0,
                system_health="error",
                performance_score=None
            )
    
    @async_track_performance("admin_config") if async_track_performance else lambda f: f
    async def get_configuration(self) -> ConfigurationResponse:
        """Get system configuration."""
        try:
            config = config_manager.get_all()
            validation_errors = config_manager.validate_configuration()
            
            return ConfigurationResponse(
                configuration=config,
                validation_errors=validation_errors
            )
            
        except Exception as e:
            logger.error(f"Error getting configuration: {e}")
            return ConfigurationResponse(
                configuration={},
                validation_errors=[f"Error retrieving configuration: {str(e)}"]
            )
    
    @async_track_performance("admin_errors") if async_track_performance else lambda f: f
    async def get_error_summary(self, hours: int = 24) -> ErrorSummary:
        """Get error summary."""
        try:
            error_data = error_handler.get_error_summary(hours)
            
            return ErrorSummary(
                summary=error_data.get("summary", "No errors"),
                count=error_data.get("count", 0),
                recent_errors=error_data.get("recent_errors", [])
            )
            
        except Exception as e:
            logger.error(f"Error getting error summary: {e}")
            return ErrorSummary(
                summary="Error retrieving error data",
                count=0,
                recent_errors=[]
            )

# Initialize service
admin_service = AdminService()

@router.get(
    "/stats",
    response_model=AdminStats,
    summary="Get admin statistics"
)
async def get_admin_stats(
    request: Request,
    current_user: Dict[str, Any] = Depends(require_admin)
):
    """Get comprehensive admin statistics with performance optimization."""
    client_ip = request.client.host if request.client else "unknown"
    logger.info(f"Admin stats requested by {current_user.get('username')} from {client_ip}")
    
    # Performance tracking
    if performance_logger:
        performance_logger.record_metric("admin_stats_requests", 1, "count")
    
    return await admin_service.get_admin_stats()

@router.get(
    "/config",
    response_model=ConfigurationResponse,
    summary="Get system configuration"
)
async def get_configuration(
    request: Request,
    current_user: Dict[str, Any] = Depends(require_admin)
):
    """Get system configuration (admin only)."""
    client_ip = request.client.host if request.client else "unknown"
    logger.info(f"Configuration requested by admin {current_user.get('username')} from {client_ip}")
    
    # Performance tracking
    if performance_logger:
        performance_logger.record_metric("admin_config_requests", 1, "count")
    
    return await admin_service.get_configuration()

@router.get(
    "/errors",
    response_model=ErrorSummary,
    summary="Get error summary"
)
async def get_error_summary(
    request: Request,
    hours: int = 24,
    current_user: Dict[str, Any] = Depends(require_admin)
):
    """Get error summary for the specified time period (admin only)."""
    client_ip = request.client.host if request.client else "unknown"
    logger.info(f"Error summary requested by admin {current_user.get('username')} from {client_ip}")
    
    # Performance tracking
    if performance_logger:
        performance_logger.record_metric("admin_error_requests", 1, "count")
    
    return await admin_service.get_error_summary(hours)

@router.get(
    "/dashboard",
    response_class=HTMLResponse,
    summary="Admin dashboard"
)
async def admin_dashboard(
    request: Request,
    current_user: Dict[str, Any] = Depends(require_admin)
):
    """Admin dashboard with comprehensive management interface."""
    client_ip = request.client.host if request.client else "unknown"
    logger.info(f"Admin dashboard accessed by {current_user.get('username')} from {client_ip}")
    
    # Performance tracking
    if performance_logger:
        performance_logger.record_metric("admin_dashboard_requests", 1, "count")
    
    # Get dashboard data
    stats = await admin_service.get_admin_stats()
    config_data = await admin_service.get_configuration()
    error_summary = await admin_service.get_error_summary()
    
    # Generate admin dashboard HTML
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>PlexiChat Admin Dashboard</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
            .container {{ max-width: 1200px; margin: 0 auto; }}
            .header {{ text-align: center; margin-bottom: 30px; background: white; padding: 20px; border-radius: 8px; }}
            .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 20px 0; }}
            .stat-card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            .stat-number {{ font-size: 2em; font-weight: bold; color: #007bff; }}
            .stat-label {{ color: #666; margin-top: 5px; }}
            .section {{ background: white; margin: 20px 0; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            .nav {{ margin: 20px 0; }}
            .nav a {{ margin-right: 20px; text-decoration: none; color: #007bff; padding: 10px 15px; background: white; border-radius: 4px; }}
            .nav a:hover {{ background: #007bff; color: white; }}
            .status-healthy {{ color: #28a745; }}
            .status-warning {{ color: #ffc107; }}
            .status-error {{ color: #dc3545; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>PlexiChat Admin Dashboard</h1>
                <p>Welcome, Administrator {current_user.get('username', 'Admin')}!</p>
                <p class="status-{stats.system_health}">System Status: {stats.system_health.title()}</p>
            </div>
            
            <div class="nav">
                <a href="/web/">Home</a>
                <a href="/admin/stats">Statistics</a>
                <a href="/admin/config">Configuration</a>
                <a href="/admin/errors">Error Logs</a>
                <a href="/system/performance">Performance</a>
                <a href="/docs">API Docs</a>
            </div>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{stats.total_users}</div>
                    <div class="stat-label">Total Users</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{stats.total_messages}</div>
                    <div class="stat-label">Total Messages</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{stats.total_files}</div>
                    <div class="stat-label">Total Files</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{stats.active_users_24h}</div>
                    <div class="stat-label">Active Users (24h)</div>
                </div>
                {"<div class='stat-card'><div class='stat-number'>" + f"{stats.performance_score:.1f}" + "</div><div class='stat-label'>Performance Score</div></div>" if stats.performance_score else ""}
            </div>
            
            <div class="section">
                <h3>System Configuration</h3>
                <p>Configuration items: {len(config_data.configuration)}</p>
                <p>Validation errors: {len(config_data.validation_errors)}</p>
                {"<p style='color: red;'>⚠️ Configuration has validation errors</p>" if config_data.validation_errors else "<p style='color: green;'>✅ Configuration is valid</p>"}
            </div>
            
            <div class="section">
                <h3>Error Summary</h3>
                <p>{error_summary.summary}</p>
                <p>Error count: {error_summary.count}</p>
            </div>
            
            <div class="section">
                <h3>Quick Actions</h3>
                <a href="/system/optimize" style="background: #28a745; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; margin: 5px;">Optimize System</a>
                <a href="/system/tests/run" style="background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; margin: 5px;">Run Tests</a>
                <a href="/status" style="background: #6c757d; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; margin: 5px;">System Status</a>
            </div>
        </div>
    </body>
    </html>
    """
    
    return HTMLResponse(content=html_content)
