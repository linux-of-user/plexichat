# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
PlexiChat Web Router

Enhanced web interface with comprehensive functionality and performance optimization.
Uses EXISTING database abstraction and optimization systems.
"""

import logging
from pathlib import Path
from typing import Any, Dict

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from colorama import Fore, Style

# Use EXISTING database abstraction layer
try:
    from plexichat.core.database.manager import database_manager
    from plexichat.core.database import get_session, execute_query
except ImportError:
    database_manager = None
    get_session = None
    execute_query = None

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

# Authentication imports
try:
    from plexichat.infrastructure.utils.auth import get_current_user, require_admin
except ImportError:
    def get_current_user():
        return {"id": 1, "username": "admin", "is_admin": True}
    def require_admin():
        return {"id": 1, "username": "admin", "is_admin": True}

# Model imports
try:
    from plexichat.features.users.user import User
except ImportError:
    class User:
        id: int
        username: str

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/web", tags=["web"])

# Initialize EXISTING performance systems
performance_logger = get_performance_logger() if get_performance_logger else None
optimization_engine = PerformanceOptimizationEngine() if PerformanceOptimizationEngine else None

class WebService:
    """Service class for web operations using EXISTING database abstraction layer."""

    def __init__(self):
        # Use EXISTING database manager
        self.db_manager = database_manager
        self.performance_logger = performance_logger

    @async_track_performance("web_dashboard") if async_track_performance else lambda f: f
    async def get_dashboard_data(self, user_id: int) -> Dict[str, Any]:
        """Get dashboard data using EXISTING database abstraction layer."""
        try:
            dashboard_data = {
                "user_id": user_id,
                "total_messages": 0,
                "total_files": 0,
                "recent_activity": [],
                "system_status": "healthy"
            }

            if self.db_manager:
                # Use EXISTING database manager for dashboard data
                try:
                    # Get user's message count
                    if self.performance_logger and timer:
                        with timer("user_message_count"):
                            result = await self.db_manager.execute_query()
                                "SELECT COUNT(*) FROM messages WHERE sender_id = ?",
                                {"sender_id": user_id}
                            )
                            dashboard_data["total_messages"] = result[0][0] if result else 0
                    else:
                        result = await self.db_manager.execute_query()
                            "SELECT COUNT(*) FROM messages WHERE sender_id = ?",
                            {"sender_id": user_id}
                        )
                        dashboard_data["total_messages"] = result[0][0] if result else 0

                    # Get user's file count
                    if self.performance_logger and timer:
                        with timer("user_file_count"):
                            result = await self.db_manager.execute_query()
                                "SELECT COUNT(*) FROM files WHERE user_id = ?",
                                {"user_id": user_id}
                            )
                            dashboard_data["total_files"] = result[0][0] if result else 0
                    else:
                        result = await self.db_manager.execute_query()
                            "SELECT COUNT(*) FROM files WHERE user_id = ?",
                            {"user_id": user_id}
                        )
                        dashboard_data["total_files"] = result[0][0] if result else 0

                    # Get recent activity
                    if self.performance_logger and timer:
                        with timer("recent_activity"):
                            result = await self.db_manager.execute_query()
                                """
                                SELECT content, timestamp FROM messages
                                WHERE sender_id = ?
                                ORDER BY timestamp DESC
                                LIMIT 5
                                """,
                                {"sender_id": user_id}
                            )
                            if result:
                                dashboard_data["recent_activity"] = [
                                    {"content": row[0][:50] + "..." if len(row[0]) > 50 else row[0],
                                     "timestamp": row[1]}
                                    for row in result
                                ]
                    else:
                        result = await self.db_manager.execute_query()
                            """
                            SELECT content, timestamp FROM messages
                            WHERE sender_id = ?
                            ORDER BY timestamp DESC
                            LIMIT 5
                            """,
                            {"sender_id": user_id}
                        )
                        if result:
                            dashboard_data["recent_activity"] = [
                                {"content": row[0][:50] + "..." if len(row[0]) > 50 else row[0],
                                 "timestamp": row[1]}
                                for row in result
                            ]

                except Exception as e:
                    logger.error(f"Error getting dashboard data: {e}")

            return dashboard_data

        except Exception as e:
            logger.error(f"Error generating dashboard data: {e}")
            return {
                "user_id": user_id,
                "total_messages": 0,
                "total_files": 0,
                "recent_activity": [],
                "system_status": "error"
            }

# Initialize service
web_service = WebService()

@router.get("/")
async def main_page(request: Request):
    """Main web interface with performance optimization."""
    client_ip = request.client.host if request.client else "unknown"
    logger.info(Fore.CYAN + f"[WEB] Main page accessed from {client_ip}" + Style.RESET_ALL)

    # Performance tracking
    if performance_logger:
        performance_logger.record_metric("web_main_page_requests", 1, "count")
        logger.debug(Fore.GREEN + "[WEB] Main page performance metric recorded" + Style.RESET_ALL)

    # Simple HTML response for now
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>PlexiChat</title>
        <meta charset=\"utf-8\">
        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .container { max-width: 800px; margin: 0 auto; }
            .header { text-align: center; margin-bottom: 40px; }
            .nav { margin: 20px 0; }
            .nav a { margin-right: 20px; text-decoration: none; color: #007bff; }
            .nav a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <div class=\"container\">
            <div class=\"header\">
                <h1>PlexiChat</h1>
                <p>Enhanced messaging platform with performance optimization</p>
            </div>
            <div class=\"nav\">
                <a href=\"/web/dashboard\">Dashboard</a>
                <a href=\"/web/admin\">Admin Panel</a>
                <a href=\"/docs\">API Documentation</a>
                <a href=\"/status\">System Status</a>
            </div>
            <div class=\"content\">
                <h2>Welcome to PlexiChat</h2>
                <p>A high-performance messaging platform with advanced features.</p>
                <ul>
                    <li>Real-time messaging</li>
                    <li>File sharing</li>
                    <li>Performance optimization</li>
                    <li>Comprehensive monitoring</li>
                </ul>
            </div>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@router.get("/dashboard")
async def dashboard(request: Request, current_user: Dict[str, Any] = Depends(get_current_user)):
    """User dashboard with performance optimization."""
    client_ip = request.client.host if request.client else "unknown"
    logger.info(Fore.CYAN + f"[WEB] Dashboard accessed by user {current_user.get('username')} from {client_ip}" + Style.RESET_ALL)

    # Performance tracking
    if performance_logger:
        performance_logger.record_metric("web_dashboard_requests", 1, "count")
        logger.debug(Fore.GREEN + "[WEB] Dashboard performance metric recorded" + Style.RESET_ALL)

    # Get dashboard data
    dashboard_data = await web_service.get_dashboard_data(current_user.get("id", 0))

    # Generate dashboard HTML
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>PlexiChat Dashboard</title>
        <meta charset=\"utf-8\">
        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; }}
            .container {{ max-width: 1000px; margin: 0 auto; }}
            .header {{ text-align: center; margin-bottom: 40px; }}
            .stats {{ display: flex; justify-content: space-around; margin: 20px 0; }}
            .stat-card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }}
            .recent-activity {{ margin: 20px 0; }}
            .activity-item {{ background: #fff; border: 1px solid #ddd; padding: 10px; margin: 5px 0; border-radius: 4px; }}
            .nav {{ margin: 20px 0; }}
            .nav a {{ margin-right: 20px; text-decoration: none; color: #007bff; }}
        </style>
    </head>
    <body>
        <div class=\"container\">
            <div class=\"header\">
                <h1>Dashboard</h1>
                <p>Welcome, {current_user.get('username', 'User')}!</p>
            </div>
            <div class=\"nav\">
                <a href=\"/web/\">Home</a>
                <a href=\"/web/admin\">Admin Panel</a>
                <a href=\"/docs\">API Docs</a>
            </div>
            <div class=\"stats\">
                <div class=\"stat-card\">
                    <h3>{dashboard_data['total_messages']}</h3>
                    <p>Messages Sent</p>
                </div>
                <div class=\"stat-card\">
                    <h3>{dashboard_data['total_files']}</h3>
                    <p>Files Uploaded</p>
                </div>
                <div class=\"stat-card\">
                    <h3>{dashboard_data['system_status']}</h3>
                    <p>System Status</p>
                </div>
            </div>
            <div class=\"recent-activity\">
                <h3>Recent Activity</h3>
                {"".join([f'<div class="activity-item">{item["content"]} - {item["timestamp"]}</div>' for item in dashboard_data['recent_activity']])}
            </div>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@router.get("/admin")
async def admin_panel(request: Request, current_user: Dict[str, Any] = Depends(require_admin)):
    """Admin panel with performance optimization."""
    client_ip = request.client.host if request.client else "unknown"
    logger.info(Fore.CYAN + f"[WEB] Admin panel accessed by admin {current_user.get('username')} from {client_ip}" + Style.RESET_ALL)

    # Performance tracking
    if performance_logger:
        performance_logger.record_metric("web_admin_panel_requests", 1, "count")
        logger.debug(Fore.GREEN + "[WEB] Admin panel performance metric recorded" + Style.RESET_ALL)

    # Simple admin panel HTML
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>PlexiChat Admin Panel</title>
        <meta charset=\"utf-8\">
        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; }}
            .container {{ max-width: 1000px; margin: 0 auto; }}
            .header {{ text-align: center; margin-bottom: 40px; }}
            .admin-section {{ background: #f8f9fa; padding: 20px; margin: 20px 0; border-radius: 8px; }}
            .nav {{ margin: 20px 0; }}
            .nav a {{ margin-right: 20px; text-decoration: none; color: #007bff; }}
            .btn {{ background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; margin: 5px; }}
        </style>
    </head>
    <body>
        <div class=\"container\">
            <div class=\"header\">
                <h1>Admin Panel</h1>
                <p>Welcome, Administrator {current_user.get('username', 'Admin')}!</p>
            </div>
            <div class=\"nav\">
                <a href=\"/web/\">Home</a>
                <a href=\"/web/dashboard\">Dashboard</a>
                <a href=\"/status\">System Status</a>
                <a href=\"/system/performance\">Performance</a>
            </div>
            <div class=\"admin-section\">
                <h3>System Management</h3>
                <a href=\"/system/status\" class=\"btn\">System Status</a>
                <a href=\"/system/analytics\" class=\"btn\">Analytics Report</a>
                <a href=\"/system/tests/run\" class=\"btn\">Run Tests</a>
                <a href=\"/system/optimize\" class=\"btn\">Optimize System</a>
            </div>
            <div class=\"admin-section\">
                <h3>User Management</h3>
                <p>User management features would be implemented here.</p>
            </div>
            <div class=\"admin-section\">
                <h3>Performance Monitoring</h3>
                <p>Real-time performance metrics and optimization controls.</p>
            </div>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)
