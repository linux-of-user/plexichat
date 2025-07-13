import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional



from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.routing import APIRouter
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

"""
PlexiChat Web Interface Layer

Modern web interface with responsive design, real-time updates,
and comprehensive admin functionality.

This module provides:
- Web UI routing and templates
- Real-time dashboard updates
- Admin panel functionality
- User interface components
- Static asset management
- WebSocket connections
- Progressive Web App features
- Mobile-responsive design
"""

logger = logging.getLogger(__name__)

class WebInterfaceType(Enum):
    """Web interface types."""
    DASHBOARD = "dashboard"
    ADMIN = "admin"
    USER = "user"
    DOCS = "docs"
    SETUP = "setup"
    MONITORING = "monitoring"

class ThemeMode(Enum):
    """Theme modes for web interface."""
    LIGHT = "light"
    DARK = "dark"
    AUTO = "auto"

@dataclass
class WebPageInfo:
    """Web page information and metadata."""
    path: str
    title: str
    description: str
    interface_type: WebInterfaceType
    requires_auth: bool = True
    permissions: List[str] = field(default_factory=list)
    template: str = ""
    scripts: List[str] = field(default_factory=list)
    styles: List[str] = field(default_factory=list)
    meta_tags: Dict[str, str] = field(default_factory=dict)

@dataclass
class WebSocketConnection:
    """WebSocket connection information."""
    websocket: WebSocket
    user_id: Optional[str] = None
    connection_time: datetime = field(default_factory=datetime.now)
    last_activity: datetime = field(default_factory=datetime.now)
    subscriptions: List[str] = field(default_factory=list)

class WebInterfaceManager:
    """
    Web interface manager for PlexiChat.
    
    Handles web routing, templates, static files, and real-time connections.
    """
    
    def __init__(self, app: FastAPI):
        self.app = app
        self.router = APIRouter()
        self.pages: Dict[str, WebPageInfo] = {}
        self.websocket_connections: Dict[str, WebSocketConnection] = {}
        
        # Setup paths
        self.web_root = from pathlib import Path
Path(__file__).parent
        self.templates_dir = self.web_root / "templates"
        self.static_dir = self.web_root / "static"
        
        # Ensure directories exist
        self.templates_dir.mkdir(exist_ok=True)
        self.static_dir.mkdir(exist_ok=True)
        (self.static_dir / "css").mkdir(exist_ok=True)
        (self.static_dir / "js").mkdir(exist_ok=True)
        (self.static_dir / "images").mkdir(exist_ok=True)
        
        # Setup templates
        self.templates = Jinja2Templates(directory=str(self.templates_dir))
        
        # Setup static files
        self.app.mount("/static", StaticFiles(directory=str(self.static_dir)), name="static")
        
        # Setup routes
        self._setup_core_routes()
        self._setup_websocket_routes()
        
        # Register router
        self.app.include_router(self.router)
        
        logger.info(" Web Interface Manager initialized")
    
    def _setup_core_routes(self):
        """Setup core web interface routes."""
        
        @self.router.get("/", response_class=HTMLResponse)
        async def dashboard(request: Request):
            """Main dashboard page."""
            return self.templates.TemplateResponse("dashboard/index.html", {
                "request": request,
                "title": "PlexiChat Dashboard",
                "page_type": "dashboard"
            })
        
        @self.router.get("/admin", response_class=HTMLResponse)
        async def admin_panel(request: Request):
            """Admin panel page."""
            return self.templates.TemplateResponse("admin/index.html", {
                "request": request,
                "title": "PlexiChat Admin Panel",
                "page_type": "admin"
            })
        
        @self.router.get("/users", response_class=HTMLResponse)
        async def user_management(request: Request):
            """User management page."""
            return self.templates.TemplateResponse("admin/users.html", {
                "request": request,
                "title": "User Management",
                "page_type": "admin"
            })
        
        @self.router.get("/settings", response_class=HTMLResponse)
        async def settings_page(request: Request):
            """Settings page."""
            return self.templates.TemplateResponse("settings/index.html", {
                "request": request,
                "title": "Settings",
                "page_type": "settings"
            })
        
        @self.router.get("/monitoring", response_class=HTMLResponse)
        async def monitoring_page(request: Request):
            """System monitoring page."""
            return self.templates.TemplateResponse("monitoring/index.html", {
                "request": request,
                "title": "System Monitoring",
                "page_type": "monitoring"
            })
        
        @self.router.get("/docs", response_class=HTMLResponse)
        async def documentation(request: Request):
            """Documentation page."""
            return self.templates.TemplateResponse("docs/index.html", {
                "request": request,
                "title": "Documentation",
                "page_type": "docs"
            })
        
        @self.router.get("/setup", response_class=HTMLResponse)
        async def setup_wizard(request: Request):
            """Setup wizard page."""
            return self.templates.TemplateResponse("setup/index.html", {
                "request": request,
                "title": "Setup Wizard",
                "page_type": "setup"
            })
    
    def _setup_websocket_routes(self):
        """Setup WebSocket routes for real-time communication."""
        
        @self.router.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            """Main WebSocket endpoint for real-time updates."""
            await self._handle_websocket_connection(websocket)
        
        @self.router.websocket("/ws/admin")
        async def admin_websocket(websocket: WebSocket):
            """Admin WebSocket endpoint."""
            await self._handle_websocket_connection(websocket, admin=True)
        
        @self.router.websocket("/ws/monitoring")
        async def monitoring_websocket(websocket: WebSocket):
            """Monitoring WebSocket endpoint."""
            await self._handle_websocket_connection(websocket, monitoring=True)
    
    async def _handle_websocket_connection(self, websocket: WebSocket, 
                                         admin: bool = False, monitoring: bool = False):
        """Handle WebSocket connection lifecycle."""
        await websocket.accept()
        
        # Generate connection ID
        connection_id = f"ws_{from datetime import datetime
datetime.now().timestamp()}"
        
        # Store connection
        connection = WebSocketConnection(websocket=websocket)
        self.websocket_connections[connection_id] = connection
        
        try:
            # Send welcome message
            await websocket.send_json({
                "type": "connection_established",
                "connection_id": connection_id,
                "timestamp": from datetime import datetime
datetime.now().isoformat()
            })
            
            # Handle messages
            while True:
                try:
                    data = await websocket.receive_json()
                    await self._handle_websocket_message(connection_id, data)
                    
                except WebSocketDisconnect:
                    break
                except Exception as e:
                    logger.error(f"WebSocket message error: {e}")
                    await websocket.send_json({
                        "type": "error",
                        "message": "Message processing error"
                    })
        
        except WebSocketDisconnect:
            pass
        except Exception as e:
            logger.error(f"WebSocket connection error: {e}")
        finally:
            # Clean up connection
            if connection_id in self.websocket_connections:
                del self.websocket_connections[connection_id]
            
            logger.info(f"WebSocket connection closed: {connection_id}")
    
    async def _handle_websocket_message(self, connection_id: str, data: Dict[str, Any]):
        """Handle incoming WebSocket message."""
        connection = self.websocket_connections.get(connection_id)
        if not connection:
            return
        
        message_type = data.get("type")
        
        if message_type == "subscribe":
            # Subscribe to updates
            channel = data.get("channel")
            if channel and channel not in connection.subscriptions:
                connection.subscriptions.append(channel)
                await connection.websocket.send_json({
                    "type": "subscribed",
                    "channel": channel
                })
        
        elif message_type == "unsubscribe":
            # Unsubscribe from updates
            channel = data.get("channel")
            if channel in connection.subscriptions:
                connection.subscriptions.remove(channel)
                await connection.websocket.send_json({
                    "type": "unsubscribed",
                    "channel": channel
                })
        
        elif message_type == "ping":
            # Respond to ping
            await connection.websocket.send_json({
                "type": "pong",
                "timestamp": from datetime import datetime
datetime.now().isoformat()
            })
        
        # Update last activity
        connection.last_activity = from datetime import datetime
datetime.now()
    
    async def broadcast_to_channel(self, channel: str, message: Dict[str, Any]):
        """Broadcast message to all connections subscribed to a channel."""
        disconnected_connections = []
        
        for connection_id, connection in self.websocket_connections.items():
            if channel in connection.subscriptions:
                try:
                    await connection.websocket.send_json({
                        "type": "broadcast",
                        "channel": channel,
                        "data": message,
                        "timestamp": from datetime import datetime
datetime.now().isoformat()
                    })
                except Exception as e:
                    logger.error(f"Failed to send to connection {connection_id}: {e}")
                    disconnected_connections.append(connection_id)
        
        # Clean up disconnected connections
        for connection_id in disconnected_connections:
            if connection_id in self.websocket_connections:
                del self.websocket_connections[connection_id]
    
    def register_page(self, page_info: WebPageInfo):
        """Register a web page."""
        self.pages[page_info.path] = page_info
        logger.info(f" Registered web page: {page_info.path}")
    
    def get_page_info(self, path: str) -> Optional[WebPageInfo]:
        """Get page information."""
        return self.pages.get(path)
    
    def list_pages(self, interface_type: Optional[WebInterfaceType] = None) -> List[WebPageInfo]:
        """List registered pages."""
        pages = list(self.pages.values())
        
        if interface_type:
            pages = [p for p in pages if p.interface_type == interface_type]
        
        return pages
    
    def get_connection_count(self) -> int:
        """Get active WebSocket connection count."""
        return len(self.websocket_connections)
    
    def get_connection_info(self) -> Dict[str, Any]:
        """Get WebSocket connection information."""
        return {
            "total_connections": len(self.websocket_connections),
            "connections": [
                {
                    "id": conn_id,
                    "user_id": conn.user_id,
                    "connection_time": conn.connection_time.isoformat(),
                    "last_activity": conn.last_activity.isoformat(),
                    "subscriptions": conn.subscriptions
                }
                for conn_id, conn in self.websocket_connections.items()
            ]
        }
    
    async def cleanup_inactive_connections(self, timeout_minutes: int = 30):
        """Clean up inactive WebSocket connections."""
        cutoff_time = from datetime import datetime
datetime.now() - timedelta(minutes=timeout_minutes)
        inactive_connections = []
        
        for connection_id, connection in self.websocket_connections.items():
            if connection.last_activity < cutoff_time:
                inactive_connections.append(connection_id)
        
        for connection_id in inactive_connections:
            connection = self.websocket_connections.pop(connection_id, None)
            if connection:
                try:
                    await connection.websocket.close()
                except Exception:
                    pass
        
        if inactive_connections:
            logger.info(f"Cleaned up {len(inactive_connections)} inactive WebSocket connections")

# Global web interface manager
_web_manager: Optional[WebInterfaceManager] = None

def get_web_manager() -> Optional[WebInterfaceManager]:
    """Get the global web interface manager."""
    return _web_manager

def initialize_web_manager(app: FastAPI) -> WebInterfaceManager:
    """Initialize the global web interface manager."""
    global _web_manager
    _web_manager = WebInterfaceManager(app)
    return _web_manager

# Utility functions
def web_page(path: str, title: str, description: str, 
            interface_type: WebInterfaceType, requires_auth: bool = True,
            permissions: List[str] = None, template: str = ""):
    """Decorator for registering web pages."""
    def decorator(func):
        if _web_manager:
            page_info = WebPageInfo(
                path=path,
                title=title,
                description=description,
                interface_type=interface_type,
                requires_auth=requires_auth,
                permissions=permissions or [],
                template=template
            )
            _web_manager.register_page(page_info)
        return func
    return decorator

# Export main components
__all__ = [
    "WebInterfaceManager",
    "WebInterfaceType",
    "ThemeMode",
    "WebPageInfo",
    "WebSocketConnection",
    "get_web_manager",
    "initialize_web_manager",
    "web_page"
]
