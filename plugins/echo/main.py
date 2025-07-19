import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

# Plugin interface imports with fallback
try:
from plugin_internal import *
except ImportError:
    from enum import Enum
    from dataclasses import dataclass
    
    class PluginType(Enum):
        UTILITY = "utility"
    
    @dataclass
    class PluginMetadata:
        name: str
        version: str
        description: str
        author: str
        plugin_type: PluginType
        entry_point: str
        dependencies: List[str]
        permissions: List[str]
        api_version: str
        min_plexichat_version: str
        enabled: bool
        category: str
        tags: List[str]
        homepage: Optional[str] = None
        repository: Optional[str] = None
        license: str = "Unknown"
        icon: Optional[str] = None
        screenshots: Optional[List[str]] = None
        changelog: Optional[List[Dict[str, Any]]] = None
        download_count: int = 0
        rating: float = 0.0
        last_updated: Optional[str] = None
        size_bytes: int = 0
        checksum: Optional[str] = None
        ui_pages: Optional[List[Dict[str, Any]]] = None
        api_endpoints: Optional[List[str]] = None
        webhooks: Optional[List[str]] = None
        settings_schema: Optional[Dict[str, Any]] = None
        auto_start: bool = False
        background_tasks: Optional[List[str]] = None
        
        def __post_init__(self):
            if self.screenshots is None:
                self.screenshots = []
            if self.changelog is None:
                self.changelog = []
            if self.tags is None:
                self.tags = []
            if self.dependencies is None:
                self.dependencies = []
            if self.permissions is None:
                self.permissions = []
            if self.ui_pages is None:
                self.ui_pages = []
            if self.api_endpoints is None:
                self.api_endpoints = []
            if self.webhooks is None:
                self.webhooks = []
            if self.background_tasks is None:
                self.background_tasks = []
    
    class PluginInterface:
        def __init__(self, name: str, version: str):
            self.name = name
            self.version = version
            self.manager = None
            self.logger = logging.getLogger(f"plugin.{name}")
        
        async def initialize(self) -> bool:
            return True


class EchoRequest(BaseModel):
    message: str
    transformation: Optional[str] = "none"
    repeat_count: Optional[int] = 1


class EchoPlugin(PluginInterface):
    """Echo Plugin that repeats messages with transformations."""
    
    def __init__(self):
        super().__init__("Echo", "1.0.0")
        self.plugin_type = PluginType.UTILITY
        
        # Plugin data directory
        self.data_dir = Path("data/plugins/echo")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Configuration
        self.config = {
            "default_transformation": "none",
            "max_repeat_count": 3,
            "enable_timestamp": True
        }
        
        # API router
        self.router = APIRouter(prefix="/api/v1/echo", tags=["Echo"])
        self._setup_routes()
        
        # Statistics
        self.stats = {
            "total_echoes": 0,
            "transformations_used": {},
            "last_echo": None
        }
    
    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        return PluginMetadata(
            name="echo",
            version="1.0.0",
            description="Echo plugin that repeats messages with various transformations",
            author="PlexiChat Team",
            plugin_type=PluginType.UTILITY,
            entry_point="main",
            dependencies=[],
            permissions=[],
            api_version="1.0",
            min_plexichat_version="3.0.0",
            enabled=True,
            category="utility",
            tags=["echo", "utility", "message"],
            homepage="https://github.com/plexichat/plugins/echo",
            repository="https://github.com/plexichat/plugins/echo",
            license="MIT",
            icon="repeat",
            ui_pages=[
                {"name": "echo", "path": "ui/echo", "title": "Echo Tool", "description": "Echo messages with transformations"}
            ],
            api_endpoints=[
                "/api/v1/echo",
                "/api/v1/echo/uppercase",
                "/api/v1/echo/lowercase",
                "/api/v1/echo/reverse",
                "/api/v1/echo/repeat"
            ],
            auto_start=True
        )
    
    async def _plugin_initialize(self) -> bool:
        """Initialize the Echo plugin."""
        try:
            self.logger.info("Initializing Echo Plugin")
            
            # Load configuration
            await self._load_configuration()
            
            # Register with main application
            if self.manager:
                # Register API routes
                app = getattr(self.manager, 'app', None)
                if app:
                    app.include_router(self.router)
                    self.logger.info("Echo API routes registered")
                
                # Register UI pages
                await self._register_ui_pages()
            
            self.logger.info("Echo Plugin initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Echo Plugin initialization failed: {e}")
            return False
    
    async def _load_configuration(self):
        """Load plugin configuration."""
        config_file = self.data_dir / "config.json"
        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    loaded_config = json.load(f)
                    self.config.update(loaded_config)
            except Exception as e:
                self.logger.warning(f"Failed to load config: {e}")
    
    async def _register_ui_pages(self):
        """Register UI pages with the main application."""
        ui_dir = Path(__file__).parent / "ui"
        if ui_dir.exists():
            # Register static files
            app = getattr(self.manager, 'app', None)
            if app:
                from fastapi.staticfiles import StaticFiles
                app.mount(f"/plugins/echo/static", StaticFiles(directory=str(ui_dir / "static")), name="echo_static")
    
    def _transform_message(self, message: str, transformation: str) -> str:
        """Apply transformation to message."""
        if transformation == "uppercase":
            return message.upper()
        elif transformation == "lowercase":
            return message.lower()
        elif transformation == "reverse":
            return message[::-1]
        elif transformation == "repeat":
            return message * self.config["max_repeat_count"]
        else:
            return message
    
    def _setup_routes(self):
        """Setup API routes."""
        
        @self.router.post("/")
        async def echo_message(request: EchoRequest):
            """Echo a message with optional transformation."""
            try:
                # Apply transformation
                transformation = request.transformation or "none"
                transformed_message = self._transform_message(request.message, transformation)
                
                # Create response
                response = {
                    "original": request.message,
                    "echo": transformed_message,
                    "transformation": request.transformation,
                    "plugin": "echo"
                }
                
                # Add timestamp if enabled
                if self.config["enable_timestamp"]:
                    response["timestamp"] = datetime.now(timezone.utc).isoformat()
                
                # Update stats
                self.stats["total_echoes"] += 1
                self.stats["transformations_used"][request.transformation] = self.stats["transformations_used"].get(request.transformation, 0) + 1
                self.stats["last_echo"] = datetime.now(timezone.utc).isoformat()
                
                # Log
                self.logger.info(f"Echo: '{request.message}' -> '{transformed_message}'")
                
                return response
            except Exception as e:
                self.logger.error(f"Echo failed: {e}")
                raise HTTPException(status_code=500, detail="Echo failed")
        
        @self.router.get("/uppercase/{message}")
        async def echo_uppercase(message: str):
            """Echo message in uppercase."""
            try:
                transformed_message = message.upper()
                
                response = {
                    "original": message,
                    "echo": transformed_message,
                    "transformation": "uppercase",
                    "plugin": "echo"
                }
                
                if self.config["enable_timestamp"]:
                    response["timestamp"] = datetime.now(timezone.utc).isoformat()
                
                # Update stats
                self.stats["total_echoes"] += 1
                self.stats["transformations_used"]["uppercase"] = self.stats["transformations_used"].get("uppercase", 0) + 1
                self.stats["last_echo"] = datetime.now(timezone.utc).isoformat()
                
                return response
            except Exception as e:
                self.logger.error(f"Uppercase echo failed: {e}")
                raise HTTPException(status_code=500, detail="Echo failed")
        
        @self.router.get("/lowercase/{message}")
        async def echo_lowercase(message: str):
            """Echo message in lowercase."""
            try:
                transformed_message = message.lower()
                
                response = {
                    "original": message,
                    "echo": transformed_message,
                    "transformation": "lowercase",
                    "plugin": "echo"
                }
                
                if self.config["enable_timestamp"]:
                    response["timestamp"] = datetime.now(timezone.utc).isoformat()
                
                # Update stats
                self.stats["total_echoes"] += 1
                self.stats["transformations_used"]["lowercase"] = self.stats["transformations_used"].get("lowercase", 0) + 1
                self.stats["last_echo"] = datetime.now(timezone.utc).isoformat()
                
                return response
            except Exception as e:
                self.logger.error(f"Lowercase echo failed: {e}")
                raise HTTPException(status_code=500, detail="Echo failed")
        
        @self.router.get("/reverse/{message}")
        async def echo_reverse(message: str):
            """Echo message reversed."""
            try:
                transformed_message = message[::-1]
                
                response = {
                    "original": message,
                    "echo": transformed_message,
                    "transformation": "reverse",
                    "plugin": "echo"
                }
                
                if self.config["enable_timestamp"]:
                    response["timestamp"] = datetime.now(timezone.utc).isoformat()
                
                # Update stats
                self.stats["total_echoes"] += 1
                self.stats["transformations_used"]["reverse"] = self.stats["transformations_used"].get("reverse", 0) + 1
                self.stats["last_echo"] = datetime.now(timezone.utc).isoformat()
                
                return response
            except Exception as e:
                self.logger.error(f"Reverse echo failed: {e}")
                raise HTTPException(status_code=500, detail="Echo failed")
        
        @self.router.get("/repeat/{message}")
        async def echo_repeat(message: str, count: int = 3):
            """Echo message repeated."""
            try:
                if count > self.config["max_repeat_count"]:
                    count = self.config["max_repeat_count"]
                
                transformed_message = message * count
                
                response = {
                    "original": message,
                    "echo": transformed_message,
                    "transformation": "repeat",
                    "repeat_count": count,
                    "plugin": "echo"
                }
                
                if self.config["enable_timestamp"]:
                    response["timestamp"] = datetime.now(timezone.utc).isoformat()
                
                # Update stats
                self.stats["total_echoes"] += 1
                self.stats["transformations_used"]["repeat"] = self.stats["transformations_used"].get("repeat", 0) + 1
                self.stats["last_echo"] = datetime.now(timezone.utc).isoformat()
                
                return response
            except Exception as e:
                self.logger.error(f"Repeat echo failed: {e}")
                raise HTTPException(status_code=500, detail="Echo failed")
        
        @self.router.get("/stats")
        async def get_stats():
            """Get echo statistics."""
            try:
                return {
                    "total_echoes": self.stats["total_echoes"],
                    "transformations_used": self.stats["transformations_used"],
                    "last_echo": self.stats["last_echo"],
                    "config": self.config
                }
            except Exception as e:
                self.logger.error(f"Get stats failed: {e}")
                raise HTTPException(status_code=500, detail="Failed to get stats")
    
    async def health_check(self) -> Dict[str, Any]:
        """Health check for the plugin."""
        return {
            "healthy": True,
            "stats": {
                "total_echoes": self.stats["total_echoes"],
                "transformations_used": self.stats["transformations_used"]
            },
            "config": self.config
        }
    
    async def cleanup(self):
        """Cleanup plugin resources."""
        self.logger.info("Echo Plugin cleanup completed")


# Plugin instance
plugin = EchoPlugin() 
