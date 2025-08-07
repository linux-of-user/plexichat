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
    pass
except ImportError:
    from enum import Enum
    from dataclasses import dataclass
    
    class PluginType(Enum):
        FEATURE = "feature"
    
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


class HelloWorldPlugin(PluginInterface):
    """Simple Hello World Plugin."""
    
    def __init__(self):
        super().__init__("HelloWorld", "1.0.0")
        self.plugin_type = PluginType.FEATURE
        
        # Plugin data directory (use project root)
        project_root = Path(__file__).parent.parent.parent
        self.data_dir = project_root / "data/plugins/hello_world"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Configuration
        self.config = {
            "greeting": "Hello",
            "enable_logging": True
        }
        
        # API router
        self.router = APIRouter(prefix="/api/v1/hello", tags=["Hello World"])
        self._setup_routes()
        
        # Statistics
        self.stats = {
            "total_greetings": 0,
            "unique_visitors": set(),
            "last_greeting": None
        }
    
    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        return PluginMetadata(
            name="hello_world",
            version="1.0.0",
            description="A simple Hello World plugin to demonstrate the plugin system",
            author="PlexiChat Team",
            plugin_type=PluginType.FEATURE,
            entry_point="main",
            dependencies=[],
            permissions=[],
            api_version="1.0",
            min_plexichat_version="3.0.0",
            enabled=True,
            category="demo",
            tags=["demo", "hello", "world"],
            homepage="https://github.com/plexichat/plugins/hello-world",
            repository="https://github.com/plexichat/plugins/hello-world",
            license="MIT",
            icon="hand-wave",
            ui_pages=[
                {"name": "hello", "path": "ui/hello", "title": "Hello World", "description": "Simple Hello World page"}
            ],
            api_endpoints=[
                "/api/v1/hello",
                "/api/v1/hello/{name}"
            ],
            auto_start=True
        )
    
    async def _plugin_initialize(self) -> bool:
        """Initialize the Hello World plugin."""
        try:
            self.logger.info("Initializing Hello World Plugin")
            
            # Load configuration
            await self._load_configuration()
            
            # Register with main application
            if self.manager:
                # Register API routes
                app = getattr(self.manager, 'app', None)
                if app:
                    app.include_router(self.router)
                    self.logger.info("Hello World API routes registered")
                
                # Register UI pages
                await self._register_ui_pages()
            
            self.logger.info("Hello World Plugin initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Hello World Plugin initialization failed: {e}")
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
                app.mount(f"/plugins/hello/static", StaticFiles(directory=str(ui_dir / "static")), name="hello_static")
    
    def _setup_routes(self):
        """Setup API routes."""
        
        @self.router.get("/")
        async def hello_world():
            """Get a simple hello world message."""
            try:
                greeting = self.config["greeting"]
                message = f"{greeting}, World!"
                
                # Update stats
                self.stats["total_greetings"] += 1
                self.stats["last_greeting"] = datetime.now(timezone.utc).isoformat()
                
                # Log if enabled
                if self.config["enable_logging"]:
                    self.logger.info(f"Greeting sent: {message}")
                
                return {
                    "message": message,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "plugin": "hello_world"
                }
            except Exception as e:
                self.logger.error(f"Hello world failed: {e}")
                raise HTTPException(status_code=500, detail="Greeting failed")
        
        @self.router.get("/{name}")
        async def hello_name(name: str):
            """Get a personalized hello message."""
            try:
                greeting = self.config["greeting"]
                message = f"{greeting}, {name}!"
                
                # Update stats
                self.stats["total_greetings"] += 1
                self.stats["unique_visitors"].add(name)
                self.stats["last_greeting"] = datetime.now(timezone.utc).isoformat()
                
                # Log if enabled
                if self.config["enable_logging"]:
                    self.logger.info(f"Personalized greeting sent to {name}: {message}")
                
                return {
                    "message": message,
                    "name": name,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "plugin": "hello_world"
                }
            except Exception as e:
                self.logger.error(f"Hello name failed: {e}")
                raise HTTPException(status_code=500, detail="Greeting failed")
        
        @self.router.get("/stats")
        async def get_stats():
            """Get plugin statistics."""
            try:
                return {
                    "total_greetings": self.stats["total_greetings"],
                    "unique_visitors": len(self.stats["unique_visitors"]),
                    "last_greeting": self.stats["last_greeting"],
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
                "total_greetings": self.stats["total_greetings"],
                "unique_visitors": len(self.stats["unique_visitors"])
            },
            "config": self.config
        }
    
    async def cleanup(self):
        """Cleanup plugin resources."""
        self.logger.info("Hello World Plugin cleanup completed")


# Plugin instance
plugin = HelloWorldPlugin() 
