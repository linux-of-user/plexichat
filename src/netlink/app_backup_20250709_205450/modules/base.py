"""
NetLink Base Module System

Provides the foundation for all NetLink modules with simplified APIs,
automatic registration, hot-reload capabilities, and comprehensive development tools.
"""

import asyncio
import logging
import yaml
import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable, Union
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, ValidationError

from app.logger_config import logger

class ModuleConfig(BaseModel):
    """Module configuration model with validation."""
    module_name: str
    module_version: str = "1.0.0"
    module_description: str = ""
    module_author: str = ""
    module_license: str = "MIT"
    
    enabled: bool = True
    auto_load: bool = True
    priority: int = 1
    
    dependencies: List[str] = []
    optional_dependencies: List[str] = []
    
    required_permissions: List[str] = []
    user_tier_access: List[str] = ["basic", "premium", "admin"]
    
    api: Dict[str, Any] = {}
    webui: Dict[str, Any] = {}
    tasks: Dict[str, Any] = {}
    settings: Dict[str, Any] = {}
    database: Dict[str, Any] = {}
    security: Dict[str, Any] = {}

class ModuleEvent(BaseModel):
    """Module event data."""
    event_type: str
    module_name: str
    data: Dict[str, Any]
    timestamp: datetime = datetime.utcnow()

class ModuleError(Exception):
    """Base exception for module errors."""
    pass

class ModuleLoadError(ModuleError):
    """Exception raised when module fails to load."""
    pass

class ModuleConfigError(ModuleError):
    """Exception raised for configuration errors."""
    pass

class BaseModule(ABC):
    """
    Base class for all NetLink modules.
    
    Provides simplified APIs, automatic registration, and development tools.
    """
    
    def __init__(self, config_path: Union[str, Path, Dict[str, Any]]):
        """Initialize the module."""
        self.config = self._load_config(config_path)
        self.logger = self._setup_logger()
        self.router = APIRouter(prefix=self.config.api.get("prefix", f"/api/v1/{self.config.module_name}"))
        self.is_initialized = False
        self.is_running = False
        self.background_tasks = []
        self.event_handlers = {}
        self.cached_data = {}
        self.metrics = {
            "requests": 0,
            "errors": 0,
            "last_activity": None,
            "uptime_start": datetime.utcnow()
        }
        
        # Auto-setup if enabled
        if hasattr(self, 'auto_setup') and self.auto_setup:
            self._auto_setup()
    
    def _load_config(self, config_source: Union[str, Path, Dict[str, Any]]) -> ModuleConfig:
        """Load and validate module configuration."""
        try:
            if isinstance(config_source, dict):
                config_data = config_source
            else:
                config_path = Path(config_source)
                if not config_path.exists():
                    raise ModuleConfigError(f"Configuration file not found: {config_path}")
                
                with open(config_path, 'r', encoding='utf-8') as f:
                    if config_path.suffix.lower() in ['.yaml', '.yml']:
                        config_data = yaml.safe_load(f)
                    else:
                        config_data = json.load(f)
            
            return ModuleConfig(**config_data)
            
        except ValidationError as e:
            raise ModuleConfigError(f"Invalid configuration: {e}")
        except Exception as e:
            raise ModuleConfigError(f"Failed to load configuration: {e}")
    
    def _setup_logger(self) -> logging.Logger:
        """Setup module-specific logger."""
        module_logger = logging.getLogger(f"netlink.modules.{self.config.module_name}")
        
        # Set log level from config
        log_level = self.config.settings.get("log_level", "INFO")
        module_logger.setLevel(getattr(logging, log_level.upper()))
        
        return module_logger
    
    def _auto_setup(self):
        """Automatically setup common module components."""
        # Auto-discover and register API routes
        if hasattr(self, 'setup_routes'):
            self.setup_routes()
        
        # Auto-discover and register background tasks
        if hasattr(self, 'setup_tasks'):
            self.setup_tasks()
        
        # Auto-discover and register event handlers
        if hasattr(self, 'setup_events'):
            self.setup_events()
    
    @abstractmethod
    async def initialize(self):
        """Initialize the module. Must be implemented by subclasses."""
        pass
    
    async def start(self):
        """Start the module."""
        try:
            if not self.is_initialized:
                await self.initialize()
                self.is_initialized = True
            
            self.is_running = True
            self.metrics["uptime_start"] = datetime.utcnow()
            
            # Start background tasks
            await self._start_background_tasks()
            
            self.logger.info(f"Module {self.config.module_name} started successfully")
            await self._emit_event("module.started", {"module": self.config.module_name})
            
        except Exception as e:
            self.logger.error(f"Failed to start module {self.config.module_name}: {e}")
            raise ModuleLoadError(f"Module startup failed: {e}")
    
    async def stop(self):
        """Stop the module."""
        try:
            self.is_running = False
            
            # Stop background tasks
            await self._stop_background_tasks()
            
            # Cleanup resources
            if hasattr(self, 'cleanup'):
                await self.cleanup()
            
            self.logger.info(f"Module {self.config.module_name} stopped")
            await self._emit_event("module.stopped", {"module": self.config.module_name})
            
        except Exception as e:
            self.logger.error(f"Error stopping module {self.config.module_name}: {e}")
    
    async def reload(self):
        """Reload the module configuration and restart."""
        self.logger.info(f"Reloading module {self.config.module_name}")
        await self.stop()
        
        # Reload configuration
        if hasattr(self, '_config_path'):
            self.config = self._load_config(self._config_path)
        
        await self.start()
    
    # Simplified API Registration
    def api_get(self, path: str, **kwargs):
        """Decorator for GET endpoints."""
        return self._create_endpoint_decorator("GET", path, **kwargs)
    
    def api_post(self, path: str, **kwargs):
        """Decorator for POST endpoints."""
        return self._create_endpoint_decorator("POST", path, **kwargs)
    
    def api_put(self, path: str, **kwargs):
        """Decorator for PUT endpoints."""
        return self._create_endpoint_decorator("PUT", path, **kwargs)
    
    def api_delete(self, path: str, **kwargs):
        """Decorator for DELETE endpoints."""
        return self._create_endpoint_decorator("DELETE", path, **kwargs)
    
    def _create_endpoint_decorator(self, method: str, path: str, **kwargs):
        """Create endpoint decorator with automatic registration."""
        def decorator(func):
            # Add endpoint to router
            route_kwargs = {
                "path": path,
                "methods": [method],
                "endpoint": self._wrap_endpoint(func, **kwargs)
            }
            
            # Add additional route parameters
            if "response_model" in kwargs:
                route_kwargs["response_model"] = kwargs["response_model"]
            if "status_code" in kwargs:
                route_kwargs["status_code"] = kwargs["status_code"]
            
            self.router.add_api_route(**route_kwargs)
            return func
        return decorator
    
    def _wrap_endpoint(self, func: Callable, **kwargs):
        """Wrap endpoint with common functionality."""
        async def wrapper(*args, **endpoint_kwargs):
            try:
                # Update metrics
                self.metrics["requests"] += 1
                self.metrics["last_activity"] = datetime.utcnow()
                
                # Check permissions if specified
                if "permissions" in kwargs:
                    await self._check_permissions(kwargs["permissions"])
                
                # Check rate limits if specified
                if "rate_limit" in kwargs:
                    await self._check_rate_limit(kwargs["rate_limit"])
                
                # Call the actual endpoint
                result = await func(*args, **endpoint_kwargs)
                
                # Log successful request
                self.logger.debug(f"API call successful: {func.__name__}")
                
                return result
                
            except Exception as e:
                self.metrics["errors"] += 1
                self.logger.error(f"API call failed: {func.__name__}: {e}")
                raise
        
        return wrapper
    
    # Background Task Management
    def background_task(self, schedule: Optional[str] = None, **kwargs):
        """Decorator for background tasks."""
        def decorator(func):
            task_config = {
                "function": func,
                "schedule": schedule,
                "kwargs": kwargs
            }
            self.background_tasks.append(task_config)
            return func
        return decorator
    
    async def _start_background_tasks(self):
        """Start all registered background tasks."""
        for task_config in self.background_tasks:
            try:
                if task_config["schedule"]:
                    # Schedule periodic task
                    asyncio.create_task(self._run_scheduled_task(task_config))
                else:
                    # Run once
                    asyncio.create_task(task_config["function"]())
                    
            except Exception as e:
                self.logger.error(f"Failed to start background task: {e}")
    
    async def _stop_background_tasks(self):
        """Stop all background tasks."""
        # Cancel all running tasks
        for task in asyncio.all_tasks():
            if task.get_name().startswith(f"module_{self.config.module_name}"):
                task.cancel()
    
    async def _run_scheduled_task(self, task_config: Dict[str, Any]):
        """Run a scheduled background task."""
        # This would integrate with a proper scheduler like APScheduler
        # For now, it's a placeholder
        pass
    
    # Event System
    def event_handler(self, event_type: str):
        """Decorator for event handlers."""
        def decorator(func):
            if event_type not in self.event_handlers:
                self.event_handlers[event_type] = []
            self.event_handlers[event_type].append(func)
            return func
        return decorator
    
    async def _emit_event(self, event_type: str, data: Dict[str, Any]):
        """Emit an event."""
        event = ModuleEvent(
            event_type=event_type,
            module_name=self.config.module_name,
            data=data
        )
        
        # This would integrate with the global event system
        # For now, just log it
        self.logger.debug(f"Event emitted: {event_type}")
    
    # Utility Methods
    async def cache_get(self, key: str) -> Any:
        """Get cached data."""
        return self.cached_data.get(key)
    
    async def cache_set(self, key: str, value: Any, ttl: Optional[int] = None):
        """Set cached data."""
        self.cached_data[key] = {
            "value": value,
            "expires": datetime.utcnow().timestamp() + (ttl or 3600)
        }
    
    async def cache_delete(self, key: str):
        """Delete cached data."""
        self.cached_data.pop(key, None)
    
    def get_setting(self, key: str, default: Any = None) -> Any:
        """Get module setting."""
        return self.config.settings.get(key, default)
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get module metrics."""
        uptime = (datetime.utcnow() - self.metrics["uptime_start"]).total_seconds()
        return {
            **self.metrics,
            "uptime_seconds": uptime,
            "is_running": self.is_running,
            "is_initialized": self.is_initialized
        }
    
    async def _check_permissions(self, required_permissions: List[str]):
        """Check if user has required permissions."""
        # This would integrate with the authentication system
        # For now, it's a placeholder
        pass
    
    async def _check_rate_limit(self, limit: int):
        """Check rate limiting."""
        # This would integrate with the rate limiting system
        # For now, it's a placeholder
        pass
    
    # Development Tools
    def debug(self, message: str, data: Optional[Dict[str, Any]] = None):
        """Debug logging with structured data."""
        if self.config.settings.get("debug", False):
            debug_info = {
                "module": self.config.module_name,
                "message": message,
                "timestamp": datetime.utcnow().isoformat()
            }
            if data:
                debug_info["data"] = data
            
            self.logger.debug(json.dumps(debug_info, indent=2))
    
    def validate_input(self, data: Dict[str, Any], schema: BaseModel) -> BaseModel:
        """Validate input data against Pydantic schema."""
        try:
            return schema(**data)
        except ValidationError as e:
            raise HTTPException(status_code=400, detail=f"Invalid input: {e}")
    
    async def health_check(self) -> Dict[str, Any]:
        """Module health check."""
        return {
            "module": self.config.module_name,
            "version": self.config.module_version,
            "status": "healthy" if self.is_running else "stopped",
            "metrics": self.get_metrics(),
            "last_activity": self.metrics["last_activity"].isoformat() if self.metrics["last_activity"] else None
        }

# Module Registry
class ModuleRegistry:
    """Registry for managing all loaded modules."""
    
    def __init__(self):
        self.modules: Dict[str, BaseModule] = {}
        self.module_configs: Dict[str, ModuleConfig] = {}
    
    def register(self, module: BaseModule):
        """Register a module."""
        self.modules[module.config.module_name] = module
        self.module_configs[module.config.module_name] = module.config
    
    def unregister(self, module_name: str):
        """Unregister a module."""
        self.modules.pop(module_name, None)
        self.module_configs.pop(module_name, None)
    
    def get(self, module_name: str) -> Optional[BaseModule]:
        """Get a module by name."""
        return self.modules.get(module_name)
    
    def list_modules(self) -> List[str]:
        """List all registered modules."""
        return list(self.modules.keys())
    
    async def start_all(self):
        """Start all registered modules."""
        for module in self.modules.values():
            if module.config.enabled:
                try:
                    await module.start()
                except Exception as e:
                    logger.error(f"Failed to start module {module.config.module_name}: {e}")
    
    async def stop_all(self):
        """Stop all registered modules."""
        for module in self.modules.values():
            try:
                await module.stop()
            except Exception as e:
                logger.error(f"Failed to stop module {module.config.module_name}: {e}")

# Global module registry
module_registry = ModuleRegistry()

# Development Tools and Utilities
class ModuleDeveloper:
    """Development tools for module creators."""

    @staticmethod
    def create_module_template(module_name: str, output_dir: str = "modules"):
        """Create a new module template."""
        from pathlib import Path
        import os

        module_dir = Path(output_dir) / module_name
        module_dir.mkdir(parents=True, exist_ok=True)

        # Create module structure
        files = {
            "__init__.py": "",
            "module.py": ModuleDeveloper._get_module_template(module_name),
            "config.yaml": ModuleDeveloper._get_config_template(module_name),
            "README.md": ModuleDeveloper._get_readme_template(module_name),
            "tests/__init__.py": "",
            "tests/test_module.py": ModuleDeveloper._get_test_template(module_name),
            "api/__init__.py": "",
            "api/routes.py": ModuleDeveloper._get_api_template(module_name),
        }

        for file_path, content in files.items():
            full_path = module_dir / file_path
            full_path.parent.mkdir(parents=True, exist_ok=True)
            with open(full_path, 'w', encoding='utf-8') as f:
                f.write(content)

        print(f"✅ Module template created: {module_dir}")
        return module_dir

    @staticmethod
    def _get_module_template(module_name: str) -> str:
        return f'''"""
{module_name.title()} Module for NetLink

This module provides [describe functionality here].
"""

from netlink.app.modules.base import BaseModule
from pydantic import BaseModel
from typing import Dict, Any

class {module_name.title()}Request(BaseModel):
    """Request model for {module_name} operations."""
    data: str
    options: Dict[str, Any] = {{}}

class {module_name.title()}Response(BaseModel):
    """Response model for {module_name} operations."""
    success: bool
    message: str
    data: Dict[str, Any] = {{}}

class {module_name.title()}Module(BaseModule):
    """Main module class."""

    auto_setup = True  # Enable automatic setup

    async def initialize(self):
        """Initialize the module."""
        self.logger.info("Initializing {module_name} module")

        # Initialize your module here
        await self.setup_database()
        await self.load_external_config()

    def setup_routes(self):
        """Setup API routes."""

        @self.api_get("/status")
        async def get_status():
            """Get module status."""
            return {{"status": "active", "version": self.config.module_version}}

        @self.api_post("/process", response_model={module_name.title()}Response)
        async def process_data(request: {module_name.title()}Request):
            """Process data through the module."""
            try:
                # Process the request
                result = await self.process_request(request.data, request.options)

                return {module_name.title()}Response(
                    success=True,
                    message="Data processed successfully",
                    data=result
                )
            except Exception as e:
                self.logger.error(f"Processing failed: {{e}}")
                return {module_name.title()}Response(
                    success=False,
                    message=str(e)
                )

    def setup_tasks(self):
        """Setup background tasks."""

        @self.background_task(schedule="*/10 * * * *")  # Every 10 minutes
        async def maintenance_task(self):
            """Periodic maintenance task."""
            self.logger.info("Running maintenance task")
            # Add your maintenance logic here

    def setup_events(self):
        """Setup event handlers."""

        @self.event_handler("user.login")
        async def on_user_login(self, event_data: Dict[str, Any]):
            """Handle user login events."""
            user_id = event_data.get("user_id")
            self.logger.info(f"User {{user_id}} logged in")

    async def process_request(self, data: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Process a request with the given data and options."""
        # Implement your processing logic here
        return {{
            "processed_data": data.upper(),  # Example processing
            "options_used": options,
            "timestamp": self.get_current_timestamp()
        }}

    async def setup_database(self):
        """Setup module-specific database tables."""
        # Add database setup logic here
        pass

    async def load_external_config(self):
        """Load external configuration if needed."""
        # Add external config loading logic here
        pass

    def get_current_timestamp(self) -> str:
        """Get current timestamp."""
        from datetime import datetime
        return datetime.utcnow().isoformat()

    async def cleanup(self):
        """Cleanup resources when module stops."""
        self.logger.info("Cleaning up {module_name} module")
        # Add cleanup logic here

# Module instance
module = {module_name.title()}Module
'''

    @staticmethod
    def _get_config_template(module_name: str) -> str:
        return f'''# {module_name.title()} Module Configuration

# Module Information
module_name: "{module_name}"
module_version: "1.0.0"
module_description: "A NetLink module for {module_name} functionality"
module_author: "Your Name"
module_license: "MIT"

# Module Settings
enabled: true
auto_load: true
priority: 1

# Dependencies
dependencies: []
optional_dependencies: []

# Permissions
required_permissions: []
user_tier_access: ["basic", "premium", "admin"]

# API Configuration
api:
  enabled: true
  prefix: "/api/v1/{module_name}"
  rate_limit: 100  # requests per minute

# WebUI Configuration
webui:
  enabled: true
  menu_title: "{module_name.title()}"
  menu_icon: "fas fa-puzzle-piece"
  menu_order: 100

# Background Tasks
tasks:
  enabled: true
  schedule: "*/10 * * * *"  # Every 10 minutes

# Custom Settings
settings:
  debug: false
  log_level: "INFO"
  cache_ttl: 3600
  max_retries: 3
  timeout: 30

# Database (if needed)
database:
  enabled: false
  tables: []

# Security
security:
  require_authentication: true
  admin_only: false
  rate_limiting: true
'''

    @staticmethod
    def _get_readme_template(module_name: str) -> str:
        return f'''# {module_name.title()} Module

A NetLink module that provides {module_name} functionality.

## Features

- Feature 1
- Feature 2
- Feature 3

## Configuration

Edit `config.yaml` to configure the module:

```yaml
settings:
  debug: false
  log_level: "INFO"
```

## API Endpoints

- `GET /api/v1/{module_name}/status` - Get module status
- `POST /api/v1/{module_name}/process` - Process data

## Development

To modify this module:

1. Edit `module.py` for main functionality
2. Update `config.yaml` for configuration
3. Add tests in `tests/test_module.py`
4. Run tests: `pytest tests/`

## License

MIT License
'''

    @staticmethod
    def _get_test_template(module_name: str) -> str:
        return f'''"""
Tests for {module_name.title()} Module
"""

import pytest
from unittest.mock import AsyncMock, patch
from {module_name}.module import {module_name.title()}Module, {module_name.title()}Request

@pytest.fixture
async def module():
    """Create module instance for testing."""
    config = {{
        "module_name": "{module_name}",
        "module_version": "1.0.0",
        "settings": {{"debug": True}}
    }}
    module = {module_name.title()}Module(config)
    await module.initialize()
    yield module
    await module.stop()

@pytest.mark.asyncio
async def test_module_initialization(module):
    """Test module initialization."""
    assert module.is_initialized
    assert module.config.module_name == "{module_name}"

@pytest.mark.asyncio
async def test_process_request(module):
    """Test request processing."""
    result = await module.process_request("test data", {{}})

    assert "processed_data" in result
    assert result["processed_data"] == "TEST DATA"

@pytest.mark.asyncio
async def test_api_endpoint(module):
    """Test API endpoint."""
    # This would test the actual API endpoint
    # You'll need to set up FastAPI test client
    pass

@pytest.mark.asyncio
async def test_error_handling(module):
    """Test error handling."""
    with patch.object(module, 'process_request', side_effect=Exception("Test error")):
        # Test that errors are handled gracefully
        pass
'''

    @staticmethod
    def _get_api_template(module_name: str) -> str:
        return f'''"""
API routes for {module_name.title()} Module
"""

from fastapi import APIRouter, HTTPException
from typing import Dict, Any

router = APIRouter()

@router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {{"status": "healthy", "module": "{module_name}"}}

@router.get("/info")
async def get_info():
    """Get module information."""
    return {{
        "name": "{module_name}",
        "version": "1.0.0",
        "description": "Module for {module_name} functionality"
    }}
'''

# Hot-reload functionality
class ModuleHotReloader:
    """Hot-reload modules during development."""

    def __init__(self):
        self.watched_modules = {{}}
        self.file_watchers = {{}}

    async def watch_module(self, module: BaseModule):
        """Watch a module for changes and reload automatically."""
        import asyncio
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler

        class ModuleChangeHandler(FileSystemEventHandler):
            def __init__(self, module_instance):
                self.module = module_instance

            def on_modified(self, event):
                if event.src_path.endswith(('.py', '.yaml', '.yml')):
                    asyncio.create_task(self.module.reload())

        # Set up file watcher
        observer = Observer()
        handler = ModuleChangeHandler(module)

        # Watch module directory
        module_path = Path(module.__file__).parent
        observer.schedule(handler, str(module_path), recursive=True)
        observer.start()

        self.file_watchers[module.config.module_name] = observer

    def stop_watching(self, module_name: str):
        """Stop watching a module."""
        if module_name in self.file_watchers:
            self.file_watchers[module_name].stop()
            del self.file_watchers[module_name]

# Global instances
module_developer = ModuleDeveloper()
hot_reloader = ModuleHotReloader()
