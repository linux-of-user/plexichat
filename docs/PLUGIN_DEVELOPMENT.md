# PlexiChat Plugin Development Guide

This guide provides comprehensive information for developing plugins for PlexiChat, including architecture, best practices, and integration examples.

## Table of Contents

1. [Plugin Architecture](#plugin-architecture)
2. [Getting Started](#getting-started)
3. [Plugin Structure](#plugin-structure)
4. [Plugin Interface](#plugin-interface)
5. [Configuration Management](#configuration-management)
6. [API Integration](#api-integration)
7. [UI Integration](#ui-integration)
8. [Background Tasks](#background-tasks)
9. [Testing](#testing)
10. [Packaging and Distribution](#packaging-and-distribution)
11. [Best Practices](#best-practices)
12. [Examples](#examples)
13. [Documentation & API Reference](#documentation--api-reference)

## Plugin Architecture

PlexiChat uses a modular plugin architecture that provides:

- **Dynamic Loading**: Plugins are loaded at runtime without system restart
- **Isolation**: Each plugin runs in its own context with error isolation
- **Configuration**: Built-in configuration management with schema validation
- **API Integration**: Easy integration with PlexiChat's API system
- **UI Integration**: Support for custom UI pages and components
- **Background Tasks**: Long-running task support
- **Marketplace**: Integration with plugin marketplace

### Plugin Types

- **CORE**: Core system functionality
- **FEATURE**: Feature plugins (most common)
- **INTEGRATION**: Third-party integrations
- **MICRO_APP**: Self-contained applications
- **AI_NODE**: AI/ML functionality
- **SECURITY_NODE**: Security features
- **STORAGE_NODE**: Storage and backup
- **EXTENSION**: Extensions to existing features
- **THEME**: UI themes and customization
- **AUTH_PROVIDER**: Authentication providers
- **NOTIFICATION**: Notification systems
- **ANALYTICS**: Analytics and reporting
- **BACKUP**: Backup and recovery
- **MONITORING**: System monitoring
- **AUTOMATION**: Workflow automation
- **CUSTOM**: Custom plugin types

## Getting Started

### Prerequisites

- Python 3.8+
- PlexiChat development environment
- Basic understanding of FastAPI and async Python

### Creating Your First Plugin

1. **Create Plugin Directory**

```bash
mkdir plugins/my_awesome_plugin
cd plugins/my_awesome_plugin
```

2. **Create Plugin Manifest**

Create `plugin.json`:

```json
{
  "name": "my_awesome_plugin",
  "version": "1.0.0",
  "description": "An awesome plugin for PlexiChat",
  "author": "Your Name",
  "type": "feature",
  "entry_point": "main",
  "dependencies": ["core_system"],
  "permissions": ["plugin:read", "plugin:write"],
  "api_version": "1.0",
  "min_plexichat_version": "3.0.0",
  "enabled": true,
  "category": "utility",
  "tags": ["awesome", "example", "demo"],
  "homepage": "https://github.com/yourusername/my-awesome-plugin",
  "repository": "https://github.com/yourusername/my-awesome-plugin",
  "license": "MIT",
  "icon": "star",
  "ui_pages": [
    {
      "name": "dashboard",
      "path": "ui/dashboard",
      "title": "Awesome Dashboard",
      "description": "Main dashboard for the awesome plugin"
    }
  ],
  "api_endpoints": [
    "/api/v1/awesome/status",
    "/api/v1/awesome/action"
  ],
  "webhooks": [
    "awesome.event.triggered",
    "awesome.action.completed"
  ],
  "settings_schema": {
    "type": "object",
    "properties": {
      "enabled": {
        "type": "boolean",
        "default": true,
        "description": "Enable the awesome feature"
      },
      "interval": {
        "type": "integer",
        "minimum": 1,
        "maximum": 3600,
        "default": 60,
        "description": "Action interval in seconds"
      }
    },
    "required": ["enabled"]
  },
  "auto_start": true,
  "background_tasks": [
    "awesome_background_task"
  ]
}
```

3. **Create Main Plugin File**

Create `main.py`:

```python
import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ...infrastructure.modules.enhanced_plugin_manager import (
    PluginInterface, PluginType, PluginMetadata
)


class AwesomePlugin(PluginInterface):
    """Awesome Plugin for PlexiChat."""
    
    def __init__(self):
        super().__init__("AwesomePlugin", "1.0.0")
        self.plugin_type = PluginType.FEATURE
        
        # Plugin data directory
        self.data_dir = Path("data/plugins/my_awesome_plugin")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Configuration
        self.config = {
            "enabled": True,
            "interval": 60
        }
        
        # API router
        self.router = APIRouter(prefix="/api/v1/awesome", tags=["Awesome Plugin"])
        self._setup_routes()
        
        # Background task
        self.background_task = None
        
        # Statistics
        self.stats = {
            "actions_performed": 0,
            "last_action": None,
            "errors": 0
        }
    
    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        return PluginMetadata(
            name="my_awesome_plugin",
            version="1.0.0",
            description="An awesome plugin for PlexiChat",
            author="Your Name",
            plugin_type=PluginType.FEATURE,
            entry_point="main",
            dependencies=["core_system"],
            permissions=["plugin:read", "plugin:write"],
            api_version="1.0",
            min_plexichat_version="3.0.0",
            enabled=True,
            category="utility",
            tags=["awesome", "example", "demo"],
            homepage="https://github.com/yourusername/my-awesome-plugin",
            repository="https://github.com/yourusername/my-awesome-plugin",
            license="MIT",
            icon="star",
            ui_pages=[
                {"name": "dashboard", "path": "ui/dashboard", "title": "Awesome Dashboard"}
            ],
            api_endpoints=[
                "/api/v1/awesome/status",
                "/api/v1/awesome/action"
            ],
            webhooks=[
                "awesome.event.triggered",
                "awesome.action.completed"
            ],
            auto_start=True,
            background_tasks=["awesome_background_task"]
        )
    
    async def _plugin_initialize(self) -> bool:
        """Initialize the awesome plugin."""
        try:
            self.logger.info("Initializing Awesome Plugin")
            
            # Load configuration
            await self._load_configuration()
            
            # Start background task
            await self._start_background_task()
            
            # Register with main application
            if self.manager:
                app = getattr(self.manager, 'app', None)
                if app:
                    app.include_router(self.router)
                    self.logger.info("Awesome API routes registered")
                
                # Register UI pages
                await self._register_ui_pages()
            
            self.logger.info("Awesome Plugin initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Awesome Plugin initialization failed: {e}")
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
    
    async def _start_background_task(self):
        """Start background task."""
        self.background_task = asyncio.create_task(self.awesome_background_task())
    
    async def _register_ui_pages(self):
        """Register UI pages with the main application."""
        ui_dir = Path(__file__).parent / "ui"
        if ui_dir.exists():
            app = getattr(self.manager, 'app', None)
            if app:
                from fastapi.staticfiles import StaticFiles
                app.mount(f"/plugins/awesome/static", StaticFiles(directory=str(ui_dir / "static")), name="awesome_static")
    
    def _setup_routes(self):
        """Setup API routes."""
        
        @self.router.get("/status")
        async def get_status():
            """Get plugin status."""
            return {
                "status": "awesome",
                "enabled": self.config["enabled"],
                "stats": self.stats,
                "config": self.config
            }
        
        @self.router.post("/action")
        async def perform_action():
            """Perform an awesome action."""
            if not self.config["enabled"]:
                raise HTTPException(status_code=400, detail="Plugin is disabled")
            
            try:
                # Perform awesome action
                self.stats["actions_performed"] += 1
                self.stats["last_action"] = datetime.now(timezone.utc).isoformat()
                
                return {
                    "success": True,
                    "message": "Awesome action performed!",
                    "timestamp": self.stats["last_action"]
                }
            except Exception as e:
                self.stats["errors"] += 1
                self.logger.error(f"Action failed: {e}")
                raise HTTPException(status_code=500, detail="Action failed")
    
    async def awesome_background_task(self):
        """Background task for awesome functionality."""
        while True:
            try:
                if self.config["enabled"]:
                    # Perform periodic awesome task
                    self.logger.info("Performing awesome background task")
                    
                    # Update statistics
                    self.stats["last_action"] = datetime.now(timezone.utc).isoformat()
                
                await asyncio.sleep(self.config["interval"])
                
            except Exception as e:
                self.logger.error(f"Background task error: {e}")
                self.stats["errors"] += 1
                await asyncio.sleep(60)  # Wait before retry
    
    async def health_check(self) -> Dict[str, Any]:
        """Health check for the plugin."""
        return {
            "healthy": True,
            "stats": self.stats,
            "config": self.config,
            "background_task_running": self.background_task and not self.background_task.done()
        }
    
    async def cleanup(self):
        """Cleanup plugin resources."""
        if self.background_task:
            self.background_task.cancel()


# Plugin instance
plugin = AwesomePlugin()
```

## Plugin Structure

### Required Files

```
my_awesome_plugin/
├── plugin.json              # Plugin manifest
├── main.py                  # Main plugin file
├── ui/                      # UI components (optional)
│   ├── dashboard/
│   │   ├── index.html
│   │   ├── style.css
│   │   └── script.js
│   └── static/
│       ├── images/
│       └── assets/
├── tests/                   # Tests (optional)
│   ├── test_main.py
│   └── test_api.py
├── docs/                    # Documentation (optional)
│   ├── README.md
│   └── API.md
└── requirements.txt         # Dependencies (optional)
```

### Optional Files

- `requirements.txt`: Python dependencies
- `README.md`: Plugin documentation
- `CHANGELOG.md`: Version history
- `LICENSE`: License information
- `screenshots/`: Plugin screenshots
- `examples/`: Usage examples

## Plugin Interface

### Core Methods

#### `__init__()`
Initialize plugin instance and set up basic configuration.

#### `get_metadata() -> PluginMetadata`
Return plugin metadata. Must be implemented.

#### `initialize() -> bool`
Initialize plugin functionality. Must be implemented.

#### `shutdown() -> bool`
Clean up plugin resources when unloaded.

#### `health_check() -> Dict[str, Any]`
Return plugin health status.

### New Extension Points (v3+)

PlexiChat plugins can now extend the system in the following ways:

- Register CLI commands
- Register API/web routers
- Register database extensions (models, DAOs, adapters)
- Register security features (middleware, policies)
- Provide self-tests for automated validation

#### `get_routers() -> Dict[str, Any]`
Return a dictionary of routers to be registered, e.g. `{ "/myroute": router }`.

```python
def get_routers(self):
    from fastapi import APIRouter
    router = APIRouter()
    @router.get("/my-plugin/health")
    async def health():
        return {"status": "ok", "plugin": "my_plugin"}
    return {"/my-plugin": router}
```

#### `get_db_extensions() -> Dict[str, Any]`
Return a dictionary of database models, DAOs, or adapters to register.

```python
def get_db_extensions(self):
    # Example: return a fake model or DAO
    return {"my_plugin_model": object()}
```

#### `get_security_features() -> Dict[str, Any]`
Return a dictionary of security features (middleware, policies, etc.) to register.

```python
def get_security_features(self):
    def fake_middleware(request, call_next):
        return call_next(request)
    return {"my_plugin_middleware": fake_middleware}
```

#### `self_test() -> Dict[str, Any]`
Return a dictionary describing the results of plugin self-tests.

```python
async def self_test(self):
    return {"passed": True, "tests": ["cli commands", "routers", "db extensions", "security features"], "message": "All self-tests passed"}
```

See the `mega_cli` plugin for a comprehensive example of all extension points.

### Advanced Extension Points and Developer Ergonomics

PlexiChat plugins can now leverage a wide range of advanced extension points for deep integration and developer productivity:

- **Event Hooks**: Register pre/post hooks for any system event (startup, shutdown, user actions, etc.)
- **Custom Config Sections/Schemas**: Define and validate your own config sections for UI and runtime
- **Custom Health Checks**: Add readiness/liveness/health probes for your plugin
- **Custom Backup/Restore Handlers**: Integrate with the backup system for custom data
- **Custom Middleware**: Register middleware for web, API, or CLI
- **Plugin Context Object**: Access all core systems, config, and utilities via `self.context`
- **Helper Decorators**: Use `@on_event`, `@register_middleware`, `@register_backup_handler` for common patterns

#### Example: Using Advanced Extension Points

```python
from plexichat.core.plugins.manager import PluginInterface

class MyAdvancedPlugin(PluginInterface):
    def get_event_hooks(self):
        return {
            'startup': self.on_startup,
            'shutdown': self.on_shutdown
        }
    def get_config_schema(self):
        return {
            'type': 'object',
            'properties': {'my_setting': {'type': 'string', 'default': 'hi'}}
        }
    def get_health_checks(self):
        return {'ready': self.ready_check}
    def get_backup_handlers(self):
        return {'backup': self.backup_data, 'restore': self.restore_data}
    def get_middleware(self):
        return {'web': [self.web_middleware], 'api': [self.api_middleware]}
    @PluginInterface.on_event('startup')
    def on_startup(self):
        self.context.logger.info('Plugin started!')
    @PluginInterface.register_middleware('web')
    def web_middleware(self, request, call_next):
        # ...
        return call_next(request)
    @PluginInterface.register_backup_handler('backup')
    def backup_data(self):
        # ...
        pass
    def set_context(self, context):
        self.context = context
        # Now self.context.logger, self.context.analytics, etc. are available
```

#### Best Practices
- Always declare your extension points via the appropriate `get_*` methods
- Use the plugin context for all core system access
- Use decorators for event/middleware/backup registration for clarity
- Document your extension points in your plugin's README and manifest

See the full PluginInterface and PluginContext API for all available features.

### Configuration Management

```python
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

async def save_configuration(self, config: Dict[str, Any]):
    """Save plugin configuration."""
    config_file = self.data_dir / "config.json"
    config_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=2)
```

## API Integration

### Creating API Routes

```python
def _setup_routes(self):
    """Setup API routes."""
    
    @self.router.get("/status")
    async def get_status():
        """Get plugin status."""
        return {"status": "ok", "plugin": "awesome"}
    
    @self.router.post("/action")
    async def perform_action(data: Dict[str, Any]):
        """Perform plugin action."""
        # Validate input
        if not data.get("action"):
            raise HTTPException(status_code=400, detail="Action required")
        
        # Perform action
        result = await self._perform_action(data["action"])
        
        return {"success": True, "result": result}
```

### Error Handling

```python
from fastapi import HTTPException

@self.router.get("/data")
async def get_data():
    try:
        data = await self._fetch_data()
        return {"data": data}
    except Exception as e:
        self.logger.error(f"Failed to fetch data: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch data")
```

### Documenting Plugin APIs (OpenAPI)

To ensure your plugin's API surface is discoverable by developers and operators, follow these guidelines:

- Use FastAPI route docstrings and response models (Pydantic) to annotate request/response schemas.
- Add clear `tags` and `summary`/`description` metadata when creating routers and endpoints.
- Declare error responses and status codes using FastAPI's response_model and HTTPException patterns.
- Include example request/response bodies via `response_model` examples or docstrings.

If you want your plugin's endpoints to appear in the repository-level generated API reference, ensure your plugin's router is registered with the application's FastAPI app prior to exporting the OpenAPI schema (see "Accessing the Generated API Reference" below).

## UI Integration

### Creating UI Pages

1. **Create UI Directory Structure**

```
ui/
├── dashboard/
│   ├── index.html
│   ├── style.css
│   └── script.js
└── static/
    ├── images/
    └── assets/
```

2. **Register UI Pages**

```python
async def _register_ui_pages(self):
    """Register UI pages with the main application."""
    ui_dir = Path(__file__).parent / "ui"
    if ui_dir.exists():
        app = getattr(self.manager, 'app', None)
        if app:
            from fastapi.staticfiles import StaticFiles
            app.mount(f"/plugins/awesome/static", StaticFiles(directory=str(ui_dir / "static")), name="awesome_static")
```

3. **Create UI Components**

```html
<!-- ui/dashboard/index.html -->
<!DOCTYPE html>
<html>
<head>
    <title>Awesome Dashboard</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <h1>Awesome Dashboard</h1>
        <div id="status"></div>
        <button onclick="performAction()">Perform Action</button>
    </div>
    <script src="script.js"></script>
</body>
</html>
```

## Background Tasks

### Creating Background Tasks

```python
async def _start_background_task(self):
    """Start background task."""
    self.background_task = asyncio.create_task(self.awesome_background_task())

async def awesome_background_task(self):
    """Background task for awesome functionality."""
    while True:
        try:
            if self.config["enabled"]:
                # Perform periodic task
                await self._perform_periodic_task()
            
            await asyncio.sleep(self.config["interval"])
            
        except Exception as e:
            self.logger.error(f"Background task error: {e}")
            await asyncio.sleep(60)  # Wait before retry
```

### Task Management

```python
async def cleanup(self):
    """Cleanup plugin resources."""
    if self.background_task:
        self.background_task.cancel()
        try:
            await self.background_task
        except asyncio.CancelledError:
            pass
```

## Testing

### Unit Tests

```python
# tests/test_main.py
import pytest
from unittest.mock import Mock, patch
from main import AwesomePlugin

@pytest.fixture
def plugin():
    return AwesomePlugin()

@pytest.mark.asyncio
async def test_plugin_initialization(plugin):
    """Test plugin initialization."""
    result = await plugin._plugin_initialize()
    assert result == True
    assert plugin.config["enabled"] == True

@pytest.mark.asyncio
async def test_health_check(plugin):
    """Test health check."""
    health = await plugin.health_check()
    assert health["healthy"] == True
    assert "stats" in health
```

### Integration Tests

```python
# tests/test_api.py
import pytest
from fastapi.testclient import TestClient
from main import plugin

@pytest.fixture
def client():
    return TestClient(plugin.router)

def test_get_status(client):
    """Test status endpoint."""
    response = client.get("/status")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "awesome"
```

## Packaging and Distribution

### Creating Plugin Package

1. **Create ZIP Package**

```bash
cd plugins/my_awesome_plugin
zip -r my_awesome_plugin.zip . -x "*.pyc" "__pycache__/*" "*.git*"
```

2. **Install Plugin**

```bash
python dev/plugin_manager.py install my_awesome_plugin.zip
```

### Marketplace Distribution

1. **Prepare Plugin for Marketplace**

- Ensure all required files are included
- Add screenshots and documentation
- Test thoroughly
- Update version in `plugin.json`

2. **Submit to Marketplace**

```bash
# Package plugin
zip -r my_awesome_plugin_v1.0.0.zip . -x "*.pyc" "__pycache__/*" "*.git*"

# Upload to marketplace (via web interface)
```

## Best Practices

### Code Organization

1. **Separate Concerns**
   - Keep API routes separate from business logic
   - Use dedicated classes for different functionalities
   - Implement proper error handling

2. **Configuration Management**
   - Use schema validation for configuration
   - Provide sensible defaults
   - Support hot-reloading of configuration

3. **Error Handling**
   - Log errors with appropriate levels
   - Provide meaningful error messages
   - Implement graceful degradation

4. **Performance**
   - Use async/await for I/O operations
   - Implement caching where appropriate
   - Monitor resource usage

### Security

1. **Input Validation**
   - Validate all user inputs
   - Use Pydantic models for API requests
   - Sanitize data before processing

2. **Permission Management**
   - Request only necessary permissions
   - Implement proper access controls
   - Audit plugin actions

3. **Data Protection**
   - Encrypt sensitive data
   - Use secure communication protocols
   - Follow data retention policies

### Documentation

1. **Code Documentation**
   - Document all public methods
   - Include usage examples
   - Maintain up-to-date docstrings

2. **User Documentation**
   - Provide clear installation instructions
   - Include configuration examples
   - Document API endpoints

3. **API Documentation**
   - Use OpenAPI/Swagger annotations
   - Provide request/response examples
   - Document error codes

## Documentation & API Reference

This section explains how plugin developers can contribute to documentation, ensure their plugin APIs are included in the generated API reference, and how to preview and validate documentation locally. PlexiChat uses a reproducible documentation pipeline (MkDocs + OpenAPI generation) and standardized naming/linking conventions across the docs/ directory.

### Contributing Plugin Documentation

- Place plugin-specific docs under your plugin directory in a `docs/` folder (e.g., `plugins/my_plugin/docs/README.md`).
- Provide a clear `README.md` as the main entry point for plugin docs and add smaller topic files for configuration, API examples, and runbooks.
- To contribute plugin docs to the main repository documentation site:
  1. Prefer adding content under your plugin's folder and reference it from the central docs if required.
  2. If adding cross-repository documentation pages (central docs/), follow the repository naming conventions (see "Naming and Linking Conventions" below) and open a pull request.
  3. Include examples, code snippets, and any required assets in the plugin docs folder.
  4. Run local documentation build and lint steps (examples below) before submitting a PR.

Recommended contribution workflow:
1. Write or update docs in `plugins/<your_plugin>/docs/`.
2. Update any central index pages if necessary (open a PR).
3. Run the local docs build:
   - python3 scripts/dump_openapi.py
   - mkdocs build
4. Run markdown lint (if your project has it): `markdownlint` or project's configured linter.
5. Submit PR and request reviews from documentation maintainers.

### Naming and Linking Conventions

To keep documentation consistent and easy to maintain, follow these rules:

- Filenames for primary documentation pages use UPPERCASE_WITH_UNDERSCORES.md (e.g., GETTING_STARTED.md, PLUGIN_DEVELOPMENT.md, WAF_RULES.md).
- Use relative links inside the docs/ directory (for example, link to the API reference page with [API Reference](API.md)).
- For generated artifacts, reference files under the _generated/ folder (for example: [_generated/openapi.json](_generated/openapi.json) or use the rendered API Reference page).
- When referencing core docs from plugin docs, use consistent names (e.g., [SECURITY](SECURITY.md), [WAF Rules](WAF_RULES.md), [Incident Response](INCIDENT_RESPONSE.md)).
- Keep link targets relative (no absolute file-system paths) so documentation builds work in CI and locally.

### Accessing the Generated API Reference

PlexiChat's API reference is produced from the running FastAPI application's OpenAPI schema. The repository pipeline generates and places the schema at docs/_generated/openapi.json and the mkdocs pipeline renders it into the site.

To access or regenerate the generated API reference locally:

1. Ensure your development environment can import the application (and any plugins you want included).
2. If you want plugin endpoints included in the generated OpenAPI schema, ensure the plugin's router is registered with the application's FastAPI instance prior to dumping the schema. This typically means loading your plugin via the development plugin manager or ensuring plugin registration occurs when importing the app used by the dump script.
3. Run the OpenAPI dump script from the repository root:

```bash
python3 scripts/dump_openapi.py
```

This will write the schema to `docs/_generated/openapi.json` (the script will create the target directory if it does not exist).

4. You can view the raw JSON or run mkdocs to render the site:

```bash
mkdocs serve  # for local preview (serves the rendered site)
# or
mkdocs build  # produces a static site in site/
```

5. The human-facing API reference is at `docs/API.md`, and the generated, machine-readable schema is at `docs/_generated/openapi.json`. The MkDocs configuration is typically set up to render the OpenAPI content into the site during the build.

### Including Plugin APIs in Generated Schema

- The OpenAPI schema is built from the FastAPI app instance. For plugin routes to appear:
  - Register your plugin router(s) with the app before calling app.openapi().
  - If your plugin is only registered dynamically at runtime via the plugin manager, run the same registration steps in your local dump script environment so the schema includes your endpoints.
- Example approaches:
  - Start a lightweight script that imports the app, loads and registers your plugin (via plugin manager or manual import), then calls app.openapi() and writes the JSON.
  - Use the provided scripts/dump_openapi.py which imports the main app (src/plexichat/main.py) and calls app.openapi(). Adjust or extend it in development if you need to register plugins manually.
- Ensure Pydantic models and response models used by plugin endpoints are importable when the dump script runs.

### Local Preview & CI

- Local preview:
  - Run `python3 scripts/dump_openapi.py` to refresh the generated OpenAPI JSON.
  - Run `mkdocs serve` to preview the site at http://127.0.0.1:8000/.
- CI:
  - CI pipelines typically re-run the dump and build steps (scripts/dump_openapi.py and mkdocs build) so the generated docs match the latest code in the branch.
  - Add tests or checks to ensure plugin APIs expose proper schemas (for example, checking that critical endpoints are present in the generated openapi.json).
- If your plugin documentation or API changes, include instructions in your PR to the reviewers on how to regenerate and validate docs locally.

## Plugin Documentation Folders

Plugins can include a `docs` folder in their root directory. Any Markdown (`.md`) or HTML (`.html`) files in this folder will be automatically registered by the plugin loader and made available in the PlexiChat web UI's `/docs` page.

- Place all plugin-specific documentation in the `docs` folder inside your plugin directory.
- Supported formats: Markdown (`.md`), HTML (`.html`).
- The web UI `/docs` page is an interactive document viewer for all documentation, including core and plugin docs.
- Users can browse, search, and interact with all documentation from the web interface.

**Example plugin structure:**

```
plugins/
  my_plugin/
    main.py
    plugin.json
    docs/
      README.md
      USAGE.md
      API_REFERENCE.html
```

**Best practices:**
- Provide a `README.md` as the main entry point for your plugin docs.
- Use clear section headings and links for navigation.
- Keep documentation up to date with plugin features and CLI commands.
- Follow repository naming conventions for any content promoted to the central docs/ directory (UPPERCASE_WITH_UNDERSCORES.md).

This guide provides a comprehensive foundation for developing plugins for PlexiChat. Follow the best practices and examples to create robust, maintainable plugins that integrate seamlessly with the PlexiChat ecosystem. 

## Example: Mega CLI Plugin

The `mega_cli` plugin demonstrates all extension points:
- Registers 400+ CLI commands, each with a detailed help string (shown with --help)
- Adds a FastAPI router
- Adds a database extension
- Adds a security feature
- Provides a self-test method

### Plugin Docstring Example

```python
"""
mega_cli Plugin for PlexiChat

This plugin registers 400+ advanced CLI commands for power users, automation, and developers.

Features:
- Registers 400+ CLI commands, each with a --help option and detailed help string
- Demonstrates plugin extension points: CLI, routers, DB extensions, security features, and self-tests
- All commands are grouped by category (dev, net, sys, user, file, chat, ai, etc.)
- Each command is self-documenting and discoverable via --help
- See docs/PLUGIN_DEVELOPMENT.md for extension API details

Usage:
  plexichat mega <command> --help
  plexichat dev <command> --help
  plexichat net <command> --help
  ...
"""
```

### CLI Command Registration Example

```python
cmd = UltimateCommand(
    name="dev_cmd_1",
    description="Mega CLI: dev command #1 (from mega_cli plugin)\n\nUsage: plexichat dev dev_cmd_1 [OPTIONS]\n\nOptions:\n  --help    Show this help message and exit.\n\nThis command is provided by the mega_cli plugin.",
    category=CommandCategory.DEV,
    handler=handler,
    version_added="1.0.0",
    admin_only=False,
    dangerous=False,
    requires_auth=False,
)
ultimate_cli.register_command(cmd)
```

### Discoverability
- All plugin CLI commands are discoverable with `--help`.
- Plugin docstrings and command descriptions should be detailed for both users and developers. 

## Core System Integration for Plugins

Plugins can now easily integrate with all major PlexiChat systems:
- **Logging**: Request a logger via `get_services()` and use `self.logger` in your plugin.
- **Analytics**: Request analytics via `get_services()` and use `self.analytics`.
- **AI**: Request AI via `get_services()` and use `self.ai` (the main AI assistant) or `self.ai_provider` (the raw provider manager).
- **Database**: Request DB via `get_services()` and use `self.db`.
- **Backup**: Request backup via `get_services()` and use `self.backup`.
- **Security**: Request security via `get_services()` and use `self.security`.

### Declaring Service Dependencies

Override the `get_services()` method in your plugin class to declare which services you want:

```python
class MyPlugin(PluginInterface):
    def get_services(self):
        return {
            "logger": True,
            "analytics": True,
            "ai": True,
            "db": True,
            "backup": True,
            "security": True,
        }
```

### Using Injected Services

After your plugin is loaded, the requested services will be available as attributes:

```python
class MyPlugin(PluginInterface):
    def get_services(self):
        return {"logger": True, "ai": True}
    async def initialize(self):
        self.logger.info("MyPlugin initialized!")
        result = await self.ai.generate_content("Hello, AI!")
        # ...
```

### Advanced: Custom Logging and Analytics Hooks

You can also provide custom logging handlers or analytics hooks:

```python
class MyPlugin(PluginInterface):
    def register_logging_handlers(self):
        return {"myplugin": MyCustomHandler()}
    def register_analytics_hooks(self):
        return {"my_event": my_analytics_hook}
```

See the main plugin manager and interface for all available extension points.