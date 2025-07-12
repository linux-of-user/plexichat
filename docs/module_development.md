# PlexiChat Module Development Guide

Welcome to the PlexiChat Module Development Guide! This comprehensive guide covers the **new unified module system** with strict interfaces, automated validation, hot-reloading, and centralized configuration management.

## 🚀 What's New in the Unified Module System

- **Strict Interface Contracts**: Type-safe interfaces with automated validation
- **Hot-Reloading**: Update modules without system restart
- **Isolation**: Modules run in isolated environments for security
- **Unified Configuration**: Centralized, hot-reloadable configuration management
- **Performance Monitoring**: Real-time resource usage tracking
- **Security Validation**: Automated security scanning and permission management
- **Contract Validation**: Ensures modules meet quality and security standards

## Table of Contents

1. [Quick Start](#quick-start)
2. [Module Interfaces](#module-interfaces)
3. [Configuration System](#configuration-system)
4. [Contract Validation](#contract-validation)
5. [Hot-Reloading](#hot-reloading)
6. [Security & Permissions](#security--permissions)
7. [Best Practices](#best-practices)
8. [Examples](#examples)
9. [Testing](#testing)
10. [Migration Guide](#migration-guide)

## Quick Start

### 1. Create Your First Module

```python
from plexichat.infrastructure.modules.interfaces import (
    BaseModule, ModulePermissions, ModuleCapability
)

class MyAwesomeModule(BaseModule):
    def __init__(self, name: str = "MyAwesome", version: str = "1.0.0"):
        super().__init__(name, version)
        self.api_client = None

    async def initialize(self) -> bool:
        """Initialize your module - REQUIRED"""
        try:
            self.logger.info("MyAwesome module initializing...")

            # Get configuration from unified config system
            api_key = self.get_config_value("api_key")
            if not api_key:
                self.logger.error("API key not configured")
                return False

            # Setup your module
            self.api_client = SomeAPIClient(api_key)

            self.logger.info("MyAwesome module initialized successfully")
            return True
        except Exception as e:
            self.last_error = e
            self.logger.error(f"Initialization failed: {e}")
            return False

    def get_metadata(self) -> Dict[str, Any]:
        """Module metadata - REQUIRED"""
        return {
            "name": self.name,
            "version": self.version,
            "description": "My awesome PlexiChat module",
            "author": "Your Name",
            "license": "MIT"
        }

    def get_required_permissions(self) -> ModulePermissions:
        """Required permissions - REQUIRED"""
        return ModulePermissions(
            capabilities=[ModuleCapability.EXTERNAL_API],
            network_access=True,
            external_api_access=True
        )
```

### 2. Create Configuration Schema

Create `config/plugins/schemas/myawesome.json`:

```json
{
  "version": "1.0.0",
  "schema": {
    "type": "object",
    "properties": {
      "settings": {
        "type": "object",
        "properties": {
          "api_key": {
            "type": "string",
            "minLength": 1,
            "description": "API key for external service"
          },
          "timeout": {
            "type": "integer",
            "minimum": 1,
            "maximum": 300,
            "default": 30
          }
        },
        "required": ["api_key"]
      }
    }
  },
  "defaults": {
    "settings": {
      "timeout": 30,
      "debug": false
    }
  }
}
```

### 3. Create Configuration File

Create `config/plugins/myawesome.yaml`:

```yaml
metadata:
  name: "My Awesome Module"
  version: "1.0.0"
  description: "Does awesome things"
  author: "Your Name"

plugin:
  type: "feature"
  category: "integration"
  enabled: true
  auto_load: true

settings:
  api_key: "your-api-key-here"
  timeout: 30
  debug: false

permissions:
  required:
    - "network.access"
    - "external_api.access"
```

### Prerequisites

- Python 3.8+
- Understanding of async/await patterns
- Familiarity with type hints
- Basic knowledge of JSON Schema

### Development Environment Setup

1. Clone the PlexiChat repository
2. Install development dependencies: `pip install -r requirements-dev.txt`
3. Create your module directory: `plugins/your_module_name/`

## Module Interfaces

The unified module system uses strict interfaces to ensure consistency and reliability.

### Core Interface: BaseModule

All modules must inherit from `BaseModule`:

```python
from plexichat.infrastructure.modules.interfaces import BaseModule

class YourModule(BaseModule):
    def __init__(self, name: str = "YourModule", version: str = "1.0.0"):
        super().__init__(name, version)

    # Required methods
    async def initialize(self) -> bool: ...
    def get_metadata(self) -> Dict[str, Any]: ...
    def get_required_permissions(self) -> ModulePermissions: ...

    # Optional lifecycle methods
    async def start(self) -> bool: ...
    async def stop(self) -> bool: ...
    async def pause(self) -> bool: ...
    async def resume(self) -> bool: ...
    async def shutdown(self) -> bool: ...
    async def health_check(self) -> Dict[str, Any]: ...
```

### Module Capabilities

Declare what your module can do:

```python
from plexichat.infrastructure.modules.interfaces import ModuleCapability

# Core capabilities
ModuleCapability.MESSAGING          # Message handling
ModuleCapability.USER_MANAGEMENT     # User operations
ModuleCapability.FILE_HANDLING       # File operations
ModuleCapability.AUTHENTICATION      # Auth operations

# Advanced capabilities
ModuleCapability.AI_PROCESSING       # AI/ML operations
ModuleCapability.BACKUP_STORAGE      # Backup operations
ModuleCapability.SECURITY_SCANNING   # Security scans
ModuleCapability.ENCRYPTION          # Crypto operations

# UI capabilities
ModuleCapability.WEB_INTERFACE       # Web UI
ModuleCapability.API_ENDPOINTS       # REST API
ModuleCapability.ADMIN_PANEL         # Admin interface
```

### Permission System

Declare required permissions:

```python
def get_required_permissions(self) -> ModulePermissions:
    return ModulePermissions(
        capabilities=[
            ModuleCapability.MESSAGING,
            ModuleCapability.DATABASE_ACCESS
        ],
        network_access=True,           # Internet access
        file_system_access=False,      # File system access
        database_access=True,          # Database access
        admin_access=False,            # Admin privileges
        user_data_access=True,         # User data access
        external_api_access=True       # External API access
    )
```

## Module Structure

The new unified structure:

```
plugins/your_module_name/
├── main.py                  # Main module class (inherits BaseModule)
├── __init__.py              # Module initialization
├── api/                     # API endpoints (optional)
│   ├── __init__.py
│   └── routes.py
├── webui/                   # WebUI components (optional)
│   ├── templates/
│   └── static/
├── tasks/                   # Background tasks (optional)
│   └── background.py
└── tests/                   # Module tests
    └── test_module.py
```

Configuration is now managed centrally:

```
config/plugins/
├── schemas/                 # Configuration schemas
│   └── your_module.json
├── your_module.yaml         # Main configuration
└── environments/            # Environment-specific configs
    ├── development/
    │   └── your_module.yaml
    ├── testing/
    │   └── your_module.yaml
    └── production/
        └── your_module.yaml
```

## Configuration System

The unified configuration system provides hot-reloadable, validated configuration management.

### Configuration Schema

Define your configuration schema in `config/plugins/schemas/your_module.json`:

```json
{
  "version": "1.0.0",
  "schema": {
    "type": "object",
    "properties": {
      "metadata": {
        "type": "object",
        "properties": {
          "name": {"type": "string"},
          "version": {"type": "string"},
          "description": {"type": "string"}
        },
        "required": ["name", "version"]
      },
      "plugin": {
        "type": "object",
        "properties": {
          "type": {"type": "string", "enum": ["feature", "system", "ui"]},
          "enabled": {"type": "boolean", "default": true},
          "auto_load": {"type": "boolean", "default": true}
        }
      },
      "settings": {
        "type": "object",
        "properties": {
          "api_key": {"type": "string", "minLength": 1},
          "timeout": {"type": "integer", "minimum": 1, "default": 30},
          "debug": {"type": "boolean", "default": false}
        },
        "required": ["api_key"]
      }
    },
    "required": ["metadata", "plugin", "settings"]
  },
  "defaults": {
    "settings": {
      "timeout": 30,
      "debug": false
    }
  },
  "environment_overrides": {
    "development": {
      "settings": {
        "debug": true,
        "timeout": 60
      }
    },
    "production": {
      "settings": {
        "debug": false,
        "timeout": 30
      }
    }
  }
}
```

### Configuration File

Create `config/plugins/your_module.yaml`:

```yaml
metadata:
  name: "Your Module"
  version: "1.0.0"
  description: "Your module description"
  author: "Your Name"
  license: "MIT"

plugin:
  type: "feature"
  category: "integration"
  enabled: true
  auto_load: true
  main_file: "main.py"
  class_name: "YourModule"

settings:
  api_key: "your-api-key"
  timeout: 30
  debug: false
  custom_setting: "value"

permissions:
  required:
    - "network.access"
    - "database.read"
  optional:
    - "admin.access"

dependencies:
  python: ">=3.8"
  packages:
    - "requests>=2.25.0"
    - "aiohttp>=3.7.0"
```

### Accessing Configuration

In your module:

```python
class YourModule(BaseModule):
    async def initialize(self) -> bool:
        # Get configuration values
        api_key = self.get_config_value("api_key")
        timeout = self.get_config_value("timeout", default=30)
        debug = self.get_config_value("debug", default=False)

        # Get nested configuration
        custom_value = self.get_config_value("nested.setting.value")

        # Get entire configuration
        full_config = self.get_current_config()

        return True
```

### Hot Configuration Reload

Register for configuration changes:

```python
def __init__(self, name: str = "YourModule"):
    super().__init__(name)

    # Register for config changes
    self.register_event_handler("config_changed", self._on_config_changed)

async def _on_config_changed(self, event_data):
    """Handle configuration changes"""
    new_config = event_data.get("config", {})

    # Apply new configuration
    if self.validate_config(new_config):
        self.apply_config(new_config)
        self.logger.info("Configuration updated successfully")
    else:
        self.logger.error("Invalid configuration - keeping current settings")
```

## Contract Validation

All modules are automatically validated against strict contracts to ensure quality and security.

### Validation Categories

1. **Interface Compliance**: Implements required interfaces
2. **Method Signatures**: Correct method signatures and types
3. **Security Compliance**: Proper permission declarations
4. **Configuration Compliance**: Valid configuration schemas
5. **Performance Constraints**: Resource usage limits
6. **API Contracts**: Consistent API behavior
7. **Documentation**: Adequate documentation

### Running Validation

```python
# Manual validation
from plexichat.infrastructure.modules.contracts import get_contract_validator

async def validate_my_module():
    module = YourModule()
    validator = get_contract_validator()

    result = await validator.validate_module(module)

    print(f"Valid: {result.is_valid}")
    print(f"Score: {result.score:.1f}%")

    if result.violations:
        print("Errors:")
        for violation in result.violations:
            print(f"  - {violation.message}")

    if result.warnings:
        print("Warnings:")
        for warning in result.warnings:
            print(f"  - {warning.message}")

    # Generate detailed report
    report = validator.generate_compliance_report(result)
    print(report)
```

### Validation Results

```python
# Example validation result
{
    "is_valid": True,
    "score": 95.5,  # Compliance score 0-100
    "violations": [],  # Critical errors
    "warnings": [     # Non-critical issues
        {
            "severity": "warning",
            "category": "documentation",
            "message": "Method lacks documentation"
        }
    ]
}
```
│   └── background.py
├── models/                  # Data models (optional)
│   ├── __init__.py
│   └── schemas.py
├── utils/                   # Utility functions (optional)
│   ├── __init__.py
│   └── helpers.py
├── tests/                   # Unit tests
│   ├── __init__.py
│   └── test_module.py
└── README.md               # Module documentation
```

## Configuration

Every module must have a `config.yaml` file that defines its metadata and settings:

```yaml
# Module Information
module_name: "example_module"
module_version: "1.0.0"
module_description: "An example PlexiChat module"
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
  prefix: "/api/v1/example"
  rate_limit: 100  # requests per minute

# WebUI Configuration
webui:
  enabled: true
  menu_title: "Example Module"
  menu_icon: "fas fa-puzzle-piece"
  menu_order: 100

# Background Tasks
tasks:
  enabled: true
  schedule: "*/5 * * * *"  # Every 5 minutes

# Custom Settings
settings:
  debug: false
  log_level: "INFO"
  external_api_url: "https://api.example.com"
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
```

## API Reference

### Base Module Class

All modules must inherit from the `BaseModule` class:

```python
from plexichat.app.modules.base import BaseModule
from plexichat.app.modules.decorators import module_endpoint, module_task
from fastapi import APIRouter
import asyncio

class ExampleModule(BaseModule):
    def __init__(self, config: dict):
        super().__init__(config)
        self.router = APIRouter()
        self.setup_routes()
    
    async def initialize(self):
        """Initialize the module."""
        self.logger.info("Initializing Example Module")
        # Perform initialization tasks
        await self.setup_database()
        await self.start_background_tasks()
    
    async def shutdown(self):
        """Cleanup when module is stopped."""
        self.logger.info("Shutting down Example Module")
        # Cleanup tasks
        await self.stop_background_tasks()
    
    def setup_routes(self):
        """Setup API routes."""
        @self.router.get("/status")
        @module_endpoint(permissions=["read"])
        async def get_status():
            return {"status": "active", "version": self.config.module_version}
        
        @self.router.post("/action")
        @module_endpoint(permissions=["write"], rate_limit=10)
        async def perform_action(data: dict):
            # Perform some action
            return {"success": True, "message": "Action completed"}
    
    @module_task(schedule="*/10 * * * *")
    async def background_task(self):
        """Background task that runs every 10 minutes."""
        self.logger.info("Running background task")
        # Perform background work
```

### Module Decorators

PlexiChat provides several decorators to enhance module functionality:

#### `@module_endpoint`

Decorates API endpoints with additional functionality:

```python
@module_endpoint(
    permissions=["read", "write"],  # Required permissions
    rate_limit=60,                  # Requests per minute
    user_tiers=["premium", "admin"], # Required user tiers
    cache_ttl=300,                  # Cache response for 5 minutes
    validate_input=True             # Validate input data
)
async def my_endpoint():
    pass
```

#### `@module_task`

Decorates background tasks:

```python
@module_task(
    schedule="0 */6 * * *",  # Cron expression
    retry_count=3,           # Retry failed tasks
    timeout=300,             # Task timeout in seconds
    priority="high"          # Task priority
)
async def my_background_task():
    pass
```

#### `@module_event`

Decorates event handlers:

```python
@module_event("user.login")
async def on_user_login(event_data: dict):
    """Handle user login events."""
    pass
```

### Module Utilities

PlexiChat provides utility functions for common tasks:

```python
from plexichat.app.modules.utils import (
    get_user_tier,
    check_permissions,
    cache_result,
    send_notification,
    log_security_event
)

# Check user permissions
if await check_permissions(user, ["admin"]):
    # User has admin permissions
    pass

# Cache expensive operations
@cache_result(ttl=3600)
async def expensive_operation():
    # This result will be cached for 1 hour
    return complex_calculation()

# Send notifications
await send_notification(
    user_id=123,
    title="Module Alert",
    message="Something important happened",
    type="info"
)
```

## Best Practices

### 1. Configuration Management

- Use YAML for configuration files
- Provide sensible defaults
- Validate configuration on startup
- Support environment variable overrides

```python
def validate_config(self):
    """Validate module configuration."""
    required_fields = ["api_url", "api_key"]
    for field in required_fields:
        if field not in self.config.settings:
            raise ValueError(f"Missing required config field: {field}")
```

### 2. Error Handling

- Use structured logging
- Implement graceful degradation
- Provide meaningful error messages
- Handle network timeouts and retries

```python
import asyncio
from tenacity import retry, stop_after_attempt, wait_exponential

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=4, max=10)
)
async def api_call(self, endpoint: str):
    """Make API call with retry logic."""
    try:
        async with self.http_client.get(endpoint) as response:
            if response.status == 200:
                return await response.json()
            else:
                raise Exception(f"API error: {response.status}")
    except asyncio.TimeoutError:
        self.logger.warning(f"Timeout calling {endpoint}")
        raise
    except Exception as e:
        self.logger.error(f"Error calling {endpoint}: {e}")
        raise
```

### 3. Security

- Validate all input data
- Use parameterized queries for database operations
- Implement proper authentication and authorization
- Log security-relevant events

```python
from pydantic import BaseModel, validator
from plexichat.app.security.validators import sanitize_input

class UserInput(BaseModel):
    name: str
    email: str
    
    @validator('name')
    def validate_name(cls, v):
        return sanitize_input(v, max_length=100)
    
    @validator('email')
    def validate_email(cls, v):
        if '@' not in v:
            raise ValueError('Invalid email format')
        return v.lower()
```

### 4. Performance

- Use async/await for I/O operations
- Implement caching for expensive operations
- Use connection pooling for external services
- Monitor resource usage

```python
import aioredis
from plexichat.app.cache import cache_manager

class ExampleModule(BaseModule):
    async def initialize(self):
        # Setup connection pools
        self.redis_pool = aioredis.ConnectionPool.from_url(
            "redis://localhost:6379",
            max_connections=10
        )
        self.redis = aioredis.Redis(connection_pool=self.redis_pool)
    
    @cache_manager.cached(ttl=3600)
    async def get_cached_data(self, key: str):
        """Get data with caching."""
        return await self.fetch_from_external_api(key)
```

### 5. Testing

- Write comprehensive unit tests
- Use pytest for testing framework
- Mock external dependencies
- Test error conditions

```python
import pytest
from unittest.mock import AsyncMock, patch
from your_module.module import ExampleModule

@pytest.fixture
async def module():
    config = {
        "module_name": "test_module",
        "settings": {"api_url": "http://test.com"}
    }
    module = ExampleModule(config)
    await module.initialize()
    yield module
    await module.shutdown()

@pytest.mark.asyncio
async def test_api_endpoint(module):
    """Test API endpoint."""
    with patch.object(module, 'external_api_call', new_callable=AsyncMock) as mock_api:
        mock_api.return_value = {"status": "success"}
        
        result = await module.process_request({"test": "data"})
        
        assert result["success"] is True
        mock_api.assert_called_once()

@pytest.mark.asyncio
async def test_error_handling(module):
    """Test error handling."""
    with patch.object(module, 'external_api_call', side_effect=Exception("API Error")):
        with pytest.raises(Exception):
            await module.process_request({"test": "data"})
```

## Examples

### Simple API Module

```python
# modules/weather/module.py
from plexichat.app.modules.base import BaseModule
from plexichat.app.modules.decorators import module_endpoint
from fastapi import APIRouter, HTTPException
import aiohttp

class WeatherModule(BaseModule):
    def __init__(self, config: dict):
        super().__init__(config)
        self.router = APIRouter()
        self.setup_routes()
        self.api_key = config.settings.get("api_key")
    
    def setup_routes(self):
        @self.router.get("/weather/{city}")
        @module_endpoint(permissions=["read"], rate_limit=30)
        async def get_weather(city: str):
            """Get weather for a city."""
            if not self.api_key:
                raise HTTPException(status_code=500, detail="API key not configured")
            
            url = f"http://api.openweathermap.org/data/2.5/weather"
            params = {"q": city, "appid": self.api_key, "units": "metric"}
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        return {
                            "city": data["name"],
                            "temperature": data["main"]["temp"],
                            "description": data["weather"][0]["description"]
                        }
                    else:
                        raise HTTPException(status_code=404, detail="City not found")
```

### Background Task Module

```python
# modules/cleanup/module.py
from plexichat.app.modules.base import BaseModule
from plexichat.app.modules.decorators import module_task
import asyncio
import os
from pathlib import Path

class CleanupModule(BaseModule):
    def __init__(self, config: dict):
        super().__init__(config)
        self.temp_dir = Path(config.settings.get("temp_dir", "/tmp"))
        self.max_age_days = config.settings.get("max_age_days", 7)
    
    @module_task(schedule="0 2 * * *")  # Run daily at 2 AM
    async def cleanup_temp_files(self):
        """Clean up old temporary files."""
        self.logger.info("Starting temp file cleanup")
        
        count = 0
        for file_path in self.temp_dir.rglob("*"):
            if file_path.is_file():
                age_days = (time.time() - file_path.stat().st_mtime) / 86400
                if age_days > self.max_age_days:
                    try:
                        file_path.unlink()
                        count += 1
                    except Exception as e:
                        self.logger.warning(f"Failed to delete {file_path}: {e}")
        
        self.logger.info(f"Cleaned up {count} temporary files")
```

## Testing

Create comprehensive tests for your modules:

```bash
# Run module tests
pytest src/plexichat/modules/your_module/tests/

# Run with coverage
pytest --cov=src/plexichat/modules/your_module src/plexichat/modules/your_module/tests/

# Run integration tests
pytest tests/integration/test_your_module.py
```

## Deployment

### Development Deployment

1. Place your module in `src/plexichat/modules/your_module_name/`
2. Restart PlexiChat to load the module
3. Check logs for any initialization errors

### Production Deployment

1. Package your module as a ZIP file
2. Use the Module Management API to upload and install
3. Configure the module through the WebUI
4. Enable and start the module

### Module Packaging

Create a `setup.py` for your module:

```python
from setuptools import setup, find_packages

setup(
    name="plexichat-your-module",
    version="1.0.0",
    description="Your PlexiChat module description",
    author="Your Name",
    author_email="your.email@example.com",
    packages=find_packages(),
    install_requires=[
        "plexichat>=3.0.0",
        # Add your dependencies here
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.8",
    ],
)
```

## Advanced Topics

### Database Integration

```python
from plexichat.app.database import get_database
from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class ModuleData(Base):
    __tablename__ = "module_data"
    
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    value = Column(String(500))
    created_at = Column(DateTime, default=datetime.utcnow)

class DatabaseModule(BaseModule):
    async def initialize(self):
        self.db = await get_database()
        # Create tables
        Base.metadata.create_all(bind=self.db.engine)
```

### WebUI Integration

```python
# modules/your_module/webui/routes.py
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory="modules/your_module/webui/templates")
router = APIRouter()

@router.get("/dashboard", response_class=HTMLResponse)
async def module_dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "title": "Your Module Dashboard"
    })
```

### Event System Integration

```python
from plexichat.app.events import event_manager

class EventModule(BaseModule):
    async def initialize(self):
        # Subscribe to events
        event_manager.subscribe("user.login", self.on_user_login)
        event_manager.subscribe("message.sent", self.on_message_sent)
    
    async def on_user_login(self, event_data: dict):
        """Handle user login events."""
        user_id = event_data.get("user_id")
        self.logger.info(f"User {user_id} logged in")
    
    async def emit_custom_event(self, data: dict):
        """Emit custom events."""
        await event_manager.emit("module.custom_event", data)
```

## Troubleshooting

### Common Issues

1. **Module not loading**: Check configuration syntax and required dependencies
2. **API endpoints not accessible**: Verify permissions and authentication
3. **Background tasks not running**: Check cron expression syntax
4. **Database errors**: Ensure proper database configuration and permissions

### Debugging

Enable debug logging in your module configuration:

```yaml
settings:
  debug: true
  log_level: "DEBUG"
```

Use the PlexiChat debugging tools:

```python
from plexichat.app.debug import debug_manager

# Add debug breakpoint
await debug_manager.breakpoint("module_name", "function_name", locals())

# Log debug information
debug_manager.log_state("module_name", {"variable": value})
```

## Support

- Documentation: [PlexiChat Docs](https://docs.plexichat.dev)
- Community: [PlexiChat Discord](https://discord.gg/plexichat)
- Issues: [GitHub Issues](https://github.com/plexichat/plexichat/issues)
- Examples: [Module Examples Repository](https://github.com/plexichat/module-examples)

Happy module development! 🚀
