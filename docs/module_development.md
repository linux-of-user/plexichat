# PlexiChat Module Development Guide

Welcome to the PlexiChat Module Development Guide! This comprehensive guide will help you create powerful, flexible modules for the PlexiChat platform.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Module Structure](#module-structure)
3. [Configuration](#configuration)
4. [API Reference](#api-reference)
5. [Best Practices](#best-practices)
6. [Examples](#examples)
7. [Testing](#testing)
8. [Deployment](#deployment)

## Getting Started

PlexiChat modules are Python packages that extend the core functionality of PlexiChat. They can add new API endpoints, WebUI components, background tasks, and integrate with external services.

### Prerequisites

- Python 3.8+
- Basic understanding of FastAPI
- Familiarity with async/await patterns
- Understanding of YAML configuration

### Development Environment Setup

1. Clone the PlexiChat repository
2. Install development dependencies: `pip install -r requirements-dev.txt`
3. Create your module directory: `src/plexichat/modules/your_module_name/`

## Module Structure

A PlexiChat module follows a standardized structure:

```
your_module_name/
├── __init__.py              # Module initialization
├── config.yaml              # Module configuration
├── module.py                # Main module class
├── api/                     # API endpoints (optional)
│   ├── __init__.py
│   └── routes.py
├── webui/                   # WebUI components (optional)
│   ├── __init__.py
│   ├── templates/
│   └── static/
├── tasks/                   # Background tasks (optional)
│   ├── __init__.py
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
