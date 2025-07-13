# PlexiChat Plugin Development Guide

Learn how to create, deploy, and manage custom plugins for PlexiChat to extend functionality and integrate with external services.

## Table of Contents

1. [Plugin System Overview](#plugin-system-overview)
2. [Plugin Architecture](#plugin-architecture)
3. [Creating Your First Plugin](#creating-your-first-plugin)
4. [Plugin API Reference](#plugin-api-reference)
5. [Advanced Features](#advanced-features)
6. [Security Considerations](#security-considerations)
7. [Testing Plugins](#testing-plugins)
8. [Publishing Plugins](#publishing-plugins)
9. [Plugin Examples](#plugin-examples)

## Plugin System Overview

PlexiChat's plugin system allows developers to extend functionality through a secure, sandboxed environment. Plugins can:

- Add new API endpoints
- Process messages and files
- Integrate with external services
- Provide custom UI components
- Implement custom authentication providers
- Add new AI capabilities

### Plugin Types

1. **Message Processors**: Process incoming/outgoing messages
2. **File Handlers**: Handle file uploads and processing
3. **API Extensions**: Add new REST API endpoints
4. **UI Components**: Custom web interface elements
5. **Authentication Providers**: Custom auth methods
6. **AI Providers**: Custom AI model integrations
7. **Notification Handlers**: Custom notification channels

### Plugin Lifecycle

```
Development → Testing → Packaging → Publishing → Installation → Activation
```

## Plugin Architecture

### Plugin Structure

```
my-plugin/
├── plugin.yaml           # Plugin manifest
├── __init__.py           # Plugin entry point
├── handlers/             # Event handlers
│   ├── __init__.py
│   ├── message_handler.py
│   └── file_handler.py
├── api/                  # API endpoints
│   ├── __init__.py
│   └── routes.py
├── ui/                   # UI components
│   ├── components/
│   └── static/
├── config/               # Configuration schemas
│   └── settings.yaml
├── tests/                # Plugin tests
│   └── test_plugin.py
├── requirements.txt      # Dependencies
└── README.md            # Documentation
```

### Plugin Manifest (plugin.yaml)

```yaml
# plugin.yaml
name: "my-awesome-plugin"
version: "1.0.0"
description: "An awesome plugin for PlexiChat"
author: "Your Name"
email: "your.email@example.com"
license: "MIT"
homepage: "https://github.com/yourname/my-awesome-plugin"

# PlexiChat compatibility
plexichat_version: ">=a.1.1-1"
api_version: "v1"

# Plugin metadata
category: "productivity"
tags: ["automation", "integration", "productivity"]
icon: "plugin-icon.png"

# Plugin configuration
config_schema: "config/settings.yaml"
permissions:
  - "messages.read"
  - "messages.write"
  - "files.read"
  - "api.create_endpoints"

# Entry points
entry_points:
  message_handlers:
    - "handlers.message_handler:MessageHandler"
  file_handlers:
    - "handlers.file_handler:FileHandler"
  api_routes:
    - "api.routes:router"

# Dependencies
dependencies:
  - "requests>=2.25.0"
  - "pydantic>=1.8.0"

# Optional features
features:
  web_ui: true
  background_tasks: true
  database_access: false
  external_api: true
```

## Creating Your First Plugin

### 1. Plugin Template

```python
# __init__.py
from plexichat.plugins import Plugin, PluginMeta
from .handlers.message_handler import MessageHandler
from .api.routes import router

class MyAwesomePlugin(Plugin):
    """My awesome PlexiChat plugin."""
    
    def __init__(self):
        super().__init__()
        self.message_handler = MessageHandler()
    
    async def on_load(self):
        """Called when plugin is loaded."""
        self.logger.info("My Awesome Plugin loaded!")
        
        # Register message handler
        self.register_message_handler(self.message_handler)
        
        # Register API routes
        self.register_api_routes("/my-plugin", router)
    
    async def on_unload(self):
        """Called when plugin is unloaded."""
        self.logger.info("My Awesome Plugin unloaded!")
    
    async def on_enable(self):
        """Called when plugin is enabled."""
        self.logger.info("My Awesome Plugin enabled!")
    
    async def on_disable(self):
        """Called when plugin is disabled."""
        self.logger.info("My Awesome Plugin disabled!")

# Plugin metadata
__plugin__ = PluginMeta(
    name="my-awesome-plugin",
    version="1.0.0",
    description="An awesome plugin for PlexiChat",
    author="Your Name",
    plugin_class=MyAwesomePlugin
)
```

### 2. Message Handler

```python
# handlers/message_handler.py
from plexichat.plugins import MessageHandler as BaseMessageHandler
from plexichat.core.events import MessageEvent

class MessageHandler(BaseMessageHandler):
    """Handle incoming messages."""
    
    async def on_message_received(self, event: MessageEvent):
        """Process incoming messages."""
        message = event.message
        
        # Check if message contains a trigger word
        if "!weather" in message.content:
            # Get weather information
            weather_info = await self.get_weather(message.content)
            
            # Send response
            await self.send_message(
                channel_id=message.channel_id,
                content=f"Weather: {weather_info}",
                reply_to=message.id
            )
    
    async def on_message_sent(self, event: MessageEvent):
        """Process outgoing messages."""
        # Log sent messages
        self.logger.info(f"Message sent: {event.message.id}")
    
    async def get_weather(self, query: str) -> str:
        """Get weather information from external API."""
        # Extract location from query
        location = query.replace("!weather", "").strip()
        
        # Call weather API (example)
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"https://api.weather.com/v1/current?location={location}"
            ) as response:
                data = await response.json()
                return f"{data['temperature']}°C, {data['description']}"
```

### 3. API Routes

```python
# api/routes.py
from fastapi import APIRouter, Depends
from plexichat.plugins import get_current_user, require_permission
from pydantic import BaseModel

router = APIRouter()

class WeatherRequest(BaseModel):
    location: str

class WeatherResponse(BaseModel):
    temperature: float
    description: str
    location: str

@router.get("/weather/{location}")
async def get_weather(
    location: str,
    user = Depends(get_current_user)
):
    """Get weather for a location."""
    # Your weather logic here
    return WeatherResponse(
        temperature=22.5,
        description="Sunny",
        location=location
    )

@router.post("/weather")
@require_permission("weather.create")
async def create_weather_alert(
    request: WeatherRequest,
    user = Depends(get_current_user)
):
    """Create a weather alert."""
    # Your alert logic here
    return {"message": f"Weather alert created for {request.location}"}

@router.get("/stats")
async def get_plugin_stats(user = Depends(get_current_user)):
    """Get plugin usage statistics."""
    return {
        "requests_handled": 1234,
        "active_alerts": 5,
        "uptime": "7 days"
    }
```

### 4. Configuration Schema

```yaml
# config/settings.yaml
type: object
properties:
  api_key:
    type: string
    description: "Weather API key"
    required: true
  
  default_location:
    type: string
    description: "Default location for weather queries"
    default: "New York"
  
  temperature_unit:
    type: string
    enum: ["celsius", "fahrenheit"]
    description: "Temperature unit"
    default: "celsius"
  
  enable_alerts:
    type: boolean
    description: "Enable weather alerts"
    default: true
  
  alert_threshold:
    type: number
    description: "Temperature threshold for alerts"
    default: 30.0
```

## Plugin API Reference

### Base Plugin Class

```python
from plexichat.plugins import Plugin

class MyPlugin(Plugin):
    # Plugin lifecycle methods
    async def on_load(self): pass
    async def on_unload(self): pass
    async def on_enable(self): pass
    async def on_disable(self): pass
    
    # Configuration
    def get_config(self, key: str, default=None): pass
    def set_config(self, key: str, value): pass
    
    # Logging
    self.logger.info("Message")
    self.logger.error("Error")
    
    # Database access (if permitted)
    async def get_db_session(self): pass
    
    # Message operations
    async def send_message(self, channel_id: str, content: str): pass
    async def edit_message(self, message_id: str, content: str): pass
    async def delete_message(self, message_id: str): pass
    
    # File operations
    async def upload_file(self, file_path: str, channel_id: str): pass
    async def download_file(self, file_id: str): pass
    
    # User operations
    async def get_user(self, user_id: str): pass
    async def get_current_user(self): pass
    
    # Channel operations
    async def get_channel(self, channel_id: str): pass
    async def create_channel(self, name: str): pass
    
    # Event registration
    def register_message_handler(self, handler): pass
    def register_file_handler(self, handler): pass
    def register_api_routes(self, prefix: str, router): pass
```

### Event Handlers

```python
from plexichat.plugins import MessageHandler, FileHandler
from plexichat.core.events import MessageEvent, FileEvent

class MyMessageHandler(MessageHandler):
    async def on_message_received(self, event: MessageEvent): pass
    async def on_message_sent(self, event: MessageEvent): pass
    async def on_message_edited(self, event: MessageEvent): pass
    async def on_message_deleted(self, event: MessageEvent): pass

class MyFileHandler(FileHandler):
    async def on_file_uploaded(self, event: FileEvent): pass
    async def on_file_downloaded(self, event: FileEvent): pass
    async def on_file_deleted(self, event: FileEvent): pass
```

### Decorators

```python
from plexichat.plugins import (
    require_permission,
    rate_limit,
    cache_result,
    background_task
)

@require_permission("messages.write")
async def send_message(): pass

@rate_limit(requests=10, window=60)  # 10 requests per minute
async def api_endpoint(): pass

@cache_result(ttl=300)  # Cache for 5 minutes
async def expensive_operation(): pass

@background_task
async def long_running_task(): pass
```

## Advanced Features

### Database Access

```python
# If database_access permission is granted
class MyPlugin(Plugin):
    async def store_data(self, key: str, value: dict):
        async with self.get_db_session() as session:
            # Use SQLAlchemy session
            result = await session.execute(
                "INSERT INTO plugin_data (key, value) VALUES (:key, :value)",
                {"key": key, "value": json.dumps(value)}
            )
            await session.commit()
    
    async def get_data(self, key: str):
        async with self.get_db_session() as session:
            result = await session.execute(
                "SELECT value FROM plugin_data WHERE key = :key",
                {"key": key}
            )
            row = result.fetchone()
            return json.loads(row[0]) if row else None
```

### Background Tasks

```python
import asyncio
from plexichat.plugins import background_task

class MyPlugin(Plugin):
    async def on_enable(self):
        # Start background task
        self.task = asyncio.create_task(self.background_worker())
    
    async def on_disable(self):
        # Stop background task
        if hasattr(self, 'task'):
            self.task.cancel()
    
    @background_task
    async def background_worker(self):
        """Background task that runs periodically."""
        while True:
            try:
                # Do background work
                await self.process_pending_items()
                await asyncio.sleep(60)  # Wait 1 minute
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Background task error: {e}")
                await asyncio.sleep(60)
```

### Custom UI Components

```python
# ui/components/weather_widget.py
from plexichat.plugins.ui import UIComponent

class WeatherWidget(UIComponent):
    template = "weather_widget.html"
    
    async def get_context(self, request):
        """Get context data for the template."""
        location = request.query_params.get("location", "New York")
        weather_data = await self.get_weather(location)
        
        return {
            "weather": weather_data,
            "location": location
        }
    
    async def handle_action(self, action: str, data: dict):
        """Handle UI actions."""
        if action == "refresh":
            return await self.get_weather(data["location"])
        elif action == "set_alert":
            return await self.create_alert(data)
```

### External API Integration

```python
import aiohttp
from plexichat.plugins import external_api

class MyPlugin(Plugin):
    @external_api
    async def call_external_service(self, endpoint: str, data: dict):
        """Make external API calls with automatic retry and error handling."""
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"https://api.example.com/{endpoint}",
                json=data,
                headers={"Authorization": f"Bearer {self.get_config('api_key')}"}
            ) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    raise Exception(f"API error: {response.status}")
```

## Security Considerations

### Permission System

Plugins must declare required permissions in their manifest:

```yaml
permissions:
  - "messages.read"      # Read messages
  - "messages.write"     # Send messages
  - "files.read"         # Read files
  - "files.write"        # Upload files
  - "users.read"         # Read user data
  - "channels.read"      # Read channel data
  - "channels.write"     # Create/modify channels
  - "api.create_endpoints"  # Create API endpoints
  - "database.access"    # Database access
  - "external.api"       # External API calls
  - "system.admin"       # Admin functions
```

### Sandboxing

Plugins run in a sandboxed environment with:

- Limited file system access
- Network restrictions
- Memory limits
- CPU limits
- API rate limiting

### Input Validation

```python
from pydantic import BaseModel, validator

class PluginInput(BaseModel):
    message: str
    location: str
    
    @validator('message')
    def validate_message(cls, v):
        if len(v) > 1000:
            raise ValueError('Message too long')
        return v
    
    @validator('location')
    def validate_location(cls, v):
        # Validate location format
        if not v.replace(' ', '').isalpha():
            raise ValueError('Invalid location')
        return v
```

## Testing Plugins

### Unit Tests

```python
# tests/test_plugin.py
import pytest
from unittest.mock import AsyncMock
from plexichat.plugins.testing import PluginTestCase
from my_plugin import MyAwesomePlugin

class TestMyAwesomePlugin(PluginTestCase):
    async def test_plugin_load(self):
        """Test plugin loading."""
        plugin = MyAwesomePlugin()
        await plugin.on_load()
        
        assert plugin.is_loaded
        assert len(plugin.message_handlers) > 0
    
    async def test_weather_command(self):
        """Test weather command handling."""
        plugin = MyAwesomePlugin()
        handler = plugin.message_handler
        
        # Mock external API
        handler.get_weather = AsyncMock(return_value="22°C, Sunny")
        
        # Create test message event
        event = self.create_message_event(
            content="!weather New York",
            channel_id="test_channel"
        )
        
        # Process message
        await handler.on_message_received(event)
        
        # Verify response was sent
        self.assert_message_sent(
            channel_id="test_channel",
            content="Weather: 22°C, Sunny"
        )
```

### Integration Tests

```python
# tests/test_integration.py
import pytest
from plexichat.testing import PlexiChatTestClient

@pytest.mark.asyncio
async def test_plugin_api_integration():
    """Test plugin API integration."""
    async with PlexiChatTestClient() as client:
        # Install plugin
        await client.plugins.install("my-awesome-plugin")
        
        # Test API endpoint
        response = await client.get("/api/v1/plugins/my-plugin/weather/New York")
        assert response.status_code == 200
        
        data = response.json()
        assert "temperature" in data
        assert "description" in data
```

### Running Tests

```bash
# Run plugin tests
python -m pytest tests/

# Run with coverage
python -m pytest tests/ --cov=my_plugin

# Run integration tests
python -m pytest tests/test_integration.py --integration
```

## Publishing Plugins

### 1. Package Plugin

```bash
# Create plugin package
python -m plexichat.plugins.cli package my-plugin/

# This creates: my-awesome-plugin-1.0.0.plx
```

### 2. Plugin Registry

```bash
# Login to plugin registry
plexichat-plugins login

# Publish plugin
plexichat-plugins publish my-awesome-plugin-1.0.0.plx

# Update plugin
plexichat-plugins update my-awesome-plugin --version 1.0.1
```

### 3. Plugin Store

Plugins can be published to the PlexiChat Plugin Store for easy discovery and installation.

## Plugin Examples

### 1. GitHub Integration Plugin

```python
# GitHub webhook handler
class GitHubPlugin(Plugin):
    async def on_load(self):
        self.register_api_routes("/github", github_router)
    
    @webhook_handler("/github/webhook")
    async def handle_github_webhook(self, payload: dict):
        if payload["action"] == "opened" and "pull_request" in payload:
            pr = payload["pull_request"]
            await self.send_message(
                channel_id=self.get_config("notifications_channel"),
                content=f"New PR: {pr['title']} by {pr['user']['login']}"
            )
```

### 2. AI Translation Plugin

```python
# Translation plugin using AI
class TranslationPlugin(Plugin):
    async def on_message_received(self, event: MessageEvent):
        if event.message.content.startswith("!translate"):
            text = event.message.content[10:].strip()
            translated = await self.translate_text(text, "en")
            
            await self.send_message(
                channel_id=event.message.channel_id,
                content=f"Translation: {translated}",
                reply_to=event.message.id
            )
    
    async def translate_text(self, text: str, target_lang: str) -> str:
        # Use AI provider for translation
        response = await self.ai_provider.translate(
            text=text,
            target_language=target_lang
        )
        return response.translated_text
```

### 3. Backup Plugin

```python
# Automated backup plugin
class BackupPlugin(Plugin):
    async def on_enable(self):
        # Schedule daily backups
        self.schedule_task(self.daily_backup, cron="0 2 * * *")
    
    @background_task
    async def daily_backup(self):
        """Perform daily backup."""
        backup_id = await self.create_backup()
        
        # Upload to cloud storage
        await self.upload_backup_to_cloud(backup_id)
        
        # Notify admin
        await self.send_message(
            channel_id=self.get_config("admin_channel"),
            content=f"Daily backup completed: {backup_id}"
        )
```

---

This guide provides everything you need to create powerful plugins for PlexiChat. Start with simple message handlers and gradually add more advanced features as needed.
