# PlexiChat Plugin SDK Documentation

## 🚀 Complete Plugin Development Guide

### Table of Contents
1. [Getting Started](#getting-started)
2. [Plugin Architecture](#plugin-architecture)
3. [Plugin Types](#plugin-types)
4. [Development Environment](#development-environment)
5. [API Reference](#api-reference)
6. [Examples](#examples)
7. [Testing](#testing)
8. [Publishing](#publishing)

## Getting Started

### Prerequisites
- Python 3.8+
- PlexiChat development environment
- Basic understanding of Python and async programming

### Quick Start
```bash
# Create a new plugin
python run.py plugin create my-awesome-plugin

# Install plugin dependencies
cd plugins/my-awesome-plugin
pip install -r requirements.txt

# Test your plugin
python run.py plugin test my-awesome-plugin

# Install plugin
python run.py plugin install my-awesome-plugin
```

## Plugin Architecture

### Plugin Structure
```
plugins/
└── my-awesome-plugin/
    ├── plugin.json          # Plugin metadata
    ├── __init__.py         # Plugin entry point
    ├── main.py             # Main plugin logic
    ├── requirements.txt    # Dependencies
    ├── README.md          # Documentation
    ├── assets/            # Static files
    │   ├── icons/
    │   └── templates/
    ├── tests/             # Unit tests
    │   └── test_plugin.py
    └── config/            # Configuration files
        └── default.json
```

### Plugin Metadata (plugin.json)
```json
{
  "name": "my-awesome-plugin",
  "version": "1.0.0",
  "description": "An awesome plugin for PlexiChat",
  "author": "Your Name",
  "email": "your.email@example.com",
  "license": "MIT",
  "type": "ai_provider",
  "category": "productivity",
  "tags": ["ai", "chat", "automation"],
  "plexichat_version": ">=1.0.0",
  "python_version": ">=3.8",
  "dependencies": {
    "requests": ">=2.25.0",
    "asyncio": ">=3.4.3"
  },
  "permissions": [
    "network_access",
    "file_system_read",
    "user_data_access"
  ],
  "entry_point": "main:AwesomePlugin",
  "config_schema": {
    "api_key": {
      "type": "string",
      "required": true,
      "description": "API key for the service"
    },
    "timeout": {
      "type": "integer",
      "default": 30,
      "description": "Request timeout in seconds"
    }
  },
  "ui_components": {
    "settings_panel": "ui/settings.html",
    "dashboard_widget": "ui/widget.html"
  },
  "api_endpoints": [
    {
      "path": "/api/v1/awesome",
      "method": "GET",
      "handler": "api_handler"
    }
  ]
}
```

## Plugin Types

### 1. AI Provider Plugins
```python
from plexichat.core.plugins.base import AIProviderPlugin

class MyAIProvider(AIProviderPlugin):
    def __init__(self):
        super().__init__()
        self.name = "My AI Provider"
        self.version = "1.0.0"
    
    async def generate_response(self, prompt: str, context: dict) -> str:
        """Generate AI response"""
        # Your AI logic here
        return "AI response"
    
    async def stream_response(self, prompt: str, context: dict):
        """Stream AI response"""
        # Yield response chunks
        for chunk in self.generate_chunks(prompt):
            yield chunk
```

### 2. Security Plugins
```python
from plexichat.core.plugins.base import SecurityPlugin

class AntivirusPlugin(SecurityPlugin):
    def __init__(self):
        super().__init__()
        self.name = "Antivirus Scanner"
    
    async def scan_file(self, file_path: str) -> dict:
        """Scan file for threats"""
        return {
            "safe": True,
            "threats": [],
            "scan_time": 0.5
        }
    
    async def scan_message(self, message: str) -> dict:
        """Scan message content"""
        return {
            "safe": True,
            "confidence": 0.95
        }
```

### 3. Interface Plugins
```python
from plexichat.core.plugins.base import InterfacePlugin

class CustomUIPlugin(InterfacePlugin):
    def __init__(self):
        super().__init__()
        self.name = "Custom UI"
    
    def register_routes(self, app):
        """Register web routes"""
        @app.route("/custom")
        async def custom_page():
            return {"message": "Custom page"}
    
    def register_gui_components(self, gui):
        """Register GUI components"""
        gui.add_menu_item("Custom", self.show_custom_dialog)
```

### 4. Automation Plugins
```python
from plexichat.core.plugins.base import AutomationPlugin

class WorkflowPlugin(AutomationPlugin):
    def __init__(self):
        super().__init__()
        self.name = "Workflow Automation"
    
    async def execute_workflow(self, workflow_id: str, data: dict):
        """Execute automation workflow"""
        # Workflow logic here
        pass
    
    def register_triggers(self):
        """Register event triggers"""
        return [
            {
                "event": "message_received",
                "handler": self.on_message_received
            }
        ]
```

## Development Environment

### Setting Up Development Environment
```bash
# Clone PlexiChat
git clone https://github.com/linux-of-user/plexichat.git
cd plexichat

# Install development dependencies
pip install -r requirements-dev.txt

# Create plugin development workspace
python run.py plugin init-dev-env

# Start development server
python run.py api --debug --reload
```

### Plugin Development Tools
```bash
# Create new plugin from template
python run.py plugin create --template ai_provider my-plugin

# Validate plugin
python run.py plugin validate my-plugin

# Test plugin
python run.py plugin test my-plugin --coverage

# Package plugin
python run.py plugin package my-plugin

# Publish to marketplace
python run.py plugin publish my-plugin --repo custom-repo
```

## API Reference

### Base Plugin Class
```python
from plexichat.core.plugins.base import BasePlugin

class MyPlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.name = "My Plugin"
        self.version = "1.0.0"
        self.description = "Plugin description"
    
    async def initialize(self):
        """Initialize plugin"""
        self.logger.info("Plugin initialized")
    
    async def cleanup(self):
        """Cleanup plugin resources"""
        self.logger.info("Plugin cleaned up")
    
    def get_config_schema(self):
        """Return configuration schema"""
        return {
            "api_key": {"type": "string", "required": True}
        }
    
    async def handle_event(self, event_type: str, data: dict):
        """Handle system events"""
        if event_type == "user_message":
            await self.process_message(data)
```

### Plugin Manager API
```python
from plexichat.core.plugins.manager import plugin_manager

# Get plugin instance
plugin = plugin_manager.get_plugin("plugin-name")

# List all plugins
plugins = plugin_manager.list_plugins()

# Install plugin
await plugin_manager.install_plugin("plugin-name", version="1.0.0")

# Uninstall plugin
await plugin_manager.uninstall_plugin("plugin-name")

# Enable/disable plugin
await plugin_manager.enable_plugin("plugin-name")
await plugin_manager.disable_plugin("plugin-name")
```

### Event System
```python
from plexichat.core.events import event_manager

# Register event handler
@event_manager.on("user_message")
async def handle_message(data):
    print(f"Received message: {data['content']}")

# Emit event
await event_manager.emit("custom_event", {"key": "value"})

# Register multiple events
@event_manager.on(["user_login", "user_logout"])
async def handle_user_events(data):
    print(f"User event: {data}")
```

### Configuration API
```python
from plexichat.core.config import config_manager

# Get plugin config
config = config_manager.get_plugin_config("my-plugin")

# Set plugin config
config_manager.set_plugin_config("my-plugin", {
    "api_key": "secret-key",
    "enabled": True
})

# Get system config
system_config = config_manager.get_system_config()
```

## Examples

### Complete AI Provider Plugin
```python
# plugins/openai-provider/main.py
import openai
from plexichat.core.plugins.base import AIProviderPlugin

class OpenAIProvider(AIProviderPlugin):
    def __init__(self):
        super().__init__()
        self.name = "OpenAI Provider"
        self.version = "1.0.0"
        self.client = None
    
    async def initialize(self):
        config = self.get_config()
        self.client = openai.AsyncOpenAI(
            api_key=config.get("api_key")
        )
    
    async def generate_response(self, prompt: str, context: dict) -> str:
        response = await self.client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": context.get("system_prompt", "")},
                {"role": "user", "content": prompt}
            ]
        )
        return response.choices[0].message.content
    
    async def stream_response(self, prompt: str, context: dict):
        stream = await self.client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "user", "content": prompt}
            ],
            stream=True
        )
        
        async for chunk in stream:
            if chunk.choices[0].delta.content:
                yield chunk.choices[0].delta.content
```

## Testing

### Unit Testing
```python
# plugins/my-plugin/tests/test_plugin.py
import pytest
from unittest.mock import AsyncMock
from my_plugin.main import MyPlugin

@pytest.fixture
async def plugin():
    plugin = MyPlugin()
    await plugin.initialize()
    return plugin

@pytest.mark.asyncio
async def test_plugin_initialization(plugin):
    assert plugin.name == "My Plugin"
    assert plugin.version == "1.0.0"

@pytest.mark.asyncio
async def test_message_processing(plugin):
    result = await plugin.process_message("test message")
    assert result is not None
```

### Integration Testing
```bash
# Run plugin tests
python run.py plugin test my-plugin

# Run with coverage
python run.py plugin test my-plugin --coverage

# Run specific test
python run.py plugin test my-plugin --test test_initialization
```

## Publishing

### Plugin Marketplace
```bash
# Login to marketplace
python run.py plugin login

# Publish plugin
python run.py plugin publish my-plugin

# Update plugin
python run.py plugin update my-plugin --version 1.1.0

# Set plugin visibility
python run.py plugin visibility my-plugin --public
```

### Custom Repository
```bash
# Add custom repository
python run.py plugin repo add my-repo https://github.com/user/plugins

# Publish to custom repo
python run.py plugin publish my-plugin --repo my-repo

# Install from custom repo
python run.py plugin install my-plugin --repo my-repo
```

## Best Practices

### Security
- Always validate input data
- Use proper authentication for API calls
- Sanitize user-provided content
- Follow principle of least privilege

### Performance
- Use async/await for I/O operations
- Implement proper caching
- Avoid blocking operations
- Monitor resource usage

### Error Handling
```python
try:
    result = await some_operation()
except Exception as e:
    self.logger.error(f"Operation failed: {e}")
    raise PluginError(f"Failed to process: {e}")
```

### Logging
```python
# Use plugin logger
self.logger.info("Plugin operation started")
self.logger.warning("Potential issue detected")
self.logger.error("Operation failed", exc_info=True)
```

## Support

- **Documentation**: https://docs.plexichat.com/plugins
- **GitHub**: https://github.com/linux-of-user/plexichat
- **Discord**: https://discord.gg/plexichat
- **Email**: plugins@plexichat.com
