# PlexiChat Module Interfaces and Contracts Guide

## Overview

PlexiChat uses a comprehensive module system with strict interfaces and contracts to ensure:
- **Loose Coupling**: Modules interact through well-defined interfaces
- **Type Safety**: Strong typing and validation prevent runtime errors
- **Security**: Permission-based access control and sandboxing
- **Reliability**: Contract validation ensures consistent behavior
- **Performance**: Resource monitoring and constraints

## Core Interfaces

### 1. BaseModule Class

All modules must inherit from `BaseModule` which provides:

```python
from plexichat.infrastructure.modules.interfaces import BaseModule, ModulePermissions, ModuleCapability

class MyModule(BaseModule):
    def __init__(self, name: str = "MyModule", version: str = "1.0.0"):
        super().__init__(name, version)
    
    async def initialize(self) -> bool:
        """Initialize the module - REQUIRED"""
        # Your initialization logic here
        return True
    
    def get_metadata(self) -> Dict[str, Any]:
        """Get module metadata - REQUIRED"""
        return {
            "name": self.name,
            "version": self.version,
            "description": "My custom module",
            "author": "Your Name"
        }
    
    def get_required_permissions(self) -> ModulePermissions:
        """Define required permissions - REQUIRED"""
        return ModulePermissions(
            capabilities=[ModuleCapability.MESSAGING],
            network_access=False,
            database_access=True
        )
```

### 2. Module Lifecycle Interface (IModuleLifecycle)

Defines the complete lifecycle of a module:

```python
async def initialize(self) -> bool:
    """Initialize the module"""
    
async def start(self) -> bool:
    """Start the module"""
    
async def stop(self) -> bool:
    """Stop the module"""
    
async def pause(self) -> bool:
    """Pause the module"""
    
async def resume(self) -> bool:
    """Resume the module"""
    
async def shutdown(self) -> bool:
    """Shutdown the module"""
    
async def health_check(self) -> Dict[str, Any]:
    """Perform health check"""
```

### 3. Configuration Interface (IModuleConfiguration)

Handles module configuration:

```python
def get_config_schema(self) -> Dict[str, Any]:
    """Return JSON schema for configuration validation"""
    return {
        "type": "object",
        "properties": {
            "api_key": {"type": "string", "minLength": 1},
            "timeout": {"type": "integer", "minimum": 1, "default": 30}
        },
        "required": ["api_key"]
    }

def validate_config(self, config: Dict[str, Any]) -> bool:
    """Validate configuration"""
    
def apply_config(self, config: Dict[str, Any]) -> bool:
    """Apply configuration"""
    
def get_current_config(self) -> Dict[str, Any]:
    """Get current configuration"""
```

### 4. API Interface (IModuleAPI)

For inter-module communication:

```python
def get_api_version(self) -> str:
    """Get API version"""
    
def get_available_methods(self) -> List[str]:
    """List available API methods"""
    
async def call_method(self, method: str, **kwargs) -> Any:
    """Call module method"""
    
def register_event_handler(self, event: str, handler: Callable) -> bool:
    """Register event handler"""
    
def emit_event(self, event: str, data: Any) -> bool:
    """Emit event"""
```

## Module Capabilities

Define what your module can do:

```python
from plexichat.infrastructure.modules.interfaces import ModuleCapability

# Core capabilities
ModuleCapability.MESSAGING          # Message handling
ModuleCapability.USER_MANAGEMENT     # User operations
ModuleCapability.FILE_HANDLING       # File operations
ModuleCapability.AUTHENTICATION      # Auth operations
ModuleCapability.AUTHORIZATION       # Permission checks

# Advanced capabilities
ModuleCapability.AI_PROCESSING       # AI/ML operations
ModuleCapability.BACKUP_STORAGE      # Backup operations
ModuleCapability.CLUSTERING          # Cluster operations
ModuleCapability.SECURITY_SCANNING   # Security scans
ModuleCapability.ENCRYPTION          # Crypto operations

# UI capabilities
ModuleCapability.WEB_INTERFACE       # Web UI
ModuleCapability.API_ENDPOINTS       # REST API
ModuleCapability.ADMIN_PANEL         # Admin interface

# Integration capabilities
ModuleCapability.EXTERNAL_API        # External APIs
ModuleCapability.DATABASE_ACCESS     # Database access
ModuleCapability.NETWORK_ACCESS      # Network access
ModuleCapability.FILE_SYSTEM_ACCESS  # File system access
```

## Permission System

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
        system_config_access=False,    # System config access
        external_api_access=True       # External API access
    )
```

## Contract Validation

All modules are automatically validated against contracts:

### Validation Categories

1. **Interface Compliance**: Implements required interfaces
2. **Method Signatures**: Correct method signatures and types
3. **Security Compliance**: Proper permission declarations
4. **Configuration Compliance**: Valid configuration schemas
5. **Performance Constraints**: Resource usage limits
6. **API Contracts**: Consistent API behavior
7. **Documentation**: Adequate documentation

### Validation Results

```python
# Validation results include:
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

## Module States

Modules progress through defined states:

```python
from plexichat.infrastructure.modules.interfaces import ModuleState

ModuleState.UNLOADED      # Not loaded
ModuleState.LOADING       # Being loaded
ModuleState.LOADED        # Loaded but not started
ModuleState.INITIALIZING  # Being initialized
ModuleState.ACTIVE        # Running normally
ModuleState.PAUSED        # Temporarily paused
ModuleState.ERROR         # Error state
ModuleState.UNLOADING     # Being unloaded
ModuleState.FAILED        # Failed to load/start
```

## Best Practices

### 1. Error Handling

```python
async def initialize(self) -> bool:
    try:
        # Initialization logic
        await self._setup_resources()
        return True
    except Exception as e:
        self.last_error = e
        self.metrics.record_error()
        self.logger.error(f"Initialization failed: {e}")
        return False
```

### 2. Resource Management

```python
async def shutdown(self) -> bool:
    try:
        # Clean up resources
        await self._cleanup_connections()
        await self._save_state()
        return True
    except Exception as e:
        self.logger.error(f"Shutdown error: {e}")
        return False
```

### 3. Event Handling

```python
def __init__(self, name: str = "MyModule"):
    super().__init__(name)
    
    # Register for events
    self.register_event_handler("user_login", self._on_user_login)

async def _on_user_login(self, event_data):
    """Handle user login event"""
    user_id = event_data.get("user_id")
    self.logger.info(f"User logged in: {user_id}")
```

### 4. Configuration Management

```python
def apply_config(self, config: Dict[str, Any]) -> bool:
    try:
        if not self.validate_config(config):
            return False
        
        # Apply configuration
        self.api_key = config.get("api_key")
        self.timeout = config.get("timeout", 30)
        
        # Update module configuration
        self.configuration.custom_config.update(config)
        return True
    except Exception as e:
        self.logger.error(f"Config application failed: {e}")
        return False
```

## Example: Complete Module

```python
from plexichat.infrastructure.modules.interfaces import (
    BaseModule, ModulePermissions, ModuleCapability
)

class ExampleModule(BaseModule):
    def __init__(self, name: str = "ExampleModule", version: str = "1.0.0"):
        super().__init__(name, version)
        self.api_client = None
    
    async def initialize(self) -> bool:
        """Initialize the module"""
        try:
            self.logger.info("Initializing Example Module")
            
            # Setup API client
            api_key = self.configuration.custom_config.get("api_key")
            if not api_key:
                self.logger.error("API key not configured")
                return False
            
            self.api_client = APIClient(api_key)
            await self.api_client.connect()
            
            self.logger.info("Example Module initialized successfully")
            return True
        except Exception as e:
            self.last_error = e
            self.logger.error(f"Initialization failed: {e}")
            return False
    
    async def shutdown(self) -> bool:
        """Shutdown the module"""
        try:
            if self.api_client:
                await self.api_client.disconnect()
            return True
        except Exception as e:
            self.logger.error(f"Shutdown error: {e}")
            return False
    
    def get_metadata(self) -> Dict[str, Any]:
        """Get module metadata"""
        return {
            "name": self.name,
            "version": self.version,
            "description": "Example module demonstrating best practices",
            "author": "PlexiChat Team",
            "capabilities": ["external_api", "data_processing"]
        }
    
    def get_required_permissions(self) -> ModulePermissions:
        """Get required permissions"""
        return ModulePermissions(
            capabilities=[ModuleCapability.EXTERNAL_API],
            network_access=True,
            external_api_access=True
        )
    
    def get_config_schema(self) -> Dict[str, Any]:
        """Get configuration schema"""
        return {
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
                    "default": 30,
                    "description": "Request timeout in seconds"
                }
            },
            "required": ["api_key"]
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check"""
        health = await super().health_check()
        
        # Add module-specific health info
        if self.api_client:
            health["api_connected"] = await self.api_client.is_connected()
        
        return health
```

This comprehensive interface system ensures all modules are secure, reliable, and maintainable while providing clear contracts for developers.
