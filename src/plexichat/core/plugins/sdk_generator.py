"""
PlexiChat Plugin SDK Generator

Automatically generates the `plugins_internal.py` module that provides secure,
sandboxed access to PlexiChat services. This module is the primary interface
between plugins and the core PlexiChat system.

The generated module includes:
- Safe file operations through SafeFileManager
- Controlled network access through NetworkBroker
- Plugin-specific logging utilities
- Event system for plugin communication
- Configuration access limited to plugin settings
- Permission checking utilities
- Type stubs for IDE support
"""

import ast
import inspect
import json
import logging
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

try:
    import jinja2
except ImportError:
    jinja2 = None

logger = logging.getLogger(__name__)

# PlexiChat version for compatibility checks
PLEXICHAT_VERSION = "1.0.0"
SDK_VERSION = "1.0.0"


@dataclass
class APIMethod:
    """Represents an API method that can be exposed to plugins."""

    name: str
    module: str
    signature: str
    docstring: str
    is_async: bool
    is_safe: bool = False
    required_permissions: List[str] = field(default_factory=list)
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    return_type: str = "Any"
    examples: List[str] = field(default_factory=list)


@dataclass
class APIModule:
    """Represents a module with safe APIs."""

    name: str
    description: str
    methods: List[APIMethod] = field(default_factory=list)
    classes: List[str] = field(default_factory=list)
    constants: Dict[str, Any] = field(default_factory=dict)


class PluginSDKGenerator:
    """Generates the secure plugins_internal.py module for plugin access to PlexiChat services."""

    def __init__(self, output_dir: Optional[Path] = None) -> None:
        self.logger = logging.getLogger(__name__)

        # Set output directory - plugins_internal.py should be in src/plexichat/
        if output_dir is None:
            current_file = Path(__file__).resolve()
            # Navigate to src/plexichat/ directory
            self.output_dir = current_file.parent.parent.parent
        else:
            self.output_dir = Path(output_dir)

        self.output_file = self.output_dir / "plugins_internal.py"
        self.type_stubs_file = self.output_dir / "plugins_internal.pyi"

        # Safe APIs that can be exposed to plugins
        self.safe_apis = {
            "file_operations": {
                "description": "Safe file operations through SafeFileManager",
                "class": "SafeFileManager",
                "methods": ["open", "upload_file", "get_file_data"],
                "permissions": ["file_read", "file_write"],
            },
            "network_operations": {
                "description": "Controlled network access through NetworkBroker",
                "class": "NetworkBroker",
                "methods": ["get", "post", "close"],
                "permissions": ["network_access"],
            },
            "logging": {
                "description": "Plugin-specific logging utilities",
                "class": "PluginLogger",
                "methods": ["debug", "info", "warning", "error", "critical"],
                "permissions": [],
            },
            "events": {
                "description": "Event system for plugin communication",
                "class": "EventManager",
                "methods": ["emit", "listen", "unlisten"],
                "permissions": ["events_emit", "events_listen"],
            },
            "config": {
                "description": "Plugin configuration access",
                "class": "ConfigManager",
                "methods": ["get_plugin_config", "set_plugin_config"],
                "permissions": ["config_read", "config_write"],
            },
            "permissions": {
                "description": "Permission checking utilities",
                "class": "PermissionChecker",
                "methods": ["has_permission", "request_permission"],
                "permissions": [],
            },
        }

        # Dangerous patterns to filter out
        self.dangerous_patterns = [
            r"os\.",
            r"sys\.",
            r"subprocess\.",
            r"eval\(",
            r"exec\(",
            r"__import__",
            r"open\(",
            r"file\(",
            r"input\(",
            r"raw_input\(",
            r"compile\(",
            r"globals\(",
            r"locals\(",
            r"vars\(",
            r"dir\(",
            r"getattr\(",
            r"setattr\(",
            r"delattr\(",
            r"hasattr\(",
        ]

        # Initialize Jinja2 environment
        if jinja2:
            self.jinja_env = jinja2.Environment(
                loader=jinja2.BaseLoader(), trim_blocks=True, lstrip_blocks=True
            )
        else:
            self.jinja_env = None
            self.logger.warning(
                "Jinja2 not available. Install with: pip install Jinja2"
            )

    def _is_method_safe(self, method_name: str, method_obj: Any) -> bool:
        """Check if a method is safe to expose to plugins."""
        try:
            # Check if method is in safe list
            for module_info in self.safe_modules.values():
                if method_name in module_info["methods"]:
                    return True

            # Check method source for dangerous patterns
            if hasattr(method_obj, "__code__"):
                source = inspect.getsource(method_obj)
                for pattern in self.dangerous_patterns:
                    if re.search(pattern, source):
                        return False

            # Check for admin-only decorators or naming
            if method_name.startswith("_") or "admin" in method_name.lower():
                return False

            # Check docstring for safety markers
            if hasattr(method_obj, "__doc__") and method_obj.__doc__:
                doc = method_obj.__doc__.lower()
                if "plugin-safe" in doc:
                    return True
                if any(
                    word in doc for word in ["admin", "dangerous", "unsafe", "internal"]
                ):
                    return False

            return False

        except Exception as e:
            self.logger.debug(f"Error checking method safety for {method_name}: {e}")
            return False

    def _extract_method_info(
        self, method_name: str, method_obj: Any, module_name: str
    ) -> Optional[APIMethod]:
        """Extract information about a method for SDK generation."""
        try:
            # Get signature
            try:
                sig = inspect.signature(method_obj)
                signature = f"{method_name}{sig}"
            except (ValueError, TypeError):
                signature = f"{method_name}(...)"

            # Get docstring
            docstring = (
                inspect.getdoc(method_obj)
                or f"No documentation available for {method_name}"
            )

            # Check if async
            is_async = inspect.iscoroutinefunction(method_obj)

            # Extract parameters
            parameters = []
            try:
                sig = inspect.signature(method_obj)
                for param_name, param in sig.parameters.items():
                    if param_name in ["self", "cls"]:
                        continue

                    param_info = {
                        "name": param_name,
                        "type": (
                            str(param.annotation)
                            if param.annotation != param.empty
                            else "Any"
                        ),
                        "default": (
                            str(param.default) if param.default != param.empty else None
                        ),
                        "required": param.default == param.empty,
                    }
                    parameters.append(param_info)
            except Exception:
                pass

            # Get return type
            try:
                sig = inspect.signature(method_obj)
                return_type = (
                    str(sig.return_annotation)
                    if sig.return_annotation != sig.empty
                    else "Any"
                )
            except Exception:
                return_type = "Any"

            # Determine required permissions
            required_permissions = []
            for module_info in self.safe_modules.values():
                if method_name in module_info["methods"]:
                    required_permissions = module_info["permissions"]
                    break

            # Generate examples
            examples = self._generate_method_examples(method_name, parameters, is_async)

            return APIMethod(
                name=method_name,
                module=module_name,
                signature=signature,
                docstring=docstring,
                is_async=is_async,
                is_safe=True,
                required_permissions=required_permissions,
                parameters=parameters,
                return_type=return_type,
                examples=examples,
            )

        except Exception as e:
            self.logger.error(f"Error extracting method info for {method_name}: {e}")
            return None

    def _generate_method_examples(
        self, method_name: str, parameters: List[Dict[str, Any]], is_async: bool
    ) -> List[str]:
        """Generate usage examples for a method."""
        examples = []

        try:
            # Basic example
            if parameters:
                param_examples = []
                for param in parameters:
                    if param["name"] in ["key", "name"]:
                        param_examples.append('"my_key"')
                    elif param["name"] in ["value", "data"]:
                        param_examples.append('"my_value"')
                    elif param["type"] == "int":
                        param_examples.append("123")
                    elif param["type"] == "bool":
                        param_examples.append("True")
                    elif param["type"] == "dict":
                        param_examples.append('{"key": "value"}')
                    elif param["type"] == "list":
                        param_examples.append('["item1", "item2"]')
                    else:
                        param_examples.append('"example"')

                params_str = ", ".join(param_examples)
            else:
                params_str = ""

            if is_async:
                examples.append(f"result = await api.{method_name}({params_str})")
            else:
                examples.append(f"result = api.{method_name}({params_str})")

            # Add specific examples based on method name
            if method_name == "db_set_value":
                examples.append(
                    'await api.db_set_value("user_preference", {"theme": "dark"})'
                )
            elif method_name == "db_get_value":
                examples.append(
                    'theme = await api.db_get_value("user_preference", {"theme": "light"})'
                )
            elif method_name == "emit_event":
                examples.append(
                    'await api.emit_event("user_action", {"action": "login", "user_id": 123})'
                )
            elif method_name == "get_config":
                examples.append('timeout = await api.get_config("timeout", 30)')

        except Exception as e:
            self.logger.debug(f"Error generating examples for {method_name}: {e}")

        return examples

    def _scan_for_safe_apis(self) -> Dict[str, APIModule]:
        """Scan the codebase for safe APIs that can be exposed to plugins."""
        api_modules = {}

        try:
            # Import and scan the plugin manager for existing safe APIs
            from src.plexichat.core.plugins.manager import EnhancedPluginAPI

            # Scan EnhancedPluginAPI for safe methods
            api_methods = []
            for attr_name in dir(EnhancedPluginAPI):
                if attr_name.startswith("_"):
                    continue

                attr = getattr(EnhancedPluginAPI, attr_name)
                if callable(attr):
                    method_info = self._extract_method_info(
                        attr_name, attr, "plugin_api"
                    )
                    if method_info and self._is_method_safe(attr_name, attr):
                        api_methods.append(method_info)

            if api_methods:
                api_modules["plugin_api"] = APIModule(
                    name="plugin_api",
                    description="Core plugin API methods",
                    methods=api_methods,
                )

            # Scan database manager for safe methods
            try:
                from src.plexichat.core.database.manager import DatabaseSession

                db_methods = []
                safe_db_methods = ["insert", "update", "delete", "fetchone", "fetchall"]

                for method_name in safe_db_methods:
                    if hasattr(DatabaseSession, method_name):
                        method = getattr(DatabaseSession, method_name)
                        method_info = self._extract_method_info(
                            method_name, method, "database"
                        )
                        if method_info:
                            db_methods.append(method_info)

                if db_methods:
                    api_modules["database"] = APIModule(
                        name="database",
                        description="Safe database operations",
                        methods=db_methods,
                    )

            except ImportError:
                self.logger.debug("Database manager not available for API scanning")

            # Scan file manager for safe methods
            try:
                from src.plexichat.core.files import FileManager

                file_methods = []
                safe_file_methods = ["upload_file", "get_file_metadata", "delete_file"]

                for method_name in safe_file_methods:
                    if hasattr(FileManager, method_name):
                        method = getattr(FileManager, method_name)
                        method_info = self._extract_method_info(
                            method_name, method, "files"
                        )
                        if method_info:
                            file_methods.append(method_info)

                if file_methods:
                    api_modules["files"] = APIModule(
                        name="files",
                        description="Safe file operations",
                        methods=file_methods,
                    )

            except ImportError:
                self.logger.debug("File manager not available for API scanning")

        except Exception as e:
            self.logger.error(f"Error scanning for safe APIs: {e}")

        return api_modules

    def _create_plugins_internal_template(self) -> str:
        """Create the Jinja2 template for plugins_internal.py generation."""
        return '''"""
PlexiChat Plugin Internal API - Auto-Generated
==============================================

This module provides the secure interface between plugins and PlexiChat core services.
It acts as a sandboxed bridge that exposes only safe, whitelisted functionality.

Generated on: {{ generation_time }}
SDK Version: {{ sdk_version }}
PlexiChat Version: {{ plexichat_version }}

WARNING: This file is auto-generated. Do not edit manually!
Changes will be overwritten when the plugin system starts.
"""

import asyncio
import json
import logging
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, Callable
from contextlib import asynccontextmanager

# Version information
SDK_VERSION = "{{ sdk_version }}"
PLEXICHAT_VERSION = "{{ plexichat_version }}"

# Import core security components
try:
    from src.plexichat.core.plugins.security_manager import (
        SafeFileManager, NetworkBroker, PermissionType, 
        plugin_security_manager, check_plugin_permission
    )
except ImportError:
    # Fallback implementations for testing
    class SafeFileManager:
        def __init__(self, plugin_name: str, security_manager): pass
        def open(self, *args, **kwargs): raise NotImplementedError()
        async def upload_file(self, *args, **kwargs): raise NotImplementedError()
        async def get_file_data(self, *args, **kwargs): raise NotImplementedError()
    
    class NetworkBroker:
        def __init__(self, plugin_name: str, security_manager): pass
        async def get(self, *args, **kwargs): raise NotImplementedError()
        async def post(self, *args, **kwargs): raise NotImplementedError()
        async def close(self): pass
    
    class PermissionType:
        FILE_READ = "file_read"
        FILE_WRITE = "file_write"
        NETWORK_ACCESS = "network_access"
    
    plugin_security_manager = None
    def check_plugin_permission(plugin_name: str, permission_type): return False

# Core exceptions
class PluginSecurityError(Exception):
    """Raised when a plugin violates security policies."""
    pass

class PluginPermissionError(PluginSecurityError):
    """Raised when a plugin lacks required permissions."""
    pass

class PluginAPIError(Exception):
    """Base exception for plugin API errors."""
    pass

# ==============================================================================
# PLUGIN LOGGER
# ==============================================================================

class PluginLogger:
    """Plugin-specific logger that writes to plugin log files."""
    
    def __init__(self, plugin_name: str):
        self.plugin_name = plugin_name
        self.logger = logging.getLogger(f"plugin.{plugin_name}")
        
        # Ensure plugin log directory exists
        log_dir = Path(__file__).parent.parent.parent.parent / "logs" / "plugins" / plugin_name
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # Add file handler for plugin-specific logs
        if not any(isinstance(h, logging.FileHandler) for h in self.logger.handlers):
            log_file = log_dir / f"{plugin_name}.log"
            handler = logging.FileHandler(log_file)
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
    
    def debug(self, message: str, *args, **kwargs):
        """Log debug message."""
        self.logger.debug(message, *args, **kwargs)
    
    def info(self, message: str, *args, **kwargs):
        """Log info message."""
        self.logger.info(message, *args, **kwargs)
    
    def warning(self, message: str, *args, **kwargs):
        """Log warning message."""
        self.logger.warning(message, *args, **kwargs)
    
    def error(self, message: str, *args, **kwargs):
        """Log error message."""
        self.logger.error(message, *args, **kwargs)
    
    def critical(self, message: str, *args, **kwargs):
        """Log critical message."""
        self.logger.critical(message, *args, **kwargs)

# ==============================================================================
# EVENT MANAGER
# ==============================================================================

class EventManager:
    """Event system for plugin communication."""
    
    def __init__(self, plugin_name: str):
        self.plugin_name = plugin_name
        self.logger = PluginLogger(plugin_name)
        self._event_handlers: Dict[str, List[Callable]] = {}
    
    def emit(self, event_name: str, data: Any = None) -> None:
        """
        Emit an event that other plugins can listen to.
        
        Args:
            event_name: Name of the event to emit
            data: Optional data to send with the event
        """
        if not check_plugin_permission(self.plugin_name, PermissionType.EVENTS_EMIT):
            raise PluginPermissionError(f"Plugin {self.plugin_name} lacks permission to emit events")
        
        self.logger.debug(f"Emitting event: {event_name}")
        
        # Get handlers for this event
        handlers = self._event_handlers.get(event_name, [])
        for handler in handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    asyncio.create_task(handler(data))
                else:
                    handler(data)
            except Exception as e:
                self.logger.error(f"Error in event handler for {event_name}: {e}")
    
    def listen(self, event_name: str, handler: Callable) -> None:
        """
        Listen for events from other plugins.
        
        Args:
            event_name: Name of the event to listen for
            handler: Function to call when event is received
        """
        if not check_plugin_permission(self.plugin_name, PermissionType.EVENTS_LISTEN):
            raise PluginPermissionError(f"Plugin {self.plugin_name} lacks permission to listen to events")
        
        if event_name not in self._event_handlers:
            self._event_handlers[event_name] = []
        
        self._event_handlers[event_name].append(handler)
        self.logger.debug(f"Registered handler for event: {event_name}")
    
    def unlisten(self, event_name: str, handler: Callable) -> None:
        """
        Stop listening for a specific event.
        
        Args:
            event_name: Name of the event to stop listening for
            handler: Handler function to remove
        """
        if event_name in self._event_handlers:
            try:
                self._event_handlers[event_name].remove(handler)
                self.logger.debug(f"Unregistered handler for event: {event_name}")
            except ValueError:
                pass

# ==============================================================================
# CONFIG MANAGER
# ==============================================================================

class ConfigManager:
    """Plugin configuration access limited to plugin-specific settings."""
    
    def __init__(self, plugin_name: str):
        self.plugin_name = plugin_name
        self.logger = PluginLogger(plugin_name)
        self._config_prefix = f"plugins.{plugin_name}."
    
    def get_plugin_config(self, key: str, default: Any = None) -> Any:
        """
        Get a plugin-specific configuration value.
        
        Args:
            key: Configuration key (will be prefixed with plugin name)
            default: Default value if key doesn't exist
            
        Returns:
            Configuration value or default
        """
        if not check_plugin_permission(self.plugin_name, PermissionType.CONFIG_READ):
            raise PluginPermissionError(f"Plugin {self.plugin_name} lacks permission to read config")
        
        full_key = self._config_prefix + key
        self.logger.debug(f"Getting config: {full_key}")
        
        # This would integrate with the actual config manager
        # For now, return default
        return default
    
    def set_plugin_config(self, key: str, value: Any) -> None:
        """
        Set a plugin-specific configuration value.
        
        Args:
            key: Configuration key (will be prefixed with plugin name)
            value: Value to set
        """
        if not check_plugin_permission(self.plugin_name, PermissionType.CONFIG_WRITE):
            raise PluginPermissionError(f"Plugin {self.plugin_name} lacks permission to write config")
        
        full_key = self._config_prefix + key
        self.logger.debug(f"Setting config: {full_key} = {value}")
        
        # This would integrate with the actual config manager
        # For now, just log the operation

# ==============================================================================
# PERMISSION CHECKER
# ==============================================================================

class PermissionChecker:
    """Permission checking utilities for plugins."""
    
    def __init__(self, plugin_name: str):
        self.plugin_name = plugin_name
        self.logger = PluginLogger(plugin_name)
    
    def has_permission(self, permission_type: str) -> bool:
        """
        Check if the plugin has a specific permission.
        
        Args:
            permission_type: Type of permission to check
            
        Returns:
            True if plugin has permission, False otherwise
        """
        try:
            # Convert string to PermissionType enum if needed
            if hasattr(PermissionType, permission_type.upper()):
                perm_enum = getattr(PermissionType, permission_type.upper())
            else:
                perm_enum = permission_type
            
            return check_plugin_permission(self.plugin_name, perm_enum)
        except Exception as e:
            self.logger.error(f"Error checking permission {permission_type}: {e}")
            return False
    
    def request_permission(self, permission_type: str, justification: str) -> str:
        """
        Request a new permission for the plugin.
        
        Args:
            permission_type: Type of permission to request
            justification: Reason why the permission is needed
            
        Returns:
            Request ID for tracking the permission request
        """
        self.logger.info(f"Requesting permission: {permission_type} - {justification}")
        
        if plugin_security_manager:
            try:
                # Convert string to PermissionType enum if needed
                if hasattr(PermissionType, permission_type.upper()):
                    perm_enum = getattr(PermissionType, permission_type.upper())
                else:
                    perm_enum = permission_type
                
                return plugin_security_manager.request_permission(
                    self.plugin_name, perm_enum, justification
                )
            except Exception as e:
                self.logger.error(f"Error requesting permission: {e}")
                return ""
        
        return ""

# ==============================================================================
# MAIN PLUGIN API CLASS
# ==============================================================================

class PluginAPI:
    """
    Main API class that provides access to all plugin services.
    
    This is the primary interface that plugins should use to interact
    with PlexiChat core services in a secure, sandboxed manner.
    """
    
    def __init__(self, plugin_name: str):
        self.plugin_name = plugin_name
        
        # Initialize all service managers
        self.logger = PluginLogger(plugin_name)
        self.events = EventManager(plugin_name)
        self.config = ConfigManager(plugin_name)
        self.permissions = PermissionChecker(plugin_name)
        
        # Initialize secure service managers
        if plugin_security_manager:
            self.files = SafeFileManager(plugin_name, plugin_security_manager)
            self.network = NetworkBroker(plugin_name, plugin_security_manager)
        else:
            self.files = SafeFileManager(plugin_name, None)
            self.network = NetworkBroker(plugin_name, None)
        
        self.logger.info(f"Plugin API initialized for: {plugin_name}")
    
    @asynccontextmanager
    async def secure_context(self):
        """
        Context manager for secure plugin operations.
        
        Usage:
            async with api.secure_context():
                # Perform secure operations
                await api.network.get("https://api.example.com")
        """
        try:
            self.logger.debug("Entering secure context")
            yield self
        except Exception as e:
            self.logger.error(f"Error in secure context: {e}")
            raise
        finally:
            # Cleanup network connections
            try:
                await self.network.close()
            except Exception as e:
                self.logger.debug(f"Error closing network connections: {e}")
            
            self.logger.debug("Exiting secure context")
    
    def get_plugin_info(self) -> Dict[str, Any]:
        """Get information about the current plugin."""
        return {
            "name": self.plugin_name,
            "sdk_version": SDK_VERSION,
            "plexichat_version": PLEXICHAT_VERSION,
            "permissions": {
                "file_read": self.permissions.has_permission("file_read"),
                "file_write": self.permissions.has_permission("file_write"),
                "network_access": self.permissions.has_permission("network_access"),
                "config_read": self.permissions.has_permission("config_read"),
                "config_write": self.permissions.has_permission("config_write"),
                "events_emit": self.permissions.has_permission("events_emit"),
                "events_listen": self.permissions.has_permission("events_listen"),
            }
        }

# ==============================================================================
# UTILITY FUNCTIONS
# ==============================================================================

def create_plugin_api(plugin_name: str) -> PluginAPI:
    """
    Create a new PluginAPI instance for a plugin.
    
    Args:
        plugin_name: Name of the plugin
        
    Returns:
        Configured PluginAPI instance
    """
    return PluginAPI(plugin_name)

def check_compatibility(required_version: str = None) -> bool:
    """
    Check if the current PlexiChat version is compatible with the plugin.
    
    Args:
        required_version: Minimum required PlexiChat version
        
    Returns:
        True if compatible, False otherwise
    """
    if not required_version:
        return True
    
    try:
        current = tuple(map(int, PLEXICHAT_VERSION.split('.')))
        required = tuple(map(int, required_version.split('.')))
        return current >= required
    except (ValueError, AttributeError):
        return False

def get_sdk_info() -> Dict[str, str]:
    """Get SDK version information."""
    return {
        "sdk_version": SDK_VERSION,
        "plexichat_version": PLEXICHAT_VERSION,
        "generation_time": "{{ generation_time }}",
        "module_path": __file__
    }

# ==============================================================================
# EXPORTS
# ==============================================================================

# Main classes that plugins should use
__all__ = [
    # Main API class
    "PluginAPI",
    "create_plugin_api",
    
    # Service classes
    "PluginLogger",
    "EventManager", 
    "ConfigManager",
    "PermissionChecker",
    "SafeFileManager",
    "NetworkBroker",
    
    # Exceptions
    "PluginSecurityError",
    "PluginPermissionError", 
    "PluginAPIError",
    
    # Utility functions
    "check_compatibility",
    "get_sdk_info",
    
    # Constants
    "SDK_VERSION",
    "PLEXICHAT_VERSION",
]

# Auto-generated on: {{ generation_time }}
'''

    def _create_type_stubs_template(self) -> str:
        """Create type stubs for better IDE support."""
        return '''"""
Type stubs for plugins_internal.py - Auto-Generated
==================================================

This file provides type hints for better IDE support when developing plugins.
Generated on: {{ generation_time }}
"""

from typing import Any, Dict, List, Optional, Union, Callable, AsyncContextManager
from pathlib import Path

class PluginLogger:
    def __init__(self, plugin_name: str) -> None: ...
    def debug(self, message: str, *args: Any, **kwargs: Any) -> None: ...
    def info(self, message: str, *args: Any, **kwargs: Any) -> None: ...
    def warning(self, message: str, *args: Any, **kwargs: Any) -> None: ...
    def error(self, message: str, *args: Any, **kwargs: Any) -> None: ...
    def critical(self, message: str, *args: Any, **kwargs: Any) -> None: ...

class EventManager:
    def __init__(self, plugin_name: str) -> None: ...
    def emit(self, event_name: str, data: Any = None) -> None: ...
    def listen(self, event_name: str, handler: Callable) -> None: ...
    def unlisten(self, event_name: str, handler: Callable) -> None: ...

class ConfigManager:
    def __init__(self, plugin_name: str) -> None: ...
    def get_plugin_config(self, key: str, default: Any = None) -> Any: ...
    def set_plugin_config(self, key: str, value: Any) -> None: ...

class PermissionChecker:
    def __init__(self, plugin_name: str) -> None: ...
    def has_permission(self, permission_type: str) -> bool: ...
    def request_permission(self, permission_type: str, justification: str) -> str: ...

class SafeFileManager:
    def __init__(self, plugin_name: str, security_manager: Any) -> None: ...
    def open(self, filename: str, mode: str = 'r', **kwargs: Any) -> Any: ...
    async def upload_file(self, file_data: bytes, filename: str, **kwargs: Any) -> Any: ...
    async def get_file_data(self, file_id: str) -> Any: ...

class NetworkBroker:
    def __init__(self, plugin_name: str, security_manager: Any) -> None: ...
    async def get(self, url: str, **kwargs: Any) -> str: ...
    async def post(self, url: str, **kwargs: Any) -> str: ...
    async def close(self) -> None: ...

class PluginAPI:
    plugin_name: str
    logger: PluginLogger
    events: EventManager
    config: ConfigManager
    permissions: PermissionChecker
    files: SafeFileManager
    network: NetworkBroker
    
    def __init__(self, plugin_name: str) -> None: ...
    def secure_context(self) -> AsyncContextManager['PluginAPI']: ...
    def get_plugin_info(self) -> Dict[str, Any]: ...

# Exceptions
class PluginSecurityError(Exception): ...
class PluginPermissionError(PluginSecurityError): ...
class PluginAPIError(Exception): ...

# Functions
def create_plugin_api(plugin_name: str) -> PluginAPI: ...
def check_compatibility(required_version: Optional[str] = None) -> bool: ...
def get_sdk_info() -> Dict[str, str]: ...

# Constants
SDK_VERSION: str
PLEXICHAT_VERSION: str
'''

    def generate_plugins_internal(self) -> bool:
        """Generate the plugins_internal.py module."""
        try:
            self.logger.info("Starting plugins_internal.py generation...")

            # Prepare template data
            template_data = {
                "generation_time": datetime.now().isoformat(),
                "sdk_version": SDK_VERSION,
                "plexichat_version": PLEXICHAT_VERSION,
            }

            # Generate plugins_internal.py content
            if self.jinja_env:
                template_content = self._create_plugins_internal_template()
                template = self.jinja_env.from_string(template_content)
                plugins_internal_content = template.render(**template_data)
            else:
                # Fallback without Jinja2
                plugins_internal_content = (
                    self._create_plugins_internal_template()
                    .replace("{{ generation_time }}", template_data["generation_time"])
                    .replace("{{ sdk_version }}", template_data["sdk_version"])
                    .replace(
                        "{{ plexichat_version }}", template_data["plexichat_version"]
                    )
                )

            # Write plugins_internal.py file
            self.output_file.parent.mkdir(parents=True, exist_ok=True)
            self.output_file.write_text(plugins_internal_content, encoding="utf-8")

            # Generate type stubs for IDE support
            self._generate_type_stubs(template_data)

            # Update .gitignore
            self._update_gitignore()

            self.logger.info(
                f"plugins_internal.py generated successfully: {self.output_file}"
            )

            return True

        except Exception as e:
            self.logger.error(
                f"Error generating plugins_internal.py: {e}", exc_info=True
            )
            return False

    def _generate_type_stubs(self, template_data: Dict[str, Any]) -> None:
        """Generate type stubs file for IDE support."""
        try:
            if self.jinja_env:
                template_content = self._create_type_stubs_template()
                template = self.jinja_env.from_string(template_content)
                stubs_content = template.render(**template_data)
            else:
                # Fallback without Jinja2
                stubs_content = self._create_type_stubs_template().replace(
                    "{{ generation_time }}", template_data["generation_time"]
                )

            self.type_stubs_file.write_text(stubs_content, encoding="utf-8")
            self.logger.info(f"Type stubs generated: {self.type_stubs_file}")

        except Exception as e:
            self.logger.debug(f"Could not generate type stubs: {e}")

    # Keep the old method for backward compatibility
    def generate_sdk(self) -> bool:
        """Generate the plugin SDK (now generates plugins_internal.py)."""
        return self.generate_plugins_internal()

    def _update_gitignore(self) -> None:
        """Update .gitignore to exclude generated plugins_internal files."""
        try:
            # Find project root
            current_dir = Path(__file__).resolve()
            project_root = None

            for parent in current_dir.parents:
                if (parent / ".git").exists() or (parent / ".gitignore").exists():
                    project_root = parent
                    break

            if not project_root:
                self.logger.debug("Could not find project root for .gitignore update")
                return

            gitignore_path = project_root / ".gitignore"

            # Read existing .gitignore
            if gitignore_path.exists():
                content = gitignore_path.read_text()
            else:
                content = ""

            # Add generated files to .gitignore if not already present
            patterns = [
                "src/plexichat/plugins_internal.py",
                "src/plexichat/plugins_internal.pyi",
            ]

            updated = False
            for pattern in patterns:
                if pattern not in content:
                    if content and not content.endswith("\n"):
                        content += "\n"
                    if not updated:
                        content += "\n# Auto-generated plugin internal API\n"
                        updated = True
                    content += f"{pattern}\n"

            if updated:
                gitignore_path.write_text(content)
                self.logger.info(
                    "Updated .gitignore to exclude generated plugins_internal files"
                )

        except Exception as e:
            self.logger.debug(f"Could not update .gitignore: {e}")

    def validate_plugins_internal(self) -> bool:
        """Validate the generated plugins_internal.py by attempting to compile it."""
        try:
            if not self.output_file.exists():
                self.logger.error("plugins_internal.py file does not exist")
                return False

            # Try to compile the generated module
            with open(self.output_file, "r") as f:
                content = f.read()

            try:
                compile(content, str(self.output_file), "exec")
                self.logger.info("plugins_internal.py validation successful")
                return True
            except SyntaxError as e:
                self.logger.error(f"plugins_internal.py syntax error: {e}")
                return False

        except Exception as e:
            self.logger.error(f"Error validating plugins_internal.py: {e}")
            return False

    # Keep the old method for backward compatibility
    def validate_sdk(self) -> bool:
        """Validate the generated SDK (now validates plugins_internal.py)."""
        return self.validate_plugins_internal()

    def get_generation_stats(self) -> Dict[str, Any]:
        """Get statistics about the last plugins_internal.py generation."""
        try:
            if not self.output_file.exists():
                return {"error": "plugins_internal.py not generated"}

            stat = self.output_file.stat()

            # Count lines and methods in generated module
            content = self.output_file.read_text()
            lines = len(content.splitlines())
            methods = len(re.findall(r"def \w+\(", content))
            classes = len(re.findall(r"class \w+", content))

            stats = {
                "file_path": str(self.output_file),
                "file_size": stat.st_size,
                "lines_of_code": lines,
                "method_count": methods,
                "class_count": classes,
                "last_modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "sdk_version": SDK_VERSION,
                "plexichat_version": PLEXICHAT_VERSION,
            }

            # Add type stubs info if available
            if self.type_stubs_file.exists():
                stubs_stat = self.type_stubs_file.stat()
                stats["type_stubs"] = {
                    "file_path": str(self.type_stubs_file),
                    "file_size": stubs_stat.st_size,
                    "last_modified": datetime.fromtimestamp(
                        stubs_stat.st_mtime
                    ).isoformat(),
                }

            return stats

        except Exception as e:
            self.logger.error(f"Error getting generation stats: {e}")
            return {"error": str(e)}

    def regenerate_if_needed(self) -> bool:
        """Regenerate plugins_internal.py if it doesn't exist or is outdated."""
        try:
            # Check if file exists
            if not self.output_file.exists():
                self.logger.info("plugins_internal.py not found, generating...")
                return self.generate_plugins_internal()

            # Check if file is too old (older than this generator file)
            generator_mtime = Path(__file__).stat().st_mtime
            output_mtime = self.output_file.stat().st_mtime

            if output_mtime < generator_mtime:
                self.logger.info("plugins_internal.py is outdated, regenerating...")
                return self.generate_plugins_internal()

            # File is up to date
            return True

        except Exception as e:
            self.logger.error(f"Error checking if regeneration needed: {e}")
            return False


# Global SDK generator instance
sdk_generator = PluginSDKGenerator()


# Convenience functions
def generate_plugins_internal() -> bool:
    """Generate the plugins_internal.py module using the global generator."""
    return sdk_generator.generate_plugins_internal()


def validate_plugins_internal() -> bool:
    """Validate the generated plugins_internal.py module."""
    return sdk_generator.validate_plugins_internal()


def get_plugins_internal_stats() -> Dict[str, Any]:
    """Get plugins_internal.py generation statistics."""
    return sdk_generator.get_generation_stats()


def regenerate_plugins_internal_if_needed() -> bool:
    """Regenerate plugins_internal.py if needed."""
    return sdk_generator.regenerate_if_needed()


# Backward compatibility functions
def generate_plugin_sdk() -> bool:
    """Generate the plugin SDK (backward compatibility)."""
    return generate_plugins_internal()


def validate_plugin_sdk() -> bool:
    """Validate the generated plugin SDK (backward compatibility)."""
    return validate_plugins_internal()


def get_sdk_stats() -> Dict[str, Any]:
    """Get SDK generation statistics (backward compatibility)."""
    return get_plugins_internal_stats()


# Auto-generate plugins_internal.py on import if it doesn't exist or is outdated
def _auto_generate_plugins_internal():
    """Auto-generate plugins_internal.py if it doesn't exist or is outdated."""
    try:
        if not sdk_generator.regenerate_if_needed():
            logger.debug("Could not auto-generate plugins_internal.py")
    except Exception as e:
        logger.debug(f"Auto-generation failed: {e}")


# Run auto-generation
_auto_generate_plugins_internal()

__all__ = [
    "PluginSDKGenerator",
    "sdk_generator",
    "generate_plugins_internal",
    "validate_plugins_internal",
    "get_plugins_internal_stats",
    "regenerate_plugins_internal_if_needed",
    # Backward compatibility
    "generate_plugin_sdk",
    "validate_plugin_sdk",
    "get_sdk_stats",
    "APIMethod",
    "APIModule",
    "SDK_VERSION",
    "PLEXICHAT_VERSION",
]
