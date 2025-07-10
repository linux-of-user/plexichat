"""
PlexiChat Advanced Plugin System

Comprehensive plugin framework with micro-app support:
- Advanced plugin API with extensive capabilities
- Micro-app framework for complex plugins
- Rich SDK with development tools
- Plugin marketplace integration
- Security scanning and sandboxing
- Hot-loading and dependency management
"""

import asyncio
import json
import importlib
import sys
from enum import Enum
from typing import Dict, List, Optional, Any, Callable, Type
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
import logging
import hashlib
import zipfile
import tempfile

logger = logging.getLogger(__name__)


class PluginType(Enum):
    """Plugin types."""
    SIMPLE = "simple"
    MICRO_APP = "micro_app"
    SERVICE = "service"
    MIDDLEWARE = "middleware"
    THEME = "theme"
    INTEGRATION = "integration"


class PluginStatus(Enum):
    """Plugin status."""
    INACTIVE = "inactive"
    ACTIVE = "active"
    LOADING = "loading"
    ERROR = "error"
    UPDATING = "updating"
    DISABLED = "disabled"


class SecurityLevel(Enum):
    """Plugin security levels."""
    TRUSTED = "trusted"
    VERIFIED = "verified"
    COMMUNITY = "community"
    UNVERIFIED = "unverified"
    RESTRICTED = "restricted"


@dataclass
class PluginCapability:
    """Plugin capability definition."""
    name: str
    description: str
    required_permissions: List[str]
    api_endpoints: List[str] = field(default_factory=list)
    event_hooks: List[str] = field(default_factory=list)
    data_access: List[str] = field(default_factory=list)


@dataclass
class PluginManifest:
    """Plugin manifest with metadata."""
    plugin_id: str
    name: str
    version: str
    description: str
    author: str
    plugin_type: PluginType
    
    # Requirements
    min_plexichat_version: str
    python_version: str = ">=3.8"
    dependencies: List[str] = field(default_factory=list)
    
    # Capabilities and permissions
    capabilities: List[PluginCapability] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    
    # Security
    security_level: SecurityLevel = SecurityLevel.UNVERIFIED
    signature: Optional[str] = None
    checksum: Optional[str] = None
    
    # Metadata
    homepage: Optional[str] = None
    repository: Optional[str] = None
    license: str = "Unknown"
    tags: List[str] = field(default_factory=list)
    
    # Entry points
    main_module: str = "main"
    entry_point: str = "main"
    config_schema: Dict[str, Any] = field(default_factory=dict)
    
    # Micro-app specific
    ui_components: List[str] = field(default_factory=list)
    api_routes: List[str] = field(default_factory=list)
    background_tasks: List[str] = field(default_factory=list)
    
    def validate(self) -> List[str]:
        """Validate manifest and return errors."""
        errors = []
        
        if not self.plugin_id or not self.plugin_id.replace("_", "").replace("-", "").isalnum():
            errors.append("Invalid plugin_id: must be alphanumeric with underscores/hyphens")
        
        if not self.name or len(self.name) < 3:
            errors.append("Plugin name must be at least 3 characters")
        
        if not self.version or not self._is_valid_version(self.version):
            errors.append("Invalid version format")
        
        if not self.author:
            errors.append("Author is required")
        
        return errors
    
    def _is_valid_version(self, version: str) -> bool:
        """Check if version format is valid."""
        try:
            parts = version.split(".")
            return len(parts) >= 2 and all(part.isdigit() for part in parts)
        except:
            return False


@dataclass
class PluginInstance:
    """Running plugin instance."""
    manifest: PluginManifest
    module: Any
    status: PluginStatus
    config: Dict[str, Any] = field(default_factory=dict)
    
    # Runtime info
    loaded_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_error: Optional[str] = None
    performance_metrics: Dict[str, Any] = field(default_factory=dict)
    
    # Micro-app specific
    ui_instance: Optional[Any] = None
    api_instance: Optional[Any] = None
    background_tasks: List[asyncio.Task] = field(default_factory=list)
    
    def get_api_endpoint(self, endpoint: str) -> Optional[Callable]:
        """Get API endpoint from plugin."""
        if self.api_instance and hasattr(self.api_instance, endpoint):
            return getattr(self.api_instance, endpoint)
        return None
    
    def call_hook(self, hook_name: str, *args, **kwargs) -> Any:
        """Call plugin hook method."""
        if self.module and hasattr(self.module, hook_name):
            method = getattr(self.module, hook_name)
            if callable(method):
                return method(*args, **kwargs)
        return None


class PluginAPI:
    """Plugin API interface for plugins to interact with PlexiChat."""
    
    def __init__(self, plugin_id: str, permissions: List[str]):
        self.plugin_id = plugin_id
        self.permissions = permissions
        self._event_handlers: Dict[str, List[Callable]] = {}
    
    # Core API methods
    async def send_message(self, user_id: str, message: str, **kwargs) -> bool:
        """Send message through PlexiChat."""
        if "messaging" not in self.permissions:
            raise PermissionError("Plugin lacks messaging permission")
        
        # Integration with messaging system
        try:
            from ..messaging.messaging_coordinator import messaging_coordinator
            result = await messaging_coordinator.send_message(
                sender_id=f"plugin_{self.plugin_id}",
                target_id=user_id,
                message=message,
                **kwargs
            )
            return result.get("success", False)
        except Exception as e:
            logger.error(f"Plugin {self.plugin_id} message send failed: {e}")
            return False
    
    async def get_user_info(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user information."""
        if "user_data" not in self.permissions:
            raise PermissionError("Plugin lacks user data permission")
        
        try:
            from ..messaging.advanced_user_system import advanced_user_manager
            user = advanced_user_manager.get_user_profile(user_id)
            return user.to_dict() if user else None
        except Exception as e:
            logger.error(f"Plugin {self.plugin_id} user info failed: {e}")
            return None
    
    async def create_group(self, group_data: Dict[str, Any]) -> Optional[str]:
        """Create group through PlexiChat."""
        if "group_management" not in self.permissions:
            raise PermissionError("Plugin lacks group management permission")
        
        try:
            from ..messaging.group_management import group_manager
            group = await group_manager.create_group(group_data, f"plugin_{self.plugin_id}")
            return group.group_id
        except Exception as e:
            logger.error(f"Plugin {self.plugin_id} group creation failed: {e}")
            return None
    
    async def call_ai(self, request_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Call AI services."""
        if "ai_services" not in self.permissions:
            raise PermissionError("Plugin lacks AI services permission")
        
        try:
            from ..ai.ai_coordinator import ai_coordinator
            return await ai_coordinator.generate_ai_response(request_type, data)
        except Exception as e:
            logger.error(f"Plugin {self.plugin_id} AI call failed: {e}")
            return {"success": False, "error": str(e)}
    
    def register_event_handler(self, event_name: str, handler: Callable):
        """Register event handler."""
        if event_name not in self._event_handlers:
            self._event_handlers[event_name] = []
        self._event_handlers[event_name].append(handler)
    
    def emit_event(self, event_name: str, data: Any):
        """Emit event to other plugins."""
        # This would integrate with PlexiChat's event system
        logger.info(f"Plugin {self.plugin_id} emitted event: {event_name}")
    
    def log(self, level: str, message: str):
        """Plugin logging."""
        plugin_logger = logging.getLogger(f"plugin.{self.plugin_id}")
        getattr(plugin_logger, level.lower(), plugin_logger.info)(message)
    
    def get_config(self, key: str, default: Any = None) -> Any:
        """Get plugin configuration value."""
        # This would integrate with PlexiChat's config system
        return default
    
    def set_config(self, key: str, value: Any):
        """Set plugin configuration value."""
        if "config_write" not in self.permissions:
            raise PermissionError("Plugin lacks config write permission")
        
        # This would integrate with PlexiChat's config system
        pass


class MicroAppFramework:
    """Framework for micro-app plugins."""
    
    def __init__(self):
        self.registered_apps: Dict[str, Dict[str, Any]] = {}
        self.ui_components: Dict[str, Type] = {}
        self.api_routes: Dict[str, Callable] = {}
    
    def register_micro_app(self, plugin_id: str, app_config: Dict[str, Any]):
        """Register micro-app."""
        self.registered_apps[plugin_id] = {
            "config": app_config,
            "registered_at": datetime.now(timezone.utc)
        }
        
        # Register UI components
        for component_name, component_class in app_config.get("ui_components", {}).items():
            self.ui_components[f"{plugin_id}.{component_name}"] = component_class
        
        # Register API routes
        for route_path, route_handler in app_config.get("api_routes", {}).items():
            self.api_routes[f"/plugins/{plugin_id}{route_path}"] = route_handler
        
        logger.info(f"Registered micro-app: {plugin_id}")
    
    def unregister_micro_app(self, plugin_id: str):
        """Unregister micro-app."""
        if plugin_id in self.registered_apps:
            # Remove UI components
            to_remove = [key for key in self.ui_components.keys() if key.startswith(f"{plugin_id}.")]
            for key in to_remove:
                del self.ui_components[key]
            
            # Remove API routes
            to_remove = [key for key in self.api_routes.keys() if key.startswith(f"/plugins/{plugin_id}")]
            for key in to_remove:
                del self.api_routes[key]
            
            del self.registered_apps[plugin_id]
            logger.info(f"Unregistered micro-app: {plugin_id}")
    
    def get_ui_component(self, component_id: str) -> Optional[Type]:
        """Get UI component by ID."""
        return self.ui_components.get(component_id)
    
    def handle_api_request(self, path: str, method: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle API request to plugin."""
        handler = self.api_routes.get(path)
        if handler:
            try:
                return handler(method, data)
            except Exception as e:
                logger.error(f"Plugin API request failed: {e}")
                return {"error": str(e)}
        
        return {"error": "Route not found"}


class PluginSecurityScanner:
    """Security scanner for plugins."""
    
    def __init__(self):
        self.dangerous_imports = {
            "os", "subprocess", "sys", "eval", "exec", "open",
            "file", "__import__", "compile", "globals", "locals"
        }
        
        self.suspicious_patterns = [
            r"exec\s*\(",
            r"eval\s*\(",
            r"__import__\s*\(",
            r"subprocess\.",
            r"os\.system",
            r"open\s*\(",
            r"file\s*\("
        ]
    
    async def scan_plugin(self, plugin_path: Path) -> Dict[str, Any]:
        """Scan plugin for security issues."""
        scan_result = {
            "safe": True,
            "warnings": [],
            "errors": [],
            "risk_level": "low"
        }
        
        try:
            # Scan Python files
            for py_file in plugin_path.rglob("*.py"):
                file_result = await self._scan_file(py_file)
                scan_result["warnings"].extend(file_result["warnings"])
                scan_result["errors"].extend(file_result["errors"])
            
            # Determine overall risk level
            if scan_result["errors"]:
                scan_result["safe"] = False
                scan_result["risk_level"] = "high"
            elif len(scan_result["warnings"]) > 5:
                scan_result["risk_level"] = "medium"
            
        except Exception as e:
            scan_result["safe"] = False
            scan_result["errors"].append(f"Scan failed: {e}")
        
        return scan_result
    
    async def _scan_file(self, file_path: Path) -> Dict[str, Any]:
        """Scan individual file."""
        result = {"warnings": [], "errors": []}
        
        try:
            content = file_path.read_text(encoding="utf-8")
            
            # Check for dangerous imports
            for dangerous in self.dangerous_imports:
                if f"import {dangerous}" in content or f"from {dangerous}" in content:
                    result["warnings"].append(f"Potentially dangerous import: {dangerous} in {file_path.name}")
            
            # Check for suspicious patterns
            import re
            for pattern in self.suspicious_patterns:
                if re.search(pattern, content):
                    result["errors"].append(f"Suspicious code pattern found in {file_path.name}: {pattern}")
            
        except Exception as e:
            result["errors"].append(f"Failed to scan {file_path.name}: {e}")
        
        return result


class AdvancedPluginManager:
    """Advanced plugin manager with comprehensive features."""

    def __init__(self):
        self.plugins: Dict[str, PluginInstance] = {}
        self.plugin_apis: Dict[str, PluginAPI] = {}
        self.micro_app_framework = MicroAppFramework()
        self.security_scanner = PluginSecurityScanner()

        # Plugin directories
        self.plugin_dirs = [
            Path("plugins"),
            Path("user_plugins"),
            Path("system_plugins")
        ]

        # Event system
        self.event_handlers: Dict[str, List[Callable]] = {}

        # Plugin marketplace
        self.marketplace_enabled = True
        self.auto_update_enabled = False

    async def initialize(self):
        """Initialize plugin manager."""
        logger.info("🔌 Initializing Advanced Plugin Manager...")

        # Create plugin directories
        for plugin_dir in self.plugin_dirs:
            plugin_dir.mkdir(exist_ok=True)

        # Load installed plugins
        await self._discover_plugins()
        await self._load_enabled_plugins()

        # Start background tasks
        asyncio.create_task(self._plugin_health_monitor())

        logger.info(f"✅ Plugin Manager initialized with {len(self.plugins)} plugins")

    async def _discover_plugins(self):
        """Discover available plugins."""
        for plugin_dir in self.plugin_dirs:
            if not plugin_dir.exists():
                continue

            for item in plugin_dir.iterdir():
                if item.is_dir() and (item / "manifest.json").exists():
                    try:
                        await self._register_plugin(item)
                    except Exception as e:
                        logger.error(f"Failed to register plugin {item.name}: {e}")

    async def _register_plugin(self, plugin_path: Path):
        """Register plugin from path."""
        manifest_file = plugin_path / "manifest.json"

        try:
            manifest_data = json.loads(manifest_file.read_text())
            manifest = PluginManifest(**manifest_data)

            # Validate manifest
            errors = manifest.validate()
            if errors:
                logger.error(f"Plugin {manifest.plugin_id} manifest errors: {errors}")
                return

            # Security scan
            scan_result = await self.security_scanner.scan_plugin(plugin_path)
            if not scan_result["safe"]:
                logger.warning(f"Plugin {manifest.plugin_id} failed security scan: {scan_result['errors']}")
                manifest.security_level = SecurityLevel.RESTRICTED

            # Create plugin instance
            instance = PluginInstance(
                manifest=manifest,
                module=None,
                status=PluginStatus.INACTIVE
            )

            self.plugins[manifest.plugin_id] = instance
            logger.info(f"Registered plugin: {manifest.name} v{manifest.version}")

        except Exception as e:
            logger.error(f"Failed to register plugin from {plugin_path}: {e}")

    async def _load_enabled_plugins(self):
        """Load enabled plugins."""
        for plugin_id, instance in self.plugins.items():
            if self._is_plugin_enabled(plugin_id):
                await self.load_plugin(plugin_id)

    def _is_plugin_enabled(self, plugin_id: str) -> bool:
        """Check if plugin is enabled."""
        # This would check configuration
        return True  # For demo, all plugins are enabled

    async def load_plugin(self, plugin_id: str) -> bool:
        """Load and activate plugin."""
        if plugin_id not in self.plugins:
            logger.error(f"Plugin {plugin_id} not found")
            return False

        instance = self.plugins[plugin_id]

        if instance.status == PluginStatus.ACTIVE:
            logger.warning(f"Plugin {plugin_id} already active")
            return True

        try:
            instance.status = PluginStatus.LOADING

            # Load plugin module
            plugin_path = self._get_plugin_path(plugin_id)
            spec = importlib.util.spec_from_file_location(
                instance.manifest.main_module,
                plugin_path / f"{instance.manifest.main_module}.py"
            )

            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                sys.modules[f"plugin_{plugin_id}"] = module
                spec.loader.exec_module(module)

                instance.module = module

                # Create plugin API
                api = PluginAPI(plugin_id, instance.manifest.permissions)
                self.plugin_apis[plugin_id] = api

                # Initialize plugin
                if hasattr(module, instance.manifest.entry_point):
                    entry_func = getattr(module, instance.manifest.entry_point)
                    if asyncio.iscoroutinefunction(entry_func):
                        await entry_func(api)
                    else:
                        entry_func(api)

                # Register micro-app if applicable
                if instance.manifest.plugin_type == PluginType.MICRO_APP:
                    await self._register_micro_app(instance)

                instance.status = PluginStatus.ACTIVE
                instance.loaded_at = datetime.now(timezone.utc)

                logger.info(f"✅ Loaded plugin: {instance.manifest.name}")
                return True

        except Exception as e:
            instance.status = PluginStatus.ERROR
            instance.last_error = str(e)
            logger.error(f"Failed to load plugin {plugin_id}: {e}")

        return False

    async def unload_plugin(self, plugin_id: str) -> bool:
        """Unload plugin."""
        if plugin_id not in self.plugins:
            return False

        instance = self.plugins[plugin_id]

        try:
            # Stop background tasks
            for task in instance.background_tasks:
                task.cancel()
            instance.background_tasks.clear()

            # Unregister micro-app
            if instance.manifest.plugin_type == PluginType.MICRO_APP:
                self.micro_app_framework.unregister_micro_app(plugin_id)

            # Call plugin cleanup
            if instance.module and hasattr(instance.module, "cleanup"):
                cleanup_func = getattr(instance.module, "cleanup")
                if asyncio.iscoroutinefunction(cleanup_func):
                    await cleanup_func()
                else:
                    cleanup_func()

            # Remove from sys.modules
            module_name = f"plugin_{plugin_id}"
            if module_name in sys.modules:
                del sys.modules[module_name]

            instance.module = None
            instance.status = PluginStatus.INACTIVE

            # Remove API
            if plugin_id in self.plugin_apis:
                del self.plugin_apis[plugin_id]

            logger.info(f"Unloaded plugin: {instance.manifest.name}")
            return True

        except Exception as e:
            logger.error(f"Failed to unload plugin {plugin_id}: {e}")
            return False

    async def _register_micro_app(self, instance: PluginInstance):
        """Register micro-app with framework."""
        app_config = {
            "ui_components": {},
            "api_routes": {}
        }

        # Register UI components
        for component_name in instance.manifest.ui_components:
            if hasattr(instance.module, component_name):
                app_config["ui_components"][component_name] = getattr(instance.module, component_name)

        # Register API routes
        for route_name in instance.manifest.api_routes:
            if hasattr(instance.module, route_name):
                app_config["api_routes"][f"/{route_name}"] = getattr(instance.module, route_name)

        self.micro_app_framework.register_micro_app(instance.manifest.plugin_id, app_config)

    def _get_plugin_path(self, plugin_id: str) -> Path:
        """Get plugin directory path."""
        for plugin_dir in self.plugin_dirs:
            plugin_path = plugin_dir / plugin_id
            if plugin_path.exists():
                return plugin_path

        raise FileNotFoundError(f"Plugin {plugin_id} not found")

    async def install_plugin(self, plugin_package: bytes, verify_signature: bool = True) -> bool:
        """Install plugin from package."""
        try:
            # Extract to temporary directory
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)

                # Extract zip package
                with zipfile.ZipFile(io.BytesIO(plugin_package), 'r') as zip_file:
                    zip_file.extractall(temp_path)

                # Find manifest
                manifest_file = None
                for item in temp_path.rglob("manifest.json"):
                    manifest_file = item
                    break

                if not manifest_file:
                    raise ValueError("No manifest.json found in plugin package")

                # Load and validate manifest
                manifest_data = json.loads(manifest_file.read_text())
                manifest = PluginManifest(**manifest_data)

                errors = manifest.validate()
                if errors:
                    raise ValueError(f"Invalid manifest: {errors}")

                # Security scan
                scan_result = await self.security_scanner.scan_plugin(manifest_file.parent)
                if not scan_result["safe"] and scan_result["risk_level"] == "high":
                    raise SecurityError(f"Plugin failed security scan: {scan_result['errors']}")

                # Install to plugins directory
                install_path = self.plugin_dirs[0] / manifest.plugin_id
                if install_path.exists():
                    # Update existing plugin
                    import shutil
                    shutil.rmtree(install_path)

                shutil.copytree(manifest_file.parent, install_path)

                # Register plugin
                await self._register_plugin(install_path)

                logger.info(f"Installed plugin: {manifest.name} v{manifest.version}")
                return True

        except Exception as e:
            logger.error(f"Plugin installation failed: {e}")
            return False

    async def _plugin_health_monitor(self):
        """Monitor plugin health."""
        while True:
            try:
                await asyncio.sleep(300)  # Check every 5 minutes

                for plugin_id, instance in self.plugins.items():
                    if instance.status == PluginStatus.ACTIVE:
                        # Check if plugin is responsive
                        try:
                            if hasattr(instance.module, "health_check"):
                                health = instance.module.health_check()
                                if not health:
                                    logger.warning(f"Plugin {plugin_id} health check failed")
                        except Exception as e:
                            logger.error(f"Plugin {plugin_id} health check error: {e}")

            except Exception as e:
                logger.error(f"Plugin health monitor error: {e}")

    def get_plugin_status(self) -> Dict[str, Any]:
        """Get comprehensive plugin system status."""
        active_plugins = sum(1 for p in self.plugins.values() if p.status == PluginStatus.ACTIVE)
        error_plugins = sum(1 for p in self.plugins.values() if p.status == PluginStatus.ERROR)

        return {
            "plugin_system": {
                "total_plugins": len(self.plugins),
                "active_plugins": active_plugins,
                "error_plugins": error_plugins,
                "micro_apps": len(self.micro_app_framework.registered_apps),
                "ui_components": len(self.micro_app_framework.ui_components),
                "api_routes": len(self.micro_app_framework.api_routes),
                "marketplace_enabled": self.marketplace_enabled
            }
        }


# Global instances
micro_app_framework = MicroAppFramework()
plugin_security_scanner = PluginSecurityScanner()
advanced_plugin_manager = AdvancedPluginManager()
