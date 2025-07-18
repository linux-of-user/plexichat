# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
PlexiChat Unified Plugin Manager - SINGLE SOURCE OF TRUTH

Consolidates ALL plugin management functionality from:
- core/plugins/plugin_manager.py - INTEGRATED
- infrastructure/modules/plugin_manager.py - INTEGRATED
- infrastructure/modules/enhanced_plugin_manager.py - INTEGRATED
- infrastructure/modules/plugin_test_manager.py - INTEGRATED

Provides a single, unified interface for all plugin operations.
"""

import asyncio
import importlib.util
import json
import logging
import shutil
import sys
import time
import threading
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Callable, Union
from enum import Enum
from dataclasses import dataclass, field

# Import shared components (NEW ARCHITECTURE)
from ...shared.models import Plugin, Event, Priority, Status
from ...shared.types import PluginId, PluginConfig, PluginResult
from ...shared.exceptions import PluginError, ValidationError, SecurityError
from ...shared.constants import PLUGIN_TIMEOUT, MAX_PLUGIN_MEMORY, PLUGIN_SANDBOX_ENABLED

# Core imports
from ..database.manager import database_manager

# Top-level imports for AI integration
try:
    from plexichat.features.ai.advanced_ai_system import intelligent_assistant
except ImportError:
    intelligent_assistant = None
try:
    from plexichat.features.ai.advanced_ai_system import ai_provider_manager
except ImportError:
    ai_provider_manager = None

class ModuleCapability:
    CORE = "core"
    FEATURE = "feature"
    INTEGRATION = "integration"

class ModuleState:
    UNLOADED = "unloaded"
    LOADING = "loading"
    LOADED = "loaded"
    ERROR = "error"
    FAILED = "failed"

class ModulePriority:
    LOW = 1
    NORMAL = 5
    HIGH = 10
    CRITICAL = 20

class ModuleMetrics:
    def __init__(self):
        self.load_time = 0.0
        self.execution_count = 0
        self.error_count = 0
        self.last_execution = None

logger = logging.getLogger(__name__)


class PluginType(Enum):
    """Plugin types."""
    CORE = "core"
    FEATURE = "feature"
    INTEGRATION = "integration"
    EXTENSION = "extension"
    THEME = "theme"
    LANGUAGE = "language"


class PluginStatus(Enum):
    """Plugin status."""
    UNKNOWN = "unknown"
    DISCOVERED = "discovered"
    LOADING = "loading"
    LOADED = "loaded"
    ENABLED = "enabled"
    DISABLED = "disabled"
    ERROR = "error"
    FAILED = "failed"
    UPDATING = "updating"
    UNINSTALLING = "uninstalling"


class SecurityLevel(Enum):
    """Plugin security levels."""
    TRUSTED = "trusted"
    SANDBOXED = "sandboxed"
    RESTRICTED = "restricted"
    UNTRUSTED = "untrusted"


@dataclass
class PluginMetadata:
    """Plugin metadata."""
    name: str
    version: str
    description: str
    author: str
    plugin_type: PluginType = PluginType.FEATURE
    security_level: SecurityLevel = SecurityLevel.SANDBOXED
    dependencies: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    capabilities: List[ModuleCapability] = field(default_factory=list)
    priority: int = 5  # Use int instead of ModulePriority
    enabled: bool = False
    auto_load: bool = False
    checksum: Optional[str] = None
    homepage: Optional[str] = None
    repository: Optional[str] = None
    license: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    min_plexichat_version: Optional[str] = None
    max_plexichat_version: Optional[str] = None
    config_schema: Optional[Dict[str, Any]] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PluginMetadata':
        """Create metadata from dictionary."""
        return cls()
            name=data.get('name', ''),
            version=data.get('version', '1.0.0'),
            description=data.get('description', ''),
            author=data.get('author', ''),
            plugin_type=PluginType(data.get('type', 'feature')),
            security_level=SecurityLevel(data.get('security_level', 'sandboxed')),
            dependencies=data.get('dependencies', []),
            permissions=data.get('permissions', []),
            enabled=data.get('enabled', False),
            auto_load=data.get('auto_load', False),
            checksum=data.get('checksum'),
            homepage=data.get('homepage'),
            repository=data.get('repository'),
            license=data.get('license'),
            tags=data.get('tags', []),
            min_plexichat_version=data.get('min_plexichat_version'),
            max_plexichat_version=data.get('max_plexichat_version'),
            config_schema=data.get('config_schema'),
            priority=data.get('priority', 5),  # Use int
        )


@dataclass
class PluginInfo:
    """Plugin information."""
    plugin_id: str
    metadata: PluginMetadata
    path: Path
    status: PluginStatus = PluginStatus.DISCOVERED
    loaded_at: Optional[datetime] = None
    error_message: Optional[str] = None
    instance: Optional[Any] = None
    module: Optional[Any] = None
    config: Optional[Dict[str, Any]] = None
    metrics: Optional[ModuleMetrics] = None


class PluginContext:
    """Context object passed to plugins, giving access to all core systems, config, and utilities."""
    def __init__(self, logger, analytics, db, ai, ai_provider, backup, security, config, event_bus, middleware_manager, system_utils):
        self.logger = logger
        self.analytics = analytics
        self.db = db
        self.ai = ai
        self.ai_provider = ai_provider
        self.backup = backup
        self.security = security
        self.config = config
        self.event_bus = event_bus
        self.middleware_manager = middleware_manager
        self.system_utils = system_utils

class PluginInterface(ABC):
    """Base interface for all plugins."""

    def __init__(self, plugin_id: str, config: Optional[Dict[str, Any]] = None):
        self.plugin_id = plugin_id
        self.config = config or {}
        self.logger = logging.getLogger(f"plugin.{plugin_id}")
        self.state = ModuleState.UNLOADED
        self.loaded_at: Optional[datetime] = None
        self.last_error: Optional[Exception] = None
        # Allow injection of core services
        self.analytics: Optional[Any] = None
        self.db: Optional[Any] = None
        self.ai: Optional[Any] = None
        self.ai_provider: Optional[Any] = None
        self.backup: Optional[Any] = None
        self.security: Optional[Any] = None
        self.context: Optional[PluginContext] = None # Initialize context

    @abstractmethod
    async def initialize(self) -> bool:
        """Initialize the plugin."""
        pass

    @abstractmethod
    async def shutdown(self) -> bool:
        """Shutdown the plugin."""
        pass

    def get_metadata(self) -> Dict[str, Any]:
        """Get plugin metadata."""
        return {}

    def get_commands(self) -> Dict[str, Callable]:
        """Get plugin commands."""
        return {}

    def get_event_handlers(self) -> Dict[str, Callable]:
        """Get plugin event handlers."""
        return {}

    async def health_check(self) -> Dict[str, Any]:
        """Perform plugin health check."""
        return {
            "status": "healthy",
            "state": self.state,
            "loaded_at": self.loaded_at.isoformat() if self.loaded_at else None,
            "last_error": str(self.last_error) if self.last_error else None
        }

    async def self_test(self) -> Dict[str, Any]:
        """Run plugin self-tests."""
        return {
            "passed": True,
            "tests": [],
            "message": "No tests implemented"
        }
    # --- New extension points ---
    def get_routers(self) -> Dict[str, Any]:
        """Return a dict of routers to be registered (e.g., {"/myroute": router})."""
        return {}
    def get_db_extensions(self) -> Dict[str, Any]:
        """Return a dict of DB models, DAOs, or adapters to register."""
        return {}
    def get_security_features(self) -> Dict[str, Any]:
        """Return a dict of security features (middleware, policies, etc.) to register."""
        return {}
    def get_services(self) -> Dict[str, Any]:
        """Declare which core services the plugin wants injected (logger, analytics, db, ai, backup, security, etc.).
        Return a dict like {"logger": True, "analytics": True, ...} or provide custom handlers.
        The plugin manager will inject these as attributes or via dependency injection."""
        return {}
    def register_logging_handlers(self) -> Dict[str, Any]:
        """Return custom logging handlers or formatters to register with the logging system."""
        return {}
    def register_analytics_hooks(self) -> Dict[str, Any]:
        """Return analytics hooks or metrics to register with the analytics system."""
        return {}
    def get_event_hooks(self) -> Dict[str, Any]:
        """Return a dict of event hooks: {event_name: handler_fn}."""
        return {}
    def get_config_schema(self) -> Dict[str, Any]:
        """Return a config schema for this plugin (for validation/UI)."""
        return {}
    def get_health_checks(self) -> Dict[str, Any]:
        """Return custom health/readiness/liveness checks."""
        return {}
    def get_backup_handlers(self) -> Dict[str, Any]:
        """Return custom backup/restore handlers."""
        return {}
    def get_middleware(self) -> Dict[str, Any]:
        """Return custom middleware for web, API, or CLI."""
        return {}
    def set_context(self, context: PluginContext):
        """Set the plugin context (called by the plugin manager)."""
        self.context = context
    # Decorator helpers for plugin authors
    @staticmethod
    def on_event(event_name):
        def decorator(fn):
            fn._plugin_event = event_name
            return fn
        return decorator
    @staticmethod
    def register_middleware(middleware_type):
        def decorator(fn):
            fn._plugin_middleware = middleware_type
            return fn
        return decorator
    @staticmethod
    def register_backup_handler(handler_type):
        def decorator(fn):
            fn._plugin_backup_handler = handler_type
            return fn
        return decorator


class PluginIsolationManager:
    """Manages plugin isolation and sandboxing."""

    def __init__(self):
        self.isolated_modules: Dict[str, Any] = {}
        self.resource_limits: Dict[str, Dict[str, Any]] = {}

    async def load_module_isolated(self, plugin_name: str, plugin_path: Path, )
                                 config: Optional[Dict[str, Any]] = None) -> bool:
        """Load a module in isolation."""
        try:
            # For now, implement basic isolation
            # In production, this would use proper sandboxing

            # Set resource limits
            if config and 'resource_limits' in config:
                self.resource_limits[plugin_name] = config['resource_limits']

            # Load module with restricted imports
            spec = importlib.util.spec_from_file_location()
                f"isolated_{plugin_name}",
                plugin_path / "main.py"
            )

            if spec is None or spec.loader is None:
                return False

            module = importlib.util.module_from_spec(spec)

            # Restrict module access (simplified)
            restricted_builtins = {
                '__import__': self._restricted_import,
                'open': self._restricted_open,
                'exec': self._restricted_exec,
                'eval': self._restricted_eval,
            }

            module.__builtins__.update(restricted_builtins)

            # Execute module
            spec.loader.exec_module(module)

            self.isolated_modules[plugin_name] = module
            return True

        except Exception as e:
            logger.error(f"Failed to load isolated module {plugin_name}: {e}")
            return False

    def _restricted_import(self, name, *args, **kwargs):
        """Restricted import function."""
        # Allow only specific modules
        allowed_modules = {
            'json', 'datetime', 'typing', 'dataclasses', 'enum',
            'asyncio', 'logging', 'pathlib', 'uuid'
        }

        if name in allowed_modules or name.startswith('plexichat.'):
            return __import__(name, *args, **kwargs)
        else:
            raise ImportError(f"Import of '{name}' not allowed in sandboxed plugin")

    def _restricted_open(self, *args, **kwargs):
        """Restricted file open function."""
        raise PermissionError("File access not allowed in sandboxed plugin")

    def _restricted_exec(self, *args, **kwargs):
        """Restricted exec function."""
        raise PermissionError("Dynamic code execution not allowed in sandboxed plugin")

    def _restricted_eval(self, *args, **kwargs):
        """Restricted eval function."""
        raise PermissionError("Dynamic code evaluation not allowed in sandboxed plugin")


class PluginTestManager:
    """Manages plugin testing."""

    def __init__(self):
        self.test_results: Dict[str, Dict[str, Any]] = {}

    async def run_plugin_tests(self, plugin_name: str, plugin_instance: PluginInterface) -> Dict[str, Any]:
        """Run tests for a specific plugin."""
        try:
            # Run plugin self-tests
            self_test_results = await plugin_instance.self_test()

            # Run external tests if available
            external_test_results = await self._run_external_tests(plugin_name)

            # Combine results
            results = {
                "plugin_name": plugin_name,
                "timestamp": datetime.now().isoformat(),
                "self_tests": self_test_results,
                "external_tests": external_test_results,
                "overall_passed": ()
                    self_test_results.get("passed", False) and
                    external_test_results.get("passed", True)
                )
            }

            self.test_results[plugin_name] = results
            return results

        except Exception as e:
            logger.error(f"Failed to run tests for plugin {plugin_name}: {e}")
            return {
                "plugin_name": plugin_name,
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
                "overall_passed": False
            }

    async def _run_external_tests(self, plugin_name: str) -> Dict[str, Any]:
        """Run external tests for a plugin."""
        # Look for test files in plugin directory
        # This is a simplified implementation
        return {
            "passed": True,
            "tests": [],
            "message": "No external tests found"
        }


class UnifiedPluginManager:
    """
    Unified Plugin Manager - SINGLE SOURCE OF TRUTH

    Consolidates all plugin management functionality.

    Extension points:
    - CLI commands
    - Event handlers
    - Routers (web/api)
    - Database extensions (models, DAOs, adapters)
    - Security features (middleware, policies)
    - Self-tests
    """

    def __init__(self, plugins_dir: Optional[Path] = None):
        self.plugins_dir = plugins_dir or Path("plugins")
        self.plugins_dir.mkdir(exist_ok=True)

        # Plugin storage
        self.discovered_plugins: Set[str] = set()
        self.plugin_info: Dict[str, PluginInfo] = {}
        self.loaded_plugins: Dict[str, PluginInterface] = {}
        self.plugin_commands: Dict[str, Callable] = {}
        self.plugin_event_handlers: Dict[str, List[Callable]] = {}
        # --- New extension registries ---
        self.plugin_routers: Dict[str, Dict[str, Any]] = {}  # plugin_name -> {mount_path: router}
        self.plugin_db_extensions: Dict[str, Dict[str, Any]] = {}  # plugin_name -> {name: ext}
        self.plugin_security_features: Dict[str, Dict[str, Any]] = {}  # plugin_name -> {name: feature}
        self.plugin_docs: Dict[str, Dict[str, Any]] = {}

        # Managers
        self.isolation_manager = PluginIsolationManager()
        self.test_manager = PluginTestManager()

        # Configuration
        self.auto_discover = True
        self.auto_load_enabled = True
        self.security_enabled = True

        # Statistics
        self.stats = {
            "total_discovered": 0,
            "total_loaded": 0,
            "total_enabled": 0,
            "total_failed": 0,
            "last_discovery": None,
        }

        # Thread safety
        self._lock = threading.Lock()

    async def initialize(self) -> bool:
        """Initialize the plugin manager."""
        try:
            logger.info("Initializing unified plugin manager")

            # Discover plugins
            if self.auto_discover:
                await self.discover_plugins()

            # Load enabled plugins
            if self.auto_load_enabled:
                await self.load_enabled_plugins()

            logger.info("Unified plugin manager initialized successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize plugin manager: {e}")
            return False

    async def discover_plugins(self) -> List[str]:
        """Discover available plugins."""
        try:
            discovered = []

            with self._lock:
                # Scan plugins directory
                for plugin_dir in self.plugins_dir.iterdir():
                    if not plugin_dir.is_dir() or plugin_dir.name.startswith('_'):
                        continue

                    plugin_name = plugin_dir.name

                    # Look for plugin manifest
                    manifest_files = [
                        plugin_dir / "plugin.json",
                        plugin_dir / "plugin.yaml",
                        plugin_dir / "plugin.yml",
                        plugin_dir / "manifest.json"
                    ]

                    metadata = None
                    for manifest_file in manifest_files:
                        if manifest_file.exists():
                            metadata = await self._load_plugin_metadata(manifest_file)
                            break

                    # If no manifest, look for main.py or __init__.py
                    if not metadata:
                        main_files = [
                            plugin_dir / "main.py",
                            plugin_dir / "__init__.py"
                        ]

                        for main_file in main_files:
                            if main_file.exists():
                                metadata = await self._create_default_metadata(plugin_name, plugin_dir)
                                break

                    if metadata:
                        plugin_info = PluginInfo()
                            plugin_id=plugin_name,
                            metadata=metadata,
                            path=plugin_dir,
                            status=PluginStatus.DISCOVERED
                        )

                        self.plugin_info[plugin_name] = plugin_info
                        self.discovered_plugins.add(plugin_name)
                        discovered.append(plugin_name)

                        logger.debug(f"Discovered plugin: {plugin_name}")

                self.stats["total_discovered"] = len(self.discovered_plugins)
                self.stats["last_discovery"] = datetime.now().isoformat()

            logger.info(f"Discovered {len(discovered)} plugins")
            return discovered

        except Exception as e:
            logger.error(f"Failed to discover plugins: {e}")
            return []

    async def _load_plugin_metadata(self, manifest_file: Path) -> Optional[PluginMetadata]:
        """Load plugin metadata from manifest file."""
        try:
            with open(manifest_file, 'r', encoding='utf-8') as f:
                if manifest_file.suffix in ['.yaml', '.yml']:
                    import yaml
                    data = yaml.safe_load(f)
                else:
                    data = json.load(f)

            return PluginMetadata.from_dict(data)

        except Exception as e:
            logger.error(f"Failed to load metadata from {manifest_file}: {e}")
            return None

    async def _create_default_metadata(self, plugin_name: str, plugin_dir: Path) -> PluginMetadata:
        """Create default metadata for plugins without manifest."""
        return PluginMetadata()
            name=plugin_name,
            version="1.0.0",
            description=f"Plugin: {plugin_name}",
            author="Unknown",
            plugin_type=PluginType.FEATURE,
            security_level=SecurityLevel.SANDBOXED,
            priority=5, # Use int
            enabled=False,
            auto_load=False,
            checksum=None,
            homepage=None,
            repository=None,
            license=None,
            tags=[],
            min_plexichat_version=None,
            max_plexichat_version=None,
            config_schema=None,
        )

    async def load_plugin(self, plugin_name: str, force_reload: bool = False) -> bool:
        """Load a specific plugin."""
        try:
            with self._lock:
                # Check if already loaded
                if plugin_name in self.loaded_plugins and not force_reload:
                    logger.warning(f"Plugin already loaded: {plugin_name}")
                    return True

                # Check if discovered
                if plugin_name not in self.plugin_info:
                    logger.error(f"Plugin not discovered: {plugin_name}")
                    return False

                plugin_info = self.plugin_info[plugin_name]
                plugin_info.status = PluginStatus.LOADING

                # Check dependencies
                if not await self._check_dependencies(plugin_name):
                    plugin_info.status = PluginStatus.FAILED
                    plugin_info.error_message = "Dependencies not satisfied"
                    return False

                # Load plugin based on security level
                if plugin_info.metadata.security_level == SecurityLevel.SANDBOXED:
                    success = await self._load_plugin_sandboxed(plugin_name, plugin_info)
                else:
                    success = await self._load_plugin_direct(plugin_name, plugin_info)

                if success:
                    plugin_info.status = PluginStatus.LOADED
                    plugin_info.loaded_at = datetime.now()
                    self.stats["total_loaded"] += 1

                    # Register commands and event handlers
                    await self._register_plugin_components(plugin_name)

                    # On plugin load, check for a 'docs' directory in the plugin folder
                    # If found, register its contents as plugin documentation
                    # Add a method get_plugin_docs() that returns a mapping of plugin_id to their docs
                    docs_dir = plugin_info.path / "docs"
                    if docs_dir.exists():
                        self.plugin_docs[plugin_name] = {}
                        for doc_file in docs_dir.iterdir():
                            if doc_file.is_file():
                                try:
                                    with open(doc_file, 'r', encoding='utf-8') as f:
                                        self.plugin_docs[plugin_name][doc_file.name] = f.read()
                                except Exception as e:
                                    logger.warning(f"Failed to load documentation from {doc_file}: {e}")

                    # On plugin load, call set_context with a PluginContext instance
                    context = PluginContext()
                        logger=getattr(self, 'logger', None),
                        analytics=getattr(self, 'analytics', None),
                        db=getattr(self, 'db', None),
                        ai=getattr(self, 'ai', None),
                        ai_provider=getattr(self, 'ai_provider', None),
                        backup=getattr(self, 'backup', None),
                        security=getattr(self, 'security', None),
                        config=getattr(self, 'config', None),
                        event_bus=getattr(self, 'event_bus', None),
                        middleware_manager=getattr(self, 'middleware_manager', None),
                        system_utils=getattr(self, 'system_utils', None)
                    )
                    plugin_instance = self.loaded_plugins[plugin_name]
                    plugin_instance.set_context(context)

                    logger.info(f"Plugin loaded successfully: {plugin_name}")
                    return True
                else:
                    plugin_info.status = PluginStatus.FAILED
                    self.stats["total_failed"] += 1
                    return False

        except Exception as e:
            logger.error(f"Failed to load plugin {plugin_name}: {e}")
            if plugin_name in self.plugin_info:
                self.plugin_info[plugin_name].status = PluginStatus.ERROR
                self.plugin_info[plugin_name].error_message = str(e)
            return False

    async def _check_dependencies(self, plugin_name: str) -> bool:
        """Check if plugin dependencies are satisfied."""
        plugin_info = self.plugin_info[plugin_name]

        for dependency in plugin_info.metadata.dependencies:
            if dependency not in self.loaded_plugins:
                # Try to load dependency first
                if dependency in self.plugin_info:
                    if not await self.load_plugin(dependency):
                        logger.error(f"Failed to load dependency: {dependency} (required by {plugin_name})")
                        return False
                else:
                    logger.error(f"Dependency not found: {dependency} (required by {plugin_name})")
                    return False

        return True

    async def _load_plugin_sandboxed(self, plugin_name: str, plugin_info: PluginInfo) -> bool:
        """Load plugin in sandboxed environment."""
        try:
            # Use isolation manager
            config = {
                'security_level': plugin_info.metadata.security_level.value,
                'permissions': plugin_info.metadata.permissions,
                'resource_limits': {
                    'memory_mb': 100,
                    'cpu_percent': 10,
                    'network_access': False
                }
            }

            success = await self.isolation_manager.load_module_isolated()
                plugin_name, plugin_info.path, config
            )

            if success:
                # Get plugin instance from isolated module
                isolated_module = self.isolation_manager.isolated_modules[plugin_name]
                plugin_instance = await self._instantiate_plugin(plugin_name, isolated_module, plugin_info)

                if plugin_instance:
                    self.loaded_plugins[plugin_name] = plugin_instance
                    plugin_info.instance = plugin_instance
                    return True

            return False

        except Exception as e:
            logger.error(f"Failed to load sandboxed plugin {plugin_name}: {e}")
            return False

    async def _load_plugin_direct(self, plugin_name: str, plugin_info: PluginInfo) -> bool:
        """Load plugin directly (trusted plugins)."""
        try:
            # Find main module file
            main_files = [
                plugin_info.path / "main.py",
                plugin_info.path / "__init__.py"
            ]

            module_file = None
            for main_file in main_files:
                if main_file.exists():
                    module_file = main_file
                    break

            if not module_file:
                logger.error(f"No main module file found for plugin: {plugin_name}")
                return False

            # Load module
            spec = importlib.util.spec_from_file_location(f"plugin_{plugin_name}", module_file)
            if spec is None or spec.loader is None:
                logger.error(f"Could not create spec for plugin: {plugin_name}")
                return False

            module = importlib.util.module_from_spec(spec)
            sys.modules[f"plugin_{plugin_name}"] = module
            spec.loader.exec_module(module)

            # Instantiate plugin
            plugin_instance = await self._instantiate_plugin(plugin_name, module, plugin_info)

            if plugin_instance:
                self.loaded_plugins[plugin_name] = plugin_instance
                plugin_info.instance = plugin_instance
                plugin_info.module = module
                return True

            return False

        except Exception as e:
            logger.error(f"Failed to load direct plugin {plugin_name}: {e}")
            return False

    async def _instantiate_plugin(self, plugin_name: str, module: Any, plugin_info: PluginInfo) -> Optional[PluginInterface]:
        """Instantiate plugin from module."""
        try:
            # Look for plugin class
            plugin_class = None

            # Common plugin class names
            class_names = [
                'Plugin',
                f'{plugin_name.title()}Plugin',
                f'{plugin_name.upper()}Plugin',
                'Main',
                'MainPlugin'
            ]

            for class_name in class_names:
                if hasattr(module, class_name):
                    plugin_class = getattr(module, class_name)
                    break

            if not plugin_class:
                # Look for any class that inherits from PluginInterface
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (isinstance(attr, type) and)
                        issubclass(attr, PluginInterface) and
                        attr != PluginInterface):
                        plugin_class = attr
                        break

            if not plugin_class:
                logger.error(f"No plugin class found in module: {plugin_name}")
                return None

            # Instantiate plugin
            plugin_instance = plugin_class(plugin_name, plugin_info.config)
            self.inject_services(plugin_instance)

            # Initialize plugin
            if await plugin_instance.initialize():
                return plugin_instance
            else:
                logger.error(f"Plugin initialization failed: {plugin_name}")
                return None

        except Exception as e:
            logger.error(f"Failed to instantiate plugin {plugin_name}: {e}")
            return None

    async def _register_plugin_components(self, plugin_name: str) -> None:
        """Register plugin commands, event handlers, routers, db, and security features."""
        try:
            plugin_instance = self.loaded_plugins[plugin_name]
            # Register commands
            commands = plugin_instance.get_commands()
            for cmd_name, cmd_func in commands.items():
                full_cmd_name = f"{plugin_name}.{cmd_name}"
                self.plugin_commands[full_cmd_name] = cmd_func
                logger.debug(f"Registered command: {full_cmd_name}")
            # Register event handlers
            event_handlers = plugin_instance.get_event_handlers()
            for event_name, handler_func in event_handlers.items():
                if event_name not in self.plugin_event_handlers:
                    self.plugin_event_handlers[event_name] = []
                self.plugin_event_handlers[event_name].append(handler_func)
                logger.debug(f"Registered event handler: {event_name} for {plugin_name}")
            # --- Register routers ---
            routers = plugin_instance.get_routers()
            if routers:
                self.plugin_routers[plugin_name] = routers
                logger.info(f"Registered routers for plugin {plugin_name}: {list(routers.keys())}")
            # --- Register DB extensions ---
            db_exts = plugin_instance.get_db_extensions()
            if db_exts:
                self.plugin_db_extensions[plugin_name] = db_exts
                logger.info(f"Registered DB extensions for plugin {plugin_name}: {list(db_exts.keys())}")
            # --- Register security features ---
            sec_feats = plugin_instance.get_security_features()
            if sec_feats:
                self.plugin_security_features[plugin_name] = sec_feats
                logger.info(f"Registered security features for plugin {plugin_name}: {list(sec_feats.keys())}")
        except Exception as e:
            logger.error(f"Failed to register plugin components for {plugin_name}: {e}")

    async def unload_plugin(self, plugin_name: str) -> bool:
        """Unload a specific plugin."""
        try:
            with self._lock:
                if plugin_name not in self.loaded_plugins:
                    logger.warning(f"Plugin not loaded: {plugin_name}")
                    return True

                plugin_instance = self.loaded_plugins[plugin_name]
                plugin_info = self.plugin_info[plugin_name]

                # Shutdown plugin
                try:
                    await plugin_instance.shutdown()
                except Exception as e:
                    logger.warning(f"Plugin shutdown error: {plugin_name} - {e}")

                # Unregister components
                await self._unregister_plugin_components(plugin_name)

                # Remove from loaded plugins
                del self.loaded_plugins[plugin_name]
                plugin_info.status = PluginStatus.DISCOVERED
                plugin_info.instance = None
                plugin_info.loaded_at = None

                self.stats["total_loaded"] -= 1

                logger.info(f"Plugin unloaded: {plugin_name}")
                return True

        except Exception as e:
            logger.error(f"Failed to unload plugin {plugin_name}: {e}")
            return False

    async def _unregister_plugin_components(self, plugin_name: str) -> None:
        """Unregister plugin commands and event handlers."""
        try:
            # Unregister commands
            commands_to_remove = [
                cmd_name for cmd_name in self.plugin_commands.keys()
                if cmd_name.startswith(f"{plugin_name}.")
            ]
            for cmd_name in commands_to_remove:
                del self.plugin_commands[cmd_name]
                logger.debug(f"Unregistered command: {cmd_name}")

            # Unregister event handlers
            for event_name, handlers in self.plugin_event_handlers.items():
                # Remove handlers from this plugin
                # This is simplified - in practice, we'd need to track which handlers belong to which plugin
                pass

        except Exception as e:
            logger.error(f"Failed to unregister plugin components for {plugin_name}: {e}")

    async def enable_plugin(self, plugin_name: str) -> bool:
        """Enable a plugin."""
        try:
            if plugin_name not in self.plugin_info:
                logger.error(f"Plugin not found: {plugin_name}")
                return False

            plugin_info = self.plugin_info[plugin_name]
            plugin_info.metadata.enabled = True

            # Update database if available
            if database_manager:
                await self._update_plugin_enabled(plugin_name, True)

            # Load if not already loaded
            if plugin_name not in self.loaded_plugins:
                return await self.load_plugin(plugin_name)

            self.stats["total_enabled"] += 1
            return True

        except Exception as e:
            logger.error(f"Failed to enable plugin {plugin_name}: {e}")
            return False

    async def disable_plugin(self, plugin_name: str) -> bool:
        """Disable a plugin."""
        try:
            if plugin_name not in self.plugin_info:
                logger.error(f"Plugin not found: {plugin_name}")
                return False

            plugin_info = self.plugin_info[plugin_name]
            plugin_info.metadata.enabled = False

            # Update database if available
            if database_manager:
                await self._update_plugin_enabled(plugin_name, False)

            # Unload if loaded
            if plugin_name in self.loaded_plugins:
                await self.unload_plugin(plugin_name)

            self.stats["total_enabled"] -= 1
            return True

        except Exception as e:
            logger.error(f"Failed to disable plugin {plugin_name}: {e}")
            return False

    async def load_enabled_plugins(self) -> Dict[str, bool]:
        """Load all enabled plugins."""
        try:
            results = {}

            # Get enabled plugins
            enabled_plugins = [
                plugin_name for plugin_name, info in self.plugin_info.items()
                if info.metadata.enabled and plugin_name not in self.loaded_plugins
            ]

            # Sort by dependencies and priority
            sorted_plugins = self._sort_plugins_by_dependencies_and_priority(enabled_plugins)

            # Load plugins in order
            for plugin_name in sorted_plugins:
                results[plugin_name] = await self.load_plugin(plugin_name)

            loaded_count = sum(results.values())
            logger.info(f"Loaded {loaded_count}/{len(enabled_plugins)} enabled plugins")

            return results

        except Exception as e:
            logger.error(f"Failed to load enabled plugins: {e}")
            return {}

    def _sort_plugins_by_dependencies_and_priority(self, plugin_names: List[str]) -> List[str]:
        """Sort plugins by dependencies and priority."""
        try:
            # Simple topological sort with priority
            sorted_plugins = []
            remaining_plugins = plugin_names.copy()

            while remaining_plugins:
                # Find plugins with no unresolved dependencies
                ready_plugins = []
                for plugin_name in remaining_plugins:
                    plugin_info = self.plugin_info[plugin_name]
                    dependencies = plugin_info.metadata.dependencies

                    # Check if all dependencies are already sorted or not in the list
                    deps_satisfied = all()
                        dep in sorted_plugins or dep not in plugin_names
                        for dep in dependencies
                    )

                    if deps_satisfied:
                        ready_plugins.append(plugin_name)

                if not ready_plugins:
                    # Circular dependency or missing dependency
                    logger.warning(f"Circular dependency detected in plugins: {remaining_plugins}")
                    ready_plugins = remaining_plugins  # Load anyway

                # Sort ready plugins by priority (now an int)
                ready_plugins.sort()
                    key=lambda name: self.plugin_info[name].metadata.priority,
                    reverse=True
                )

                # Add to sorted list
                sorted_plugins.extend(ready_plugins)

                # Remove from remaining
                for plugin_name in ready_plugins:
                    remaining_plugins.remove(plugin_name)

            return sorted_plugins

        except Exception as e:
            logger.error(f"Failed to sort plugins: {e}")
            return plugin_names

    async def _update_plugin_enabled(self, plugin_name: str, enabled: bool) -> None:
        """Update plugin enabled status in database."""
        try:
            if database_manager:
                # This would update the database
                pass
        except Exception as e:
            logger.error(f"Failed to update plugin enabled status: {e}")

    async def run_plugin_tests(self, plugin_name: str) -> Dict[str, Any]:
        """Run tests for a specific plugin."""
        try:
            if plugin_name not in self.loaded_plugins:
                return {"error": "Plugin not loaded"}

            plugin_instance = self.loaded_plugins[plugin_name]
            return await self.test_manager.run_plugin_tests(plugin_name, plugin_instance)

        except Exception as e:
            logger.error(f"Failed to run tests for plugin {plugin_name}: {e}")
            return {"error": str(e)}

    async def run_all_plugin_tests(self) -> Dict[str, Any]:
        """Run tests for all loaded plugins."""
        try:
            all_results = {
                "total_plugins": len(self.loaded_plugins),
                "plugins_with_tests": 0,
                "total_tests": 0,
                "total_passed": 0,
                "total_failed": 0,
                "plugin_results": {}
            }

            for plugin_name in self.loaded_plugins:
                test_results = await self.run_plugin_tests(plugin_name)
                if test_results and "error" not in test_results:
                    all_results["plugins_with_tests"] += 1
                    all_results["plugin_results"][plugin_name] = test_results

            return all_results

        except Exception as e:
            logger.error(f"Failed to run all plugin tests: {e}")
            return {"error": str(e)}

    def get_plugin_info(self, plugin_name: str) -> Optional[Dict[str, Any]]:
        """Get comprehensive plugin information."""
        try:
            if plugin_name not in self.plugin_info:
                return None

            plugin_info = self.plugin_info[plugin_name]

            return {
                "plugin_id": plugin_info.plugin_id,
                "metadata": {
                    "name": plugin_info.metadata.name,
                    "version": plugin_info.metadata.version,
                    "description": plugin_info.metadata.description,
                    "author": plugin_info.metadata.author,
                    "type": plugin_info.metadata.plugin_type.value,
                    "security_level": plugin_info.metadata.security_level.value,
                    "dependencies": plugin_info.metadata.dependencies,
                    "permissions": plugin_info.metadata.permissions,
                    "enabled": plugin_info.metadata.enabled,
                    "auto_load": plugin_info.metadata.auto_load,
                    "priority": plugin_info.metadata.priority, # Use int
                },
                "status": plugin_info.status.value,
                "loaded_at": plugin_info.loaded_at.isoformat() if plugin_info.loaded_at else None,
                "error_message": plugin_info.error_message,
                "path": str(plugin_info.path),
            }

        except Exception as e:
            logger.error(f"Failed to get plugin info for {plugin_name}: {e}")
            return None

    def get_all_plugins_info(self) -> Dict[str, Dict[str, Any]]:
        """Get information for all plugins."""
        try:
            return {
                plugin_name: info
                for plugin_name in self.plugin_info
                if (info := self.get_plugin_info(plugin_name)) is not None
            }
        except Exception as e:
            logger.error(f"Failed to get all plugins info: {e}")
            return {}

    def get_stats(self) -> Dict[str, Any]:
        """Get plugin manager statistics."""
        return {
            **self.stats,
            "discovered_plugins": list(self.discovered_plugins),
            "loaded_plugins": list(self.loaded_plugins.keys()),
            "enabled_plugins": [
                name for name, info in self.plugin_info.items()
                if info.metadata.enabled
            ],
            "failed_plugins": [
                name for name, info in self.plugin_info.items()
                if info.status in [PluginStatus.ERROR, PluginStatus.FAILED]
            ]
        }

    async def execute_command(self, command_name: str, *args, **kwargs) -> Any:
        """Execute a plugin command."""
        try:
            if command_name not in self.plugin_commands:
                raise PluginError(f"Command not found: {command_name}")

            command_func = self.plugin_commands[command_name]

            # Execute command
            if asyncio.iscoroutinefunction(command_func):
                return await command_func(*args, **kwargs)
            else:
                return command_func(*args, **kwargs)

        except Exception as e:
            logger.error(f"Failed to execute command {command_name}: {e}")
            raise PluginError(f"Command execution failed: {e}")

    async def emit_event(self, event_name: str, *args, **kwargs) -> List[Any]:
        """Emit an event to all registered handlers."""
        try:
            results = []

            if event_name in self.plugin_event_handlers:
                for handler in self.plugin_event_handlers[event_name]:
                    try:
                        if asyncio.iscoroutinefunction(handler):
                            result = await handler(*args, **kwargs)
                        else:
                            result = handler(*args, **kwargs)
                        results.append(result)
                    except Exception as e:
                        logger.error(f"Event handler error for {event_name}: {e}")
                        results.append(None)

            return results

        except Exception as e:
            logger.error(f"Failed to emit event {event_name}: {e}")
            return []

    async def shutdown(self) -> None:
        """Shutdown the plugin manager."""
        try:
            logger.info("Shutting down plugin manager")

            # Unload all plugins
            for plugin_name in list(self.loaded_plugins.keys()):
                await self.unload_plugin(plugin_name)

            # Clear data
            self.discovered_plugins.clear()
            self.plugin_info.clear()
            self.loaded_plugins.clear()
            self.plugin_commands.clear()
            self.plugin_event_handlers.clear()

            logger.info("Plugin manager shut down successfully")

        except Exception as e:
            logger.error(f"Failed to shutdown plugin manager: {e}")

    # --- New public API for main app to retrieve extension points ---
    def get_all_plugin_routers(self) -> Dict[str, Any]:
        """Return all routers from all loaded plugins as {mount_path: router}."""
        routers = {}
        for plugin_routers in self.plugin_routers.values():
            routers.update(plugin_routers)
        return routers
    def get_all_plugin_db_extensions(self) -> Dict[str, Any]:
        """Return all DB extensions from all loaded plugins as {name: ext}."""
        db_exts = {}
        for plugin_db in self.plugin_db_extensions.values():
            db_exts.update(plugin_db)
        return db_exts
    def get_all_plugin_security_features(self) -> Dict[str, Any]:
        """Return all security features from all loaded plugins as {name: feature}."""
        sec_feats = {}
        for plugin_sec in self.plugin_security_features.values():
            sec_feats.update(plugin_sec)
        return sec_feats

    def get_plugin_docs(self) -> Dict[str, Dict[str, Any]]:
        """
        Returns a dictionary of plugin IDs to their documentation.
        The documentation is stored as a dictionary of file names to their content.
        """
        return self.plugin_docs

    def inject_services(self, plugin_instance: PluginInterface):
        """Inject requested core services into the plugin instance based on get_services()."""
        services = plugin_instance.get_services()
        # Example: inject logger, analytics, db, ai, backup, security, etc.
        if services.get("logger"):
            plugin_instance.logger = logging.getLogger(f"plugin.{plugin_instance.plugin_id}")
        if services.get("analytics"):
            try:
                from plexichat.core.analytics import analytics_manager
                plugin_instance.analytics = analytics_manager
            except ImportError:
                plugin_instance.analytics = None
        if services.get("db"):
            from plexichat.core.database import db_factory
            plugin_instance.db = db_factory
        if services.get("ai"):
            plugin_instance.ai = intelligent_assistant  # Main AI assistant for plugin AI integration
            plugin_instance.ai_provider = ai_provider_manager  # Raw provider manager for advanced use
        if services.get("backup"):
            from plexichat.core.backup.unified_backup_system import backup_manager
            plugin_instance.backup = backup_manager
        if services.get("security"):
            from plexichat.core.security import input_validation
            plugin_instance.security = input_validation
        # Add more as needed
        # Allow plugins to provide custom handlers as well
        if hasattr(plugin_instance, "register_logging_handlers"):
            handlers = plugin_instance.register_logging_handlers()
            # Register handlers with logging system
            for name, handler in handlers.items():
                logging.getLogger(name).addHandler(handler)
        if hasattr(plugin_instance, "register_analytics_hooks"):
            hooks = plugin_instance.register_analytics_hooks()
            # Register hooks with analytics system (pseudo-code)
            # analytics_manager.register_hooks(hooks)


# Global unified plugin manager instance
unified_plugin_manager = UnifiedPluginManager()

# Backward compatibility functions
async def get_plugin_manager() -> UnifiedPluginManager:
    """Get the global plugin manager instance."""
    return unified_plugin_manager

async def discover_plugins() -> List[str]:
    """Discover available plugins."""
    return await unified_plugin_manager.discover_plugins()

async def load_plugin(plugin_name: str) -> bool:
    """Load a specific plugin."""
    return await unified_plugin_manager.load_plugin(plugin_name)

async def unload_plugin(plugin_name: str) -> bool:
    """Unload a specific plugin."""
    return await unified_plugin_manager.unload_plugin(plugin_name)

async def enable_plugin(plugin_name: str) -> bool:
    """Enable a plugin."""
    return await unified_plugin_manager.enable_plugin(plugin_name)

async def disable_plugin(plugin_name: str) -> bool:
    """Disable a plugin."""
    return await unified_plugin_manager.disable_plugin(plugin_name)

def get_plugin_info(plugin_name: str) -> Optional[Dict[str, Any]]:
    """Get plugin information."""
    return unified_plugin_manager.get_plugin_info(plugin_name)

def get_all_plugins_info() -> Dict[str, Dict[str, Any]]:
    """Get information for all plugins."""
    return unified_plugin_manager.get_all_plugins_info()

async def execute_command(command_name: str, *args, **kwargs) -> Any:
    """Execute a plugin command."""
    return await unified_plugin_manager.execute_command(command_name, *args, **kwargs)

async def emit_event(event_name: str, *args, **kwargs) -> List[Any]:
    """Emit an event to all registered handlers."""
    return await unified_plugin_manager.emit_event(event_name, *args, **kwargs)

# Backward compatibility aliases
plugin_manager = unified_plugin_manager
PluginManager = UnifiedPluginManager

__all__ = [
    # Main classes
    'UnifiedPluginManager',
    'unified_plugin_manager',
    'PluginInterface',
    'PluginIsolationManager',
    'PluginTestManager',

    # Data classes
    'PluginMetadata',
    'PluginInfo',
    'PluginType',
    'PluginStatus',
    'SecurityLevel',

    # Main functions
    'get_plugin_manager',
    'discover_plugins',
    'load_plugin',
    'unload_plugin',
    'enable_plugin',
    'disable_plugin',
    'get_plugin_info',
    'get_all_plugins_info',
    'execute_command',
    'emit_event',

    # Backward compatibility aliases
    'plugin_manager',
    'PluginManager',

    # Exceptions
    'PluginError',
]
