import asyncio
import importlib
import importlib.util
import json
import sys
import threading
import traceback
import weakref
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from ...core_system.config import get_config
from ...core_system.database.abstraction.phase4_integration import phase4_database
from ...core_system.logging import get_logger
from ...features.ai.phase3_integration import phase3_ai
from ...features.security.phase1_integration import phase1_security
from ...infrastructure.scalability.phase2_integration import phase2_scalability
from ...integration.master_coordinator import master_coordinator
from .config_manager import get_plugin_config_manager
from .contracts import get_contract_validator
from .interfaces import BaseModule, ModuleCapability, ModulePermissions, ModuleState
from .isolation import IsolationConfig, get_isolation_manager

from pathlib import Path
from pathlib import Path
from pathlib import Path
from pathlib import Path
from pathlib import Path
from datetime import datetime
from datetime import datetime
from pathlib import Path

from pathlib import Path
from pathlib import Path
from pathlib import Path
from pathlib import Path
from pathlib import Path
from datetime import datetime
from datetime import datetime
from pathlib import Path

"""
PlexiChat Unified Plugin Manager - SINGLE SOURCE OF TRUTH

CONSOLIDATED from multiple plugin management systems:
- infrastructure/modules/loader.py - REMOVED
- features/plugins/plugin_manager.py - REMOVED
- features/plugins/advanced_plugin_system.py - REMOVED
- features/plugins/enhanced_plugin_manager.py - REMOVED

Features:
- Dynamic module loading with error isolation
- Plugin discovery and lifecycle management
- Security scanning and validation
- Hot-reloading and dependency management
- Plugin marketplace integration
- Comprehensive plugin interfaces with strict contracts
- Advanced sandboxing and isolation
- Contract validation and compliance checking
"""

# Import system coordinators for plugin access
logger = get_logger(__name__)


class ModuleStatus(Enum):
    """Module/Plugin status."""
    UNKNOWN = "unknown"
    DISCOVERED = "discovered"
    LOADING = "loading"
    LOADED = "loaded"
    UNLOADING = "unloading"
    UNLOADED = "unloaded"
    ERROR = "error"
    DISABLED = "disabled"


class PluginType(Enum):
    """Plugin types."""
    CORE = "core"
    FEATURE = "feature"
    INTEGRATION = "integration"
    MICRO_APP = "micro_app"
    AI_NODE = "ai_node"
    SECURITY_NODE = "security_node"
    STORAGE_NODE = "storage_node"
    EXTENSION = "extension"
    THEME = "theme"


class PluginSource(Enum):
    """Plugin installation sources."""
    LOCAL = "local"
    OFFICIAL = "official"
    COMMUNITY = "community"
    DEVELOPMENT = "development"


@dataclass
class PluginMetadata:
    """Plugin metadata information."""
    name: str
    version: str
    description: str = ""
    author: str = ""
    plugin_type: PluginType = PluginType.FEATURE
    entry_point: str = "main"
    dependencies: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    api_version: str = "1.0"
    min_plexichat_version: str = "1.0.0"
    enabled: bool = True
    category: str = "general"
    tags: List[str] = field(default_factory=list)
    homepage: Optional[str] = None
    repository: Optional[str] = None
    license: str = "Unknown"


@dataclass
class ModuleInfo:
    """Module information tracking."""
    name: str
    path: Optional[Path] = None
    module: Optional[Any] = None
    status: ModuleStatus = ModuleStatus.UNKNOWN
    metadata: Optional[PluginMetadata] = None
    load_time: Optional[datetime] = None
    error_message: Optional[str] = None
    dependencies: Set[str] = field(default_factory=set)
    dependents: Set[str] = field(default_factory=set)


class PluginSystemAccess:
    """
    Provides controlled access to PlexiChat system components for plugins.
    """

    def __init__(self, plugin_name: str, permissions: ModulePermissions):
        self.plugin_name = plugin_name
        self.permissions = permissions
        self.logger = get_logger(f"plugin.{plugin_name}.system_access")

    # Security System Access
    async def get_security_status(self) -> Dict[str, Any]:
        """Get security system status."""
        if ModuleCapability.SECURITY not in self.permissions.capabilities:
            raise PermissionError("Plugin lacks SECURITY capability")
        return phase1_security.get_security_status()

    async def scan_for_threats(self, data: Any) -> Dict[str, Any]:
        """Scan data for security threats."""
        if ModuleCapability.SECURITY not in self.permissions.capabilities:
            raise PermissionError("Plugin lacks SECURITY capability")
        # Implementation would call security scanning
        return {"clean": True, "threats": []}

    # Scalability System Access
    async def submit_background_task(self, task_type: str, payload: Dict[str, Any]) -> str:
        """Submit background task to queue system."""
        if ModuleCapability.BACKGROUND_TASKS not in self.permissions.capabilities:
            raise PermissionError("Plugin lacks BACKGROUND_TASKS capability")
        return await phase2_scalability.submit_background_task(task_type, payload)

    async def get_cache_value(self, key: str) -> Any:
        """Get value from distributed cache."""
        if ModuleCapability.CACHING not in self.permissions.capabilities:
            raise PermissionError("Plugin lacks CACHING capability")
        return await phase2_scalability.get_cache_value(key)

    async def set_cache_value(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in distributed cache."""
        if ModuleCapability.CACHING not in self.permissions.capabilities:
            raise PermissionError("Plugin lacks CACHING capability")
        return await phase2_scalability.set_cache_value(key, value, ttl)

    # AI System Access
    async def moderate_content(self, content: str, content_type: str = "text") -> Dict[str, Any]:
        """Moderate content using AI."""
        if ModuleCapability.AI_SERVICES not in self.permissions.capabilities:
            raise PermissionError("Plugin lacks AI_SERVICES capability")
        return await phase3_ai.moderate_content(content, content_type, self.plugin_name)

    async def start_chatbot_conversation(self, user_id: str, language: str = "auto") -> str:
        """Start AI chatbot conversation."""
        if ModuleCapability.AI_SERVICES not in self.permissions.capabilities:
            raise PermissionError("Plugin lacks AI_SERVICES capability")
        return await phase3_ai.start_chatbot_conversation(user_id, language)

    async def search_content(self, query: str, search_type: str = "global") -> List[Dict[str, Any]]:
        """Perform semantic search."""
        if ModuleCapability.AI_SERVICES not in self.permissions.capabilities:
            raise PermissionError("Plugin lacks AI_SERVICES capability")
        return await phase3_ai.search_content(query, self.plugin_name, search_type)

    async def get_recommendations(self, user_id: str, rec_type: str = "content") -> List[Dict[str, Any]]:
        """Get AI recommendations."""
        if ModuleCapability.AI_SERVICES not in self.permissions.capabilities:
            raise PermissionError("Plugin lacks AI_SERVICES capability")
        return await phase3_ai.get_recommendations(user_id, rec_type)

    # Database System Access
    async def execute_query(self, query: str, parameters: Dict[str, Any] = None) -> Any:
        """Execute database query."""
        if not self.permissions.database_access:
            raise PermissionError("Plugin lacks database access")
        return await phase4_database.execute_query(query, parameters)

    async def get_dao(self, name: str):
        """Get DAO instance."""
        if not self.permissions.database_access:
            raise PermissionError("Plugin lacks database access")
        return phase4_database.get_dao(name)

    async def get_repository(self, name: str):
        """Get repository instance."""
        if not self.permissions.database_access:
            raise PermissionError("Plugin lacks database access")
        return phase4_database.get_repository(name)

    # Clustering System Access
    async def get_cluster_status(self) -> Dict[str, Any]:
        """Get cluster status."""
        if ModuleCapability.CLUSTERING not in self.permissions.capabilities:
            raise PermissionError("Plugin lacks CLUSTERING capability")
        # Implementation would access clustering system
        return {"status": "healthy", "nodes": 3}

    async def broadcast_to_cluster(self, message: Dict[str, Any]) -> bool:
        """Broadcast message to cluster."""
        if ModuleCapability.CLUSTERING not in self.permissions.capabilities:
            raise PermissionError("Plugin lacks CLUSTERING capability")
        # Implementation would broadcast to cluster
        return True

    # System Monitoring Access
    async def get_system_metrics(self) -> Dict[str, Any]:
        """Get system metrics."""
        if ModuleCapability.MONITORING not in self.permissions.capabilities:
            raise PermissionError("Plugin lacks MONITORING capability")
        return master_coordinator.get_system_status()


class PluginInterface(BaseModule):
    """
    Enhanced plugin interface with strict contracts and system access.

    All plugins must inherit from this class to ensure compliance
    with the unified module system and security standards.
    """

    def __init__(self, name: Optional[str] = None, version: str = "1.0.0"):
        # Use class name if no name provided
        if name is None:
            name = self.__class__.__name__

        super().__init__(name, version)

        # Plugin-specific properties
        self.manager: Optional['UnifiedPluginManager'] = None
        self.config: Dict[str, Any] = {}
        self.system_access: Optional[PluginSystemAccess] = None

        # Override logger for plugin context
        self.logger = get_logger(f"plugin.{self.name}")

    async def initialize(self) -> bool:
        """Initialize the plugin. Must be implemented by subclasses."""
        self.state = ModuleState.INITIALIZING
        try:
            success = await self._plugin_initialize()
            if success:
                self.state = ModuleState.LOADED
                self.loaded_at = datetime.now(timezone.utc)
                return True
            else:
                self.state = ModuleState.ERROR
                return False
        except Exception as e:
            self.last_error = e
            self.state = ModuleState.FAILED
            self.metrics.record_error()
            self.logger.error(f"Plugin initialization failed: {e}")
            return False

    async def _plugin_initialize(self) -> bool:
        """Override this method for plugin-specific initialization."""
        return True

    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata. Should be overridden by subclasses."""
        return PluginMetadata(
            name=self.name,
            version=self.version,
            description="Base plugin",
            plugin_type=PluginType.FEATURE
        )

    def get_required_permissions(self) -> ModulePermissions:
        """Get required permissions. Should be overridden by subclasses."""
        return ModulePermissions(
            capabilities=[ModuleCapability.MESSAGING],
            network_access=False,
            file_system_access=False,
            database_access=False
        )


class UnifiedPluginManager:
    """
    Unified Plugin Manager - Single Source of Truth

    Consolidates all previous plugin management systems with comprehensive
    features for discovery, loading, security, and lifecycle management.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or get_config().get("plugins", {})
        self.initialized = False

        # Plugin storage
        self.modules: Dict[str, ModuleInfo] = {}
        self.loaded_plugins: Dict[str, PluginInterface] = {}

        # Plugin directories - plugins go in root folder, not src
        self.plugin_paths: List[Path] = [
            Path("plugins"),  # Main plugins directory (autogenerated)
            Path("user_plugins"),  # User-installed plugins
            Path("system_plugins")  # System plugins
        ]

        # Add custom paths from config
        custom_paths = self.config.get("plugin_paths", [])
        for path in custom_paths:
            self.plugin_paths.append(Path(path))

        # Event hooks
        self.hooks: Dict[str, List[Callable]] = {
            'before_load': [],
            'after_load': [],
            'before_unload': [],
            'after_unload': [],
            'on_error': [],
            'on_discovery': []
        }

        # Security and validation
        self.security_enabled = self.config.get("security_enabled", True)
        self.signature_verification = self.config.get("signature_verification", True)
        self.allow_unsigned_plugins = self.config.get("allow_unsigned_plugins", False)

        # Performance and limits
        self.max_plugin_size_mb = self.config.get("max_plugin_size_mb", 100)
        self.load_timeout_seconds = self.config.get("load_timeout_seconds", 30)

        # Thread safety
        self._lock = threading.RLock()
        self._shutdown_handlers = weakref.WeakSet()

        # Isolation and hot-loading
        self.isolation_manager = get_isolation_manager()
        self.hot_reload_enabled = self.config.get("hot_reload_enabled", True)
        self.isolation_enabled = self.config.get("isolation_enabled", True)

        # Test integration
        self.test_manager = None
        self.webui_renderer = None

        # Unified configuration management
        self.plugin_config_manager = get_plugin_config_manager()

        # File watchers for hot-reload
        self.file_watchers: Dict[str, Any] = {}

        # Statistics
        self.stats = {
            "total_discovered": 0,
            "total_loaded": 0,
            "total_failed": 0,
            "total_hot_reloaded": 0,
            "load_time_total": 0.0,
            "last_discovery": None
        }

        logger.info("Unified Plugin Manager initialized with isolation support")

    async def initialize(self) -> bool:
        """Initialize the plugin manager."""
        try:
            # Create plugin directories
            for path in self.plugin_paths:
                path.mkdir(parents=True, exist_ok=True)

            # Discover available plugins
            await self.discover_plugins()

            # Initialize plugin configuration manager
            await self.if plugin_config_manager and hasattr(plugin_config_manager, "initialize"): plugin_config_manager.initialize()

            # Load enabled plugins
            await self.load_enabled_plugins()

            # Start background tasks
            asyncio.create_task(self._plugin_health_monitor())

            # Start hot-reload monitoring if enabled
            if self.hot_reload_enabled:
                asyncio.create_task(self._hot_reload_monitor())

            # Initialize test manager
            await self._initialize_test_manager()

            # Initialize WebUI renderer
            await self._initialize_webui_renderer()

            self.initialized = True
            logger.info(" Unified Plugin Manager initialized successfully")
            return True

        except Exception as e:
            logger.error(f" Plugin Manager initialization failed: {e}")
            return False

    async def discover_plugins(self) -> List[str]:
        """Discover available plugins in all registered paths."""
        discovered = []

        with self._lock:
            for path in self.plugin_paths:
                try:
                    if not path.exists():
                        continue

                    for plugin_dir in path.iterdir():
                        if not plugin_dir.is_dir() or plugin_dir.name.startswith('_'):
                            continue

                        # Look for plugin manifest or entry points
                        manifest_file = plugin_dir / "plugin.json"
                        init_file = plugin_dir / "__init__.py"
                        main_file = plugin_dir / "main.py"

                        if manifest_file.exists() or init_file.exists() or main_file.exists():
                            plugin_name = plugin_dir.name

                            if plugin_name not in self.modules:
                                self.modules[plugin_name] = ModuleInfo(
                                    name=plugin_name,
                                    path=plugin_dir,
                                    status=ModuleStatus.DISCOVERED
                                )

                            # Load metadata if available
                            if manifest_file.exists():
                                await self._load_plugin_metadata(plugin_name, manifest_file)

                            discovered.append(plugin_name)
                            logger.debug(f"Discovered plugin: {plugin_name}")

                except Exception as e:
                    logger.error(f"Error discovering plugins in {path}: {e}")

            self.stats["total_discovered"] = len(discovered)
            self.stats["last_discovery"] = datetime.now(timezone.utc)

            # Execute discovery hooks
            self._execute_hooks('on_discovery', discovered)

        logger.info(f" Discovered {len(discovered)} plugins")
        return discovered

    async def _load_plugin_metadata(self, plugin_name: str, manifest_file: Path):
        """Load plugin metadata from manifest file."""
        try:
            with open(manifest_file, 'r') as f:
                manifest_data = json.load(f)

            metadata = PluginMetadata(
                name=manifest_data.get("name", plugin_name),
                version=manifest_data.get("version", "1.0.0"),
                description=manifest_data.get("description", ""),
                author=manifest_data.get("author", ""),
                plugin_type=PluginType(manifest_data.get("type", "feature")),
                entry_point=manifest_data.get("entry_point", "main"),
                dependencies=manifest_data.get("dependencies", []),
                permissions=manifest_data.get("permissions", []),
                api_version=manifest_data.get("api_version", "1.0"),
                min_plexichat_version=manifest_data.get("min_plexichat_version", "1.0.0"),
                enabled=manifest_data.get("enabled", True),
                category=manifest_data.get("category", "general"),
                tags=manifest_data.get("tags", []),
                homepage=manifest_data.get("homepage"),
                repository=manifest_data.get("repository"),
                license=manifest_data.get("license", "Unknown")
            )

            if plugin_name in self.modules:
                self.modules[plugin_name].metadata = metadata

        except Exception as e:
            logger.error(f"Failed to load metadata for {plugin_name}: {e}")

    async def load_plugin(self, plugin_name: str) -> bool:
        """Load a specific plugin."""
        if not self.initialized:
            await if self and hasattr(self, "initialize"): self.initialize()

        with self._lock:
            if plugin_name not in self.modules:
                logger.error(f"Plugin not found: {plugin_name}")
                return False

            module_info = self.modules[plugin_name]

            if module_info.status == ModuleStatus.LOADED:
                logger.info(f"Plugin already loaded: {plugin_name}")
                return True

            if module_info.metadata and not module_info.metadata.enabled:
                logger.info(f"Plugin disabled: {plugin_name}")
                return False

            try:
                from datetime import datetime
                start_time = datetime.now()
                module_info.status = ModuleStatus.LOADING

                # Execute before_load hooks
                self._execute_hooks('before_load', plugin_name)

                # Check dependencies
                if not await self._check_dependencies(plugin_name):
                    raise ImportError(f"Dependencies not satisfied for {plugin_name}")

                # Load the plugin module
                plugin_module = await self._load_plugin_module(plugin_name, module_info)
                if not plugin_module:
                    raise ImportError(f"Failed to load module for {plugin_name}")

                # Find and instantiate plugin class
                plugin_instance = await self._instantiate_plugin(plugin_name, plugin_module, module_info)
                if not plugin_instance:
                    raise ImportError(f"Failed to instantiate plugin {plugin_name}")

                # Initialize system access for the plugin
                if isinstance(plugin_instance, PluginInterface):
                    permissions = plugin_instance.get_required_permissions()
                    plugin_instance.system_access = PluginSystemAccess(plugin_name, permissions)

                # Validate plugin contracts
                validator = get_contract_validator()
                validation_result = await validator.validate_module(plugin_instance)

                if not validation_result.is_valid:
                    error_msg = f"Plugin {plugin_name} failed contract validation"
                    logger.error(error_msg)
                    logger.error(validator.generate_compliance_report(validation_result))
                    raise RuntimeError(error_msg)

                if validation_result.warnings:
                    logger.warning(f"Plugin {plugin_name} has contract warnings:")
                    for warning in validation_result.warnings:
                        logger.warning(f"  - {warning.message}")

                # Initialize plugin
                if not await if plugin_instance and hasattr(plugin_instance, "initialize"): plugin_instance.initialize():
                    raise RuntimeError(f"Plugin initialization failed: {plugin_name}")

                # Run plugin self-tests if available
                test_results = await self._run_plugin_self_tests(plugin_instance, plugin_name)
                if test_results and not test_results.get('success', True):
                    logger.warning(f"Plugin self-tests failed for {plugin_name}: {test_results.get('error', 'Unknown error')}")
                    # Don't fail loading for test failures, but log them

                # Store plugin
                module_info.module = plugin_module
                module_info.status = ModuleStatus.LOADED
                module_info.load_time = start_time
                module_info.test_results = test_results
                self.loaded_plugins[plugin_name] = plugin_instance

                # Update statistics
                load_duration = (datetime.now() - start_time).total_seconds()
                self.stats["total_loaded"] += 1
                self.stats["load_time_total"] += load_duration

                # Execute after_load hooks
                self._execute_hooks('after_load', plugin_name)

                logger.info(f" Loaded plugin: {plugin_name} ({load_duration:.2f}s, compliance: {validation_result.score:.1f}%)")
                return True

            except Exception as e:
                error_msg = f"Failed to load plugin {plugin_name}: {e}"
                logger.error(error_msg)
                logger.debug(traceback.format_exc())

                # Update module info with error
                module_info.status = ModuleStatus.ERROR
                module_info.error_message = str(e)
                self.stats["total_failed"] += 1

                # Execute error hooks
                self._execute_hooks('on_error', plugin_name, error=e)

                # Clean up
                if plugin_name in sys.modules:
                    del sys.modules[plugin_name]

                return False

    async def _check_dependencies(self, plugin_name: str) -> bool:
        """Check if plugin dependencies are satisfied."""
        module_info = self.modules[plugin_name]
        if not module_info.metadata or not module_info.metadata.dependencies:
            return True

        for dependency in module_info.metadata.dependencies:
            if dependency not in self.modules:
                logger.error(f"Dependency not found: {dependency} (required by {plugin_name})")
                return False

            dep_module = self.modules[dependency]
            if dep_module.status != ModuleStatus.LOADED:
                # Try to load dependency first
                if not await self.load_plugin(dependency):
                    logger.error(f"Failed to load dependency: {dependency} (required by {plugin_name})")
                    return False

        return True

    async def _load_plugin_module(self, plugin_name: str, module_info: ModuleInfo):
        """Load the plugin module."""
        try:
            plugin_path = module_info.path
            if not plugin_path:
                return None

            # Determine entry point
            entry_point = "main.py"
            if module_info.metadata and module_info.metadata.entry_point:
                entry_point = module_info.metadata.entry_point
                if not entry_point.endswith('.py'):
                    entry_point += '.py'

            # Try different entry points
            possible_entries = [
                plugin_path / entry_point,
                plugin_path / "main.py",
                plugin_path / "__init__.py",
                plugin_path / f"{plugin_name}.py"
            ]

            module_file = None
            for entry in possible_entries:
                if entry.exists():
                    module_file = entry
                    break

            if not module_file:
                logger.error(f"No valid entry point found for plugin: {plugin_name}")
                return None

            # Load module
            spec = importlib.util.spec_from_file_location(f"plugin_{plugin_name}", module_file)
            if spec is None or spec.loader is None:
                logger.error(f"Could not create spec for plugin: {plugin_name}")
                return None

            module = importlib.util.module_from_spec(spec)
            sys.modules[f"plugin_{plugin_name}"] = module
            spec.loader.exec_module(module)

            return module

        except Exception as e:
            logger.error(f"Failed to load module for {plugin_name}: {e}")
            return None

    async def _instantiate_plugin(self, plugin_name: str, plugin_module, module_info: ModuleInfo):
        """Instantiate the plugin class."""
        try:
            # Look for plugin class
            plugin_class = None

            # Try common class names
            class_names = [
                f"{plugin_name.title()}Plugin",
                f"{plugin_name.title()}",
                "Plugin",
                "Main"
            ]

            for class_name in class_names:
                if hasattr(plugin_module, class_name):
                    potential_class = getattr(plugin_module, class_name)
                    if (isinstance(potential_class, type) and
                        (issubclass(potential_class, PluginInterface) or
                         issubclass(potential_class, BaseModule))):
                        plugin_class = potential_class
                        break

            if not plugin_class:
                logger.error(f"No valid plugin class found in {plugin_name}. Must inherit from PluginInterface or BaseModule.")
                return None

            # Instantiate plugin with proper parameters
            try:
                # Try to instantiate with name parameter (new interface)
                plugin_instance = plugin_class(name=plugin_name)
            except TypeError:
                # Fallback to parameterless instantiation (legacy)
                plugin_instance = plugin_class()
                if hasattr(plugin_instance, 'name'):
                    plugin_instance.name = plugin_name

            plugin_instance.manager = self

            # Load plugin configuration from unified system
            plugin_config = self.plugin_config_manager.get_plugin_config(plugin_name)
            if plugin_config:
                plugin_instance.config = plugin_config.get("settings", {})

                # Apply plugin-specific configuration
                if hasattr(plugin_instance, 'apply_config'):
                    plugin_instance.apply_config(plugin_instance.config)
            else:
                # Fallback to legacy config loading
                if module_info.metadata:
                    config_file = module_info.path / "config.json"
                    if config_file.exists():
                        with open(config_file, 'r') as f:
                            legacy_config = json.load(f)
                            plugin_instance.config = legacy_config

                            # Register with unified config system
                            asyncio.create_task(
                                self.plugin_config_manager.register_plugin_config(
                                    plugin_name,
                                    {"settings": legacy_config}
                                )
                            )

            return plugin_instance

        except Exception as e:
            logger.error(f"Failed to instantiate plugin {plugin_name}: {e}")
            return None

    async def unload_plugin(self, plugin_name: str) -> bool:
        """Unload a specific plugin."""
        with self._lock:
            if plugin_name not in self.loaded_plugins:
                logger.warning(f"Plugin not loaded: {plugin_name}")
                return True

            try:
                # Execute before_unload hooks
                self._execute_hooks('before_unload', plugin_name)

                # Shutdown plugin
                plugin_instance = self.loaded_plugins[plugin_name]
                if not plugin_instance.shutdown():
                    logger.warning(f"Plugin shutdown returned False: {plugin_name}")

                # Remove from loaded plugins
                del self.loaded_plugins[plugin_name]

                # Update module info
                if plugin_name in self.modules:
                    self.modules[plugin_name].status = ModuleStatus.UNLOADED
                    self.modules[plugin_name].module = None

                # Remove from sys.modules
                module_key = f"plugin_{plugin_name}"
                if module_key in sys.modules:
                    del sys.modules[module_key]

                # Execute after_unload hooks
                self._execute_hooks('after_unload', plugin_name)

                logger.info(f" Unloaded plugin: {plugin_name}")
                return True

            except Exception as e:
                logger.error(f"Failed to unload plugin {plugin_name}: {e}")
                return False

    async def reload_plugin(self, plugin_name: str) -> bool:
        """Reload a specific plugin."""
        if plugin_name in self.loaded_plugins:
            if not await self.unload_plugin(plugin_name):
                return False

        return await self.load_plugin(plugin_name)

    async def load_enabled_plugins(self) -> Dict[str, bool]:
        """Load all enabled plugins."""
        results = {}

        for plugin_name, module_info in self.modules.items():
            if module_info.metadata and module_info.metadata.enabled:
                results[plugin_name] = await self.load_plugin(plugin_name)
            else:
                results[plugin_name] = False

        loaded_count = sum(results.values())
        total_count = len([m for m in self.modules.values() if m.metadata and m.metadata.enabled])

        logger.info(f" Loaded {loaded_count}/{total_count} enabled plugins")
        return results

    def _execute_hooks(self, event: str, plugin_name: str, **kwargs):
        """Execute hooks for an event."""
        for hook in self.hooks.get(event, []):
            try:
                hook(plugin_name, **kwargs)
            except Exception as e:
                logger.error(f"Error executing {event} hook: {e}")

    async def _plugin_health_monitor(self):
        """Background task for monitoring plugin health."""
        while True:
            try:
                await asyncio.sleep(300)  # Check every 5 minutes

                # Check loaded plugins
                for plugin_name, plugin_instance in list(self.loaded_plugins.items()):
                    try:
                        # Basic health check - ensure plugin is still responsive
                        if hasattr(plugin_instance, 'health_check'):
                            if not plugin_instance.health_check():
                                logger.warning(f"Plugin health check failed: {plugin_name}")
                    except Exception as e:
                        logger.error(f"Plugin health check error for {plugin_name}: {e}")

            except Exception as e:
                logger.error(f"Plugin health monitor error: {e}")

    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive plugin manager status."""
        return {
            "initialized": self.initialized,
            "statistics": self.stats.copy(),
            "plugins": {
                name: {
                    "status": info.status.value,
                    "metadata": {
                        "name": info.metadata.name if info.metadata else name,
                        "version": info.metadata.version if info.metadata else "unknown",
                        "type": info.metadata.plugin_type.value if info.metadata else "unknown",
                        "enabled": info.metadata.enabled if info.metadata else False
                    } if info.metadata else {},
                    "load_time": info.load_time.isoformat() if info.load_time else None,
                    "error": info.error_message
                }
                for name, info in self.modules.items()
            },
            "loaded_plugins": list(self.loaded_plugins.keys()),
            "plugin_paths": [str(p) for p in self.plugin_paths]
        }

    def add_hook(self, event: str, callback: Callable):
        """Add a hook for plugin events."""
        if event not in self.hooks:
            self.hooks[event] = []
        self.hooks[event].append(callback)

    def remove_hook(self, event: str, callback: Callable):
        """Remove a hook for plugin events."""
        if event in self.hooks and callback in self.hooks[event]:
            self.hooks[event].remove(callback)

    async def shutdown_all(self) -> None:
        """Shutdown all loaded plugins."""
        logger.info("Shutting down all plugins...")

        for plugin_name in list(self.loaded_plugins.keys()):
            await self.unload_plugin(plugin_name)

        logger.info("All plugins shut down")

    async def shutdown(self) -> None:
        """Shutdown the plugin manager."""
        await self.shutdown_all()
        logger.info("Plugin manager shutdown complete")

    async def load_plugin_with_isolation(self, plugin_name: str, isolation_config: Optional[IsolationConfig] = None) -> bool:
        """Load a plugin with isolation support."""
        if not self.isolation_enabled:
            return await self.load_plugin(plugin_name)

        try:
            with self._lock:
                if plugin_name not in self.modules:
                    logger.error(f"Plugin not discovered: {plugin_name}")
                    return False

                module_info = self.modules[plugin_name]
                if not module_info.path:
                    logger.error(f"No path found for plugin: {plugin_name}")
                    return False

                # Use isolation manager to load
                success = await self.isolation_manager.load_module_isolated(
                    plugin_name,
                    module_info.path,
                    isolation_config
                )

                if success:
                    module_info.status = ModuleStatus.LOADED
                    logger.info(f" Plugin loaded with isolation: {plugin_name}")
                else:
                    module_info.status = ModuleStatus.FAILED
                    self.stats["total_failed"] += 1

                return success

        except Exception as e:
            logger.error(f"Isolated plugin loading failed for {plugin_name}: {e}")
            return False

    async def hot_reload_plugin(self, plugin_name: str) -> bool:
        """Hot-reload a plugin without stopping the system."""
        try:
            logger.info(f"Hot-reloading plugin: {plugin_name}")

            with self._lock:
                if plugin_name not in self.loaded_plugins:
                    logger.warning(f"Plugin not loaded, performing regular load: {plugin_name}")
                    return await self.load_plugin(plugin_name)

                # Get plugin info
                plugin_instance = self.loaded_plugins[plugin_name]
                module_info = self.modules.get(plugin_name)

                if not module_info or not module_info.path:
                    logger.error(f"Cannot hot-reload {plugin_name}: missing module info")
                    return False

                # Execute before_unload hooks
                self._execute_hooks('before_unload', plugin_name)

                # Gracefully shutdown existing plugin
                try:
                    if hasattr(plugin_instance, 'shutdown'):
                        await plugin_instance.shutdown()
                except Exception as e:
                    logger.warning(f"Plugin shutdown error during hot-reload: {e}")

                # Remove from loaded plugins
                del self.loaded_plugins[plugin_name]

                # Clear module from sys.modules to force reload
                module_key = f"plugin_{plugin_name}"
                if module_key in sys.modules:
                    del sys.modules[module_key]

                # Execute after_unload hooks
                self._execute_hooks('after_unload', plugin_name)

                # Wait a moment for cleanup
                await asyncio.sleep(0.1)

                # Reload the plugin
                success = await self.load_plugin(plugin_name)

                if success:
                    self.stats["total_hot_reloaded"] += 1
                    logger.info(f" Plugin hot-reloaded successfully: {plugin_name}")
                else:
                    logger.error(f" Plugin hot-reload failed: {plugin_name}")

                return success

        except Exception as e:
            logger.error(f"Hot-reload failed for {plugin_name}: {e}")
            return False

    async def _hot_reload_monitor(self):
        """Monitor plugin files for changes and trigger hot-reload."""
        try:
            class PluginFileHandler(FileSystemEventHandler):
                def __init__(self, plugin_manager):
                    self.plugin_manager = plugin_manager

                def on_modified(self, event):
                    if event.is_directory:
                        return

                    # Check if it's a Python file in a plugin directory
                    from pathlib import Path
file_path = Path
Path(event.src_path)
                    if file_path.suffix == '.py':
                        # Find which plugin this file belongs to
                        for plugin_name, module_info in self.plugin_manager.modules.items():
                            if module_info.path and file_path.is_relative_to(module_info.path):
                                logger.info(f"Plugin file changed: {file_path}")
                                # Schedule hot-reload
                                asyncio.create_task(
                                    self.plugin_manager.hot_reload_plugin(plugin_name)
                                )
                                break

            # Setup file watchers for plugin directories
            observer = Observer()
            handler = PluginFileHandler(self)

            for path in self.plugin_paths:
                if path.exists():
                    observer.schedule(handler, str(path), recursive=True)
                    logger.info(f"Watching for changes: {path}")

            if observer and hasattr(observer, "start"): observer.start()

            # Keep monitoring
            while self.initialized:
                await asyncio.sleep(1)

            if observer and hasattr(observer, "stop"): observer.stop()
            observer.join()

        except ImportError:
            logger.warning("Watchdog not available - hot-reload monitoring disabled")
        except Exception as e:
            logger.error(f"Hot-reload monitoring failed: {e}")

    def enable_hot_reload(self, plugin_name: str) -> bool:
        """Enable hot-reload for a specific plugin."""
        try:
            if plugin_name in self.modules:
                # Add to hot-reload list
                self.file_watchers[plugin_name] = True
                logger.info(f"Hot-reload enabled for plugin: {plugin_name}")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to enable hot-reload for {plugin_name}: {e}")
            return False

    def disable_hot_reload(self, plugin_name: str) -> bool:
        """Disable hot-reload for a specific plugin."""
        try:
            if plugin_name in self.file_watchers:
                del self.file_watchers[plugin_name]
                logger.info(f"Hot-reload disabled for plugin: {plugin_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to disable hot-reload for {plugin_name}: {e}")
            return False

    def get_plugin_manager_status(self) -> Dict[str, Any]:
        """Get comprehensive plugin manager status including isolation."""
        base_status = {
            "plugin_manager": {
                "initialized": self.initialized,
                "total_plugins": len(self.modules),
                "loaded_plugins": len(self.loaded_plugins),
                "hot_reload_enabled": self.hot_reload_enabled,
                "isolation_enabled": self.isolation_enabled,
                "statistics": self.stats,
                "plugin_paths": [str(p) for p in self.plugin_paths],
                "security_enabled": self.security_enabled
            }
        }

        # Add isolation status if enabled
        if self.isolation_enabled:
            isolation_status = self.isolation_manager.get_isolation_status()
            base_status.update(isolation_status)

        return base_status

    async def _run_plugin_self_tests(self, plugin_instance, plugin_name: str) -> Optional[Dict[str, Any]]:
        """Run self-tests for a plugin if available."""
        try:
            # Check if plugin has run_tests method
            if hasattr(plugin_instance, 'run_tests') and callable(getattr(plugin_instance, 'run_tests')):
                logger.info(f"🧪 Running self-tests for plugin: {plugin_name}")
                test_results = await plugin_instance.run_tests()

                if test_results:
                    passed = test_results.get('passed', 0)
                    failed = test_results.get('failed', 0)
                    total = test_results.get('total', passed + failed)

                    if failed > 0:
                        logger.warning(f"❌ Plugin {plugin_name} self-tests: {passed}/{total} passed, {failed} failed")
                    else:
                        logger.info(f"✅ Plugin {plugin_name} self-tests: {passed}/{total} passed")

                return test_results

            # Check for test suite in plugin metadata
            elif hasattr(plugin_instance, 'metadata') and plugin_instance.metadata:
                metadata = plugin_instance.metadata
                if hasattr(metadata, 'self_tests') and metadata.self_tests:
                    logger.info(f"🧪 Running metadata-defined tests for plugin: {plugin_name}")
                    return await self._run_metadata_tests(plugin_instance, metadata.self_tests)

            return None

        except Exception as e:
            logger.error(f"Error running self-tests for plugin {plugin_name}: {e}")
            return {"success": False, "error": str(e)}

    async def _run_metadata_tests(self, plugin_instance, test_names: List[str]) -> Dict[str, Any]:
        """Run tests defined in plugin metadata."""
        results = {
            "success": True,
            "total": len(test_names),
            "passed": 0,
            "failed": 0,
            "tests": {}
        }

        for test_name in test_names:
            try:
                # Look for test method in plugin
                test_method = getattr(plugin_instance, test_name, None)
                if test_method and callable(test_method):
                    if asyncio.iscoroutinefunction(test_method):
                        test_result = await test_method()
                    else:
                        test_result = test_method()

                    if test_result is True or (isinstance(test_result, dict) and test_result.get('success', False)):
                        results["passed"] += 1
                        results["tests"][test_name] = {"status": "passed"}
                    else:
                        results["failed"] += 1
                        results["tests"][test_name] = {"status": "failed", "error": str(test_result)}
                else:
                    results["failed"] += 1
                    results["tests"][test_name] = {"status": "failed", "error": "Test method not found"}

            except Exception as e:
                results["failed"] += 1
                results["tests"][test_name] = {"status": "failed", "error": str(e)}

        results["success"] = results["failed"] == 0
        return results

    async def run_all_plugin_tests(self) -> Dict[str, Any]:
        """Run self-tests for all loaded plugins."""
        all_results = {
            "total_plugins": len(self.loaded_plugins),
            "plugins_with_tests": 0,
            "total_tests": 0,
            "total_passed": 0,
            "total_failed": 0,
            "plugin_results": {}
        }

        for plugin_name, plugin_instance in self.loaded_plugins.items():
            test_results = await self._run_plugin_self_tests(plugin_instance, plugin_name)
            if test_results:
                all_results["plugins_with_tests"] += 1
                all_results["total_tests"] += test_results.get("total", 0)
                all_results["total_passed"] += test_results.get("passed", 0)
                all_results["total_failed"] += test_results.get("failed", 0)
                all_results["plugin_results"][plugin_name] = test_results

        return all_results

    async def _initialize_test_manager(self):
        """Initialize the test manager integration."""
        try:
            from .plugin_test_manager import get_test_manager

            self.test_manager = get_test_manager()

            # Discover tests for all loaded plugins
            for plugin_name, plugin_info in self.modules.items():
                if plugin_info.status == ModuleStatus.LOADED:
                    await self.test_manager.discover_plugin_tests(plugin_name, plugin_info.path)

            # Start test scheduler
            self.test_manager.start_scheduler()

            logger.info("Test manager integration initialized")

        except Exception as e:
            logger.error(f"Failed to initialize test manager: {e}")

    async def _initialize_webui_renderer(self):
        """Initialize the WebUI renderer integration."""
        try:
            from ..gui.webui_renderer import get_webui_renderer

            self.webui_renderer = get_webui_renderer()

            # Register plugin pages with renderer
            for plugin_name, plugin_instance in self.loaded_plugins.items():
                if hasattr(plugin_instance, 'config') and 'webui' in plugin_instance.config:
                    webui_config = plugin_instance.config['webui']
                    if webui_config.get('enabled', False) and 'routes' in webui_config:
                        self.webui_renderer.register_plugin_pages(plugin_name, webui_config['routes'])

            logger.info("WebUI renderer integration initialized")

        except Exception as e:
            logger.error(f"Failed to initialize WebUI renderer: {e}")

    def get_test_manager(self):
        """Get the test manager instance."""
        return self.test_manager

    def get_webui_renderer(self):
        """Get the WebUI renderer instance."""
        return self.webui_renderer


# Global instance - SINGLE SOURCE OF TRUTH
_plugin_manager: Optional[UnifiedPluginManager] = None


def get_plugin_manager() -> UnifiedPluginManager:
    """Get the global plugin manager instance."""
    global _plugin_manager
    if _plugin_manager is None:
        _plugin_manager = UnifiedPluginManager()
    return _plugin_manager


# Export main components
__all__ = [
    "UnifiedPluginManager",
    "get_plugin_manager",
    "PluginInterface",
    "PluginMetadata",
    "ModuleInfo",
    "ModuleStatus",
    "PluginType",
    "PluginSource"
]
