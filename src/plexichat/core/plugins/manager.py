"""
PlexiChat Plugin Manager - SINGLE SOURCE OF TRUTH

Consolidates ALL plugin management functionality.

Provides a single, unified interface for all plugin operations.
"""

import asyncio
import importlib
import importlib.util
import json
import logging
import shutil
import sys
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Union

# Import shared components (with fallbacks)
try:
    from src.plexichat.shared.models import Event, Plugin, Priority, Status
except ImportError:
    # Create placeholder classes
    class Plugin:
        pass

    class Event:
        pass

    class Priority:
        pass

    class Status:
        pass


try:
    from src.plexichat.shared.types import PluginConfig, PluginId, PluginResult
except ImportError:
    # Use basic types as fallbacks
    PluginId = str
    PluginConfig = dict
    PluginResult = dict

try:
    from src.plexichat.shared.exceptions import (
        PluginError,
        SecurityError,
        ValidationError,
    )
except ImportError:
    # Create basic exception classes
    class PluginError(Exception):
        pass

    class ValidationError(Exception):
        pass

    class SecurityError(Exception):
        pass


try:
    from src.plexichat.core.unified_config import (
        get_max_plugin_memory,
        get_plugin_sandbox_enabled,
        get_plugin_timeout,
    )
except ImportError:
    # Provide default functions
    def get_plugin_timeout():
        return 30

    def get_max_plugin_memory():
        return 100 * 1024 * 1024  # 100MB

    def get_plugin_sandbox_enabled():
        return True


# Core imports (with fallbacks)
try:
    from src.plexichat.core.database.manager import database_manager
except ImportError:
    database_manager = None

# SDK generator - ensure plugins_internal exists
try:
    from src.plexichat.core.plugins.sdk_generator import (
        generate_plugins_internal,
        regenerate_plugins_internal_if_needed,
        sdk_generator,
    )
except ImportError:
    sdk_generator = None
    regenerate_plugins_internal_if_needed = None
    generate_plugins_internal = None

# Security manager integration
try:
    from src.plexichat.core.plugins.security_manager import (
        PermissionType,
        PluginSecurityManager,
        create_plugin_sandbox,
        get_security_manager,
        plugin_security_manager,
    )
except ImportError:
    plugin_security_manager = None
    get_security_manager = None
    create_plugin_sandbox = None
    PluginSecurityManager = None
    PermissionType = None

# Enhanced plugin systems (optional)
plugin_security = None
plugin_dependency_manager = None
EnhancedSecurityLevel = None

# Top-level imports for AI integration (with fallbacks)
intelligent_assistant = None
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
    ANALYTICS = "analytics"
    AI_PROVIDER = "ai_provider"
    TESTING = "testing"
    DEVELOPMENT = "development"
    UTILITY = "utility"
    NOTIFICATION = "notification"
    MONITORING = "monitoring"
    BACKUP = "backup"
    SYSTEM = "system"
    SECURITY_NODE = "security_node"
    USER_MANAGEMENT = "user_management"
    AUTOMATION = "automation"
    SECURITY = "security"


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
    QUARANTINED = "quarantined"


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
    def from_dict(cls, data: Dict[str, Any]) -> "PluginMetadata":
        """Create metadata from dictionary."""
        # Defensive conversion for security level and plugin type
        sec_level = data.get("security_level", "sandboxed")
        try:
            sec_enum = SecurityLevel(sec_level)
        except Exception:
            sec_enum = SecurityLevel.SANDBOXED

        try:
            ptype = PluginType(data.get("type", "feature"))
        except Exception:
            ptype = PluginType.FEATURE

        return cls(
            name=data.get("name", ""),
            version=data.get("version", "1.0.0"),
            description=data.get("description", ""),
            author=data.get("author", ""),
            plugin_type=ptype,
            security_level=sec_enum,
            dependencies=data.get("dependencies", []),
            permissions=data.get("permissions", []),
            enabled=data.get("enabled", False),
            auto_load=data.get("auto_load", False),
            checksum=data.get("checksum"),
            homepage=data.get("homepage"),
            repository=data.get("repository"),
            license=data.get("license"),
            tags=data.get("tags", []),
            min_plexichat_version=data.get("min_plexichat_version"),
            max_plexichat_version=data.get("max_plexichat_version"),
            config_schema=data.get("config_schema"),
            priority=data.get("priority", 5),  # Use int
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


# The PluginInterface is now defined in this file.
# This manager will work with plugins that inherit from BasePlugin.



class PluginIsolationManager:
    """Manages plugin isolation and sandboxing."""

    def __init__(self):
        self.isolated_modules: Dict[str, Any] = {}
        self.resource_limits: Dict[str, Dict[str, Any]] = {}
        self.plugin_module_permissions: Dict[str, Set[str]] = (
            {}
        )  # New: track allowed modules per plugin
        self.plugin_module_requests: Dict[str, Set[str]] = (
            {}
        )  # New: track requested modules per plugin

    async def load_module_isolated(
        self,
        plugin_name: str,
        plugin_path: Path,
        config: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Load a module in isolation with enhanced sandboxing."""
        try:
            # Set plugin name in thread context for sandboxing
            threading.current_thread().plugin_name = plugin_name

            # Set resource limits
            if config and "resource_limits" in config:
                self.resource_limits[plugin_name] = config["resource_limits"]

            # Create plugin-specific directories
            plugin_dirs = [
                Path(f"logs/plugin/{plugin_name}"),
                Path(f"logs/plugins/{plugin_name}"),
                Path(f"plugins/{plugin_name}/logs"),
                Path(f"plugins/{plugin_name}/data"),
                Path(f"plugins/{plugin_name}/cache"),
                Path(f"plugins/{plugin_name}/temp"),
            ]

            for plugin_dir in plugin_dirs:
                plugin_dir.mkdir(parents=True, exist_ok=True)

            # Load module with restricted imports
            spec = importlib.util.spec_from_file_location(
                f"isolated_{plugin_name}", (plugin_path / "main.py").resolve()
            )

            if spec is None or spec.loader is None:
                return False

            module = importlib.util.module_from_spec(spec)

            # Ensure __builtins__ exists before modification
            if not hasattr(module, "__builtins__"):
                module.__builtins__ = {}

            # Restrict module access with enhanced sandboxing
            restricted_builtins = {
                "__import__": self._restricted_import,
                "open": self._restricted_open,
                "exec": self._restricted_exec,
                "eval": self._restricted_eval,
                # Essential built-in exceptions
                "Exception": Exception,
                "ImportError": ImportError,
                "ValueError": ValueError,
                "TypeError": TypeError,
                "AttributeError": AttributeError,
                "KeyError": KeyError,
                "IndexError": IndexError,
                "FileNotFoundError": FileNotFoundError,
                "OSError": OSError,
                "RuntimeError": RuntimeError,
                "NotImplementedError": NotImplementedError,
                # Essential built-in functions
                "len": len,
                "str": str,
                "int": int,
                "float": float,
                "bool": bool,
                "list": list,
                "dict": dict,
                "tuple": tuple,
                "set": set,
                "print": print,
                "range": range,
                "enumerate": enumerate,
                "zip": zip,
                "isinstance": isinstance,
                "hasattr": hasattr,
                "getattr": getattr,
                "setattr": setattr,
                "delattr": delattr,
                # Mathematical and utility functions
                "sum": sum,
                "max": max,
                "min": min,
                "abs": abs,
                "round": round,
                "pow": pow,
                "divmod": divmod,
                "any": any,
                "all": all,
                "map": map,
                "filter": filter,
                "sorted": sorted,
                "reversed": reversed,
                "dir": dir,
                "vars": vars,
                "id": id,
                "hash": hash,
                "repr": repr,
                "ascii": ascii,
                "ord": ord,
                "chr": chr,
                "bin": bin,
                "oct": oct,
                "hex": hex,
                "format": format,
                "iter": iter,
                "next": next,
                "slice": slice,
                "callable": callable,
                "issubclass": issubclass,
                "bytes": bytes,
                "bytearray": bytearray,
                "memoryview": memoryview,
                "complex": complex,
                "frozenset": frozenset,
                # Essential Python internals
                "__build_class__": (
                    __builtins__["__build_class__"]
                    if "__build_class__" in __builtins__
                    else None
                ),
                "__name__": "__main__",
                "staticmethod": staticmethod,
                "classmethod": classmethod,
                "property": property,
                "super": super,
                "type": type,
                "object": object,
            }

            # Update only available builtins to avoid KeyErrors
            for k, v in list(restricted_builtins.items()):
                if v is None:
                    restricted_builtins.pop(k, None)

            module.__builtins__.update(restricted_builtins)

            # Execute module in sandboxed environment
            spec.loader.exec_module(module)

            self.isolated_modules[plugin_name] = module

            # Log successful sandboxed loading
            try:
                from src.plexichat.core.logging import get_logger

                sandbox_logger = get_logger(f"plugin.{plugin_name}.sandbox")
                sandbox_logger.info(
                    f"Plugin '{plugin_name}' loaded in sandboxed environment"
                )
            except ImportError:
                pass

            return True

        except Exception as e:
            logger.error(f"Failed to load isolated module {plugin_name}: {e}")
            return False
        finally:
            # Clean up thread context
            if hasattr(threading.current_thread(), "plugin_name"):
                delattr(threading.current_thread(), "plugin_name")

    def _restricted_import(self, name, *args, **kwargs):
        """Restricted import function with dynamic permission system."""
        # Baseline allowlist
        allowed_modules = {
            "json",
            "datetime",
            "typing",
            "dataclasses",
            "enum",
            "asyncio",
            "logging",
            "pathlib",
            "uuid",
            "time",
            "base64",
            "mimetypes",
            "ast",
            "secrets",
            "io",
            "re",
            "hashlib",
            "functools",
            "itertools",
            "collections",
            "math",
            "random",
            "copy",
            "types",
            "inspect",
            "traceback",
        }
        # Dynamic per-plugin allowlist (populated by admin/cli approval)
        plugin_name = getattr(threading.current_thread(), "plugin_name", None)
        extra_allowed = set()
        if plugin_name and hasattr(self, "plugin_module_permissions"):
            extra_allowed = self.plugin_module_permissions.get(plugin_name, set())
        # Allow plexichat.* imports for plugins_internal & whitelisted modules
        if (
            name in allowed_modules
            or name in extra_allowed
            or name.startswith("plexichat.")
            or name == "plugins_internal"
        ):
            return __import__(name, *args, **kwargs)
        # Record the attempted import for admin review
        if plugin_name:
            if not hasattr(self, "plugin_module_requests"):
                self.plugin_module_requests = {}
            self.plugin_module_requests.setdefault(plugin_name, set()).add(name)
        raise ImportError(
            f"Import of '{name}' not allowed in sandboxed plugin. Admin approval required."
        )

    def _restricted_open(self, filename, mode="r", *args, **kwargs):
        """Restricted file open function - only allows access to plugin's own directory."""
        from pathlib import Path

        # Get current plugin name from thread context
        plugin_name = getattr(threading.current_thread(), "plugin_name", None)
        if not plugin_name:
            raise PermissionError("Plugin name not found in thread context")

        # Convert filename to absolute path
        file_path = Path(filename).resolve()

        # Define allowed directories for this plugin (relative to project root)
        project_root = Path(__file__).parent.parent.parent.parent.parent
        allowed_dirs = [
            (project_root / f"logs/plugin/{plugin_name}").resolve(),
            (project_root / f"logs/plugins/{plugin_name}").resolve(),
            (project_root / f"plugins/{plugin_name}/logs").resolve(),
            (project_root / f"plugins/{plugin_name}/data").resolve(),
            (project_root / f"plugins/{plugin_name}/cache").resolve(),
            (project_root / f"plugins/{plugin_name}/temp").resolve(),
        ]

        # Ensure plugin directories exist
        for allowed_dir in allowed_dirs:
            allowed_dir.mkdir(parents=True, exist_ok=True)

        # Check if file path is within allowed directories
        allowed = False
        for allowed_dir in allowed_dirs:
            try:
                file_path.relative_to(allowed_dir)
                allowed = True
                break
            except ValueError:
                continue

        if not allowed:
            raise PermissionError(
                f"Plugin '{plugin_name}' can only access files in: {[str(d) for d in allowed_dirs]}"
            )

        # Use existing logging system for plugin file operations
        try:
            from src.plexichat.core.logging import get_logger

            logger = get_logger(f"plugin.{plugin_name}.filesystem")
            logger.info(f"Plugin file access: {filename} (mode: {mode})")
        except ImportError:
            pass

        # Allow the file operation
        return open(filename, mode, *args, **kwargs)

    def _restricted_exec(self, *args, **kwargs):
        """Restricted exec function."""
        raise PermissionError("Dynamic code execution not allowed in sandboxed plugin")

    def _restricted_eval(self, *args, **kwargs):
        """Restricted eval function."""
        raise PermissionError("Dynamic code evaluation not allowed in sandboxed plugin")

    # --- Admin/CLI permission management stubs ---
    def grant_plugin_module_permission(self, plugin_name: str, module_name: str):
        if not hasattr(self, "plugin_module_permissions"):
            self.plugin_module_permissions = {}
        self.plugin_module_permissions.setdefault(plugin_name, set()).add(module_name)

    def revoke_plugin_module_permission(self, plugin_name: str, module_name: str):
        if hasattr(self, "plugin_module_permissions"):
            self.plugin_module_permissions.get(plugin_name, set()).discard(module_name)

    def get_plugin_module_requests(self, plugin_name: str = None):
        if not hasattr(self, "plugin_module_requests"):
            return {}
        if plugin_name:
            return {
                plugin_name: list(self.plugin_module_requests.get(plugin_name, set()))
            }
        return {k: list(v) for k, v in self.plugin_module_requests.items()}


class PluginTestManager:
    """Manages plugin testing."""

    def __init__(self):
        self.test_results: Dict[str, Dict[str, Any]] = {}
        self.logger = logging.getLogger(__name__)

    async def run_plugin_tests(
        self, plugin_name: str, plugin_instance: "PluginInterface"
    ) -> Dict[str, Any]:
        """Run tests for a specific plugin."""
        try:
            # Run plugin self-tests (if available)
            self_test_results = {}
            try:
                if hasattr(
                    plugin_instance, "self_test"
                ) and asyncio.iscoroutinefunction(plugin_instance.self_test):
                    self_test_results = await plugin_instance.self_test()
                elif hasattr(plugin_instance, "self_test"):
                    self_test_results = plugin_instance.self_test()
                else:
                    self_test_results = {
                        "passed": True,
                        "message": "No self-test provided",
                    }
            except Exception as e:
                self.logger.warning(f"Plugin self-test failed for {plugin_name}: {e}")
                self_test_results = {"passed": False, "error": str(e)}

            # Run external tests if available
            external_test_results = await self._run_external_tests(plugin_name)

            # Combine results
            results = {
                "plugin_name": plugin_name,
                "timestamp": datetime.now().isoformat(),
                "self_tests": self_test_results,
                "external_tests": external_test_results,
                "overall_passed": (
                    self_test_results.get("passed", False)
                    and external_test_results.get("passed", True)
                ),
            }

            self.test_results[plugin_name] = results
            return results

        except Exception as e:
            self.logger.error(f"Failed to run tests for plugin {plugin_name}: {e}")
            return {
                "plugin_name": plugin_name,
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
                "overall_passed": False,
            }

    async def _run_external_tests(self, plugin_name: str) -> Dict[str, Any]:
        """Run external tests for a plugin."""
        # Look for test files in plugin directory
        # This is a simplified implementation
        return {"passed": True, "tests": [], "message": "No external tests found"}


class PluginManager:
    """
    Plugin Manager - SINGLE SOURCE OF TRUTH

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
        self.logger = logging.getLogger(__name__)
        # Ensure plugins directory is relative to project root, not src
        if plugins_dir is None:
            project_root = Path(__file__).parent.parent.parent.parent.parent
            self.plugins_dir = project_root / "plugins"
        else:
            self.plugins_dir = plugins_dir
        self.plugins_dir.mkdir(exist_ok=True)

        # Plugin storage
        self.discovered_plugins: Set[str] = set()
        self.plugin_info: Dict[str, PluginInfo] = {}
        self.loaded_plugins: Dict[str, "PluginInterface"] = {}
        self.plugin_commands: Dict[str, Callable] = {}
        self.plugin_event_handlers: Dict[str, List[Callable]] = {}
        # --- New extension registries ---
        self.plugin_routers: Dict[str, Dict[str, Any]] = (
            {}
        )  # plugin_name -> {mount_path: router}
        self.plugin_db_extensions: Dict[str, Dict[str, Any]] = (
            {}
        )  # plugin_name -> {name: ext}
        self.plugin_security_features: Dict[str, Dict[str, Any]] = (
            {}
        )  # plugin_name -> {name: feature}
        self.plugin_docs: Dict[str, Dict[str, Any]] = {}

        # Add new fields for better error tracking
        self.plugin_errors: Dict[str, List[str]] = {}
        self.plugin_dependencies_graph: Dict[str, Set[str]] = {}
        self.plugin_load_order: List[str] = []
        self.plugin_load_times: Dict[str, float] = {}
        self.plugin_metrics: Dict[str, Dict[str, Any]] = {}

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

        # Auto-generate plugin SDK for sandboxing via core SDK generator if available.
        try:
            if regenerate_plugins_internal_if_needed:
                regenerate_plugins_internal_if_needed()
                self.logger.debug(
                    "plugins_internal generation requested via sdk_generator"
                )
            else:
                # Fallback to local generator
                self._generate_plugin_sdk()
        except Exception as e:
            self.logger.error(f"Error generating plugin SDK at init: {e}")

    def _generate_plugin_sdk(self):
        """Auto-generate the plugin SDK (plugins_internal.py) in plugins directory."""
        try:
            sdk_content = self._create_plugin_sdk_content()
            sdk_file = self.plugins_dir / "plugins_internal.py"

            # Ensure plugins directory exists
            self.plugins_dir.mkdir(exist_ok=True)

            with open(sdk_file, "w", encoding="utf-8") as f:
                f.write(sdk_content)
            self.logger.info(f"Generated plugin SDK (fallback): {sdk_file}")

        except Exception as e:
            self.logger.error(f"Failed to generate plugin SDK (fallback): {e}")

    def _create_plugin_sdk_content(self) -> str:
        """Create the content for the auto-generated plugin SDK."""
        # This SDK is simplified and provides a safe interface for plugins.
        # It prevents direct imports from the core application structure.
        return f'''"""
PlexiChat Plugin Internal SDK - Auto-Generated
==============================================
This file is automatically generated by the PlexiChat Plugin Manager.
DO NOT EDIT MANUALLY - Changes will be overwritten.

This SDK provides the core interfaces and utilities for developing PlexiChat plugins.
It acts as a secure bridge to the main application's core services.
"""

import logging
import json
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Callable

# Re-importing the core SDK classes to expose them to plugins
from src.plexichat.core.plugins.sdk import EnhancedBasePlugin, PluginConfig, PluginAPI

# This makes the core SDK classes available to plugins that `import plugins_internal`
__all__ = [
    'EnhancedBasePlugin',
    'PluginConfig',
    'PluginAPI',
]

# Auto-generated on: {datetime.now().isoformat()}
'''

    async def initialize(self) -> bool:
        """Initialize the plugin manager."""
        try:
            self.logger.info("Initializing unified plugin manager")

            # Discover plugins
            if self.auto_discover:
                await self.discover_plugins()

            # Load enabled plugins
            if self.auto_load_enabled:
                await self.load_enabled_plugins()

            self.logger.info("Unified plugin manager initialized successfully")
            return True

        except Exception as e:
            self.logger.error(f"Failed to initialize plugin manager: {e}")
            return False

    async def discover_plugins(self) -> List[str]:
        """Discover available plugins."""
        try:
            discovered = []

            with self._lock:
                # Scan plugins directory
                for plugin_dir in self.plugins_dir.iterdir():
                    if not plugin_dir.is_dir() or plugin_dir.name.startswith("_"):
                        continue

                    plugin_name = plugin_dir.name

                    # Look for plugin manifest
                    manifest_files = [
                        plugin_dir / "plugin.json",
                        plugin_dir / "plugin.yaml",
                        plugin_dir / "plugin.yml",
                        plugin_dir / "manifest.json",
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
                            plugin_dir / "__init__.py",
                        ]

                        for main_file in main_files:
                            if main_file.exists():
                                metadata = await self._create_default_metadata(
                                    plugin_name, plugin_dir
                                )
                                break

                    if metadata:
                        plugin_info = PluginInfo(
                            plugin_id=plugin_name,
                            metadata=metadata,
                            path=plugin_dir,
                            status=PluginStatus.DISCOVERED,
                        )

                        # Persist known disabled state if DB has it
                        if database_manager:
                            try:
                                # Try to read plugin_settings table if present
                                async with database_manager.get_session() as session:
                                    row = await session.fetchone(
                                        "SELECT enabled, admin_approved FROM plugin_settings WHERE plugin_name = :name",
                                        {"name": plugin_name},
                                    )
                                    if row:
                                        enabled = row.get("enabled", 0)
                                        admin_approved = row.get("admin_approved", 0)
                                        plugin_info.metadata.enabled = bool(
                                            enabled
                                        ) and bool(admin_approved)
                                        if enabled and not admin_approved:
                                            # Mark as awaiting admin approval
                                            plugin_info.status = PluginStatus.DISABLED
                            except Exception:
                                # Ignore DB read errors during discovery
                                pass

                        self.plugin_info[plugin_name] = plugin_info
                        self.discovered_plugins.add(plugin_name)
                        discovered.append(plugin_name)

                        self.logger.debug(f"Discovered plugin: {plugin_name}")

                self.stats["total_discovered"] = len(self.discovered_plugins)
                self.stats["last_discovery"] = datetime.now().isoformat()

            self.logger.info(f"Discovered {len(discovered)} plugins")
            return discovered

        except Exception as e:
            self.logger.error(f"Failed to discover plugins: {e}")
            return []

    async def _load_plugin_metadata(
        self, manifest_file: Path
    ) -> Optional[PluginMetadata]:
        """Load plugin metadata from manifest file."""
        try:
            with open(manifest_file, "r", encoding="utf-8") as f:
                if manifest_file.suffix in [".yaml", ".yml"]:
                    import yaml

                    data = yaml.safe_load(f)
                else:
                    data = json.load(f)

            return PluginMetadata.from_dict(data)

        except Exception as e:
            self.logger.error(f"Failed to load metadata from {manifest_file}: {e}")
            return None

    async def _create_default_metadata(
        self, plugin_name: str, plugin_dir: Path
    ) -> PluginMetadata:
        """Create default metadata for plugins without manifest."""
        return PluginMetadata(
            name=plugin_name,
            version="1.0.0",
            description=f"Plugin: {plugin_name}",
            author="Unknown",
            plugin_type=PluginType.FEATURE,
            security_level=SecurityLevel.SANDBOXED,
            priority=5,  # Use int
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
        """Load a specific plugin with improved error handling and dependency resolution."""
        start_time = time.time()

        try:
            with self._lock:
                # Track errors for this plugin
                self.plugin_errors.setdefault(plugin_name, [])

                # Check if already loaded
                if plugin_name in self.loaded_plugins and not force_reload:
                    self.logger.warning(f"Plugin already loaded: {plugin_name}")
                    return True

                # Check if discovered
                if plugin_name not in self.plugin_info:
                    error_msg = f"Plugin not discovered: {plugin_name}"
                    self.plugin_errors[plugin_name].append(error_msg)
                    self.logger.error(error_msg)
                    return False

                plugin_info = self.plugin_info[plugin_name]
                plugin_info.status = PluginStatus.LOADING

                # Ensure SDK (plugins_internal) exists before any plugin imports occur
                if not await self._ensure_plugins_internal():
                    error_msg = (
                        "plugins_internal SDK not available; plugin cannot be loaded"
                    )
                    self.plugin_errors[plugin_name].append(error_msg)
                    self.logger.error(error_msg)
                    # Quarantine plugin proactively
                    await self.quarantine_plugin(
                        plugin_name, reason=error_msg, quarantined_by="system"
                    )
                    plugin_info.status = PluginStatus.QUARANTINED
                    plugin_info.error_message = error_msg
                    return False

                # Enhanced dependency resolution
                if plugin_dependency_manager and plugin_name != "testing_plugin":
                    # Analyze and install dependencies
                    plugin_path = Path(self.plugins_dir) / plugin_name
                    try:
                        dependencies = (
                            await plugin_dependency_manager.analyze_plugin_dependencies(
                                plugin_path
                            )
                        )
                    except Exception:
                        dependencies = None

                    if dependencies and not dependencies.all_dependencies_met:
                        self.logger.info(
                            f"Installing dependencies for plugin {plugin_name}"
                        )
                        deps_installed = (
                            await plugin_dependency_manager.install_plugin_dependencies(
                                plugin_name
                            )
                        )
                        if not deps_installed:
                            error_msg = f"Failed to install dependencies for plugin: {plugin_name}"
                            self.plugin_errors[plugin_name].append(error_msg)
                            plugin_info.status = PluginStatus.FAILED
                            plugin_info.error_message = error_msg
                            return False
                elif plugin_name == "testing_plugin":
                    # Skip dependency checking for testing plugin
                    self.logger.info(f"Skipping dependency checking for testing plugin")
                else:
                    # Fallback to original dependency resolution
                    if not await self._resolve_dependencies(plugin_name):
                        error_msg = (
                            f"Failed to resolve dependencies for plugin: {plugin_name}"
                        )
                        self.plugin_errors[plugin_name].append(error_msg)
                        plugin_info.status = PluginStatus.FAILED
                        plugin_info.error_message = error_msg
                        return False

                # If security is enabled, ensure plugin is allowed by security manager
                if plugin_security_manager:
                    # If quarantined in security manager, abort
                    if plugin_security_manager.is_quarantined(plugin_name):
                        error_msg = (
                            f"Plugin {plugin_name} is quarantined by security manager"
                        )
                        self.plugin_errors[plugin_name].append(error_msg)
                        plugin_info.status = PluginStatus.QUARANTINED
                        plugin_info.error_message = error_msg
                        self.logger.error(error_msg)
                        return False

                    # If plugin is disabled in security manager (requires admin approval), do not load
                    if not plugin_security_manager.is_plugin_enabled(plugin_name):
                        self.logger.info(
                            f"Plugin {plugin_name} is not enabled by admin approval. Marked as awaiting approval."
                        )
                        plugin_info.status = PluginStatus.DISABLED
                        # Do not auto-load without admin approval
                        return False

                # Decide loading mode: sandboxed by default unless explicitly TRUSTED and security disabled
                load_in_sandbox = True
                if not self.security_enabled:
                    load_in_sandbox = False
                else:
                    # If plugin explicitly TRUSTED and system allows trusted plugins, allow direct load
                    if (
                        plugin_info.metadata.security_level == SecurityLevel.TRUSTED
                        and not self.security_enabled
                    ):
                        load_in_sandbox = False
                    else:
                        load_in_sandbox = True

                # Legacy: if metadata explicitly TRUSTED and security is disabled, use direct
                if (
                    plugin_info.metadata.security_level == SecurityLevel.TRUSTED
                    and not self.security_enabled
                ):
                    load_in_sandbox = False

                # If security is enabled, all non-TRUSTED plugins are sandboxed
                if (
                    self.security_enabled
                    and plugin_info.metadata.security_level != SecurityLevel.TRUSTED
                ):
                    load_in_sandbox = True

                # Load plugin based on sandbox decision
                if load_in_sandbox:
                    success = await self._load_plugin_sandboxed(
                        plugin_name, plugin_info
                    )
                else:
                    success = await self._load_plugin_direct(plugin_name, plugin_info)

                if success:
                    plugin_info.status = PluginStatus.LOADED
                    plugin_info.loaded_at = datetime.now(timezone.utc)
                    self.stats["total_loaded"] += 1

                    # Register plugin components
                    await self._register_plugin_components(plugin_name)

                    # Update load metrics
                    load_time = time.time() - start_time
                    self.plugin_load_times[plugin_name] = load_time
                    self.plugin_metrics.setdefault(plugin_name, {})
                    self.plugin_metrics[plugin_name].update(
                        {
                            "load_time": load_time,
                            "memory_usage": self._get_plugin_memory_usage(plugin_name),
                            "component_count": len(self.plugin_commands)
                            + len(self.plugin_event_handlers),
                        }
                    )

                    # Add security summary metrics if available
                    try:
                        if plugin_security_manager:
                            self.plugin_metrics[plugin_name]["security"] = (
                                plugin_security_manager.get_plugin_permissions(
                                    plugin_name
                                )
                            )
                    except Exception:
                        pass

                    # Add to load order
                    self.plugin_load_order.append(plugin_name)

                    self.logger.info(
                        f"Plugin loaded successfully: {plugin_name} (took {load_time:.2f}s)"
                    )
                    return True
                else:
                    error_msg = f"Failed to load plugin: {plugin_name}"
                    self.plugin_errors[plugin_name].append(error_msg)
                    plugin_info.status = PluginStatus.FAILED
                    self.stats["total_failed"] += 1
                    # If security manager available and indicates suspicious import requests for this plugin, quarantine
                    try:
                        if self.isolation_manager.get_plugin_module_requests(
                            plugin_name
                        ):
                            await self.quarantine_plugin(
                                plugin_name,
                                reason="Blocked imports requested",
                                quarantined_by="system",
                            )
                    except Exception:
                        pass
                    return False

        except Exception as e:
            error_msg = f"Error loading plugin {plugin_name}: {e}"
            self.plugin_errors.setdefault(plugin_name, []).append(error_msg)
            self.logger.error(error_msg, exc_info=True)
            if plugin_name in self.plugin_info:
                self.plugin_info[plugin_name].status = PluginStatus.ERROR
                self.plugin_info[plugin_name].error_message = str(e)
            # Quarantine on unexpected critical error
            try:
                await self.quarantine_plugin(
                    plugin_name, reason=str(e), quarantined_by="system"
                )
            except Exception:
                pass
            return False

    async def _ensure_plugins_internal(self) -> bool:
        """Ensure generated plugins_internal SDK is available and importable."""
        try:
            try:
                import plugins_internal  # noqa: F401

                return True
            except Exception:
                # Try to regenerate using central sdk generator
                if sdk_generator:
                    try:
                        sdk_generator.regenerate_if_needed()
                    except Exception:
                        # fallback to calling function
                        try:
                            regenerate_plugins_internal_if_needed and regenerate_plugins_internal_if_needed()
                        except Exception:
                            pass
                elif regenerate_plugins_internal_if_needed:
                    try:
                        regenerate_plugins_internal_if_needed()
                    except Exception:
                        pass
                # Try importing again after generation attempt
                try:
                    import importlib

                    importlib.invalidate_caches()
                    import plugins_internal  # noqa: F401

                    return True
                except Exception as e:
                    self.logger.error(
                        f"plugins_internal import failed after generation: {e}"
                    )
                    return False
        except Exception as e:
            self.logger.error(f"Unexpected error ensuring plugins_internal: {e}")
            return False

    async def _resolve_dependencies(
        self, plugin_name: str, visited: Optional[Set[str]] = None
    ) -> bool:
        """Resolve plugin dependencies with cycle detection."""
        if visited is None:
            visited = set()

        if plugin_name in visited:
            self.logger.error(f"Circular dependency detected for plugin: {plugin_name}")
            return False

        visited.add(plugin_name)
        plugin_info = self.plugin_info[plugin_name]

        # Build dependency graph
        self.plugin_dependencies_graph[plugin_name] = set()

        for dependency in plugin_info.metadata.dependencies:
            self.plugin_dependencies_graph[plugin_name].add(dependency)

            if dependency not in self.plugin_info:
                self.logger.error(
                    f"Missing dependency: {dependency} (required by {plugin_name})"
                )
                return False

            # Check security policy for dependency
            try:
                if plugin_security_manager:
                    if plugin_security_manager.is_quarantined(dependency):
                        self.logger.error(
                            f"Dependency {dependency} is quarantined; cannot satisfy dependency for {plugin_name}"
                        )
                        return False
                    if not plugin_security_manager.is_plugin_enabled(dependency):
                        self.logger.error(
                            f"Dependency {dependency} is not enabled (admin approval required); cannot load {plugin_name}"
                        )
                        return False
            except Exception:
                # If security manager check fails, fail safe and prevent load
                self.logger.error(
                    f"Security check failed for dependency {dependency} required by {plugin_name}"
                )
                return False

            # Check if dependency is already loaded
            if dependency not in self.loaded_plugins:
                # Recursively resolve dependency's dependencies
                if not await self._resolve_dependencies(dependency, visited):
                    return False

                # Try to load dependency
                if not await self.load_plugin(dependency):
                    self.logger.error(
                        f"Failed to load dependency: {dependency} (required by {plugin_name})"
                    )
                    return False

        visited.remove(plugin_name)
        return True

    async def _load_plugin_sandboxed(
        self, plugin_name: str, plugin_info: PluginInfo
    ) -> bool:
        """Load plugin in sandboxed environment with enhanced security."""
        try:
            # Ensure plugins_internal available
            if not await self._ensure_plugins_internal():
                self.logger.error(
                    "plugins_internal module not available for sandboxed plugin"
                )
                return False

            # Create security profile if available
            if plugin_security:
                try:
                    security_level = (
                        getattr(
                            EnhancedSecurityLevel,
                            "STANDARD",
                            EnhancedSecurityLevel.STANDARD,
                        )
                        if EnhancedSecurityLevel
                        else None
                    )
                    if security_level:
                        profile = plugin_security.create_security_profile(
                            plugin_name, security_level
                        )
                        secure_import = (
                            plugin_security.create_secure_import_hook(
                                plugin_name
                            )
                        )
                        original_import = __builtins__["__import__"]
                        __builtins__["__import__"] = secure_import
                except Exception:
                    original_import = None

            # Use isolation manager with enhanced config
            config = {
                "security_level": plugin_info.metadata.security_level.value,
                "permissions": plugin_info.metadata.permissions,
                "resource_limits": {
                    "memory_mb": 100,
                    "cpu_percent": 10,
                    "network_access": True,  # Default allow network via broker with checks
                },
            }

            success = await self.isolation_manager.load_module_isolated(
                plugin_name, plugin_info.path, config
            )

            if success:
                # Get plugin instance from isolated module
                isolated_module = self.isolation_manager.isolated_modules.get(
                    plugin_name
                )
                plugin_instance = await self._instantiate_plugin(
                    plugin_name, isolated_module, plugin_info
                )

                if plugin_instance:
                    self.loaded_plugins[plugin_name] = plugin_instance
                    plugin_info.instance = plugin_instance

                    # Restore original import if we modified it
                    if (
                        plugin_security
                        and "original_import" in locals()
                        and locals()["original_import"]
                    ):
                        __builtins__["__import__"] = locals()["original_import"]

                    return True

            # Restore original import on failure
            if (
                plugin_security
                and "original_import" in locals()
                and locals()["original_import"]
            ):
                __builtins__["__import__"] = locals()["original_import"]

            return False

        except Exception as e:
            # Restore original import on exception
            if (
                plugin_security
                and "original_import" in locals()
                and locals()["original_import"]
            ):
                __builtins__["__import__"] = locals()["original_import"]

            self.logger.error(f"Failed to load sandboxed plugin {plugin_name}: {e}")
            # If security manager exists, consider quarantining plugin on repeated failures
            try:
                await self.quarantine_plugin(
                    plugin_name, reason=str(e), quarantined_by="system"
                )
            except Exception:
                pass
            return False

    async def _load_plugin_direct(
        self, plugin_name: str, plugin_info: PluginInfo
    ) -> bool:
        """Load plugin directly (trusted plugins)."""
        try:
            # Ensure plugins_internal available
            if not await self._ensure_plugins_internal():
                self.logger.error(
                    "plugins_internal module not available for direct plugin"
                )
                return False

            # Find main module file
            main_files = [
                plugin_info.path / "main.py",
                plugin_info.path / "__init__.py",
            ]

            module_file = None
            for main_file in main_files:
                if main_file.exists():
                    module_file = main_file
                    break

            if not module_file:
                self.logger.error(
                    f"No main module file found for plugin: {plugin_name}"
                )
                return False

            # Load module
            spec = importlib.util.spec_from_file_location(
                f"plugin_{plugin_name}", module_file
            )
            if spec is None or spec.loader is None:
                self.logger.error(f"Could not create spec for plugin: {plugin_name}")
                return False

            module = importlib.util.module_from_spec(spec)
            sys.modules[f"plugin_{plugin_name}"] = module
            spec.loader.exec_module(module)

            # Instantiate plugin
            plugin_instance = await self._instantiate_plugin(
                plugin_name, module, plugin_info
            )

            if plugin_instance:
                self.loaded_plugins[plugin_name] = plugin_instance
                plugin_info.instance = plugin_instance
                plugin_info.module = module
                return True

            return False

        except Exception as e:
            self.logger.error(f"Failed to load direct plugin {plugin_name}: {e}")
            try:
                await self.quarantine_plugin(
                    plugin_name, reason=str(e), quarantined_by="system"
                )
            except Exception:
                pass
            return False

    async def _instantiate_plugin(
        self, plugin_name: str, module: Any, plugin_info: PluginInfo
    ) -> Optional[EnhancedBasePlugin]:
        """
        Instantiates a plugin from its loaded module.
        It looks for a variable named 'plugin' which should be an instance
        of a class that inherits from EnhancedBasePlugin.
        """
        try:
            if not hasattr(module, "plugin"):
                self.logger.error(
                    f"Plugin module '{plugin_name}' does not have a 'plugin' instance."
                )
                return None

            plugin_instance = getattr(module, "plugin")

            if not isinstance(plugin_instance, EnhancedBasePlugin):
                self.logger.error(
                    f"'plugin' in {plugin_name} is not an instance of EnhancedBasePlugin."
                )
                return None

            # Initialize the plugin (with sandbox context if available)
            init_result = False
            try:
                if asyncio.iscoroutinefunction(plugin_instance.initialize):
                    init_result = await plugin_instance.initialize()
                else:
                    init_result = plugin_instance.initialize()
            except Exception as e:
                self.logger.error(
                    f"Plugin initialization exception for {plugin_name}: {e}",
                    exc_info=True,
                )
                init_result = False

            if init_result:
                return plugin_instance
            else:
                self.logger.error(f"Plugin initialization failed for: {plugin_name}")
                return None

        except Exception as e:
            self.logger.error(
                f"Failed to instantiate plugin {plugin_name}: {e}", exc_info=True
            )
            return None

    async def _register_plugin_components(self, plugin_name: str) -> None:
        """Register plugin commands, event handlers, routers, db, and security features."""
        try:
            plugin_instance = self.loaded_plugins[plugin_name]
            # Register commands
            try:
                commands = plugin_instance.get_commands()
            except Exception:
                commands = {}
            for cmd_name, cmd_func in commands.items():
                full_cmd_name = f"{plugin_name}.{cmd_name}"
                self.plugin_commands[full_cmd_name] = cmd_func
                self.logger.debug(f"Registered command: {full_cmd_name}")
            # Register event handlers
            try:
                event_handlers = plugin_instance.get_event_handlers()
            except Exception:
                event_handlers = {}
            for event_name, handler_func in event_handlers.items():
                if event_name not in self.plugin_event_handlers:
                    self.plugin_event_handlers[event_name] = []
                self.plugin_event_handlers[event_name].append(handler_func)
                self.logger.debug(
                    f"Registered event handler: {event_name} for {plugin_name}"
                )
            # --- Register routers ---
            try:
                routers = plugin_instance.get_routers()
            except Exception:
                routers = {}
            if routers:
                self.plugin_routers[plugin_name] = routers
                self.logger.info(
                    f"Registered routers for plugin {plugin_name}: {list(routers.keys())}"
                )
            # --- Register DB extensions ---
            try:
                db_exts = plugin_instance.get_db_extensions()
            except Exception:
                db_exts = {}
            if db_exts:
                self.plugin_db_extensions[plugin_name] = db_exts
                self.logger.info(
                    f"Registered DB extensions for plugin {plugin_name}: {list(db_exts.keys())}"
                )
            # --- Register security features ---
            try:
                sec_feats = plugin_instance.get_security_features()
            except Exception:
                sec_feats = {}
            if sec_feats:
                self.plugin_security_features[plugin_name] = sec_feats
                self.logger.info(
                    f"Registered security features for plugin {plugin_name}: {list(sec_feats.keys())}"
                )
        except Exception as e:
            self.logger.error(
                f"Failed to register plugin components for {plugin_name}: {e}"
            )

    async def unload_plugin(self, plugin_name: str) -> bool:
        """Unload a plugin with improved cleanup."""
        try:
            with self._lock:
                if plugin_name not in self.loaded_plugins:
                    self.logger.warning(f"Plugin not loaded: {plugin_name}")
                    return True

                # Check if other plugins depend on this one
                dependent_plugins = []
                for other_plugin, deps in self.plugin_dependencies_graph.items():
                    if plugin_name in deps and other_plugin in self.loaded_plugins:
                        dependent_plugins.append(other_plugin)

                if dependent_plugins:
                    self.logger.error(
                        f"Cannot unload {plugin_name} - required by: {', '.join(dependent_plugins)}"
                    )
                    return False

                plugin_instance = self.loaded_plugins[plugin_name]
                plugin_info = self.plugin_info[plugin_name]

                # Shutdown plugin with timeout
                try:
                    shutdown_task = asyncio.create_task(plugin_instance.shutdown())
                    await asyncio.wait_for(shutdown_task, timeout=5.0)
                except asyncio.TimeoutError:
                    self.logger.warning(f"Plugin shutdown timed out: {plugin_name}")
                except Exception as e:
                    self.logger.warning(f"Plugin shutdown error: {plugin_name} - {e}")

                # Unregister components
                await self._unregister_plugin_components(plugin_name)

                # Remove from loaded plugins and update status
                del self.loaded_plugins[plugin_name]
                plugin_info.status = PluginStatus.DISCOVERED
                plugin_info.instance = None
                plugin_info.loaded_at = None

                # Update metrics
                if plugin_name in self.plugin_metrics:
                    del self.plugin_metrics[plugin_name]
                if plugin_name in self.plugin_load_times:
                    del self.plugin_load_times[plugin_name]

                # Remove from load order
                if plugin_name in self.plugin_load_order:
                    self.plugin_load_order.remove(plugin_name)

                self.stats["total_loaded"] = max(
                    0, self.stats.get("total_loaded", 0) - 1
                )

                # Clear any stored errors
                if plugin_name in self.plugin_errors:
                    del self.plugin_errors[plugin_name]

                self.logger.info(f"Plugin unloaded: {plugin_name}")
                return True

        except Exception as e:
            self.logger.error(f"Failed to unload plugin {plugin_name}: {e}")
            return False

    async def _unregister_plugin_components(self, plugin_name: str) -> None:
        """Unregister plugin commands and event handlers."""
        try:
            # Unregister commands
            commands_to_remove = [
                cmd_name
                for cmd_name in list(self.plugin_commands.keys())
                if cmd_name.startswith(f"{plugin_name}.")
            ]
            for cmd_name in commands_to_remove:
                del self.plugin_commands[cmd_name]
                self.logger.debug(f"Unregistered command: {cmd_name}")

            # Unregister event handlers
            for event_name, handlers in list(self.plugin_event_handlers.items()):
                # Remove handlers associated with this plugin
                new_handlers = []
                for handler in handlers:
                    # Best-effort removal: handlers might have __module__ or __qualname__ to inspect
                    try:
                        owner = getattr(handler, "__module__", None)
                        if owner and owner.startswith(f"plugin_{plugin_name}"):
                            continue
                    except Exception:
                        pass
                    new_handlers.append(handler)
                if new_handlers:
                    self.plugin_event_handlers[event_name] = new_handlers
                else:
                    del self.plugin_event_handlers[event_name]

            # Remove routers, db extensions, security features
            self.plugin_routers.pop(plugin_name, None)
            self.plugin_db_extensions.pop(plugin_name, None)
            self.plugin_security_features.pop(plugin_name, None)

        except Exception as e:
            self.logger.error(
                f"Failed to unregister plugin components for {plugin_name}: {e}"
            )

    async def enable_plugin(
        self, plugin_name: str, approved_by: Optional[str] = None
    ) -> bool:
        """Enable a plugin.

        Note: This method will mark plugin as enabled but will not load it unless the
        security manager acknowledges admin approval. If security manager is present,
        enabling without 'approved_by' will mark plugin as awaiting approval.
        """
        try:
            if plugin_name not in self.plugin_info:
                self.logger.error(f"Plugin not found: {plugin_name}")
                return False

            plugin_info = self.plugin_info[plugin_name]
            plugin_info.metadata.enabled = True

            # If security manager exists, require admin approval to actually activate plugin
            if plugin_security_manager:
                if not approved_by:
                    # Persist requested enabled state but not admin_approved
                    await self._update_plugin_enabled(
                        plugin_name, enabled=True, admin_approved=False
                    )
                    plugin_info.status = PluginStatus.DISABLED
                    self.logger.info(
                        f"Plugin enable requested for {plugin_name}; awaiting admin approval"
                    )
                    return False
                else:
                    # Admin approval path
                    try:
                        approved = await plugin_security_manager.enable_plugin(
                            plugin_name, approved_by
                        )
                        if not approved:
                            self.logger.error(
                                f"Security manager failed to enable plugin {plugin_name}"
                            )
                            return False
                        # Persist enabled state as admin approved
                        await self._update_plugin_enabled(
                            plugin_name,
                            enabled=True,
                            admin_approved=True,
                            approved_by=approved_by,
                        )
                        # Now load the plugin
                        if plugin_name not in self.loaded_plugins:
                            loaded = await self.load_plugin(plugin_name)
                            if loaded:
                                self.stats["total_enabled"] += 1
                                return True
                            return False
                    except Exception as e:
                        self.logger.error(
                            f"Failed to enable plugin via security manager: {e}"
                        )
                        return False

            # No security manager: persist and load immediately
            if database_manager:
                await self._update_plugin_enabled(
                    plugin_name, enabled=True, admin_approved=True
                )

            # Load if not already loaded
            if plugin_name not in self.loaded_plugins:
                loaded = await self.load_plugin(plugin_name)
                if loaded:
                    self.stats["total_enabled"] += 1
                    return True
                return False

            self.stats["total_enabled"] += 1
            return True

        except Exception as e:
            self.logger.error(f"Failed to enable plugin {plugin_name}: {e}")
            return False

    async def disable_plugin(self, plugin_name: str) -> bool:
        """Disable a plugin."""
        try:
            if plugin_name not in self.plugin_info:
                self.logger.error(f"Plugin not found: {plugin_name}")
                return False

            plugin_info = self.plugin_info[plugin_name]
            plugin_info.metadata.enabled = False

            # Update database if available
            if database_manager:
                await self._update_plugin_enabled(
                    plugin_name, False, admin_approved=False
                )

            # Unload if loaded
            if plugin_name in self.loaded_plugins:
                await self.unload_plugin(plugin_name)

            self.stats["total_enabled"] = max(0, self.stats.get("total_enabled", 0) - 1)
            return True

        except Exception as e:
            self.logger.error(f"Failed to disable plugin {plugin_name}: {e}")
            return False

    async def load_enabled_plugins(self) -> Dict[str, bool]:
        """Load all enabled plugins."""
        try:
            results = {}

            # Get enabled plugins
            enabled_plugins = [
                plugin_name
                for plugin_name, info in self.plugin_info.items()
                if info.metadata.enabled and plugin_name not in self.loaded_plugins
            ]

            # Sort by dependencies and priority
            sorted_plugins = self._sort_plugins_by_dependencies_and_priority(
                enabled_plugins
            )

            # Load plugins in order
            for plugin_name in sorted_plugins:
                results[plugin_name] = await self.load_plugin(plugin_name)

            loaded_count = sum(1 for v in results.values() if v)
            self.logger.info(
                f"Loaded {loaded_count}/{len(enabled_plugins)} enabled plugins"
            )

            return results

        except Exception as e:
            self.logger.error(f"Failed to load enabled plugins: {e}")
            return {}

    def _sort_plugins_by_dependencies_and_priority(
        self, plugin_names: List[str]
    ) -> List[str]:
        """Sort plugins by dependencies and priority."""
        try:
            # Simple topological sort with priority
            sorted_plugins = []
            remaining_plugins = plugin_names.copy()

            while remaining_plugins:
                # Find plugins with no unresolved dependencies
                ready_plugins = []
                for plugin_name in list(remaining_plugins):
                    plugin_info = self.plugin_info[plugin_name]
                    dependencies = plugin_info.metadata.dependencies

                    # Check if all dependencies are already sorted or not in the list
                    deps_satisfied = all(
                        dep in sorted_plugins or dep not in plugin_names
                        for dep in dependencies
                    )

                    if deps_satisfied:
                        ready_plugins.append(plugin_name)

                if not ready_plugins:
                    # Circular dependency or missing dependency
                    self.logger.warning(
                        f"Circular dependency detected in plugins: {remaining_plugins}"
                    )
                    ready_plugins = remaining_plugins  # Load anyway

                # Sort ready plugins by priority (now an int)
                ready_plugins.sort(
                    key=lambda name: self.plugin_info[name].metadata.priority,
                    reverse=True,
                )

                # Add to sorted list
                sorted_plugins.extend(ready_plugins)

                # Remove from remaining
                for plugin_name in ready_plugins:
                    if plugin_name in remaining_plugins:
                        remaining_plugins.remove(plugin_name)

            return sorted_plugins

        except Exception as e:
            self.logger.error(f"Failed to sort plugins: {e}")
            return plugin_names

        except Exception as e:
            self.logger.error(f"Failed to sort plugins: {e}")
            return plugin_names

    async def _update_plugin_enabled(
        self,
        plugin_name: str,
        enabled: bool,
        admin_approved: bool = False,
        approved_by: Optional[str] = None,
    ) -> None:
        """Update plugin enabled status in database."""
        try:
            if not database_manager:
                return

            # Ensure plugin_settings table exists (best-effort)
            try:
                await database_manager.ensure_table_exists(
                    "plugin_settings",
                    {
                        "id": "INTEGER PRIMARY KEY AUTOINCREMENT",
                        "plugin_name": "TEXT UNIQUE NOT NULL",
                        "enabled": "BOOLEAN DEFAULT 0",
                        "admin_approved": "BOOLEAN DEFAULT 0",
                        "approved_by": "TEXT",
                        "approved_at": "TIMESTAMP",
                        "disabled_reason": "TEXT",
                        "created_at": "TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
                        "updated_at": "TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
                    },
                )
            except Exception:
                # ignore create table errors
                pass

            async with database_manager.get_session() as session:
                now = datetime.now(timezone.utc)
                # Upsert pattern for sqlite
                try:
                    # Try an INSERT OR REPLACE (sqlite). For other DBs this may not be supported; fall back to delete+insert
                    await session.execute(
                        """
                        INSERT OR REPLACE INTO plugin_settings
                        (plugin_name, enabled, admin_approved, approved_by, approved_at, updated_at)
                        VALUES (:plugin_name, :enabled, :admin_approved, :approved_by, :approved_at, :updated_at)
                    """,
                        {
                            "plugin_name": plugin_name,
                            "enabled": 1 if enabled else 0,
                            "admin_approved": 1 if admin_approved else 0,
                            "approved_by": approved_by,
                            "approved_at": now if admin_approved else None,
                            "updated_at": now,
                        },
                    )
                    await session.commit()
                except Exception:
                    # Generic fallback: try delete then insert
                    try:
                        await session.execute(
                            "DELETE FROM plugin_settings WHERE plugin_name = :name",
                            {"name": plugin_name},
                        )
                        await session.execute(
                            """
                            INSERT INTO plugin_settings
                            (plugin_name, enabled, admin_approved, approved_by, approved_at, updated_at)
                            VALUES (:plugin_name, :enabled, :admin_approved, :approved_by, :approved_at, :updated_at)
                        """,
                            {
                                "plugin_name": plugin_name,
                                "enabled": 1 if enabled else 0,
                                "admin_approved": 1 if admin_approved else 0,
                                "approved_by": approved_by,
                                "approved_at": now if admin_approved else None,
                                "updated_at": now,
                            },
                        )
                        await session.commit()
                    except Exception as e:
                        self.logger.error(
                            f"Failed to upsert plugin_settings for {plugin_name}: {e}"
                        )

        except Exception as e:
            self.logger.error(f"Failed to update plugin enabled status: {e}")

    async def run_plugin_tests(self, plugin_name: str) -> Dict[str, Any]:
        """Run tests for a specific plugin."""
        try:
            if plugin_name not in self.loaded_plugins:
                return {"error": "Plugin not loaded"}

            plugin_instance = self.loaded_plugins[plugin_name]
            return await self.test_manager.run_plugin_tests(
                plugin_name, plugin_instance
            )

        except Exception as e:
            self.logger.error(f"Failed to run tests for plugin {plugin_name}: {e}")
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
                "plugin_results": {},
            }

            for plugin_name in list(self.loaded_plugins.keys()):
                test_results = await self.run_plugin_tests(plugin_name)
                if test_results and "error" not in test_results:
                    all_results["plugins_with_tests"] += 1
                    all_results["plugin_results"][plugin_name] = test_results

            return all_results

        except Exception as e:
            self.logger.error(f"Failed to run all plugin tests: {e}")
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
                    "priority": plugin_info.metadata.priority,  # Use int
                },
                "status": plugin_info.status.value,
                "loaded_at": (
                    plugin_info.loaded_at.isoformat() if plugin_info.loaded_at else None
                ),
                "error_message": plugin_info.error_message,
                "path": str(plugin_info.path),
            }

        except Exception as e:
            self.logger.error(f"Failed to get plugin info for {plugin_name}: {e}")
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
            self.logger.error(f"Failed to get all plugins info: {e}")
            return {}

    def get_stats(self) -> Dict[str, Any]:
        """Get plugin manager statistics."""
        quarantined = []
        try:
            if plugin_security_manager:
                try:
                    # security manager exposes quarantined set
                    quarantined = list(
                        getattr(plugin_security_manager, "_quarantined_plugins", [])
                    )
                except Exception:
                    quarantined = []
        except Exception:
            quarantined = []

        return {
            **self.stats,
            "discovered_plugins": list(self.discovered_plugins),
            "loaded_plugins": list(self.loaded_plugins.keys()),
            "enabled_plugins": [
                name for name, info in self.plugin_info.items() if info.metadata.enabled
            ],
            "failed_plugins": [
                name
                for name, info in self.plugin_info.items()
                if info.status
                in [PluginStatus.ERROR, PluginStatus.FAILED, PluginStatus.QUARANTINED]
            ],
            "quarantined_plugins": quarantined,
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
            self.logger.error(f"Failed to execute command {command_name}: {e}")
            raise PluginError(f"Command execution failed: {e}")

    async def emit_event(self, event_name: str, *args, **kwargs) -> List[Any]:
        """Emit an event to all registered handlers."""
        try:
            results = []

            if event_name in self.plugin_event_handlers:
                for handler in list(self.plugin_event_handlers[event_name]):
                    try:
                        if asyncio.iscoroutinefunction(handler):
                            result = await handler(*args, **kwargs)
                        else:
                            result = handler(*args, **kwargs)
                        results.append(result)
                    except Exception as e:
                        self.logger.error(f"Event handler error for {event_name}: {e}")
                        results.append(None)

            return results

        except Exception as e:
            self.logger.error(f"Failed to emit event {event_name}: {e}")
            return []

    async def quarantine_plugin(
        self, plugin_name: str, reason: str, quarantined_by: str
    ) -> bool:
        """Quarantine a plugin due to security violations or suspicious behavior."""
        try:
            if plugin_name not in self.plugin_info:
                self.logger.error(f"Plugin not found to quarantine: {plugin_name}")
                return False

            # Unload plugin if loaded
            if plugin_name in self.loaded_plugins:
                try:
                    await self.unload_plugin(plugin_name)
                except Exception:
                    pass

            # Mark as quarantined in local state
            self.plugin_info[plugin_name].status = PluginStatus.QUARANTINED
            self.plugin_info[plugin_name].error_message = f"Quarantined: {reason}"

            # Ask security manager to quarantine (persistent)
            if plugin_security_manager:
                try:
                    plugin_security_manager.quarantine_plugin(
                        plugin_name, reason, quarantined_by
                    )
                except Exception as e:
                    self.logger.error(
                        f"Failed to record quarantine in security manager: {e}"
                    )

            # Persist quarantine in DB plugin_settings if available
            if database_manager:
                try:
                    await self._update_plugin_enabled(
                        plugin_name, enabled=False, admin_approved=False
                    )
                except Exception:
                    pass

            self.logger.critical(
                f"Plugin {plugin_name} quarantined by {quarantined_by}: {reason}"
            )
            return True

        except Exception as e:
            self.logger.error(f"Failed to quarantine plugin {plugin_name}: {e}")
            return False

    async def release_plugin_quarantine(
        self, plugin_name: str, released_by: str
    ) -> bool:
        """Release a plugin from quarantine."""
        try:
            if plugin_name not in self.plugin_info:
                self.logger.error(
                    f"Plugin not found to release from quarantine: {plugin_name}"
                )
                return False

            # Ask security manager to release
            if plugin_security_manager:
                try:
                    plugin_security_manager.release_from_quarantine(
                        plugin_name, released_by
                    )
                except Exception as e:
                    self.logger.error(
                        f"Failed to release quarantine in security manager: {e}"
                    )

            # Update status locally
            self.plugin_info[plugin_name].status = PluginStatus.DISCOVERED
            self.plugin_info[plugin_name].error_message = None

            # Persist state in DB if available
            if database_manager:
                try:
                    await self._update_plugin_enabled(
                        plugin_name, enabled=False, admin_approved=False
                    )
                except Exception:
                    pass

            self.logger.warning(
                f"Plugin {plugin_name} released from quarantine by {released_by}"
            )
            return True

        except Exception as e:
            self.logger.error(
                f"Failed to release plugin {plugin_name} from quarantine: {e}"
            )
            return False

    async def shutdown(self) -> None:
        """Shutdown the plugin manager with improved cleanup."""
        try:
            self.logger.info("Shutting down plugin manager")

            # Unload plugins in reverse load order
            for plugin_name in reversed(self.plugin_load_order):
                await self.unload_plugin(plugin_name)

            # Clear all data structures
            self.discovered_plugins.clear()
            self.plugin_info.clear()
            self.loaded_plugins.clear()
            self.plugin_commands.clear()
            self.plugin_event_handlers.clear()
            self.plugin_errors.clear()
            self.plugin_dependencies_graph.clear()
            self.plugin_load_order.clear()
            self.plugin_load_times.clear()
            self.plugin_metrics.clear()

            self.logger.info("Plugin manager shut down successfully")

        except Exception as e:
            self.logger.error(f"Failed to shutdown plugin manager: {e}")

    async def load_plugins(self) -> None:
        """Load all enabled plugins."""
        await self.load_enabled_plugins()

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

    def get_all_plugin_docs(self) -> Dict[str, Dict[str, Any]]:
        """
        Returns a dictionary of plugin IDs to their documentation.
        The documentation is stored as a dictionary of file names to their content.
        """
        return self.plugin_docs

    def _get_plugin_memory_usage(self, plugin_name: str) -> float:
        """Get memory usage of a plugin in MB."""
        try:
            import psutil

            process = psutil.Process()

            # Get memory before
            mem_before = process.memory_info().rss

            # Potentially instrument plugin's thread/process etc. For now estimate.
            mem_after = process.memory_info().rss

            # Return difference in MB
            return max(0.0, (mem_after - mem_before) / (1024 * 1024))
        except:
            pass
        return 0.0

    def get_plugin_errors(
        self, plugin_name: Optional[str] = None
    ) -> Dict[str, List[str]]:
        """Get errors for a specific plugin or all plugins."""
        if plugin_name:
            return {plugin_name: self.plugin_errors.get(plugin_name, [])}
        return self.plugin_errors

    def get_plugin_metrics(
        self, plugin_name: Optional[str] = None
    ) -> Dict[str, Dict[str, Any]]:
        """Get metrics for a specific plugin or all plugins."""
        if plugin_name:
            return {plugin_name: self.plugin_metrics.get(plugin_name, {})}
        return self.plugin_metrics

    def get_dependency_graph(self) -> Dict[str, Set[str]]:
        """Get the plugin dependency graph."""
        return self.plugin_dependencies_graph.copy()


import os

# Global plugin manager instance
# Point to the correct plugins directory in project root
from pathlib import Path

# Get the correct path to plugins directory (project root)
project_root = Path(__file__).parent.parent.parent.parent.parent
plugins_dir = project_root / "plugins"

# Ensure the directory exists
plugins_dir.mkdir(exist_ok=True)

plugin_manager = PluginManager(plugins_dir=plugins_dir)

# Backward compatibility alias (some modules may still import plugin_manager)
plugin_manager = plugin_manager


# Backward compatibility functions
async def get_plugin_manager() -> PluginManager:
    """Get the global plugin manager instance."""
    return plugin_manager


async def discover_plugins() -> List[str]:
    """Discover available plugins."""
    return await plugin_manager.discover_plugins()


async def load_plugin(plugin_name: str) -> bool:
    """Load a specific plugin."""
    return await plugin_manager.load_plugin(plugin_name)


async def unload_plugin(plugin_name: str) -> bool:
    return await plugin_manager.unload_plugin(plugin_name)


async def enable_plugin(plugin_name: str) -> bool:
    return await plugin_manager.enable_plugin(plugin_name)


async def disable_plugin(plugin_name: str) -> bool:
    return await plugin_manager.disable_plugin(plugin_name)


def get_plugin_info(plugin_name: str) -> Optional[Dict[str, Any]]:
    return plugin_manager.get_plugin_info(plugin_name)


def get_all_plugins_info() -> Dict[str, Dict[str, Any]]:
    return plugin_manager.get_all_plugins_info()


async def execute_command(command_name: str, *args, **kwargs) -> Any:
    return await plugin_manager.execute_command(command_name, *args, **kwargs)


async def emit_event(event_name: str, *args, **kwargs) -> List[Any]:
    return await plugin_manager.emit_event(event_name, *args, **kwargs)


# Backward compatibility aliases
PluginManager = PluginManager

__all__ = [
    # Main classes
    "PluginManager",
    "plugin_manager",
    "PluginInterface",
    "PluginIsolationManager",
    "PluginTestManager",
    # Data classes
    "PluginMetadata",
    "PluginInfo",
    "PluginType",
    "PluginStatus",
    "SecurityLevel",
    # Main functions
    "get_plugin_manager",
    "discover_plugins",
    "load_plugin",
    "unload_plugin",
    "enable_plugin",
    "disable_plugin",
    "get_plugin_info",
    "get_all_plugins_info",
    "execute_command",
    "emit_event",
    # Backward compatibility aliases
    "plugin_manager",
    "PluginManager",
    # Exceptions
    "PluginError",
]
