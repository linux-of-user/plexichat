"""
PlexiChat Unified Plugin and SDK Manager

This single file consolidates ALL plugin management and SDK functionality,
providing a single source of truth to resolve previous circular dependencies.

It contains:
- The core `UnifiedPluginManager` for discovering, loading, and managing plugins.
- The `PluginInterface` and supporting data classes (`PluginInfo`, `PluginMetadata`).
- The full Plugin SDK, including `EnhancedBasePlugin`, `EnhancedPluginAPI`, and config classes.
- Sandboxing and isolation managers (`PluginIsolationManager`).
- The plugin testing framework (`PluginTestManager`).
"""

import asyncio
import importlib.util
import json
import logging
import os
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

# ======================================================================
# Attempt to import the SDK generator and plugin security manager to
# allow generating a robust plugins_internal.py on startup. These are
# optional and will fall back to lightweight generation if missing.
# ======================================================================
try:
    from plexichat.core.plugins.sdk_generator import PluginSDKGenerator
    from plexichat.core.plugins.sdk_generator import sdk_generator as core_sdk_generator
except Exception:
    core_sdk_generator = None
    PluginSDKGenerator = None

try:
    from plexichat.core.plugins.security_manager import (
        plugin_security_manager as core_plugin_security_manager,
    )
except Exception:
    core_plugin_security_manager = None

# ==============================================================================
# 1. SHARED AND CORE IMPORTS (WITH FALLBACKS)
# ==============================================================================

logger = logging.getLogger(__name__)

# Shared components
try:
    from plexichat.shared.models import Event, Plugin, Priority, Status
except ImportError:

    class Plugin:
        pass

    class Event:
        pass

    class Priority:
        pass

    class Status:
        pass


try:
    from plexichat.shared.types import PluginConfig, PluginId, PluginResult
except ImportError:
    PluginId = str
    PluginConfig = dict
    PluginResult = dict

try:
    from plexichat.shared.exceptions import PluginError, SecurityError, ValidationError
except ImportError:

    class PluginError(Exception):
        pass

    class ValidationError(Exception):
        pass

    class SecurityError(Exception):
        pass


# Core configurations
try:
    from plexichat.core.config_manager import (
        get_max_plugin_memory,
        get_plugin_sandbox_enabled,
        get_plugin_timeout,
    )
except ImportError:

    def get_plugin_timeout():
        return 30

    def get_max_plugin_memory():
        return 100 * 1024 * 1024

    def get_plugin_sandbox_enabled():
        return True


# Core services (for SDK)
try:
    from plexichat.core.database.manager import database_manager
except ImportError:
    database_manager = None
try:
    from plexichat.core.logging import get_logger
except ImportError:
    get_logger = logging.getLogger
try:
    from plexichat.core.performance import performance_monitor
except ImportError:
    performance_monitor = None
try:
    from plexichat.core.cache import secure_cache as cache_manager
except ImportError:
    cache_manager = None
try:
    from plexichat.core.config import config
except ImportError:
    config = {}

# Enhanced plugin systems
# try:
#     from .advanced_plugin_security import enhanced_plugin_security, SecurityLevel as EnhancedSecurityLevel
#     from .plugin_dependency_manager import plugin_dependency_manager
# except ImportError:
enhanced_plugin_security = None
plugin_dependency_manager = None
EnhancedSecurityLevel = None

# AI integration
# try:
#     from plexichat.features.ai.advanced_ai_system import intelligent_assistant, ai_provider_manager
# except ImportError:
intelligent_assistant = None
ai_provider_manager = None


# ==============================================================================
# 2. DATA CLASSES, ENUMS, AND BASIC METRICS
# ==============================================================================


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


class PluginType(Enum):
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
    TRUSTED = "trusted"
    SANDBOXED = "sandboxed"
    RESTRICTED = "restricted"
    UNTRUSTED = "untrusted"


@dataclass
class PluginMetadata:
    name: str
    version: str
    description: str
    author: str
    plugin_type: PluginType = PluginType.FEATURE
    security_level: SecurityLevel = SecurityLevel.SANDBOXED
    dependencies: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    capabilities: List[ModuleCapability] = field(default_factory=list)
    priority: int = 5
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
        return cls(
            name=data.get("name", ""),
            version=data.get("version", "1.0.0"),
            description=data.get("description", ""),
            author=data.get("author", ""),
            plugin_type=PluginType(data.get("type", "feature")),
            security_level=SecurityLevel(data.get("security_level", "sandboxed")),
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
            priority=data.get("priority", 5),
        )


@dataclass
class PluginInfo:
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


# ==============================================================================
# 3. PLUGIN AND SDK INTERFACES (ABCs)
# ==============================================================================


class PluginInterface(ABC):
    @abstractmethod
    async def initialize(self) -> bool:
        pass

    @abstractmethod
    async def shutdown(self) -> None:
        pass

    @abstractmethod
    def get_commands(self) -> Dict[str, Callable]:
        pass

    @abstractmethod
    def get_event_handlers(self) -> Dict[str, Callable]:
        pass

    @abstractmethod
    async def self_test(self) -> Dict[str, Any]:
        pass

    def get_routers(self) -> Dict[str, Any]:
        return {}

    def get_db_extensions(self) -> Dict[str, Any]:
        return {}

    def get_security_features(self) -> Dict[str, Any]:
        return {}


# ==============================================================================
# 4. ENHANCED PLUGIN SDK
# ==============================================================================


@dataclass
class EnhancedPluginConfig:
    name: str
    version: str
    description: str
    author: str
    email: Optional[str] = None
    license: str = "MIT"
    homepage: Optional[str] = None
    repository: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    plugin_type: str = "feature"
    security_level: str = "sandboxed"
    min_plexichat_version: Optional[str] = None
    max_plexichat_version: Optional[str] = None
    dependencies: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    auto_load: bool = True
    priority: int = 5
    cache_enabled: bool = True
    cache_ttl: int = 300
    performance_monitoring: bool = True


class EnhancedPluginLogger:
    def __init__(self, plugin_name: str):
        self.plugin_name = plugin_name
        try:
            from plexichat.core.logging.unified_logger import get_plugin_logger as _gpl

            self.logger = _gpl(plugin_name)
        except Exception:
            from plexichat.core.logging import get_logger as _gl

            self.logger = _gl(f"plugin.{plugin_name}")
        self._performance_metrics = {}

    def info(self, message: str, **kwargs):
        self.logger.info(f"[{self.plugin_name}] {message}", **kwargs)
        if performance_monitor:
            performance_monitor.log_plugin_event(self.plugin_name, "info", message)

    def error(self, message: str, **kwargs):
        self.logger.error(f"[{self.plugin_name}] {message}", **kwargs)
        if performance_monitor:
            performance_monitor.log_plugin_event(self.plugin_name, "error", message)

    def warning(self, message: str, **kwargs):
        self.logger.warning(f"[{self.plugin_name}] {message}", **kwargs)
        if performance_monitor:
            performance_monitor.log_plugin_event(self.plugin_name, "warning", message)

    def debug(self, message: str, **kwargs):
        self.logger.debug(f"[{self.plugin_name}] {message}", **kwargs)

    def track_performance(self, operation: str, duration: float):
        if operation not in self._performance_metrics:
            self._performance_metrics[operation] = []
        self._performance_metrics[operation].append(duration)
        if performance_monitor:
            performance_monitor.track_plugin_performance(
                self.plugin_name, operation, duration
            )


class PerformanceTracker:
    def __init__(self, logger: EnhancedPluginLogger, operation: str):
        self.logger = logger
        self.operation = operation
        self.start_time = None

    def __enter__(self):
        self.start_time = datetime.now(timezone.utc)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.start_time:
            duration = (datetime.now(timezone.utc) - self.start_time).total_seconds()
            self.logger.track_performance(self.operation, duration)


class EnhancedPluginAPI:
    def __init__(self, plugin_name: str, config: EnhancedPluginConfig):
        self.plugin_name = plugin_name
        self.config = config
        self.logger = EnhancedPluginLogger(plugin_name)
        self._cache_prefix = f"plugin:{plugin_name}"

    async def cache_get(self, key: str) -> Optional[Any]:
        if not cache_manager or not self.config.cache_enabled:
            return None
        try:
            return await cache_manager.get(f"{self._cache_prefix}:{key}")
        except Exception as e:
            self.logger.error(f"Cache get failed for key {key}: {e}")
            return None

    async def cache_set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        if not cache_manager or not self.config.cache_enabled:
            return False
        try:
            await cache_manager.set(
                f"{self._cache_prefix}:{key}", value, ttl=ttl or self.config.cache_ttl
            )
            return True
        except Exception as e:
            self.logger.error(f"Cache set failed for key {key}: {e}")
            return False

    async def cache_delete(self, key: str) -> bool:
        if not cache_manager:
            return False
        try:
            await cache_manager.delete(f"{self._cache_prefix}:{key}")
            return True
        except Exception as e:
            self.logger.error(f"Cache delete failed for key {key}: {e}")
            return False

    async def db_set_value(self, key: str, value: Any) -> bool:
        if not database_manager:
            self.logger.error("DB unavailable for db_set_value.")
            return False
        try:
            serialized_value = json.dumps(value)
            async with database_manager.get_session() as session:
                query = "INSERT OR REPLACE INTO plugin_data (plugin_name, key, value) VALUES (:plugin_name, :key, :value)"
                params = {
                    "plugin_name": self.plugin_name,
                    "key": key,
                    "value": serialized_value,
                }
                await session.execute(query, params)
                await session.commit()
            return True
        except Exception as e:
            self.logger.error(f"Failed to set value for key '{key}': {e}")
            return False

    async def db_get_value(self, key: str, default: Any = None) -> Any:
        if not database_manager:
            self.logger.error("DB unavailable for db_get_value.")
            return default
        try:
            async with database_manager.get_session() as session:
                query = "SELECT value FROM plugin_data WHERE plugin_name = :plugin_name AND key = :key"
                params = {"plugin_name": self.plugin_name, "key": key}
                row = await session.fetchone(query, params)
                return json.loads(row["value"]) if row else default
        except Exception as e:
            self.logger.error(f"Failed to get value for key '{key}': {e}")
            return default

    async def db_delete_value(self, key: str) -> bool:
        if not database_manager:
            self.logger.error("DB unavailable for db_delete_value.")
            return False
        try:
            async with database_manager.get_session() as session:
                await session.delete(
                    "plugin_data", where={"plugin_name": self.plugin_name, "key": key}
                )
                await session.commit()
            return True
        except Exception as e:
            self.logger.error(f"Failed to delete value for key '{key}': {e}")
            return False

    async def get_config(self, key: str, default: Any = None) -> Any:
        cached_value = await self.cache_get(f"config:{key}")
        if cached_value is not None:
            return cached_value
        plugin_config = config.get(f"plugins.{self.plugin_name}", {})
        value = plugin_config.get(key, default)
        await self.cache_set(f"config:{key}", value, ttl=60)
        return value

    async def set_config(self, key: str, value: Any) -> bool:
        try:
            if f"plugins.{self.plugin_name}" not in config:
                config[f"plugins.{self.plugin_name}"] = {}
            config[f"plugins.{self.plugin_name}"][key] = value
            await self.cache_set(f"config:{key}", value, ttl=60)
            return True
        except Exception as e:
            self.logger.error(f"Failed to set config {key}: {e}")
            return False

    async def emit_event(self, event_name: str, data: Dict[str, Any]) -> bool:
        try:
            if "unified_plugin_manager" in globals():
                await unified_plugin_manager.emit_event(event_name, data)
                return True
            return False
        except Exception as e:
            self.logger.error(f"Failed to emit event {event_name}: {e}")
            return False

    def track_performance(self, operation: str):
        return PerformanceTracker(self.logger, operation)


class EnhancedBasePlugin(PluginInterface):
    def __init__(self, config: EnhancedPluginConfig):
        self.config = config
        self.api = EnhancedPluginAPI(config.name, config)
        self.logger = self.api.logger
        self._initialized = False

    async def initialize(self) -> bool:
        if self._initialized:
            return True
        with self.api.track_performance("initialization"):
            try:
                await self._initialize_plugin()
                self._initialized = True
                self.logger.info(f"Plugin {self.config.name} initialized")
                return True
            except Exception as e:
                self.logger.error(f"Plugin initialization failed: {e}")
                return False

    async def shutdown(self) -> None:
        try:
            await self._shutdown_plugin()
            self.logger.info(f"Plugin {self.config.name} shut down")
        except Exception as e:
            self.logger.error(f"Plugin shutdown failed: {e}")

    @abstractmethod
    async def _initialize_plugin(self):
        pass

    async def _shutdown_plugin(self):
        pass

    def get_commands(self) -> Dict[str, Callable]:
        return {}

    def get_event_handlers(self) -> Dict[str, Callable]:
        return {}

    async def self_test(self) -> Dict[str, Any]:
        return {"status": "not_implemented"}


# ==============================================================================
# 5. CORE PLUGIN MANAGER COMPONENTS
# ==============================================================================


class PluginIsolationManager:
    """Manages plugin isolation and sandboxing."""

    def __init__(self):
        self.isolated_modules: Dict[str, Any] = {}
        self.resource_limits: Dict[str, Dict[str, Any]] = {}
        self.plugin_module_permissions: Dict[str, Set[str]] = {}
        self.plugin_module_requests: Dict[str, Set[str]] = {}

    async def load_module_isolated(
        self,
        plugin_name: str,
        plugin_path: Path,
        config: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Load a module in isolation with enhanced sandboxing."""
        try:
            threading.current_thread().plugin_name = plugin_name
            if config and "resource_limits" in config:
                self.resource_limits[plugin_name] = config["resource_limits"]
            for p_dir in [f"logs/plugin/{plugin_name}", f"plugins/{plugin_name}/data"]:
                Path(p_dir).mkdir(parents=True, exist_ok=True)

            spec = importlib.util.spec_from_file_location(
                f"isolated_{plugin_name}", plugin_path / "main.py"
            )
            if spec is None or spec.loader is None:
                return False
            module = importlib.util.module_from_spec(spec)
            if not hasattr(module, "__builtins__"):
                module.__builtins__ = {}

            restricted_builtins = {
                "__import__": self._restricted_import,
                "open": self._restricted_open,
                "exec": self._restricted_exec,
                "eval": self._restricted_eval,
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
                "__build_class__": __builtins__["__build_class__"],
                "__name__": "__main__",
                "staticmethod": staticmethod,
                "classmethod": classmethod,
                "property": property,
                "super": super,
                "type": type,
                "object": object,
            }
            module.__builtins__.update(restricted_builtins)
            spec.loader.exec_module(module)
            self.isolated_modules[plugin_name] = module
            get_logger(f"plugin.{plugin_name}.sandbox").info(
                f"Plugin '{plugin_name}' loaded in sandboxed environment"
            )
            return True
        except Exception as e:
            logger.error(f"Failed to load isolated module {plugin_name}: {e}")
            return False
        finally:
            if hasattr(threading.current_thread(), "plugin_name"):
                delattr(threading.current_thread(), "plugin_name")

    def _restricted_import(self, name, *args, **kwargs):
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
            "re",
            "ssl",
            "sys",
            "os",
            "hashlib",
            "collections",
            "math",
            "random",
            "requests",
            "fastapi",
            "sqlalchemy",
        }
        plugin_name = getattr(threading.current_thread(), "plugin_name", None)
        extra_allowed = self.plugin_module_permissions.get(plugin_name, set())
        if (
            name in allowed_modules
            or name in extra_allowed
            or name.startswith("plexichat.")
        ):
            return __import__(name, *args, **kwargs)
        if plugin_name:
            self.plugin_module_requests.setdefault(plugin_name, set()).add(name)
        raise ImportError(
            f"Import of '{name}' not allowed in sandboxed plugin. Admin approval required."
        )

    def _restricted_open(self, filename, mode="r", *args, **kwargs):
        plugin_name = getattr(threading.current_thread(), "plugin_name", None)
        if not plugin_name:
            raise PermissionError("Plugin name not found in thread context")
        file_path = Path(filename).resolve()
        project_root = Path(__file__).resolve().parents[4]
        allowed_dirs = [
            (project_root / f"logs/plugin/{plugin_name}").resolve(),
            (project_root / f"plugins/{plugin_name}/data").resolve(),
        ]
        if not any(file_path.is_relative_to(p) for p in allowed_dirs):
            raise PermissionError(f"Plugin '{plugin_name}' cannot access {file_path}")
        get_logger(f"plugin.{plugin_name}.filesystem").info(
            f"Plugin file access: {filename} (mode: {mode})"
        )
        return open(filename, mode, *args, **kwargs)

    def _restricted_exec(self, *args, **kwargs):
        raise PermissionError("Dynamic code execution not allowed")

    def _restricted_eval(self, *args, **kwargs):
        raise PermissionError("Dynamic code evaluation not allowed")

    def grant_plugin_module_permission(self, p_name: str, m_name: str):
        self.plugin_module_permissions.setdefault(p_name, set()).add(m_name)

    def revoke_plugin_module_permission(self, p_name: str, m_name: str):
        self.plugin_module_permissions.get(p_name, set()).discard(m_name)

    def get_plugin_module_requests(self, p_name: str = None):
        if p_name:
            return {p_name: list(self.plugin_module_requests.get(p_name, set()))}
        return {k: list(v) for k, v in self.plugin_module_requests.items()}


class PluginTestManager:
    def __init__(self):
        self.test_results: Dict[str, Dict[str, Any]] = {}
        self.logger = logging.getLogger(__name__)

    async def run_plugin_tests(
        self, plugin_name: str, plugin_instance: PluginInterface
    ) -> Dict[str, Any]:
        try:
            self_test_results = await plugin_instance.self_test()
            results = {
                "plugin_name": plugin_name,
                "timestamp": datetime.now().isoformat(),
                "self_tests": self_test_results,
                "overall_passed": self_test_results.get("passed", False),
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


class UnifiedPluginManager:
    def __init__(self, plugins_dir: Optional[Path] = None):
        self.logger = logging.getLogger(__name__)
        if plugins_dir is None:
            project_root = Path(__file__).resolve().parents[4]
            self.plugins_dir = project_root / "plugins"
        else:
            self.plugins_dir = plugins_dir
        self.plugins_dir.mkdir(exist_ok=True)

        self.plugin_info: Dict[str, PluginInfo] = {}
        self.loaded_plugins: Dict[str, PluginInterface] = {}
        self.plugin_commands: Dict[str, Callable] = {}
        self.plugin_event_handlers: Dict[str, List[Callable]] = {}
        self.plugin_routers: Dict[str, Dict[str, Any]] = {}
        self.plugin_db_extensions: Dict[str, Dict[str, Any]] = {}
        self.plugin_security_features: Dict[str, Dict[str, Any]] = {}
        self.plugin_errors: Dict[str, List[str]] = {}
        self.plugin_dependencies_graph: Dict[str, Set[str]] = {}
        self.plugin_load_order: List[str] = []

        self.isolation_manager = PluginIsolationManager()
        self.test_manager = PluginTestManager()
        self.stats = {
            "total_discovered": 0,
            "total_loaded": 0,
            "total_enabled": 0,
            "total_failed": 0,
            "last_discovery": None,
        }
        self._lock = threading.Lock()

        # Ensure the plugin SDK (plugins_internal.py) exists and is up to date.
        # This will try to use the central SDK generator if available, otherwise
        # fall back to a lightweight generator implemented in this module.
        self._ensure_plugins_internal_generated()

    def _ensure_plugins_internal_generated(self) -> None:
        """
        Ensure plugins_internal.py is generated and validated.
        Uses the core_sdk_generator when available for robust SDK generation.
        Will regenerate if the core plugin manager file (this file) is newer than
        the generated SDK or if the generator reports it as outdated.
        """
        try:
            # Prefer the central SDK generator if available
            if core_sdk_generator:
                try:
                    # If a plugin security manager exists, provide it to the generator if it expects it
                    try:
                        setattr(
                            core_sdk_generator,
                            "plugin_security_manager",
                            core_plugin_security_manager,
                        )
                    except Exception:
                        pass

                    # Attempt to regenerate if needed (generator has its own checks)
                    regenerated = core_sdk_generator.regenerate_if_needed()
                    if not regenerated:
                        # As a last resort, if the generator didn't run successfully, try explicit generate
                        regenerated = core_sdk_generator.generate_plugins_internal()
                        if not regenerated:
                            raise RuntimeError(
                                "core_sdk_generator failed to generate plugins_internal.py"
                            )

                    # Validate the generated module
                    valid = core_sdk_generator.validate_plugins_internal()
                    if not valid:
                        raise RuntimeError(
                            "Generated plugins_internal.py failed validation"
                        )

                    # Extra safety: if this manager file changed after generation, force regenerate
                    try:
                        manager_mtime = Path(__file__).stat().st_mtime
                        gen_file = getattr(core_sdk_generator, "output_file", None)
                        if gen_file and gen_file.exists():
                            gen_mtime = gen_file.stat().st_mtime
                            if manager_mtime > gen_mtime:
                                logger.info(
                                    "Manager file is newer than generated SDK; regenerating plugins_internal.py"
                                )
                                core_sdk_generator.generate_plugins_internal()
                                core_sdk_generator.validate_plugins_internal()
                    except Exception:
                        # Non-fatal; continue
                        pass

                    logger.info(
                        "plugins_internal.py successfully generated and validated via core_sdk_generator"
                    )
                    return
                except Exception as e:
                    logger.error(f"core_sdk_generator failed: {e}", exc_info=True)

            # Fallback lightweight generation (older behavior)
            try:
                self._generate_plugin_sdk()
                # Validate by attempting to import the generated module if possible
                gen_file = self.plugins_dir.parent / "plugins_internal.py"
                if gen_file.exists():
                    try:
                        import importlib.util

                        spec = importlib.util.spec_from_file_location(
                            "plugins_internal_fallback", str(gen_file)
                        )
                        if spec and spec.loader:
                            module = importlib.util.module_from_spec(spec)
                            spec.loader.exec_module(module)
                            logger.info(
                                "Fallback plugins_internal.py generated and import-validated"
                            )
                    except Exception as e:
                        logger.error(
                            f"Fallback plugins_internal.py exists but failed to import: {e}",
                            exc_info=True,
                        )
            except Exception as e:
                logger.error(
                    f"Failed to generate fallback plugins_internal.py: {e}",
                    exc_info=True,
                )

        except Exception as e:
            logger.error(
                f"Unexpected error while ensuring plugins_internal.py: {e}",
                exc_info=True,
            )

    def _generate_plugin_sdk(self):
        try:
            sdk_content = self._create_plugin_sdk_content()
            sdk_file = self.plugins_dir.parent / "plugins_internal.py"
            sdk_file.write_text(sdk_content)
            self.logger.info(f"Generated plugin SDK (fallback): {sdk_file}")
        except Exception as e:
            self.logger.error(f"Failed to generate plugin SDK (fallback): {e}")

    def _create_plugin_sdk_content(self) -> str:
        return f'''"""
PlexiChat Plugin Internal SDK - Auto-Generated. DO NOT EDIT.
This SDK provides the core interfaces for developing PlexiChat plugins.
"""
import logging, json
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Callable
from plexichat.core.plugins.manager import EnhancedBasePlugin, EnhancedPluginConfig, EnhancedPluginAPI
__all__ = ['EnhancedBasePlugin', 'EnhancedPluginConfig', 'EnhancedPluginAPI']
# Auto-generated on: {datetime.now().isoformat()}
'''

    async def initialize(self):
        self.logger.info("Initializing unified plugin manager")
        await self.discover_plugins()
        await self.load_enabled_plugins()
        self.logger.info("Unified plugin manager initialized")

    async def discover_plugins(self) -> List[str]:
        discovered = []
        with self._lock:
            for p_dir in self.plugins_dir.iterdir():
                if not p_dir.is_dir() or p_dir.name.startswith(("_", ".")):
                    continue
                p_name = p_dir.name
                manifest_file = p_dir / "plugin.json"
                if manifest_file.exists():
                    try:
                        metadata = PluginMetadata.from_dict(
                            json.loads(manifest_file.read_text())
                        )
                        info = PluginInfo(
                            plugin_id=p_name, metadata=metadata, path=p_dir
                        )
                        self.plugin_info[p_name] = info
                        discovered.append(p_name)
                    except Exception as e:
                        self.logger.error(f"Failed to load manifest for {p_name}: {e}")
            self.stats["total_discovered"] = len(self.plugin_info)
            self.stats["last_discovery"] = datetime.now().isoformat()
        self.logger.info(f"Discovered {len(discovered)} plugins")
        return discovered

    async def load_plugin(self, plugin_name: str, force_reload: bool = False) -> bool:
        with self._lock:
            if plugin_name in self.loaded_plugins and not force_reload:
                return True
            if plugin_name not in self.plugin_info:
                self.logger.error(f"Plugin not found: {plugin_name}")
                return False
            info = self.plugin_info[plugin_name]
            info.status = PluginStatus.LOADING
        try:
            if not await self._resolve_dependencies(plugin_name):
                raise PluginError(f"Dependency resolution failed for {plugin_name}")

            if info.metadata.security_level == SecurityLevel.SANDBOXED:
                success = await self.isolation_manager.load_module_isolated(
                    plugin_name, info.path
                )
                if success:
                    # For sandboxed plugins, we need to instantiate the plugin instance
                    module = self.isolation_manager.isolated_modules.get(plugin_name)
                    if module:
                        success = await self._instantiate_plugin(
                            plugin_name, module, info
                        )
                    else:
                        success = False
            else:
                success = await self._load_plugin_direct(plugin_name, info)

            if not success:
                raise PluginError("Module loading failed")

            await self._register_plugin_components(plugin_name)
            with self._lock:
                info.status = PluginStatus.LOADED
                info.loaded_at = datetime.now()
                self.stats["total_loaded"] += 1
                self.plugin_load_order.append(plugin_name)
            self.logger.info(f"Plugin loaded successfully: {plugin_name}")
            return True
        except Exception as e:
            self.logger.error(
                f"Failed to load plugin {plugin_name}: {e}", exc_info=True
            )
            with self._lock:
                info.status = PluginStatus.FAILED
                info.error_message = str(e)
                self.stats["total_failed"] += 1
            return False

    async def _resolve_dependencies(
        self, plugin_name: str, visited: Optional[Set[str]] = None
    ) -> bool:
        visited = visited or set()
        if plugin_name in visited:
            raise PluginError(f"Circular dependency: {plugin_name}")
        visited.add(plugin_name)
        info = self.plugin_info[plugin_name]
        self.plugin_dependencies_graph.setdefault(plugin_name, set()).update(
            info.metadata.dependencies
        )
        for dep in info.metadata.dependencies:
            if dep not in self.loaded_plugins:
                if dep not in self.plugin_info:
                    raise PluginError(f"Missing dependency: {dep} for {plugin_name}")
                if not await self.load_plugin(dep):
                    raise PluginError(f"Failed to load dependency: {dep}")
        return True

    async def _load_plugin_direct(
        self, plugin_name: str, plugin_info: PluginInfo
    ) -> bool:
        module_file = plugin_info.path / "main.py"
        if not module_file.exists():
            return False
        spec = importlib.util.spec_from_file_location(
            f"plugin_{plugin_name}", module_file
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[f"plugin_{plugin_name}"] = module
        spec.loader.exec_module(module)
        return await self._instantiate_plugin(plugin_name, module, plugin_info)

    async def _instantiate_plugin(
        self, plugin_name: str, module: Any, plugin_info: PluginInfo
    ) -> bool:
        if not hasattr(module, "plugin"):
            raise PluginError(f"No 'plugin' instance in {plugin_name}")
        instance = getattr(module, "plugin")
        # For sandboxed plugins, check against the SDK's EnhancedBasePlugin class
        # since sandboxed plugins inherit from plexichat.core.plugins.sdk.EnhancedBasePlugin
        from .sdk import EnhancedBasePlugin as SDK_EnhancedBasePlugin

        if not isinstance(instance, (EnhancedBasePlugin, SDK_EnhancedBasePlugin)):
            logger.error(f"Plugin {plugin_name} instance type: {type(instance)}")
            logger.error(f"Plugin {plugin_name} instance MRO: {type(instance).__mro__}")
            raise PluginError(f"'plugin' is not EnhancedBasePlugin")
        if await instance.initialize():
            with self._lock:
                self.loaded_plugins[plugin_name] = instance
                plugin_info.instance = instance
            return True
        return False

    async def _register_plugin_components(self, plugin_name: str):
        instance = self.loaded_plugins[plugin_name]
        for name, cmd in instance.get_commands().items():
            self.plugin_commands[f"{plugin_name}.{name}"] = cmd
        for name, hnd in instance.get_event_handlers().items():
            self.plugin_event_handlers.setdefault(name, []).append(hnd)
        if routers := instance.get_routers():
            self.plugin_routers[plugin_name] = routers
        if db_exts := instance.get_db_extensions():
            self.plugin_db_extensions[plugin_name] = db_exts
        if sec_feats := instance.get_security_features():
            self.plugin_security_features[plugin_name] = sec_feats

    async def unload_plugin(self, plugin_name: str) -> bool:
        with self._lock:
            if plugin_name not in self.loaded_plugins:
                return True
            for p, deps in self.plugin_dependencies_graph.items():
                if plugin_name in deps and p in self.loaded_plugins:
                    self.logger.error(f"Cannot unload {plugin_name}, required by {p}")
                    return False
            instance = self.loaded_plugins.pop(plugin_name)
            info = self.plugin_info[plugin_name]
            info.status = PluginStatus.DISCOVERED
            info.instance = None
            self.stats["total_loaded"] -= 1
            self.plugin_load_order.remove(plugin_name)
            for cmd in list(self.plugin_commands.keys()):
                if cmd.startswith(f"{plugin_name}."):
                    del self.plugin_commands[cmd]
        await instance.shutdown()
        self.logger.info(f"Plugin unloaded: {plugin_name}")
        return True

    async def enable_plugin(self, plugin_name: str) -> bool:
        if plugin_name not in self.plugin_info:
            return False
        self.plugin_info[plugin_name].metadata.enabled = True
        return await self.load_plugin(plugin_name)

    async def disable_plugin(self, plugin_name: str) -> bool:
        if plugin_name not in self.plugin_info:
            return False
        self.plugin_info[plugin_name].metadata.enabled = False
        return await self.unload_plugin(plugin_name)

    async def load_enabled_plugins(self) -> Dict[str, bool]:
        enabled = [
            name for name, info in self.plugin_info.items() if info.metadata.enabled
        ]
        sorted_plugins = self._sort_plugins_by_dependencies(enabled)
        results = {name: await self.load_plugin(name) for name in sorted_plugins}
        self.logger.info(
            f"Loaded {sum(results.values())}/{len(enabled)} enabled plugins"
        )
        return results

    def _sort_plugins_by_dependencies(self, plugin_names: List[str]) -> List[str]:
        sorted_list = []
        graph = {p: self.plugin_info[p].metadata.dependencies for p in plugin_names}
        while graph:
            ready = [
                p for p, deps in graph.items() if not any(d in graph for d in deps)
            ]
            if not ready:
                raise PluginError(f"Circular dependency in {list(graph.keys())}")
            ready.sort(
                key=lambda p: self.plugin_info[p].metadata.priority, reverse=True
            )
            for p in ready:
                sorted_list.append(p)
                del graph[p]
        return sorted_list

    async def run_all_plugin_tests(self) -> Dict[str, Any]:
        results = {}
        for name, instance in self.loaded_plugins.items():
            results[name] = await self.test_manager.run_plugin_tests(name, instance)
        return results

    def get_all_plugin_routers(self) -> Dict[str, Any]:
        routers = {}
        [routers.update(r) for r in self.plugin_routers.values()]
        return routers

    def get_all_plugin_db_extensions(self) -> Dict[str, Any]:
        exts = {}
        [exts.update(e) for e in self.plugin_db_extensions.values()]
        return exts

    def get_all_plugin_security_features(self) -> Dict[str, Any]:
        feats = {}
        [feats.update(f) for f in self.plugin_security_features.values()]
        return feats

    async def execute_command(self, cmd: str, *a, **kw) -> Any:
        if cmd not in self.plugin_commands:
            raise PluginError(f"Command not found: {cmd}")
        func = self.plugin_commands[cmd]
        return (
            await func(*a, **kw)
            if asyncio.iscoroutinefunction(func)
            else func(*a, **kw)
        )

    async def emit_event(self, event: str, *a, **kw) -> List[Any]:
        results = []
        for handler in self.plugin_event_handlers.get(event, []):
            try:
                res = (
                    await handler(*a, **kw)
                    if asyncio.iscoroutinefunction(handler)
                    else handler(*a, **kw)
                )
                results.append(res)
            except Exception as e:
                self.logger.error(f"Event handler error for {event}: {e}")
        return results

    async def shutdown(self):
        self.logger.info("Shutting down plugin manager")
        for plugin_name in reversed(self.plugin_load_order):
            await self.unload_plugin(plugin_name)
        self.logger.info("Plugin manager shut down")

    # Utility accessors used by external modules (added to avoid missing references)
    def get_plugin_info(self, p_name: str) -> Optional[Dict[str, Any]]:
        info = self.plugin_info.get(p_name)
        if not info:
            return None
        return {
            "plugin_id": info.plugin_id,
            "metadata": info.metadata,
            "path": str(info.path),
            "status": info.status,
            "loaded_at": info.loaded_at.isoformat() if info.loaded_at else None,
            "error_message": info.error_message,
        }

    def get_all_plugins_info(self) -> Dict[str, Dict[str, Any]]:
        return {
            name: self.get_plugin_info(name) or {} for name in self.plugin_info.keys()
        }


# ==============================================================================
# 6. GLOBAL INSTANCE AND BACKWARD COMPATIBILITY
# ==============================================================================

project_root = Path(__file__).resolve().parents[4]
plugins_dir = project_root / "plugins"
unified_plugin_manager = UnifiedPluginManager(plugins_dir=plugins_dir)

# Backward compatibility aliases
plugin_manager = unified_plugin_manager
PluginManager = UnifiedPluginManager


async def get_plugin_manager() -> UnifiedPluginManager:
    return unified_plugin_manager


async def discover_plugins() -> List[str]:
    return await unified_plugin_manager.discover_plugins()


async def load_plugin(p_name: str) -> bool:
    return await unified_plugin_manager.load_plugin(p_name)


async def unload_plugin(p_name: str) -> bool:
    return await unified_plugin_manager.unload_plugin(p_name)


async def enable_plugin(p_name: str) -> bool:
    return await unified_plugin_manager.enable_plugin(p_name)


async def disable_plugin(p_name: str) -> bool:
    return await unified_plugin_manager.disable_plugin(p_name)


def get_plugin_info(p_name: str) -> Optional[Dict[str, Any]]:
    return unified_plugin_manager.get_plugin_info(p_name)


def get_all_plugins_info() -> Dict[str, Dict[str, Any]]:
    return unified_plugin_manager.get_all_plugins_info()


async def execute_command(cmd: str, *a, **kw) -> Any:
    return await unified_plugin_manager.execute_command(cmd, *a, **kw)


async def emit_event(event: str, *a, **kw) -> List[Any]:
    return await unified_plugin_manager.emit_event(event, *a, **kw)


__all__ = [
    "UnifiedPluginManager",
    "unified_plugin_manager",
    "PluginInterface",
    "PluginIsolationManager",
    "PluginTestManager",
    "PluginMetadata",
    "PluginInfo",
    "PluginType",
    "PluginStatus",
    "SecurityLevel",
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
    "plugin_manager",
    "PluginManager",
    "PluginError",
    "EnhancedBasePlugin",
    "EnhancedPluginConfig",
    "EnhancedPluginAPI",
]
