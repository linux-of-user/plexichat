# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import jsonschema
import yaml
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from ...core.config import get_config
from ...core.logging import get_logger

from pathlib import Path
from datetime import datetime
from pathlib import Path

from pathlib import Path
from datetime import datetime
from pathlib import Path

"""
PlexiChat Unified Plugin Configuration Manager

Centralizes all plugin configuration management with:
- Hot-reloadable configuration
- Schema validation
- Configuration inheritance
- Environment-specific overrides
- Real-time configuration updates
- Configuration versioning and rollback
"""

logger = get_logger(__name__)


@dataclass
class PluginConfigSchema:
    """Plugin configuration schema definition."""
    name: str
    version: str
    schema: Dict[str, Any]
    default_values: Dict[str, Any] = field(default_factory=dict)
    required_fields: List[str] = field(default_factory=list)
    environment_overrides: Dict[str, Dict[str, Any]] = field(default_factory=dict)


@dataclass
class ConfigurationEntry:
    """Configuration entry with metadata."""
    plugin_name: str
    config_data: Dict[str, Any]
    schema: Optional[PluginConfigSchema] = None
    last_modified: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    version: int = 1
    source_file: Optional[Path] = None
    is_valid: bool = True
    validation_errors: List[str] = field(default_factory=list)


class PluginConfigurationManager:
    """
    Unified Plugin Configuration Manager

    Manages all plugin configurations through a centralized system with:
    - Automatic discovery of plugin configurations
    - Schema validation and type checking
    - Hot-reloading of configuration changes
    - Environment-specific configuration overrides
    - Configuration versioning and rollback
    - Real-time configuration updates
    """

    def __init__(self, config_dir: Optional[Path] = None):
        from pathlib import Path
        self.config_dir = config_dir or Path("config/plugins")
        self.schemas_dir = self.config_dir / "schemas"
        self.environments_dir = self.config_dir / "environments"
        self.backups_dir = self.config_dir / "backups"

        # Create directories
        for directory in [self.config_dir, self.schemas_dir, self.environments_dir, self.backups_dir]:
            directory.mkdir(parents=True, exist_ok=True)

        # Configuration storage
        self.configurations: Dict[str, ConfigurationEntry] = {}
        self.schemas: Dict[str, PluginConfigSchema] = {}

        # Hot-reload support
        self.file_observer: Optional[Observer] = None
        self.reload_callbacks: Dict[str, List[Callable]] = {}
        self.hot_reload_enabled = True

        # Environment settings
        self.current_environment = get_config().server.environment

        # Configuration cache
        self.config_cache: Dict[str, Dict[str, Any]] = {}
        self.cache_ttl = 300  # 5 minutes
        self.last_cache_update: Dict[str, datetime] = {}

        logger.info("Plugin Configuration Manager initialized")

    async def initialize(self) -> bool:
        """Initialize the configuration manager."""
        try:
            # Load all schemas
            await self._load_schemas()

            # Load all configurations
            await self._load_configurations()

            # Start file watching for hot-reload
            if self.hot_reload_enabled:
                self._start_file_watching()

            logger.info(" Plugin Configuration Manager initialized successfully")
            return True

        except Exception as e:
            logger.error(f" Configuration Manager initialization failed: {e}")
            return False

    async def register_plugin_config(self,
                                   plugin_name: str,
                                   config_data: Dict[str, Any],
                                   schema: Optional[PluginConfigSchema] = None) -> bool:
        """Register a plugin configuration."""
        try:
            # Validate configuration if schema provided
            if schema:
                validation_result = self._validate_config(config_data, schema)
                if not validation_result["valid"]:
                    logger.error(f"Configuration validation failed for {plugin_name}: {validation_result['errors']}")
                    return False

                self.schemas[plugin_name] = schema

            # Apply environment overrides
            final_config = self._apply_environment_overrides(plugin_name, config_data)

            # Create configuration entry
            config_entry = ConfigurationEntry(
                plugin_name=plugin_name,
                config_data=final_config,
                schema=schema,
                is_valid=True
            )

            self.configurations[plugin_name] = config_entry

            # Save to file
            await self._save_plugin_config(plugin_name, config_entry)

            # Clear cache
            self._clear_cache(plugin_name)

            # Notify callbacks
            await self._notify_config_change(plugin_name, "registered")

            logger.info(f"Plugin configuration registered: {plugin_name}")
            return True

        except Exception as e:
            logger.error(f"Failed to register plugin config {plugin_name}: {e}")
            return False

    async def update_plugin_config(self,
                                 plugin_name: str,
                                 config_updates: Dict[str, Any],
                                 validate: bool = True) -> bool:
        """Update a plugin configuration."""
        try:
            if plugin_name not in self.configurations:
                logger.error(f"Plugin configuration not found: {plugin_name}")
                return False

            config_entry = self.configurations[plugin_name]

            # Backup current configuration
            await self._backup_config(plugin_name, config_entry)

            # Merge updates
            updated_config = {**config_entry.config_data, **config_updates}

            # Validate if requested
            if validate and config_entry.schema:
                validation_result = self._validate_config(updated_config, config_entry.schema)
                if not validation_result["valid"]:
                    logger.error(f"Configuration update validation failed for {plugin_name}: {validation_result['errors']}")
                    return False

            # Apply environment overrides
            final_config = self._apply_environment_overrides(plugin_name, updated_config)

            # Update configuration entry
            config_entry.config_data = final_config
            config_entry.last_modified = datetime.now(timezone.utc)
            config_entry.version += 1
            config_entry.is_valid = True
            config_entry.validation_errors = []

            # Save to file
            await self._save_plugin_config(plugin_name, config_entry)

            # Clear cache
            self._clear_cache(plugin_name)

            # Notify callbacks
            await self._notify_config_change(plugin_name, "updated")

            logger.info(f"Plugin configuration updated: {plugin_name} (version {config_entry.version})")
            return True

        except Exception as e:
            logger.error(f"Failed to update plugin config {plugin_name}: {e}")
            return False

    def get_plugin_config(self, plugin_name: str, use_cache: bool = True) -> Optional[Dict[str, Any]]:
        """Get plugin configuration."""
        try:
            # Check cache first
            if use_cache and plugin_name in self.config_cache:
                cache_time = self.last_cache_update.get(plugin_name)
                if cache_time and (datetime.now(timezone.utc) - cache_time).total_seconds() < self.cache_ttl:
                    return self.config_cache[plugin_name].copy()

            # Get from storage
            if plugin_name not in self.configurations:
                logger.warning(f"Plugin configuration not found: {plugin_name}")
                return None

            config_entry = self.configurations[plugin_name]
            config_data = config_entry.config_data.copy()

            # Update cache
            if use_cache:
                self.config_cache[plugin_name] = config_data.copy()
                self.last_cache_update[plugin_name] = datetime.now(timezone.utc)

            return config_data

        except Exception as e:
            logger.error(f"Failed to get plugin config {plugin_name}: {e}")
            return None

    def get_config_value(self, plugin_name: str, key: str, default: Optional[Any] = None) -> Any:
        """Get a specific configuration value."""
        config = self.get_plugin_config(plugin_name)
        if config is None:
            return default

        # Support nested keys with dot notation
        keys = key.split('.')
        value = config

        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default

    async def reload_plugin_config(self, plugin_name: str) -> bool:
        """Reload plugin configuration from file."""
        try:
            config_file = self.config_dir / f"{plugin_name}.yaml"
            if not config_file.exists():
                config_file = self.config_dir / f"{plugin_name}.json"

            if not config_file.exists():
                logger.warning(f"No configuration file found for plugin: {plugin_name}")
                return False

            # Load configuration from file
            config_data = await self._load_config_file(config_file)
            if config_data is None:
                return False

            # Get existing schema if available
            schema = self.schemas.get(plugin_name)

            # Register the reloaded configuration
            return await self.register_plugin_config(plugin_name, config_data, schema)

        except Exception as e:
            logger.error(f"Failed to reload plugin config {plugin_name}: {e}")
            return False

    def register_config_change_callback(self, plugin_name: str, callback: Callable):
        """Register a callback for configuration changes."""
        if plugin_name not in self.reload_callbacks:
            self.reload_callbacks[plugin_name] = []
        self.reload_callbacks[plugin_name].append(callback)

    def unregister_config_change_callback(self, plugin_name: str, callback: Callable):
        """Unregister a configuration change callback."""
        if plugin_name in self.reload_callbacks and callback in self.reload_callbacks[plugin_name]:
            self.reload_callbacks[plugin_name].remove(callback)

    async def _load_schemas(self):
        """Load all plugin schemas."""
        try:
            for schema_file in self.schemas_dir.glob("*.json"):
                plugin_name = schema_file.stem

                with open(schema_file, 'r') as f:
                    schema_data = json.load(f)

                schema = PluginConfigSchema(
                    name=plugin_name,
                    version=schema_data.get("version", "1.0.0"),
                    schema=schema_data.get("schema", {}),
                    default_values=schema_data.get("defaults", {}),
                    required_fields=schema_data.get("required", []),
                    environment_overrides=schema_data.get("environment_overrides", {})
                )

                self.schemas[plugin_name] = schema
                logger.debug(f"Loaded schema for plugin: {plugin_name}")

        except Exception as e:
            logger.error(f"Failed to load schemas: {e}")

    async def _load_configurations(self):
        """Load all plugin configurations."""
        try:
            # Load from YAML files
            for config_file in self.config_dir.glob("*.yaml"):
                plugin_name = config_file.stem
                config_data = await self._load_config_file(config_file)

                if config_data:
                    schema = self.schemas.get(plugin_name)
                    await self.register_plugin_config(plugin_name, config_data, schema)

            # Load from JSON files (fallback)
            for config_file in self.config_dir.glob("*.json"):
                plugin_name = config_file.stem

                # Skip if already loaded from YAML
                if plugin_name in self.configurations:
                    continue

                config_data = await self._load_config_file(config_file)

                if config_data:
                    schema = self.schemas.get(plugin_name)
                    await self.register_plugin_config(plugin_name, config_data, schema)

        except Exception as e:
            logger.error(f"Failed to load configurations: {e}")

    async def _load_config_file(self, config_file: Path) -> Optional[Dict[str, Any]]:
        """Load configuration from file."""
        try:
            with open(config_file, 'r') as f:
                if config_file.suffix.lower() in ['.yaml', '.yml']:
                    return yaml.safe_load(f)
                else:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load config file {config_file}: {e}")
            return None

    def _validate_config(self, config_data: Dict[str, Any], schema: PluginConfigSchema) -> Dict[str, Any]:
        """Validate configuration against schema."""
        try:
            jsonschema.validate(config_data, schema.schema)
            return {"valid": True, "errors": []}
        except jsonschema.ValidationError as e:
            return {"valid": False, "errors": [str(e)]}
        except Exception as e:
            return {"valid": False, "errors": [f"Validation error: {str(e)}"]}

    def _apply_environment_overrides(self, plugin_name: str, config_data: Dict[str, Any]) -> Dict[str, Any]:
        """Apply environment-specific configuration overrides."""
        try:
            # Check for environment-specific config file
            env_config_file = self.environments_dir / self.current_environment / f"{plugin_name}.yaml"
            if env_config_file.exists():
                with open(env_config_file, 'r') as f:
                    env_overrides = yaml.safe_load(f) or {}

                # Deep merge environment overrides
                return self._deep_merge(config_data, env_overrides)

            # Check schema for environment overrides
            schema = self.schemas.get(plugin_name)
            if schema and self.current_environment in schema.environment_overrides:
                env_overrides = schema.environment_overrides[self.current_environment]
                return self._deep_merge(config_data, env_overrides)

            return config_data

        except Exception as e:
            logger.error(f"Failed to apply environment overrides for {plugin_name}: {e}")
            return config_data

    def _deep_merge(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """Deep merge two dictionaries."""
        result = base.copy()

        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value

        return result

    async def _save_plugin_config(self, plugin_name: str, config_entry: ConfigurationEntry):
        """Save plugin configuration to file."""
        try:
            config_file = self.config_dir / f"{plugin_name}.yaml"

            # Prepare data for saving
            save_data = {
                "# Plugin Configuration": f"Configuration for {plugin_name}",
                "# Last Modified": config_entry.last_modified.isoformat(),
                "# Version": config_entry.version,
                **config_entry.config_data
            }

            with open(config_file, 'w') as f:
                yaml.dump(save_data, f, default_flow_style=False, sort_keys=False)

            config_entry.source_file = config_file

        except Exception as e:
            logger.error(f"Failed to save plugin config {plugin_name}: {e}")

    async def _backup_config(self, plugin_name: str, config_entry: ConfigurationEntry):
        """Backup current configuration."""
        try:
            backup_file = self.backups_dir / f"{plugin_name}_v{config_entry.version}_{int(from datetime import datetime
datetime = datetime.now().timestamp())}.yaml"

            backup_data = {
                "plugin_name": plugin_name,
                "version": config_entry.version,
                "timestamp": config_entry.last_modified.isoformat(),
                "config": config_entry.config_data
            }

            with open(backup_file, 'w') as f:
                yaml.dump(backup_data, f, default_flow_style=False)

        except Exception as e:
            logger.error(f"Failed to backup config for {plugin_name}: {e}")

    def _clear_cache(self, plugin_name: str):
        """Clear configuration cache for a plugin."""
        if plugin_name in self.config_cache:
            del self.config_cache[plugin_name]
        if plugin_name in self.last_cache_update:
            del self.last_cache_update[plugin_name]

    async def _notify_config_change(self, plugin_name: str, change_type: str):
        """Notify callbacks of configuration changes."""
        try:
            if plugin_name in self.reload_callbacks:
                for callback in self.reload_callbacks[plugin_name]:
                    try:
                        if asyncio.iscoroutinefunction(callback):
                            await callback(plugin_name, change_type)
                        else:
                            callback(plugin_name, change_type)
                    except Exception as e:
                        logger.error(f"Config change callback failed: {e}")

        except Exception as e:
            logger.error(f"Failed to notify config change for {plugin_name}: {e}")

    def _start_file_watching(self):
        """Start watching configuration files for changes."""
        try:
            class ConfigFileHandler(FileSystemEventHandler):
                def __init__(self, config_manager):
                    self.config_manager = config_manager

                def on_modified(self, event):
                    if event.is_directory:
                        return

                    from pathlib import Path
file_path = Path
Path(event.src_path)
                    if file_path.suffix.lower() in ['.yaml', '.yml', '.json']:
                        plugin_name = file_path.stem
                        logger.info(f"Configuration file changed: {file_path}")

                        # Schedule reload
                        asyncio.create_task(
                            self.config_manager.reload_plugin_config(plugin_name)
                        )

            self.file_observer = Observer()
            handler = ConfigFileHandler(self)

            self.file_observer.schedule(handler, str(self.config_dir), recursive=True)
            self.if file_observer and hasattr(file_observer, "start"): file_observer.start()

            logger.info("Configuration file watching started")

        except Exception as e:
            logger.error(f"Failed to start file watching: {e}")

    def get_configuration_status(self) -> Dict[str, Any]:
        """Get configuration manager status."""
        return {
            "plugin_configuration": {
                "total_configurations": len(self.configurations),
                "total_schemas": len(self.schemas),
                "hot_reload_enabled": self.hot_reload_enabled,
                "current_environment": self.current_environment,
                "cache_entries": len(self.config_cache),
                "configurations": {
                    name: {
                        "version": entry.version,
                        "last_modified": entry.last_modified.isoformat(),
                        "is_valid": entry.is_valid,
                        "has_schema": entry.schema is not None
                    }
                    for name, entry in self.configurations.items()
                }
            }
        }

    async def shutdown(self):
        """Shutdown configuration manager."""
        logger.info("Shutting down Plugin Configuration Manager")

        if self.file_observer:
            self.if file_observer and hasattr(file_observer, "stop"): file_observer.stop()
            self.file_observer.join()


# Global instance
_config_manager: Optional[PluginConfigurationManager] = None


def get_plugin_config_manager() -> PluginConfigurationManager:
    """Get the global plugin configuration manager instance."""
    global _config_manager
    if _config_manager is None:
        _config_manager = PluginConfigurationManager()
    return _config_manager


# Export main components
__all__ = [
    "PluginConfigurationManager",
    "get_plugin_config_manager",
    "PluginConfigSchema",
    "ConfigurationEntry"
]
