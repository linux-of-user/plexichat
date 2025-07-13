import asyncio
import hashlib
import importlib
import json
import shutil
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Type, Union

import jsonschema
import yaml
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from ...core_system.config import get_config
from ...core_system.logging import get_logger

from pathlib import Path
from pathlib import Path
from pathlib import Path
from datetime import datetime

from pathlib import Path
from pathlib import Path
from pathlib import Path
from datetime import datetime

"""
PlexiChat Enhanced Module Configuration Manager
Advanced configuration system with dynamic loading, validation, and hot-reloading
"""

logger = get_logger(__name__)


class ConfigFormat(Enum):
    """Configuration file formats."""
    YAML = "yaml"
    JSON = "json"
    TOML = "toml"
    INI = "ini"
    PYTHON = "py"


class ConfigScope(Enum):
    """Configuration scope levels."""
    GLOBAL = "global"
    MODULE = "module"
    INSTANCE = "instance"
    USER = "user"
    ENVIRONMENT = "environment"


class ValidationLevel(Enum):
    """Configuration validation levels."""
    NONE = "none"
    BASIC = "basic"
    STRICT = "strict"
    PARANOID = "paranoid"


@dataclass
class ConfigSchema:
    """Configuration schema definition."""
    name: str
    version: str
    schema: Dict[str, Any]
    validation_level: ValidationLevel = ValidationLevel.STRICT
    required_fields: List[str] = field(default_factory=list)
    optional_fields: List[str] = field(default_factory=list)
    field_types: Dict[str, Type] = field(default_factory=dict)
    field_constraints: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    custom_validators: List[Callable] = field(default_factory=list)


@dataclass
class ConfigEntry:
    """Configuration entry with metadata."""
    name: str
    scope: ConfigScope
    format: ConfigFormat
    data: Dict[str, Any]
    schema: Optional[ConfigSchema] = None
    file_path: Optional[Path] = None
    checksum: Optional[str] = None
    version: int = 1
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    modified_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    is_valid: bool = True
    validation_errors: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    hot_reload_enabled: bool = False
    backup_count: int = 5


@dataclass
class ConfigTemplate:
    """Configuration template for generating new configs."""
    name: str
    description: str
    template_data: Dict[str, Any]
    schema: Optional[ConfigSchema] = None
    variables: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)


class ConfigWatcher(FileSystemEventHandler):
    """File system watcher for configuration changes."""

    def __init__(self, config_manager):
        self.config_manager = config_manager
        super().__init__()

    def on_modified(self, event):
        if not event.is_directory:
            asyncio.create_task(self.config_manager._handle_file_change(from pathlib import Path
Path(event.src_path)))

    def on_created(self, event):
        if not event.is_directory:
            asyncio.create_task(self.config_manager._handle_file_change(from pathlib import Path
Path(event.src_path)))


class EnhancedConfigManager:
    """Enhanced configuration manager with advanced features."""

    def __init__(self, config_dir: Optional[Path] = None):
        self.config_dir = config_dir or from pathlib import Path
Path("config/modules")
        self.config_dir.mkdir(parents=True, exist_ok=True)

        # Configuration storage
        self.configs: Dict[str, ConfigEntry] = {}
        self.schemas: Dict[str, ConfigSchema] = {}
        self.templates: Dict[str, ConfigTemplate] = {}

        # Hot-reload system
        self.watchers: Dict[str, Observer] = {}
        self.reload_callbacks: Dict[str, List[Callable]] = {}

        # Validation system
        self.validators: Dict[str, Callable] = {}
        self.validation_cache: Dict[str, Dict[str, Any]] = {}

        # Backup system
        self.backup_dir = self.config_dir / "backups"
        self.backup_dir.mkdir(exist_ok=True)

        # Performance tracking
        self.load_times: Dict[str, float] = {}
        self.access_counts: Dict[str, int] = {}

        # Initialize
        self._setup_default_schemas()
        self._setup_file_watchers()

    def _setup_default_schemas(self):
        """Setup default configuration schemas."""
        # Module schema
        module_schema = ConfigSchema(
            name="module",
            version="1.0",
            schema={
                "type": "object",
                "properties": {
                    "enabled": {"type": "boolean"},
                    "priority": {"type": "integer", "minimum": 0, "maximum": 100},
                    "dependencies": {"type": "array", "items": {"type": "string"}},
                    "settings": {"type": "object"},
                    "resources": {
                        "type": "object",
                        "properties": {
                            "memory_limit": {"type": "string"},
                            "cpu_limit": {"type": "number"},
                            "timeout": {"type": "integer"}
                        }
                    }
                },
                "required": ["enabled"]
            },
            validation_level=ValidationLevel.STRICT,
            required_fields=["enabled"],
            optional_fields=["priority", "dependencies", "settings", "resources"]
        )
        self.register_schema(module_schema)

        # Security schema
        security_schema = ConfigSchema(
            name="security",
            version="1.0",
            schema={
                "type": "object",
                "properties": {
                    "encryption": {
                        "type": "object",
                        "properties": {
                            "algorithm": {"type": "string", "enum": ["AES-256", "ChaCha20"]},
                            "key_rotation": {"type": "boolean"},
                            "key_rotation_interval": {"type": "integer"}
                        }
                    },
                    "authentication": {
                        "type": "object",
                        "properties": {
                            "required": {"type": "boolean"},
                            "methods": {"type": "array", "items": {"type": "string"}},
                            "timeout": {"type": "integer"}
                        }
                    },
                    "permissions": {
                        "type": "object",
                        "properties": {
                            "read": {"type": "array", "items": {"type": "string"}},
                            "write": {"type": "array", "items": {"type": "string"}},
                            "execute": {"type": "array", "items": {"type": "string"}}
                        }
                    }
                },
                "required": ["encryption", "authentication"]
            },
            validation_level=ValidationLevel.PARANOID
        )
        self.register_schema(security_schema)

    def _setup_file_watchers(self):
        """Setup file system watchers for hot-reload."""
        try:
            self.file_watcher = ConfigWatcher(self)
            self.observer = Observer()
            self.observer.schedule(self.file_watcher, str(self.config_dir), recursive=True)
            self.observer.start()
            logger.info("Configuration file watchers started")
        except Exception as e:
            logger.error(f"Failed to setup file watchers: {e}")

    def register_schema(self, schema: ConfigSchema):
        """Register a configuration schema."""
        self.schemas[schema.name] = schema
        logger.debug(f"Registered schema: {schema.name} v{schema.version}")

    def register_template(self, template: ConfigTemplate):
        """Register a configuration template."""
        self.templates[template.name] = template
        logger.debug(f"Registered template: {template.name}")

    async def load_config(self,
                         name: str,
                         scope: ConfigScope = ConfigScope.MODULE,
                         format: Optional[ConfigFormat] = None,
                         validate: bool = True) -> Optional[ConfigEntry]:
        """Load configuration with advanced features."""
        start_time = asyncio.get_event_loop().time()

        try:
            # Check if already loaded
            if name in self.configs:
                config = self.configs[name]
                if not self._needs_reload(config):
                    self.access_counts[name] = self.access_counts.get(name, 0) + 1
                    return config

            # Find configuration file
            config_file = await self._find_config_file(name, format)
            if not config_file:
                logger.warning(f"Configuration file not found: {name}")
                return None

            # Load configuration data
            config_data = await self._load_config_data(config_file)
            if config_data is None:
                return None

            # Detect format
            detected_format = self._detect_format(config_file)

            # Create configuration entry
            config_entry = ConfigEntry(
                name=name,
                scope=scope,
                format=detected_format,
                data=config_data,
                file_path=config_file,
                checksum=self._calculate_checksum(config_data)
            )

            # Apply schema if available
            schema_name = config_data.get("schema", name)
            if schema_name in self.schemas:
                config_entry.schema = self.schemas[schema_name]

            # Validate configuration
            if validate and config_entry.schema:
                validation_result = await self._validate_config(config_entry)
                config_entry.is_valid = validation_result["valid"]
                config_entry.validation_errors = validation_result.get("errors", [])

                if not config_entry.is_valid and config_entry.schema.validation_level == ValidationLevel.PARANOID:
                    logger.error(f"Configuration validation failed for {name}: {config_entry.validation_errors}")
                    return None

            # Process dependencies
            await self._process_dependencies(config_entry)

            # Store configuration
            self.configs[name] = config_entry

            # Setup hot-reload if enabled
            if config_entry.data.get("hot_reload", False):
                await self._enable_hot_reload(name)

            # Track performance
            load_time = asyncio.get_event_loop().time() - start_time
            self.load_times[name] = load_time
            self.access_counts[name] = self.access_counts.get(name, 0) + 1

            logger.info(f"Configuration loaded: {name} ({load_time:.3f}s)")
            return config_entry

        except Exception as e:
            logger.error(f"Failed to load configuration {name}: {e}")
            return None

    async def save_config(self, config_entry: ConfigEntry, backup: bool = True) -> bool:
        """Save configuration with backup support."""
        try:
            if backup:
                await self._create_backup(config_entry)

            # Update metadata
            config_entry.modified_at = datetime.now(timezone.utc)
            config_entry.version += 1
            config_entry.checksum = self._calculate_checksum(config_entry.data)

            # Save to file
            if config_entry.file_path:
                await self._save_config_data(config_entry.file_path, config_entry.data, config_entry.format)
                logger.info(f"Configuration saved: {config_entry.name} v{config_entry.version}")
                return True

            return False

        except Exception as e:
            logger.error(f"Failed to save configuration {config_entry.name}: {e}")
            return False

    async def update_config(self,
                           name: str,
                           updates: Dict[str, Any],
                           validate: bool = True,
                           merge: bool = True) -> bool:
        """Update configuration with validation."""
        try:
            config = self.configs.get(name)
            if not config:
                logger.error(f"Configuration not found: {name}")
                return False

            # Merge or replace data
            if merge:
                self._deep_merge(config.data, updates)
            else:
                config.data = updates

            # Validate if requested
            if validate and config.schema:
                validation_result = await self._validate_config(config)
                if not validation_result["valid"]:
                    logger.error(f"Configuration update validation failed: {validation_result['errors']}")
                    return False

            # Save configuration
            success = await self.save_config(config)

            # Notify callbacks
            if success:
                await self._notify_config_change(name, "updated", updates)

            return success

        except Exception as e:
            logger.error(f"Failed to update configuration {name}: {e}")
            return False

    async def reload_config(self, name: str) -> bool:
        """Reload configuration from file."""
        try:
            if name not in self.configs:
                return await self.load_config(name) is not None

            config = self.configs[name]
            if not config.file_path or not config.file_path.exists():
                logger.warning(f"Configuration file not found for reload: {name}")
                return False

            # Check if file has changed
            current_checksum = self._calculate_file_checksum(config.file_path)
            if current_checksum == config.checksum:
                logger.debug(f"Configuration unchanged, skipping reload: {name}")
                return True

            # Backup current config
            await self._create_backup(config)

            # Reload data
            new_data = await self._load_config_data(config.file_path)
            if new_data is None:
                return False

            # Update config
            config.data = new_data
            config.modified_at = datetime.now(timezone.utc)
            config.version += 1
            config.checksum = current_checksum

            # Validate
            if config.schema:
                validation_result = await self._validate_config(config)
                config.is_valid = validation_result["valid"]
                config.validation_errors = validation_result.get("errors", [])

            # Notify callbacks
            await self._notify_config_change(name, "reloaded", config.data)

            logger.info(f"Configuration reloaded: {name} v{config.version}")
            return True

        except Exception as e:
            logger.error(f"Failed to reload configuration {name}: {e}")
            return False

    async def create_from_template(self,
                                  template_name: str,
                                  config_name: str,
                                  variables: Optional[Dict[str, Any]] = None) -> Optional[ConfigEntry]:
        """Create configuration from template."""
        try:
            template = self.templates.get(template_name)
            if not template:
                logger.error(f"Template not found: {template_name}")
                return None

            # Merge variables
            template_vars = {**template.variables, **(variables or {})}

            # Process template
            config_data = self._process_template(template.template_data, template_vars)

            # Create config entry
            config_entry = ConfigEntry(
                name=config_name,
                scope=ConfigScope.MODULE,
                format=ConfigFormat.YAML,
                data=config_data,
                schema=template.schema,
                file_path=self.config_dir / f"{config_name}.yaml"
            )

            # Validate
            if template.schema:
                validation_result = await self._validate_config(config_entry)
                config_entry.is_valid = validation_result["valid"]
                config_entry.validation_errors = validation_result.get("errors", [])

            # Save
            await self.save_config(config_entry, backup=False)

            # Store
            self.configs[config_name] = config_entry

            logger.info(f"Configuration created from template: {config_name} (template: {template_name})")
            return config_entry

        except Exception as e:
            logger.error(f"Failed to create configuration from template {template_name}: {e}")
            return None

    def register_change_callback(self, config_name: str, callback: Callable):
        """Register callback for configuration changes."""
        if config_name not in self.reload_callbacks:
            self.reload_callbacks[config_name] = []
        self.reload_callbacks[config_name].append(callback)

    def unregister_change_callback(self, config_name: str, callback: Callable):
        """Unregister configuration change callback."""
        if config_name in self.reload_callbacks and callback in self.reload_callbacks[config_name]:
            self.reload_callbacks[config_name].remove(callback)

    async def enable_hot_reload(self, config_name: str) -> bool:
        """Enable hot-reload for configuration."""
        try:
            config = self.configs.get(config_name)
            if not config:
                logger.error(f"Configuration not found: {config_name}")
                return False

            config.hot_reload_enabled = True
            await self._enable_hot_reload(config_name)

            logger.info(f"Hot-reload enabled for configuration: {config_name}")
            return True

        except Exception as e:
            logger.error(f"Failed to enable hot-reload for {config_name}: {e}")
            return False

    # Helper Methods

    async def _find_config_file(self, name: str, format: Optional[ConfigFormat] = None) -> Optional[Path]:
        """Find configuration file with format detection."""
        if format:
            extensions = [format.value]
        else:
            extensions = ["yaml", "yml", "json", "toml", "ini", "py"]

        for ext in extensions:
            config_file = self.config_dir / f"{name}.{ext}"
            if config_file.exists():
                return config_file

        return None

    async def _load_config_data(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Load configuration data from file."""
        try:
            format = self._detect_format(file_path)

            with open(file_path, 'r', encoding='utf-8') as f:
                if format == ConfigFormat.YAML:
                    return yaml.safe_load(f)
                elif format == ConfigFormat.JSON:
                    return json.load(f)
                elif format == ConfigFormat.PYTHON:
                    # Execute Python config file
                    code = f.read()
                    namespace = {}
                    exec(code, namespace)
                    return {k: v for k, v in namespace.items() if not k.startswith('_')}
                else:
                    logger.error(f"Unsupported format: {format}")
                    return None

        except Exception as e:
            logger.error(f"Failed to load config data from {file_path}: {e}")
            return None

    async def _save_config_data(self, file_path: Path, data: Dict[str, Any], format: ConfigFormat):
        """Save configuration data to file."""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                if format == ConfigFormat.YAML:
                    yaml.dump(data, f, default_flow_style=False, sort_keys=False)
                elif format == ConfigFormat.JSON:
                    json.dump(data, f, indent=2, sort_keys=False)
                else:
                    logger.error(f"Saving not supported for format: {format}")

        except Exception as e:
            logger.error(f"Failed to save config data to {file_path}: {e}")
            raise

    def _detect_format(self, file_path: Path) -> ConfigFormat:
        """Detect configuration file format."""
        suffix = file_path.suffix.lower()

        if suffix in ['.yaml', '.yml']:
            return ConfigFormat.YAML
        elif suffix == '.json':
            return ConfigFormat.JSON
        elif suffix == '.toml':
            return ConfigFormat.TOML
        elif suffix == '.ini':
            return ConfigFormat.INI
        elif suffix == '.py':
            return ConfigFormat.PYTHON
        else:
            return ConfigFormat.YAML  # Default

    def _calculate_checksum(self, data: Dict[str, Any]) -> str:
        """Calculate checksum for configuration data."""
        json_str = json.dumps(data, sort_keys=True)
        return hashlib.sha256(json_str.encode()).hexdigest()

    def _calculate_file_checksum(self, file_path: Path) -> str:
        """Calculate checksum for configuration file."""
        with open(file_path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()

    def _needs_reload(self, config: ConfigEntry) -> bool:
        """Check if configuration needs reload."""
        if not config.file_path or not config.file_path.exists():
            return False

        current_checksum = self._calculate_file_checksum(config.file_path)
        return current_checksum != config.checksum

    async def _validate_config(self, config: ConfigEntry) -> Dict[str, Any]:
        """Validate configuration against schema."""
        if not config.schema:
            return {"valid": True}

        try:
            # JSON Schema validation
            jsonschema.validate(config.data, config.schema.schema)

            # Custom validators
            for validator in config.schema.custom_validators:
                result = validator(config.data)
                if not result.get("valid", True):
                    return result

            return {"valid": True}

        except jsonschema.ValidationError as e:
            return {"valid": False, "errors": [str(e)]}
        except Exception as e:
            return {"valid": False, "errors": [f"Validation error: {e}"]}

    async def _process_dependencies(self, config: ConfigEntry):
        """Process configuration dependencies."""
        dependencies = config.data.get("dependencies", [])
        config.dependencies = dependencies

        for dep in dependencies:
            if dep not in self.configs:
                await self.load_config(dep)

    def _deep_merge(self, target: Dict[str, Any], source: Dict[str, Any]):
        """Deep merge two dictionaries."""
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                self._deep_merge(target[key], value)
            else:
                target[key] = value

    def _process_template(self, template_data: Dict[str, Any], variables: Dict[str, Any]) -> Dict[str, Any]:
        """Process template with variables."""
        # Simple variable substitution
        json_str = json.dumps(template_data)
        for key, value in variables.items():
            json_str = json_str.replace(f"${{{key}}}", str(value))
        return json.loads(json_str)

    async def _create_backup(self, config: ConfigEntry):
        """Create configuration backup."""
        if not config.file_path:
            return

        from datetime import datetime
timestamp = datetime.now()
datetime = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = self.backup_dir / f"{config.name}_{timestamp}.backup"

        try:
            shutil.copy2(config.file_path, backup_file)

            # Cleanup old backups
            await self._cleanup_backups(config.name, config.backup_count)

        except Exception as e:
            logger.error(f"Failed to create backup for {config.name}: {e}")

    async def _cleanup_backups(self, config_name: str, keep_count: int):
        """Cleanup old configuration backups."""
        try:
            pattern = f"{config_name}_*.backup"
            backups = sorted(self.backup_dir.glob(pattern), key=lambda x: x.stat().st_mtime, reverse=True)

            for backup in backups[keep_count:]:
                backup.unlink()

        except Exception as e:
            logger.error(f"Failed to cleanup backups for {config_name}: {e}")

    async def _enable_hot_reload(self, config_name: str):
        """Enable hot-reload for specific configuration."""
        # This would integrate with the file watcher system
        pass

    async def _notify_config_change(self, config_name: str, change_type: str, data: Any):
        """Notify registered callbacks of configuration changes."""
        callbacks = self.reload_callbacks.get(config_name, [])

        for callback in callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(config_name, change_type, data)
                else:
                    callback(config_name, change_type, data)
            except Exception as e:
                logger.error(f"Callback error for {config_name}: {e}")

    async def _handle_file_change(self, file_path: Path):
        """Handle file system changes."""
        config_name = file_path.stem
        if config_name in self.configs:
            config = self.configs[config_name]
            if config.hot_reload_enabled:
                await self.reload_config(config_name)


# Global instance
enhanced_config_manager = EnhancedConfigManager()
