"""
NetLink Enhanced Plugin Management System

Advanced plugin system with root storage, marketplace integration,
security validation, and comprehensive lifecycle management.
"""

import asyncio
import json
import shutil
import zipfile
import hashlib
import secrets
from typing import Dict, List, Optional, Any, Set, Callable
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
import logging
import importlib
import importlib.util
import sys
import tempfile
import subprocess

logger = logging.getLogger(__name__)


class PluginStatus(Enum):
    """Plugin status enumeration."""
    DISABLED = "disabled"
    ENABLED = "enabled"
    LOADING = "loading"
    RUNNING = "running"
    ERROR = "error"
    UPDATING = "updating"
    UNINSTALLING = "uninstalling"


class PluginType(Enum):
    """Plugin type enumeration."""
    CORE = "core"
    UI = "ui"
    API = "api"
    INTEGRATION = "integration"
    UTILITY = "utility"
    THEME = "theme"
    LANGUAGE = "language"
    EXTENSION = "extension"


class SecurityLevel(Enum):
    """Plugin security levels."""
    SAFE = "safe"
    TRUSTED = "trusted"
    SANDBOXED = "sandboxed"
    RESTRICTED = "restricted"
    DANGEROUS = "dangerous"


@dataclass
class PluginMetadata:
    """Enhanced plugin metadata."""
    plugin_id: str
    name: str
    description: str
    version: str
    author: str
    author_email: Optional[str] = None
    website: Optional[str] = None
    license: str = "MIT"
    
    # Plugin classification
    plugin_type: PluginType = PluginType.UTILITY
    security_level: SecurityLevel = SecurityLevel.SANDBOXED
    
    # Dependencies and compatibility
    dependencies: List[str] = field(default_factory=list)
    netlink_version_min: str = "1.0.0"
    netlink_version_max: Optional[str] = None
    python_version_min: str = "3.8"
    
    # Plugin configuration
    config_schema: Dict[str, Any] = field(default_factory=dict)
    default_config: Dict[str, Any] = field(default_factory=dict)
    
    # Capabilities and permissions
    permissions: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    hooks: List[str] = field(default_factory=list)
    
    # Installation info
    install_date: Optional[datetime] = None
    last_update: Optional[datetime] = None
    file_hash: Optional[str] = None
    signature: Optional[str] = None
    
    # Runtime info
    status: PluginStatus = PluginStatus.DISABLED
    error_message: Optional[str] = None
    load_time: Optional[float] = None


@dataclass
class PluginStorage:
    """Plugin storage configuration."""
    root_path: Path
    plugins_path: Path
    cache_path: Path
    temp_path: Path
    config_path: Path
    
    def ensure_directories(self):
        """Ensure all storage directories exist."""
        for path in [self.plugins_path, self.cache_path, self.temp_path, self.config_path]:
            path.mkdir(parents=True, exist_ok=True)


class PluginSecurityValidator:
    """Security validator for plugins."""
    
    def __init__(self):
        self.dangerous_imports = {
            'os', 'sys', 'subprocess', 'importlib', '__import__',
            'eval', 'exec', 'compile', 'open', 'file', 'input',
            'raw_input', 'reload', 'vars', 'globals', 'locals'
        }
        
        self.dangerous_functions = {
            'eval', 'exec', 'compile', '__import__', 'getattr',
            'setattr', 'delattr', 'hasattr', 'callable'
        }
    
    async def validate_plugin(self, plugin_path: Path) -> Dict[str, Any]:
        """Validate plugin security."""
        validation_result = {
            "is_safe": True,
            "security_level": SecurityLevel.SAFE,
            "issues": [],
            "warnings": [],
            "permissions_needed": []
        }
        
        try:
            # Check file structure
            await self._validate_file_structure(plugin_path, validation_result)
            
            # Scan Python files for dangerous code
            await self._scan_python_files(plugin_path, validation_result)
            
            # Check metadata and permissions
            await self._validate_metadata(plugin_path, validation_result)
            
            # Determine final security level
            self._determine_security_level(validation_result)
            
        except Exception as e:
            validation_result["is_safe"] = False
            validation_result["issues"].append(f"Validation error: {str(e)}")
            validation_result["security_level"] = SecurityLevel.DANGEROUS
        
        return validation_result
    
    async def _validate_file_structure(self, plugin_path: Path, result: Dict[str, Any]):
        """Validate plugin file structure."""
        required_files = ["plugin.json", "__init__.py"]
        
        for required_file in required_files:
            if not (plugin_path / required_file).exists():
                result["issues"].append(f"Missing required file: {required_file}")
                result["is_safe"] = False
    
    async def _scan_python_files(self, plugin_path: Path, result: Dict[str, Any]):
        """Scan Python files for dangerous code patterns."""
        for py_file in plugin_path.rglob("*.py"):
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Check for dangerous imports
                for dangerous_import in self.dangerous_imports:
                    if f"import {dangerous_import}" in content or f"from {dangerous_import}" in content:
                        result["warnings"].append(f"Potentially dangerous import '{dangerous_import}' in {py_file.name}")
                        result["permissions_needed"].append(f"system_access")
                
                # Check for dangerous function calls
                for dangerous_func in self.dangerous_functions:
                    if f"{dangerous_func}(" in content:
                        result["warnings"].append(f"Potentially dangerous function '{dangerous_func}' in {py_file.name}")
                        result["permissions_needed"].append(f"code_execution")
                
                # Check for file operations
                if any(pattern in content for pattern in ["open(", "file(", "with open"]):
                    result["permissions_needed"].append("file_access")
                
                # Check for network operations
                if any(pattern in content for pattern in ["urllib", "requests", "socket", "http"]):
                    result["permissions_needed"].append("network_access")
                
            except Exception as e:
                result["warnings"].append(f"Could not scan {py_file.name}: {str(e)}")
    
    async def _validate_metadata(self, plugin_path: Path, result: Dict[str, Any]):
        """Validate plugin metadata."""
        metadata_file = plugin_path / "plugin.json"
        
        if not metadata_file.exists():
            result["issues"].append("Missing plugin.json metadata file")
            result["is_safe"] = False
            return
        
        try:
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            
            required_fields = ["plugin_id", "name", "version", "author"]
            for field in required_fields:
                if field not in metadata:
                    result["issues"].append(f"Missing required metadata field: {field}")
                    result["is_safe"] = False
            
            # Check permissions
            permissions = metadata.get("permissions", [])
            for permission in permissions:
                if permission in ["system_admin", "file_system", "network_unrestricted"]:
                    result["warnings"].append(f"High-privilege permission requested: {permission}")
                    result["permissions_needed"].append(permission)
            
        except json.JSONDecodeError as e:
            result["issues"].append(f"Invalid JSON in plugin.json: {str(e)}")
            result["is_safe"] = False
    
    def _determine_security_level(self, result: Dict[str, Any]):
        """Determine the final security level."""
        if not result["is_safe"]:
            result["security_level"] = SecurityLevel.DANGEROUS
        elif len(result["issues"]) > 0:
            result["security_level"] = SecurityLevel.RESTRICTED
        elif len(result["warnings"]) > 3:
            result["security_level"] = SecurityLevel.SANDBOXED
        elif len(result["permissions_needed"]) > 0:
            result["security_level"] = SecurityLevel.TRUSTED
        else:
            result["security_level"] = SecurityLevel.SAFE


class EnhancedPluginManager:
    """Enhanced plugin management system."""
    
    def __init__(self, root_storage_path: str = "plugins"):
        # Setup storage
        self.storage = PluginStorage(
            root_path=Path(root_storage_path),
            plugins_path=Path(root_storage_path) / "installed",
            cache_path=Path(root_storage_path) / "cache",
            temp_path=Path(root_storage_path) / "temp",
            config_path=Path(root_storage_path) / "config"
        )
        self.storage.ensure_directories()
        
        # Plugin registry
        self.plugins: Dict[str, PluginMetadata] = {}
        self.loaded_plugins: Dict[str, Any] = {}
        self.plugin_configs: Dict[str, Dict[str, Any]] = {}
        
        # Security and validation
        self.security_validator = PluginSecurityValidator()
        
        # Hook system
        self.hooks: Dict[str, List[Callable]] = {}
        
        # Statistics
        self.stats = {
            "total_plugins": 0,
            "enabled_plugins": 0,
            "disabled_plugins": 0,
            "failed_plugins": 0,
            "installations": 0,
            "updates": 0
        }
        
        # Load existing plugins
        asyncio.create_task(self._load_existing_plugins())
        
        logger.info("Enhanced Plugin Manager initialized")
    
    async def _load_existing_plugins(self):
        """Load existing plugins from storage."""
        try:
            for plugin_dir in self.storage.plugins_path.iterdir():
                if plugin_dir.is_dir():
                    await self._load_plugin_metadata(plugin_dir)
            
            logger.info(f"Loaded {len(self.plugins)} existing plugins")
            
        except Exception as e:
            logger.error(f"Failed to load existing plugins: {e}")
    
    async def _load_plugin_metadata(self, plugin_dir: Path) -> Optional[PluginMetadata]:
        """Load plugin metadata from directory."""
        try:
            metadata_file = plugin_dir / "plugin.json"
            if not metadata_file.exists():
                logger.warning(f"No metadata file found in {plugin_dir}")
                return None
            
            with open(metadata_file, 'r') as f:
                metadata_dict = json.load(f)
            
            # Convert to PluginMetadata
            metadata = PluginMetadata(
                plugin_id=metadata_dict["plugin_id"],
                name=metadata_dict["name"],
                description=metadata_dict.get("description", ""),
                version=metadata_dict["version"],
                author=metadata_dict["author"],
                author_email=metadata_dict.get("author_email"),
                website=metadata_dict.get("website"),
                license=metadata_dict.get("license", "MIT"),
                plugin_type=PluginType(metadata_dict.get("plugin_type", "utility")),
                security_level=SecurityLevel(metadata_dict.get("security_level", "sandboxed")),
                dependencies=metadata_dict.get("dependencies", []),
                netlink_version_min=metadata_dict.get("netlink_version_min", "1.0.0"),
                netlink_version_max=metadata_dict.get("netlink_version_max"),
                python_version_min=metadata_dict.get("python_version_min", "3.8"),
                config_schema=metadata_dict.get("config_schema", {}),
                default_config=metadata_dict.get("default_config", {}),
                permissions=metadata_dict.get("permissions", []),
                api_endpoints=metadata_dict.get("api_endpoints", []),
                hooks=metadata_dict.get("hooks", [])
            )
            
            # Set runtime info
            if "install_date" in metadata_dict:
                metadata.install_date = datetime.fromisoformat(metadata_dict["install_date"])
            if "last_update" in metadata_dict:
                metadata.last_update = datetime.fromisoformat(metadata_dict["last_update"])
            
            metadata.file_hash = metadata_dict.get("file_hash")
            metadata.signature = metadata_dict.get("signature")
            
            self.plugins[metadata.plugin_id] = metadata
            return metadata
            
        except Exception as e:
            logger.error(f"Failed to load plugin metadata from {plugin_dir}: {e}")
            return None
    
    async def install_plugin(self, plugin_file: Path, validate_security: bool = True) -> bool:
        """Install a plugin from a file."""
        try:
            # Create temporary extraction directory
            with tempfile.TemporaryDirectory(dir=self.storage.temp_path) as temp_dir:
                temp_path = Path(temp_dir)
                
                # Extract plugin
                if plugin_file.suffix == '.zip':
                    with zipfile.ZipFile(plugin_file, 'r') as zip_ref:
                        zip_ref.extractall(temp_path)
                else:
                    # Assume it's a directory
                    shutil.copytree(plugin_file, temp_path / plugin_file.name)
                
                # Find plugin directory (should contain plugin.json)
                plugin_dir = None
                for item in temp_path.iterdir():
                    if item.is_dir() and (item / "plugin.json").exists():
                        plugin_dir = item
                        break
                
                if not plugin_dir:
                    logger.error("No valid plugin directory found in archive")
                    return False
                
                # Load metadata
                metadata = await self._load_plugin_metadata(plugin_dir)
                if not metadata:
                    logger.error("Failed to load plugin metadata")
                    return False
                
                # Security validation
                if validate_security:
                    validation_result = await self.security_validator.validate_plugin(plugin_dir)
                    if not validation_result["is_safe"]:
                        logger.error(f"Plugin failed security validation: {validation_result['issues']}")
                        return False
                    
                    metadata.security_level = validation_result["security_level"]
                
                # Check if plugin already exists
                if metadata.plugin_id in self.plugins:
                    logger.warning(f"Plugin {metadata.plugin_id} already installed")
                    return False
                
                # Calculate file hash
                metadata.file_hash = await self._calculate_directory_hash(plugin_dir)
                metadata.install_date = datetime.now(timezone.utc)
                
                # Copy to plugins directory
                final_plugin_dir = self.storage.plugins_path / metadata.plugin_id
                shutil.copytree(plugin_dir, final_plugin_dir)
                
                # Save updated metadata
                await self._save_plugin_metadata(metadata, final_plugin_dir)
                
                # Register plugin
                self.plugins[metadata.plugin_id] = metadata
                
                # Load default configuration
                self.plugin_configs[metadata.plugin_id] = metadata.default_config.copy()
                
                self.stats["total_plugins"] += 1
                self.stats["installations"] += 1
                
                logger.info(f"Successfully installed plugin: {metadata.name}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to install plugin: {e}")
            return False
    
    async def _calculate_directory_hash(self, directory: Path) -> str:
        """Calculate hash of directory contents."""
        hasher = hashlib.sha256()
        
        for file_path in sorted(directory.rglob("*")):
            if file_path.is_file():
                with open(file_path, 'rb') as f:
                    hasher.update(f.read())
        
        return hasher.hexdigest()
    
    async def _save_plugin_metadata(self, metadata: PluginMetadata, plugin_dir: Path):
        """Save plugin metadata to file."""
        metadata_dict = asdict(metadata)
        
        # Convert datetime objects to ISO strings
        if metadata_dict["install_date"]:
            metadata_dict["install_date"] = metadata.install_date.isoformat()
        if metadata_dict["last_update"]:
            metadata_dict["last_update"] = metadata.last_update.isoformat()
        
        # Convert enums to strings
        metadata_dict["plugin_type"] = metadata.plugin_type.value
        metadata_dict["security_level"] = metadata.security_level.value
        metadata_dict["status"] = metadata.status.value
        
        metadata_file = plugin_dir / "plugin.json"
        with open(metadata_file, 'w') as f:
            json.dump(metadata_dict, f, indent=2)
    
    async def enable_plugin(self, plugin_id: str) -> bool:
        """Enable a plugin."""
        if plugin_id not in self.plugins:
            logger.error(f"Plugin not found: {plugin_id}")
            return False
        
        metadata = self.plugins[plugin_id]
        
        if metadata.status == PluginStatus.RUNNING:
            logger.info(f"Plugin already enabled: {plugin_id}")
            return True
        
        try:
            metadata.status = PluginStatus.LOADING
            
            # Load plugin module
            plugin_dir = self.storage.plugins_path / plugin_id
            plugin_module = await self._load_plugin_module(plugin_dir, metadata)
            
            if not plugin_module:
                metadata.status = PluginStatus.ERROR
                metadata.error_message = "Failed to load plugin module"
                return False
            
            # Initialize plugin
            if hasattr(plugin_module, 'initialize'):
                if not await plugin_module.initialize():
                    metadata.status = PluginStatus.ERROR
                    metadata.error_message = "Plugin initialization failed"
                    return False
            
            # Register hooks
            if hasattr(plugin_module, 'register_hooks'):
                await plugin_module.register_hooks(self)
            
            self.loaded_plugins[plugin_id] = plugin_module
            metadata.status = PluginStatus.RUNNING
            metadata.error_message = None
            
            self.stats["enabled_plugins"] += 1
            
            logger.info(f"Enabled plugin: {metadata.name}")
            return True
            
        except Exception as e:
            metadata.status = PluginStatus.ERROR
            metadata.error_message = str(e)
            self.stats["failed_plugins"] += 1
            logger.error(f"Failed to enable plugin {plugin_id}: {e}")
            return False
    
    async def _load_plugin_module(self, plugin_dir: Path, metadata: PluginMetadata):
        """Load plugin module."""
        try:
            # Add plugin directory to Python path
            plugin_path = str(plugin_dir)
            if plugin_path not in sys.path:
                sys.path.insert(0, plugin_path)
            
            # Import main module
            main_file = plugin_dir / "__init__.py"
            if not main_file.exists():
                main_file = plugin_dir / "main.py"
            
            if not main_file.exists():
                logger.error(f"No main module found for plugin {metadata.plugin_id}")
                return None
            
            spec = importlib.util.spec_from_file_location(
                f"plugin_{metadata.plugin_id}",
                main_file
            )
            
            if not spec or not spec.loader:
                logger.error(f"Could not load spec for plugin {metadata.plugin_id}")
                return None
            
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            return module
            
        except Exception as e:
            logger.error(f"Failed to load plugin module: {e}")
            return None
    
    async def disable_plugin(self, plugin_id: str) -> bool:
        """Disable a plugin."""
        if plugin_id not in self.plugins:
            logger.error(f"Plugin not found: {plugin_id}")
            return False
        
        metadata = self.plugins[plugin_id]
        
        if metadata.status != PluginStatus.RUNNING:
            logger.info(f"Plugin not running: {plugin_id}")
            return True
        
        try:
            # Shutdown plugin
            if plugin_id in self.loaded_plugins:
                plugin_module = self.loaded_plugins[plugin_id]
                
                if hasattr(plugin_module, 'shutdown'):
                    await plugin_module.shutdown()
                
                del self.loaded_plugins[plugin_id]
            
            metadata.status = PluginStatus.DISABLED
            metadata.error_message = None
            
            self.stats["enabled_plugins"] = max(0, self.stats["enabled_plugins"] - 1)
            
            logger.info(f"Disabled plugin: {metadata.name}")
            return True
            
        except Exception as e:
            metadata.status = PluginStatus.ERROR
            metadata.error_message = str(e)
            logger.error(f"Failed to disable plugin {plugin_id}: {e}")
            return False
    
    async def uninstall_plugin(self, plugin_id: str) -> bool:
        """Uninstall a plugin."""
        if plugin_id not in self.plugins:
            logger.error(f"Plugin not found: {plugin_id}")
            return False
        
        try:
            # Disable plugin first
            await self.disable_plugin(plugin_id)
            
            # Remove plugin directory
            plugin_dir = self.storage.plugins_path / plugin_id
            if plugin_dir.exists():
                shutil.rmtree(plugin_dir)
            
            # Remove from registry
            del self.plugins[plugin_id]
            
            # Remove configuration
            if plugin_id in self.plugin_configs:
                del self.plugin_configs[plugin_id]
            
            self.stats["total_plugins"] = max(0, self.stats["total_plugins"] - 1)
            
            logger.info(f"Uninstalled plugin: {plugin_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to uninstall plugin {plugin_id}: {e}")
            return False
    
    def register_hook(self, hook_name: str, callback: Callable):
        """Register a hook callback."""
        if hook_name not in self.hooks:
            self.hooks[hook_name] = []
        
        self.hooks[hook_name].append(callback)
    
    async def execute_hook(self, hook_name: str, *args, **kwargs):
        """Execute all callbacks for a hook."""
        if hook_name in self.hooks:
            for callback in self.hooks[hook_name]:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(*args, **kwargs)
                    else:
                        callback(*args, **kwargs)
                except Exception as e:
                    logger.error(f"Hook callback error: {e}")
    
    def get_plugin_info(self, plugin_id: str) -> Optional[Dict[str, Any]]:
        """Get plugin information."""
        if plugin_id not in self.plugins:
            return None
        
        metadata = self.plugins[plugin_id]
        return {
            "plugin_id": metadata.plugin_id,
            "name": metadata.name,
            "description": metadata.description,
            "version": metadata.version,
            "author": metadata.author,
            "plugin_type": metadata.plugin_type.value,
            "security_level": metadata.security_level.value,
            "status": metadata.status.value,
            "install_date": metadata.install_date.isoformat() if metadata.install_date else None,
            "dependencies": metadata.dependencies,
            "permissions": metadata.permissions,
            "error_message": metadata.error_message
        }
    
    def list_plugins(self) -> List[Dict[str, Any]]:
        """List all plugins."""
        return [self.get_plugin_info(plugin_id) for plugin_id in self.plugins.keys()]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get plugin manager statistics."""
        self.stats["disabled_plugins"] = len([p for p in self.plugins.values() if p.status == PluginStatus.DISABLED])
        self.stats["failed_plugins"] = len([p for p in self.plugins.values() if p.status == PluginStatus.ERROR])
        
        return self.stats.copy()


# Global enhanced plugin manager instance
enhanced_plugin_manager = EnhancedPluginManager()

def get_enhanced_plugin_manager() -> EnhancedPluginManager:
    """Get the global enhanced plugin manager."""
    return enhanced_plugin_manager
