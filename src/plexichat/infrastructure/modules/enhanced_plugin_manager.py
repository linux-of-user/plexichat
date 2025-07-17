# pyright: reportMissingImports=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportCallIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import asyncio
import importlib
import importlib.util
import json
import shutil
import sys
import tempfile
import threading
import time
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import aiofiles
import aiohttp
import yaml
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from ...core.config import get_config
from ...core.logging import get_logger
from .interfaces import ModuleState
from .isolation import IsolationConfig

logger = get_logger(__name__)


class PluginStatus(Enum):
    """Enhanced plugin status."""
    UNKNOWN = "unknown"
    DISCOVERED = "discovered"
    LOADING = "loading"
    LOADED = "loaded"
    UNLOADING = "unloading"
    UNLOADED = "unloaded"
    ERROR = "error"
    DISABLED = "disabled"
    UPDATING = "updating"
    INSTALLING = "installing"
    REMOVING = "removing"
    QUARANTINED = "quarantined"


class PluginType(Enum):
    """Enhanced plugin types."""
    CORE = "core"
    FEATURE = "feature"
    INTEGRATION = "integration"
    MICRO_APP = "micro_app"
    AI_NODE = "ai_node"
    SECURITY_NODE = "security_node"
    STORAGE_NODE = "storage_node"
    EXTENSION = "extension"
    THEME = "theme"
    AUTH_PROVIDER = "auth_provider"
    NOTIFICATION = "notification"
    ANALYTICS = "analytics"
    BACKUP = "backup"
    MONITORING = "monitoring"
    AUTOMATION = "automation"
    CUSTOM = "custom"


@dataclass
class PluginMetadata:
    """Enhanced plugin metadata."""
    name: str
    version: str
    description: str = ""
    author: str = ""
    plugin_type: PluginType = PluginType.FEATURE
    entry_point: str = "main"
    dependencies: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    api_version: str = "1.0"
    min_plexichat_version: str = "3.0.0"
    enabled: bool = True
    category: str = "general"
    tags: List[str] = field(default_factory=list)
    homepage: Optional[str] = None
    repository: Optional[str] = None
    license: str = "Unknown"
    icon: Optional[str] = None
    screenshots: List[str] = field(default_factory=list)
    changelog: List[Dict[str, str]] = field(default_factory=list)
    download_count: int = 0
    rating: float = 0.0
    last_updated: Optional[datetime] = None
    size_bytes: int = 0
    checksum: Optional[str] = None
    ui_pages: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    webhooks: List[str] = field(default_factory=list)
    settings_schema: Optional[Dict[str, Any]] = None
    auto_start: bool = False
    background_tasks: List[str] = field(default_factory=list)


@dataclass
class PluginInstallationInfo:
    """Plugin installation information."""
    plugin_id: str
    installed_at: datetime
    installed_by: str
    installation_method: str  # "manual", "marketplace", "zip"
    source_url: Optional[str] = None
    checksum_verified: bool = False
    dependencies_installed: List[str] = field(default_factory=list)
    conflicts_resolved: List[str] = field(default_factory=list)
    backup_created: bool = False
    rollback_available: bool = False


class PluginMarketplace:
    """Plugin marketplace integration."""
    
    def __init__(self):
        self.marketplace_url = "https://api.plexichat.com/plugins/marketplace"
        self.cache_dir = Path("data/plugin_cache")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_ttl = 3600  # 1 hour
        
    async def search_plugins(self, query: str = "", category: str = "", 
                           plugin_type: Optional[PluginType] = None) -> List[Dict[str, Any]]:
        """Search plugins in marketplace."""
        try:
            async with aiohttp.ClientSession() as session:
                params = {"q": query, "category": category}
                if plugin_type:
                    params["type"] = plugin_type.value
                    
                async with session.get(self.marketplace_url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get("plugins", [])
                    else:
                        logger.warning(f"Marketplace search failed: {response.status}")
                        return []
        except Exception as e:
            logger.error(f"Marketplace search error: {e}")
            return []
    
    async def get_plugin_info(self, plugin_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed plugin information from marketplace."""
        try:
            cache_file = self.cache_dir / f"{plugin_id}.json"
            
            # Check cache first
            if cache_file.exists():
                cache_age = time.time() - cache_file.stat().st_mtime
                if cache_age < self.cache_ttl:
                    async with aiofiles.open(cache_file, 'r') as f:
                        return json.loads(await f.read())
            
            # Fetch from marketplace
            async with aiohttp.ClientSession() as session:
                url = f"{self.marketplace_url}/plugin/{plugin_id}"
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Cache the result
                        async with aiofiles.open(cache_file, 'w') as f:
                            await f.write(json.dumps(data))
                        
                        return data
                    else:
                        logger.warning(f"Failed to get plugin info: {response.status}")
                        return None
        except Exception as e:
            logger.error(f"Get plugin info error: {e}")
            return None
    
    async def download_plugin(self, plugin_id: str, version: str = "latest") -> Optional[Path]:
        """Download plugin from marketplace."""
        try:
            plugin_info = await self.get_plugin_info(plugin_id)
            logger.info(f"Downloading plugin {plugin_id} version {version}")
            if not plugin_info:
                return None
            
            download_url = plugin_info.get("download_url")
            if not download_url:
                return None
            
            # Create temp file
            temp_file = Path(tempfile.mktemp(suffix=".zip"))
            
            async with aiohttp.ClientSession() as session:
                async with session.get(download_url) as response:
                    if response.status == 200:
                        async with aiofiles.open(temp_file, 'wb') as f:
                            await f.write(await response.read())
                        
                        # Verify checksum if available
                        if plugin_info.get("checksum"):
                            if not await self._verify_checksum(temp_file, plugin_info["checksum"]):
                                temp_file.unlink()
                                return None
                        
                        return temp_file
                    else:
                        logger.warning(f"Plugin download failed: {response.status}")
                        return None
        except Exception as e:
            logger.error(f"Download plugin error: {e}")
            return None
    
    async def _verify_checksum(self, file_path: Path, expected_checksum: str) -> bool:
        """Verify file checksum."""
        import hashlib
        try:
            async with aiofiles.open(file_path, 'rb') as f:
                content = await f.read()
                actual_checksum = hashlib.sha256(content).hexdigest()
                return actual_checksum == expected_checksum
        except Exception as e:
            logger.error(f"Checksum verification error: {e}")
            return False


class EnhancedPluginManager:
    """Enhanced plugin manager with comprehensive functionality."""
    
    def __init__(self):
        self.plugins_dir = Path("plugins")
        self.plugins_dir.mkdir(exist_ok=True)
        
        # Plugin registry
        self.plugins: Dict[str, Any] = {}
        self.plugin_metadata: Dict[str, PluginMetadata] = {}
        self.plugin_status: Dict[str, PluginStatus] = {}
        self.installation_info: Dict[str, PluginInstallationInfo] = {}
        
        # Plugin discovery
        self.discovered_plugins: Set[str] = set()
        self.loaded_plugins: Set[str] = set()
        self.enabled_plugins: Set[str] = set()
        
        # Marketplace integration
        self.marketplace = PluginMarketplace()
        
        # File watching
        self.file_observer: Optional[Observer] = None
        self.watch_thread: Optional[threading.Thread] = None
        
        # Plugin UI pages
        self.ui_pages: Dict[str, Dict[str, Any]] = {}
        
        # Background tasks
        self.background_tasks: Dict[str, asyncio.Task] = {}
        
        # Configuration
        self.config = get_config()
        self.logger = get_logger(__name__)
        
        # Initialize
        self._setup_file_watching()
        
    def _setup_file_watching(self):
        """Setup file watching for plugin changes."""
        try:
            self.file_observer = Observer()
            self.file_observer.schedule(
                PluginFileHandler(self),
                str(self.plugins_dir),
                recursive=True
            )
            if self.file_observer and hasattr(self.file_observer, "start"): self.file_observer.start()
            self.logger.info("Plugin file watching enabled")
        except Exception as e:
            self.logger.warning(f"File watching setup failed: {e}")
    
    async def initialize(self) -> bool:
        """Initialize the plugin manager."""
        try:
            self.logger.info("Initializing Enhanced Plugin Manager")
            
            # Discover plugins
            await self.discover_all_plugins()
            
            # Load enabled plugins
            await self.load_enabled_plugins()
            
            # Start background tasks
            await self.start_background_tasks()
            
            self.logger.info("Enhanced Plugin Manager initialized")
            return True
        except Exception as e:
            self.logger.error(f"Plugin manager initialization failed: {e}")
            return False
    
    async def discover_all_plugins(self) -> List[str]:
        """Discover all available plugins."""
        discovered = []
        
        for plugin_dir in self.plugins_dir.iterdir():
            if plugin_dir.is_dir():
                plugin_name = plugin_dir.name
                
                # Check for plugin manifest
                manifest_files = [
                    plugin_dir / "plugin.json",
                    plugin_dir / "plugin.yaml",
                    plugin_dir / "plugin.yml"
                ]
                
                for manifest_file in manifest_files:
                    if manifest_file.exists():
                        try:
                            metadata = await self._load_plugin_metadata(manifest_file)
                            if metadata:
                                self.plugin_metadata[plugin_name] = metadata
                                self.plugin_status[plugin_name] = PluginStatus.DISCOVERED
                                self.discovered_plugins.add(plugin_name)
                                discovered.append(plugin_name)
                                self.logger.info(f"Discovered plugin: {plugin_name}")
                                break
                        except Exception as e:
                            self.logger.warning(f"Failed to load metadata for {plugin_name}: {e}")
        
        return discovered
    
    async def _load_plugin_metadata(self, manifest_path: Path) -> Optional[PluginMetadata]:
        """Load plugin metadata from manifest file."""
        try:
            if manifest_path.suffix in ['.yaml', '.yml']:
                async with aiofiles.open(manifest_path, 'r') as f:
                    content = await f.read()
                    data = yaml.safe_load(content)
            else:
                async with aiofiles.open(manifest_path, 'r') as f:
                    content = await f.read()
                    data = json.loads(content)
            
            # Convert to PluginMetadata
            return PluginMetadata(
                name=data.get("name", manifest_path.parent.name),
                version=data.get("version", "1.0.0"),
                description=data.get("description", ""),
                author=data.get("author", ""),
                plugin_type=PluginType(data.get("type", "feature")),
                entry_point=data.get("entry_point", "main"),
                dependencies=data.get("dependencies", []),
                permissions=data.get("permissions", []),
                api_version=data.get("api_version", "1.0"),
                min_plexichat_version=data.get("min_plexichat_version", "3.0.0"),
                enabled=data.get("enabled", True),
                category=data.get("category", "general"),
                tags=data.get("tags", []),
                homepage=data.get("homepage"),
                repository=data.get("repository"),
                license=data.get("license", "Unknown"),
                icon=data.get("icon"),
                screenshots=data.get("screenshots", []),
                changelog=data.get("changelog", []),
                download_count=data.get("download_count", 0),
                rating=data.get("rating", 0.0),
                last_updated=data.get("last_updated"),
                size_bytes=data.get("size_bytes", 0),
                checksum=data.get("checksum"),
                ui_pages=data.get("ui_pages", []),
                api_endpoints=data.get("api_endpoints", []),
                webhooks=data.get("webhooks", []),
                settings_schema=data.get("settings_schema"),
                auto_start=data.get("auto_start", False),
                background_tasks=data.get("background_tasks", [])
            )
        except Exception as e:
            self.logger.error(f"Failed to load plugin metadata from {manifest_path}: {e}")
            return None
    
    async def load_enabled_plugins(self) -> List[str]:
        """Load all enabled plugins."""
        loaded = []
        
        for plugin_name in self.discovered_plugins:
            metadata = self.plugin_metadata.get(plugin_name)
            if metadata and metadata.enabled:
                try:
                    success = await self.load_plugin(plugin_name)
                    if success:
                        loaded.append(plugin_name)
                        self.enabled_plugins.add(plugin_name)
                except Exception as e:
                    self.logger.error(f"Failed to load plugin {plugin_name}: {e}")
                    self.plugin_status[plugin_name] = PluginStatus.ERROR
        
        return loaded
    
    async def load_plugin(self, plugin_name: str) -> bool:
        """Load a specific plugin."""
        try:
            self.logger.info(f"Loading plugin: {plugin_name}")
            self.plugin_status[plugin_name] = PluginStatus.LOADING
            
            plugin_dir = self.plugins_dir / plugin_name
            metadata = self.plugin_metadata.get(plugin_name)
            
            if not metadata:
                self.logger.error(f"No metadata found for plugin: {plugin_name}")
                return False
            
            # Load plugin module
            entry_point = metadata.entry_point
            main_file = plugin_dir / f"{entry_point}.py"
            
            if not main_file.exists():
                self.logger.error(f"Entry point not found: {main_file}")
                return False
            
            # Import plugin module
            spec = importlib.util.spec_from_file_location(
                f"plugins.{plugin_name}.{entry_point}",
                main_file
            )
            
            if spec is None or spec.loader is None:
                self.logger.error(f"Failed to create spec for {plugin_name}")
                return False
            
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            
            # Find plugin class
            plugin_class = None
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (isinstance(attr, type) and 
                    hasattr(attr, '__bases__') and
                    any('PluginInterface' in str(base) for base in attr.__bases__)):
                    plugin_class = attr
                    break
            
            if not plugin_class:
                self.logger.error(f"No plugin class found in {plugin_name}")
                return False
            
            # Instantiate plugin
            plugin_instance = plugin_class()
            plugin_instance.manager = self
            
            # Initialize plugin
            success = False
            if plugin_instance and hasattr(plugin_instance, "initialize"):
                success = await plugin_instance.initialize()
            if success:
                self.plugins[plugin_name] = plugin_instance
                self.plugin_status[plugin_name] = PluginStatus.LOADED
                self.loaded_plugins.add(plugin_name)
                
                # Register UI pages
                await self._register_plugin_ui_pages(plugin_name, metadata)
                
                # Start background tasks
                await self._start_plugin_background_tasks(plugin_name, metadata)
                
                self.logger.info(f"Plugin {plugin_name} loaded successfully")
                return True
            else:
                self.plugin_status[plugin_name] = PluginStatus.ERROR
                self.logger.error(f"Plugin {plugin_name} initialization failed")
                return False
                
        except Exception as e:
            self.plugin_status[plugin_name] = PluginStatus.ERROR
            self.logger.error(f"Failed to load plugin {plugin_name}: {e}")
            return False
    
    async def unload_plugin(self, plugin_name: str) -> bool:
        """Unload a plugin."""
        try:
            self.logger.info(f"Unloading plugin: {plugin_name}")
            self.plugin_status[plugin_name] = PluginStatus.UNLOADING
            
            plugin = self.plugins.get(plugin_name)
            if plugin:
                # Stop background tasks
                await self._stop_plugin_background_tasks(plugin_name)
                
                # Cleanup plugin
                if hasattr(plugin, 'cleanup'):
                    if plugin and hasattr(plugin, "cleanup"):
                        await plugin.cleanup()
                
                # Remove from registry
                del self.plugins[plugin_name]
                self.loaded_plugins.discard(plugin_name)
                self.enabled_plugins.discard(plugin_name)
            
            self.plugin_status[plugin_name] = PluginStatus.UNLOADED
            self.logger.info(f"Plugin {plugin_name} unloaded")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to unload plugin {plugin_name}: {e}")
            return False
    
    async def install_plugin_from_zip(self, zip_path: Path, verify_checksum: bool = True) -> bool:
        """Install plugin from ZIP file."""
        try:
            self.logger.info(f"Installing plugin from ZIP: {zip_path}")
            
            # Extract and validate
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                
                # Extract ZIP
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_path)
                
                # Find plugin manifest
                manifest_file = None
                for manifest_name in ["plugin.json", "plugin.yaml", "plugin.yml"]:
                    manifest_file = temp_path / manifest_name
                    if manifest_file.exists():
                        break
                
                if not manifest_file or not manifest_file.exists():
                    self.logger.error("No plugin manifest found in ZIP")
                    return False
                
                # Load metadata
                metadata = await self._load_plugin_metadata(manifest_file)
                if not metadata:
                    self.logger.error("Failed to load plugin metadata")
                    return False
                
                # Verify checksum if requested
                if verify_checksum and metadata.checksum:
                    if not await self._verify_plugin_checksum(temp_path, metadata.checksum):
                        self.logger.error("Plugin checksum verification failed")
                        return False
                
                # Check for conflicts
                conflicts = await self._check_plugin_conflicts(metadata)
                if conflicts:
                    self.logger.warning(f"Plugin conflicts detected: {conflicts}")
                    # TODO: Implement conflict resolution
                
                # Create backup
                plugin_dir = self.plugins_dir / metadata.name
                if plugin_dir.exists():
                    backup_dir = Path("backups/plugins") / f"{metadata.name}_{int(time.time())}"
                    backup_dir.mkdir(parents=True, exist_ok=True)
                    shutil.copytree(plugin_dir, backup_dir / metadata.name)
                
                # Install plugin
                if plugin_dir.exists():
                    shutil.rmtree(plugin_dir)
                
                shutil.copytree(temp_path, plugin_dir)
                
                # Record installation
                self.installation_info[metadata.name] = PluginInstallationInfo(
                    plugin_id=metadata.name,
                    installed_at=datetime.now(timezone.utc),
                    installed_by="system",
                    installation_method="zip",
                    checksum_verified=verify_checksum and metadata.checksum is not None
                )
                
                # Discover and load if auto-start
                await self.discover_all_plugins()
                if metadata.auto_start:
                    await self.load_plugin(metadata.name)
                
                self.logger.info(f"Plugin {metadata.name} installed successfully")
                return True
                
        except Exception as e:
            self.logger.error(f"Plugin installation failed: {e}")
            return False
    
    async def remove_plugin(self, plugin_name: str, keep_data: bool = False) -> bool:
        """Remove a plugin."""
        try:
            self.logger.info(f"Removing plugin: {plugin_name}")
            self.plugin_status[plugin_name] = PluginStatus.REMOVING
            
            # Unload if loaded
            if plugin_name in self.loaded_plugins:
                await self.unload_plugin(plugin_name)
            
            # Create backup
            plugin_dir = self.plugins_dir / plugin_name
            if plugin_dir.exists():
                backup_dir = Path("backups/plugins") / f"{plugin_name}_removed_{int(time.time())}"
                backup_dir.mkdir(parents=True, exist_ok=True)
                shutil.copytree(plugin_dir, backup_dir / plugin_name)
            
            # Remove plugin directory
            if plugin_dir.exists():
                if keep_data:
                    # Keep data directory
                    data_dir = plugin_dir / "data"
                    if data_dir.exists():
                        temp_data = Path(f"temp_{plugin_name}_data")
                        shutil.move(str(data_dir), str(temp_data))
                
                shutil.rmtree(plugin_dir)
                
                if keep_data and temp_data.exists():
                    # Restore data directory
                    new_plugin_dir = self.plugins_dir / plugin_name
                    new_plugin_dir.mkdir(exist_ok=True)
                    shutil.move(str(temp_data), str(new_plugin_dir / "data"))
            
            # Clean up registry
            self.discovered_plugins.discard(plugin_name)
            self.loaded_plugins.discard(plugin_name)
            self.enabled_plugins.discard(plugin_name)
            
            if plugin_name in self.plugins:
                del self.plugins[plugin_name]
            if plugin_name in self.plugin_metadata:
                del self.plugin_metadata[plugin_name]
            if plugin_name in self.plugin_status:
                del self.plugin_status[plugin_name]
            if plugin_name in self.installation_info:
                del self.installation_info[plugin_name]
            
            self.logger.info(f"Plugin {plugin_name} removed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to remove plugin {plugin_name}: {e}")
            return False
    
    async def _register_plugin_ui_pages(self, plugin_name: str, metadata: PluginMetadata):
        """Register plugin UI pages."""
        if not metadata.ui_pages:
            return
        
        plugin_dir = self.plugins_dir / plugin_name
        for page_info in metadata.ui_pages:
            page_name = page_info.get("name", "default")
            page_path = page_info.get("path", "ui")
            page_title = page_info.get("title", f"{plugin_name} - {page_name}")
            
            ui_dir = plugin_dir / page_path
            if ui_dir.exists():
                self.ui_pages[f"{plugin_name}_{page_name}"] = {
                    "plugin": plugin_name,
                    "name": page_name,
                    "title": page_title,
                    "path": str(ui_dir),
                    "route": f"/plugins/{plugin_name}/{page_name}"
                }
    
    async def _start_plugin_background_tasks(self, plugin_name: str, metadata: PluginMetadata):
        """Start plugin background tasks."""
        if not metadata.background_tasks:
            return
        
        plugin = self.plugins.get(plugin_name)
        if not plugin:
            return
        
        for task_name in metadata.background_tasks:
            if hasattr(plugin, task_name):
                task_method = getattr(plugin, task_name)
                if callable(task_method):
                    if asyncio.iscoroutinefunction(task_method):
                        task = asyncio.create_task(task_method())
                    else:
                        # For non-async methods, wrap in a coroutine
                        async def wrapper():
                            return task_method()
                        task = asyncio.create_task(wrapper())
                    self.background_tasks[f"{plugin_name}_{task_name}"] = task
                    self.logger.info(f"Started background task: {plugin_name}.{task_name}")
    
    async def _stop_plugin_background_tasks(self, plugin_name: str):
        """Stop plugin background tasks."""
        tasks_to_remove = []
        for task_name, task in self.background_tasks.items():
            if task_name.startswith(f"{plugin_name}_"):
                task.cancel()
                tasks_to_remove.append(task_name)
        
        for task_name in tasks_to_remove:
            del self.background_tasks[task_name]
    
    async def start_background_tasks(self):
        """Start plugin manager background tasks."""
        # Start marketplace sync task
        asyncio.create_task(self._marketplace_sync_task())
        
        # Start plugin health check task
        asyncio.create_task(self._plugin_health_check_task())
    
    async def _marketplace_sync_task(self):
        """Background task to sync with marketplace."""
        while True:
            try:
                # Sync plugin updates
                for plugin_name in self.discovered_plugins:
                    metadata = self.plugin_metadata.get(plugin_name)
                    if metadata and metadata.repository:
                        # Check for updates
                        pass
                
                await asyncio.sleep(3600)  # Check every hour
            except Exception as e:
                self.logger.error(f"Marketplace sync error: {e}")
                await asyncio.sleep(3600)
    
    async def _plugin_health_check_task(self):
        """Background task to check plugin health."""
        while True:
            try:
                for plugin_name, plugin in self.plugins.items():
                    if hasattr(plugin, 'health_check'):
                        try:
                            health = await plugin.health_check()
                            if not health.get('healthy', True):
                                self.logger.warning(f"Plugin {plugin_name} health check failed")
                        except Exception as e:
                            self.logger.error(f"Plugin {plugin_name} health check error: {e}")
                
                await asyncio.sleep(300)  # Check every 5 minutes
            except Exception as e:
                self.logger.error(f"Plugin health check error: {e}")
                await asyncio.sleep(300)
    
    async def _verify_plugin_checksum(self, plugin_path: Path, expected_checksum: str) -> bool:
        """Verify plugin checksum."""
        import hashlib
        try:
            checksum = hashlib.sha256()
            for file_path in plugin_path.rglob("*"):
                if file_path.is_file():
                    with open(file_path, 'rb') as f:
                        checksum.update(f.read())
            
            return checksum.hexdigest() == expected_checksum
        except Exception as e:
            self.logger.error(f"Checksum verification error: {e}")
            return False
    
    async def _check_plugin_conflicts(self, metadata: PluginMetadata) -> List[str]:
        """Check for plugin conflicts."""
        conflicts = []
        
        # Check name conflicts
        if metadata.name in self.discovered_plugins:
            conflicts.append(f"Name conflict with existing plugin: {metadata.name}")
        
        # Check dependency conflicts
        for dep in metadata.dependencies:
            if dep not in self.discovered_plugins:
                conflicts.append(f"Missing dependency: {dep}")
        
        return conflicts
    
    def get_plugin_info(self, plugin_name: str) -> Optional[Dict[str, Any]]:
        """Get comprehensive plugin information."""
        if plugin_name not in self.discovered_plugins:
            return None
        
        metadata = self.plugin_metadata.get(plugin_name)
        status = self.plugin_status.get(plugin_name)
        installation = self.installation_info.get(plugin_name)
        plugin = self.plugins.get(plugin_name)
        
        info = {
            "name": plugin_name,
            "status": status.value if status else "unknown",
            "metadata": metadata.__dict__ if metadata else {},
            "installation": installation.__dict__ if installation else {},
            "loaded": plugin_name in self.loaded_plugins,
            "enabled": plugin_name in self.enabled_plugins,
            "ui_pages": [page for _, page in self.ui_pages.items()
                        if page["plugin"] == plugin_name],
            "background_tasks": [task_name for task_name in self.background_tasks.keys() 
                               if task_name.startswith(f"{plugin_name}_")]
        }
        
        if plugin:
            info["instance"] = {
                "class": plugin.__class__.__name__,
                "version": getattr(plugin, 'version', 'unknown'),
                "state": getattr(plugin, 'state', 'unknown').value if hasattr(plugin, 'state') else 'unknown'
            }
        
        return info
    
    def get_all_plugins_info(self) -> Dict[str, Dict[str, Any]]:
        """Get information for all plugins."""
        return {
            plugin_name: self.get_plugin_info(plugin_name)
            for plugin_name in self.discovered_plugins
        }


class PluginFileHandler(FileSystemEventHandler):
    """Handle plugin file system events."""
    
    def __init__(self, plugin_manager: EnhancedPluginManager):
        self.plugin_manager = plugin_manager
        self.logger = get_logger(__name__)
    
    def on_created(self, event):
        if not event.is_directory:
            self.logger.info(f"Plugin file created: {event.src_path}")
            asyncio.create_task(self.plugin_manager.discover_all_plugins())
    
    def on_modified(self, event):
        if not event.is_directory:
            self.logger.info(f"Plugin file modified: {event.src_path}")
            asyncio.create_task(self.plugin_manager.discover_all_plugins())
    
    def on_deleted(self, event):
        if not event.is_directory:
            self.logger.info(f"Plugin file deleted: {event.src_path}")
            asyncio.create_task(self.plugin_manager.discover_all_plugins())


# Global instance
_enhanced_plugin_manager: Optional[EnhancedPluginManager] = None


def get_enhanced_plugin_manager() -> EnhancedPluginManager:
    """Get the global enhanced plugin manager instance."""
    global _enhanced_plugin_manager
    if _enhanced_plugin_manager is None:
        _enhanced_plugin_manager = EnhancedPluginManager()
    return _enhanced_plugin_manager 
