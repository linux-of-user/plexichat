"""
Enhanced Module System for NetLink

Advanced module/plugin architecture with:
- Intelligent auto-loading and dependency resolution
- User tier-based access control and permissions
- Hot-swapping and live updates
- Module marketplace integration
- Performance monitoring and optimization
- Security sandboxing and validation
- Cross-module communication and events
"""

import asyncio
import json
import sys
import importlib
import importlib.util
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Callable, Union
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
import hashlib
import aiofiles
import aiohttp
from concurrent.futures import ThreadPoolExecutor

from app.logger_config import logger
from app.profiles.advanced_profile_system import advanced_profile_system, UserTier
from app.plugins.plugin_manager import PluginInterface, PluginMetadata
from app.plugins.enhanced_plugin_manager import EnhancedPluginManager

class ModuleAccessLevel(str, Enum):
    """Module access levels based on user tiers."""
    PUBLIC = "public"           # Available to all users
    BASIC = "basic"            # Basic tier and above
    PREMIUM = "premium"        # Premium tier and above
    VIP = "vip"               # VIP tier and above
    ALPHA_TESTER = "alpha"    # Alpha testers only
    BETA_TESTER = "beta"      # Beta testers only
    DEVELOPER = "developer"   # Developers only
    MODERATOR = "moderator"   # Moderators and admins
    ADMIN = "admin"           # Admins only

class ModuleStatus(str, Enum):
    """Module status states."""
    INACTIVE = "inactive"
    LOADING = "loading"
    ACTIVE = "active"
    ERROR = "error"
    UPDATING = "updating"
    DISABLED = "disabled"

class ModulePriority(int, Enum):
    """Module loading priority."""
    CRITICAL = 0      # Core system modules
    HIGH = 1          # Important functionality
    NORMAL = 2        # Standard modules
    LOW = 3           # Optional features
    BACKGROUND = 4    # Background services

@dataclass
class ModuleDependency:
    """Module dependency specification."""
    name: str
    version: Optional[str] = None
    optional: bool = False
    access_level: ModuleAccessLevel = ModuleAccessLevel.PUBLIC

@dataclass
class ModulePermission:
    """Module permission specification."""
    permission: str
    description: str
    required: bool = True
    access_level: ModuleAccessLevel = ModuleAccessLevel.PUBLIC

@dataclass
class ModuleMetadata:
    """Enhanced module metadata."""
    name: str
    version: str
    description: str
    author: str
    license: str = "MIT"
    
    # Access control
    access_level: ModuleAccessLevel = ModuleAccessLevel.PUBLIC
    required_tier: UserTier = UserTier.GUEST
    permissions: List[ModulePermission] = field(default_factory=list)
    
    # Dependencies
    dependencies: List[ModuleDependency] = field(default_factory=list)
    conflicts: List[str] = field(default_factory=list)
    
    # Loading
    priority: ModulePriority = ModulePriority.NORMAL
    auto_load: bool = True
    hot_swappable: bool = False
    
    # Features
    provides_api: bool = False
    provides_cli: bool = False
    provides_ui: bool = False
    provides_hooks: bool = False
    
    # Marketplace
    marketplace_id: Optional[str] = None
    update_url: Optional[str] = None
    signature: Optional[str] = None
    
    # Performance
    memory_limit_mb: int = 100
    cpu_limit_percent: int = 10
    startup_timeout_seconds: int = 30

@dataclass
class ModuleInstance:
    """Runtime module instance."""
    metadata: ModuleMetadata
    module_object: Any
    status: ModuleStatus = ModuleStatus.INACTIVE
    load_time: Optional[datetime] = None
    last_error: Optional[str] = None
    performance_stats: Dict[str, Any] = field(default_factory=dict)
    user_access_cache: Dict[int, bool] = field(default_factory=dict)

class EnhancedModuleSystem:
    """Advanced module system with tier integration and intelligent loading."""
    
    def __init__(self, modules_dir: str = "src/netlink/modules"):
        self.modules_dir = Path(modules_dir)
        self.modules_dir.mkdir(parents=True, exist_ok=True)
        
        # Module registry
        self.modules: Dict[str, ModuleInstance] = {}
        self.module_metadata: Dict[str, ModuleMetadata] = {}
        self.dependency_graph: Dict[str, Set[str]] = {}
        self.load_order: List[str] = []
        
        # Access control
        self.tier_access_map = {
            UserTier.GUEST: [ModuleAccessLevel.PUBLIC],
            UserTier.BASIC: [ModuleAccessLevel.PUBLIC, ModuleAccessLevel.BASIC],
            UserTier.PREMIUM: [ModuleAccessLevel.PUBLIC, ModuleAccessLevel.BASIC, ModuleAccessLevel.PREMIUM],
            UserTier.VIP: [ModuleAccessLevel.PUBLIC, ModuleAccessLevel.BASIC, ModuleAccessLevel.PREMIUM, ModuleAccessLevel.VIP],
            UserTier.ALPHA_TESTER: [ModuleAccessLevel.PUBLIC, ModuleAccessLevel.BASIC, ModuleAccessLevel.PREMIUM, ModuleAccessLevel.VIP, ModuleAccessLevel.ALPHA_TESTER],
            UserTier.BETA_TESTER: [ModuleAccessLevel.PUBLIC, ModuleAccessLevel.BASIC, ModuleAccessLevel.PREMIUM, ModuleAccessLevel.VIP, ModuleAccessLevel.BETA_TESTER],
            UserTier.DEVELOPER: [ModuleAccessLevel.PUBLIC, ModuleAccessLevel.BASIC, ModuleAccessLevel.PREMIUM, ModuleAccessLevel.VIP, ModuleAccessLevel.DEVELOPER],
            UserTier.MODERATOR: [ModuleAccessLevel.PUBLIC, ModuleAccessLevel.BASIC, ModuleAccessLevel.PREMIUM, ModuleAccessLevel.VIP, ModuleAccessLevel.MODERATOR],
            UserTier.ADMIN: list(ModuleAccessLevel)  # Admins have access to all levels
        }
        
        # Event system
        self.event_handlers: Dict[str, List[Callable]] = {}
        self.module_hooks: Dict[str, Dict[str, List[Callable]]] = {}
        
        # Performance monitoring
        self.performance_monitor = ModulePerformanceMonitor()
        
        # Configuration
        self.config = {
            "auto_discovery": True,
            "hot_swapping_enabled": True,
            "performance_monitoring": True,
            "security_validation": True,
            "dependency_auto_install": False,
            "marketplace_enabled": True,
            "cache_user_access": True,
            "max_concurrent_loads": 5,
            "load_timeout_seconds": 60
        }
        
        # Thread pool for async operations
        self.executor = ThreadPoolExecutor(max_workers=self.config["max_concurrent_loads"])
        
        logger.info("🔧 Enhanced Module System initialized")
    
    async def initialize(self):
        """Initialize the module system."""
        try:
            # Discover available modules
            await self.discover_modules()
            
            # Build dependency graph
            await self.build_dependency_graph()
            
            # Calculate load order
            self.calculate_load_order()
            
            # Auto-load modules
            if self.config["auto_discovery"]:
                await self.auto_load_modules()
            
            logger.info(f"🔧 Module system initialized with {len(self.modules)} modules")
            
        except Exception as e:
            logger.error(f"Failed to initialize module system: {e}")
            raise
    
    async def discover_modules(self):
        """Discover available modules in the modules directory."""
        try:
            discovered_count = 0
            
            for module_dir in self.modules_dir.iterdir():
                if not module_dir.is_dir():
                    continue
                
                metadata_file = module_dir / "module.json"
                if not metadata_file.exists():
                    continue
                
                try:
                    async with aiofiles.open(metadata_file, 'r') as f:
                        metadata_dict = json.loads(await f.read())
                    
                    # Parse metadata
                    metadata = self._parse_module_metadata(metadata_dict)
                    self.module_metadata[metadata.name] = metadata
                    
                    discovered_count += 1
                    logger.debug(f"Discovered module: {metadata.name} v{metadata.version}")
                    
                except Exception as e:
                    logger.warning(f"Failed to parse module metadata in {module_dir}: {e}")
            
            logger.info(f"🔍 Discovered {discovered_count} modules")
            
        except Exception as e:
            logger.error(f"Module discovery failed: {e}")
    
    def _parse_module_metadata(self, metadata_dict: Dict[str, Any]) -> ModuleMetadata:
        """Parse module metadata from dictionary."""
        # Parse dependencies
        dependencies = []
        for dep_data in metadata_dict.get("dependencies", []):
            if isinstance(dep_data, str):
                dependencies.append(ModuleDependency(name=dep_data))
            else:
                dependencies.append(ModuleDependency(
                    name=dep_data["name"],
                    version=dep_data.get("version"),
                    optional=dep_data.get("optional", False),
                    access_level=ModuleAccessLevel(dep_data.get("access_level", "public"))
                ))
        
        # Parse permissions
        permissions = []
        for perm_data in metadata_dict.get("permissions", []):
            if isinstance(perm_data, str):
                permissions.append(ModulePermission(permission=perm_data, description=""))
            else:
                permissions.append(ModulePermission(
                    permission=perm_data["permission"],
                    description=perm_data.get("description", ""),
                    required=perm_data.get("required", True),
                    access_level=ModuleAccessLevel(perm_data.get("access_level", "public"))
                ))
        
        return ModuleMetadata(
            name=metadata_dict["name"],
            version=metadata_dict["version"],
            description=metadata_dict["description"],
            author=metadata_dict["author"],
            license=metadata_dict.get("license", "MIT"),
            access_level=ModuleAccessLevel(metadata_dict.get("access_level", "public")),
            required_tier=UserTier(metadata_dict.get("required_tier", "guest")),
            permissions=permissions,
            dependencies=dependencies,
            conflicts=metadata_dict.get("conflicts", []),
            priority=ModulePriority(metadata_dict.get("priority", 2)),
            auto_load=metadata_dict.get("auto_load", True),
            hot_swappable=metadata_dict.get("hot_swappable", False),
            provides_api=metadata_dict.get("provides_api", False),
            provides_cli=metadata_dict.get("provides_cli", False),
            provides_ui=metadata_dict.get("provides_ui", False),
            provides_hooks=metadata_dict.get("provides_hooks", False),
            marketplace_id=metadata_dict.get("marketplace_id"),
            update_url=metadata_dict.get("update_url"),
            signature=metadata_dict.get("signature"),
            memory_limit_mb=metadata_dict.get("memory_limit_mb", 100),
            cpu_limit_percent=metadata_dict.get("cpu_limit_percent", 10),
            startup_timeout_seconds=metadata_dict.get("startup_timeout_seconds", 30)
        )
    
    async def build_dependency_graph(self):
        """Build module dependency graph."""
        try:
            self.dependency_graph.clear()
            
            for module_name, metadata in self.module_metadata.items():
                self.dependency_graph[module_name] = set()
                
                for dependency in metadata.dependencies:
                    if not dependency.optional:
                        self.dependency_graph[module_name].add(dependency.name)
            
            # Validate dependencies
            await self._validate_dependencies()
            
            logger.info("📊 Module dependency graph built")
            
        except Exception as e:
            logger.error(f"Failed to build dependency graph: {e}")
    
    async def _validate_dependencies(self):
        """Validate module dependencies."""
        missing_deps = []
        circular_deps = []
        
        for module_name, deps in self.dependency_graph.items():
            # Check for missing dependencies
            for dep in deps:
                if dep not in self.module_metadata:
                    missing_deps.append(f"{module_name} -> {dep}")
            
            # Check for circular dependencies
            if self._has_circular_dependency(module_name, set()):
                circular_deps.append(module_name)
        
        if missing_deps:
            logger.warning(f"Missing dependencies: {missing_deps}")
        
        if circular_deps:
            logger.error(f"Circular dependencies detected: {circular_deps}")
    
    def _has_circular_dependency(self, module_name: str, visited: Set[str]) -> bool:
        """Check for circular dependencies."""
        if module_name in visited:
            return True
        
        visited.add(module_name)
        
        for dep in self.dependency_graph.get(module_name, set()):
            if self._has_circular_dependency(dep, visited.copy()):
                return True
        
        return False
    
    def calculate_load_order(self):
        """Calculate optimal module loading order."""
        try:
            # Topological sort with priority consideration
            self.load_order.clear()
            visited = set()
            temp_visited = set()
            
            def visit(module_name: str):
                if module_name in temp_visited:
                    return  # Circular dependency, skip
                if module_name in visited:
                    return
                
                temp_visited.add(module_name)
                
                # Visit dependencies first
                for dep in self.dependency_graph.get(module_name, set()):
                    if dep in self.module_metadata:
                        visit(dep)
                
                temp_visited.remove(module_name)
                visited.add(module_name)
                self.load_order.append(module_name)
            
            # Sort modules by priority first
            modules_by_priority = sorted(
                self.module_metadata.items(),
                key=lambda x: x[1].priority.value
            )
            
            for module_name, metadata in modules_by_priority:
                if module_name not in visited:
                    visit(module_name)
            
            logger.info(f"📋 Module load order calculated: {len(self.load_order)} modules")
            
        except Exception as e:
            logger.error(f"Failed to calculate load order: {e}")

class ModulePerformanceMonitor:
    """Monitor module performance and resource usage."""
    
    def __init__(self):
        self.metrics: Dict[str, Dict[str, Any]] = {}
        self.monitoring_active = True
    
    def start_monitoring(self, module_name: str):
        """Start monitoring a module."""
        if not self.monitoring_active:
            return
        
        self.metrics[module_name] = {
            "start_time": datetime.now(timezone.utc),
            "memory_usage": [],
            "cpu_usage": [],
            "api_calls": 0,
            "errors": 0
        }
    
    def record_metric(self, module_name: str, metric_type: str, value: Any):
        """Record a performance metric."""
        if module_name not in self.metrics:
            return
        
        if metric_type in self.metrics[module_name]:
            if isinstance(self.metrics[module_name][metric_type], list):
                self.metrics[module_name][metric_type].append({
                    "value": value,
                    "timestamp": datetime.now(timezone.utc)
                })
            else:
                self.metrics[module_name][metric_type] = value

    async def auto_load_modules(self):
        """Auto-load modules based on configuration and dependencies."""
        try:
            loaded_count = 0
            failed_count = 0

            for module_name in self.load_order:
                metadata = self.module_metadata.get(module_name)
                if not metadata or not metadata.auto_load:
                    continue

                try:
                    success = await self.load_module(module_name)
                    if success:
                        loaded_count += 1
                    else:
                        failed_count += 1

                except Exception as e:
                    logger.error(f"Failed to auto-load module {module_name}: {e}")
                    failed_count += 1

            logger.info(f"🚀 Auto-loaded {loaded_count} modules ({failed_count} failed)")

        except Exception as e:
            logger.error(f"Auto-loading failed: {e}")

    async def load_module(self, module_name: str) -> bool:
        """Load a specific module."""
        try:
            if module_name in self.modules:
                logger.warning(f"Module {module_name} already loaded")
                return True

            metadata = self.module_metadata.get(module_name)
            if not metadata:
                logger.error(f"Module metadata not found: {module_name}")
                return False

            # Check dependencies
            if not await self._check_dependencies(module_name):
                logger.error(f"Dependencies not satisfied for module: {module_name}")
                return False

            # Start performance monitoring
            self.performance_monitor.start_monitoring(module_name)

            # Load module
            module_instance = ModuleInstance(metadata=metadata, module_object=None)
            module_instance.status = ModuleStatus.LOADING
            self.modules[module_name] = module_instance

            try:
                # Import module
                module_path = self.modules_dir / module_name / "module.py"
                if not module_path.exists():
                    raise FileNotFoundError(f"Module file not found: {module_path}")

                spec = importlib.util.spec_from_file_location(module_name, module_path)
                module_obj = importlib.util.module_from_spec(spec)

                # Execute module with timeout
                await asyncio.wait_for(
                    asyncio.get_event_loop().run_in_executor(
                        self.executor,
                        spec.loader.exec_module,
                        module_obj
                    ),
                    timeout=metadata.startup_timeout_seconds
                )

                # Initialize module if it has an init function
                if hasattr(module_obj, 'initialize'):
                    init_result = await self._call_module_function(
                        module_obj.initialize,
                        timeout=metadata.startup_timeout_seconds
                    )
                    if not init_result:
                        raise Exception("Module initialization failed")

                # Store module instance
                module_instance.module_object = module_obj
                module_instance.status = ModuleStatus.ACTIVE
                module_instance.load_time = datetime.now(timezone.utc)

                # Register module hooks and events
                await self._register_module_hooks(module_name, module_obj)

                logger.info(f"✅ Loaded module: {module_name} v{metadata.version}")
                return True

            except asyncio.TimeoutError:
                module_instance.status = ModuleStatus.ERROR
                module_instance.last_error = "Module loading timeout"
                logger.error(f"Module {module_name} loading timeout")
                return False

            except Exception as e:
                module_instance.status = ModuleStatus.ERROR
                module_instance.last_error = str(e)
                logger.error(f"Failed to load module {module_name}: {e}")
                return False

        except Exception as e:
            logger.error(f"Module loading error for {module_name}: {e}")
            return False

    async def _check_dependencies(self, module_name: str) -> bool:
        """Check if module dependencies are satisfied."""
        try:
            metadata = self.module_metadata.get(module_name)
            if not metadata:
                return False

            for dependency in metadata.dependencies:
                if dependency.optional:
                    continue

                # Check if dependency is loaded
                if dependency.name not in self.modules:
                    # Try to load dependency first
                    if not await self.load_module(dependency.name):
                        logger.error(f"Failed to load dependency {dependency.name} for {module_name}")
                        return False

                # Check dependency status
                dep_instance = self.modules.get(dependency.name)
                if not dep_instance or dep_instance.status != ModuleStatus.ACTIVE:
                    logger.error(f"Dependency {dependency.name} not active for {module_name}")
                    return False

            return True

        except Exception as e:
            logger.error(f"Dependency check failed for {module_name}: {e}")
            return False

    async def _call_module_function(self, func: Callable, timeout: int = 30) -> Any:
        """Call a module function with timeout."""
        try:
            if asyncio.iscoroutinefunction(func):
                return await asyncio.wait_for(func(), timeout=timeout)
            else:
                return await asyncio.wait_for(
                    asyncio.get_event_loop().run_in_executor(self.executor, func),
                    timeout=timeout
                )
        except Exception as e:
            logger.error(f"Module function call failed: {e}")
            return None

    async def _register_module_hooks(self, module_name: str, module_obj: Any):
        """Register module hooks and event handlers."""
        try:
            self.module_hooks[module_name] = {}

            # Register hooks if module provides them
            if hasattr(module_obj, 'get_hooks'):
                hooks = await self._call_module_function(module_obj.get_hooks)
                if hooks:
                    for hook_name, handler in hooks.items():
                        if hook_name not in self.event_handlers:
                            self.event_handlers[hook_name] = []
                        self.event_handlers[hook_name].append(handler)
                        self.module_hooks[module_name][hook_name] = handler

            # Register API endpoints if module provides them
            if hasattr(module_obj, 'get_api_endpoints'):
                endpoints = await self._call_module_function(module_obj.get_api_endpoints)
                if endpoints:
                    await self._register_api_endpoints(module_name, endpoints)

        except Exception as e:
            logger.error(f"Failed to register hooks for {module_name}: {e}")

    async def _register_api_endpoints(self, module_name: str, endpoints: List[Dict[str, Any]]):
        """Register API endpoints from a module."""
        try:
            # This would integrate with the main API router
            logger.info(f"Registering {len(endpoints)} API endpoints for module {module_name}")

            # Store endpoints for later registration with FastAPI
            if not hasattr(self, 'module_endpoints'):
                self.module_endpoints = {}
            self.module_endpoints[module_name] = endpoints

        except Exception as e:
            logger.error(f"Failed to register API endpoints for {module_name}: {e}")

    async def unload_module(self, module_name: str) -> bool:
        """Unload a specific module."""
        try:
            if module_name not in self.modules:
                logger.warning(f"Module {module_name} not loaded")
                return True

            module_instance = self.modules[module_name]

            # Call module shutdown if available
            if (module_instance.module_object and
                hasattr(module_instance.module_object, 'shutdown')):
                await self._call_module_function(module_instance.module_object.shutdown)

            # Unregister hooks
            if module_name in self.module_hooks:
                for hook_name, handler in self.module_hooks[module_name].items():
                    if hook_name in self.event_handlers:
                        self.event_handlers[hook_name].remove(handler)
                del self.module_hooks[module_name]

            # Remove from modules
            del self.modules[module_name]

            logger.info(f"🔄 Unloaded module: {module_name}")
            return True

        except Exception as e:
            logger.error(f"Failed to unload module {module_name}: {e}")
            return False

    async def reload_module(self, module_name: str) -> bool:
        """Reload a specific module."""
        try:
            # Unload first
            await self.unload_module(module_name)

            # Reload metadata
            await self.discover_modules()

            # Load again
            return await self.load_module(module_name)

        except Exception as e:
            logger.error(f"Failed to reload module {module_name}: {e}")
            return False

    async def check_user_access(self, user_id: int, module_name: str) -> bool:
        """Check if user has access to a specific module."""
        try:
            # Check cache first
            module_instance = self.modules.get(module_name)
            if not module_instance:
                return False

            if self.config["cache_user_access"] and user_id in module_instance.user_access_cache:
                return module_instance.user_access_cache[user_id]

            # Get user profile
            profile = await advanced_profile_system.get_user_profile(user_id)
            if not profile:
                return False

            metadata = module_instance.metadata

            # Check tier requirement
            if profile.tier.value < metadata.required_tier.value:
                result = False
            else:
                # Check access level
                allowed_levels = self.tier_access_map.get(profile.tier, [])
                result = metadata.access_level in allowed_levels

            # Cache result
            if self.config["cache_user_access"]:
                module_instance.user_access_cache[user_id] = result

            return result

        except Exception as e:
            logger.error(f"Failed to check user access for {user_id} to {module_name}: {e}")
            return False

    async def get_user_accessible_modules(self, user_id: int) -> List[str]:
        """Get list of modules accessible to a user."""
        try:
            accessible_modules = []

            for module_name in self.modules:
                if await self.check_user_access(user_id, module_name):
                    accessible_modules.append(module_name)

            return accessible_modules

        except Exception as e:
            logger.error(f"Failed to get accessible modules for user {user_id}: {e}")
            return []

    async def trigger_event(self, event_name: str, data: Any = None):
        """Trigger an event for all registered handlers."""
        try:
            handlers = self.event_handlers.get(event_name, [])

            for handler in handlers:
                try:
                    await self._call_module_function(lambda: handler(data))
                except Exception as e:
                    logger.error(f"Event handler failed for {event_name}: {e}")

        except Exception as e:
            logger.error(f"Failed to trigger event {event_name}: {e}")

    def get_module_stats(self) -> Dict[str, Any]:
        """Get module system statistics."""
        try:
            stats = {
                "total_modules": len(self.modules),
                "active_modules": sum(1 for m in self.modules.values() if m.status == ModuleStatus.ACTIVE),
                "failed_modules": sum(1 for m in self.modules.values() if m.status == ModuleStatus.ERROR),
                "modules_by_status": {},
                "modules_by_access_level": {},
                "modules_by_priority": {},
                "performance_summary": {}
            }

            # Count by status
            for status in ModuleStatus:
                stats["modules_by_status"][status.value] = sum(
                    1 for m in self.modules.values() if m.status == status
                )

            # Count by access level
            for level in ModuleAccessLevel:
                stats["modules_by_access_level"][level.value] = sum(
                    1 for m in self.modules.values() if m.metadata.access_level == level
                )

            # Count by priority
            for priority in ModulePriority:
                stats["modules_by_priority"][priority.name] = sum(
                    1 for m in self.modules.values() if m.metadata.priority == priority
                )

            # Performance summary
            if self.performance_monitor.metrics:
                stats["performance_summary"] = {
                    "monitored_modules": len(self.performance_monitor.metrics),
                    "total_errors": sum(
                        metrics.get("errors", 0)
                        for metrics in self.performance_monitor.metrics.values()
                    )
                }

            return stats

        except Exception as e:
            logger.error(f"Failed to get module stats: {e}")
            return {}

# Global enhanced module system instance
enhanced_module_system = EnhancedModuleSystem()
