# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import asyncio
import importlib
import importlib.util
import inspect
import logging
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from pathlib import Path
from pathlib import Path

from pathlib import Path
from pathlib import Path

"""
PlexiChat Modular Service Loader

Enhanced service loading system that loads small modular service files
and provides dynamic service management with hot-reloading capabilities.
"""

logger = logging.getLogger(__name__)


class ServiceType(Enum):
    """Types of services."""
    CORE = "core"
    API = "api"
    BACKGROUND = "background"
    UTILITY = "utility"
    PLUGIN = "plugin"
    EXTERNAL = "external"


class ServiceStatus(Enum):
    """Service status."""
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    ERROR = "error"
    RELOADING = "reloading"


@dataclass
class ServiceModule:
    """Represents a small modular service."""
    module_id: str
    name: str
    description: str
    version: str
    service_type: ServiceType
    file_path: Path
    dependencies: List[str] = field(default_factory=list)
    provides: List[str] = field(default_factory=list)
    config: Dict[str, Any] = field(default_factory=dict)
    auto_start: bool = True
    hot_reload: bool = True

    # Runtime data
    module_instance: Optional[Any] = None
    status: ServiceStatus = ServiceStatus.STOPPED
    last_loaded: Optional[datetime] = None
    error_count: int = 0
    last_error: Optional[str] = None


@dataclass
class ServiceInterface:
    """Interface definition for modular services."""

    async def initialize(self) -> bool:
        """Initialize the service."""
        return True

    async def start(self) -> bool:
        """Start the service."""
        return True

    async def stop(self) -> bool:
        """Stop the service."""
        return True

    async def health_check(self) -> Dict[str, Any]:
        """Perform health check."""
        return {"status": "healthy"}

    def get_metadata(self) -> Dict[str, Any]:
        """Get service metadata."""
        return {}


class ServiceFileWatcher(FileSystemEventHandler):
    """File system watcher for hot-reloading services."""

    def __init__(self, service_loader):
        self.service_loader = service_loader
        self.debounce_time = 1.0  # 1 second debounce
        self.pending_reloads = {}

    def on_modified(self, event):
        """Handle file modification events."""
        if event.is_directory:
            return

        from pathlib import Path


        self.file_path = Path(event.src_path)
        if file_path.suffix == '.py':
            # Debounce rapid file changes
            current_time = time.time()
            if file_path in self.pending_reloads:
                if current_time - self.pending_reloads[file_path] < self.debounce_time:
                    return

            self.pending_reloads[file_path] = current_time

            # Schedule reload
            asyncio.create_task(self.service_loader.reload_service_from_file(file_path))


class ModularServiceLoader:
    """Enhanced modular service loader."""

    def __init__(self, services_dir: str = "src/plexichat/services/modules"):
        from pathlib import Path
self.services_dir = Path(services_dir)
        self.services_dir.mkdir(parents=True, exist_ok=True)

        # Service registry
        self.services: Dict[str, ServiceModule] = {}
        self.running_services: Dict[str, Any] = {}
        self.service_dependencies: Dict[str, Set[str]] = {}

        # Hot-reload support
        self.file_watcher = None
        self.observer = None
        self.hot_reload_enabled = True

        # Service discovery patterns
        self.service_patterns = [
            "*_service.py",
            "*_module.py",
            "service_*.py",
            "module_*.py"
        ]

        # Statistics
        self.stats = {
            "total_services": 0,
            "running_services": 0,
            "failed_services": 0,
            "reloads": 0,
            "errors": 0
        }

        logger.info("Modular Service Loader initialized")

    async def initialize(self):
        """Initialize the service loader."""
        try:
            # Discover and load services
            await self.discover_services()

            # Start file watcher for hot-reload
            if self.hot_reload_enabled:
                self._start_file_watcher()

            # Auto-start services
            await self.auto_start_services()

            logger.info(f"Service loader initialized with {len(self.services)} services")

        except Exception as e:
            logger.error(f"Failed to initialize service loader: {e}")
            raise

    async def discover_services(self):
        """Discover service modules in the services directory."""
        discovered_count = 0

        for pattern in self.service_patterns:
            for service_file in self.services_dir.rglob(pattern):
                try:
                    await self.load_service_from_file(service_file)
                    discovered_count += 1
                except Exception as e:
                    logger.warning(f"Failed to load service from {service_file}: {e}")

        self.stats["total_services"] = len(self.services)
        logger.info(f"Discovered {discovered_count} service modules")

    async def load_service_from_file(self, file_path: Path) -> Optional[ServiceModule]:
        """Load a service module from a file."""
        try:
            # Generate module name from file path
            relative_path = file_path.relative_to(self.services_dir)
            module_name = str(relative_path.with_suffix("")).replace("/", ".").replace("\\", ".")
            full_module_name = f"plexichat.services.modules.{module_name}"

            # Load module spec
            spec = importlib.util.spec_from_file_location(full_module_name, file_path)
            if not spec or not spec.loader:
                logger.warning(f"Could not load spec for {file_path}")
                return None

            # Load the module
            module = importlib.util.module_from_spec(spec)
            sys.modules[full_module_name] = module
            spec.loader.exec_module(module)

            # Extract service metadata
            service_metadata = self._extract_service_metadata(module, file_path)
            if not service_metadata:
                logger.warning(f"No service metadata found in {file_path}")
                return None

            # Create service module
            service_module = ServiceModule()
                module_id=service_metadata["module_id"],
                name=service_metadata["name"],
                description=service_metadata["description"],
                version=service_metadata["version"],
                service_type=ServiceType(service_metadata.get("service_type", "utility")),
                file_path=file_path,
                dependencies=service_metadata.get("dependencies", []),
                provides=service_metadata.get("provides", []),
                config=service_metadata.get("config", {}),
                auto_start=service_metadata.get("auto_start", True),
                hot_reload=service_metadata.get("hot_reload", True),
                module_instance=module,
                last_loaded=datetime.now(timezone.utc)
            )

            # Register service
            self.services[service_module.module_id] = service_module

            logger.info(f"Loaded service module: {service_module.name}")
            return service_module

        except Exception as e:
            logger.error(f"Failed to load service from {file_path}: {e}")
            return None

    def _extract_service_metadata(self, module: Any, file_path: Path) -> Optional[Dict[str, Any]]:
        """Extract service metadata from a module."""
        # Look for SERVICE_METADATA constant
        if hasattr(module, 'SERVICE_METADATA'):
            return module.SERVICE_METADATA

        # Look for service class with metadata
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if hasattr(obj, 'SERVICE_METADATA'):
                return obj.SERVICE_METADATA

        # Look for get_service_metadata function
        if hasattr(module, 'get_service_metadata'):
            try:
                return module.get_service_metadata()
            except Exception as e:
                logger.warning(f"Failed to get metadata from function: {e}")

        # Generate default metadata from file
        module_id = file_path.stem
        return {
            "module_id": module_id,
            "name": module_id.replace("_", " ").title(),
            "description": f"Service module: {module_id}",
            "version": "1.0.0",
            "service_type": "utility"
        }

    async def start_service(self, module_id: str) -> bool:
        """Start a specific service."""
        if module_id not in self.services:
            logger.error(f"Service not found: {module_id}")
            return False

        service = self.services[module_id]

        if service.status == ServiceStatus.RUNNING:
            logger.info(f"Service already running: {module_id}")
            return True

        try:
            service.status = ServiceStatus.STARTING

            # Start dependencies first
            for dep in service.dependencies:
                if not await self.start_service(dep):
                    logger.error(f"Failed to start dependency {dep} for {module_id}")
                    service.status = ServiceStatus.ERROR
                    return False

            # Find and instantiate service class or function
            service_instance = await self._instantiate_service(service)
            if not service_instance:
                service.status = ServiceStatus.ERROR
                return False

            # Initialize service
            if service_instance and hasattr(service_instance, "initialize"):
                if not await service_instance.initialize():
                    service.status = ServiceStatus.ERROR
                    return False

            # Start service
            if service_instance and hasattr(service_instance, "start"):
                if not await service_instance.start():
                    service.status = ServiceStatus.ERROR
                    return False

            # Register running service
            self.running_services[module_id] = service_instance
            service.status = ServiceStatus.RUNNING
            service.error_count = 0
            service.last_error = None

            self.stats["running_services"] += 1
            logger.info(f"Started service: {service.name}")
            return True

        except Exception as e:
            service.status = ServiceStatus.ERROR
            service.error_count += 1
            service.last_error = str(e)
            self.stats["errors"] += 1
            logger.error(f"Failed to start service {module_id}: {e}")
            return False

    async def _instantiate_service(self, service: ServiceModule) -> Optional[Any]:
        """Instantiate a service from its module."""
        module = service.module_instance

        # Look for service class
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if (hasattr(obj, 'SERVICE_METADATA') or )
                name.endswith('Service') or
                name.endswith('Module')):
                try:
                    return obj()
                except Exception as e:
                    logger.warning(f"Failed to instantiate class {name}: {e}")

        # Look for create_service function
        if hasattr(module, 'create_service'):
            try:
                return await module.create_service()
            except Exception as e:
                logger.warning(f"Failed to create service from function: {e}")

        # Return module itself if it has service methods
        if (hasattr(module, 'initialize') or )
            hasattr(module, 'start') or
            hasattr(module, 'health_check')):
            return module

        logger.warning(f"No service implementation found in {service.file_path}")
        return None

    async def stop_service(self, module_id: str) -> bool:
        """Stop a specific service."""
        if module_id not in self.services:
            logger.error(f"Service not found: {module_id}")
            return False

        service = self.services[module_id]

        if service.status != ServiceStatus.RUNNING:
            logger.info(f"Service not running: {module_id}")
            return True

        try:
            service.status = ServiceStatus.STOPPING

            # Stop dependent services first
            for other_id, other_service in self.services.items():
                if module_id in other_service.dependencies and other_service.status == ServiceStatus.RUNNING:
                    await self.stop_service(other_id)

            # Stop the service
            if module_id in self.running_services:
                service_instance = self.running_services[module_id]

                if service_instance and hasattr(service_instance, "stop"):
                    await service_instance.stop()

                del self.running_services[module_id]

            service.status = ServiceStatus.STOPPED
            self.stats["running_services"] = max(0, self.stats["running_services"] - 1)

            logger.info(f"Stopped service: {service.name}")
            return True

        except Exception as e:
            service.status = ServiceStatus.ERROR
            service.error_count += 1
            service.last_error = str(e)
            logger.error(f"Failed to stop service {module_id}: {e}")
            return False

    async def reload_service(self, module_id: str) -> bool:
        """Reload a service module."""
        if module_id not in self.services:
            logger.error(f"Service not found: {module_id}")
            return False

        service = self.services[module_id]

        if not service.hot_reload:
            logger.info(f"Hot reload disabled for service: {module_id}")
            return False

        try:
            # Stop service if running
            was_running = service.status == ServiceStatus.RUNNING
            if was_running:
                await self.stop_service(module_id)

            service.status = ServiceStatus.RELOADING

            # Reload the module
            await self.load_service_from_file(service.file_path)

            # Restart if it was running
            if was_running:
                await self.start_service(module_id)

            self.stats["reloads"] += 1
            logger.info(f"Reloaded service: {service.name}")
            return True

        except Exception as e:
            service.status = ServiceStatus.ERROR
            service.error_count += 1
            service.last_error = str(e)
            logger.error(f"Failed to reload service {module_id}: {e}")
            return False

    async def reload_service_from_file(self, file_path: Path):
        """Reload a service from a file path."""
        # Find service by file path
        for module_id, service in self.services.items():
            if service.file_path == file_path:
                await self.reload_service(module_id)
                break

    async def auto_start_services(self):
        """Auto-start services that have auto_start enabled."""
        auto_start_services = [
            service for service in self.services.values()
            if service.auto_start and service.status == ServiceStatus.STOPPED
        ]

        # Sort by dependencies (start dependencies first)
        sorted_services = self._sort_by_dependencies(auto_start_services)

        for service in sorted_services:
            await self.start_service(service.module_id)

    def _sort_by_dependencies(self, services: List[ServiceModule]) -> List[ServiceModule]:
        """Sort services by their dependencies."""
        # Simple topological sort
        sorted_services = []
        remaining = services.copy()

        while remaining:
            # Find services with no unmet dependencies
            ready = []
            for service in remaining:
                deps_met = all()
                    dep_id in [s.module_id for s in sorted_services] or
                    dep_id not in [s.module_id for s in services]
                    for dep_id in service.dependencies
                )
                if deps_met:
                    ready.append(service)

            if not ready:
                # Circular dependency or missing dependency
                logger.warning("Circular dependency detected or missing dependencies")
                ready = remaining[:1]  # Start with first remaining

            for service in ready:
                sorted_services.append(service)
                remaining.remove(service)

        return sorted_services

    def _start_file_watcher(self):
        """Start file system watcher for hot-reload."""
        try:
            self.file_watcher = ServiceFileWatcher(self)
            self.observer = Observer()
            self.observer.schedule(self.file_watcher, str(self.services_dir), recursive=True)
            self.if observer and hasattr(observer, "start"): observer.start()
            logger.info("File watcher started for hot-reload")
        except Exception as e:
            logger.warning(f"Failed to start file watcher: {e}")

    def get_service_status(self, module_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a specific service."""
        if module_id not in self.services:
            return None

        service = self.services[module_id]

        return {
            "module_id": service.module_id,
            "name": service.name,
            "status": service.status.value,
            "service_type": service.service_type.value,
            "dependencies": service.dependencies,
            "provides": service.provides,
            "auto_start": service.auto_start,
            "hot_reload": service.hot_reload,
            "last_loaded": service.last_loaded.isoformat() if service.last_loaded else None,
            "error_count": service.error_count,
            "last_error": service.last_error
        }

    def get_all_services_status(self) -> List[Dict[str, Any]]:
        """Get status of all services."""
        return [self.get_service_status(module_id) for module_id in self.services.keys()]

    def get_statistics(self) -> Dict[str, Any]:
        """Get service loader statistics."""
        self.stats["running_services"] = len(self.running_services)
        self.stats["failed_services"] = len([s for s in self.services.values() if s.status == ServiceStatus.ERROR])

        return self.stats.copy()

    async def shutdown(self):
        """Shutdown the service loader."""
        try:
            # Stop file watcher
            if self.observer:
                self.if observer and hasattr(observer, "stop"): observer.stop()
                self.observer.join()

            # Stop all running services
            for module_id in list(self.running_services.keys()):
                await self.stop_service(module_id)

            logger.info("Service loader shutdown complete")

        except Exception as e:
            logger.error(f"Error during service loader shutdown: {e}")


# Global modular service loader instance
modular_service_loader = ModularServiceLoader()

def get_modular_service_loader() -> ModularServiceLoader:
    """Get the global modular service loader."""
    return modular_service_loader
