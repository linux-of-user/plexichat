"""
PlexiChat Service Manager
Consolidated service management for the entire application.
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class ServiceStatus(Enum):
    """Service status enumeration."""

    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    FAILED = "failed"


class BaseService(ABC):
    """Base service class."""

    def __init__(self, name: str):
        self.name = name
        self.status = ServiceStatus.STOPPED
        self.dependencies: Set[str] = set()
        self.dependents: Set[str] = set()

    @abstractmethod
    async def start(self) -> bool:
        """Start the service."""
        pass

    @abstractmethod
    async def stop(self) -> bool:
        """Stop the service."""
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """Check service health."""
        pass


class ServiceManager:
    """Manages all services in the application."""

    def __init__(self):
        self.services: Dict[str, BaseService] = {}
        self.startup_order: List[str] = []
        self.shutdown_order: List[str] = []
        self._lock = asyncio.Lock()

    def register_service(
        self, service: BaseService, dependencies: Optional[List[str]] = None
    ):
        """Register a service with optional dependencies."""
        self.services[service.name] = service
        if dependencies:
            service.dependencies.update(dependencies)
            # Update reverse dependencies
            for dep in dependencies:
                if dep in self.services:
                    self.services[dep].dependents.add(service.name)

        # Recalculate startup order
        self._calculate_startup_order()

    def _calculate_startup_order(self):
        """Calculate service startup order using topological sort."""
        # Build dependency graph
        in_degree = defaultdict(int)
        graph = defaultdict(list)

        for service_name, service in self.services.items():
            in_degree[service_name] = len(service.dependencies)
            for dep in service.dependencies:
                graph[dep].append(service_name)

        # Topological sort
        queue = deque([name for name, degree in in_degree.items() if degree == 0])
        result = []

        while queue:
            service_name = queue.popleft()
            result.append(service_name)

            for dependent in graph[service_name]:
                in_degree[dependent] -= 1
                if in_degree[dependent] == 0:
                    queue.append(dependent)

        # Check for circular dependencies
        if len(result) != len(self.services):
            remaining = set(self.services.keys()) - set(result)
            logger.error(f"Circular dependencies detected: {remaining}")
            # Add remaining services anyway
            result.extend(remaining)

        self.startup_order = result
        self.shutdown_order = result[::-1]  # Reverse order for shutdown

    async def start_all(self) -> bool:
        """Start all services in dependency order."""
        async with self._lock:
            logger.info("Starting all services...")

            for service_name in self.startup_order:
                if service_name not in self.services:
                    continue

                service = self.services[service_name]
                if service.status == ServiceStatus.RUNNING:
                    continue

                logger.info(f"Starting service: {service_name}")
                service.status = ServiceStatus.STARTING

                try:
                    success = await service.start()
                    if success:
                        service.status = ServiceStatus.RUNNING
                        logger.info(f"Service started: {service_name}")
                    else:
                        service.status = ServiceStatus.FAILED
                        logger.error(f"Failed to start service: {service_name}")
                        return False
                except Exception as e:
                    service.status = ServiceStatus.FAILED
                    logger.error(f"Error starting service {service_name}: {e}")
                    return False

            logger.info("All services started successfully")
            return True

    async def stop_all(self) -> bool:
        """Stop all services in reverse dependency order."""
        async with self._lock:
            logger.info("Stopping all services...")

            for service_name in self.shutdown_order:
                if service_name not in self.services:
                    continue

                service = self.services[service_name]
                if service.status != ServiceStatus.RUNNING:
                    continue

                logger.info(f"Stopping service: {service_name}")
                service.status = ServiceStatus.STOPPING

                try:
                    success = await service.stop()
                    service.status = ServiceStatus.STOPPED
                    if success:
                        logger.info(f"Service stopped: {service_name}")
                    else:
                        logger.warning(f"Service stop returned false: {service_name}")
                except Exception as e:
                    service.status = ServiceStatus.FAILED
                    logger.error(f"Error stopping service {service_name}: {e}")

            logger.info("All services stopped")
            return True

    async def restart_service(self, service_name: str) -> bool:
        """Restart a specific service."""
        if service_name not in self.services:
            logger.error(f"Service not found: {service_name}")
            return False

        service = self.services[service_name]

        # Stop service
        if service.status == ServiceStatus.RUNNING:
            await service.stop()

        # Start service
        try:
            service.status = ServiceStatus.STARTING
            success = await service.start()
            service.status = ServiceStatus.RUNNING if success else ServiceStatus.FAILED
            return success
        except Exception as e:
            service.status = ServiceStatus.FAILED
            logger.error(f"Error restarting service {service_name}: {e}")
            return False

    async def health_check_all(self) -> Dict[str, bool]:
        """Run health checks on all services."""
        results = {}

        for service_name, service in self.services.items():
            try:
                if service.status == ServiceStatus.RUNNING:
                    results[service_name] = await service.health_check()
                else:
                    results[service_name] = False
            except Exception as e:
                logger.error(f"Health check failed for {service_name}: {e}")
                results[service_name] = False

        return results

    def get_service_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all services."""
        return {
            name: {
                "status": service.status.value,
                "dependencies": list(service.dependencies),
                "dependents": list(service.dependents),
            }
            for name, service in self.services.items()
        }

    def get_service(self, name: str) -> Optional[BaseService]:
        """Get a service by name."""
        return self.services.get(name)


# Global service manager instance
service_manager = ServiceManager()


# Example service implementations
class DatabaseService(BaseService):
    """Database service implementation."""

    def __init__(self):
        super().__init__("database")

    async def start(self) -> bool:
        # Database startup logic would go here
        logger.info("Database service starting...")
        await asyncio.sleep(0.1)  # Simulate startup time
        return True

    async def stop(self) -> bool:
        # Database shutdown logic would go here
        logger.info("Database service stopping...")
        await asyncio.sleep(0.1)  # Simulate shutdown time
        return True

    async def health_check(self) -> bool:
        # Database health check logic would go here
        return True


class WebService(BaseService):
    """Web service implementation."""

    def __init__(self):
        super().__init__("web")
        self.dependencies.add("database")

    async def start(self) -> bool:
        # Web service startup logic would go here
        logger.info("Web service starting...")
        await asyncio.sleep(0.1)  # Simulate startup time
        return True

    async def stop(self) -> bool:
        # Web service shutdown logic would go here
        logger.info("Web service stopping...")
        await asyncio.sleep(0.1)  # Simulate shutdown time
        return True

    async def health_check(self) -> bool:
        # Web service health check logic would go here
        return True


# Global database service instance
_database_service = DatabaseService()


def get_database_service() -> DatabaseService:
    """Get the global database service instance."""
    return _database_service


class ServiceLoader:
    """Service loader for dynamic service loading."""

    def __init__(self):
        self.loaded_services: Dict[str, BaseService] = {}

    def load_service(
        self, service_name: str, service_class: type
    ) -> Optional[BaseService]:
        """Load a service by name and class."""
        try:
            service = service_class()
            self.loaded_services[service_name] = service
            return service
        except Exception as e:
            logger.error(f"Failed to load service {service_name}: {e}")
            return None

    def get_service(self, service_name: str) -> Optional[BaseService]:
        """Get a loaded service by name."""
        return self.loaded_services.get(service_name)

    def unload_service(self, service_name: str) -> bool:
        """Unload a service by name."""
        if service_name in self.loaded_services:
            del self.loaded_services[service_name]
            return True
        return False


def load_services() -> ServiceLoader:
    """Get the global service loader instance."""
    return ServiceLoader()


# Global service loader instance
_service_loader = ServiceLoader()


__all__ = [
    "ServiceStatus",
    "BaseService",
    "ServiceManager",
    "service_manager",
    "DatabaseService",
    "WebService",
    "get_database_service",
    "ServiceLoader",
    "load_services",
]
