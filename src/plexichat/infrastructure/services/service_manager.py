import asyncio
import importlib
import inspect
import logging
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Type

from . import SecureService, ServiceMetadata, ServiceStatus


"""
PlexiChat Service Manager

Centralized service orchestration with quantum security integration,
intelligent dependency resolution, and adaptive resource management.
"""

logger = logging.getLogger(__name__)


class ServiceDependencyError(Exception):
    """Raised when service dependencies cannot be resolved."""


class ServiceManager:
    """
    Centralized Service Manager
    
    Features:
    - Intelligent service discovery and loading
    - Dependency resolution and ordering
    - Resource-aware service scheduling
    - Health monitoring and recovery
    - Security-integrated service communication
    - Performance optimization
    - Hot-swapping and live updates
    """
    
    def __init__(self, services_dir: str = "src/plexichat/services"):
        self.services_dir = from pathlib import Path
Path(services_dir)
        
        # Service registry
        self.registered_services: Dict[str, Type[SecureService]] = {}
        self.active_services: Dict[str, SecureService] = {}
        self.service_metadata: Dict[str, ServiceMetadata] = {}
        
        # Dependency management
        self.dependency_graph: Dict[str, Set[str]] = defaultdict(set)
        self.reverse_dependencies: Dict[str, Set[str]] = defaultdict(set)
        
        # Service scheduling
        self.startup_queue: deque = deque()
        self.shutdown_queue: deque = deque()
        
        # Performance tracking
        self.service_metrics: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        
        # Configuration
        self.max_concurrent_starts = 5
        self.service_timeout = 30.0  # seconds
        self.health_check_interval = 60.0  # seconds
        
        # Initialize manager
        asyncio.create_task(self._initialize_manager())
    
    async def _initialize_manager(self):
        """Initialize the service manager."""
        try:
            await self._discover_services()
            await self._start_health_monitoring()
            logger.info(" Service manager initialized")
        except Exception as e:
            logger.error(f"Failed to initialize service manager: {e}")
    
    async def _discover_services(self):
        """Discover and register available services."""
        if not self.services_dir.exists():
            logger.warning(f"Services directory not found: {self.services_dir}")
            return
        
        discovered_count = 0
        
        # Scan for service files
        for service_file in self.services_dir.rglob("*.py"):
            if service_file.name.startswith("_"):
                continue
            
            try:
                await self._load_service_from_file(service_file)
                discovered_count += 1
            except Exception as e:
                logger.warning(f"Failed to load service from {service_file}: {e}")
        
        logger.info(f" Discovered {discovered_count} services")
    
    async def _load_service_from_file(self, service_file: Path):
        """Load a service from a Python file."""
        # Convert file path to module name
        relative_path = service_file.relative_to(self.services_dir.parent)
        module_name = str(relative_path.with_suffix("")).replace("/", ".").replace("\\", ".")
        
        try:
            # Import the module
            module = importlib.import_module(module_name)
            
            # Find service classes
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if (issubclass(obj, SecureService) and 
                    obj != SecureService and 
                    hasattr(obj, 'SERVICE_METADATA')):
                    
                    metadata = obj.SERVICE_METADATA
                    await self.register_service(obj, metadata)
                    
        except Exception as e:
            logger.error(f"Failed to load service module {module_name}: {e}")
    
    async def register_service(self, service_class: Type[SecureService], metadata: ServiceMetadata):
        """Register a service class with metadata."""
        service_id = metadata.service_id
        
        if service_id in self.registered_services:
            logger.warning(f"Service already registered: {service_id}")
            return
        
        # Validate service class
        if not issubclass(service_class, SecureService):
            raise ValueError(f"Service class must inherit from SecureService: {service_class}")
        
        # Register service
        self.registered_services[service_id] = service_class
        self.service_metadata[service_id] = metadata
        
        # Build dependency graph
        for dependency in metadata.dependencies:
            self.dependency_graph[service_id].add(dependency)
            self.reverse_dependencies[dependency].add(service_id)
        
        logger.info(f" Registered service: {metadata.name} ({service_id})")
    
    async def start_service(self, service_id: str) -> bool:
        """Start a specific service and its dependencies."""
        if service_id not in self.registered_services:
            logger.error(f"Service not registered: {service_id}")
            return False
        
        if service_id in self.active_services:
            logger.info(f"Service already running: {service_id}")
            return True
        
        try:
            # Resolve and start dependencies first
            await self._start_dependencies(service_id)
            
            # Create and start service instance
            service_class = self.registered_services[service_id]
            metadata = self.service_metadata[service_id]
            
            service_instance = service_class(metadata)
            await service_instance.start()
            
            self.active_services[service_id] = service_instance
            
            logger.info(f" Started service: {metadata.name}")
            return True
            
        except Exception as e:
            logger.error(f" Failed to start service {service_id}: {e}")
            return False
    
    async def _start_dependencies(self, service_id: str):
        """Start all dependencies for a service."""
        dependencies = self.dependency_graph.get(service_id, set())
        
        for dependency_id in dependencies:
            if dependency_id not in self.active_services:
                if not await self.start_service(dependency_id):
                    raise ServiceDependencyError(f"Failed to start dependency: {dependency_id}")
    
    async def stop_service(self, service_id: str, force: bool = False) -> bool:
        """Stop a specific service and handle dependents."""
        if service_id not in self.active_services:
            logger.info(f"Service not running: {service_id}")
            return True
        
        try:
            # Check for dependent services
            dependents = self.reverse_dependencies.get(service_id, set())
            active_dependents = [dep for dep in dependents if dep in self.active_services]
            
            if active_dependents and not force:
                logger.warning(f"Cannot stop service {service_id}, has active dependents: {active_dependents}")
                return False
            
            # Stop dependent services first if force=True
            if force:
                for dependent_id in active_dependents:
                    await self.stop_service(dependent_id, force=True)
            
            # Stop the service
            service_instance = self.active_services[service_id]
            await service_instance.stop()
            
            del self.active_services[service_id]
            
            logger.info(f" Stopped service: {service_id}")
            return True
            
        except Exception as e:
            logger.error(f" Failed to stop service {service_id}: {e}")
            return False
    
    async def restart_service(self, service_id: str) -> bool:
        """Restart a specific service."""
        if await self.stop_service(service_id, force=True):
            return await self.start_service(service_id)
        return False
    
    async def start_all_services(self):
        """Start all registered services in dependency order."""
        # Topological sort of services by dependencies
        start_order = self._get_startup_order()
        
        logger.info(f" Starting {len(start_order)} services in dependency order")
        
        # Start services in batches based on priority
        priority_groups = defaultdict(list)
        for service_id in start_order:
            metadata = self.service_metadata[service_id]
            priority_groups[metadata.priority].append(service_id)
        
        # Start by priority (critical first)
        for priority in sorted(priority_groups.keys(), key=lambda p: p.value):
            services = priority_groups[priority]
            logger.info(f"Starting {len(services)} {priority.name} priority services")
            
            # Start services in this priority group concurrently
            tasks = [self.start_service(service_id) for service_id in services]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Check results
            for service_id, result in zip(services, results):
                if isinstance(result, Exception):
                    logger.error(f"Failed to start {service_id}: {result}")
                elif not result:
                    logger.error(f"Failed to start {service_id}")
    
    def _get_startup_order(self) -> List[str]:
        """Get service startup order using topological sort."""
        # Kahn's algorithm for topological sorting
        in_degree = {service_id: 0 for service_id in self.registered_services}
        
        # Calculate in-degrees
        for service_id, dependencies in self.dependency_graph.items():
            for dependency in dependencies:
                if dependency in in_degree:
                    in_degree[service_id] += 1
        
        # Start with services that have no dependencies
        queue = deque([service_id for service_id, degree in in_degree.items() if degree == 0])
        result = []
        
        while queue:
            service_id = queue.popleft()
            result.append(service_id)
            
            # Update in-degrees of dependent services
            for dependent in self.reverse_dependencies.get(service_id, set()):
                if dependent in in_degree:
                    in_degree[dependent] -= 1
                    if in_degree[dependent] == 0:
                        queue.append(dependent)
        
        # Check for circular dependencies
        if len(result) != len(self.registered_services):
            remaining = set(self.registered_services.keys()) - set(result)
            logger.error(f"Circular dependencies detected in services: {remaining}")
            # Add remaining services anyway
            result.extend(remaining)
        
        return result
    
    async def stop_all_services(self):
        """Stop all active services in reverse dependency order."""
        # Get shutdown order (reverse of startup order)
        shutdown_order = list(reversed(self._get_startup_order()))
        
        logger.info(f" Stopping {len(self.active_services)} services")
        
        for service_id in shutdown_order:
            if service_id in self.active_services:
                await self.stop_service(service_id, force=True)
    
    async def _start_health_monitoring(self):
        """Start health monitoring for all services."""
        async def health_monitor():
            while True:
                try:
                    await self._check_all_service_health()
                    await asyncio.sleep(self.health_check_interval)
                except Exception as e:
                    logger.error(f"Health monitoring error: {e}")
                    await asyncio.sleep(self.health_check_interval * 2)
        
        asyncio.create_task(health_monitor())
        logger.info(" Service health monitoring started")
    
    async def _check_all_service_health(self):
        """Check health of all active services."""
        unhealthy_services = []
        
        for service_id, service in self.active_services.items():
            if service.health.status == ServiceStatus.ERROR:
                unhealthy_services.append(service_id)
            elif service.health.performance_score < 50:
                logger.warning(f"Service {service_id} has low performance score: {service.health.performance_score}")
        
        # Attempt recovery for unhealthy services
        for service_id in unhealthy_services:
            logger.info(f" Attempting recovery for unhealthy service: {service_id}")
            await self.restart_service(service_id)
    
    def get_service_status(self, service_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a specific service."""
        if service_id in self.active_services:
            return self.active_services[service_id].get_status()
        elif service_id in self.registered_services:
            return {
                "service_id": service_id,
                "name": self.service_metadata[service_id].name,
                "status": "stopped",
                "registered": True
            }
        return None
    
    def get_all_services_status(self) -> Dict[str, Any]:
        """Get status of all services."""
        services_status = {}
        
        for service_id in self.registered_services:
            services_status[service_id] = self.get_service_status(service_id)
        
        return {
            "total_registered": len(self.registered_services),
            "total_active": len(self.active_services),
            "services": services_status,
            "health_summary": self._get_health_summary()
        }
    
    def _get_health_summary(self) -> Dict[str, Any]:
        """Get overall health summary of all services."""
        if not self.active_services:
            return {"status": "no_services", "score": 0}
        
        total_score = sum(service.health.performance_score for service in self.active_services.values())
        avg_score = total_score / len(self.active_services)
        
        status_counts = defaultdict(int)
        for service in self.active_services.values():
            status_counts[service.health.status.value] += 1
        
        return {
            "status": "healthy" if avg_score > 80 else "degraded" if avg_score > 50 else "unhealthy",
            "average_performance_score": avg_score,
            "status_breakdown": dict(status_counts),
            "total_errors": sum(service.health.error_count for service in self.active_services.values()),
            "total_warnings": sum(service.health.warning_count for service in self.active_services.values())
        }


# Global service manager instance
service_manager = ServiceManager()

__all__ = [
    'ServiceManager',
    'service_manager',
    'ServiceDependencyError'
]
