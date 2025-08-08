import asyncio
import logging
import threading
from typing import Any, Dict, List, Optional, Type, Union
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class ServiceStatus(Enum):
    """Service status enumeration."""
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    ERROR = "error"


@dataclass
class ServiceInfo:
    """Service information."""
    name: str
    service_class: Type
    instance: Optional[Any] = None
    status: ServiceStatus = ServiceStatus.STOPPED
    dependencies: List[str] = None
    config: Dict[str, Any] = None
    error: Optional[str] = None

    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = []
        if self.config is None:
            self.config = {}


class ServiceLoader:
    """Simplified service loader for managing application services."""
    
    def __init__(self):
        self.services: Dict[str, ServiceInfo] = {}
        self.startup_order: List[str] = []
        self.shutdown_order: List[str] = []
        self.lock = threading.RLock()
        self.initialized = False
        
    def initialize(self):
        """Initialize the service loader."""
        with self.lock:
            if self.initialized:
                return
                
            # Register core services
            self._register_core_services()
            
            logger.info("Service loader initialized")
            self.initialized = True
    
    def _register_core_services(self):
        """Register core system services."""
        core_services = [
            ("database", "plexichat.core.services.database_service", "DatabaseService"),
            ("cache", "plexichat.core.caching.cache_manager", "CacheManager"),
            ("auth", "plexichat.core.auth.auth_manager", "AuthManager"),
            ("logging", "plexichat.core.logging.unified_logger", "UnifiedLogger"),
        ]
        
        for name, module_path, class_name in core_services:
            try:
                self.register_service(name, module_path, class_name)
            except Exception as e:
                logger.warning(f"Failed to register core service {name}: {e}")
    
    def register_service(self, name: str, module_path: str, class_name: str,
                        dependencies: Optional[List[str]] = None,
                        config: Optional[Dict[str, Any]] = None):
        """Register a service."""
        try:
            # Dynamic import
            module = __import__(module_path, fromlist=[class_name])
            service_class = getattr(module, class_name)
            
            service_info = ServiceInfo(
                name=name,
                service_class=service_class,
                dependencies=dependencies or [],
                config=config or {}
            )
            
            with self.lock:
                self.services[name] = service_info
                
            logger.debug(f"Registered service: {name}")
            
        except Exception as e:
            logger.error(f"Failed to register service {name}: {e}")
            # Register a placeholder
            service_info = ServiceInfo(
                name=name,
                service_class=type(f"Mock{class_name}", (), {}),
                status=ServiceStatus.ERROR,
                error=str(e)
            )
            with self.lock:
                self.services[name] = service_info
    
    async def start_service(self, name: str) -> bool:
        """Start a specific service."""
        with self.lock:
            if name not in self.services:
                logger.error(f"Service {name} not registered")
                return False
                
            service_info = self.services[name]
            
            if service_info.status == ServiceStatus.RUNNING:
                return True
                
            if service_info.status == ServiceStatus.ERROR:
                logger.error(f"Cannot start service {name}: {service_info.error}")
                return False
        
        try:
            # Start dependencies first
            for dep in service_info.dependencies:
                if not await self.start_service(dep):
                    logger.error(f"Failed to start dependency {dep} for service {name}")
                    return False
            
            # Update status
            with self.lock:
                service_info.status = ServiceStatus.STARTING
            
            # Create service instance
            if service_info.instance is None:
                service_info.instance = service_info.service_class()
            
            # Initialize service if it has an initialize method
            if hasattr(service_info.instance, 'initialize'):
                await service_info.instance.initialize()
            elif hasattr(service_info.instance, 'start'):
                await service_info.instance.start()
            
            # Update status
            with self.lock:
                service_info.status = ServiceStatus.RUNNING
                
            logger.info(f"Started service: {name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start service {name}: {e}")
            with self.lock:
                service_info.status = ServiceStatus.ERROR
                service_info.error = str(e)
            return False
    
    async def stop_service(self, name: str) -> bool:
        """Stop a specific service."""
        with self.lock:
            if name not in self.services:
                logger.error(f"Service {name} not registered")
                return False
                
            service_info = self.services[name]
            
            if service_info.status != ServiceStatus.RUNNING:
                return True
        
        try:
            # Update status
            with self.lock:
                service_info.status = ServiceStatus.STOPPING
            
            # Stop service if it has a stop method
            if service_info.instance:
                if hasattr(service_info.instance, 'stop'):
                    await service_info.instance.stop()
                elif hasattr(service_info.instance, 'cleanup'):
                    await service_info.instance.cleanup()
            
            # Update status
            with self.lock:
                service_info.status = ServiceStatus.STOPPED
                
            logger.info(f"Stopped service: {name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to stop service {name}: {e}")
            with self.lock:
                service_info.status = ServiceStatus.ERROR
                service_info.error = str(e)
            return False
    
    async def start_all_services(self) -> bool:
        """Start all registered services."""
        logger.info("Starting all services")
        
        # Determine startup order based on dependencies
        startup_order = self._calculate_startup_order()
        
        success = True
        for service_name in startup_order:
            if not await self.start_service(service_name):
                logger.error(f"Failed to start service {service_name}")
                success = False
                break
        
        if success:
            logger.info("All services started successfully")
        else:
            logger.error("Failed to start all services")
            
        return success
    
    async def stop_all_services(self) -> bool:
        """Stop all running services."""
        logger.info("Stopping all services")
        
        # Stop in reverse order
        shutdown_order = list(reversed(self._calculate_startup_order()))
        
        success = True
        for service_name in shutdown_order:
            if not await self.stop_service(service_name):
                logger.warning(f"Failed to stop service {service_name}")
                success = False
        
        logger.info("All services stopped")
        return success
    
    def _calculate_startup_order(self) -> List[str]:
        """Calculate the order to start services based on dependencies."""
        order = []
        visited = set()
        visiting = set()
        
        def visit(service_name: str):
            if service_name in visiting:
                logger.warning(f"Circular dependency detected involving {service_name}")
                return
            if service_name in visited:
                return
                
            visiting.add(service_name)
            
            if service_name in self.services:
                for dep in self.services[service_name].dependencies:
                    visit(dep)
            
            visiting.remove(service_name)
            visited.add(service_name)
            order.append(service_name)
        
        for service_name in self.services:
            visit(service_name)
        
        return order
    
    def get_service(self, name: str) -> Optional[Any]:
        """Get a service instance by name."""
        with self.lock:
            if name in self.services:
                service_info = self.services[name]
                if service_info.status == ServiceStatus.RUNNING:
                    return service_info.instance
        return None
    
    def get_service_status(self, name: str) -> Optional[ServiceStatus]:
        """Get the status of a service."""
        with self.lock:
            if name in self.services:
                return self.services[name].status
        return None
    
    def list_services(self) -> Dict[str, Dict[str, Any]]:
        """List all registered services and their status."""
        with self.lock:
            return {
                name: {
                    "status": info.status.value,
                    "dependencies": info.dependencies,
                    "error": info.error
                }
                for name, info in self.services.items()
            }
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform a health check on all services."""
        health_status = {}
        
        with self.lock:
            for name, service_info in self.services.items():
                status = {
                    "status": service_info.status.value,
                    "healthy": service_info.status == ServiceStatus.RUNNING
                }
                
                # Check if service has a health_check method
                if (service_info.instance and 
                    hasattr(service_info.instance, 'health_check')):
                    try:
                        health_result = await service_info.instance.health_check()
                        status.update(health_result)
                    except Exception as e:
                        status["healthy"] = False
                        status["error"] = str(e)
                
                health_status[name] = status
        
        return {
            "overall_healthy": all(s.get("healthy", False) for s in health_status.values()),
            "services": health_status
        }


# Global service loader instance
_service_loader: Optional[ServiceLoader] = None


def get_service_loader() -> ServiceLoader:
    """Get the global service loader instance."""
    global _service_loader
    if _service_loader is None:
        _service_loader = ServiceLoader()
        _service_loader.initialize()
    return _service_loader


def get_service(name: str) -> Optional[Any]:
    """Get a service instance by name."""
    return get_service_loader().get_service(name)


async def start_all_services() -> bool:
    """Start all services."""
    return await get_service_loader().start_all_services()


async def stop_all_services() -> bool:
    """Stop all services."""
    return await get_service_loader().stop_all_services()
