#!/usr/bin/env python3
"""
Service Loader System for PlexiChat

Manages loading, initialization, and lifecycle of all services.
Handles dependencies, error recovery, and proper shutdown.
"""

import asyncio
import time
import traceback
from typing import Dict, List, Any, Optional, Type, Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

# Import our logging system
try:
    from ..logging.unified_logger import get_logger, LogCategory
    logger = get_logger("service_loader")
except ImportError:
    import logging
    logger = logging.getLogger("service_loader")

class ServiceState(Enum):
    """Service states."""
    UNLOADED = "unloaded"
    LOADING = "loading"
    LOADED = "loaded"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"

class ServicePriority(Enum):
    """Service loading priorities."""
    CRITICAL = 1    # Core services (logging, config)
    HIGH = 2        # Security services (auth, rate limiting)
    NORMAL = 3      # Application services (API, database)
    LOW = 4         # Optional services (monitoring, analytics)

@dataclass
class ServiceDefinition:
    """Definition of a service."""
    name: str
    module_path: str
    class_name: str
    priority: ServicePriority = ServicePriority.NORMAL
    dependencies: List[str] = field(default_factory=list)
    config_key: Optional[str] = None
    auto_start: bool = True
    retry_count: int = 3
    retry_delay: float = 1.0

@dataclass
class ServiceInstance:
    """Runtime instance of a service."""
    definition: ServiceDefinition
    instance: Optional[Any] = None
    state: ServiceState = ServiceState.UNLOADED
    load_time: Optional[float] = None
    start_time: Optional[float] = None
    error_count: int = 0
    last_error: Optional[str] = None

class ServiceLoader:
    """Service loader and manager."""
    
    def __init__(self):
        self.services: Dict[str, ServiceInstance] = {}
        self.load_order: List[str] = []
        self.running = False
        
        # Register core services
        self._register_core_services()
        
        logger.info("Service loader initialized", LogCategory.STARTUP)
    
    def _register_core_services(self):
        """Register core system services."""
        core_services = [
            ServiceDefinition(
                name="config",
                module_path="plexichat.core.config.simple_config",
                class_name="SimpleConfig",
                priority=ServicePriority.CRITICAL,
                dependencies=[]
            ),
            ServiceDefinition(
                name="rate_limiter",
                module_path="plexichat.core.middleware.unified_rate_limiter",
                class_name="UnifiedRateLimiter",
                priority=ServicePriority.HIGH,
                dependencies=["config"]
            ),
            ServiceDefinition(
                name="ddos_protection",
                module_path="plexichat.infrastructure.services.enhanced_ddos_service",
                class_name="EnhancedDDoSProtectionService",
                priority=ServicePriority.HIGH,
                dependencies=["config"]
            ),
            ServiceDefinition(
                name="integrated_protection",
                module_path="plexichat.core.middleware.integrated_protection_system",
                class_name="IntegratedProtectionSystem",
                priority=ServicePriority.HIGH,
                dependencies=["config", "rate_limiter", "ddos_protection"]
            )
        ]
        
        for service_def in core_services:
            self.register_service(service_def)
    
    def register_service(self, service_def: ServiceDefinition):
        """Register a service definition."""
        if service_def.name in self.services:
            logger.warning(f"Service {service_def.name} already registered", LogCategory.STARTUP)
            return
        
        self.services[service_def.name] = ServiceInstance(definition=service_def)
        logger.debug(f"Registered service: {service_def.name}", LogCategory.STARTUP)
    
    def _calculate_load_order(self) -> List[str]:
        """Calculate service loading order based on dependencies and priorities."""
        # Topological sort with priority consideration
        visited = set()
        temp_visited = set()
        order = []
        
        def visit(service_name: str):
            if service_name in temp_visited:
                raise ValueError(f"Circular dependency detected involving {service_name}")
            if service_name in visited:
                return
            
            temp_visited.add(service_name)
            
            # Visit dependencies first
            service_instance = self.services.get(service_name)
            if service_instance:
                for dep in service_instance.definition.dependencies:
                    if dep in self.services:
                        visit(dep)
            
            temp_visited.remove(service_name)
            visited.add(service_name)
            order.append(service_name)
        
        # Sort services by priority first
        services_by_priority = sorted(
            self.services.keys(),
            key=lambda name: self.services[name].definition.priority.value
        )
        
        # Visit all services
        for service_name in services_by_priority:
            visit(service_name)
        
        return order
    
    async def load_service(self, service_name: str) -> bool:
        """Load a single service."""
        if service_name not in self.services:
            logger.error(f"Service {service_name} not registered", LogCategory.STARTUP)
            return False
        
        service_instance = self.services[service_name]
        service_def = service_instance.definition
        
        if service_instance.state != ServiceState.UNLOADED:
            logger.warning(f"Service {service_name} already loaded", LogCategory.STARTUP)
            return True
        
        logger.info(f"Loading service: {service_name}", LogCategory.STARTUP)
        service_instance.state = ServiceState.LOADING
        
        try:
            start_time = time.time()
            
            # Import the module
            module_parts = service_def.module_path.split('.')
            module = __import__(service_def.module_path, fromlist=[service_def.class_name])
            
            # Get the class
            service_class = getattr(module, service_def.class_name)
            
            # Create instance
            if hasattr(service_class, '__init__'):
                # Try to create with config if available
                try:
                    config_service = self.get_service("config")
                    if config_service and service_def.config_key:
                        config_data = getattr(config_service, 'get', lambda x: {})
                        service_instance.instance = service_class(config_data(service_def.config_key))
                    else:
                        service_instance.instance = service_class()
                except Exception:
                    # Fallback to no-args constructor
                    service_instance.instance = service_class()
            else:
                service_instance.instance = service_class
            
            service_instance.load_time = time.time() - start_time
            service_instance.state = ServiceState.LOADED
            
            logger.info(f"Service {service_name} loaded successfully in {service_instance.load_time:.3f}s", 
                       LogCategory.STARTUP)
            return True
            
        except Exception as e:
            service_instance.state = ServiceState.ERROR
            service_instance.error_count += 1
            service_instance.last_error = str(e)
            
            logger.error(f"Failed to load service {service_name}: {e}", LogCategory.STARTUP, 
                        {"service": service_name, "error": str(e)})
            return False
    
    async def start_service(self, service_name: str) -> bool:
        """Start a loaded service."""
        if service_name not in self.services:
            logger.error(f"Service {service_name} not registered", LogCategory.STARTUP)
            return False
        
        service_instance = self.services[service_name]
        
        if service_instance.state != ServiceState.LOADED:
            logger.warning(f"Service {service_name} not loaded", LogCategory.STARTUP)
            return False
        
        logger.info(f"Starting service: {service_name}", LogCategory.STARTUP)
        service_instance.state = ServiceState.STARTING
        
        try:
            start_time = time.time()
            
            # Call start method if available
            if hasattr(service_instance.instance, 'start'):
                if asyncio.iscoroutinefunction(service_instance.instance.start):
                    await service_instance.instance.start()
                else:
                    service_instance.instance.start()
            
            service_instance.start_time = time.time() - start_time
            service_instance.state = ServiceState.RUNNING
            
            logger.info(f"Service {service_name} started successfully", LogCategory.STARTUP)
            return True
            
        except Exception as e:
            service_instance.state = ServiceState.ERROR
            service_instance.error_count += 1
            service_instance.last_error = str(e)
            
            logger.error(f"Failed to start service {service_name}: {e}", LogCategory.STARTUP,
                        {"service": service_name, "error": str(e)})
            return False
    
    async def stop_service(self, service_name: str) -> bool:
        """Stop a running service."""
        if service_name not in self.services:
            return True
        
        service_instance = self.services[service_name]
        
        if service_instance.state != ServiceState.RUNNING:
            return True
        
        logger.info(f"Stopping service: {service_name}", LogCategory.STARTUP)
        service_instance.state = ServiceState.STOPPING
        
        try:
            # Call stop method if available
            if hasattr(service_instance.instance, 'stop'):
                if asyncio.iscoroutinefunction(service_instance.instance.stop):
                    await service_instance.instance.stop()
                else:
                    service_instance.instance.stop()
            
            service_instance.state = ServiceState.STOPPED
            logger.info(f"Service {service_name} stopped successfully", LogCategory.STARTUP)
            return True
            
        except Exception as e:
            service_instance.state = ServiceState.ERROR
            service_instance.error_count += 1
            service_instance.last_error = str(e)
            
            logger.error(f"Failed to stop service {service_name}: {e}", LogCategory.STARTUP,
                        {"service": service_name, "error": str(e)})
            return False
    
    async def load_all_services(self) -> bool:
        """Load all registered services in dependency order."""
        logger.info("Loading all services...", LogCategory.STARTUP)
        
        try:
            self.load_order = self._calculate_load_order()
            logger.info(f"Service load order: {' -> '.join(self.load_order)}", LogCategory.STARTUP)
            
            success_count = 0
            for service_name in self.load_order:
                if await self.load_service(service_name):
                    success_count += 1
            
            logger.info(f"Loaded {success_count}/{len(self.load_order)} services", LogCategory.STARTUP)
            return success_count == len(self.load_order)
            
        except Exception as e:
            logger.error(f"Failed to load services: {e}", LogCategory.STARTUP)
            return False
    
    async def start_all_services(self) -> bool:
        """Start all loaded services."""
        logger.info("Starting all services...", LogCategory.STARTUP)
        
        success_count = 0
        for service_name in self.load_order:
            service_instance = self.services[service_name]
            if service_instance.definition.auto_start and service_instance.state == ServiceState.LOADED:
                if await self.start_service(service_name):
                    success_count += 1
        
        self.running = True
        logger.info(f"Started {success_count} services", LogCategory.STARTUP)
        return success_count > 0
    
    async def stop_all_services(self):
        """Stop all running services."""
        logger.info("Stopping all services...", LogCategory.STARTUP)
        
        # Stop in reverse order
        for service_name in reversed(self.load_order):
            await self.stop_service(service_name)
        
        self.running = False
        logger.info("All services stopped", LogCategory.STARTUP)
    
    def get_service(self, service_name: str) -> Optional[Any]:
        """Get a service instance."""
        service_instance = self.services.get(service_name)
        if service_instance and service_instance.state == ServiceState.RUNNING:
            return service_instance.instance
        return None
    
    def get_service_status(self) -> Dict[str, Any]:
        """Get status of all services."""
        status = {}
        for name, instance in self.services.items():
            status[name] = {
                "state": instance.state.value,
                "priority": instance.definition.priority.value,
                "load_time": instance.load_time,
                "start_time": instance.start_time,
                "error_count": instance.error_count,
                "last_error": instance.last_error
            }
        return status

# Global service loader
_global_service_loader: Optional[ServiceLoader] = None

def get_service_loader() -> ServiceLoader:
    """Get the global service loader."""
    global _global_service_loader
    if _global_service_loader is None:
        _global_service_loader = ServiceLoader()
    return _global_service_loader

def get_service(service_name: str) -> Optional[Any]:
    """Get a service instance."""
    return get_service_loader().get_service(service_name)
