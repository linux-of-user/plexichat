# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import asyncio
import logging
import signal
import sys
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from ..core.config import get_config
from ..core.logging import get_logger
from plexichat.core.resilience.manager import get_system_resilience


"""
PlexiChat Base Service

Base class for all PlexiChat services providing common functionality
like lifecycle management, logging, configuration, and health monitoring.

Features:
- Service lifecycle management (start/stop/restart)
- Standardized logging
- Configuration management
- Health monitoring
- Service registration and discovery
- Graceful shutdown handling
- Error handling and recovery
"""


class ServiceState(Enum):
    """Service state enumeration."""

    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    ERROR = "error"


class ServiceHealth(Enum):
    """Service health status."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class BaseService(ABC):
    """Base class for all PlexiChat services."""

    def __init__(self, service_name: str):
        self.service_name = service_name
        self.logger = get_logger(f"service.{service_name}")
        self.config = get_config()

        # Service state
        self.state = ServiceState.STOPPED
        self.health = ServiceHealth.UNKNOWN
        self.start_time: Optional[datetime] = None
        self.last_health_check: Optional[datetime] = None

        # Service metadata
        self.version = "1.0.0"
        self.description = f"PlexiChat {service_name} service"
        self.dependencies: List[str] = []

        # Health monitoring
        self.health_check_interval = 60  # seconds
        self.health_check_task: Optional[asyncio.Task] = None

        # Error tracking
        self.error_count = 0
        self.last_error: Optional[Exception] = None
        self.last_error_time: Optional[datetime] = None

        # Performance metrics
        self.metrics = {
            "requests_handled": 0,
            "errors_encountered": 0,
            "average_response_time": 0.0,
            "uptime_seconds": 0,
        }

        # Shutdown handling
        self._shutdown_event = asyncio.Event()
        self._setup_signal_handlers()

        # System resilience manager
        self.resilience_manager = get_system_resilience()

    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown."""
        if sys.platform != "win32":
            try:
                signal.signal(signal.SIGTERM, self._signal_handler)
                signal.signal(signal.SIGINT, self._signal_handler)
            except ValueError:
                # Signals can only be set from main thread
                pass

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        self.logger.info(f"Received signal {signum}, initiating graceful shutdown (frame: {frame})")
        if self and hasattr(self, "stop"):
            asyncio.create_task(self.stop())

    async def start(self):
        """Start the service."""
        if self.state != ServiceState.STOPPED:
            self.logger.warning()
                f"Service {self.service_name} is already running or starting"
            )
            return

        self.logger.info(f"Starting service: {self.service_name}")
        self.state = ServiceState.STARTING

        try:
            # Check dependencies
            await self._check_dependencies()

            # Initialize service
            await self._initialize()

            # Start health monitoring
            self.health_check_task = asyncio.create_task(self._health_monitoring_loop())

            # Mark as running
            self.state = ServiceState.RUNNING
            self.health = ServiceHealth.HEALTHY
            self.start_time = datetime.now(timezone.utc)

            self.logger.info(f"Service {self.service_name} started successfully")

        except Exception as e:
            self.state = ServiceState.ERROR
            self.health = ServiceHealth.UNHEALTHY
            self.last_error = e
            self.last_error_time = datetime.now(timezone.utc)
            self.error_count += 1

            self.logger.error(f"Failed to start service {self.service_name}: {e}")
            raise

    async def stop(self):
        """Stop the service."""
        if self.state == ServiceState.STOPPED:
            self.logger.warning(f"Service {self.service_name} is already stopped")
            return

        self.logger.info(f"Stopping service: {self.service_name}")
        self.state = ServiceState.STOPPING

        try:
            # Stop health monitoring
            if self.health_check_task:
                self.health_check_task.cancel()
                try:
                    await self.health_check_task
                except asyncio.CancelledError:
                    pass

            # Cleanup service
            await self._cleanup()

            # Mark as stopped
            self.state = ServiceState.STOPPED
            self.health = ServiceHealth.UNKNOWN

            self.logger.info(f"Service {self.service_name} stopped successfully")

        except Exception as e:
            self.state = ServiceState.ERROR
            self.health = ServiceHealth.UNHEALTHY
            self.last_error = e
            self.last_error_time = datetime.now(timezone.utc)
            self.error_count += 1

            self.logger.error(f"Error stopping service {self.service_name}: {e}")
            raise

    async def restart(self):
        """Restart the service."""
        self.logger.info(f"Restarting service: {self.service_name}")
        if self and hasattr(self, "stop"):
            await self.stop()
        await asyncio.sleep(1)  # Brief pause
        if self and hasattr(self, "start"):
            await self.start()

    async def health_check(self) -> Dict[str, Any]:
        """Perform health check and return status."""
        try:
            # Update uptime
            if self.start_time:
                uptime = (datetime.now(timezone.utc) - self.start_time).total_seconds()
                self.metrics["uptime_seconds"] = uptime

            # Perform service-specific health check
            health_data = await self._perform_health_check()

            # Integrate system resilience check
            if self.resilience_manager:
                try:
                    resilience_report = await self.resilience_manager.run_system_check()
                    health_data['resilience'] = resilience_report
                except Exception as e:
                    health_data['resilience'] = {'error': str(e)}

            # Update health status
            self.health = health_data.get("status", ServiceHealth.UNKNOWN)
            self.last_health_check = datetime.now(timezone.utc)

            return {}}
                "service_name": self.service_name,
                "state": self.state.value,
                "health": self.health.value,
                "uptime_seconds": self.metrics["uptime_seconds"],
                "error_count": self.error_count,
                "last_error": str(self.last_error) if self.last_error else None,
                "last_error_time": ()
                    self.last_error_time.isoformat() if self.last_error_time else None
                ),
                "last_health_check": ()
                    self.last_health_check.isoformat()
                    if self.last_health_check
                    else None
                ),
                "metrics": self.metrics.copy(),
                **health_data,
            }

        except Exception as e:
            self.health = ServiceHealth.UNHEALTHY
            self.last_error = e
            self.last_error_time = datetime.now(timezone.utc)
            self.error_count += 1

            self.logger.error(f"Health check failed for {self.service_name}: {e}")

            return {}}
                "service_name": self.service_name,
                "state": self.state.value,
                "health": ServiceHealth.UNHEALTHY.value,
                "error": str(e),
                "error_time": datetime.now(timezone.utc).isoformat(),
            }

    def get_info(self) -> Dict[str, Any]:
        """Get service information."""
        return {}}
            "name": self.service_name,
            "version": self.version,
            "description": self.description,
            "state": self.state.value,
            "health": self.health.value,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "uptime_seconds": self.metrics["uptime_seconds"],
            "dependencies": self.dependencies,
            "metrics": self.metrics.copy(),
        }

    def update_metric(self, name: str, value: Any):
        """Update a service metric."""
        self.metrics[name] = value

    def increment_metric(self, name: str, amount: int = 1):
        """Increment a service metric."""
        self.metrics[name] = self.metrics.get(name, 0) + amount

    async def _health_monitoring_loop(self):
        """Background health monitoring loop."""
        while self.state == ServiceState.RUNNING:
            try:
                await self.health_check()
                await asyncio.sleep(self.health_check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error()
                    f"Health monitoring error for {self.service_name}: {e}"
                )
                await asyncio.sleep(self.health_check_interval)

    async def _check_dependencies(self):
        """Check service dependencies."""
        # This would check if required services are running
        # For now, just log the dependencies
        if self.dependencies:
            self.logger.info()
                f"Service {self.service_name} depends on: {', '.join(self.dependencies)}"
            )

    # Abstract methods that must be implemented by subclasses
    @abstractmethod
    async def _initialize(self):
        """Initialize the service. Must be implemented by subclasses."""

    @abstractmethod
    async def _cleanup(self):
        """Cleanup the service. Must be implemented by subclasses."""

    async def _perform_health_check(self) -> Dict[str, Any]:
        """Perform service-specific health check. Can be overridden by subclasses."""
        return {}}"status": ServiceHealth.HEALTHY, "checks": {"basic": "ok"}}


class ServiceRegistry:
    """Registry for managing multiple services."""

    def __init__(self):
        self.services: Dict[str, BaseService] = {}
        self.logger = get_logger("service.registry")

    def register(self, service: BaseService):
        """Register a service."""
        self.services[service.service_name] = service
        self.logger.info(f"Registered service: {service.service_name}")

    def unregister(self, service_name: str):
        """Unregister a service."""
        if service_name in self.services:
            del self.services[service_name]
            self.logger.info(f"Unregistered service: {service_name}")

    def get_service(self, service_name: str) -> Optional[BaseService]:
        """Get a service by name."""
        return self.services.get(service_name)

    def list_services(self) -> List[str]:
        """List all registered services."""
        return list(self.services.keys())

    async def start_all(self):
        """Start all registered services."""
        self.logger.info("Starting all services")
        for service in self.services.values():
            try:
                if service and hasattr(service, "start"):
                    await service.start()
            except Exception as e:
                self.logger.error()
                    f"Failed to start service {service.service_name}: {e}"
                )

    async def stop_all(self):
        """Stop all registered services."""
        self.logger.info("Stopping all services")
        for service in self.services.values():
            try:
                if service and hasattr(service, "stop"):
                    await service.stop()
            except Exception as e:
                self.logger.error(f"Failed to stop service {service.service_name}: {e}")

    async def get_all_health(self) -> Dict[str, Any]:
        """Get health status of all services."""
        health_data = {}
        for service_name, service in self.services.items():
            health_data[service_name] = await service.health_check()
        return health_data


# Global service registry
_service_registry = ServiceRegistry()


def get_service_registry() -> ServiceRegistry:
    """Get the global service registry."""
    return _service_registry


# Export main components
__all__ = [
    "BaseService",
    "ServiceState",
    "ServiceHealth",
    "ServiceRegistry",
    "get_service_registry",
]
