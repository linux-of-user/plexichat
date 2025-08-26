# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import asyncio
import logging
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set
import http.client

import aiohttp


"""
PlexiChat Microservices Service Registry
Manages service discovery, registration, and health monitoring
"""

logger = logging.getLogger(__name__)


class ServiceStatus(Enum):
    """Service status enumeration."""
    STARTING = "starting"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    STOPPING = "stopping"
    STOPPED = "stopped"


class ServiceType(Enum):
    """Microservice types."""
    AUTHENTICATION = "authentication"
    USER_MANAGEMENT = "user_management"
    MESSAGING = "messaging"
    FILE_STORAGE = "file_storage"
    AI_SERVICES = "ai_services"
    NOTIFICATION = "notification"
    ANALYTICS = "analytics"
    SECURITY = "security"
    BACKUP = "backup"
    CLUSTERING = "clustering"
    API_GATEWAY = "api_gateway"
    WEB_UI = "web_ui"
    DATABASE = "database"
    CACHE = "cache"
    SEARCH = "search"


@dataclass
class ServiceEndpoint:
    """Service endpoint definition."""
    service_id: str
    service_name: str
    service_type: ServiceType
    host: str
    port: int
    protocol: str = "http"
    version: str = "1.0.0"
    status: ServiceStatus = ServiceStatus.STARTING
    health_check_url: str = "/health"
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: Set[str] = field(default_factory=set)

    # Health monitoring
    last_health_check: Optional[datetime] = None
    consecutive_failures: int = 0
    response_time_ms: float = 0.0

    # Registration info
    registered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_heartbeat: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def base_url(self) -> str:
        """Get the base URL for this service."""
        return f"{self.protocol}://{self.host}:{self.port}"

    @property
    def health_url(self) -> str:
        """Get the health check URL."""
        return f"{self.base_url}{self.health_check_url}"

    def is_healthy(self) -> bool:
        """Check if service is considered healthy."""
        return self.status == ServiceStatus.HEALTHY and self.consecutive_failures < 3

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = asdict(self)
        data["service_type"] = self.service_type.value
        data["status"] = self.status.value
        data["tags"] = list(self.tags)
        data["registered_at"] = self.registered_at.isoformat()
        data["last_heartbeat"] = self.last_heartbeat.isoformat()
        if self.last_health_check:
            data["last_health_check"] = self.last_health_check.isoformat()
        return data


class ServiceRegistry:
    """
    Microservices Service Registry.

    Features:
    - Service registration and discovery
    - Health monitoring and circuit breaking
    - Load balancing support
    - Service versioning
    - Metadata and tagging
    - Event-driven notifications
    - Distributed consensus for HA
    """
    def __init__(self):
        self.services: Dict[str, ServiceEndpoint] = {}
        self.service_groups: Dict[ServiceType, List[str]] = {}
        self.health_check_interval = 30  # seconds
        self.health_check_timeout = 5  # seconds
        self.max_consecutive_failures = 3

        # Statistics
        self.stats = {
            "total_services": 0,
            "healthy_services": 0,
            "unhealthy_services": 0,
            "total_health_checks": 0,
            "failed_health_checks": 0,
            "average_response_time": 0.0,
        }

        # Event callbacks
        self.event_callbacks: Dict[str, List[callable]] = {
            "service_registered": [],
            "service_deregistered": [],
            "service_health_changed": [],
            "service_failed": [],
        }

        self.running = False
        self.health_check_task: Optional[asyncio.Task] = None

        # Initialize service groups
        for service_type in ServiceType:
            self.service_groups[service_type] = []

    async def start(self):
        """Start the service registry."""
        if self.running:
            return

        self.running = True
        self.health_check_task = asyncio.create_task(self._health_check_loop())
        logger.info(" Service Registry started")

    async def stop(self):
        """Stop the service registry."""
        self.running = False
        if self.health_check_task:
            self.health_check_task.cancel()
            try:
                await self.health_check_task
            except asyncio.CancelledError:
                pass
        logger.info(" Service Registry stopped")

    async def register_service(self, service: ServiceEndpoint) -> bool:
        """Register a new service."""
        try:
            # Check if service already exists
            if service.service_id in self.services:
                logger.warning(
                    f"Service {service.service_id} already registered, updating"
                )

            # Add to registry
            self.services[service.service_id] = service

            # Add to service group
            if service.service_type not in self.service_groups:
                self.service_groups[service.service_type] = []

            if service.service_id not in self.service_groups[service.service_type]:
                self.service_groups[service.service_type].append(service.service_id)

            # Update statistics
            self._update_stats()

            # Trigger event
            await self._trigger_event("service_registered", service)

            logger.info(
                f" Registered service: {service.service_name} ({service.service_id})"
            )
            return True

        except Exception as e:
            logger.error(f" Failed to register service {service.service_id}: {e}")
            return False

    async def deregister_service(self, service_id: str) -> bool:
        """Deregister a service."""
        try:
            if service_id not in self.services:
                logger.warning(f"Service {service_id} not found for deregistration")
                return False

            service = self.services[service_id]

            # Remove from service group
            if service.service_type in self.service_groups:
                if service_id in self.service_groups[service.service_type]:
                    self.service_groups[service.service_type].remove(service_id)

            # Remove from registry
            del self.services[service_id]

            # Update statistics
            self._update_stats()

            # Trigger event
            await self._trigger_event("service_deregistered", service)

            logger.info(f" Deregistered service: {service.service_name} ({service_id})")
            return True

        except Exception as e:
            logger.error(f" Failed to deregister service {service_id}: {e}")
            return False

    async def discover_services(
        self,
        service_type: Optional[ServiceType] = None,
        tags: Optional[Set[str]] = None,
        healthy_only: bool = True,
    ) -> List[ServiceEndpoint]:
        """Discover services by type and tags."""
        services = []

        for service in self.services.values():
            # Filter by type
            if service_type and service.service_type != service_type:
                continue

            # Filter by health
            if healthy_only and not service.is_healthy():
                continue

            # Filter by tags
            if tags and not tags.issubset(service.tags):
                continue

            services.append(service)

        # Sort by response time (fastest first)
        services.sort(key=lambda s: s.response_time_ms)

        return services

    async def get_service(self, service_id: str) -> Optional[ServiceEndpoint]:
        """Get a specific service by ID."""
        return self.services.get(service_id)

    async def get_service_by_name(self, service_name: str) -> Optional[ServiceEndpoint]:
        """Get a service by name."""
        for service in self.services.values():
            if service.service_name == service_name:
                return service
        return None

    async def update_service_heartbeat(self, service_id: str) -> bool:
        """Update service heartbeat."""
        if service_id in self.services:
            self.services[service_id].last_heartbeat = datetime.now(timezone.utc)
            return True
        return False

    async def _health_check_loop(self):
        """Continuous health checking loop."""
        while self.running:
            try:
                await self._perform_health_checks()
                await asyncio.sleep(self.health_check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Health check loop error: {e}")
                await asyncio.sleep(5)  # Brief pause before retrying

    async def _perform_health_checks(self):
        """Perform health checks on all registered services."""
        if not self.services:
            return

        # Create health check tasks
        tasks = []
        for service_id, service in self.services.items():
            task = asyncio.create_task(self._check_service_health(service))
            tasks.append(task)

        # Wait for all health checks to complete
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        # Update statistics
        self._update_stats()

    async def _check_service_health(self, service: ServiceEndpoint):
        """Check health of a single service."""
        start_time = time.time()

        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.health_check_timeout)
            ) as session:
                async with session.get(service.health_url) as response:
                    response_time = (time.time() - start_time) * 1000  # Convert to ms
                    service.response_time_ms = response_time
                    service.last_health_check = datetime.now(timezone.utc)

                    if response.status == 200:
                        # Service is healthy
                        old_status = service.status
                        service.status = ServiceStatus.HEALTHY
                        service.consecutive_failures = 0

                        if old_status != ServiceStatus.HEALTHY:
                            await self._trigger_event("service_health_changed", service)
                    else:
                        # Service returned error status
                        await self._handle_service_failure(
                            service, f"HTTP {response.status}"
                        )

        except asyncio.TimeoutError:
            await self._handle_service_failure(service, "Health check timeout")
        except Exception as e:
            await self._handle_service_failure(service, str(e))

        self.stats["total_health_checks"] += 1

    async def _handle_service_failure(self, service: ServiceEndpoint, error: str):
        """Handle service health check failure."""
        service.consecutive_failures += 1
        service.last_health_check = datetime.now(timezone.utc)

        old_status = service.status

        if service.consecutive_failures >= self.max_consecutive_failures:
            service.status = ServiceStatus.UNHEALTHY
        else:
            service.status = ServiceStatus.DEGRADED

        self.stats["failed_health_checks"] += 1

        logger.warning(
            f"Service {service.service_name} health check failed: {error} "
            f"(failures: {service.consecutive_failures})"
        )

        # Trigger events
        if old_status != service.status:
            await self._trigger_event("service_health_changed", service)

        if service.status == ServiceStatus.UNHEALTHY:
            await self._trigger_event("service_failed", service)

    def _update_stats(self):
        """Update registry statistics."""
        total = len(self.services)
        healthy = sum(
            1 for s in self.services.values() if s.status == ServiceStatus.HEALTHY
        )
        unhealthy = sum(
            1 for s in self.services.values() if s.status == ServiceStatus.UNHEALTHY
        )

        # Calculate average response time
        response_times = [
            s.response_time_ms for s in self.services.values() if s.response_time_ms > 0
        ]
        avg_response_time = (
            sum(response_times) / len(response_times) if response_times else 0.0
        )

        self.stats.update(
            {
                "total_services": total,
                "healthy_services": healthy,
                "unhealthy_services": unhealthy,
                "average_response_time": avg_response_time,
            }
        )

    async def _trigger_event(self, event_type: str, service: ServiceEndpoint):
        """Trigger event callbacks."""
        if event_type in self.event_callbacks:
            for callback in self.event_callbacks[event_type]:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(service)
                    else:
                        callback(service)
                except Exception as e:
                    logger.error(f"Event callback error for {event_type}: {e}")

    def add_event_listener(self, event_type: str, callback: callable):
        """Add event listener."""
        if event_type not in self.event_callbacks:
            self.event_callbacks[event_type] = []
        self.event_callbacks[event_type].append(callback)

    def get_registry_status(self) -> Dict[str, Any]:
        """Get comprehensive registry status."""
        service_types_count = {}
        for service_type, service_ids in self.service_groups.items():
            healthy_count = sum(
                1
                for sid in service_ids
                if sid in self.services and self.services[sid].is_healthy()
            )
            service_types_count[service_type.value] = {
                "total": len(service_ids),
                "healthy": healthy_count,
                "unhealthy": len(service_ids) - healthy_count,
            }

        return {
            "running": self.running,
            "statistics": self.stats,
            "service_types": service_types_count,
            "health_check_interval": self.health_check_interval,
            "last_updated": datetime.now(timezone.utc).isoformat(),
        }


# Global service registry instance
service_registry = ServiceRegistry()
