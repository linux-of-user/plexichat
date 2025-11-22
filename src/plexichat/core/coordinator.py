"""
PlexiChat - Real-time Communication Platform
Copyright (C) 2025 PlexiChat Contributors

Core Coordinator
"""
# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Dict, Optional

from plexichat.core.logging import get_logger
from plexichat.core.security.security_manager import get_security_module
from plexichat.core.database.manager import database_manager
from plexichat.core.config import get_config

logger = get_logger(__name__)

# Import other coordinators if they exist
try:
    from plexichat.features.ai.ai_coordinator import ai_coordinator
except ImportError:
    ai_coordinator = None

try:
    from plexichat.infrastructure.scalability.coordinator import scalability_coordinator
except ImportError:
    scalability_coordinator = None

logger = logging.getLogger(__name__)

@dataclass
class SystemMetrics:
    """Overall system metrics."""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    average_response_time: float = 0.0
    system_uptime: float = 0.0
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    disk_usage_percent: float = 0.0
    network_throughput_mbps: float = 0.0

class SystemCoordinator:
    """
    PlexiChat System Coordinator.
    Orchestrates unified system initialization, monitoring, and shutdown.
    """

    def __init__(self):
        self.system_name = "PlexiChat"
        self.version = "2.0.0"
        self.initialized = False
        self.running = False
        self.config = get_config()

        # Core Components
        self.security_manager = get_security_module()
        self.database_manager = database_manager
        self.scalability_coordinator = scalability_coordinator
        self.ai_coordinator = ai_coordinator

        # Metrics & Stats
        self.metrics = SystemMetrics()
        self.start_time: Optional[datetime] = None
        self.stats: Dict[str, Any] = {
            "initialization_time": None,
            "component_status": {
                "security": "not_initialized",
                "database": "not_initialized",
                "scalability": "not_initialized",
                "ai": "not_initialized",
            },
        }

        # Tasks
        self.monitoring_task: Optional[asyncio.Task] = None

    async def initialize_system(self):
        """Initialize all system components in the correct order."""
        if self.initialized:
            logger.warning("System already initialized.")
            return

        self.start_time = datetime.now(UTC)
        logger.info(f"Initializing {self.system_name} v{self.version}...")

        try:
            # 1. Security (First priority)
            if self.security_manager:
                logger.info("Initializing Security Infrastructure...")
                if hasattr(self.security_manager, "initialize"):
                    if asyncio.iscoroutinefunction(self.security_manager.initialize):
                        await self.security_manager.initialize()
                    else:
                        self.security_manager.initialize()
                self.stats["component_status"]["security"] = "active"

            # 2. Database (Critical dependency)
            logger.info("Initializing Database Manager...")
            await self.database_manager.initialize()
            self.stats["component_status"]["database"] = "active"

            # 3. Scalability (Optional)
            if self.scalability_coordinator:
                logger.info("Initializing Scalability Coordinator...")
                if hasattr(self.scalability_coordinator, "initialize"):
                    await self.scalability_coordinator.initialize()
                self.stats["component_status"]["scalability"] = "active"

            # 4. AI (Optional)
            if self.ai_coordinator:
                logger.info("Initializing AI Coordinator...")
                if hasattr(self.ai_coordinator, "initialize"):
                    await self.ai_coordinator.initialize()
                self.stats["component_status"]["ai"] = "active"

            # Start Monitoring
            self.running = True
            self.monitoring_task = asyncio.create_task(self._monitoring_loop())
            self.initialized = True

            init_time = (datetime.now(UTC) - self.start_time).total_seconds()
            self.stats["initialization_time"] = init_time
            logger.info(f"System initialized successfully in {init_time:.2f}s")
            
            await self._log_status()

        except Exception as e:
            logger.critical(f"System initialization failed: {e}")
            await self.shutdown_system()
            raise

    async def shutdown_system(self):
        """Gracefully shutdown all components."""
        if not self.running and not self.initialized:
            return

        logger.info("Shutting down system...")
        self.running = False

        if self.monitoring_task:
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass

        # Shutdown in reverse order
        
        # 4. AI
        if self.ai_coordinator and hasattr(self.ai_coordinator, "shutdown"):
             await self.ai_coordinator.shutdown()
        
        # 3. Scalability
        if self.scalability_coordinator and hasattr(self.scalability_coordinator, "shutdown"):
            await self.scalability_coordinator.shutdown()

        # 2. Database
        await self.database_manager.shutdown()
        self.stats["component_status"]["database"] = "shutdown"

        # 1. Security
        # Security manager usually doesn't need explicit shutdown, but check if exists
        if self.security_manager and hasattr(self.security_manager, "shutdown"):
             if asyncio.iscoroutinefunction(self.security_manager.shutdown):
                await self.security_manager.shutdown()
             else:
                self.security_manager.shutdown()

        self.initialized = False
        logger.info("System shutdown complete.")

    async def _monitoring_loop(self):
        """Background monitoring loop."""
        while self.running:
            try:
                # Placeholder for real metrics collection
                if self.start_time:
                    self.metrics.system_uptime = (datetime.now(UTC) - self.start_time).total_seconds()
                await asyncio.sleep(60)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")
                await asyncio.sleep(60)

    async def _log_status(self):
        """Log current system status."""
        status = self.stats["component_status"]
        logger.info(f"System Status: DB={status['database']}, Sec={status['security']}, AI={status['ai']}")

    def get_system_status(self) -> Dict[str, Any]:
        """Return comprehensive system status."""
        return {
            "name": self.system_name,
            "version": self.version,
            "uptime": self.metrics.system_uptime,
            "components": self.stats["component_status"],
            "metrics": self.metrics.__dict__
        }

system_coordinator = SystemCoordinator()

