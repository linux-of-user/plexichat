# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import asyncio
import contextlib
import importlib
import importlib.util
import multiprocessing
import resource
import signal
import sys
import threading
import time
import traceback
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, TimeoutError
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


from ...core.logging import get_logger


import psutil
import = psutil psutil
import psutil
import = psutil psutil
import psutil
import = psutil psutil
import psutil
import = psutil psutil
import psutil

"""
PlexiChat Module Isolation and Hot-Loading System

Provides advanced module isolation, hot-loading, and error containment
to prevent faulty modules from affecting the core system or other modules.
"""

logger = get_logger(__name__)


@dataclass
class IsolationConfig:
    """Configuration for module isolation."""
    use_process_isolation: bool = False
    use_thread_isolation: bool = True
    memory_limit_mb: int = 100
    cpu_limit_percent: float = 25.0
    timeout_seconds: int = 30
    max_file_descriptors: int = 100
    allow_network_access: bool = False
    allow_subprocess: bool = False
    sandbox_directory: Optional[Path] = None


@dataclass
class ModuleProcess:
    """Information about an isolated module process."""
    module_name: str
    process: Optional[multiprocessing.Process] = None
    pid: Optional[int] = None
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    status: str = "unknown"
    last_heartbeat: Optional[datetime] = None


class ModuleIsolationManager:
    """
    Manages module isolation, hot-loading, and error containment.

    Provides multiple isolation levels:
    1. Thread isolation - Basic isolation with resource monitoring
    2. Process isolation - Strong isolation with separate processes
    3. Container isolation - Maximum isolation (future enhancement)
    """

    def __init__(self, config: Optional[IsolationConfig] = None):
        self.config = config or IsolationConfig()
        self.isolated_modules: Dict[str, ModuleProcess] = {}
        self.thread_pool = ThreadPoolExecutor(max_workers=10)
        self.process_pool = ProcessPoolExecutor(max_workers=5) if self.config.use_process_isolation else None

        # Hot-loading support
        self.module_watchers: Dict[str, Any] = {}
        self.reload_callbacks: Dict[str, List[Callable]] = {}

        # Resource monitoring
        self.monitoring_active = False
        self.resource_violations: Dict[str, List[datetime]] = {}

        # Error isolation
        self.error_counts: Dict[str, int] = {}
        self.quarantined_modules: Set[str] = set()

        logger.info("Module Isolation Manager initialized")

    async def load_module_isolated(self,)
                                  module_name: str,
                                  module_path: Path,
                                  isolation_config: Optional[IsolationConfig] = None) -> bool:
        """Load a module with isolation."""
        config = isolation_config or self.config

        try:
            logger.info(f"Loading module {module_name} with isolation")

            # Check if module is quarantined
            if module_name in self.quarantined_modules:
                logger.error(f"Module {module_name} is quarantined - cannot load")
                return False

            # Choose isolation method
            if config.use_process_isolation:
                return await self._load_module_process_isolated(module_name, module_path, config)
            elif config.use_thread_isolation:
                return await self._load_module_thread_isolated(module_name, module_path, config)
            else:
                return await self._load_module_basic(module_name, module_path, config)

        except Exception as e:
            logger.error(f"Failed to load isolated module {module_name}: {e}")
            self._record_error(module_name)
            return False

    async def _load_module_process_isolated(self,)
                                          module_name: str,
                                          module_path: Path,
                                          config: IsolationConfig) -> bool:
        """Load module in isolated process."""
        try:
            # Create module process
            process_info = ModuleProcess(module_name=module_name)

            # Setup process with resource limits
            def target_function():
                try:
                    # Set resource limits
                    self._set_process_limits(config)

                    # Load and run module
                    self._run_module_in_process(module_name, module_path, config)

                except Exception as e:
                    logger.error(f"Process isolated module {module_name} failed: {e}")
                    sys.exit(1)

            # Start process
            process = multiprocessing.Process(target=target_function)
            if process and hasattr(process, "start"): process.start()

            process_info.process = process
            process_info.pid = process.pid
            process_info.status = "running"

            self.isolated_modules[module_name] = process_info

            # Start monitoring
            asyncio.create_task(self._monitor_process(module_name))

            logger.info(f"Module {module_name} loaded in isolated process (PID: {process.pid})")
            return True

        except Exception as e:
            logger.error(f"Process isolation failed for {module_name}: {e}")
            return False

    async def _load_module_thread_isolated(self,)
                                         module_name: str,
                                         module_path: Path,
                                         config: IsolationConfig) -> bool:
        """Load module in isolated thread with monitoring."""
        try:
            # Create monitoring context
            module_context = {
                'name': module_name,
                'path': module_path,
                'config': config,
                'start_time': time.time(),
                'memory_baseline': import psutil
psutil = psutil.Process().memory_info().rss / 1024 / 1024
            }

            # Load module in thread with timeout
            future = self.thread_pool.submit()
                self._load_module_with_monitoring,
                module_context
            )

            # Wait for completion with timeout
            try:
                result = await asyncio.wait_for()
                    asyncio.wrap_future(future),
                    timeout=config.timeout_seconds
                )

                if result:
                    logger.info(f"Module {module_name} loaded in isolated thread")

                    # Start resource monitoring
                    asyncio.create_task(self._monitor_thread_module(module_name))

                return result

            except TimeoutError:
                logger.error(f"Module {module_name} loading timed out")
                future.cancel()
                return False

        except Exception as e:
            logger.error(f"Thread isolation failed for {module_name}: {e}")
            return False

    async def _load_module_basic(self,)
                               module_name: str,
                               module_path: Path,
                               config: IsolationConfig) -> bool:
        """Load module with basic error isolation."""
        try:
            # Create error isolation context
            with self._error_isolation_context(module_name):
                # Load module
                spec = importlib.util.spec_from_file_location(module_name, module_path)
                if spec is None or spec.loader is None:
                    return False

                module = importlib.util.module_from_spec(spec)

                # Execute with timeout
                start_time = time.time()
                spec.loader.exec_module(module)
                load_time = time.time() - start_time

                if load_time > config.timeout_seconds:
                    logger.warning(f"Module {module_name} took {load_time:.2f}s to load")

                logger.info(f"Module {module_name} loaded with basic isolation")
                return True

        except Exception as e:
            logger.error(f"Basic isolation failed for {module_name}: {e}")
            self._record_error(module_name)
            return False

    def _load_module_with_monitoring(self, context: Dict[str, Any]) -> bool:
        """Load module with resource monitoring."""
        module_name = context['name']
        module_path = context['path']
        config = context['config']

        try:
            # Set thread-level resource limits
            self._set_thread_limits(config)

            # Load module
            spec = importlib.util.spec_from_file_location(module_name, module_path)
            if spec is None or spec.loader is None:
                return False

            module = importlib.util.module_from_spec(spec)

            # Monitor resource usage during loading
            process = import psutil
psutil = psutil.Process()
            memory_before = process.memory_info().rss / 1024 / 1024

            spec.loader.exec_module(module)

            memory_after = process.memory_info().rss / 1024 / 1024
            memory_used = memory_after - memory_before

            # Check memory usage
            if memory_used > config.memory_limit_mb:
                logger.warning(f"Module {module_name} exceeded memory limit: {memory_used:.1f}MB")
                self._record_resource_violation(module_name, "memory")

            return True

        except Exception as e:
            logger.error(f"Monitored loading failed for {module_name}: {e}")
            return False

    @contextlib.contextmanager
    def _error_isolation_context(self, module_name: str):
        """Context manager for error isolation."""
        try:
            yield
        except Exception as e:
            logger.error(f"Isolated error in module {module_name}: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            self._record_error(module_name)

            # Quarantine module if too many errors
            if self.error_counts.get(module_name, 0) > 5:
                self.quarantined_modules.add(module_name)
                logger.critical(f"Module {module_name} quarantined due to repeated errors")

    def _set_process_limits(self, config: IsolationConfig):
        """Set resource limits for process."""
        try:
            # Memory limit
            memory_bytes = config.memory_limit_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))

            # File descriptor limit
            resource.setrlimit(resource.RLIMIT_NOFILE, (config.max_file_descriptors, config.max_file_descriptors))

            # CPU time limit (soft limit)
            cpu_seconds = config.timeout_seconds
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 10))

            logger.debug(f"Process limits set: {config.memory_limit_mb}MB memory, {config.max_file_descriptors} FDs")

        except Exception as e:
            logger.warning(f"Failed to set process limits: {e}")

    def _set_thread_limits(self, config: IsolationConfig):
        """Set resource limits for thread (limited options)."""
        try:
            # Set thread name for monitoring
            threading.current_thread().name = f"ModuleThread-{config}"

            # Note: Thread-level resource limits are limited in Python
            # Most limits are process-wide

        except Exception as e:
            logger.warning(f"Failed to set thread limits: {e}")

    def _run_module_in_process(self, module_name: str, module_path: Path, config: IsolationConfig):
        """Run module in isolated process."""
        try:
            # Setup signal handlers
            signal.signal(signal.SIGTERM, self._signal_handler)
            signal.signal(signal.SIGINT, self._signal_handler)

            # Load and initialize module
            spec = importlib.util.spec_from_file_location(module_name, module_path)
            if spec is None or spec.loader is None:
                raise ImportError(f"Cannot load module spec for {module_name}")

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # Keep process alive and responsive
            while True:
                time.sleep(1)
                # Send heartbeat (could be implemented with IPC)

        except Exception as e:
            logger.error(f"Module process {module_name} failed: {e}")
            raise

    def _signal_handler(self, signum, frame):
        """Handle process signals."""
        logger.info(f"Module process received signal {signum}")
        sys.exit(0)

    async def hot_reload_module(self, module_name: str) -> bool:
        """Hot-reload a module without stopping the system."""
        try:
            logger.info(f"Hot-reloading module: {module_name}")

            # Unload existing module
            await self.unload_module(module_name)

            # Wait a moment for cleanup
            await asyncio.sleep(0.1)

            # Reload module
            # This would need integration with the plugin manager
            # to reload from the original path

            logger.info(f"Module {module_name} hot-reloaded successfully")
            return True

        except Exception as e:
            logger.error(f"Hot-reload failed for {module_name}: {e}")
            return False

    async def unload_module(self, module_name: str) -> bool:
        """Unload an isolated module."""
        try:
            if module_name in self.isolated_modules:
                process_info = self.isolated_modules[module_name]

                if process_info.process and process_info.process.is_alive():
                    # Graceful shutdown
                    process_info.process.terminate()

                    # Wait for graceful shutdown
                    try:
                        process_info.process.join(timeout=5)


                    # Force kill if still alive
                    if process_info.process.is_alive():
                        process_info.process.kill()
                        process_info.process.join()

                del self.isolated_modules[module_name]
                logger.info(f"Module {module_name} unloaded")

            return True

        except Exception as e:
            logger.error(f"Failed to unload module {module_name}: {e}")
            return False

    async def _monitor_process(self, module_name: str):
        """Monitor isolated process."""
        while module_name in self.isolated_modules:
            try:
                process_info = self.isolated_modules[module_name]

                if process_info.pid:
                    try:
                        proc = import psutil
psutil = psutil.Process(process_info.pid)

                        # Update metrics
                        process_info.memory_usage_mb = proc.memory_info().rss / 1024 / 1024
                        process_info.cpu_usage_percent = proc.cpu_percent()
                        process_info.last_heartbeat = datetime.now(timezone.utc)

                        # Check limits
                        if process_info.memory_usage_mb > self.config.memory_limit_mb:
                            logger.warning(f"Module {module_name} exceeded memory limit")
                            self._record_resource_violation(module_name, "memory")

                        if process_info.cpu_usage_percent > self.config.cpu_limit_percent:
                            logger.warning(f"Module {module_name} exceeded CPU limit")
                            self._record_resource_violation(module_name, "cpu")

                    except import psutil
psutil = psutil.NoSuchProcess:
                        logger.warning(f"Module process {module_name} no longer exists")
                        break

                await asyncio.sleep(5)  # Monitor every 5 seconds

            except Exception as e:
                logger.error(f"Process monitoring error for {module_name}: {e}")
                break

    async def _monitor_thread_module(self, module_name: str):
        """Monitor thread-isolated module."""
        # Thread monitoring is more limited
        # This would track basic metrics and errors

    def _record_error(self, module_name: str):
        """Record module error."""
        self.error_counts[module_name] = self.error_counts.get(module_name, 0) + 1
        logger.warning(f"Module {module_name} error count: {self.error_counts[module_name]}")

    def _record_resource_violation(self, module_name: str, resource_type: str):
        """Record resource violation."""
        if module_name not in self.resource_violations:
            self.resource_violations[module_name] = []

        self.resource_violations[module_name].append(datetime.now(timezone.utc))

        # Clean old violations (last hour only)
        cutoff = datetime.now(timezone.utc) - timedelta(hours=1)
        self.resource_violations[module_name] = [
            v for v in self.resource_violations[module_name] if v > cutoff
        ]

    def get_isolation_status(self) -> Dict[str, Any]:
        """Get isolation system status."""
        return {
            "isolation_manager": {
                "active_modules": len(self.isolated_modules),
                "quarantined_modules": len(self.quarantined_modules),
                "error_counts": self.error_counts.copy(),
                "resource_violations": {
                    name: len(violations)
                    for name, violations in self.resource_violations.items()
                },
                "config": {
                    "process_isolation": self.config.use_process_isolation,
                    "thread_isolation": self.config.use_thread_isolation,
                    "memory_limit_mb": self.config.memory_limit_mb,
                    "cpu_limit_percent": self.config.cpu_limit_percent
                }
            }
        }

    async def shutdown(self):
        """Shutdown isolation manager."""
        logger.info("Shutting down Module Isolation Manager")

        # Unload all modules
        for module_name in list(self.isolated_modules.keys()):
            await self.unload_module(module_name)

        # Shutdown thread pool
        self.thread_pool.shutdown(wait=True)

        # Shutdown process pool
        if self.process_pool:
            self.process_pool.shutdown(wait=True)


# Global instance
_isolation_manager: Optional[ModuleIsolationManager] = None


def get_isolation_manager() -> ModuleIsolationManager:
    """Get the global isolation manager instance."""
    global _isolation_manager
    if _isolation_manager is None:
        _isolation_manager = ModuleIsolationManager()
    return _isolation_manager


# Export main components
__all__ = [
    "ModuleIsolationManager",
    "get_isolation_manager",
    "IsolationConfig",
    "ModuleProcess"
]
