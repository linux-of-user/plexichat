"""
PlexiChat Health Check Service

Comprehensive health monitoring service for application health and dependencies
in production environments. Monitors system resources, database connections,
external services, and application components.
"""

import asyncio
import logging
import psutil
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import aiohttp

logger = logging.getLogger(__name__)


class HealthStatus(Enum):
    """Health status enumeration."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class HealthCheck:
    """Individual health check configuration."""
    name: str
    check_function: Callable
    timeout: float = 5.0
    interval: float = 30.0
    critical: bool = False
    description: str = ""
    last_check: Optional[datetime] = None
    last_status: HealthStatus = HealthStatus.UNKNOWN
    last_error: Optional[str] = None
    consecutive_failures: int = 0


@dataclass
class HealthResult:
    """Result of a health check."""
    name: str
    status: HealthStatus
    message: str
    duration_ms: float
    timestamp: datetime
    details: Dict[str, Any] = field(default_factory=dict)


class HealthCheckService:
    """
    Comprehensive health monitoring service.
    """
    
    def __init__(self):
        self.checks: Dict[str, HealthCheck] = {}
        self.results: Dict[str, HealthResult] = {}
        self.running = False
        self.check_task = None
        self.failure_threshold = 3
        self.startup_time = datetime.now()
        
    def register_check(self, health_check: HealthCheck):
        """Register a new health check."""
        self.checks[health_check.name] = health_check
        logger.info(f"Registered health check: {health_check.name}")
    
    def unregister_check(self, name: str):
        """Unregister a health check."""
        if name in self.checks:
            del self.checks[name]
            if name in self.results:
                del self.results[name]
            logger.info(f"Unregistered health check: {name}")
    
    async def run_check(self, check: HealthCheck) -> HealthResult:
        """Run a single health check."""
        start_time = time.time()
        
        try:
            # Run the check with timeout
            result = await asyncio.wait_for(
                check.check_function(),
                timeout=check.timeout
            )
            
            duration_ms = (time.time() - start_time) * 1000
            
            if isinstance(result, bool):
                status = HealthStatus.HEALTHY if result else HealthStatus.UNHEALTHY
                message = "Check passed" if result else "Check failed"
                details = {}
            elif isinstance(result, dict):
                status = HealthStatus(result.get("status", "unknown"))
                message = result.get("message", "No message")
                details = result.get("details", {})
            else:
                status = HealthStatus.HEALTHY
                message = str(result)
                details = {}
            
            # Reset consecutive failures on success
            if status == HealthStatus.HEALTHY:
                check.consecutive_failures = 0
            else:
                check.consecutive_failures += 1
            
            check.last_status = status
            check.last_error = None
            
        except asyncio.TimeoutError:
            duration_ms = check.timeout * 1000
            status = HealthStatus.UNHEALTHY
            message = f"Check timed out after {check.timeout}s"
            details = {}
            check.consecutive_failures += 1
            check.last_error = "Timeout"
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            status = HealthStatus.UNHEALTHY
            message = f"Check failed: {str(e)}"
            details = {"error": str(e), "type": type(e).__name__}
            check.consecutive_failures += 1
            check.last_error = str(e)
        
        check.last_check = datetime.now()
        check.last_status = status
        
        return HealthResult(
            name=check.name,
            status=status,
            message=message,
            duration_ms=duration_ms,
            timestamp=check.last_check,
            details=details
        )
    
    async def run_all_checks(self) -> Dict[str, HealthResult]:
        """Run all registered health checks."""
        results = {}
        
        # Run checks concurrently
        tasks = []
        for check in self.checks.values():
            task = asyncio.create_task(self.run_check(check))
            tasks.append((check.name, task))
        
        # Wait for all checks to complete
        for name, task in tasks:
            try:
                result = await task
                results[name] = result
                self.results[name] = result
            except Exception as e:
                logger.error(f"Health check {name} failed unexpectedly: {e}")
                results[name] = HealthResult(
                    name=name,
                    status=HealthStatus.UNHEALTHY,
                    message=f"Unexpected error: {e}",
                    duration_ms=0,
                    timestamp=datetime.now()
                )
        
        return results
    
    async def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status."""
        # Run health checks
        check_results = await self.run_all_checks()
        
        # Determine overall status
        overall_status = HealthStatus.HEALTHY
        critical_failures = 0
        total_failures = 0
        
        for result in check_results.values():
            if result.status == HealthStatus.UNHEALTHY:
                total_failures += 1
                check = self.checks.get(result.name)
                if check and check.critical:
                    critical_failures += 1
        
        if critical_failures > 0:
            overall_status = HealthStatus.UNHEALTHY
        elif total_failures > 0:
            overall_status = HealthStatus.DEGRADED
        
        # Get system metrics
        system_metrics = await self._get_system_metrics()
        
        return {
            "status": overall_status.value,
            "timestamp": datetime.now(),
            "uptime": (datetime.now() - self.startup_time).total_seconds(),
            "checks": {name: {
                "status": result.status.value,
                "message": result.message,
                "duration_ms": result.duration_ms,
                "timestamp": result.timestamp,
                "details": result.details
            } for name, result in check_results.items()},
            "metrics": system_metrics,
            "summary": {
                "total_checks": len(check_results),
                "healthy_checks": len([r for r in check_results.values() if r.status == HealthStatus.HEALTHY]),
                "unhealthy_checks": total_failures,
                "critical_failures": critical_failures
            }
        }
    
    async def _get_system_metrics(self) -> Dict[str, Any]:
        """Get system performance metrics."""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Memory usage
            memory = psutil.virtual_memory()
            memory_usage = {
                "total": memory.total,
                "available": memory.available,
                "percent": memory.percent,
                "used": memory.used
            }
            
            # Disk usage
            disk = psutil.disk_usage('/')
            disk_usage = {
                "total": disk.total,
                "used": disk.used,
                "free": disk.free,
                "percent": (disk.used / disk.total) * 100
            }
            
            # Network stats
            network = psutil.net_io_counters()
            network_stats = {
                "bytes_sent": network.bytes_sent,
                "bytes_recv": network.bytes_recv,
                "packets_sent": network.packets_sent,
                "packets_recv": network.packets_recv
            }
            
            # Process info
            process = psutil.Process()
            process_info = {
                "pid": process.pid,
                "memory_percent": process.memory_percent(),
                "cpu_percent": process.cpu_percent(),
                "num_threads": process.num_threads(),
                "create_time": process.create_time()
            }
            
            return {
                "cpu_usage_percent": cpu_percent,
                "memory_usage": memory_usage,
                "disk_usage": disk_usage,
                "network_stats": network_stats,
                "process_info": process_info
            }
            
        except Exception as e:
            logger.error(f"Failed to get system metrics: {e}")
            return {"error": str(e)}
    
    async def start_monitoring(self):
        """Start continuous health monitoring."""
        if self.running:
            return
        
        self.running = True
        self.check_task = asyncio.create_task(self._monitoring_loop())
        logger.info("Health monitoring started")
    
    async def stop_monitoring(self):
        """Stop continuous health monitoring."""
        if not self.running:
            return
        
        self.running = False
        if self.check_task:
            self.check_task.cancel()
            try:
                await self.check_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Health monitoring stopped")
    
    async def _monitoring_loop(self):
        """Continuous monitoring loop."""
        while self.running:
            try:
                # Run checks that are due
                current_time = datetime.now()
                
                for check in self.checks.values():
                    if (check.last_check is None or 
                        (current_time - check.last_check).total_seconds() >= check.interval):
                        
                        # Run check in background
                        asyncio.create_task(self.run_check(check))
                
                # Wait before next iteration
                await asyncio.sleep(5)  # Check every 5 seconds for due checks
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(10)  # Wait longer on error


# Built-in health checks
async def database_health_check() -> Dict[str, Any]:
    """Check database connectivity."""
    try:
        from ...core_system.database import database_manager
        
        # Test database connection
        is_connected = await database_manager.test_connection()
        
        if is_connected:
            return {
                "status": "healthy",
                "message": "Database connection successful",
                "details": {"connection_pool": "active"}
            }
        else:
            return {
                "status": "unhealthy",
                "message": "Database connection failed"
            }
            
    except Exception as e:
        return {
            "status": "unhealthy",
            "message": f"Database check failed: {e}"
        }


async def api_health_check() -> Dict[str, Any]:
    """Check API server health."""
    try:
        # This would check if the API server is responding
        async with aiohttp.ClientSession() as session:
            async with session.get("http://localhost:8000/health", timeout=5) as response:
                if response.status == 200:
                    return {
                        "status": "healthy",
                        "message": "API server responding",
                        "details": {"status_code": response.status}
                    }
                else:
                    return {
                        "status": "degraded",
                        "message": f"API server returned status {response.status}"
                    }
                    
    except Exception as e:
        return {
            "status": "unhealthy",
            "message": f"API server check failed: {e}"
        }


# Global health service instance
health_service = HealthCheckService()

# Register default health checks
health_service.register_check(HealthCheck(
    name="database",
    check_function=database_health_check,
    critical=True,
    description="Database connectivity check"
))

health_service.register_check(HealthCheck(
    name="api",
    check_function=api_health_check,
    critical=True,
    description="API server health check"
))


# Convenience functions
async def get_health_status() -> Dict[str, Any]:
    """Get current health status."""
    return await health_service.get_system_status()


async def is_healthy() -> bool:
    """Check if system is healthy."""
    status = await health_service.get_system_status()
    return status["status"] == "healthy"
