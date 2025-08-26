# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import asyncio
import logging
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional
import time

try:
    import psutil
except ImportError:
    psutil = None

"""
PlexiChat Metrics Collection Service Module

Small modular service for collecting and aggregating system metrics.
"""

# Service metadata
SERVICE_METADATA = {
    "module_id": "metrics_service",
    "name": "System Metrics Collection",
    "description": "Collects and aggregates system performance metrics",
    "version": "1.0.0",
    "service_type": "background",
    "dependencies": ["logging_service"],
    "provides": ["metrics", "performance_monitoring", "alerts"],
    "config": {
        "collection_interval": 30,  # seconds
        "retention_hours": 24,
        "alert_thresholds": {
            "cpu_percent": 80,
            "memory_percent": 85,
            "disk_percent": 90
        },
        "enable_alerts": True
    },
    "auto_start": True,
    "hot_reload": True
}

logger = logging.getLogger(__name__)


class MetricsService:
    """System metrics collection service."""
    def __init__(self):
        self.config = SERVICE_METADATA["config"]
        self.metrics_data = defaultdict(lambda: deque(maxlen=2880))  # 24h at 30s intervals
        self.alert_callbacks = []
        self.collection_task = None
        self.running = False
        self.metric_categories = {}
        self.logger = logging.getLogger(__name__)

    async def initialize(self) -> bool:
        """Initialize the metrics service."""
        try:
            # Verify psutil is available
            if not psutil:
                self.logger.error("psutil not available for metrics collection")
                return False

            # Initialize metric categories
            self.metric_categories = {
                "system": self._collect_system_metrics,
                "cpu": self._collect_cpu_metrics,
                "memory": self._collect_memory_metrics,
                "disk": self._collect_disk_metrics,
                "network": self._collect_network_metrics,
                "process": self._collect_process_metrics
            }

            self.logger.info("Metrics service initialized")
            return True

        except Exception as e:
            self.logger.error(f"Failed to initialize metrics service: {e}")
            return False

    async def start(self) -> bool:
        """Start the metrics service."""
        try:
            self.running = True

            # Start metrics collection task
            self.collection_task = asyncio.create_task(self._collection_loop())

            self.logger.info("Metrics service started")
            return True

        except Exception as e:
            self.logger.error(f"Failed to start metrics service: {e}")
            return False

    async def stop(self) -> bool:
        """Stop the metrics service."""
        try:
            self.running = False

            if self.collection_task:
                self.collection_task.cancel()
                try:
                    await self.collection_task
                except asyncio.CancelledError:
                    pass

            self.logger.info("Metrics service stopped")
            return True

        except Exception as e:
            self.logger.error(f"Failed to stop metrics service: {e}")
            return False

    async def _collection_loop(self):
        """Main metrics collection loop."""
        while self.running:
            try:
                await self._collect_all_metrics()
                await self._check_alerts()
                await self._cleanup_old_metrics()

                await asyncio.sleep(self.config["collection_interval"])

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in metrics collection loop: {e}")
                await asyncio.sleep(5)  # Brief pause before retrying

    async def _collect_all_metrics(self):
        """Collect all metrics."""
        timestamp = datetime.now(timezone.utc)

        for category, collector in self.metric_categories.items():
            try:
                metrics = await collector()

                for metric_name, value in metrics.items():
                    metric_key = f"{category}.{metric_name}"
                    self.metrics_data[metric_key].append({
                        "timestamp": timestamp,
                        "value": value
                    })

            except Exception as e:
                self.logger.warning(f"Failed to collect {category} metrics: {e}")

    async def _collect_system_metrics(self) -> Dict[str, float]:
        """Collect general system metrics."""
        try:
            if not psutil: return {}
            boot_time = datetime.fromtimestamp(psutil.boot_time(), timezone.utc)
            uptime = (datetime.now(timezone.utc) - boot_time).total_seconds()

            return {
                "uptime_seconds": uptime,
                "load_average_1m": psutil.getloadavg()[0] if hasattr(psutil, 'getloadavg') else 0,
                "process_count": len(psutil.pids())
            }
        except Exception as e:
            self.logger.warning(f"Failed to collect system metrics: {e}")
            return {}

    async def _collect_cpu_metrics(self) -> Dict[str, float]:
        """Collect CPU metrics."""
        try:
            if not psutil: return {}
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_count = psutil.cpu_count()
            cpu_freq = psutil.cpu_freq()

            metrics = {
                "usage_percent": cpu_percent,
                "count": cpu_count
            }

            if cpu_freq:
                metrics.update({
                    "frequency_mhz": cpu_freq.current,
                    "frequency_max_mhz": cpu_freq.max
                })

            # Per-core usage
            per_cpu = psutil.cpu_percent(percpu=True)
            for i, usage in enumerate(per_cpu):
                metrics[f"core_{i}_percent"] = usage

            return metrics

        except Exception as e:
            self.logger.warning(f"Failed to collect CPU metrics: {e}")
            return {}

    async def _collect_memory_metrics(self) -> Dict[str, float]:
        """Collect memory metrics."""
        try:
            if not psutil: return {}
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()

            return {
                "total_bytes": memory.total,
                "available_bytes": memory.available,
                "used_bytes": memory.used,
                "usage_percent": memory.percent,
                "swap_total_bytes": swap.total,
                "swap_used_bytes": swap.used,
                "swap_percent": swap.percent
            }

        except Exception as e:
            self.logger.warning(f"Failed to collect memory metrics: {e}")
            return {}

    async def _collect_disk_metrics(self) -> Dict[str, float]:
        """Collect disk metrics."""
        try:
            if not psutil: return {}
            metrics = {}

            # Disk usage for root partition
            disk_usage = psutil.disk_usage('/')
            metrics.update({
                "total_bytes": disk_usage.total,
                "used_bytes": disk_usage.used,
                "free_bytes": disk_usage.free,
                "usage_percent": (disk_usage.used / disk_usage.total) * 100
            })

            # Disk I/O
            disk_io = psutil.disk_io_counters()
            if disk_io:
                metrics.update({
                    "read_bytes": disk_io.read_bytes,
                    "write_bytes": disk_io.write_bytes,
                    "read_count": disk_io.read_count,
                    "write_count": disk_io.write_count
                })

            return metrics

        except Exception as e:
            self.logger.warning(f"Failed to collect disk metrics: {e}")
            return {}

    async def _collect_network_metrics(self) -> Dict[str, float]:
        """Collect network metrics."""
        try:
            if not psutil: return {}
            net_io = psutil.net_io_counters()

            if not net_io:
                return {}

            return {
                "bytes_sent": net_io.bytes_sent,
                "bytes_recv": net_io.bytes_recv,
                "packets_sent": net_io.packets_sent,
                "packets_recv": net_io.packets_recv,
                "errors_in": net_io.errin,
                "errors_out": net_io.errout,
                "drops_in": net_io.dropin,
                "drops_out": net_io.dropout
            }

        except Exception as e:
            self.logger.warning(f"Failed to collect network metrics: {e}")
            return {}

    async def _collect_process_metrics(self) -> Dict[str, float]:
        """Collect process-specific metrics."""
        try:
            if not psutil: return {}
            current_process = psutil.Process()

            memory_info = current_process.memory_info()
            cpu_percent = current_process.cpu_percent()

            return {
                "memory_rss_bytes": memory_info.rss,
                "memory_vms_bytes": memory_info.vms,
                "cpu_percent": cpu_percent,
                "num_threads": current_process.num_threads(),
                "num_fds": current_process.num_fds() if hasattr(current_process, 'num_fds') else 0
            }

        except Exception as e:
            self.logger.warning(f"Failed to collect process metrics: {e}")
            return {}

    async def _check_alerts(self):
        """Check for alert conditions."""
        if not self.config.get("enable_alerts", True):
            return

        thresholds = self.config.get("alert_thresholds", {})

        # Check CPU usage
        cpu_data = self.metrics_data.get("cpu.usage_percent")
        if cpu_data and len(cpu_data) > 0:
            current_cpu = cpu_data[-1]["value"]
            if current_cpu > thresholds.get("cpu_percent", 80):
                await self._trigger_alert("cpu_high", {
                    "metric": "cpu.usage_percent",
                    "value": current_cpu,
                    "threshold": thresholds["cpu_percent"]
                })

        # Check memory usage
        memory_data = self.metrics_data.get("memory.usage_percent")
        if memory_data and len(memory_data) > 0:
            current_memory = memory_data[-1]["value"]
            if current_memory > thresholds.get("memory_percent", 85):
                await self._trigger_alert("memory_high", {
                    "metric": "memory.usage_percent",
                    "value": current_memory,
                    "threshold": thresholds["memory_percent"]
                })

        # Check disk usage
        disk_data = self.metrics_data.get("disk.usage_percent")
        if disk_data and len(disk_data) > 0:
            current_disk = disk_data[-1]["value"]
            if current_disk > thresholds.get("disk_percent", 90):
                await self._trigger_alert("disk_high", {
                    "metric": "disk.usage_percent",
                    "value": current_disk,
                    "threshold": thresholds["disk_percent"]
                })

    async def _trigger_alert(self, alert_type: str, data: Dict[str, Any]):
        """Trigger an alert."""
        alert = {
            "type": alert_type,
            "timestamp": datetime.now(timezone.utc),
            "data": data
        }

        self.logger.warning(f"Alert triggered: {alert_type} - {data}")

        # Call registered alert callbacks
        for callback in self.alert_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(alert)
                else:
                    callback(alert)
            except Exception as e:
                self.logger.error(f"Alert callback error: {e}")

    async def _cleanup_old_metrics(self):
        """Clean up old metrics data."""
        retention_hours = self.config.get("retention_hours", 24)
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=retention_hours)

        for metric_key, data_points in self.metrics_data.items():
            while data_points and data_points[0]["timestamp"] < cutoff_time:
                data_points.popleft()

    def register_alert_callback(self, callback: Callable):
        """Register an alert callback function."""
        self.alert_callbacks.append(callback)

    def unregister_alert_callback(self, callback: Callable):
        """Unregister an alert callback function."""
        if callback in self.alert_callbacks:
            self.alert_callbacks.remove(callback)

    def get_metric(self, metric_name: str, hours: int = 1) -> List[Dict[str, Any]]:
        """Get metric data for the specified time period."""
        if metric_name not in self.metrics_data:
            return []

        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)

        return [
            point for point in self.metrics_data[metric_name]
            if point["timestamp"] >= cutoff_time
        ]

    def get_latest_metrics(self) -> Dict[str, Any]:
        """Get the latest values for all metrics."""
        latest = {}

        for metric_name, data_points in self.metrics_data.items():
            if data_points:
                latest[metric_name] = data_points[-1]["value"]

        return latest

    def get_metric_summary(self, metric_name: str, hours: int = 1) -> Dict[str, float]:
        """Get summary statistics for a metric."""
        data = self.get_metric(metric_name, hours)

        if not data:
            return {}

        values = [point["value"] for point in data]

        return {
            "min": min(values),
            "max": max(values),
            "avg": sum(values) / len(values),
            "count": len(values),
            "latest": values[-1]
        }

    async def health_check(self) -> Dict[str, Any]:
        """Perform health check."""
        try:
            collection_running = self.running and self.collection_task and not self.collection_task.done()
            latest_metrics = self.get_latest_metrics()
            data_fresh = len(latest_metrics) > 0
            cpu_ok = True
            memory_ok = True

            if "cpu.usage_percent" in latest_metrics:
                cpu_ok = latest_metrics["cpu.usage_percent"] < 95
            if "memory.usage_percent" in latest_metrics:
                memory_ok = latest_metrics["memory.usage_percent"] < 95

            overall_health = collection_running and data_fresh and cpu_ok and memory_ok

            return {
                "status": "healthy" if overall_health else "unhealthy",
                "collection_running": collection_running,
                "data_fresh": data_fresh,
                "cpu_ok": cpu_ok,
                "memory_ok": memory_ok,
                "metrics_count": len(self.metrics_data),
                "latest_metrics": latest_metrics
            }

        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }


def create_service():
    """Create metrics service instance."""
    return MetricsService()


async def initialize():
    """Initialize the metrics service."""
    service = create_service()
    if service and hasattr(service, "initialize"):
        return await service.initialize()


async def start():
    """Start the metrics service."""
    service = create_service()
    if service and hasattr(service, "start"):
        return await service.start()


async def health_check():
    """Perform health check."""
    service = create_service()
    return await service.health_check()
