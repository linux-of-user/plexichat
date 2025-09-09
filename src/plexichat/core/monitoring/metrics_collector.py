"""
Real-time Metrics Collection Service

Collects system performance metrics at regular intervals and stores them.
"""

import asyncio
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import psutil

from plexichat.core.database.manager import database_manager
from plexichat.core.monitoring.unified_monitoring_system import record_metric

logger = logging.getLogger(__name__)


@dataclass
class CollectionConfig:
    """Configuration for metrics collection."""

    interval_seconds: int = 60
    enabled: bool = True
    cpu_enabled: bool = True
    memory_enabled: bool = True
    disk_enabled: bool = True
    network_enabled: bool = True
    process_enabled: bool = True


class MetricsCollector:
    """Real-time metrics collection service."""

    def __init__(self, config: Optional[CollectionConfig] = None):
        self.config = config or CollectionConfig()
        self.running = False
        self.task: Optional[asyncio.Task] = None
        self.last_collection = datetime.now()

        logger.info("Metrics collector initialized")

    async def start(self):
        """Start the metrics collection service."""
        if self.running:
            logger.warning("Metrics collector is already running")
            return

        self.running = True
        self.task = asyncio.create_task(self._collection_loop())
        logger.info("Metrics collector started")

    async def stop(self):
        """Stop the metrics collection service."""
        if not self.running:
            return

        self.running = False
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass

        logger.info("Metrics collector stopped")

    async def _collection_loop(self):
        """Main collection loop."""
        while self.running:
            try:
                await self._collect_metrics()
                self.last_collection = datetime.now()
            except Exception as e:
                logger.error(f"Error in metrics collection: {e}")

            await asyncio.sleep(self.config.interval_seconds)

    async def _collect_metrics(self):
        """Collect all enabled metrics."""
        timestamp = datetime.now()

        # CPU metrics
        if self.config.cpu_enabled:
            await self._collect_cpu_metrics(timestamp)

        # Memory metrics
        if self.config.memory_enabled:
            await self._collect_memory_metrics(timestamp)

        # Disk metrics
        if self.config.disk_enabled:
            await self._collect_disk_metrics(timestamp)

        # Network metrics
        if self.config.network_enabled:
            await self._collect_network_metrics(timestamp)

        # Process metrics
        if self.config.process_enabled:
            await self._collect_process_metrics(timestamp)

    async def _collect_cpu_metrics(self, timestamp: datetime):
        """Collect CPU usage metrics."""
        try:
            # Overall CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            record_metric(
                "cpu_usage_percent", cpu_percent, "percent", {"type": "overall"}
            )

            # Per-core CPU usage
            cpu_per_core = psutil.cpu_percent(interval=1, percpu=True)
            for i, core_percent in enumerate(cpu_per_core):
                record_metric(
                    f"cpu_core_{i}_usage_percent",
                    core_percent,
                    "percent",
                    {"core": str(i)},
                )

            # CPU frequency
            cpu_freq = psutil.cpu_freq()
            if cpu_freq:
                record_metric(
                    "cpu_frequency_mhz", cpu_freq.current, "MHz", {"type": "current"}
                )
                record_metric(
                    "cpu_frequency_min_mhz", cpu_freq.min, "MHz", {"type": "min"}
                )
                record_metric(
                    "cpu_frequency_max_mhz", cpu_freq.max, "MHz", {"type": "max"}
                )

            # CPU times
            cpu_times = psutil.cpu_times()
            record_metric("cpu_time_user", cpu_times.user, "seconds", {"type": "user"})
            record_metric(
                "cpu_time_system", cpu_times.system, "seconds", {"type": "system"}
            )
            record_metric("cpu_time_idle", cpu_times.idle, "seconds", {"type": "idle"})

        except Exception as e:
            logger.error(f"Failed to collect CPU metrics: {e}")

    async def _collect_memory_metrics(self, timestamp: datetime):
        """Collect memory usage metrics."""
        try:
            memory = psutil.virtual_memory()

            record_metric(
                "memory_total_bytes", memory.total, "bytes", {"type": "total"}
            )
            record_metric(
                "memory_available_bytes",
                memory.available,
                "bytes",
                {"type": "available"},
            )
            record_metric("memory_used_bytes", memory.used, "bytes", {"type": "used"})
            record_metric(
                "memory_percent", memory.percent, "percent", {"type": "usage"}
            )
            record_metric("memory_free_bytes", memory.free, "bytes", {"type": "free"})

            # Swap memory
            swap = psutil.swap_memory()
            record_metric("swap_total_bytes", swap.total, "bytes", {"type": "total"})
            record_metric("swap_used_bytes", swap.used, "bytes", {"type": "used"})
            record_metric("swap_free_bytes", swap.free, "bytes", {"type": "free"})
            record_metric("swap_percent", swap.percent, "percent", {"type": "usage"})

        except Exception as e:
            logger.error(f"Failed to collect memory metrics: {e}")

    async def _collect_disk_metrics(self, timestamp: datetime):
        """Collect disk usage metrics."""
        try:
            # Overall disk usage
            disk = psutil.disk_usage("/")
            record_metric("disk_total_bytes", disk.total, "bytes", {"mount": "/"})
            record_metric("disk_used_bytes", disk.used, "bytes", {"mount": "/"})
            record_metric("disk_free_bytes", disk.free, "bytes", {"mount": "/"})
            record_metric("disk_percent", disk.percent, "percent", {"mount": "/"})

            # Disk I/O
            disk_io = psutil.disk_io_counters()
            if disk_io:
                record_metric(
                    "disk_read_bytes", disk_io.read_bytes, "bytes", {"type": "read"}
                )
                record_metric(
                    "disk_write_bytes", disk_io.write_bytes, "bytes", {"type": "write"}
                )
                record_metric(
                    "disk_read_count", disk_io.read_count, "count", {"type": "read"}
                )
                record_metric(
                    "disk_write_count", disk_io.write_count, "count", {"type": "write"}
                )

        except Exception as e:
            logger.error(f"Failed to collect disk metrics: {e}")

    async def _collect_network_metrics(self, timestamp: datetime):
        """Collect network usage metrics."""
        try:
            network = psutil.net_io_counters()
            if network:
                record_metric(
                    "network_bytes_sent",
                    network.bytes_sent,
                    "bytes",
                    {"direction": "sent"},
                )
                record_metric(
                    "network_bytes_recv",
                    network.bytes_recv,
                    "bytes",
                    {"direction": "received"},
                )
                record_metric(
                    "network_packets_sent",
                    network.packets_sent,
                    "count",
                    {"direction": "sent"},
                )
                record_metric(
                    "network_packets_recv",
                    network.packets_recv,
                    "count",
                    {"direction": "received"},
                )
                record_metric(
                    "network_errin", network.errin, "count", {"type": "errors_in"}
                )
                record_metric(
                    "network_errout", network.errout, "count", {"type": "errors_out"}
                )
                record_metric(
                    "network_dropin", network.dropin, "count", {"type": "drops_in"}
                )
                record_metric(
                    "network_dropout", network.dropout, "count", {"type": "drops_out"}
                )

        except Exception as e:
            logger.error(f"Failed to collect network metrics: {e}")

    async def _collect_process_metrics(self, timestamp: datetime):
        """Collect process-related metrics."""
        try:
            # Process count
            process_count = len(psutil.pids())
            record_metric("process_count", process_count, "count", {"type": "total"})

            # System load (if available)
            try:
                load_avg = psutil.getloadavg()
                record_metric("system_load_1m", load_avg[0], "load", {"period": "1m"})
                record_metric("system_load_5m", load_avg[1], "load", {"period": "5m"})
                record_metric("system_load_15m", load_avg[2], "load", {"period": "15m"})
            except AttributeError:
                # getloadavg not available on Windows
                pass

        except Exception as e:
            logger.error(f"Failed to collect process metrics: {e}")

    def get_status(self) -> Dict[str, Any]:
        """Get collector status."""
        return {
            "running": self.running,
            "last_collection": (
                self.last_collection.isoformat() if self.last_collection else None
            ),
            "interval_seconds": self.config.interval_seconds,
            "enabled_metrics": {
                "cpu": self.config.cpu_enabled,
                "memory": self.config.memory_enabled,
                "disk": self.config.disk_enabled,
                "network": self.config.network_enabled,
                "process": self.config.process_enabled,
            },
        }


# Global instance
metrics_collector = MetricsCollector()


async def start_metrics_collection(interval_seconds: int = 60):
    """Start the metrics collection service."""
    global metrics_collector
    metrics_collector.config.interval_seconds = interval_seconds
    await metrics_collector.start()


async def stop_metrics_collection():
    """Stop the metrics collection service."""
    global metrics_collector
    await metrics_collector.stop()


def get_metrics_collector_status() -> Dict[str, Any]:
    """Get the status of the metrics collector."""
    return metrics_collector.get_status()


__all__ = [
    "MetricsCollector",
    "CollectionConfig",
    "metrics_collector",
    "start_metrics_collection",
    "stop_metrics_collection",
    "get_metrics_collector_status",
]
