"""
Database Performance Monitor

Advanced monitoring system for database performance, query optimization,
and resource usage tracking with real-time alerts and analytics.
"""

import asyncio
import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set
import psutil
import threading

logger = logging.getLogger(__name__)


@dataclass
class QueryMetrics:
    """Metrics for individual queries."""
    query_hash: str
    query_text: str
    execution_count: int = 0
    total_execution_time: float = 0.0
    min_execution_time: float = float('inf')
    max_execution_time: float = 0.0
    avg_execution_time: float = 0.0
    last_executed: Optional[datetime] = None
    error_count: int = 0
    rows_affected: int = 0
    cache_hits: int = 0
    cache_misses: int = 0


@dataclass
class ConnectionMetrics:
    """Connection pool metrics."""
    active_connections: int = 0
    idle_connections: int = 0
    total_connections: int = 0
    peak_connections: int = 0
    connection_errors: int = 0
    connection_timeouts: int = 0
    avg_connection_time: float = 0.0
    pool_utilization: float = 0.0


@dataclass
class ResourceMetrics:
    """System resource metrics."""
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    disk_io_read: float = 0.0
    disk_io_write: float = 0.0
    network_io_sent: float = 0.0
    network_io_recv: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)


class DatabasePerformanceMonitor:
    """Advanced database performance monitoring system."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.enabled = self.config.get('enabled', True)

        # Metrics storage
        self.query_metrics: Dict[str, QueryMetrics] = {}
        self.connection_metrics = ConnectionMetrics()
        self.resource_history: deque = deque(maxlen=1000)

        # Performance tracking
        self.slow_queries: deque = deque(maxlen=100)
        self.error_queries: deque = deque(maxlen=100)
        self.performance_alerts: List[Dict[str, Any]] = []

        # Configuration
        self.slow_query_threshold = self.config.get('slow_query_threshold_ms', 1000) / 1000.0
        self.monitoring_interval = self.config.get('monitoring_interval', 30)
        self.alert_thresholds = self.config.get('alert_thresholds', {})

        # Background tasks
        self._monitoring_task = None
        self._cleanup_task = None
        self._running = False

        logger.info("Database Performance Monitor initialized")

    async def start_monitoring(self):
        """Start background monitoring tasks."""
        if not self.enabled or self._running:
            return

        self._running = True
        self._monitoring_task = asyncio.create_task(self._monitoring_loop())
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())

        logger.info("Database performance monitoring started")

    async def stop_monitoring(self):
        """Stop background monitoring tasks."""
        self._running = False

        if self._monitoring_task:
            self._monitoring_task.cancel()
        if self._cleanup_task:
            self._cleanup_task.cancel()

        logger.info("[STOP] Database performance monitoring stopped")

    def record_query_execution(self, query: str, execution_time: float,
                             rows_affected: int = 0, error: Optional[str] = None,
                             cache_hit: bool = False):
        """Record query execution metrics."""
        if not self.enabled:
            return

        query_hash = str(hash(query.strip().lower()))

        if query_hash not in self.query_metrics:
            self.query_metrics[query_hash] = QueryMetrics(
                query_hash=query_hash,
                query_text=query[:200] + "..." if len(query) > 200 else query
            )

        metrics = self.query_metrics[query_hash]
        metrics.execution_count += 1
        metrics.total_execution_time += execution_time
        metrics.min_execution_time = min(metrics.min_execution_time, execution_time)
        metrics.max_execution_time = max(metrics.max_execution_time, execution_time)
        metrics.avg_execution_time = metrics.total_execution_time / metrics.execution_count
        metrics.last_executed = datetime.now()
        metrics.rows_affected += rows_affected

        if cache_hit:
            metrics.cache_hits += 1
        else:
            metrics.cache_misses += 1

        if error:
            metrics.error_count += 1
            self.error_queries.append({
                'query': query[:100],
                'error': error,
                'timestamp': datetime.now()
            })

        # Check for slow queries
        if execution_time > self.slow_query_threshold:
            self.slow_queries.append({
                'query': query[:100],
                'execution_time': execution_time,
                'timestamp': datetime.now()
            })

    def update_connection_metrics(self, active: int, idle: int, total: int,
                                errors: int = 0, timeouts: int = 0):
        """Update connection pool metrics."""
        if not self.enabled:
            return

        self.connection_metrics.active_connections = active
        self.connection_metrics.idle_connections = idle
        self.connection_metrics.total_connections = total
        self.connection_metrics.peak_connections = max(
            self.connection_metrics.peak_connections, total
        )
        self.connection_metrics.connection_errors += errors
        self.connection_metrics.connection_timeouts += timeouts

        if total > 0:
            self.connection_metrics.pool_utilization = active / total

    async def _monitoring_loop(self):
        """Background monitoring loop."""
        while self._running:
            try:
                # Collect system resource metrics
                await self._collect_resource_metrics()

                # Check alert thresholds
                await self._check_alerts()

                # Wait for next monitoring cycle
                await asyncio.sleep(self.monitoring_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(5)

    async def _collect_resource_metrics(self):
        """Collect system resource metrics."""
        try:
            # CPU and memory usage
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()

            # Disk I/O
            disk_io = psutil.disk_io_counters()

            # Network I/O
            network_io = psutil.net_io_counters()

            metrics = ResourceMetrics(
                cpu_usage=cpu_percent,
                memory_usage=memory.percent,
                disk_io_read=disk_io.read_bytes if disk_io else 0,
                disk_io_write=disk_io.write_bytes if disk_io else 0,
                network_io_sent=network_io.bytes_sent if network_io else 0,
                network_io_recv=network_io.bytes_recv if network_io else 0
            )

            self.resource_history.append(metrics)

        except Exception as e:
            logger.error(f"Error collecting resource metrics: {e}")

    async def _check_alerts(self):
        """Check for performance alerts."""
        if not self.alert_thresholds:
            return

        try:
            # Check resource usage alerts
            if self.resource_history:
                latest = self.resource_history[-1]

                if latest.cpu_usage > self.alert_thresholds.get('cpu_usage_percent', 80):
                    await self._trigger_alert('high_cpu_usage', {
                        'cpu_usage': latest.cpu_usage,
                        'threshold': self.alert_thresholds.get('cpu_usage_percent', 80)
                    })

                if latest.memory_usage > self.alert_thresholds.get('memory_usage_percent', 85):
                    await self._trigger_alert('high_memory_usage', {
                        'memory_usage': latest.memory_usage,
                        'threshold': self.alert_thresholds.get('memory_usage_percent', 85)
                    })

            # Check connection pool alerts
            pool_threshold = self.alert_thresholds.get('connection_pool_usage_percent', 90)
            if self.connection_metrics.pool_utilization > pool_threshold / 100:
                await self._trigger_alert('high_connection_pool_usage', {
                    'pool_utilization': self.connection_metrics.pool_utilization * 100,
                    'threshold': pool_threshold
                })

        except Exception as e:
            logger.error(f"Error checking alerts: {e}")

    async def _trigger_alert(self, alert_type: str, data: Dict[str, Any]):
        """Trigger a performance alert."""
        alert = {
            'type': alert_type,
            'data': data,
            'timestamp': datetime.now(),
            'severity': 'warning'
        }

        self.performance_alerts.append(alert)
        logger.warning(f"[ALERT] Performance Alert: {alert_type} - {data}")

    async def _cleanup_loop(self):
        """Background cleanup loop."""
        while self._running:
            try:
                # Clean up old metrics
                cutoff_time = datetime.now() - timedelta(days=7)

                # Clean up old alerts
                self.performance_alerts = [
                    alert for alert in self.performance_alerts
                    if alert['timestamp'] > cutoff_time
                ]

                # Wait for next cleanup cycle
                await asyncio.sleep(3600)  # Run every hour

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")
                await asyncio.sleep(300)

    def get_performance_summary(self) -> Dict[str, Any]:
        """Get comprehensive performance summary."""
        total_queries = sum(m.execution_count for m in self.query_metrics.values())
        total_errors = sum(m.error_count for m in self.query_metrics.values())

        return {}
            'query_metrics': {
                'total_queries': total_queries,
                'total_errors': total_errors,
                'error_rate': total_errors / total_queries if total_queries > 0 else 0,
                'slow_queries_count': len(self.slow_queries),
                'unique_queries': len(self.query_metrics)
            },
            'connection_metrics': {
                'active_connections': self.connection_metrics.active_connections,
                'total_connections': self.connection_metrics.total_connections,
                'pool_utilization': self.connection_metrics.pool_utilization,
                'connection_errors': self.connection_metrics.connection_errors
            },
            'resource_metrics': {
                'current_cpu': self.resource_history[-1].cpu_usage if self.resource_history else 0,
                'current_memory': self.resource_history[-1].memory_usage if self.resource_history else 0,
                'samples_collected': len(self.resource_history)
            },
            'alerts': {
                'total_alerts': len(self.performance_alerts),
                'recent_alerts': len([a for a in self.performance_alerts
                                    if a['timestamp'] > datetime.now() - timedelta(hours=1)])
            }
        }


# Global performance monitor instance
performance_monitor = DatabasePerformanceMonitor()
