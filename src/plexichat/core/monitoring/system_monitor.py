"""
PlexiChat System Monitor

System monitoring with threading and performance optimization.
"""

import asyncio
import logging
import psutil
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

try:
    from plexichat.core.database.manager import database_manager
except ImportError:
    database_manager = None

try:
    from plexichat.core.threading.thread_manager import async_thread_manager, submit_task
except ImportError:
    async_thread_manager = None
    submit_task = None

try:
    from plexichat.core.caching.cache_manager import cache_get, cache_set
except ImportError:
    cache_get = None
    cache_set = None

try:
    from plexichat.core.analytics.analytics_manager import track_event
except ImportError:
    track_event = None

try:
    from plexichat.infrastructure.performance.optimization_engine import PerformanceOptimizationEngine
    from plexichat.core.logging_advanced.performance_logger import get_performance_logger
except ImportError:
    PerformanceOptimizationEngine = None
    get_performance_logger = None

logger = logging.getLogger(__name__)
performance_logger = get_performance_logger() if get_performance_logger else None

@dataclass
class SystemMetrics:
    """System metrics data."""
    timestamp: datetime
    cpu_percent: float
    memory_percent: float
    memory_used: int
    memory_total: int
    disk_percent: float
    disk_used: int
    disk_total: int
    network_sent: int
    network_recv: int
    process_count: int
    load_average: Optional[List[float]]

@dataclass
class ApplicationMetrics:
    """Application metrics data."""
    timestamp: datetime
    active_connections: int
    active_threads: int
    queue_sizes: Dict[str, int]
    cache_hit_rate: float
    database_connections: int
    response_times: Dict[str, float]
    error_rates: Dict[str, float]

class SystemMonitor:
    """System monitor with threading support."""
    
    def __init__(self, collection_interval: int = 60):
        self.collection_interval = collection_interval
        self.db_manager = database_manager
        self.performance_logger = performance_logger
        self.async_thread_manager = async_thread_manager
        
        # Monitoring state
        self.monitoring = False
        self.last_network_stats = None
        
        # Metrics storage
        self.system_metrics_history = []
        self.app_metrics_history = []
        self.max_history_size = 1440  # 24 hours at 1-minute intervals
        
        # Alert thresholds
        self.cpu_threshold = 80.0
        self.memory_threshold = 85.0
        self.disk_threshold = 90.0
        self.response_time_threshold = 5.0
    
    async def start_monitoring(self):
        """Start system monitoring."""
        if self.monitoring:
            return
        
        self.monitoring = True
        asyncio.create_task(self._monitoring_loop())
        logger.info("System monitoring started")
    
    async def stop_monitoring(self):
        """Stop system monitoring."""
        self.monitoring = False
        logger.info("System monitoring stopped")
    
    async def _monitoring_loop(self):
        """Main monitoring loop."""
        while self.monitoring:
            try:
                # Collect metrics
                if self.async_thread_manager:
                    await self.async_thread_manager.run_in_thread(
                        self._collect_metrics_sync
                    )
                else:
                    await self._collect_metrics()
                
                # Wait for next collection
                await asyncio.sleep(self.collection_interval)
                
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                await asyncio.sleep(self.collection_interval)
    
    def _collect_metrics_sync(self):
        """Collect metrics synchronously for threading."""
        try:
            asyncio.create_task(self._collect_metrics())
        except Exception as e:
            logger.error(f"Error in sync metrics collection: {e}")
    
    async def _collect_metrics(self):
        """Collect system and application metrics."""
        try:
            start_time = time.time()
            
            # Collect system metrics
            system_metrics = await self._collect_system_metrics()
            
            # Collect application metrics
            app_metrics = await self._collect_application_metrics()
            
            # Store metrics
            await self._store_metrics(system_metrics, app_metrics)
            
            # Check alerts
            await self._check_alerts(system_metrics, app_metrics)
            
            # Performance tracking
            if self.performance_logger:
                duration = time.time() - start_time
                self.performance_logger.record_metric("monitoring_collection_duration", duration, "seconds")
                self.performance_logger.record_metric("monitoring_collections", 1, "count")
            
        except Exception as e:
            logger.error(f"Error collecting metrics: {e}")
    
    async def _collect_system_metrics(self) -> SystemMetrics:
        """Collect system metrics."""
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Memory metrics
            memory = psutil.virtual_memory()
            
            # Disk metrics
            disk = psutil.disk_usage('/')
            
            # Network metrics
            network = psutil.net_io_counters()
            network_sent = network.bytes_sent
            network_recv = network.bytes_recv
            
            # Process count
            process_count = len(psutil.pids())
            
            # Load average (Unix only)
            load_average = None
            try:
                load_average = list(psutil.getloadavg())
            except AttributeError:
                pass  # Windows doesn't have load average
            
            return SystemMetrics(
                timestamp=datetime.now(),
                cpu_percent=cpu_percent,
                memory_percent=memory.percent,
                memory_used=memory.used,
                memory_total=memory.total,
                disk_percent=disk.percent,
                disk_used=disk.used,
                disk_total=disk.total,
                network_sent=network_sent,
                network_recv=network_recv,
                process_count=process_count,
                load_average=load_average
            )
            
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
            return SystemMetrics(
                timestamp=datetime.now(),
                cpu_percent=0.0,
                memory_percent=0.0,
                memory_used=0,
                memory_total=0,
                disk_percent=0.0,
                disk_used=0,
                disk_total=0,
                network_sent=0,
                network_recv=0,
                process_count=0,
                load_average=None
            )
    
    async def _collect_application_metrics(self) -> ApplicationMetrics:
        """Collect application metrics."""
        try:
            # Get metrics from various components
            active_connections = 0
            active_threads = 0
            queue_sizes = {}
            cache_hit_rate = 0.0
            database_connections = 0
            response_times = {}
            error_rates = {}
            
            # Thread manager metrics
            try:
                from plexichat.core.threading.thread_manager import thread_manager
                if thread_manager:
                    thread_status = thread_manager.get_status()
                    active_threads = thread_status.get("active_tasks", 0)
                    queue_sizes["thread_manager"] = thread_status.get("queue_size", 0)
            except ImportError:
                pass
            
            # WebSocket metrics
            try:
                from plexichat.core.websocket.websocket_manager import websocket_manager
                if websocket_manager:
                    ws_stats = websocket_manager.get_stats()
                    active_connections = ws_stats.get("active_connections", 0)
                    queue_sizes["websocket"] = ws_stats.get("queue_size", 0)
            except ImportError:
                pass
            
            # Cache metrics
            try:
                from plexichat.core.caching.cache_manager import cache_manager
                if cache_manager:
                    cache_stats = cache_manager.get_stats()
                    total_requests = cache_stats.get("hits", 0) + cache_stats.get("misses", 0)
                    if total_requests > 0:
                        cache_hit_rate = cache_stats.get("hits", 0) / total_requests
            except ImportError:
                pass
            
            # Database metrics
            try:
                if self.db_manager:
                    db_stats = self.db_manager.get_stats()
                    database_connections = db_stats.get("connection_pool_size", 0)
                    response_times["database"] = db_stats.get("average_execution_time", 0.0)
            except Exception:
                pass
            
            # Message processor metrics
            try:
                from plexichat.core.messaging.message_processor import message_processor
                if message_processor:
                    processor_stats = message_processor.get_status()
                    queue_sizes["message_processor"] = processor_stats.get("queue_size", 0)
            except ImportError:
                pass
            
            return ApplicationMetrics(
                timestamp=datetime.now(),
                active_connections=active_connections,
                active_threads=active_threads,
                queue_sizes=queue_sizes,
                cache_hit_rate=cache_hit_rate,
                database_connections=database_connections,
                response_times=response_times,
                error_rates=error_rates
            )
            
        except Exception as e:
            logger.error(f"Error collecting application metrics: {e}")
            return ApplicationMetrics(
                timestamp=datetime.now(),
                active_connections=0,
                active_threads=0,
                queue_sizes={},
                cache_hit_rate=0.0,
                database_connections=0,
                response_times={},
                error_rates={}
            )
    
    async def _store_metrics(self, system_metrics: SystemMetrics, app_metrics: ApplicationMetrics):
        """Store metrics in database and memory."""
        try:
            # Store in memory
            self.system_metrics_history.append(system_metrics)
            self.app_metrics_history.append(app_metrics)
            
            # Limit history size
            if len(self.system_metrics_history) > self.max_history_size:
                self.system_metrics_history.pop(0)
            if len(self.app_metrics_history) > self.max_history_size:
                self.app_metrics_history.pop(0)
            
            # Store in database
            if self.db_manager:
                # Store system metrics
                system_query = """
                    INSERT INTO system_metrics (
                        timestamp, cpu_percent, memory_percent, memory_used,
                        memory_total, disk_percent, disk_used, disk_total,
                        network_sent, network_recv, process_count, load_average
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """
                system_params = {
                    "timestamp": system_metrics.timestamp,
                    "cpu_percent": system_metrics.cpu_percent,
                    "memory_percent": system_metrics.memory_percent,
                    "memory_used": system_metrics.memory_used,
                    "memory_total": system_metrics.memory_total,
                    "disk_percent": system_metrics.disk_percent,
                    "disk_used": system_metrics.disk_used,
                    "disk_total": system_metrics.disk_total,
                    "network_sent": system_metrics.network_sent,
                    "network_recv": system_metrics.network_recv,
                    "process_count": system_metrics.process_count,
                    "load_average": str(system_metrics.load_average) if system_metrics.load_average else None
                }
                await self.db_manager.execute_query(system_query, system_params)
                
                # Store application metrics
                app_query = """
                    INSERT INTO application_metrics (
                        timestamp, active_connections, active_threads,
                        queue_sizes, cache_hit_rate, database_connections,
                        response_times, error_rates
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """
                app_params = {
                    "timestamp": app_metrics.timestamp,
                    "active_connections": app_metrics.active_connections,
                    "active_threads": app_metrics.active_threads,
                    "queue_sizes": str(app_metrics.queue_sizes),
                    "cache_hit_rate": app_metrics.cache_hit_rate,
                    "database_connections": app_metrics.database_connections,
                    "response_times": str(app_metrics.response_times),
                    "error_rates": str(app_metrics.error_rates)
                }
                await self.db_manager.execute_query(app_query, app_params)
            
            # Cache latest metrics
            if cache_set:
                cache_set("latest_system_metrics", system_metrics.__dict__, ttl=300)
                cache_set("latest_app_metrics", app_metrics.__dict__, ttl=300)
            
        except Exception as e:
            logger.error(f"Error storing metrics: {e}")
    
    async def _check_alerts(self, system_metrics: SystemMetrics, app_metrics: ApplicationMetrics):
        """Check for alert conditions."""
        try:
            alerts = []
            
            # CPU alert
            if system_metrics.cpu_percent > self.cpu_threshold:
                alerts.append({
                    "type": "cpu_high",
                    "message": f"High CPU usage: {system_metrics.cpu_percent:.1f}%",
                    "severity": "warning" if system_metrics.cpu_percent < 95 else "critical"
                })
            
            # Memory alert
            if system_metrics.memory_percent > self.memory_threshold:
                alerts.append({
                    "type": "memory_high",
                    "message": f"High memory usage: {system_metrics.memory_percent:.1f}%",
                    "severity": "warning" if system_metrics.memory_percent < 95 else "critical"
                })
            
            # Disk alert
            if system_metrics.disk_percent > self.disk_threshold:
                alerts.append({
                    "type": "disk_high",
                    "message": f"High disk usage: {system_metrics.disk_percent:.1f}%",
                    "severity": "warning" if system_metrics.disk_percent < 98 else "critical"
                })
            
            # Response time alerts
            for component, response_time in app_metrics.response_times.items():
                if response_time > self.response_time_threshold:
                    alerts.append({
                        "type": "response_time_high",
                        "message": f"High response time for {component}: {response_time:.2f}s",
                        "severity": "warning"
                    })
            
            # Process alerts if any
            if alerts:
                await self._process_alerts(alerts)
            
        except Exception as e:
            logger.error(f"Error checking alerts: {e}")
    
    async def _process_alerts(self, alerts: List[Dict[str, Any]]):
        """Process alerts."""
        try:
            for alert in alerts:
                logger.warning(f"ALERT: {alert['message']}")
                
                # Track alert in analytics
                if track_event:
                    await track_event(
                        "system_alert",
                        properties={
                            "alert_type": alert["type"],
                            "severity": alert["severity"],
                            "message": alert["message"]
                        }
                    )
                
                # Send notification (if notification system is available)
                try:
                    from plexichat.core.notifications.notification_manager import send_notification
                    await send_notification(
                        1,  # Admin user ID
                        "system",
                        f"System Alert: {alert['type']}",
                        alert["message"],
                        priority=alert["severity"]
                    )
                except ImportError:
                    pass
                
        except Exception as e:
            logger.error(f"Error processing alerts: {e}")
    
    def get_latest_metrics(self) -> Dict[str, Any]:
        """Get latest metrics."""
        try:
            # Check cache first
            if cache_get:
                system_metrics = cache_get("latest_system_metrics")
                app_metrics = cache_get("latest_app_metrics")
                
                if system_metrics and app_metrics:
                    return {
                        "system": system_metrics,
                        "application": app_metrics,
                        "timestamp": datetime.now().isoformat()
                    }
            
            # Get from memory
            if self.system_metrics_history and self.app_metrics_history:
                return {
                    "system": self.system_metrics_history[-1].__dict__,
                    "application": self.app_metrics_history[-1].__dict__,
                    "timestamp": datetime.now().isoformat()
                }
            
            return {}
            
        except Exception as e:
            logger.error(f"Error getting latest metrics: {e}")
            return {}
    
    def get_metrics_history(self, hours: int = 24) -> Dict[str, Any]:
        """Get metrics history."""
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            
            # Filter history
            system_history = [
                m.__dict__ for m in self.system_metrics_history
                if m.timestamp >= cutoff_time
            ]
            
            app_history = [
                m.__dict__ for m in self.app_metrics_history
                if m.timestamp >= cutoff_time
            ]
            
            return {
                "system": system_history,
                "application": app_history,
                "period_hours": hours,
                "data_points": len(system_history)
            }
            
        except Exception as e:
            logger.error(f"Error getting metrics history: {e}")
            return {}
    
    def get_stats(self) -> Dict[str, Any]:
        """Get monitoring statistics."""
        return {
            "monitoring": self.monitoring,
            "collection_interval": self.collection_interval,
            "history_size": len(self.system_metrics_history),
            "max_history_size": self.max_history_size,
            "thresholds": {
                "cpu": self.cpu_threshold,
                "memory": self.memory_threshold,
                "disk": self.disk_threshold,
                "response_time": self.response_time_threshold
            }
        }

# Global system monitor
system_monitor = SystemMonitor()

# Convenience functions
async def start_monitoring():
    """Start system monitoring."""
    await system_monitor.start_monitoring()

async def stop_monitoring():
    """Stop system monitoring."""
    await system_monitor.stop_monitoring()

def get_system_metrics() -> Dict[str, Any]:
    """Get latest system metrics."""
    return system_monitor.get_latest_metrics()

def get_metrics_history(hours: int = 24) -> Dict[str, Any]:
    """Get metrics history."""
    return system_monitor.get_metrics_history(hours)
