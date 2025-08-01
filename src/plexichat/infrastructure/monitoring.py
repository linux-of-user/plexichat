"""
PlexiChat Infrastructure Monitoring
Comprehensive monitoring utilities for system health, performance, and errors.
"""

import asyncio
import logging
import psutil
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class AlertLevel(Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class SystemMetrics:
    """System performance metrics."""
    cpu_percent: float
    memory_percent: float
    disk_percent: float
    network_io: Dict[str, int]
    process_count: int
    timestamp: datetime


@dataclass
class Alert:
    """System alert."""
    level: AlertLevel
    message: str
    component: str
    timestamp: datetime
    details: Dict[str, Any]


class SystemMonitor:
    """System performance and health monitor."""
    
    def __init__(self, alert_thresholds: Dict[str, float] = None):
        self.alert_thresholds = alert_thresholds or {
            "cpu_percent": 80.0,
            "memory_percent": 85.0,
            "disk_percent": 90.0
        }
        self.metrics_history: deque = deque(maxlen=1000)
        self.alerts: deque = deque(maxlen=500)
        self.alert_callbacks: List[Callable] = []
    
    def get_system_metrics(self) -> SystemMetrics:
        """Get current system metrics."""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            # Disk usage
            disk = psutil.disk_usage('/')
            disk_percent = (disk.used / disk.total) * 100
            
            # Network I/O
            network = psutil.net_io_counters()
            network_io = {
                "bytes_sent": network.bytes_sent,
                "bytes_recv": network.bytes_recv,
                "packets_sent": network.packets_sent,
                "packets_recv": network.packets_recv
            }
            
            # Process count
            process_count = len(psutil.pids())
            
            metrics = SystemMetrics(
                cpu_percent=cpu_percent,
                memory_percent=memory_percent,
                disk_percent=disk_percent,
                network_io=network_io,
                process_count=process_count,
                timestamp=datetime.now()
            )
            
            # Store in history
            self.metrics_history.append(metrics)
            
            # Check for alerts
            self._check_alerts(metrics)
            
            return metrics
            
        except Exception as e:
            logger.error(f"Failed to get system metrics: {e}")
            return SystemMetrics(0, 0, 0, {}, 0, datetime.now())
    
    def _check_alerts(self, metrics: SystemMetrics):
        """Check metrics against thresholds and generate alerts."""
        alerts_to_send = []
        
        # CPU alert
        if metrics.cpu_percent > self.alert_thresholds["cpu_percent"]:
            alert = Alert(
                level=AlertLevel.WARNING if metrics.cpu_percent < 95 else AlertLevel.CRITICAL,
                message=f"High CPU usage: {metrics.cpu_percent:.1f}%",
                component="system",
                timestamp=metrics.timestamp,
                details={"cpu_percent": metrics.cpu_percent}
            )
            alerts_to_send.append(alert)
        
        # Memory alert
        if metrics.memory_percent > self.alert_thresholds["memory_percent"]:
            alert = Alert(
                level=AlertLevel.WARNING if metrics.memory_percent < 95 else AlertLevel.CRITICAL,
                message=f"High memory usage: {metrics.memory_percent:.1f}%",
                component="system",
                timestamp=metrics.timestamp,
                details={"memory_percent": metrics.memory_percent}
            )
            alerts_to_send.append(alert)
        
        # Disk alert
        if metrics.disk_percent > self.alert_thresholds["disk_percent"]:
            alert = Alert(
                level=AlertLevel.WARNING if metrics.disk_percent < 98 else AlertLevel.CRITICAL,
                message=f"High disk usage: {metrics.disk_percent:.1f}%",
                component="system",
                timestamp=metrics.timestamp,
                details={"disk_percent": metrics.disk_percent}
            )
            alerts_to_send.append(alert)
        
        # Send alerts
        for alert in alerts_to_send:
            self._send_alert(alert)
    
    def _send_alert(self, alert: Alert):
        """Send alert to registered callbacks."""
        self.alerts.append(alert)
        logger.warning(f"ALERT [{alert.level.value.upper()}] {alert.component}: {alert.message}")
        
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Alert callback failed: {e}")
    
    def add_alert_callback(self, callback: Callable[[Alert], None]):
        """Add alert callback."""
        self.alert_callbacks.append(callback)
    
    def get_recent_alerts(self, hours: int = 24) -> List[Alert]:
        """Get recent alerts."""
        cutoff = datetime.now() - timedelta(hours=hours)
        return [alert for alert in self.alerts if alert.timestamp > cutoff]
    
    def get_metrics_summary(self, hours: int = 1) -> Dict[str, Any]:
        """Get metrics summary for the specified time period."""
        cutoff = datetime.now() - timedelta(hours=hours)
        recent_metrics = [m for m in self.metrics_history if m.timestamp > cutoff]
        
        if not recent_metrics:
            return {"error": "No metrics available"}
        
        return {
            "period_hours": hours,
            "sample_count": len(recent_metrics),
            "cpu": {
                "avg": sum(m.cpu_percent for m in recent_metrics) / len(recent_metrics),
                "max": max(m.cpu_percent for m in recent_metrics),
                "min": min(m.cpu_percent for m in recent_metrics)
            },
            "memory": {
                "avg": sum(m.memory_percent for m in recent_metrics) / len(recent_metrics),
                "max": max(m.memory_percent for m in recent_metrics),
                "min": min(m.memory_percent for m in recent_metrics)
            },
            "disk": {
                "avg": sum(m.disk_percent for m in recent_metrics) / len(recent_metrics),
                "max": max(m.disk_percent for m in recent_metrics),
                "min": min(m.disk_percent for m in recent_metrics)
            }
        }


class ErrorMonitor:
    """Error tracking and monitoring."""
    
    def __init__(self, max_errors: int = 1000):
        self.max_errors = max_errors
        self.errors: deque = deque(maxlen=max_errors)
        self.error_counts: defaultdict = defaultdict(int)
        self.error_rate_window = 300  # 5 minutes
    
    def record_error(self, error: Exception, context: Dict[str, Any] = None):
        """Record an error occurrence."""
        error_info = {
            "type": type(error).__name__,
            "message": str(error),
            "timestamp": datetime.now(),
            "context": context or {}
        }
        
        self.errors.append(error_info)
        self.error_counts[error_info["type"]] += 1
        
        logger.error(f"Error recorded: {error_info['type']} - {error_info['message']}")
    
    def get_error_rate(self, window_minutes: int = 5) -> float:
        """Get error rate per minute for the specified window."""
        cutoff = datetime.now() - timedelta(minutes=window_minutes)
        recent_errors = [e for e in self.errors if e["timestamp"] > cutoff]
        return len(recent_errors) / window_minutes
    
    def get_top_errors(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get most frequent error types."""
        sorted_errors = sorted(self.error_counts.items(), key=lambda x: x[1], reverse=True)
        return [{"type": error_type, "count": count} for error_type, count in sorted_errors[:limit]]
    
    def get_recent_errors(self, hours: int = 1) -> List[Dict[str, Any]]:
        """Get recent errors."""
        cutoff = datetime.now() - timedelta(hours=hours)
        return [e for e in self.errors if e["timestamp"] > cutoff]


class HealthChecker:
    """Application health checker."""
    
    def __init__(self):
        self.health_checks: Dict[str, Callable] = {}
        self.last_results: Dict[str, Dict[str, Any]] = {}
    
    def register_check(self, name: str, check_func: Callable[[], bool], 
                      description: str = ""):
        """Register a health check."""
        self.health_checks[name] = {
            "func": check_func,
            "description": description
        }
    
    async def run_all_checks(self) -> Dict[str, Any]:
        """Run all health checks."""
        results = {
            "overall_status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "checks": {}
        }
        
        failed_checks = 0
        
        for name, check_info in self.health_checks.items():
            try:
                start_time = time.time()
                
                if asyncio.iscoroutinefunction(check_info["func"]):
                    status = await check_info["func"]()
                else:
                    status = check_info["func"]()
                
                duration = time.time() - start_time
                
                check_result = {
                    "status": "pass" if status else "fail",
                    "duration_ms": duration * 1000,
                    "description": check_info["description"]
                }
                
                if not status:
                    failed_checks += 1
                
            except Exception as e:
                check_result = {
                    "status": "error",
                    "error": str(e),
                    "description": check_info["description"]
                }
                failed_checks += 1
            
            results["checks"][name] = check_result
        
        # Determine overall status
        if failed_checks == 0:
            results["overall_status"] = "healthy"
        elif failed_checks < len(self.health_checks) / 2:
            results["overall_status"] = "degraded"
        else:
            results["overall_status"] = "unhealthy"
        
        self.last_results = results
        return results
    
    def get_last_results(self) -> Dict[str, Any]:
        """Get last health check results."""
        return self.last_results


# Global monitoring instances
system_monitor = SystemMonitor()
error_monitor = ErrorMonitor()
health_checker = HealthChecker()

__all__ = [
    "AlertLevel", "SystemMetrics", "Alert", "SystemMonitor", "ErrorMonitor", "HealthChecker",
    "system_monitor", "error_monitor", "health_checker"
]
