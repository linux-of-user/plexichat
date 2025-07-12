"""
PlexiChat Canary Health Monitor

Real-time health monitoring for canary deployments with:
- Continuous health checks during rollouts
- Anomaly detection and alerting
- Performance regression detection
- Automatic rollback triggers
- Custom metric collection
"""

import asyncio
import aiohttp
import json
from enum import Enum
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
import logging
import statistics

from .canary_deployment_manager import CanaryNode, HealthCheck, HealthCheckType

logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class MetricTrend(Enum):
    """Metric trend directions."""
    IMPROVING = "improving"
    STABLE = "stable"
    DEGRADING = "degrading"
    CRITICAL = "critical"


@dataclass
class HealthAlert:
    """Health monitoring alert."""
    alert_id: str
    node_id: str
    severity: AlertSeverity
    message: str
    metric_name: str
    current_value: float
    threshold: float
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    acknowledged: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary."""
        return {
            "alert_id": self.alert_id,
            "node_id": self.node_id,
            "severity": self.severity.value,
            "message": self.message,
            "metric_name": self.metric_name,
            "current_value": self.current_value,
            "threshold": self.threshold,
            "timestamp": self.timestamp.isoformat(),
            "acknowledged": self.acknowledged
        }


@dataclass
class MetricHistory:
    """Historical metric data for trend analysis."""
    metric_name: str
    values: List[float] = field(default_factory=list)
    timestamps: List[datetime] = field(default_factory=list)
    max_history_size: int = 100
    
    def add_value(self, value: float, timestamp: Optional[datetime] = None):
        """Add new metric value."""
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)
        
        self.values.append(value)
        self.timestamps.append(timestamp)
        
        # Maintain history size limit
        if len(self.values) > self.max_history_size:
            self.values.pop(0)
            self.timestamps.pop(0)
    
    def get_trend(self, window_size: int = 10) -> MetricTrend:
        """Analyze metric trend."""
        if len(self.values) < window_size:
            return MetricTrend.STABLE
        
        recent_values = self.values[-window_size:]
        
        # Calculate trend using linear regression slope
        x_values = list(range(len(recent_values)))
        n = len(recent_values)
        
        sum_x = sum(x_values)
        sum_y = sum(recent_values)
        sum_xy = sum(x * y for x, y in zip(x_values, recent_values))
        sum_x2 = sum(x * x for x in x_values)
        
        slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x)
        
        # Determine trend based on slope
        if slope > 0.1:
            return MetricTrend.DEGRADING if self.metric_name in ["error_rate", "response_time"] else MetricTrend.IMPROVING
        elif slope < -0.1:
            return MetricTrend.IMPROVING if self.metric_name in ["error_rate", "response_time"] else MetricTrend.DEGRADING
        else:
            return MetricTrend.STABLE
    
    def get_average(self, window_size: int = 10) -> float:
        """Get average value over window."""
        if not self.values:
            return 0.0
        
        recent_values = self.values[-window_size:]
        return statistics.mean(recent_values)
    
    def detect_anomaly(self, current_value: float, sensitivity: float = 2.0) -> bool:
        """Detect if current value is anomalous."""
        if len(self.values) < 10:
            return False
        
        mean = statistics.mean(self.values)
        stdev = statistics.stdev(self.values)
        
        # Z-score based anomaly detection
        z_score = abs(current_value - mean) / stdev if stdev > 0 else 0
        return z_score > sensitivity


class CanaryHealthMonitor:
    """Monitors health of canary deployments in real-time."""
    
    def __init__(self):
        self.monitoring_tasks: Dict[str, asyncio.Task] = {}
        self.metric_history: Dict[str, Dict[str, MetricHistory]] = {}  # node_id -> metric_name -> history
        self.active_alerts: Dict[str, HealthAlert] = {}
        self.alert_callbacks: List[Callable[[HealthAlert], None]] = []
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Monitoring configuration
        self.check_interval_seconds = 30
        self.anomaly_sensitivity = 2.0
        self.alert_cooldown_minutes = 5
        self.last_alert_times: Dict[str, datetime] = {}
    
    async def initialize(self):
        """Initialize health monitor."""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30)
        )
        logger.info("Canary health monitor initialized")
    
    async def start_monitoring(self, nodes: List[CanaryNode], 
                             health_checks: List[HealthCheck],
                             duration_minutes: int = 30) -> str:
        """Start monitoring canary nodes."""
        monitoring_id = f"monitor_{int(datetime.now().timestamp())}"
        
        # Create monitoring task
        task = asyncio.create_task(
            self._monitor_nodes(monitoring_id, nodes, health_checks, duration_minutes)
        )
        
        self.monitoring_tasks[monitoring_id] = task
        logger.info(f"Started monitoring {len(nodes)} nodes for {duration_minutes} minutes")
        
        return monitoring_id
    
    async def stop_monitoring(self, monitoring_id: str):
        """Stop monitoring task."""
        if monitoring_id in self.monitoring_tasks:
            task = self.monitoring_tasks[monitoring_id]
            task.cancel()
            
            try:
                await task
            except asyncio.CancelledError:
                pass
            
            del self.monitoring_tasks[monitoring_id]
            logger.info(f"Stopped monitoring: {monitoring_id}")
    
    async def _monitor_nodes(self, monitoring_id: str, nodes: List[CanaryNode],
                           health_checks: List[HealthCheck], duration_minutes: int):
        """Monitor nodes for specified duration."""
        end_time = datetime.now(timezone.utc) + timedelta(minutes=duration_minutes)
        
        try:
            while datetime.now(timezone.utc) < end_time:
                # Check health of all nodes
                for node in nodes:
                    await self._check_node_health(node, health_checks)
                
                # Wait before next check
                await asyncio.sleep(self.check_interval_seconds)
                
        except asyncio.CancelledError:
            logger.info(f"Monitoring cancelled: {monitoring_id}")
        except Exception as e:
            logger.error(f"Monitoring error: {e}")
    
    async def _check_node_health(self, node: CanaryNode, health_checks: List[HealthCheck]):
        """Check health of a single node."""
        try:
            for check in health_checks:
                metric_value = await self._execute_health_check(node, check)
                
                if metric_value is not None:
                    # Store metric history
                    self._store_metric_value(node.node_id, check.metric_name or check.check_type.value, metric_value)
                    
                    # Check for threshold violations
                    if not check.evaluate(metric_value):
                        await self._handle_threshold_violation(node, check, metric_value)
                    
                    # Check for anomalies
                    if self._is_anomalous_value(node.node_id, check.metric_name or check.check_type.value, metric_value):
                        await self._handle_anomaly(node, check, metric_value)
                        
        except Exception as e:
            logger.error(f"Health check failed for node {node.node_id}: {e}")
    
    async def _execute_health_check(self, node: CanaryNode, check: HealthCheck) -> Optional[float]:
        """Execute individual health check."""
        try:
            if check.check_type == HealthCheckType.HTTP_ENDPOINT:
                return await self._check_http_endpoint(node, check)
            elif check.check_type == HealthCheckType.PERFORMANCE_METRICS:
                return await self._check_performance_metrics(node, check)
            elif check.check_type == HealthCheckType.ERROR_RATE:
                return await self._check_error_rate(node, check)
            elif check.check_type == HealthCheckType.RESPONSE_TIME:
                return await self._check_response_time(node, check)
            elif check.check_type == HealthCheckType.RESOURCE_USAGE:
                return await self._check_resource_usage(node, check)
            else:
                logger.warning(f"Unknown health check type: {check.check_type}")
                return None
                
        except Exception as e:
            logger.error(f"Health check execution failed: {e}")
            return None
    
    async def _check_http_endpoint(self, node: CanaryNode, check: HealthCheck) -> Optional[float]:
        """Check HTTP endpoint health."""
        if not check.endpoint:
            return None
        
        try:
            # Construct URL (this would need actual node endpoint)
            url = f"http://{node.node_id}:8000{check.endpoint}"
            
            start_time = datetime.now()
            if self.session is None or self.session.closed:
                self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30))
            async with self.session.get(url, timeout=check.timeout_seconds) as response:
                response_time = (datetime.now() - start_time).total_seconds() * 1000
                
                if check.metric_name == "response_time":
                    return response_time
                else:
                    return float(response.status)
                    
        except asyncio.TimeoutError:
            return 0.0  # Timeout = unhealthy
        except Exception as e:
            logger.debug(f"HTTP check failed for {node.node_id}: {e}")
            return 0.0
    
    async def _check_performance_metrics(self, node: CanaryNode, check: HealthCheck) -> Optional[float]:
        """Check performance metrics."""
        # Placeholder for performance metrics collection
        # This would integrate with monitoring systems like Prometheus
        return 0.5  # Simulate good performance
    
    async def _check_error_rate(self, node: CanaryNode, check: HealthCheck) -> Optional[float]:
        """Check error rate."""
        # Placeholder for error rate collection
        return 0.1  # Simulate low error rate
    
    async def _check_response_time(self, node: CanaryNode, check: HealthCheck) -> Optional[float]:
        """Check response time."""
        # Placeholder for response time collection
        return 150.0  # Simulate good response time
    
    async def _check_resource_usage(self, node: CanaryNode, check: HealthCheck) -> Optional[float]:
        """Check resource usage."""
        # Placeholder for resource usage collection
        return 0.3  # Simulate moderate resource usage
    
    def _store_metric_value(self, node_id: str, metric_name: str, value: float):
        """Store metric value in history."""
        if node_id not in self.metric_history:
            self.metric_history[node_id] = {}
        
        if metric_name not in self.metric_history[node_id]:
            self.metric_history[node_id][metric_name] = MetricHistory(metric_name)
        
        self.metric_history[node_id][metric_name].add_value(value)
    
    def _is_anomalous_value(self, node_id: str, metric_name: str, value: float) -> bool:
        """Check if value is anomalous."""
        if node_id not in self.metric_history or metric_name not in self.metric_history[node_id]:
            return False
        
        history = self.metric_history[node_id][metric_name]
        return history.detect_anomaly(value, self.anomaly_sensitivity)
    
    async def _handle_threshold_violation(self, node: CanaryNode, check: HealthCheck, value: float):
        """Handle threshold violation."""
        alert_key = f"{node.node_id}_{check.metric_name or check.check_type.value}_threshold"
        
        # Check alert cooldown
        if self._is_alert_in_cooldown(alert_key):
            return
        
        alert = HealthAlert(
            alert_id=f"alert_{int(datetime.now().timestamp())}",
            node_id=node.node_id,
            severity=AlertSeverity.WARNING,
            message=f"Threshold violation: {check.metric_name or check.check_type.value} = {value:.2f} (threshold: {check.threshold})",
            metric_name=check.metric_name or check.check_type.value,
            current_value=value,
            threshold=check.threshold
        )
        
        await self._emit_alert(alert)
        self.last_alert_times[alert_key] = datetime.now(timezone.utc)
    
    async def _handle_anomaly(self, node: CanaryNode, check: HealthCheck, value: float):
        """Handle anomalous value."""
        alert_key = f"{node.node_id}_{check.metric_name or check.check_type.value}_anomaly"
        
        # Check alert cooldown
        if self._is_alert_in_cooldown(alert_key):
            return
        
        alert = HealthAlert(
            alert_id=f"alert_{int(datetime.now().timestamp())}",
            node_id=node.node_id,
            severity=AlertSeverity.ERROR,
            message=f"Anomalous value detected: {check.metric_name or check.check_type.value} = {value:.2f}",
            metric_name=check.metric_name or check.check_type.value,
            current_value=value,
            threshold=0.0
        )
        
        await self._emit_alert(alert)
        self.last_alert_times[alert_key] = datetime.now(timezone.utc)
    
    def _is_alert_in_cooldown(self, alert_key: str) -> bool:
        """Check if alert is in cooldown period."""
        if alert_key not in self.last_alert_times:
            return False
        
        last_alert = self.last_alert_times[alert_key]
        cooldown_end = last_alert + timedelta(minutes=self.alert_cooldown_minutes)
        
        return datetime.now(timezone.utc) < cooldown_end
    
    async def _emit_alert(self, alert: HealthAlert):
        """Emit alert to registered callbacks."""
        self.active_alerts[alert.alert_id] = alert
        
        logger.warning(f"Health alert: {alert.message}")
        
        # Call registered alert callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Alert callback failed: {e}")
    
    def register_alert_callback(self, callback: Callable[[HealthAlert], None]):
        """Register alert callback."""
        self.alert_callbacks.append(callback)
    
    def get_node_metrics(self, node_id: str) -> Dict[str, Any]:
        """Get current metrics for node."""
        if node_id not in self.metric_history:
            return {}
        
        metrics = {}
        for metric_name, history in self.metric_history[node_id].items():
            if history.values:
                metrics[metric_name] = {
                    "current": history.values[-1],
                    "average": history.get_average(),
                    "trend": history.get_trend().value
                }
        
        return metrics
    
    def get_active_alerts(self, node_id: Optional[str] = None) -> List[HealthAlert]:
        """Get active alerts."""
        alerts = list(self.active_alerts.values())
        
        if node_id:
            alerts = [alert for alert in alerts if alert.node_id == node_id]
        
        return alerts
    
    async def cleanup(self):
        """Cleanup health monitor resources."""
        # Cancel all monitoring tasks
        for task in self.monitoring_tasks.values():
            task.cancel()
        
        # Wait for tasks to complete
        if self.monitoring_tasks:
            await asyncio.gather(*self.monitoring_tasks.values(), return_exceptions=True)
        
        # Close HTTP session
        if self.session:
            await self.session.close()
        
        logger.info("Canary health monitor cleaned up")
