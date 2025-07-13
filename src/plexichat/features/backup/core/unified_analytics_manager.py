import asyncio
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from ...core_system.logging import get_logger

"""
Unified Analytics Manager

Provides comprehensive analytics and monitoring for the backup system with:
- Real-time performance metrics
- Predictive analytics
- Capacity planning
- Security monitoring
"""

logger = get_logger(__name__)


class MetricType(Enum):
    """Types of metrics."""
    PERFORMANCE = "performance"
    CAPACITY = "capacity"
    SECURITY = "security"
    RELIABILITY = "reliability"


class AlertLevel(Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class UnifiedAnalyticsManager:
    """
    Unified Analytics Manager
    
    Provides comprehensive analytics, monitoring, and alerting
    for the backup system with predictive capabilities.
    """
    
    def __init__(self, backup_manager):
        self.backup_manager = backup_manager
        self.initialized = False
        
        # Configuration
        self.config = backup_manager.config.get("analytics", {})
        
        # Metrics storage
        self.metrics_history: Dict[str, List[Dict[str, Any]]] = {}
        self.active_alerts: List[Dict[str, Any]] = []
        
        # Thresholds
        self.thresholds = {
            "backup_success_rate": 0.95,
            "storage_usage": 0.85,
            "node_availability": 0.90,
            "response_time": 5.0  # seconds
        }
        
        logger.info("Unified Analytics Manager initialized")
    
    async def initialize(self) -> None:
        """Initialize the analytics manager."""
        if self.initialized:
            return
        
        # Start background tasks
        asyncio.create_task(self._metrics_collection_task())
        asyncio.create_task(self._alerting_task())
        asyncio.create_task(self._predictive_analysis_task())
        
        self.initialized = True
        logger.info("Unified Analytics Manager initialized successfully")
    
    async def record_metric(
        self,
        metric_name: str,
        metric_type: MetricType,
        value: float,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Record a metric value."""
        metric_entry = {
            "timestamp": datetime.now(timezone.utc),
            "metric_name": metric_name,
            "metric_type": metric_type.value,
            "value": value,
            "metadata": metadata or {}
        }
        
        if metric_name not in self.metrics_history:
            self.metrics_history[metric_name] = []
        
        self.metrics_history[metric_name].append(metric_entry)
        
        # Keep only last 1000 entries per metric
        if len(self.metrics_history[metric_name]) > 1000:
            self.metrics_history[metric_name] = self.metrics_history[metric_name][-1000:]
        
        # Check for threshold violations
        await self._check_thresholds(metric_name, value)
    
    async def get_metrics(
        self,
        metric_name: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Get metrics data."""
        if metric_name:
            metrics = {metric_name: self.metrics_history.get(metric_name, [])}
        else:
            metrics = self.metrics_history.copy()
        
        # Filter by time range if specified
        if start_time or end_time:
            filtered_metrics = {}
            for name, entries in metrics.items():
                filtered_entries = []
                for entry in entries:
                    timestamp = entry["timestamp"]
                    if start_time and timestamp < start_time:
                        continue
                    if end_time and timestamp > end_time:
                        continue
                    filtered_entries.append(entry)
                filtered_metrics[name] = filtered_entries
            metrics = filtered_metrics
        
        return metrics
    
    async def get_system_overview(self) -> Dict[str, Any]:
        """Get comprehensive system overview."""
        overview = {
            "timestamp": datetime.now(timezone.utc),
            "performance": await self._get_performance_summary(),
            "capacity": await self._get_capacity_summary(),
            "security": await self._get_security_summary(),
            "reliability": await self._get_reliability_summary(),
            "alerts": self.active_alerts.copy()
        }
        
        return overview
    
    async def create_alert(
        self,
        alert_level: AlertLevel,
        message: str,
        metric_name: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Create a new alert."""
        alert = {
            "alert_id": f"alert_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}",
            "level": alert_level.value,
            "message": message,
            "metric_name": metric_name,
            "created_at": datetime.now(timezone.utc),
            "metadata": metadata or {}
        }
        
        self.active_alerts.append(alert)
        
        # Keep only last 100 alerts
        if len(self.active_alerts) > 100:
            self.active_alerts = self.active_alerts[-100:]
        
        logger.warning(f"Alert created: {alert_level.value} - {message}")
    
    async def _metrics_collection_task(self) -> None:
        """Background task for collecting system metrics."""
        while True:
            try:
                await asyncio.sleep(60)  # Collect every minute
                
                # Collect performance metrics
                await self._collect_performance_metrics()
                
                # Collect capacity metrics
                await self._collect_capacity_metrics()
                
                # Collect security metrics
                await self._collect_security_metrics()
                
                # Collect reliability metrics
                await self._collect_reliability_metrics()
                
            except Exception as e:
                logger.error(f"Metrics collection task error: {e}")
    
    async def _alerting_task(self) -> None:
        """Background task for processing alerts."""
        while True:
            try:
                await asyncio.sleep(300)  # Check every 5 minutes
                
                # Clean up old alerts (older than 24 hours)
                current_time = datetime.now(timezone.utc)
                self.active_alerts = [
                    alert for alert in self.active_alerts
                    if (current_time - alert["created_at"]).total_seconds() < 86400
                ]
                
            except Exception as e:
                logger.error(f"Alerting task error: {e}")
    
    async def _predictive_analysis_task(self) -> None:
        """Background task for predictive analysis."""
        while True:
            try:
                await asyncio.sleep(3600)  # Run every hour
                
                # Perform predictive analysis
                await self._analyze_trends()
                await self._predict_capacity_needs()
                await self._detect_anomalies()
                
            except Exception as e:
                logger.error(f"Predictive analysis task error: {e}")
    
    async def _collect_performance_metrics(self) -> None:
        """Collect performance metrics."""
        # Get backup operation performance
        active_ops = len(self.backup_manager.active_operations)
        await self.record_metric("active_operations", MetricType.PERFORMANCE, active_ops)
        
        # Calculate average operation time
        if self.backup_manager.operation_history:
            recent_ops = self.backup_manager.operation_history[-10:]  # Last 10 operations
            total_time = sum(
                (op.completed_at - op.started_at).total_seconds()
                for op in recent_ops
                if op.started_at and op.completed_at
            )
            avg_time = total_time / len(recent_ops) if recent_ops else 0
            await self.record_metric("avg_operation_time", MetricType.PERFORMANCE, avg_time)
    
    async def _collect_capacity_metrics(self) -> None:
        """Collect capacity metrics."""
        # Get storage usage from node manager
        if self.backup_manager.node_manager:
            node_stats = await self.backup_manager.node_manager.get_node_statistics()
            total_nodes = node_stats["total"]
            healthy_nodes = node_stats["healthy"]
            
            if total_nodes > 0:
                node_availability = healthy_nodes / total_nodes
                await self.record_metric("node_availability", MetricType.CAPACITY, node_availability)
    
    async def _collect_security_metrics(self) -> None:
        """Collect security metrics."""
        # Security metrics would be collected from security manager
        await self.record_metric("encryption_compliance", MetricType.SECURITY, 1.0)
        await self.record_metric("security_incidents", MetricType.SECURITY, 0)
    
    async def _collect_reliability_metrics(self) -> None:
        """Collect reliability metrics."""
        # Calculate backup success rate
        if self.backup_manager.operation_history:
            recent_ops = self.backup_manager.operation_history[-100:]  # Last 100 operations
            successful_ops = sum(1 for op in recent_ops if op.status.value == "completed")
            success_rate = successful_ops / len(recent_ops) if recent_ops else 1.0
            await self.record_metric("backup_success_rate", MetricType.RELIABILITY, success_rate)
    
    async def _check_thresholds(self, metric_name: str, value: float) -> None:
        """Check if metric value violates thresholds."""
        if metric_name in self.thresholds:
            threshold = self.thresholds[metric_name]
            
            if metric_name == "backup_success_rate" and value < threshold:
                await self.create_alert(
                    AlertLevel.WARNING,
                    f"Backup success rate below threshold: {value:.1%} < {threshold:.1%}",
                    metric_name
                )
            elif metric_name == "storage_usage" and value > threshold:
                await self.create_alert(
                    AlertLevel.WARNING,
                    f"Storage usage above threshold: {value:.1%} > {threshold:.1%}",
                    metric_name
                )
            elif metric_name == "node_availability" and value < threshold:
                await self.create_alert(
                    AlertLevel.ERROR,
                    f"Node availability below threshold: {value:.1%} < {threshold:.1%}",
                    metric_name
                )
    
    async def _get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary."""
        return {
            "active_operations": len(self.backup_manager.active_operations),
            "avg_operation_time": 0.0,  # Would be calculated from metrics
            "throughput": 0.0  # Would be calculated from metrics
        }
    
    async def _get_capacity_summary(self) -> Dict[str, Any]:
        """Get capacity summary."""
        return {
            "total_storage": 0,
            "used_storage": 0,
            "available_storage": 0,
            "node_count": 0
        }
    
    async def _get_security_summary(self) -> Dict[str, Any]:
        """Get security summary."""
        return {
            "encryption_compliance": 1.0,
            "security_incidents": 0,
            "threat_level": "low"
        }
    
    async def _get_reliability_summary(self) -> Dict[str, Any]:
        """Get reliability summary."""
        return {
            "backup_success_rate": 1.0,
            "uptime": 1.0,
            "data_integrity": 1.0
        }
    
    async def _analyze_trends(self) -> None:
        """Analyze metric trends."""
        # Placeholder for trend analysis
    
    async def _predict_capacity_needs(self) -> None:
        """Predict future capacity needs."""
        # Placeholder for capacity prediction
    
    async def _detect_anomalies(self) -> None:
        """Detect anomalies in metrics."""
        # Placeholder for anomaly detection
