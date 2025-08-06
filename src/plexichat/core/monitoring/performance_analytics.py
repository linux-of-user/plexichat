"""
Comprehensive Performance Monitoring & Analytics System

Provides enterprise-grade performance monitoring with:
- Real-time system metrics collection
- Query performance analytics
- System health dashboards
- Performance trend analysis
- Automated alerting and notifications
- Resource utilization tracking
- Bottleneck detection and analysis
- Performance optimization recommendations


import asyncio
import time
import psutil
import threading
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import deque, defaultdict
import json
import statistics

from ..logging.unified_logging import get_logger
from ..logging.correlation_tracker import correlation_tracker, CorrelationType

logger = get_logger(__name__)


class MetricType(Enum):
    """Types of performance metrics."""
        COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"
    RATE = "rate"


class AlertLevel(Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


@dataclass
class PerformanceMetric:
    """Individual performance metric data point."""
        name: str
    value: float
    metric_type: MetricType
    timestamp: datetime = field(default_factory=datetime.now)
    tags: Dict[str, str] = field(default_factory=dict)
    unit: str = ""
    description: str = ""


@dataclass
class SystemHealthStatus:
    """System health status information.
        overall_status: str  # healthy, degraded, unhealthy
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    network_io: Dict[str, float]
    active_connections: int
    response_time_avg: float
    error_rate: float
    uptime_seconds: float
    timestamp: datetime = field(default_factory=datetime.now)
    
    # Component health
    database_healthy: bool = True
    cache_healthy: bool = True
    api_healthy: bool = True
    
    # Performance indicators
    performance_score: float = 100.0
    bottlenecks: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


@dataclass
class PerformanceAlert:
    """Performance alert information."""
        alert_id: str
    level: AlertLevel
    title: str
    message: str
    metric_name: str
    current_value: float
    threshold_value: float
    timestamp: datetime = field(default_factory=datetime.now)
    resolved: bool = False
    resolved_at: Optional[datetime] = None


class MetricsCollector:
    Collects and aggregates performance metrics."""
        def __init__(self, max_metrics: int = 10000):
        self.max_metrics = max_metrics
        self.metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.metric_definitions: Dict[str, Dict] = {}
        self.collection_interval = 5  # seconds
        self.collection_task: Optional[asyncio.Task] = None
        self._lock = threading.RLock()
        
        # System baseline metrics
        self.baseline_metrics = {}
        self.start_time = time.time()
        
    async def start_collection(self):
        """Start automatic metrics collection."""
        if self.collection_task and not self.collection_task.done():
            return
        
        self.collection_task = asyncio.create_task(self._collection_loop())
        logger.info("Performance metrics collection started")
    
    async def stop_collection(self):
        """Stop automatic metrics collection."""
        if self.collection_task:
            self.collection_task.cancel()
            try:
                await self.collection_task
            except asyncio.CancelledError:
                pass
        logger.info("Performance metrics collection stopped")
    
    async def _collection_loop(self):
        """Main metrics collection loop."""
        while True:
            try:
                await self._collect_system_metrics()
                await asyncio.sleep(self.collection_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in metrics collection: {e}")
                await asyncio.sleep(self.collection_interval)
    
    async def _collect_system_metrics(self):
        """Collect system performance metrics."""
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=0.1)
            self.record_metric("system.cpu.usage_percent", cpu_percent, MetricType.GAUGE, unit="%")
            
            # Memory metrics
            memory = psutil.virtual_memory()
            self.record_metric("system.memory.usage_percent", memory.percent, MetricType.GAUGE, unit="%")
            self.record_metric("system.memory.available_gb", memory.available / (1024**3), MetricType.GAUGE, unit="GB")
            self.record_metric("system.memory.used_gb", memory.used / (1024**3), MetricType.GAUGE, unit="GB")
            
            # Disk metrics
            disk = psutil.disk_usage('/')
            disk_percent = (disk.used / disk.total) * 100
            self.record_metric("system.disk.usage_percent", disk_percent, MetricType.GAUGE, unit="%")
            self.record_metric("system.disk.free_gb", disk.free / (1024**3), MetricType.GAUGE, unit="GB")
            
            # Network metrics
            network = psutil.net_io_counters()
            self.record_metric("system.network.bytes_sent", network.bytes_sent, MetricType.COUNTER, unit="bytes")
            self.record_metric("system.network.bytes_recv", network.bytes_recv, MetricType.COUNTER, unit="bytes")
            
            # Process metrics
            process = psutil.Process()
            self.record_metric("process.cpu.usage_percent", process.cpu_percent(), MetricType.GAUGE, unit="%")
            self.record_metric("process.memory.rss_mb", process.memory_info().rss / (1024**2), MetricType.GAUGE, unit="MB")
            self.record_metric("process.threads.count", process.num_threads(), MetricType.GAUGE, unit="count")
            
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
    
    def record_metric(self, name: str, value: float, metric_type: MetricType, 
                    tags: Optional[Dict[str, str]] = None, unit: str = "", description: str = ""):
        """Record a performance metric.
        with self._lock:
            metric = PerformanceMetric(
                name=name,
                value=value,
                metric_type=metric_type,
                tags=tags or {},
                unit=unit,
                description=description
            )
            
            self.metrics[name].append(metric)
            
            # Store metric definition
            if name not in self.metric_definitions:
                self.metric_definitions[name] = {
                    'type': metric_type.value,
                    'unit': unit,
                    'description': description
                }
    
    def get_metric_history(self, name: str, duration_minutes: int = 60) -> List[PerformanceMetric]:
        """Get metric history for specified duration."""
        with self._lock:
            if name not in self.metrics:
                return []
            
            cutoff_time = datetime.now() - timedelta(minutes=duration_minutes)
            return [
                metric for metric in self.metrics[name]
                if metric.timestamp >= cutoff_time
            ]
    
    def get_metric_stats(self, name: str, duration_minutes: int = 60) -> Dict[str, float]:
        Get statistical summary of a metric."""
        history = self.get_metric_history(name, duration_minutes)
        if not history:
            return {

        values = [m.value for m in history]
        return {
            'count': len(values),
            'min': min(values),
            'max': max(values),
            'mean': statistics.mean(values),
            'median': statistics.median(values),
            'std_dev': statistics.stdev(values) if len(values) > 1 else 0.0,
            'latest': values[-1] if values else 0.0
        }}
    
    def get_all_metrics_summary(self) -> Dict[str, Any]:
        """Get summary of all collected metrics.
        with self._lock:
            summary = {}
            for name in self.metrics:
                stats = self.get_metric_stats(name, 60)
                if stats:
                    summary[name] = {
                        **stats,
                        'definition': self.metric_definitions.get(name, {})
                    }
            return summary


class PerformanceAnalyzer:
    """Analyzes performance metrics and detects issues."""
        def __init__(self, metrics_collector: MetricsCollector):
        self.metrics_collector = metrics_collector
        self.thresholds = {
            'system.cpu.usage_percent': {'warning': 70.0, 'critical': 85.0},
            'system.memory.usage_percent': {'warning': 75.0, 'critical': 90.0},
            'system.disk.usage_percent': {'warning': 80.0, 'critical': 95.0},
            'api.response_time_ms': {'warning': 500.0, 'critical': 1000.0},
            'api.error_rate_percent': {'warning': 5.0, 'critical': 10.0}
        }
        self.alerts: List[PerformanceAlert] = []
        self.alert_callbacks: List[Callable] = []
    
    def analyze_system_health(self) -> SystemHealthStatus:
        Analyze overall system health."""
        try:
            # Get current metrics
            cpu_stats = self.metrics_collector.get_metric_stats('system.cpu.usage_percent', 5)
            memory_stats = self.metrics_collector.get_metric_stats('system.memory.usage_percent', 5)
            disk_stats = self.metrics_collector.get_metric_stats('system.disk.usage_percent', 5)
            
            cpu_usage = cpu_stats.get('latest', 0.0)
            memory_usage = memory_stats.get('latest', 0.0)
            disk_usage = disk_stats.get('latest', 0.0)
            
            # Network I/O
            network_sent = self.metrics_collector.get_metric_stats('system.network.bytes_sent', 5)
            network_recv = self.metrics_collector.get_metric_stats('system.network.bytes_recv', 5)
            
            # Calculate overall status
            overall_status = "healthy"
            performance_score = 100.0
            bottlenecks = []
            recommendations = []
            
            # Check thresholds
            if cpu_usage > 85:
                overall_status = "unhealthy"
                performance_score -= 30
                bottlenecks.append("High CPU usage")
                recommendations.append("Consider scaling CPU resources or optimizing CPU-intensive operations")
            elif cpu_usage > 70:
                overall_status = "degraded"
                performance_score -= 15
                bottlenecks.append("Elevated CPU usage")
                recommendations.append("Monitor CPU usage and consider optimization")
            
            if memory_usage > 90:
                overall_status = "unhealthy"
                performance_score -= 25
                bottlenecks.append("High memory usage")
                recommendations.append("Increase memory or optimize memory usage")
            elif memory_usage > 75:
                if overall_status == "healthy":
                    overall_status = "degraded"
                performance_score -= 10
                bottlenecks.append("Elevated memory usage")
                recommendations.append("Monitor memory usage trends")
            
            if disk_usage > 95:
                overall_status = "unhealthy"
                performance_score -= 20
                bottlenecks.append("Disk space critical")
                recommendations.append("Free up disk space immediately")
            elif disk_usage > 80:
                if overall_status == "healthy":
                    overall_status = "degraded"
                performance_score -= 5
                bottlenecks.append("Low disk space")
                recommendations.append("Plan for disk space cleanup or expansion")
            
            # Calculate uptime
            uptime_seconds = time.time() - self.metrics_collector.start_time
            
            return SystemHealthStatus(
                overall_status=overall_status,
                cpu_usage=cpu_usage,
                memory_usage=memory_usage,
                disk_usage=disk_usage,
                network_io={
                    'bytes_sent_latest': network_sent.get('latest', 0.0),
                    'bytes_recv_latest': network_recv.get('latest', 0.0)
                },
                active_connections=0,  # Would be populated from connection pool
                response_time_avg=0.0,  # Would be populated from API metrics
                error_rate=0.0,  # Would be populated from error metrics
                uptime_seconds=uptime_seconds,
                performance_score=max(0.0, performance_score),
                bottlenecks=bottlenecks,
                recommendations=recommendations
            )
            
        except Exception as e:
            logger.error(f"Error analyzing system health: {e}")
            return SystemHealthStatus(
                overall_status="unknown",
                cpu_usage=0.0,
                memory_usage=0.0,
                disk_usage=0.0,
                network_io={},
                active_connections=0,
                response_time_avg=0.0,
                error_rate=0.0,
                uptime_seconds=0.0
            )
    
    def check_alerts(self) -> List[PerformanceAlert]:
        """Check for performance alerts based on thresholds."""
        new_alerts = []
        
        for metric_name, thresholds in self.thresholds.items():
            stats = self.metrics_collector.get_metric_stats(metric_name, 5)
            if not stats:
                continue
            
            current_value = stats.get('latest', 0.0)
            
            # Check critical threshold
            if current_value > thresholds.get('critical', float('inf')):
                alert = PerformanceAlert(
                    alert_id=f"alert_{metric_name}_{int(time.time())}",
                    level=AlertLevel.CRITICAL,
                    title=f"Critical: {metric_name}",
                    message=f"{metric_name} is critically high: {current_value:.2f}",
                    metric_name=metric_name,
                    current_value=current_value,
                    threshold_value=thresholds['critical']
                )
                new_alerts.append(alert)
                
            # Check warning threshold
            elif current_value > thresholds.get('warning', float('inf')):
                alert = PerformanceAlert(
                    alert_id=f"alert_{metric_name}_{int(time.time())}",
                    level=AlertLevel.WARNING,
                    title=f"Warning: {metric_name}",
                    message=f"{metric_name} is elevated: {current_value:.2f}",
                    metric_name=metric_name,
                    current_value=current_value,
                    threshold_value=thresholds['warning']
                )
                new_alerts.append(alert)
        
        # Store alerts and trigger callbacks
        self.alerts.extend(new_alerts)
        for alert in new_alerts:
            for callback in self.alert_callbacks:
                try:
                    callback(alert)
                except Exception as e:
                    logger.error(f"Error in alert callback: {e}")
        
        return new_alerts
    
    def add_alert_callback(self, callback: Callable[[PerformanceAlert], None]):
        """Add callback for alert notifications.
        self.alert_callbacks.append(callback)
    
    def get_performance_trends(self, duration_hours: int = 24) -> Dict[str, Any]:
        """Analyze performance trends over time."""
        trends = {}
        
        key_metrics = [
            'system.cpu.usage_percent',
            'system.memory.usage_percent',
            'system.disk.usage_percent'
        ]
        
        for metric_name in key_metrics:
            history = self.metrics_collector.get_metric_history(metric_name, duration_hours * 60)
            if len(history) < 2:
                continue
            
            values = [m.value for m in history]
            timestamps = [m.timestamp for m in history]
            
            # Calculate trend (simple linear regression slope)
            n = len(values)
            if n > 1:
                x_vals = list(range(n))
                x_mean = sum(x_vals) / n
                y_mean = sum(values) / n
                
                numerator = sum((x_vals[i] - x_mean) * (values[i] - y_mean) for i in range(n))
                denominator = sum((x_vals[i] - x_mean) ** 2 for i in range(n))
                
                slope = numerator / denominator if denominator != 0 else 0
                
                trends[metric_name] = {
                    'slope': slope,
                    'direction': 'increasing' if slope > 0.1 else 'decreasing' if slope < -0.1 else 'stable',
                    'current_value': values[-1],
                    'min_value': min(values),
                    'max_value': max(values),
                    'data_points': n
                }
        
        return trends


class PerformanceMonitor:
    Main performance monitoring system."""
        def __init__(self):
        self.metrics_collector = MetricsCollector()
        self.analyzer = PerformanceAnalyzer(self.metrics_collector)
        self.dashboard_data = {}
        self.monitoring_active = False
        
        # Setup alert callback
        self.analyzer.add_alert_callback(self._handle_alert)
    
    async def start_monitoring(self):
        """Start performance monitoring."""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        await self.metrics_collector.start_collection()
        
        # Start periodic analysis
        asyncio.create_task(self._analysis_loop())
        
        logger.info("Performance monitoring started")
    
    async def stop_monitoring(self):
        """Stop performance monitoring."""
        self.monitoring_active = False
        await self.metrics_collector.stop_collection()
        logger.info("Performance monitoring stopped")
    
    async def _analysis_loop(self):
        """Periodic analysis loop."""
        while self.monitoring_active:
            try:
                # Check for alerts
                self.analyzer.check_alerts()
                
                # Update dashboard data
                await self._update_dashboard_data()
                
                await asyncio.sleep(30)  # Analyze every 30 seconds
            except Exception as e:
                logger.error(f"Error in analysis loop: {e}")
                await asyncio.sleep(30)
    
    async def _update_dashboard_data(self):
        """Update dashboard data."""
        try:
            self.dashboard_data = {
                'system_health': self.analyzer.analyze_system_health(),
                'metrics_summary': self.metrics_collector.get_all_metrics_summary(),
                'recent_alerts': self.analyzer.alerts[-10:],  # Last 10 alerts
                'performance_trends': self.analyzer.get_performance_trends(24),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Error updating dashboard data: {e}")
    
    def _handle_alert(self, alert: PerformanceAlert):
        """Handle performance alert."""
        log_level = logger.critical if alert.level == AlertLevel.CRITICAL else logger.warning
        log_level(f"Performance Alert: {alert.title} - {alert.message}")
    
    def get_dashboard_data(self) -> Dict[str, Any]:
        """Get current dashboard data.
        return self.dashboard_data.copy()
    
    def get_system_health(self) -> SystemHealthStatus:
        """Get current system health status."""
        return self.analyzer.analyze_system_health()
    
    def record_custom_metric(self, name: str, value: float, metric_type: MetricType = MetricType.GAUGE, 
                        tags: Optional[Dict[str, str]] = None, unit: str = ""):
        """Record a custom metric.
        self.metrics_collector.record_metric(name, value, metric_type, tags, unit)
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance report."""
        health = self.get_system_health()
        trends = self.analyzer.get_performance_trends(24)
        alerts = self.analyzer.alerts[-50:]  # Last 50 alerts
        
        return {
            'report_timestamp': datetime.now().isoformat(),
            'system_health': {
                'overall_status': health.overall_status,
                'performance_score': health.performance_score,
                'cpu_usage': health.cpu_usage,
                'memory_usage': health.memory_usage,
                'disk_usage': health.disk_usage,
                'uptime_hours': health.uptime_seconds / 3600,
                'bottlenecks': health.bottlenecks,
                'recommendations': health.recommendations
            },
            'performance_trends': trends,
            'alert_summary': {
                'total_alerts': len(alerts),
                'critical_alerts': len([a for a in alerts if a.level == AlertLevel.CRITICAL]),
                'warning_alerts': len([a for a in alerts if a.level == AlertLevel.WARNING]),
                'recent_alerts': [
                    {
                        'level': a.level.value,
                        'title': a.title,
                        'message': a.message,
                        'timestamp': a.timestamp.isoformat()
                    }
                    for a in alerts[-10:]
                ]
            },
            'metrics_overview': self.metrics_collector.get_all_metrics_summary()
        }


class PredictiveAnalytics:
    Machine learning-based predictive analytics for performance."""
        def __init__(self, performance_monitor):
        self.performance_monitor = performance_monitor
        self.prediction_models: Dict[str, Any] = {}
        self.prediction_cache: Dict[str, Dict] = {}
        self.training_data: Dict[str, List] = defaultdict(list)

        # Prediction configuration
        self.prediction_window_hours = 24
        self.min_training_samples = 100
        self.prediction_accuracy_threshold = 0.7

        logger.info("Predictive analytics system initialized")

    def collect_training_data(self, metric_name: str, value: float, timestamp: datetime):
        """Collect training data for predictive models.
        self.training_data[metric_name].append({
            'timestamp': timestamp,
            'value': value,
            'hour': timestamp.hour,
            'day_of_week': timestamp.weekday(),
            'day_of_month': timestamp.day
        })

        # Keep only recent data for training
        cutoff_time = datetime.now() - timedelta(days=30)
        self.training_data[metric_name] = [
            data for data in self.training_data[metric_name]
            if data['timestamp'] > cutoff_time
        ]

    def predict_metric_trend(self, metric_name: str, hours_ahead: int = 1) -> Optional[Dict[str, Any]]:
        """Predict metric trend using simple linear regression."""
        if metric_name not in self.training_data:
            return None

        data = self.training_data[metric_name]
        if len(data) < self.min_training_samples:
            return None

        try:
            # Simple linear regression prediction
            recent_data = data[-50:]  # Use last 50 data points

            if len(recent_data) < 10:
                return None

            # Calculate trend
            values = [d['value'] for d in recent_data]
            n = len(values)

            # Simple moving average prediction
            recent_avg = sum(values[-10:]) / 10
            older_avg = sum(values[-20:-10]) / 10 if len(values) >= 20 else recent_avg

            trend = recent_avg - older_avg
            predicted_value = recent_avg + (trend * hours_ahead)

            # Calculate confidence based on variance
            variance = sum((v - recent_avg) ** 2 for v in values[-10:]) / 10
            confidence = max(0.1, min(0.9, 1.0 - (variance / (recent_avg + 1))))

            return {
                'metric_name': metric_name,
                'predicted_value': predicted_value,
                'current_value': values[-1],
                'trend': 'increasing' if trend > 0 else 'decreasing' if trend < 0 else 'stable',
                'confidence': confidence,
                'hours_ahead': hours_ahead,
                'prediction_timestamp': datetime.now()
            }

        except Exception as e:
            logger.error(f"Error predicting trend for {metric_name}: {e}")
            return None

    def detect_anomalies(self, metric_name: str) -> List[Dict[str, Any]]:
        """Detect anomalies in metric data."""
        if metric_name not in self.training_data:
            return []

        data = self.training_data[metric_name]
        if len(data) < 20:
            return []

        try:
            values = [d['value'] for d in data[-50:]]  # Last 50 values
            mean_val = statistics.mean(values)
            std_dev = statistics.stdev(values) if len(values) > 1 else 0

            anomalies = []
            threshold = 2 * std_dev  # 2 standard deviations

            for i, data_point in enumerate(data[-10:]):  # Check last 10 points
                if abs(data_point['value'] - mean_val) > threshold:
                    anomalies.append({
                        'timestamp': data_point['timestamp'],
                        'value': data_point['value'],
                        'expected_range': [mean_val - threshold, mean_val + threshold],
                        'severity': 'high' if abs(data_point['value'] - mean_val) > 3 * std_dev else 'medium'
                    })

            return anomalies

        except Exception as e:
            logger.error(f"Error detecting anomalies for {metric_name}: {e}")
            return []

    def get_performance_forecast(self, hours_ahead: int = 24) -> Dict[str, Any]:
        """Get performance forecast for key metrics."""
        key_metrics = [
            'system.cpu.usage_percent',
            'system.memory.usage_percent',
            'system.disk.usage_percent'
        ]

        forecast = {
            'forecast_timestamp': datetime.now(),
            'hours_ahead': hours_ahead,
            'predictions': {},
            'anomalies': {},
            'recommendations': []
        }

        for metric in key_metrics:
            # Get prediction
            prediction = self.predict_metric_trend(metric, hours_ahead)
            if prediction:
                forecast['predictions'][metric] = prediction

                # Add recommendations based on predictions
                if prediction['predicted_value'] > 80 and metric.endswith('usage_percent'):
                    forecast['recommendations'].append(
                        f"High {metric.split('.')[1]} usage predicted ({prediction['predicted_value']:.1f}%) - consider scaling resources"
                    )

            # Get anomalies
            anomalies = self.detect_anomalies(metric)
            if anomalies:
                forecast['anomalies'][metric] = anomalies

        return forecast


class AutoScaler:
    """Automatic scaling system based on performance metrics."""
        def __init__(self, performance_monitor):
        self.performance_monitor = performance_monitor
        self.scaling_rules: List[Dict] = []
        self.scaling_history: List[Dict] = []
        self.scaling_enabled = True

        # Default scaling rules
        self._setup_default_scaling_rules()

        logger.info("Auto-scaler initialized")

    def _setup_default_scaling_rules(self):
        """Setup default scaling rules.
        self.scaling_rules = [
            {
                'name': 'cpu_scale_up',
                'metric': 'system.cpu.usage_percent',
                'condition': 'greater_than',
                'threshold': 80.0,
                'action': 'scale_up',
                'cooldown_minutes': 5
            },
            {
                'name': 'memory_scale_up',
                'metric': 'system.memory.usage_percent',
                'condition': 'greater_than',
                'threshold': 85.0,
                'action': 'scale_up',
                'cooldown_minutes': 5
            },
            {
                'name': 'cpu_scale_down',
                'metric': 'system.cpu.usage_percent',
                'condition': 'less_than',
                'threshold': 30.0,
                'action': 'scale_down',
                'cooldown_minutes': 10
            }
        ]

    async def evaluate_scaling_rules(self):
        """Evaluate scaling rules and take action if needed."""
        if not self.scaling_enabled:
            return

        for rule in self.scaling_rules:
            try:
                # Check cooldown
                if self._is_in_cooldown(rule):
                    continue

                # Get current metric value
                stats = self.performance_monitor.metrics_collector.get_metric_stats(
                    rule['metric'], 5  # Last 5 minutes
                )

                if not stats:
                    continue

                current_value = stats.get('latest', 0.0)

                # Check condition
                should_scale = False
                if rule['condition'] == 'greater_than' and current_value > rule['threshold']:
                    should_scale = True
                elif rule['condition'] == 'less_than' and current_value < rule['threshold']:
                    should_scale = True

                if should_scale:
                    await self._execute_scaling_action(rule, current_value)

            except Exception as e:
                logger.error(f"Error evaluating scaling rule {rule['name']}: {e}")

    def _is_in_cooldown(self, rule: Dict) -> bool:
        """Check if scaling rule is in cooldown period.
        cooldown_minutes = rule.get('cooldown_minutes', 5)
        cutoff_time = datetime.now() - timedelta(minutes=cooldown_minutes)

        for history_entry in self.scaling_history:
            if (history_entry['rule_name'] == rule['name'] and
                history_entry['timestamp'] > cutoff_time):
                return True

        return False

    async def _execute_scaling_action(self, rule: Dict, current_value: float):
        """Execute scaling action."""
        try:
            action = rule['action']

            # Log scaling action
            scaling_entry = {
                'rule_name': rule['name'],
                'action': action,
                'metric': rule['metric'],
                'current_value': current_value,
                'threshold': rule['threshold'],
                'timestamp': datetime.now()
            }

            self.scaling_history.append(scaling_entry)

            # Keep only recent history
            if len(self.scaling_history) > 100:
                self.scaling_history = self.scaling_history[-50:]

            logger.info(f"Scaling action triggered: {action} for {rule['metric']} (current: {current_value}, threshold: {rule['threshold']})")

            # In a real implementation, this would trigger actual scaling
            # For now, just log the action
            if action == 'scale_up':
                logger.info("Would scale up resources (increase CPU/memory allocation)")
            elif action == 'scale_down':
                logger.info("Would scale down resources (decrease CPU/memory allocation)")

        except Exception as e:
            logger.error(f"Error executing scaling action: {e}")

    def get_scaling_status(self) -> Dict[str, Any]:
        """Get current scaling status.
        recent_actions = [
            entry for entry in self.scaling_history
            if entry['timestamp'] > datetime.now() - timedelta(hours=24)
        ]

        return {
            'scaling_enabled': self.scaling_enabled,
            'total_rules': len(self.scaling_rules),
            'recent_actions_24h': len(recent_actions),
            'last_action': self.scaling_history[-1] if self.scaling_history else None,
            'scaling_rules': self.scaling_rules
        }


# Enhanced Performance Monitor with Predictive Analytics
class EnhancedPerformanceMonitor(PerformanceMonitor):
    """Enhanced performance monitor with predictive analytics and auto-scaling."""
        def __init__(self):
        super().__init__()
        self.predictive_analytics = PredictiveAnalytics(self)
        self.auto_scaler = AutoScaler(self)

        # Enhanced monitoring
        self.prediction_task: Optional[asyncio.Task] = None
        self.scaling_task: Optional[asyncio.Task] = None

    async def start_monitoring(self):
        Start enhanced monitoring with predictive analytics."""
        await super().start_monitoring()

        # Start predictive analytics
        self.prediction_task = asyncio.create_task(self._prediction_loop())

        # Start auto-scaling
        self.scaling_task = asyncio.create_task(self._scaling_loop())

        logger.info("Enhanced performance monitoring started with predictive analytics")

    async def stop_monitoring(self):
        """Stop enhanced monitoring."""
        await super().stop_monitoring()

        if self.prediction_task:
            self.prediction_task.cancel()

        if self.scaling_task:
            self.scaling_task.cancel()

        logger.info("Enhanced performance monitoring stopped")

    async def _prediction_loop(self):
        """Predictive analytics loop."""
        while self.monitoring_active:
            try:
                # Collect training data for key metrics
                key_metrics = [
                    'system.cpu.usage_percent',
                    'system.memory.usage_percent',
                    'system.disk.usage_percent'
                ]

                for metric_name in key_metrics:
                    stats = self.metrics_collector.get_metric_stats(metric_name, 5)
                    if stats and 'latest' in stats:
                        self.predictive_analytics.collect_training_data(
                            metric_name, stats['latest'], datetime.now()
                        )

                await asyncio.sleep(300)  # Run every 5 minutes

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in prediction loop: {e}")
                await asyncio.sleep(300)

    async def _scaling_loop(self):
        """Auto-scaling loop."""
        while self.monitoring_active:
            try:
                await self.auto_scaler.evaluate_scaling_rules()
                await asyncio.sleep(60)  # Check every minute

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in scaling loop: {e}")
                await asyncio.sleep(60)

    def get_enhanced_dashboard_data(self) -> Dict[str, Any]:
        """Get enhanced dashboard data with predictions.
        base_data = super().get_dashboard_data()

        # Add predictive analytics data
        forecast = self.predictive_analytics.get_performance_forecast(24)
        scaling_status = self.auto_scaler.get_scaling_status()

        base_data.update({
            'performance_forecast': forecast,
            'auto_scaling': scaling_status,
            'enhanced_features': {
                'predictive_analytics': True,
                'auto_scaling': True,
                'anomaly_detection': True
            }
        })

        return base_data


# Global enhanced performance monitor instance
performance_monitor = EnhancedPerformanceMonitor()


async def start_performance_monitoring():
    """Start global performance monitoring."""
    await performance_monitor.start_monitoring()


async def stop_performance_monitoring():
    Stop global performance monitoring."""
    await performance_monitor.stop_monitoring()


def get_performance_dashboard() -> Dict[str, Any]:
    """Get performance dashboard data.
    return performance_monitor.get_enhanced_dashboard_data()


def get_system_health_status() -> SystemHealthStatus:
    """Get current system health status."""
    return performance_monitor.get_system_health()


def record_performance_metric(name: str, value: float, metric_type: MetricType = MetricType.GAUGE,
                            tags: Optional[Dict[str, str]] = None, unit: str = ""):
    """Record a custom performance metric."""
    performance_monitor.record_custom_metric(name, value, metric_type, tags, unit)
