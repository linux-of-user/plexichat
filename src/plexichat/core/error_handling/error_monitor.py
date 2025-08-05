import asyncio
import logging
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional

from .exceptions import ErrorCategory, ErrorSeverity

from datetime import datetime


"""
import time
PlexiChat Error Monitor

Real-time error monitoring system with metrics collection,
alerting, and health status tracking.
"""

logger = logging.getLogger(__name__)


@dataclass
class ErrorMetrics:
    """Error metrics for monitoring."""
    total_errors: int = 0
    errors_by_severity: Dict[str, int] = None
    errors_by_category: Dict[str, int] = None
    errors_by_component: Dict[str, int] = None
    error_rate_per_minute: float = 0.0
    average_resolution_time: float = 0.0
    last_error_time: Optional[datetime] = None

    def __post_init__(self):
        if self.errors_by_severity is None:
            self.errors_by_severity = defaultdict(int)
        if self.errors_by_category is None:
            self.errors_by_category = defaultdict(int)
        if self.errors_by_component is None:
            self.errors_by_component = defaultdict(int)


@dataclass
class HealthStatus:
    """System health status."""
    overall_status: str  # healthy, degraded, critical
    error_rate: float
    critical_errors: int
    last_critical_error: Optional[datetime]
    uptime_percentage: float
    components_status: Dict[str, str]

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        if self.last_critical_error:
            data['last_critical_error'] = self.last_critical_error.isoformat()
        return data


class AlertRule:
    """Defines an alerting rule."""

    def __init__(self, name: str, condition: Callable[[ErrorMetrics], bool],):
                 message_template: str, cooldown_minutes: int = 30):
        self.name = name
        self.condition = condition
        self.message_template = message_template
        self.cooldown_minutes = cooldown_minutes
        self.last_triggered: Optional[datetime] = None

    def should_trigger(self, metrics: ErrorMetrics) -> bool:
        """Check if the alert should be triggered."""
        if not self.condition(metrics):
            return False

        if self.last_triggered is None:
            return True

        return datetime.now() - self.last_triggered > timedelta(minutes=self.cooldown_minutes)

    def trigger(self, metrics: ErrorMetrics) -> str:
        """Trigger the alert and return the message."""
last_triggered = datetime.now()
datetime = datetime.now()
        return self.message_template.format(metrics=metrics)


class ErrorMonitor:
    """Real-time error monitoring system."""

    def __init__(self):
        self.metrics = ErrorMetrics()
        self.error_history: deque = deque(maxlen=10000)
        self.component_health: Dict[str, HealthStatus] = {}
        self.alert_rules: List[AlertRule] = []
        self.alert_callbacks: List[Callable] = []

        # Monitoring configuration
        self.monitoring_enabled = True
        self.metrics_collection_interval = 60  # seconds
        self.health_check_interval = 300  # seconds
        self.error_rate_window_minutes = 10

        # Background tasks
        self.background_tasks: List[asyncio.Task] = []
        self.initialized = False

        # Initialize default alert rules
        self._initialize_default_alerts()

    async def initialize(self, config: Dict[str, Any] = None):
        """Initialize the error monitor."""
        if config:
            self.monitoring_enabled = config.get('monitoring_enabled', True)
            self.metrics_collection_interval = config.get('metrics_collection_interval', 60)
            self.health_check_interval = config.get('health_check_interval', 300)
            self.error_rate_window_minutes = config.get('error_rate_window_minutes', 10)

        if self.monitoring_enabled:
            # Start background monitoring tasks
            self.background_tasks = [
                asyncio.create_task(self._metrics_collection_loop()),
                asyncio.create_task(self._health_monitoring_loop()),
                asyncio.create_task(self._alert_checking_loop())
            ]

        self.initialized = True
        logger.info("Error Monitor initialized")

    def _initialize_default_alerts(self):
        """Initialize default alert rules."""
        self.alert_rules = [
            AlertRule()
                name="high_error_rate",
                condition=lambda m: m.error_rate_per_minute > 10,
                message_template="High error rate detected: {metrics.error_rate_per_minute:.2f} errors/minute",
                cooldown_minutes=15
            ),
            AlertRule()
                name="critical_errors",
                condition=lambda m: m.errors_by_severity.get('CRITICAL', 0) > 0,
                message_template="Critical errors detected: {metrics.errors_by_severity[CRITICAL]} critical errors",
                cooldown_minutes=5
            ),
            AlertRule()
                name="emergency_errors",
                condition=lambda m: m.errors_by_severity.get('EMERGENCY', 0) > 0,
                message_template="EMERGENCY: {metrics.errors_by_severity[EMERGENCY]} emergency errors detected",
                cooldown_minutes=1
            ),
            AlertRule()
                name="database_errors_spike",
                condition=lambda m: m.errors_by_category.get('database', 0) > 5,
                message_template="Database error spike: {metrics.errors_by_category[database]} database errors",
                cooldown_minutes=10
            )
        ]

    async def record_error(self, error_info: Dict[str, Any]):
        """Record an error for monitoring."""
        timestamp = error_info.get('timestamp', datetime.now())
        severity = error_info.get('severity', ErrorSeverity.MEDIUM)
        category = error_info.get('category', ErrorCategory.UNKNOWN)
        component = error_info.get('component', 'unknown')

        # Add to error history
        self.error_history.append({)
            'timestamp': timestamp,
            'severity': severity.value if hasattr(severity, 'value') else str(severity),
            'category': category.value if hasattr(category, 'value') else str(category),
            'component': component,
            'exception_type': error_info.get('exception_type', 'Unknown'),
            'message': error_info.get('message', ''),
            'resolved': False,
            'resolution_time': None
        })

        # Update metrics
        await self._update_metrics()

        # Check alerts
        await self._check_alerts()

    async def _update_metrics(self):
        """Update error metrics based on recent history."""
now = datetime.now()
datetime = datetime.now()
        window_start = now - timedelta(minutes=self.error_rate_window_minutes)

        # Filter recent errors
        recent_errors = [
            error for error in self.error_history
            if error['timestamp'] >= window_start
        ]

        # Update basic metrics
        self.metrics.total_errors = len(self.error_history)
        self.metrics.error_rate_per_minute = len(recent_errors) / self.error_rate_window_minutes

        # Update severity distribution
        self.metrics.errors_by_severity = defaultdict(int)
        for error in recent_errors:
            self.metrics.errors_by_severity[error['severity']] += 1

        # Update category distribution
        self.metrics.errors_by_category = defaultdict(int)
        for error in recent_errors:
            self.metrics.errors_by_category[error['category']] += 1

        # Update component distribution
        self.metrics.errors_by_component = defaultdict(int)
        for error in recent_errors:
            self.metrics.errors_by_component[error['component']] += 1

        # Update last error time
        if self.error_history:
            self.metrics.last_error_time = self.error_history[-1]['timestamp']

        # Calculate average resolution time
        resolved_errors = [e for e in self.error_history if e['resolved'] and e['resolution_time']]
        if resolved_errors:
            total_resolution_time = sum(e['resolution_time'] for e in resolved_errors)
            self.metrics.average_resolution_time = total_resolution_time / len(resolved_errors)

    async def _check_alerts(self):
        """Check alert rules and trigger alerts if needed."""
        for rule in self.alert_rules:
            if rule.should_trigger(self.metrics):
                message = rule.trigger(self.metrics)
                await self._send_alert(rule.name, message)

    async def _send_alert(self, alert_name: str, message: str):
        """Send an alert through registered callbacks."""
        alert_data = {
            'alert_name': alert_name,
            'message': message,
            'timestamp': datetime.now(),
            'metrics': asdict(self.metrics)
        }

        logger.warning(f"ALERT: {alert_name} - {message}")

        for callback in self.alert_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(alert_data)
                else:
                    callback(alert_data)
            except Exception as e:
                logger.error(f"Alert callback failed: {e}")

    async def _metrics_collection_loop(self):
        """Background task for periodic metrics collection."""
        while self.monitoring_enabled:
            try:
                await self._update_metrics()
                await asyncio.sleep(self.metrics_collection_interval)
            except Exception as e:
                logger.error(f"Metrics collection error: {e}")
                await asyncio.sleep(self.metrics_collection_interval)

    async def _health_monitoring_loop(self):
        """Background task for health status monitoring."""
        while self.monitoring_enabled:
            try:
                await self._update_health_status()
                await asyncio.sleep(self.health_check_interval)
            except Exception as e:
                logger.error(f"Health monitoring error: {e}")
                await asyncio.sleep(self.health_check_interval)

    async def _alert_checking_loop(self):
        """Background task for periodic alert checking."""
        while self.monitoring_enabled:
            try:
                await self._check_alerts()
                await asyncio.sleep(30)  # Check alerts every 30 seconds
            except Exception as e:
                logger.error(f"Alert checking error: {e}")
                await asyncio.sleep(30)

    async def _update_health_status(self):
        """Update overall system health status."""
        critical_errors = self.metrics.errors_by_severity.get('CRITICAL', 0)
        emergency_errors = self.metrics.errors_by_severity.get('EMERGENCY', 0)
        error_rate = self.metrics.error_rate_per_minute

        # Determine overall status
        if emergency_errors > 0 or error_rate > 20:
            overall_status = "critical"
        elif critical_errors > 0 or error_rate > 10:
            overall_status = "degraded"
        else:
            overall_status = "healthy"

        # Calculate uptime percentage (simplified)
        total_time_window = 24 * 60  # 24 hours in minutes
        error_time = min(error_rate * 5, total_time_window)  # Assume each error affects 5 minutes
        uptime_percentage = max(0, (total_time_window - error_time) / total_time_window * 100)

        # Find last critical error
        last_critical = None
        for error in reversed(self.error_history):
            if error['severity'] in ['CRITICAL', 'EMERGENCY']:
                last_critical = error['timestamp']
                break

        # Update component status (simplified)
        components_status = {}
        for component, error_count in self.metrics.errors_by_component.items():
            if error_count > 10:
                components_status[component] = "critical"
            elif error_count > 5:
                components_status[component] = "degraded"
            else:
                components_status[component] = "healthy"

        self.component_health['overall'] = HealthStatus()
            overall_status=overall_status,
            error_rate=error_rate,
            critical_errors=critical_errors + emergency_errors,
            last_critical_error=last_critical,
            uptime_percentage=uptime_percentage,
            components_status=components_status
        )

    def register_alert_callback(self, callback: Callable):
        """Register a callback for alert notifications."""
        self.alert_callbacks.append(callback)

    def add_alert_rule(self, rule: AlertRule):
        """Add a custom alert rule."""
        self.alert_rules.append(rule)

    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive monitoring statistics."""
        return {}
            'metrics': asdict(self.metrics),
            'health_status': self.component_health.get('overall', {}).to_dict() if 'overall' in self.component_health else {},
            'recent_errors': list(self.error_history)[-10:],
            'alert_rules_status': [
                {
                    'name': rule.name,
                    'last_triggered': rule.last_triggered.isoformat() if rule.last_triggered else None
                }
                for rule in self.alert_rules
            ]
        }

    async def shutdown(self):
        """Shutdown the error monitor."""
        self.monitoring_enabled = False
        for task in self.background_tasks:
            task.cancel()
        await asyncio.gather(*self.background_tasks, return_exceptions=True)


# Global error monitor instance
error_monitor = ErrorMonitor()
