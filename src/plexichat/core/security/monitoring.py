"""
Security Monitoring System for PlexiChat
Comprehensive monitoring and alerting for security events.

Features:
- Real-time security metrics collection
- Configurable alerts and notifications
- Security event correlation
- Performance monitoring
- Compliance reporting
"""

import asyncio
import json
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional

from plexichat.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class SecurityAlert:
    """Security alert configuration."""

    name: str
    condition: str
    threshold: Any
    severity: str
    enabled: bool = True
    cooldown_minutes: int = 5
    last_triggered: Optional[float] = None


@dataclass
class SecurityMetrics:
    """Security metrics data point."""

    timestamp: float
    metric_name: str
    value: Any
    tags: Dict[str, str] = field(default_factory=dict)


class SecurityMonitoringSystem:
    """
    Security monitoring system with alerting and metrics.

    Features:
    - Real-time metrics collection
    - Configurable security alerts
    - Event correlation and analysis
    - Performance monitoring
    - Compliance reporting
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get("metrics_enabled", True)

        if not self.enabled:
            logger.info("Security monitoring is disabled")
            return

        # Alerting settings
        self.alerts_enabled = config.get("alerts_enabled", True)
        self.compliance_reporting = config.get("compliance_reporting", True)

        # Metrics storage
        self.metrics_buffer: deque = deque(maxlen=10000)
        self.metrics_aggregation: Dict[str, Dict[str, Any]] = defaultdict(dict)

        # Alert configurations
        self.alerts = self._initialize_default_alerts()

        # Alert callbacks
        self.alert_callbacks: List[Callable] = []

        # Monitoring settings
        self.collection_interval = 60  # seconds
        self.aggregation_window = 300  # 5 minutes

        # Background tasks
        self._monitoring_task: Optional[asyncio.Task] = None
        self._cleanup_task: Optional[asyncio.Task] = None

        logger.info("Security monitoring system initialized")

    def start_background_tasks(self):
        """Start background tasks when event loop is available."""
        if self.enabled and not self._monitoring_task:
            self._start_monitoring()

    def _initialize_default_alerts(self) -> Dict[str, SecurityAlert]:
        """Initialize default security alerts."""
        return {
            "high_rate_limit_hits": SecurityAlert(
                name="High Rate Limit Hits",
                condition="rate_limit_hits_per_minute > 100",
                threshold=100,
                severity="medium",
                cooldown_minutes=10,
            ),
            "brute_force_detected": SecurityAlert(
                name="Brute Force Attack Detected",
                condition="brute_force_blocks_per_hour > 5",
                threshold=5,
                severity="high",
                cooldown_minutes=30,
            ),
            "sql_injection_attempts": SecurityAlert(
                name="SQL Injection Attempts",
                condition="sql_injection_detections_per_hour > 10",
                threshold=10,
                severity="critical",
                cooldown_minutes=15,
            ),
            "suspicious_traffic_spike": SecurityAlert(
                name="Suspicious Traffic Spike",
                condition="requests_per_minute > 1000",
                threshold=1000,
                severity="high",
                cooldown_minutes=5,
            ),
            "failed_authentication_spike": SecurityAlert(
                name="Failed Authentication Spike",
                condition="failed_auths_per_minute > 20",
                threshold=20,
                severity="medium",
                cooldown_minutes=10,
            ),
        }

    def _start_monitoring(self):
        """Start background monitoring tasks."""
        if not self.enabled:
            return

        async def monitoring_worker():
            """Background monitoring worker."""
            while True:
                try:
                    await asyncio.sleep(self.collection_interval)
                    await self._collect_system_metrics()
                    await self._check_alerts()
                    self._aggregate_metrics()
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Error in monitoring worker: {e}")

        async def cleanup_worker():
            """Background cleanup worker."""
            while True:
                try:
                    await asyncio.sleep(3600)  # Clean up every hour
                    self._cleanup_old_metrics()
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Error in cleanup worker: {e}")

        self._monitoring_task = asyncio.create_task(monitoring_worker())
        self._cleanup_task = asyncio.create_task(cleanup_worker())

    async def _collect_system_metrics(self):
        """Collect system-level security metrics."""
        try:
            import psutil

            # System resource metrics
            cpu_percent = psutil.cpu_percent()
            memory_percent = psutil.virtual_memory().percent
            disk_usage = psutil.disk_usage("/").percent

            # Network metrics
            network_connections = len(psutil.net_connections())

            # Record metrics
            await self.record_metric("system.cpu_percent", cpu_percent)
            await self.record_metric("system.memory_percent", memory_percent)
            await self.record_metric("system.disk_usage_percent", disk_usage)
            await self.record_metric("system.network_connections", network_connections)

        except ImportError:
            # psutil not available
            pass
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")

    async def record_event(self, event: Any):
        """
        Record a security event for monitoring.

        Args:
            event: Security event to record
        """
        if not self.enabled:
            return

        try:
            # Extract event data
            event_type = getattr(event, "event_type", "unknown")
            threat_level = getattr(event, "threat_level", "low")
            context = getattr(event, "context", None)

            # Record event metrics
            await self.record_metric(
                "security.events_total",
                1,
                {"event_type": str(event_type), "threat_level": str(threat_level)},
            )

            # Record specific event types
            if hasattr(event_type, "value"):
                event_name = event_type.value
            else:
                event_name = str(event_type)

            await self.record_metric(f"security.events.{event_name}", 1)

            # Extract additional context
            if context:
                ip_address = getattr(context, "ip_address", None)
                user_id = getattr(context, "user_id", None)

                if ip_address:
                    await self.record_metric(
                        "security.events_by_ip", 1, {"ip": ip_address}
                    )
                if user_id:
                    await self.record_metric(
                        "security.events_by_user", 1, {"user_id": user_id}
                    )

        except Exception as e:
            logger.error(f"Error recording security event: {e}")

    async def record_metric(
        self, name: str, value: Any, tags: Optional[Dict[str, str]] = None
    ):
        """
        Record a metric data point.

        Args:
            name: Metric name
            value: Metric value
            tags: Optional tags for the metric
        """
        if not self.enabled:
            return

        try:
            metric = SecurityMetrics(
                timestamp=time.time(), metric_name=name, value=value, tags=tags or {}
            )

            self.metrics_buffer.append(metric)

        except Exception as e:
            logger.error(f"Error recording metric {name}: {e}")

    async def _check_alerts(self):
        """Check configured alerts against current metrics."""
        if not self.alerts_enabled:
            return

        try:
            current_time = time.time()

            for alert_name, alert in self.alerts.items():
                if not alert.enabled:
                    continue

                # Check cooldown
                if (
                    alert.last_triggered
                    and current_time - alert.last_triggered
                    < alert.cooldown_minutes * 60
                ):
                    continue

                # Evaluate condition
                if await self._evaluate_alert_condition(alert):
                    # Trigger alert
                    await self._trigger_alert(alert)
                    alert.last_triggered = current_time

        except Exception as e:
            logger.error(f"Error checking alerts: {e}")

    async def _evaluate_alert_condition(self, alert: SecurityAlert) -> bool:
        """Evaluate alert condition against current metrics."""
        try:
            # Simple condition evaluation (in production, use a proper expression evaluator)
            condition = alert.condition

            if "rate_limit_hits_per_minute" in condition:
                rate = self._get_metric_rate("security.events.rate_limit_exceeded", 60)
                return rate > alert.threshold

            elif "brute_force_blocks_per_hour" in condition:
                rate = self._get_metric_rate(
                    "security.events.brute_force_attempt", 3600
                )
                return rate > alert.threshold

            elif "sql_injection_detections_per_hour" in condition:
                rate = self._get_metric_rate(
                    "security.events.sql_injection_attempt", 3600
                )
                return rate > alert.threshold

            elif "requests_per_minute" in condition:
                rate = self._get_metric_rate("security.requests_total", 60)
                return rate > alert.threshold

            elif "failed_auths_per_minute" in condition:
                rate = self._get_metric_rate("security.events.login_failure", 60)
                return rate > alert.threshold

            return False

        except Exception as e:
            logger.error(f"Error evaluating alert condition: {e}")
            return False

    def _get_metric_rate(self, metric_name: str, window_seconds: int) -> float:
        """Get the rate of a metric over a time window."""
        try:
            current_time = time.time()
            window_start = current_time - window_seconds

            # Count metrics in the window
            count = sum(
                1
                for m in self.metrics_buffer
                if m.metric_name == metric_name and m.timestamp > window_start
            )

            # Calculate rate
            return count / (window_seconds / 60)  # per minute

        except Exception:
            return 0.0

    async def _trigger_alert(self, alert: SecurityAlert):
        """Trigger a security alert."""
        try:
            alert_data = {
                "alert_name": alert.name,
                "severity": alert.severity,
                "condition": alert.condition,
                "threshold": alert.threshold,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "current_metrics": self.get_current_metrics_summary(),
            }

            logger.warning(f"Security Alert Triggered: {alert.name} ({alert.severity})")

            # Call alert callbacks
            for callback in self.alert_callbacks:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(alert_data)
                    else:
                        callback(alert_data)
                except Exception as e:
                    logger.error(f"Error in alert callback: {e}")

        except Exception as e:
            logger.error(f"Error triggering alert: {e}")

    def _aggregate_metrics(self):
        """Aggregate metrics for reporting."""
        try:
            current_time = time.time()
            window_start = current_time - self.aggregation_window

            # Aggregate by metric name
            aggregated = defaultdict(
                lambda: {"count": 0, "sum": 0, "min": float("inf"), "max": 0}
            )

            for metric in self.metrics_buffer:
                if metric.timestamp > window_start:
                    agg = aggregated[metric.metric_name]
                    agg["count"] += 1

                    if isinstance(metric.value, (int, float)):
                        agg["sum"] += metric.value
                        agg["min"] = min(agg["min"], metric.value)
                        agg["max"] = max(agg["max"], metric.value)

            # Calculate averages
            for name, agg in aggregated.items():
                if agg["count"] > 0:
                    agg["avg"] = agg["sum"] / agg["count"]
                else:
                    agg["avg"] = 0

            self.metrics_aggregation = dict(aggregated)

        except Exception as e:
            logger.error(f"Error aggregating metrics: {e}")

    def _cleanup_old_metrics(self):
        """Clean up old metrics data."""
        try:
            current_time = time.time()
            retention_period = 24 * 3600  # 24 hours

            # Remove old metrics
            cutoff_time = current_time - retention_period
            original_size = len(self.metrics_buffer)

            self.metrics_buffer = deque(
                (m for m in self.metrics_buffer if m.timestamp > cutoff_time),
                maxlen=self.metrics_buffer.maxlen,
            )

            removed_count = original_size - len(self.metrics_buffer)
            if removed_count > 0:
                logger.info(f"Cleaned up {removed_count} old metrics")

        except Exception as e:
            logger.error(f"Error cleaning up metrics: {e}")

    def add_alert_callback(self, callback: Callable):
        """Add a callback function for alerts."""
        self.alert_callbacks.append(callback)

    def add_custom_alert(self, alert: SecurityAlert):
        """Add a custom security alert."""
        self.alerts[alert.name] = alert
        logger.info(f"Added custom alert: {alert.name}")

    def remove_alert(self, alert_name: str):
        """Remove a security alert."""
        if alert_name in self.alerts:
            del self.alerts[alert_name]
            logger.info(f"Removed alert: {alert_name}")

    def get_current_metrics_summary(self) -> Dict[str, Any]:
        """Get current metrics summary."""
        if not self.enabled:
            return {"enabled": False}

        return {
            "enabled": True,
            "total_metrics": len(self.metrics_buffer),
            "aggregated_metrics": dict(self.metrics_aggregation),
            "active_alerts": len([a for a in self.alerts.values() if a.enabled]),
            "recent_alerts": [
                {
                    "name": alert.name,
                    "severity": alert.severity,
                    "last_triggered": alert.last_triggered,
                }
                for alert in self.alerts.values()
                if alert.last_triggered
            ],
        }

    def get_compliance_report(self) -> Dict[str, Any]:
        """Generate compliance report."""
        if not self.compliance_reporting:
            return {"enabled": False}

        try:
            # Calculate compliance metrics
            report = {
                "report_generated": datetime.now(timezone.utc).isoformat(),
                "period_days": 30,
                "metrics": {},
            }

            # Security event analysis
            security_events = [
                m
                for m in self.metrics_buffer
                if m.metric_name.startswith("security.events")
            ]

            # Failed authentication rate
            failed_auths = sum(
                1 for m in security_events if "login_failure" in m.metric_name
            )
            total_auths = sum(1 for m in security_events if "login" in m.metric_name)

            report["metrics"]["authentication_failure_rate"] = (
                failed_auths / max(total_auths, 1) * 100
            )

            # Rate limiting effectiveness
            rate_limit_hits = sum(
                1 for m in security_events if "rate_limit" in m.metric_name
            )
            total_requests = sum(
                m.value
                for m in self.metrics_buffer
                if m.metric_name == "security.requests_total"
            )

            report["metrics"]["rate_limiting_effectiveness"] = (
                rate_limit_hits / max(total_requests, 1) * 100
            )

            # Threat detection rate
            threat_detections = sum(
                1
                for m in security_events
                if any(
                    word in m.metric_name
                    for word in ["sql_injection", "xss", "malicious"]
                )
            )

            report["metrics"]["threat_detection_rate"] = threat_detections

            return report

        except Exception as e:
            logger.error(f"Error generating compliance report: {e}")
            return {"error": str(e)}

    def update_config(self, new_config: Dict[str, Any]):
        """Update monitoring configuration."""
        if not self.enabled:
            return

        self.config.update(new_config)
        self.alerts_enabled = new_config.get("alerts_enabled", self.alerts_enabled)
        self.compliance_reporting = new_config.get(
            "compliance_reporting", self.compliance_reporting
        )

        logger.info("Security monitoring configuration updated")

    async def shutdown(self):
        """Shutdown the monitoring system."""
        if self._monitoring_task and not self._monitoring_task.done():
            self._monitoring_task.cancel()
            try:
                await self._monitoring_task
            except asyncio.CancelledError:
                pass

        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

        logger.info("Security monitoring system shut down")


__all__ = ["SecurityMonitoringSystem", "SecurityAlert", "SecurityMetrics"]
