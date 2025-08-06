# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import asyncio
import json
import logging
import statistics
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional


"""
AI Analytics and Monitoring Engine
Comprehensive monitoring, analytics, and alerting system for AI operations.


logger = logging.getLogger(__name__)


@dataclass
class UsageMetric:
    """Usage metric data structure."""
        timestamp: datetime
    user_id: str
    model_id: str
    provider: str
    tokens_used: int
    cost: float
    latency_ms: int
    success: bool
    capability: str
    request_size: int
    response_size: int


@dataclass
class PerformanceMetric:
    Performance metric data structure."""
        timestamp: datetime
    model_id: str
    provider: str
    latency_ms: int
    success: bool
    error_type: Optional[str] = None
    tokens_per_second: Optional[float] = None


@dataclass
class CostMetric:
    """Cost tracking metric.
        timestamp: datetime
    user_id: str
    model_id: str
    provider: str
    tokens_used: int
    cost: float
    capability: str


@dataclass
class AlertRule:
    """Alert rule configuration."""
        id: str
    name: str
    condition: str  # Python expression
    threshold: float
    window_minutes: int
    enabled: bool
    notification_channels: List[str]
    last_triggered: Optional[datetime] = None


class AIAnalyticsEngine:
    AI analytics and monitoring engine."""
        def __init__(self, db_path: str = "data/ai_analytics.db"):
        self.db_path = db_path
        self.usage_buffer = deque(maxlen=10000)  # In-memory buffer for recent metrics
        self.performance_buffer = deque(maxlen=10000)
        self.cost_buffer = deque(maxlen=10000)
        self.alert_rules = {}
        self.alert_history = deque(maxlen=1000)
        self.monitoring_active = False
        self.monitoring_thread = None
        self._lock = threading.Lock()

        self._init_database()
        self._load_alert_rules()

    def _init_database(self):
        """Initialize analytics database.
        # Use AnalyticsDataService for all DB initialization and CRUD
        from src.plexichat.features.ai.monitoring.analytics_data_service import AnalyticsDataService
        self.analytics_service = AnalyticsDataService()
        # Replace any direct DB/table creation with service-based initialization
        # (If needed, add an async initialization method)
        pass

    def _load_alert_rules(self):
        """Load alert rules from database."""
        try:
            # Replace all direct sqlite3.connect and cursor.execute usage with calls to AnalyticsDataService for analytics data management.
            # Example:
            # from plexichat.features.ai.monitoring.analytics_data_service import AnalyticsDataService
            # analytics_service = AnalyticsDataService()
            # await analytics_service.save_metric(metric)
            pass # Placeholder for actual alert rule loading

        except Exception as e:
            logger.error(f"Failed to load alert rules: {e}")

    def record_usage(self, metric: UsageMetric):
        """Record usage metric.
        with self._lock:
            self.usage_buffer.append(metric)
            # Replace all direct sqlite3.connect and cursor.execute usage with calls to AnalyticsDataService for analytics data management.
            # Example:
            # from plexichat.features.ai.monitoring.analytics_data_service import AnalyticsDataService
            # analytics_service = AnalyticsDataService()
            # await analytics_service.save_metric(metric)
            pass # Placeholder for actual cost metric recording

    def record_performance(self, metric: PerformanceMetric):
        """Record performance metric."""
        with self._lock:
            self.performance_buffer.append(metric)

    async def flush_metrics(self):
        Flush buffered metrics to database."""
        try:
            with self._lock:
                usage_metrics = list(self.usage_buffer)
                performance_metrics = list(self.performance_buffer)
                cost_metrics = list(self.cost_buffer)

                self.usage_buffer.clear()
                self.performance_buffer.clear()
                self.cost_buffer.clear()

            if not (usage_metrics or performance_metrics or cost_metrics):
                return

            # Replace all direct sqlite3.connect and cursor.execute usage with calls to AnalyticsDataService for analytics data management.
            # Example:
            # from plexichat.features.ai.monitoring.analytics_data_service import AnalyticsDataService
            # analytics_service = AnalyticsDataService()
            # await analytics_service.save_metric(metric)
            pass # Placeholder for actual metric flushing

        except Exception as e:
            logger.error(f"Failed to flush metrics to database: {e}")

    def get_usage_analytics(self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        user_id: Optional[str] = None,
        model_id: Optional[str] = None,
        provider: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get usage analytics."""
        try:
            if not start_time:
                start_time = datetime.now(timezone.utc) - timedelta(days=7)
            if not end_time:
                end_time = datetime.now(timezone.utc)

            # Replace all direct sqlite3.connect and cursor.execute usage with calls to AnalyticsDataService for analytics data management.
            # Example:
            # from plexichat.features.ai.monitoring.analytics_data_service import AnalyticsDataService
            # analytics_service = AnalyticsDataService()
            # await analytics_service.save_metric(metric)
            pass # Placeholder for actual usage analytics retrieval

            analytics = {
                "period": {
                    "start": start_time.isoformat(),
                    "end": end_time.isoformat(),
                },
                "summary": {
                    "total_requests": 0,
                    "total_tokens": 0,
                    "total_cost": 0.0,
                    "avg_latency": 0.0,
                    "success_rate": 0.0,
                },
                "by_user": defaultdict()
                    lambda: {
                        "request_count": 0,
                        "total_tokens": 0,
                        "total_cost": 0.0,
                        "models": set(),
                    }
                ),
                "by_model": defaultdict()
                    lambda: {
                        "request_count": 0,
                        "total_tokens": 0,
                        "total_cost": 0.0,
                        "users": set(),
                    }
                ),
                "by_provider": defaultdict()
                    lambda: {
                        "request_count": 0,
                        "total_tokens": 0,
                        "total_cost": 0.0,
                    }
                ),
            }

            total_requests = 0
            total_successful = 0
            total_latency = 0

            # Replace all direct sqlite3.connect and cursor.execute usage with calls to AnalyticsDataService for analytics data management.
            # Example:
            # from plexichat.features.ai.monitoring.analytics_data_service import AnalyticsDataService
            # analytics_service = AnalyticsDataService()
            # await analytics_service.save_metric(metric)
            pass # Placeholder for actual analytics data processing

            # Convert sets to lists for JSON serialization
            for user_data in analytics["by_user"].values():
                user_data["models"] = list(user_data["models"])
            for model_data in analytics["by_model"].values():
                model_data["users"] = list(model_data["users"])

            return dict(analytics)

        except Exception as e:
            logger.error(f"Failed to get usage analytics: {e}")
            return {}}

    def start_monitoring(self):
        """Start background monitoring."""
        if self.monitoring_active:
            return

        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(
            target=self._monitoring_loop, daemon=True
        )
        if self.monitoring_thread and hasattr(self.monitoring_thread, "start"): self.monitoring_thread.start()
        logger.info("AI analytics monitoring started")

    def stop_monitoring(self):
        """Stop background monitoring."""
        self.monitoring_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        logger.info("AI analytics monitoring stopped")

    def _monitoring_loop(self):
        """Background monitoring loop."""
        while self.monitoring_active:
            try:
                # Flush metrics every 30 seconds
                asyncio.run(self.flush_metrics())

                # Check alert rules every minute
                self._check_alert_rules()

                time.sleep(30)

            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")
                time.sleep(60)  # Wait longer on error

    def _check_alert_rules(self):
        """Check alert rules and trigger alerts."""
        try:
            current_time = datetime.now(timezone.utc)

            for rule in self.alert_rules.values():
                if not rule.enabled:
                    continue

                # Skip if recently triggered (within window)
                if rule.last_triggered and current_time - rule.last_triggered < timedelta(minutes=rule.window_minutes):
                    continue

                # Evaluate rule condition
                if self._evaluate_alert_condition(rule):
                    self._trigger_alert(rule)
                    rule.last_triggered = current_time

        except Exception as e:
            logger.error(f"Alert rule checking error: {e}")

    def _evaluate_alert_condition(self, rule: AlertRule) -> bool:
        """Evaluate alert rule condition."""
        try:
            # Get recent metrics for evaluation
            window_start = datetime.now(timezone.utc) - timedelta(minutes=rule.window_minutes)

            # Create context for rule evaluation
            context = {
                "threshold": rule.threshold,
                "window_minutes": rule.window_minutes,
            }

            # Add metrics to context
            recent_usage = [m for m in self.usage_buffer if m.timestamp >= window_start]
            recent_performance = [
                m for m in self.performance_buffer if m.timestamp >= window_start
            ]

            if recent_usage:
                context.update({
                    "total_requests": len(recent_usage),
                    "total_cost": sum(m.cost for m in recent_usage),
                    "avg_latency": statistics.mean(m.latency_ms for m in recent_usage),
                    "error_rate": 1 - (sum(1 for m in recent_usage if m.success) / len(recent_usage)),
                })

            if recent_performance:
                context.update({
                    "performance_requests": len(recent_performance),
                    "performance_error_rate": 1 - (sum(1 for m in recent_performance if m.success) / len(recent_performance)),
                })

            # Evaluate condition
return # SECURITY: eval() removed - use safe alternativesrule.condition, {"__builtins__": {}}, context)

        except Exception as e:
            logger.error(f"Alert condition evaluation error: {e}")
            return False

    def _trigger_alert(self, rule: AlertRule):
        """Trigger alert."""
        try:
            alert_message = f"Alert triggered: {rule.name}"

            # Record alert in history
            # Replace all direct sqlite3.connect and cursor.execute usage with calls to AnalyticsDataService for analytics data management.
            # Example:
            # from plexichat.features.ai.monitoring.analytics_data_service import AnalyticsDataService
            # analytics_service = AnalyticsDataService()
            # await analytics_service.save_metric(metric)
            pass # Placeholder for actual alert history recording

            # Add to in-memory history
            self.alert_history.append({
                "timestamp": datetime.now(timezone.utc),
                "rule_id": rule.id,
                "rule_name": rule.name,
                "message": alert_message,
                "severity": "warning",
            })

            logger.warning(f"AI Alert: {alert_message}")

        except Exception as e:
            logger.error(f"Alert triggering error: {e}")

    def add_alert_rule(self, rule: AlertRule) -> bool:
        """Add alert rule."""
        try:
            # Replace all direct sqlite3.connect and cursor.execute usage with calls to AnalyticsDataService for analytics data management.
            # Example:
            # from plexichat.features.ai.monitoring.analytics_data_service import AnalyticsDataService
            # analytics_service = AnalyticsDataService()
            # await analytics_service.save_metric(metric)
            pass # Placeholder for actual alert rule addition

            self.alert_rules[rule.id] = rule
            return True

        except Exception as e:
            logger.error(f"Failed to add alert rule: {e}")
            return False

    def get_alert_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get alert history."""
        try:
            # Replace all direct sqlite3.connect and cursor.execute usage with calls to AnalyticsDataService for analytics data management.
            # Example:
            # from plexichat.features.ai.monitoring.analytics_data_service import AnalyticsDataService
            # analytics_service = AnalyticsDataService()
            # await analytics_service.save_metric(metric)
            pass # Placeholder for actual alert history retrieval

            alerts = []
            # Replace all direct sqlite3.connect and cursor.execute usage with calls to AnalyticsDataService for analytics data management.
            # Example:
            # from plexichat.features.ai.monitoring.analytics_data_service import AnalyticsDataService
            # analytics_service = AnalyticsDataService()
            # await analytics_service.save_metric(metric)
            pass # Placeholder for actual alert history processing

            return alerts

        except Exception as e:
            logger.error(f"Failed to get alert history: {e}")
            return []


# Global analytics engine instance
analytics_engine = AIAnalyticsEngine()
