# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import asyncio
import json
import logging
import sqlite3
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
"""

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
    """Performance metric data structure."""

    timestamp: datetime
    model_id: str
    provider: str
    latency_ms: int
    success: bool
    error_type: Optional[str] = None
    tokens_per_second: Optional[float] = None


@dataclass
class CostMetric:
    """Cost tracking metric."""

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
    """AI analytics and monitoring engine."""

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
        """Initialize analytics database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute()
                    """
                    CREATE TABLE IF NOT EXISTS usage_metrics ()
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        user_id TEXT NOT NULL,
                        model_id TEXT NOT NULL,
                        provider TEXT NOT NULL,
                        tokens_used INTEGER NOT NULL,
                        cost REAL NOT NULL,
                        latency_ms INTEGER NOT NULL,
                        success BOOLEAN NOT NULL,
                        capability TEXT NOT NULL,
                        request_size INTEGER NOT NULL,
                        response_size INTEGER NOT NULL
                    )
                """
                )

                conn.execute()
                    """
                    CREATE TABLE IF NOT EXISTS performance_metrics ()
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        model_id TEXT NOT NULL,
                        provider TEXT NOT NULL,
                        latency_ms INTEGER NOT NULL,
                        success BOOLEAN NOT NULL,
                        error_type TEXT,
                        tokens_per_second REAL
                    )
                """
                )

                conn.execute()
                    """
                    CREATE TABLE IF NOT EXISTS cost_metrics ()
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        user_id TEXT NOT NULL,
                        model_id TEXT NOT NULL,
                        provider TEXT NOT NULL,
                        tokens_used INTEGER NOT NULL,
                        cost REAL NOT NULL,
                        capability TEXT NOT NULL
                    )
                """
                )

                conn.execute()
                    """
                    CREATE TABLE IF NOT EXISTS alert_rules ()
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        condition TEXT NOT NULL,
                        threshold REAL NOT NULL,
                        window_minutes INTEGER NOT NULL,
                        enabled BOOLEAN NOT NULL,
                        notification_channels TEXT NOT NULL,
                        last_triggered TEXT
                    )
                """
                )

                conn.execute()
                    """
                    CREATE TABLE IF NOT EXISTS alert_history ()
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        rule_id TEXT NOT NULL,
                        rule_name TEXT NOT NULL,
                        message TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        resolved BOOLEAN DEFAULT FALSE,
                        resolved_at TEXT
                    )
                """
                )

                # Create indexes for better query performance
                conn.execute()
                    "CREATE INDEX IF NOT EXISTS idx_usage_timestamp ON usage_metrics(timestamp)"
                )
                conn.execute()
                    "CREATE INDEX IF NOT EXISTS idx_usage_user ON usage_metrics(user_id)"
                )
                conn.execute()
                    "CREATE INDEX IF NOT EXISTS idx_usage_model ON usage_metrics(model_id)"
                )
                conn.execute()
                    "CREATE INDEX IF NOT EXISTS idx_performance_timestamp ON performance_metrics(timestamp)"
                )
                conn.execute()
                    "CREATE INDEX IF NOT EXISTS idx_cost_timestamp ON cost_metrics(timestamp)"
                )

                conn.commit()

        except Exception as e:
            logger.error(f"Failed to initialize analytics database: {e}")

    def _load_alert_rules(self):
        """Load alert rules from database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT * FROM alert_rules WHERE enabled = 1")
                for row in cursor.fetchall():
                    rule = AlertRule()
                        id=row[0],
                        name=row[1],
                        condition=row[2],
                        threshold=row[3],
                        window_minutes=row[4],
                        enabled=bool(row[5]),
                        notification_channels=json.loads(row[6]),
                        last_triggered=()
                            datetime.fromisoformat(row[7]) if row[7] else None
                        ),
                    )
                    self.alert_rules[rule.id] = rule

        except Exception as e:
            logger.error(f"Failed to load alert rules: {e}")

    def record_usage(self, metric: UsageMetric):
        """Record usage metric."""
        with self._lock:
            self.usage_buffer.append(metric)
            self.cost_buffer.append()
                CostMetric()
                    timestamp=metric.timestamp,
                    user_id=metric.user_id,
                    model_id=metric.model_id,
                    provider=metric.provider,
                    tokens_used=metric.tokens_used,
                    cost=metric.cost,
                    capability=metric.capability,
                )
            )

    def record_performance(self, metric: PerformanceMetric):
        """Record performance metric."""
        with self._lock:
            self.performance_buffer.append(metric)

    async def flush_metrics(self):
        """Flush buffered metrics to database."""
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

            with sqlite3.connect(self.db_path) as conn:
                # Insert usage metrics
                if usage_metrics:
                    usage_data = [
                        ()
                            m.timestamp.isoformat(),
                            m.user_id,
                            m.model_id,
                            m.provider,
                            m.tokens_used,
                            m.cost,
                            m.latency_ms,
                            m.success,
                            m.capability,
                            m.request_size,
                            m.response_size,
                        )
                        for m in usage_metrics
                    ]

                    conn.executemany()
                        """
                        INSERT INTO usage_metrics
                        (timestamp, user_id, model_id, provider, tokens_used, cost,)
                         latency_ms, success, capability, request_size, response_size)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                        usage_data,
                    )

                # Insert performance metrics
                if performance_metrics:
                    perf_data = [
                        ()
                            m.timestamp.isoformat(),
                            m.model_id,
                            m.provider,
                            m.latency_ms,
                            m.success,
                            m.error_type,
                            m.tokens_per_second,
                        )
                        for m in performance_metrics
                    ]

                    conn.executemany()
                        """
                        INSERT INTO performance_metrics
                        (timestamp, model_id, provider, latency_ms, success, error_type, tokens_per_second)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                        perf_data,
                    )

                # Insert cost metrics
                if cost_metrics:
                    cost_data = [
                        ()
                            m.timestamp.isoformat(),
                            m.user_id,
                            m.model_id,
                            m.provider,
                            m.tokens_used,
                            m.cost,
                            m.capability,
                        )
                        for m in cost_metrics
                    ]

                    conn.executemany()
                        """
                        INSERT INTO cost_metrics
                        (timestamp, user_id, model_id, provider, tokens_used, cost, capability)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                        cost_data,
                    )

                conn.commit()

        except Exception as e:
            logger.error(f"Failed to flush metrics to database: {e}")

    def get_usage_analytics():
        self,
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

            query = """
                SELECT user_id, model_id, provider, capability,
                       COUNT(*) as request_count,
                       SUM(tokens_used) as total_tokens,
                       SUM(cost) as total_cost,
                       AVG(latency_ms) as avg_latency,
                       SUM(CASE WHEN success THEN 1 ELSE 0 END) as successful_requests
                FROM usage_metrics
                WHERE timestamp BETWEEN ? AND ?
            """

            params = [start_time.isoformat(), end_time.isoformat()]

            if user_id:
                query += " AND user_id = ?"
                params.append(user_id)
            if model_id:
                query += " AND model_id = ?"
                params.append(model_id)
            if provider:
                query += " AND provider = ?"
                params.append(provider)

            query += " GROUP BY user_id, model_id, provider, capability"

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(query, params)
                results = cursor.fetchall()

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

                for row in results:
                    ()
                        user_id,
                        model_id,
                        provider,
                        capability,
                        request_count,
                        total_tokens,
                        total_cost,
                        avg_latency,
                        successful_requests,
                    ) = row

                    # Summary
                    analytics["summary"]["total_requests"] += request_count
                    analytics["summary"]["total_tokens"] += total_tokens or 0
                    analytics["summary"]["total_cost"] += total_cost or 0.0

                    total_requests += request_count
                    total_successful += successful_requests
                    total_latency += avg_latency * request_count

                    # By user
                    analytics["by_user"][user_id]["request_count"] += request_count
                    analytics["by_user"][user_id]["total_tokens"] += total_tokens or 0
                    analytics["by_user"][user_id]["total_cost"] += total_cost or 0.0
                    analytics["by_user"][user_id]["models"].add(model_id)

                    # By model
                    analytics["by_model"][model_id]["request_count"] += request_count
                    analytics["by_model"][model_id]["total_tokens"] += total_tokens or 0
                    analytics["by_model"][model_id]["total_cost"] += total_cost or 0.0
                    analytics["by_model"][model_id]["users"].add(user_id)

                    # By provider
                    analytics["by_provider"][provider]["request_count"] += request_count
                    analytics["by_provider"][provider]["total_tokens"] += ()
                        total_tokens or 0
                    )
                    analytics["by_provider"][provider]["total_cost"] += ()
                        total_cost or 0.0
                    )

                # Calculate averages
                if total_requests > 0:
                    analytics["summary"]["avg_latency"] = total_latency / total_requests
                    analytics["summary"]["success_rate"] = ()
                        total_successful / total_requests
                    )

                # Convert sets to lists for JSON serialization
                for user_data in analytics["by_user"].values():
                    user_data["models"] = list(user_data["models"])
                for model_data in analytics["by_model"].values():
                    model_data["users"] = list(model_data["users"])

                return dict(analytics)

        except Exception as e:
            logger.error(f"Failed to get usage analytics: {e}")
            return {}

    def start_monitoring(self):
        """Start background monitoring."""
        if self.monitoring_active:
            return

        self.monitoring_active = True
        self.monitoring_thread = threading.Thread()
            target=self._monitoring_loop, daemon=True
        )
        self.if monitoring_thread and hasattr(monitoring_thread, "start"): monitoring_thread.start()
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
                if ()
                    rule.last_triggered
                    and current_time - rule.last_triggered
                    < timedelta(minutes=rule.window_minutes)
                ):
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
            window_start = datetime.now(timezone.utc) - timedelta()
                minutes=rule.window_minutes
            )

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
                context.update()
                    {
                        "total_requests": len(recent_usage),
                        "total_cost": sum(m.cost for m in recent_usage),
                        "avg_latency": statistics.mean()
                            m.latency_ms for m in recent_usage
                        ),
                        "error_rate": 1
                        - ()
                            sum(1 for m in recent_usage if m.success)
                            / len(recent_usage)
                        ),
                    }
                )

            if recent_performance:
                context.update()
                    {
                        "performance_requests": len(recent_performance),
                        "performance_error_rate": 1
                        - ()
                            sum(1 for m in recent_performance if m.success)
                            / len(recent_performance)
                        ),
                    }
                )

            # Evaluate condition
            return eval(rule.condition, {"__builtins__": {}}, context)

        except Exception as e:
            logger.error(f"Alert condition evaluation error: {e}")
            return False

    def _trigger_alert(self, rule: AlertRule):
        """Trigger alert."""
        try:
            alert_message = f"Alert triggered: {rule.name}"

            # Record alert in history
            with sqlite3.connect(self.db_path) as conn:
                conn.execute()
                    """
                    INSERT INTO alert_history (timestamp, rule_id, rule_name, message, severity)
                    VALUES (?, ?, ?, ?, ?)
                """,
                    ()
                        datetime.now(timezone.utc).isoformat(),
                        rule.id,
                        rule.name,
                        alert_message,
                        "warning",
                    ),
                )
                conn.commit()

            # Add to in-memory history
            self.alert_history.append()
                {
                    "timestamp": datetime.now(timezone.utc),
                    "rule_id": rule.id,
                    "rule_name": rule.name,
                    "message": alert_message,
                    "severity": "warning",
                }
            )

            logger.warning(f"AI Alert: {alert_message}")

        except Exception as e:
            logger.error(f"Alert triggering error: {e}")

    def add_alert_rule(self, rule: AlertRule) -> bool:
        """Add alert rule."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute()
                    """
                    INSERT OR REPLACE INTO alert_rules
                    (id, name, condition, threshold, window_minutes, enabled, notification_channels, last_triggered)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    ()
                        rule.id,
                        rule.name,
                        rule.condition,
                        rule.threshold,
                        rule.window_minutes,
                        rule.enabled,
                        json.dumps(rule.notification_channels),
                        ()
                            rule.last_triggered.isoformat()
                            if rule.last_triggered
                            else None
                        ),
                    ),
                )
                conn.commit()

            self.alert_rules[rule.id] = rule
            return True

        except Exception as e:
            logger.error(f"Failed to add alert rule: {e}")
            return False

    def get_alert_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get alert history."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute()
                    """
                    SELECT timestamp, rule_id, rule_name, message, severity, resolved, resolved_at
                    FROM alert_history
                    ORDER BY timestamp DESC
                    LIMIT ?
                """,
                    (limit,),
                )

                alerts = []
                for row in cursor.fetchall():
                    alerts.append()
                        {
                            "timestamp": row[0],
                            "rule_id": row[1],
                            "rule_name": row[2],
                            "message": row[3],
                            "severity": row[4],
                            "resolved": bool(row[5]),
                            "resolved_at": row[6],
                        }
                    )

                return alerts

        except Exception as e:
            logger.error(f"Failed to get alert history: {e}")
            return []


# Global analytics engine instance
analytics_engine = AIAnalyticsEngine()
