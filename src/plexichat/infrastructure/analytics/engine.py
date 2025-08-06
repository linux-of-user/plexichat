# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import statistics
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Union

try:
    from plexichat.core.config import get_config
    from plexichat.core.logging import get_logger
    settings = get_config()
    logger = get_logger(__name__)
except ImportError:
    settings = None
    logger = print

"""
Advanced Analytics Engine
Comprehensive analytics, reporting, and monitoring system.


class EventType(Enum):
    """Analytics event types."""
        USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    USER_REGISTER = "user_register"
    MESSAGE_SENT = "message_sent"
    MESSAGE_RECEIVED = "message_received"
    FILE_UPLOAD = "file_upload"
    FILE_DOWNLOAD = "file_download"
    API_REQUEST = "api_request"
    ERROR_OCCURRED = "error_occurred"
    SYSTEM_METRIC = "system_metric"
    PERFORMANCE_METRIC = "performance_metric"

@dataclass
class AnalyticsEvent:
    """Represents an analytics event.
    event_type: EventType
    timestamp: datetime
    user_id: Optional[int] = None
    session_id: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    endpoint: Optional[str] = None
    duration_ms: Optional[float] = None

@dataclass
class MetricSnapshot:
    """Represents a metric snapshot."""
        name: str
    value: Union[int, float]
    unit: str
    timestamp: datetime
    tags: Dict[str, str] = field(default_factory=dict)

class RealTimeMetrics:
    Real-time metrics collector."""
        def __init__(self, window_size: int = 300):  # 5 minutes
        self.window_size = window_size
        self.metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=window_size))
        self.counters: Dict[str, int] = defaultdict(int)
        self.gauges: Dict[str, float] = defaultdict(float)
        self.histograms: Dict[str, List[float]] = defaultdict(list)
        self.lock = threading.Lock()

    def increment_counter(self, name: str, value: int = 1, tags: Dict[str, str] = None):
        """Increment a counter metric.
        with self.lock:
            key = self._make_key(name, tags)
            self.counters[key] += value

    def set_gauge(self, name: str, value: float, tags: Dict[str, str] = None):
        """Set a gauge metric."""
        with self.lock:
            key = self._make_key(name, tags)
            self.gauges[key] = value

    def record_histogram(self, name: str, value: float, tags: Dict[str, str] = None):
        Record a histogram value."""
        with self.lock:
            key = self._make_key(name, tags)
            self.histograms[key].append(value)

            # Keep only recent values (last 1000)
            if len(self.histograms[key]) > 1000:
                self.histograms[key] = self.histograms[key][-1000:]

    def record_timing(self, name: str, duration_ms: float, tags: Dict[str, str] = None):
        """Record timing metric."""
        self.record_histogram(f"{name}.duration", duration_ms, tags)

    def _make_key(self, name: str, tags: Dict[str, str] = None) -> str:
        """Create metric key with tags."""
        if not tags:
            return name
        tag_str = ",".join(f"{k}={v}" for k, v in sorted(tags.items()))
        return f"{name}[{tag_str}]"

    def get_counter(self, name: str, tags: Dict[str, str] = None) -> int:
        """Get counter value.
        key = self._make_key(name, tags)
        return self.counters.get(key, 0)

    def get_gauge(self, name: str, tags: Dict[str, str] = None) -> float:
        """Get gauge value."""
        key = self._make_key(name, tags)
        return self.gauges.get(key, 0.0)

    def get_histogram_stats(self, name: str, tags: Dict[str, str] = None) -> Dict[str, float]:
        Get histogram statistics."""
        key = self._make_key(name, tags)
        values = self.histograms.get(key, [])

        if not values:
            return {"count": 0, "min": 0, "max": 0, "mean": 0, "p50": 0, "p95": 0, "p99": 0}

        sorted_values = sorted(values)
        count = len(sorted_values)

        return {
            "count": count,
            "min": min(sorted_values),
            "max": max(sorted_values),
            "mean": statistics.mean(sorted_values),
            "p50": sorted_values[int(count * 0.5)] if count > 0 else 0,
            "p95": sorted_values[int(count * 0.95)] if count > 0 else 0,
            "p99": sorted_values[int(count * 0.99)] if count > 0 else 0
        }}

class AnalyticsCollector:
    """Collects and processes analytics events."""
        def __init__(self):
        self.events: deque = deque(maxlen=10000)  # Keep last 10k events
        self.metrics = RealTimeMetrics()
        self.session_data: Dict[str, Dict[str, Any]] = {}
        self.user_sessions: Dict[int, List[str]] = defaultdict(list)
        self.endpoint_stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "count": 0,
            "total_duration": 0,
            "error_count": 0,
            "last_accessed": None
        })

    async def track_event(self, event: AnalyticsEvent):
        """Track an analytics event."""
        try:
            # Store event
            self.events.append(event)

            # Update metrics
            self._update_metrics(event)

            # Update session data
            if event.session_id:
                self._update_session_data(event)

            # Update endpoint stats
            if event.endpoint:
                self._update_endpoint_stats(event)

            logger.debug(f"Tracked event: {event.event_type.value}")

        except Exception as e:
            logger.error(f"Failed to track event: {e}")

    def _update_metrics(self, event: AnalyticsEvent):
        """Update real-time metrics."""
        # Increment event counter
        self.metrics.increment_counter(
            "events.total",
            tags={"type": event.event_type.value}
        )

        # Track user activity
        if event.user_id:
            self.metrics.increment_counter()
                "users.active",
                tags={"user_id": str(event.user_id)}
            )

        # Track API requests
        if event.event_type == EventType.API_REQUEST:
            self.metrics.increment_counter("api.requests.total")

            if event.duration_ms:
                self.metrics.record_timing("api.request", event.duration_ms)

        # Track errors
        if event.event_type == EventType.ERROR_OCCURRED:
            self.metrics.increment_counter("errors.total")

    def _update_session_data(self, event: AnalyticsEvent):
        """Update session tracking data."""
        session_id = event.session_id

        if session_id not in self.session_data:
            self.session_data[session_id] = {
                "start_time": event.timestamp,
                "last_activity": event.timestamp,
                "event_count": 0,
                "user_id": event.user_id,
                "ip_address": event.ip_address,
                "user_agent": event.user_agent
            }

            # Track user sessions
            if event.user_id:
                self.user_sessions[event.user_id].append(session_id)

        # Update session
        session = self.session_data[session_id]
        session["last_activity"] = event.timestamp
        session["event_count"] += 1

    def _update_endpoint_stats(self, event: AnalyticsEvent):
        """Update endpoint statistics."""
        endpoint = event.endpoint
        stats = self.endpoint_stats[endpoint]

        stats["count"] += 1
        stats["last_accessed"] = event.timestamp

        if event.duration_ms:
            stats["total_duration"] += event.duration_ms

        if event.event_type == EventType.ERROR_OCCURRED:
            stats["error_count"] += 1

    def get_real_time_stats(self) -> Dict[str, Any]:
        """Get real-time statistics."""
now = datetime.now()
datetime.utcnow()

        # Active sessions (last 30 minutes)
        active_sessions = sum()
            1 for session in self.session_data.values()
            if (now - session["last_activity"]).total_seconds() < 1800
        )

        # Recent events (last 10 minutes)
        recent_events = sum()
            1 for event in self.events
            if (now - event.timestamp).total_seconds() < 600
        )

        return {
            "timestamp": now.isoformat(),
            "active_sessions": active_sessions,
            "total_sessions": len(self.session_data),
            "recent_events": recent_events,
            "total_events": len(self.events),
            "api_requests": self.metrics.get_counter("api.requests.total"),
            "errors": self.metrics.get_counter("errors.total"),
            "request_timing": self.metrics.get_histogram_stats("api.request.duration")
        }}

    def get_endpoint_analytics(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get endpoint analytics."""
        endpoint_list = []

        for endpoint, stats in self.endpoint_stats.items():
            avg_duration = ()
                stats["total_duration"] / stats["count"]
                if stats["count"] > 0 else 0
            )

            error_rate = ()
                stats["error_count"] / stats["count"] * 100
                if stats["count"] > 0 else 0
            )

            endpoint_list.append({)
                "endpoint": endpoint,
                "request_count": stats["count"],
                "error_count": stats["error_count"],
                "error_rate": round(error_rate, 2),
                "avg_duration_ms": round(avg_duration, 2),
                "last_accessed": stats["last_accessed"].isoformat() if stats["last_accessed"] else None
            })

        # Sort by request count
        endpoint_list.sort(key=lambda x: x["request_count"], reverse=True)
        return endpoint_list[:limit]

    def get_user_analytics(self, user_id: int) -> Dict[str, Any]:
        """Get analytics for a specific user."""
        user_events = [e for e in self.events if e.user_id == user_id]
        user_sessions = self.user_sessions.get(user_id, [])

        if not user_events:
            return {"user_id": user_id, "total_events": 0, "sessions": 0}

        first_event = min(user_events, key=lambda e: e.timestamp)
        last_event = max(user_events, key=lambda e: e.timestamp)

        # Event type breakdown
        event_types = defaultdict(int)
        for event in user_events:
            event_types[event.event_type.value] += 1

        return {
            "user_id": user_id,
            "total_events": len(user_events),
            "sessions": len(user_sessions),
            "first_activity": first_event.timestamp.isoformat(),
            "last_activity": last_event.timestamp.isoformat(),
            "event_breakdown": dict(event_types)
        }}

class AnalyticsDashboard:
    """Analytics dashboard data provider.
        def __init__(self, collector: AnalyticsCollector):
        self.collector = collector

    async def get_dashboard_data(self) -> Dict[str, Any]:
        """Get comprehensive dashboard data."""
now = datetime.now()
datetime.utcnow()

        # Time ranges
        last_hour = now - timedelta(hours=1)
        last_day = now - timedelta(days=1)
        last_week = now - timedelta(weeks=1)

        # Filter events by time
        events_last_hour = [e for e in self.collector.events if e.timestamp >= last_hour]
        events_last_day = [e for e in self.collector.events if e.timestamp >= last_day]
        events_last_week = [e for e in self.collector.events if e.timestamp >= last_week]

        # User activity
        unique_users_hour = len(set(e.user_id for e in events_last_hour if e.user_id))
        unique_users_day = len(set(e.user_id for e in events_last_day if e.user_id))
        unique_users_week = len(set(e.user_id for e in events_last_week if e.user_id))

        # Event breakdown
        event_breakdown = defaultdict(int)
        for event in events_last_day:
            event_breakdown[event.event_type.value] += 1

        return {
            "overview": {
                "total_events": len(self.collector.events),
                "active_sessions": self.collector.get_real_time_stats()["active_sessions"],
                "unique_users_hour": unique_users_hour,
                "unique_users_day": unique_users_day,
                "unique_users_week": unique_users_week
            }},
            "activity": {
                "events_last_hour": len(events_last_hour),
                "events_last_day": len(events_last_day),
                "events_last_week": len(events_last_week)
            },
            "event_breakdown": dict(event_breakdown),
            "top_endpoints": self.collector.get_endpoint_analytics(10),
            "real_time_stats": self.collector.get_real_time_stats(),
            "timestamp": now.isoformat()
        }

    async def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics."""
        return {
            "api_timing": self.collector.metrics.get_histogram_stats("api.request.duration"),
            "error_rate": self._calculate_error_rate(),
            "throughput": self._calculate_throughput(),
            "response_codes": self._get_response_code_breakdown()
        }}

    def _calculate_error_rate(self) -> float:
        """Calculate error rate."""
        total_requests = self.collector.metrics.get_counter("api.requests.total")
        total_errors = self.collector.metrics.get_counter("errors.total")

        if total_requests == 0:
            return 0.0

        return (total_errors / total_requests) * 100

    def _calculate_throughput(self) -> Dict[str, float]:
        """Calculate request throughput."""
now = datetime.now()
datetime.utcnow()

        # Requests in last minute
        last_minute = now - timedelta(minutes=1)
        requests_last_minute = sum()
            1 for event in self.collector.events
            if event.event_type == EventType.API_REQUEST and event.timestamp >= last_minute
        )

        # Requests in last hour
        last_hour = now - timedelta(hours=1)
        requests_last_hour = sum()
            1 for event in self.collector.events
            if event.event_type == EventType.API_REQUEST and event.timestamp >= last_hour
        )

        return {
            "requests_per_minute": requests_last_minute,
            "requests_per_hour": requests_last_hour
        }}

    def _get_response_code_breakdown(self) -> Dict[str, int]:
        """Get response code breakdown."""
        # This would need to be tracked in events
        # For now, return placeholder data
        return {
            "2xx": 0,
            "3xx": 0,
            "4xx": 0,
            "5xx": 0
        }}

class AnalyticsEngine:
    """Main analytics engine.
        def __init__(self):
        self.collector = AnalyticsCollector()
        self.dashboard = AnalyticsDashboard(self.collector)
        self.enabled = getattr(settings, 'ANALYTICS_ENABLED', True)

    async def track_event(self, event_type: EventType, **kwargs):
        """Track an analytics event."""
        if not self.enabled:
            return

        event = AnalyticsEvent()
            event_type=event_type,
timestamp = datetime.now()
datetime.utcnow(),
            **kwargs
        )

        await self.collector.track_event(event)

    async def track_api_request(self, endpoint: str, method: str, status_code: int,)
                            duration_ms: float, user_id: Optional[int] = None,
                            session_id: Optional[str] = None, ip_address: Optional[str] = None):
        Track API request."""
        await self.track_event()
            EventType.API_REQUEST,
            endpoint=f"{method} {endpoint}",
            duration_ms=duration_ms,
            user_id=user_id,
            session_id=session_id,
            ip_address=ip_address,
            data={"status_code": status_code, "method": method}
        )

    async def track_user_action(self, action: str, user_id: int,)
                            session_id: Optional[str] = None, **data):
        """Track user action."""
        event_type_map = {
            "login": EventType.USER_LOGIN,
            "logout": EventType.USER_LOGOUT,
            "register": EventType.USER_REGISTER,
            "message_sent": EventType.MESSAGE_SENT,
            "file_upload": EventType.FILE_UPLOAD,
            "file_download": EventType.FILE_DOWNLOAD
        }

        event_type = event_type_map.get(action, EventType.API_REQUEST)

        await self.track_event()
            event_type,
            user_id=user_id,
            session_id=session_id,
            data=data
        )

    async def get_analytics_data(self) -> Dict[str, Any]:
        """Get comprehensive analytics data.
        return await self.dashboard.get_dashboard_data()

    async def get_user_analytics(self, user_id: int) -> Dict[str, Any]:
        """Get analytics for specific user."""
        return self.collector.get_user_analytics(user_id)

# Global analytics engine instance
analytics_engine = AnalyticsEngine()
