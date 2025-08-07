"""
Advanced Analytics Engine

Comprehensive analytics, reporting, and monitoring system.
"""

import statistics
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Union

try:
    from plexichat.core.config import get_config
    settings = get_config() if get_config else None
except ImportError:
    settings = None

try:
    from plexichat.core.logging import get_logger
    logger = get_logger(__name__)
except ImportError:
    logger = None


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
    """Represents an analytics event."""
    event_type: EventType
    timestamp: datetime
    user_id: Optional[int] = None
    session_id: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary."""
        return {
            'event_type': self.event_type.value,
            'timestamp': self.timestamp.isoformat(),
            'user_id': self.user_id,
            'session_id': self.session_id,
            'data': self.data,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent
        }


@dataclass
class MetricData:
    """Represents metric data."""
    name: str
    value: Union[int, float]
    timestamp: datetime
    tags: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metric to dictionary."""
        return {
            'name': self.name,
            'value': self.value,
            'timestamp': self.timestamp.isoformat(),
            'tags': self.tags
        }


class AnalyticsEngine:
    """Advanced analytics engine for comprehensive data collection and analysis."""
    
    def __init__(self, buffer_size: int = 10000):
        self.buffer_size = buffer_size
        self.events_buffer = deque(maxlen=buffer_size)
        self.metrics_buffer = deque(maxlen=buffer_size)
        self.real_time_stats = defaultdict(int)
        self.aggregated_stats = defaultdict(lambda: defaultdict(int))
        self.lock = threading.RLock()
        
        # Performance tracking
        self.performance_metrics = defaultdict(list)
        self.error_counts = defaultdict(int)
        
        # Start background processing
        self._start_background_tasks()
    
    def _start_background_tasks(self):
        """Start background processing tasks."""
        # In a real implementation, these would be proper async tasks
        pass
    
    def track_event(self, event_type: EventType, user_id: Optional[int] = None,
                   session_id: Optional[str] = None, data: Optional[Dict[str, Any]] = None,
                   ip_address: Optional[str] = None, user_agent: Optional[str] = None):
        """Track an analytics event."""
        event = AnalyticsEvent(
            event_type=event_type,
            timestamp=datetime.now(),
            user_id=user_id,
            session_id=session_id,
            data=data or {},
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        with self.lock:
            self.events_buffer.append(event)
            self._update_real_time_stats(event)
    
    def track_metric(self, name: str, value: Union[int, float], 
                    tags: Optional[Dict[str, str]] = None):
        """Track a metric."""
        metric = MetricData(
            name=name,
            value=value,
            timestamp=datetime.now(),
            tags=tags or {}
        )
        
        with self.lock:
            self.metrics_buffer.append(metric)
            self._update_metric_stats(metric)
    
    def _update_real_time_stats(self, event: AnalyticsEvent):
        """Update real-time statistics."""
        # Update event counts
        self.real_time_stats[f"events_{event.event_type.value}"] += 1
        self.real_time_stats["total_events"] += 1
        
        # Update user activity
        if event.user_id:
            self.real_time_stats["active_users"] = len(set(
                e.user_id for e in list(self.events_buffer) 
                if e.user_id and e.timestamp > datetime.now() - timedelta(minutes=5)
            ))
    
    def _update_metric_stats(self, metric: MetricData):
        """Update metric statistics."""
        # Store recent values for statistical analysis
        metric_key = f"metric_{metric.name}"
        if len(self.performance_metrics[metric_key]) >= 100:
            self.performance_metrics[metric_key].pop(0)
        self.performance_metrics[metric_key].append(metric.value)
    
    def get_real_time_stats(self) -> Dict[str, Any]:
        """Get current real-time statistics."""
        with self.lock:
            return dict(self.real_time_stats)
    
    def get_event_stats(self, time_range: timedelta = timedelta(hours=1)) -> Dict[str, Any]:
        """Get event statistics for a time range."""
        cutoff_time = datetime.now() - time_range
        
        with self.lock:
            recent_events = [e for e in self.events_buffer if e.timestamp > cutoff_time]
            
            stats = {
                'total_events': len(recent_events),
                'events_by_type': defaultdict(int),
                'unique_users': set(),
                'unique_sessions': set()
            }
            
            for event in recent_events:
                stats['events_by_type'][event.event_type.value] += 1
                if event.user_id:
                    stats['unique_users'].add(event.user_id)
                if event.session_id:
                    stats['unique_sessions'].add(event.session_id)
            
            stats['unique_users'] = len(stats['unique_users'])
            stats['unique_sessions'] = len(stats['unique_sessions'])
            stats['events_by_type'] = dict(stats['events_by_type'])
            
            return stats
    
    def get_metric_stats(self, metric_name: str) -> Dict[str, Any]:
        """Get statistics for a specific metric."""
        metric_key = f"metric_{metric_name}"
        values = self.performance_metrics.get(metric_key, [])
        
        if not values:
            return {}
        
        return {
            'count': len(values),
            'min': min(values),
            'max': max(values),
            'mean': statistics.mean(values),
            'median': statistics.median(values),
            'std_dev': statistics.stdev(values) if len(values) > 1 else 0
        }
    
    def get_user_activity(self, user_id: int, time_range: timedelta = timedelta(hours=24)) -> Dict[str, Any]:
        """Get activity statistics for a specific user."""
        cutoff_time = datetime.now() - time_range
        
        with self.lock:
            user_events = [e for e in self.events_buffer 
                          if e.user_id == user_id and e.timestamp > cutoff_time]
            
            activity = {
                'total_events': len(user_events),
                'events_by_type': defaultdict(int),
                'first_activity': None,
                'last_activity': None,
                'sessions': set()
            }
            
            if user_events:
                activity['first_activity'] = min(e.timestamp for e in user_events)
                activity['last_activity'] = max(e.timestamp for e in user_events)
                
                for event in user_events:
                    activity['events_by_type'][event.event_type.value] += 1
                    if event.session_id:
                        activity['sessions'].add(event.session_id)
            
            activity['events_by_type'] = dict(activity['events_by_type'])
            activity['session_count'] = len(activity['sessions'])
            del activity['sessions']  # Remove set for JSON serialization
            
            return activity
    
    def get_error_stats(self) -> Dict[str, Any]:
        """Get error statistics."""
        with self.lock:
            return dict(self.error_counts)
    
    def track_error(self, error_type: str, details: Optional[Dict[str, Any]] = None):
        """Track an error occurrence."""
        self.error_counts[error_type] += 1
        
        # Track as an event as well
        self.track_event(
            EventType.ERROR_OCCURRED,
            data={'error_type': error_type, 'details': details or {}}
        )
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get a summary of performance metrics."""
        summary = {}
        
        with self.lock:
            for metric_name, values in self.performance_metrics.items():
                if values:
                    summary[metric_name] = {
                        'current': values[-1],
                        'avg': statistics.mean(values),
                        'min': min(values),
                        'max': max(values),
                        'count': len(values)
                    }
        
        return summary
    
    def clear_buffers(self):
        """Clear all buffers (useful for testing)."""
        with self.lock:
            self.events_buffer.clear()
            self.metrics_buffer.clear()
            self.real_time_stats.clear()
            self.performance_metrics.clear()
            self.error_counts.clear()


# Global analytics engine instance
analytics_engine = AnalyticsEngine()


# Convenience functions
def track_event(event_type: EventType, **kwargs):
    """Track an event using the global analytics engine."""
    analytics_engine.track_event(event_type, **kwargs)


def track_metric(name: str, value: Union[int, float], **kwargs):
    """Track a metric using the global analytics engine."""
    analytics_engine.track_metric(name, value, **kwargs)


def track_error(error_type: str, **kwargs):
    """Track an error using the global analytics engine."""
    analytics_engine.track_error(error_type, **kwargs)


def get_stats():
    """Get current statistics from the global analytics engine."""
    return analytics_engine.get_real_time_stats()
