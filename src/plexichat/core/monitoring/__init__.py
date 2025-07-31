"""
PlexiChat Core Monitoring Module

Comprehensive monitoring and analytics system providing:
- Real-time performance monitoring
- System health tracking
- Performance analytics and trends
- Automated alerting
- Dashboard data aggregation
"""

from .performance_analytics import (
    performance_monitor,
    start_performance_monitoring,
    stop_performance_monitoring,
    get_performance_dashboard,
    get_system_health_status,
    record_performance_metric,
    MetricType,
    AlertLevel,
    PerformanceMetric,
    SystemHealthStatus,
    PerformanceAlert
)

__all__ = [
    'performance_monitor',
    'start_performance_monitoring', 
    'stop_performance_monitoring',
    'get_performance_dashboard',
    'get_system_health_status',
    'record_performance_metric',
    'MetricType',
    'AlertLevel',
    'PerformanceMetric',
    'SystemHealthStatus',
    'PerformanceAlert'
]
