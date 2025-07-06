"""
NetLink Backup Services

Service layer components for the government-level backup system:
- Status monitoring and health checks
- Background task management
- API integration services
- Performance monitoring
- Alerting and notification services
"""

from .status_monitor import (
    BackupStatusMonitor,
    BackupCoverageReport,
    DeviceStatus,
    ShardStatus,
    PerformanceMetrics,
    BackupHealthStatus,
    RedundancyLevel,
    backup_status_monitor
)

__version__ = "2.0.0"
__all__ = [
    # Status monitoring
    "BackupStatusMonitor",
    "BackupCoverageReport", 
    "DeviceStatus",
    "ShardStatus",
    "PerformanceMetrics",
    "BackupHealthStatus",
    "RedundancyLevel",
    "backup_status_monitor"
]
