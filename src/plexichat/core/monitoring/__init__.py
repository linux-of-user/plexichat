"""PlexiChat Monitoring"""

import logging
from typing import Any, Dict

try:
    from .system_monitor import (
        SystemMonitor, SystemMetrics, ApplicationMetrics,
        system_monitor, start_monitoring, stop_monitoring,
        get_system_metrics, get_metrics_history
    )
    logger = logging.getLogger(__name__)
    logger.info("Monitoring modules imported")
except ImportError as e:
    logger = logging.getLogger(__name__)
    logger.warning(f"Could not import monitoring modules: {e}")

__all__ = [
    "SystemMonitor",
    "SystemMetrics",
    "ApplicationMetrics",
    "system_monitor",
    "start_monitoring",
    "stop_monitoring",
    "get_system_metrics",
    "get_metrics_history",
]

__version__ = "1.0.0"
