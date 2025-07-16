"""PlexiChat Analytics"""

import logging
from typing import Any, Dict, List, Optional
from datetime import datetime

try:
    from .analytics_manager import (
        AnalyticsManager, AnalyticsEvent,
        analytics_manager, track_event, get_analytics_metrics,
        get_user_analytics, get_user_engagement_metrics
    )
    logger = logging.getLogger(__name__)
    logger.info("Analytics modules imported")
except ImportError as e:
    logger = logging.getLogger(__name__)
    logger.warning(f"Could not import analytics modules: {e}")

__all__ = [
    "AnalyticsManager",
    "AnalyticsEvent",
    "analytics_manager",
    "track_event",
    "get_analytics_metrics",
    "get_user_analytics",
    "get_user_engagement_metrics",
]

__version__ = "1.0.0"
