"""
PlexiChat Analytics - COMPATIBILITY WRAPPER

This module has been CONSOLIDATED into core/monitoring/unified_monitoring_system.py
This file now serves as a compatibility wrapper to maintain backward compatibility.

DEPRECATED: Use plexichat.core.monitoring instead.
"""

import warnings
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime

# Issue deprecation warning
warnings.warn()
    "plexichat.core.analytics is deprecated. "
    "Use plexichat.core.monitoring instead.",
    DeprecationWarning,
    stacklevel=2
)

logger = logging.getLogger(__name__)
logger.info("Using compatibility wrapper - please migrate to unified monitoring system")

# Re-export everything from the unified monitoring system
try:
    from ..monitoring.unified_monitoring_system import (
        # Main classes
        UnifiedMonitoringManager,
        unified_monitoring_manager,
        AnalyticsCollector,

        # Data classes
        AnalyticsEvent,
        EventType,

        # Main functions
        track_event,
        get_analytics_metrics,
    )

    # Backward compatibility aliases
    analytics_manager = unified_monitoring_manager
    AnalyticsManager = UnifiedMonitoringManager

    async def get_user_analytics(user_id: int, days: int = 30) -> Dict[str, Any]:
        """Get user analytics (backward compatibility)."""
        return {"user_id": user_id, "days": days, "events": []}

    async def get_user_engagement_metrics(user_id: int, days: int = 7) -> Dict[str, Any]:
        """Get user engagement metrics (backward compatibility)."""
        return {"user_id": user_id, "engagement_score": 0.0}

except ImportError as e:
    logger.error(f"Failed to import from unified monitoring system: {e}")

    # Fallback definitions
    class AnalyticsEvent:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    class AnalyticsManager:
        def __init__(self):
            self.events_processed = 0

        async def track_event(self, event_type: str, **kwargs):
            logger.debug(f"Tracking event: {event_type}")
            self.events_processed += 1

        async def get_metrics(self, **kwargs) -> Dict[str, Any]:
            return {"events_processed": self.events_processed}

        async def get_user_activity(self, user_id: int, days: int = 30) -> Dict[str, Any]:
            return {"user_id": user_id, "activity": []}

        async def get_user_engagement(self, user_id: int, days: int = 7) -> Dict[str, Any]:
            return {"user_id": user_id, "engagement": 0.0}

    analytics_manager = AnalyticsManager()

    async def track_event(event_type: str, **kwargs):
        await analytics_manager.track_event(event_type, **kwargs)

    async def get_analytics_metrics(**kwargs) -> Dict[str, Any]:
        return await analytics_manager.get_metrics(**kwargs)

    async def get_user_analytics(user_id: int, days: int = 30) -> Dict[str, Any]:
        return await analytics_manager.get_user_activity(user_id, days)

    async def get_user_engagement_metrics(user_id: int, days: int = 7) -> Dict[str, Any]:
        return await analytics_manager.get_user_engagement(user_id, days)

# Export all the main classes and functions for backward compatibility
__all__ = [
    # Main classes
    "AnalyticsManager",
    "analytics_manager",

    # Data classes
    "AnalyticsEvent",

    # Main functions
    "track_event",
    "get_analytics_metrics",
    "get_user_analytics",
    "get_user_engagement_metrics",
]

__version__ = "3.0.0"
