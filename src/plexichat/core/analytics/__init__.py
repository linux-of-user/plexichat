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
warnings.warn(
    "plexichat.core.analytics is deprecated. Use plexichat.core.monitoring instead.",
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
        AnalyticsEvent as _AnalyticsEvent,
        EventType,

        # Main functions
        track_event as _track_event,
        get_analytics_metrics as _get_analytics_metrics,
    )

    # Create aliases to avoid conflicts
    AnalyticsEvent = _AnalyticsEvent  # type: ignore
    track_event = _track_event  # type: ignore
    get_analytics_metrics = _get_analytics_metrics  # type: ignore

    # Create a proper AnalyticsManager class for this module
    class UnifiedAnalyticsManager:
        def __init__(self):
            self._monitoring_manager = unified_monitoring_manager

        async def track_event(self, event_type: str, **kwargs):
            """Track an event."""
            # Call the imported function directly with required data parameter
            _track_event(event_type, kwargs or {}, None, None)

        async def get_metrics(self, **kwargs) -> Dict[str, Any]:
            """Get metrics."""
            # Call the imported function directly
            return _get_analytics_metrics(**kwargs)

        async def get_user_activity(self, user_id: int, days: int = 30) -> Dict[str, Any]:
            """Get user activity."""
            # This method doesn't exist in the monitoring system, so return mock data
            return {"user_id": user_id, "activity": []}

        async def get_user_engagement(self, user_id: int, days: int = 7) -> Dict[str, Any]:
            """Get user engagement."""
            # This method doesn't exist in the monitoring system, so return mock data
            return {"user_id": user_id, "engagement": 0.0}

    # Create the analytics manager instance
    AnalyticsManager = UnifiedAnalyticsManager  # type: ignore
    analytics_manager = UnifiedAnalyticsManager()

    async def track_event_async(event_type: str, **kwargs):
        """Track an event (async wrapper)."""
        # Call the imported function directly with required data parameter
        _track_event(event_type, kwargs or {}, None, None)

    async def get_analytics_metrics_async(**kwargs) -> Dict[str, Any]:
        """Get analytics metrics (async wrapper)."""
        # Call the imported function directly
        return _get_analytics_metrics(**kwargs)

    async def get_user_analytics(user_id: int, days: int = 30) -> Dict[str, Any]:
        """Get user analytics (backward compatibility)."""
        return {"user_id": user_id, "days": days, "events": []}

    async def get_user_engagement_metrics(user_id: int, days: int = 7) -> Dict[str, Any]:
        """Get user engagement metrics (backward compatibility)."""
        return {"user_id": user_id, "engagement_score": 0.0}

    # Create synchronous wrappers for backward compatibility
    def track_event(event_type: str, **kwargs):
        """Track an event (sync wrapper)."""
        _track_event(event_type, kwargs or {}, None, None)

    def get_analytics_metrics(**kwargs) -> Dict[str, Any]:
        """Get analytics metrics (sync wrapper)."""
        return _get_analytics_metrics(**kwargs)

except ImportError as e:
    logger.error(f"Failed to import from unified monitoring system: {e}")

    # Fallback definitions
    class AnalyticsEvent:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    class FallbackAnalyticsManager:
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

    # Create alias and instance for backward compatibility
    AnalyticsManager = FallbackAnalyticsManager  # type: ignore
    analytics_manager = FallbackAnalyticsManager()

    def track_event(event_type: str, **kwargs):
        """Track an event (sync wrapper)."""
        logger.debug(f"Tracking event: {event_type}")

    def get_analytics_metrics(**kwargs) -> Dict[str, Any]:
        """Get analytics metrics (sync wrapper)."""
        return {"events_processed": 0}

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
