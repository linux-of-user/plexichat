"""
PlexiChat Analytics Manager

Analytics system with threading and performance optimization.
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from dataclasses import dataclass
from uuid import uuid4

try:
    from plexichat.core.database.manager import database_manager
except ImportError:
    database_manager = None

try:
    from plexichat.core.threading.thread_manager import async_thread_manager, submit_task
except ImportError:
    async_thread_manager = None
    submit_task = None

try:
    from plexichat.core.caching.cache_manager import cache_get, cache_set
except ImportError:
    cache_get = None
    cache_set = None

try:
    from plexichat.infrastructure.performance.optimization_engine import PerformanceOptimizationEngine
    from plexichat.core.logging_advanced.performance_logger import get_performance_logger
except ImportError:
    PerformanceOptimizationEngine = None
    get_performance_logger = None

logger = logging.getLogger(__name__)
performance_logger = get_performance_logger() if get_performance_logger else None

@dataclass
class AnalyticsEvent:
    """Analytics event data."""
    event_id: str
    event_type: str
    user_id: Optional[int]
    session_id: Optional[str]
    timestamp: datetime
    properties: Dict[str, Any]
    context: Dict[str, Any]

class AnalyticsManager:
    """Analytics manager with threading support."""
    
    def __init__(self):
        self.db_manager = database_manager
        self.performance_logger = performance_logger
        self.async_thread_manager = async_thread_manager
        
        # Event queue
        self.event_queue = asyncio.Queue()
        self.processing = False
        
        # Statistics
        self.events_processed = 0
        self.events_failed = 0
    
    async def start_processing(self):
        """Start analytics processing loop."""
        if self.processing:
            return
        
        self.processing = True
        asyncio.create_task(self._processing_loop())
        logger.info("Analytics processor started")
    
    async def stop_processing(self):
        """Stop analytics processing."""
        self.processing = False
        logger.info("Analytics processor stopped")
    
    async def _processing_loop(self):
        """Main analytics processing loop."""
        while self.processing:
            try:
                # Get event from queue with timeout
                event = await asyncio.wait_for(self.event_queue.get(), timeout=1.0)
                
                # Process event
                if self.async_thread_manager:
                    await self.async_thread_manager.run_in_thread(
                        self._process_event_sync, event
                    )
                else:
                    await self._process_event(event)
                
                self.event_queue.task_done()
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Analytics processing error: {e}")
    
    def _process_event_sync(self, event: AnalyticsEvent):
        """Process event synchronously for threading."""
        try:
            asyncio.create_task(self._process_event(event))
        except Exception as e:
            logger.error(f"Error in sync event processing: {e}")
    
    async def _process_event(self, event: AnalyticsEvent):
        """Process individual analytics event."""
        try:
            start_time = time.time()
            
            # Store event in database
            await self._store_event(event)
            
            # Update aggregated metrics
            await self._update_metrics(event)
            
            # Performance tracking
            if self.performance_logger:
                duration = time.time() - start_time
                self.performance_logger.record_metric("analytics_event_processing_duration", duration, "seconds")
                self.performance_logger.record_metric("analytics_events_processed", 1, "count")
            
            self.events_processed += 1
            
        except Exception as e:
            logger.error(f"Error processing analytics event {event.event_id}: {e}")
            self.events_failed += 1
            if self.performance_logger:
                self.performance_logger.record_metric("analytics_processing_errors", 1, "count")
    
    async def _store_event(self, event: AnalyticsEvent):
        """Store analytics event in database."""
        try:
            if self.db_manager:
                query = """
                    INSERT INTO analytics_events (
                        event_id, event_type, user_id, session_id,
                        timestamp, properties, context
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """
                params = {
                    "event_id": event.event_id,
                    "event_type": event.event_type,
                    "user_id": event.user_id,
                    "session_id": event.session_id,
                    "timestamp": event.timestamp,
                    "properties": json.dumps(event.properties),
                    "context": json.dumps(event.context)
                }
                await self.db_manager.execute_query(query, params)
        except Exception as e:
            logger.error(f"Error storing analytics event: {e}")
    
    async def _update_metrics(self, event: AnalyticsEvent):
        """Update aggregated metrics."""
        try:
            if self.db_manager:
                # Update daily metrics
                date_key = event.timestamp.date()
                
                query = """
                    INSERT OR REPLACE INTO analytics_daily_metrics (
                        date, event_type, count, last_updated
                    ) VALUES (?, ?, COALESCE((SELECT count FROM analytics_daily_metrics WHERE date = ? AND event_type = ?), 0) + 1, ?)
                """
                params = {
                    "date": date_key,
                    "event_type": event.event_type,
                    "date2": date_key,
                    "event_type2": event.event_type,
                    "last_updated": datetime.now()
                }
                await self.db_manager.execute_query(query, params)
        except Exception as e:
            logger.error(f"Error updating metrics: {e}")
    
    async def track_event(self, event_type: str, user_id: Optional[int] = None,
                         session_id: Optional[str] = None, properties: Dict[str, Any] = None,
                         context: Dict[str, Any] = None) -> str:
        """Track analytics event."""
        try:
            event_id = str(uuid4())
            
            event = AnalyticsEvent(
                event_id=event_id,
                event_type=event_type,
                user_id=user_id,
                session_id=session_id,
                timestamp=datetime.now(),
                properties=properties or {},
                context=context or {}
            )
            
            # Queue for processing
            await self.event_queue.put(event)
            
            return event_id
            
        except Exception as e:
            logger.error(f"Error tracking event: {e}")
            raise
    
    async def get_metrics(self, start_date: datetime, end_date: datetime,
                         event_types: Optional[List[str]] = None) -> Dict[str, Any]:
        """Get analytics metrics."""
        try:
            if not self.db_manager:
                return {}
            
            # Build query
            query = """
                SELECT event_type, SUM(count) as total_count
                FROM analytics_daily_metrics
                WHERE date >= ? AND date <= ?
            """
            params = {"start_date": start_date.date(), "end_date": end_date.date()}
            
            if event_types:
                placeholders = ','.join(['?' for _ in event_types])
                query += f" AND event_type IN ({placeholders})"
                for i, event_type in enumerate(event_types):
                    params[f"event_type_{i}"] = event_type
            
            query += " GROUP BY event_type ORDER BY total_count DESC"
            
            result = await self.db_manager.execute_query(query, params)
            
            metrics = {}
            for row in result:
                metrics[row[0]] = row[1]
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error getting metrics: {e}")
            return {}
    
    async def get_user_activity(self, user_id: int, days: int = 30) -> Dict[str, Any]:
        """Get user activity metrics."""
        try:
            if not self.db_manager:
                return {}
            
            start_date = datetime.now() - timedelta(days=days)
            
            query = """
                SELECT event_type, COUNT(*) as count, DATE(timestamp) as date
                FROM analytics_events
                WHERE user_id = ? AND timestamp >= ?
                GROUP BY event_type, DATE(timestamp)
                ORDER BY date DESC
            """
            params = {"user_id": user_id, "start_date": start_date}
            
            result = await self.db_manager.execute_query(query, params)
            
            activity = {}
            for row in result:
                event_type, count, date = row
                if date not in activity:
                    activity[date] = {}
                activity[date][event_type] = count
            
            return activity
            
        except Exception as e:
            logger.error(f"Error getting user activity: {e}")
            return {}
    
    async def get_popular_content(self, content_type: str = "message", limit: int = 10) -> List[Dict[str, Any]]:
        """Get popular content based on analytics."""
        try:
            if not self.db_manager:
                return []
            
            query = """
                SELECT properties, COUNT(*) as interaction_count
                FROM analytics_events
                WHERE event_type = ? AND JSON_EXTRACT(properties, '$.content_id') IS NOT NULL
                GROUP BY JSON_EXTRACT(properties, '$.content_id')
                ORDER BY interaction_count DESC
                LIMIT ?
            """
            params = {"event_type": f"{content_type}_interaction", "limit": limit}
            
            result = await self.db_manager.execute_query(query, params)
            
            popular_content = []
            for row in result:
                properties = json.loads(row[0])
                popular_content.append({
                    "content_id": properties.get("content_id"),
                    "interaction_count": row[1],
                    "properties": properties
                })
            
            return popular_content
            
        except Exception as e:
            logger.error(f"Error getting popular content: {e}")
            return []
    
    async def get_user_engagement(self, user_id: int, days: int = 7) -> Dict[str, Any]:
        """Get user engagement metrics."""
        try:
            if not self.db_manager:
                return {}
            
            start_date = datetime.now() - timedelta(days=days)
            
            # Get session count
            session_query = """
                SELECT COUNT(DISTINCT session_id) as session_count
                FROM analytics_events
                WHERE user_id = ? AND timestamp >= ?
            """
            
            # Get total events
            events_query = """
                SELECT COUNT(*) as total_events
                FROM analytics_events
                WHERE user_id = ? AND timestamp >= ?
            """
            
            # Get unique days active
            days_query = """
                SELECT COUNT(DISTINCT DATE(timestamp)) as active_days
                FROM analytics_events
                WHERE user_id = ? AND timestamp >= ?
            """
            
            params = {"user_id": user_id, "start_date": start_date}
            
            session_result = await self.db_manager.execute_query(session_query, params)
            events_result = await self.db_manager.execute_query(events_query, params)
            days_result = await self.db_manager.execute_query(days_query, params)
            
            return {
                "session_count": session_result[0][0] if session_result else 0,
                "total_events": events_result[0][0] if events_result else 0,
                "active_days": days_result[0][0] if days_result else 0,
                "period_days": days
            }
            
        except Exception as e:
            logger.error(f"Error getting user engagement: {e}")
            return {}
    
    def get_stats(self) -> Dict[str, Any]:
        """Get analytics statistics."""
        return {
            "events_processed": self.events_processed,
            "events_failed": self.events_failed,
            "queue_size": self.event_queue.qsize(),
            "processing": self.processing
        }

# Global analytics manager
analytics_manager = AnalyticsManager()

# Convenience functions
async def track_event(event_type: str, user_id: Optional[int] = None, **kwargs) -> str:
    """Track event using global analytics manager."""
    return await analytics_manager.track_event(event_type, user_id, **kwargs)

async def get_analytics_metrics(start_date: datetime, end_date: datetime, event_types: Optional[List[str]] = None) -> Dict[str, Any]:
    """Get metrics using global analytics manager."""
    return await analytics_manager.get_metrics(start_date, end_date, event_types)

async def get_user_analytics(user_id: int, days: int = 30) -> Dict[str, Any]:
    """Get user analytics using global analytics manager."""
    return await analytics_manager.get_user_activity(user_id, days)

async def get_user_engagement_metrics(user_id: int, days: int = 7) -> Dict[str, Any]:
    """Get user engagement using global analytics manager."""
    return await analytics_manager.get_user_engagement(user_id, days)
