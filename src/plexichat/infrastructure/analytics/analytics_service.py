"""
PlexiChat Analytics Service

Provides comprehensive analytics and metrics collection for the PlexiChat platform.
"""

import asyncio
import json
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional


try:
    import redis.asyncio as redis
except ImportError:
    redis = None

try:
    from plexichat.core.database.manager import database_manager as db_cluster
except ImportError:
    db_cluster = None

try:
    from plexichat.core.logging.logger import get_logger
    logger = get_logger(__name__)
except ImportError:
    logger = None

try:
    from plexichat.shared.models import Channel, FileRecord, Message, Guild, GuildMember, User
except ImportError:
    Channel = None
    FileRecord = None
    Message = None
    Guild = None
    GuildMember = None
    User = None

try:
    from sqlmodel import Session, and_, func, select
except ImportError:
    Session = None
    and_ = None
    func = None
    select = None


# Constants
METRICS_BUFFER_SIZE = 10000
METRICS_BATCH_SIZE = 100
METRICS_PROCESS_INTERVAL = 10
STATS_UPDATE_INTERVAL = 30
REDIS_EXPIRE_TIME = 86400 * 7  # 7 days


class MetricType(str, Enum):
    """Types of metrics."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"


class TimeRange(str, Enum):
    """Time range options."""
    HOUR = "1h"
    DAY = "1d"
    WEEK = "1w"
    MONTH = "1m"
    YEAR = "1y"


@dataclass
class Metric:
    """Metric data structure."""
    name: str
    type: MetricType
    value: float
    timestamp: datetime
    tags: Optional[Dict[str, str]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'type': self.type,
            'value': self.value,
            'timestamp': self.timestamp.isoformat(),
            'tags': self.tags or {}
        }


class AnalyticsService:
    """Comprehensive analytics service."""
    
    def __init__(self):
        self.metrics_buffer = deque(maxlen=METRICS_BUFFER_SIZE)
        self.real_time_stats = defaultdict(float)
        self.redis_client = None
        
        # Initialize Redis connection
        asyncio.create_task(self._initialize_redis())
        
        # Start background tasks
        asyncio.create_task(self._metrics_processor())
        asyncio.create_task(self._real_time_updater())

    async def _initialize_redis(self):
        """Initialize Redis connection for caching."""
        try:
            if redis:
                self.redis_client = redis.from_url(
                    'redis://localhost:6379',
                    decode_responses=True
                )
                await self.redis_client.ping()
                if logger:
                    logger.info("Analytics Redis connection established")
        except Exception as e:
            if logger:
                logger.warning(f"Redis connection failed, using in-memory storage: {e}")

    async def record_metric(self, name: str, value: float,
                          metric_type: MetricType = MetricType.COUNTER,
                          tags: Optional[Dict[str, str]] = None):
        """Record a metric."""
        metric = Metric(
            name=name,
            type=metric_type,
            value=value,
            timestamp=datetime.now(),
            tags=tags
        )

        self.metrics_buffer.append(metric)

        # Update real-time stats
        if metric_type == MetricType.COUNTER:
            self.real_time_stats[name] += value
        elif metric_type == MetricType.GAUGE:
            self.real_time_stats[name] = value

    async def _metrics_processor(self):
        """Background task to process metrics."""
        while True:
            try:
                await asyncio.sleep(METRICS_PROCESS_INTERVAL)

                if not self.metrics_buffer:
                    continue

                # Batch process metrics
                metrics_batch = []
                while self.metrics_buffer and len(metrics_batch) < METRICS_BATCH_SIZE:
                    metrics_batch.append(self.metrics_buffer.popleft())

                await self._store_metrics(metrics_batch)

            except Exception as e:
                if logger:
                    logger.error(f"Metrics processor error: {e}")

    async def _store_metrics(self, metrics: List[Metric]):
        """Store metrics in database and cache."""
        try:
            # Store in Redis for fast access
            if self.redis_client:
                pipe = self.redis_client.pipeline()

                for metric in metrics:
                    key = f"metric:{metric.name}:{metric.timestamp.strftime('%Y%m%d%H')}"
                    pipe.lpush(key, json.dumps(metric.to_dict()))
                    pipe.expire(key, REDIS_EXPIRE_TIME)

                await pipe.execute()

            # Store aggregated data in database
            await self._store_aggregated_metrics(metrics)

        except Exception as e:
            if logger:
                logger.error(f"Failed to store metrics: {e}")

    async def _store_aggregated_metrics(self, metrics: List[Metric]):
        """Store aggregated metrics in database."""
        # Group metrics by name and hour
        aggregated = defaultdict(lambda: {'count': 0, 'sum': 0, 'min': float('inf'), 'max': float('-inf')})

        for metric in metrics:
            hour_key = f"{metric.name}:{metric.timestamp.strftime('%Y%m%d%H')}"
            agg = aggregated[hour_key]

            agg['count'] += 1
            agg['sum'] += metric.value
            agg['min'] = min(agg['min'], metric.value)
            agg['max'] = max(agg['max'], metric.value)

        # Store in database (would need a metrics table)
        # For now, just log the aggregated data
        if logger:
            logger.debug(f"Aggregated {len(aggregated)} metric groups")

    async def _real_time_updater(self):
        """Update real-time statistics."""
        while True:
            try:
                await asyncio.sleep(STATS_UPDATE_INTERVAL)
                await self._update_real_time_stats()
            except Exception as e:
                if logger:
                    logger.error(f"Real-time updater error: {e}")

    async def _update_real_time_stats(self):
        """Update real-time statistics from database."""
        try:
            if db_cluster and select and func and User and Message:
                async with db_cluster.get_session() as session:
                    # Active users (last 5 minutes)
                    five_min_ago = datetime.now() - timedelta(minutes=5)
                    active_users = await session.execute(
                        select(func.count(User.id.distinct()))
                        .where(User.last_seen >= five_min_ago)
                    )
                    self.real_time_stats['active_users'] = active_users.scalar() or 0

                    # Messages in last hour
                    hour_ago = datetime.now() - timedelta(hours=1)
                    recent_messages = await session.execute(
                        select(func.count(Message.id))
                        .where(Message.timestamp >= hour_ago)
                    )
                    self.real_time_stats['messages_last_hour'] = recent_messages.scalar() or 0

                    # Online users
                    online_users = await session.execute(
                        select(func.count(User.id))
                        .where(User.status == 'online')
                    )
                    self.real_time_stats['online_users'] = online_users.scalar() or 0

        except Exception as e:
            if logger:
                logger.error(f"Failed to update real-time stats: {e}")

    async def get_dashboard_stats(self, user_id: int) -> Dict[str, Any]:
        """Get dashboard statistics for a user."""
        try:
            if db_cluster and select and func and GuildMember and Message:
                async with db_cluster.get_session() as session:
                    # User's guilds
                    user_guilds = await session.execute(
                        select(func.count(GuildMember.guild_id))
                        .where(GuildMember.user_id == user_id)
                    )
                    guilds_count = user_guilds.scalar() or 0

                    # User's messages
                    user_messages = await session.execute(
                        select(func.count(Message.id))
                        .where(Message.author_id == user_id)
                    )
                    messages_count = user_messages.scalar() or 0

                    return {
                        'guilds_count': guilds_count,
                        'messages_count': messages_count,
                        'real_time_stats': dict(self.real_time_stats)
                    }
            
            return {'real_time_stats': dict(self.real_time_stats)}

        except Exception as e:
            if logger:
                logger.error(f"Failed to get dashboard stats: {e}")
            return {}

    def get_real_time_stats(self) -> Dict[str, Any]:
        """Get current real-time statistics."""
        return dict(self.real_time_stats)


# Global analytics service instance
analytics_service = AnalyticsService()
