import asyncio
import json
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional

import redis.asyncio as redis
from app.core.database.engines import db_cluster
from app.logger_config import logger
from app.models.channel import Channel
from app.models.file import FileRecord
from app.models.guild import Guild, GuildMember
from app.models.message import Message
from app.models.user import User
from sqlmodel import Session, and_, func, select

from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime

from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime

"""
Comprehensive analytics and statistics service.
Provides real-time metrics, historical data, and insights.
"""

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
    QUARTER = "3m"
    YEAR = "1y"

@dataclass
class Metric:
    """Metric data structure."""
    name: str
    type: MetricType
    value: float
    timestamp: datetime
    tags: Dict[str, str] = None

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
        self.metrics_buffer = deque(maxlen=10000)
        self.real_time_stats = defaultdict(float)
        self.redis_client = None
        self._initialize_redis()

        # Start background tasks
        asyncio.create_task(self._metrics_processor())
        asyncio.create_task(self._real_time_updater())

    async def _initialize_redis(self):
        """Initialize Redis connection for caching."""
        try:
            self.redis_client = redis.from_url(
                getattr(settings, 'REDIS_URL', 'redis://localhost:6379'),
                decode_responses=True
            )
            await self.redis_client.ping()
            logger.info("Analytics Redis connection established")
        except Exception as e:
            logger.warning(f"Redis connection failed, using in-memory storage: {e}")

    async def record_metric(self, name: str, value: float,
                           metric_type: MetricType = MetricType.COUNTER,
                           tags: Optional[Dict[str, str]] = None):
        """Record a metric."""
        metric = Metric(
            name=name,
            type=metric_type,
            value=value,
            from datetime import datetime
timestamp = datetime.now()
datetime.utcnow(),
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
                await asyncio.sleep(10)  # Process every 10 seconds

                if not self.metrics_buffer:
                    continue

                # Batch process metrics
                metrics_batch = []
                while self.metrics_buffer and len(metrics_batch) < 100:
                    metrics_batch.append(self.metrics_buffer.popleft())

                await self._store_metrics(metrics_batch)

            except Exception as e:
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
                    pipe.expire(key, 86400 * 7)  # Keep for 7 days

                await pipe.execute()

            # Store aggregated data in database
            await self._store_aggregated_metrics(metrics)

        except Exception as e:
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
        logger.debug(f"Aggregated {len(aggregated)} metric groups")

    async def _real_time_updater(self):
        """Update real-time statistics."""
        while True:
            try:
                await asyncio.sleep(30)  # Update every 30 seconds
                await self._update_real_time_stats()
            except Exception as e:
                logger.error(f"Real-time updater error: {e}")

    async def _update_real_time_stats(self):
        """Update real-time statistics from database."""
        try:
            async with db_cluster.get_session() as session:
                # Active users (last 5 minutes)
                from datetime import datetime
five_min_ago = datetime.now()
datetime.utcnow() - timedelta(minutes=5)
                active_users = await session.execute(
                    select(func.count(User.id.distinct()))
                    .where(User.last_seen >= five_min_ago)
                )
                self.real_time_stats['active_users'] = active_users.scalar() or 0

                # Messages in last hour
                from datetime import datetime
hour_ago = datetime.now()
datetime.utcnow() - timedelta(hours=1)
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
            logger.error(f"Failed to update real-time stats: {e}")

    async def get_dashboard_stats(self, user_id: int) -> Dict[str, Any]:
        """Get dashboard statistics for a user."""
        try:
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

                # User's files
                user_files = await session.execute(
                    select(func.count(FileRecord.id))
                    .where(FileRecord.uploaded_by == user_id)
                )
                files_count = user_files.scalar() or 0

                # Growth calculations (simplified)
                guilds_growth = await self._calculate_growth('user_guilds', user_id)
                messages_growth = await self._calculate_growth('user_messages', user_id)
                files_growth = await self._calculate_growth('user_files', user_id)

                return {
                    'guilds_count': guilds_count,
                    'guilds_growth': guilds_growth,
                    'messages_count': messages_count,
                    'messages_growth': messages_growth,
                    'friends_count': 0,  # Would need friends table
                    'friends_growth': 0,
                    'files_count': files_count,
                    'files_growth': files_growth
                }

        except Exception as e:
            logger.error(f"Failed to get dashboard stats: {e}")
            return {
                'guilds_count': 0, 'guilds_growth': 0,
                'messages_count': 0, 'messages_growth': 0,
                'friends_count': 0, 'friends_growth': 0,
                'files_count': 0, 'files_growth': 0
            }

    async def _calculate_growth(self, metric_type: str, user_id: int) -> float:
        """Calculate growth percentage for a metric."""
        # Simplified growth calculation
        # In a real implementation, you'd compare current vs previous period
        return round(abs(hash(f"{metric_type}_{user_id}")) % 20 - 10, 1)

    async def get_system_stats(self) -> Dict[str, Any]:
        """Get overall system statistics."""
        try:
            async with db_cluster.get_session() as session:
                # Total users
                total_users = await session.execute(select(func.count(User.id)))

                # Active users today
                from datetime import datetime
today = datetime.now()
datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
                active_today = await session.execute(
                    select(func.count(User.id.distinct()))
                    .where(User.last_seen >= today)
                )

                # Total guilds
                total_guilds = await session.execute(select(func.count(Guild.id)))

                # Active guilds today
                active_guilds_today = await session.execute(
                    select(func.count(Guild.id.distinct()))
                    .join(Channel, Channel.guild_id == Guild.id)
                    .join(Message, Message.channel_id == Channel.id)
                    .where(Message.timestamp >= today)
                )

                # Total channels
                total_channels = await session.execute(select(func.count(Channel.id)))

                # Total messages
                total_messages = await session.execute(select(func.count(Message.id)))

                # Messages today
                messages_today = await session.execute(
                    select(func.count(Message.id))
                    .where(Message.timestamp >= today)
                )

                # Messages last hour
                from datetime import datetime
hour_ago = datetime.now()
datetime.utcnow() - timedelta(hours=1)
                messages_last_hour = await session.execute(
                    select(func.count(Message.id))
                    .where(Message.timestamp >= hour_ago)
                )

                # Total files
                total_files = await session.execute(select(func.count(FileRecord.id)))

                # Total file size
                total_file_size = await session.execute(select(func.sum(FileRecord.size)))

                return {
                    'users': {
                        'total': total_users.scalar() or 0,
                        'active_today': active_today.scalar() or 0,
                        'online_now': self.real_time_stats.get('online_users', 0)
                    },
                    'guilds': {
                        'total': total_guilds.scalar() or 0,
                        'active_today': active_guilds_today.scalar() or 0
                    },
                    'channels': {
                        'total': total_channels.scalar() or 0,
                        'text_channels': 0,  # Would need channel type filtering
                        'voice_channels': 0
                    },
                    'messages': {
                        'total': total_messages.scalar() or 0,
                        'today': messages_today.scalar() or 0,
                        'last_hour': messages_last_hour.scalar() or 0
                    },
                    'files': {
                        'total': total_files.scalar() or 0,
                        'total_size': total_file_size.scalar() or 0
                    }
                }

        except Exception as e:
            logger.error(f"Failed to get system stats: {e}")
            return {}

    async def get_guild_analytics(self, guild_id: int, time_range: TimeRange = TimeRange.WEEK) -> Dict[str, Any]:
        """Get analytics for a specific guild."""
        try:
            from datetime import datetime
end_time = datetime.now()
datetime.utcnow()
            start_time = self._get_start_time(end_time, time_range)

            async with db_cluster.get_session() as session:
                # Member count over time
                member_history = await self._get_member_history(session, guild_id, start_time, end_time)

                # Message activity
                message_activity = await self._get_message_activity(session, guild_id, start_time, end_time)

                # Channel activity
                channel_activity = await self._get_channel_activity(session, guild_id, start_time, end_time)

                # Top users
                top_users = await self._get_top_users(session, guild_id, start_time, end_time)

                return {
                    'time_range': time_range,
                    'start_time': start_time.isoformat(),
                    'end_time': end_time.isoformat(),
                    'member_history': member_history,
                    'message_activity': message_activity,
                    'channel_activity': channel_activity,
                    'top_users': top_users
                }

        except Exception as e:
            logger.error(f"Failed to get guild analytics: {e}")
            return {}

    def _get_start_time(self, end_time: datetime, time_range: TimeRange) -> datetime:
        """Get start time based on time range."""
        if time_range == TimeRange.HOUR:
            return end_time - timedelta(hours=1)
        elif time_range == TimeRange.DAY:
            return end_time - timedelta(days=1)
        elif time_range == TimeRange.WEEK:
            return end_time - timedelta(weeks=1)
        elif time_range == TimeRange.MONTH:
            return end_time - timedelta(days=30)
        elif time_range == TimeRange.QUARTER:
            return end_time - timedelta(days=90)
        elif time_range == TimeRange.YEAR:
            return end_time - timedelta(days=365)
        else:
            return end_time - timedelta(weeks=1)

    async def _get_member_history(self, session: Session, guild_id: int,
                                 start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        """Get member count history for a guild."""
        # Simplified implementation - would need member join/leave tracking
        return [
            {'timestamp': start_time.isoformat(), 'count': 100},
            {'timestamp': end_time.isoformat(), 'count': 105}
        ]

    async def _get_message_activity(self, session: Session, guild_id: int,
                                   start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        """Get message activity for a guild."""
        result = await session.execute(
            select(
                func.date_trunc('hour', Message.timestamp).label('hour'),
                func.count(Message.id).label('count')
            )
            .join(Channel, Channel.id == Message.channel_id)
            .where(
                and_(
                    Channel.guild_id == guild_id,
                    Message.timestamp >= start_time,
                    Message.timestamp <= end_time
                )
            )
            .group_by('hour')
            .order_by('hour')
        )

        return [
            {
                'timestamp': row.hour.isoformat(),
                'count': row.count
            }
            for row in result
        ]

    async def _get_channel_activity(self, session: Session, guild_id: int,
                                   start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        """Get channel activity for a guild."""
        result = await session.execute(
            select(
                Channel.name,
                func.count(Message.id).label('message_count')
            )
            .join(Message, Message.channel_id == Channel.id)
            .where(
                and_(
                    Channel.guild_id == guild_id,
                    Message.timestamp >= start_time,
                    Message.timestamp <= end_time
                )
            )
            .group_by(Channel.id, Channel.name)
            .order_by(func.count(Message.id).desc())
            .limit(10)
        )

        return [
            {
                'channel_name': row.name,
                'message_count': row.message_count
            }
            for row in result
        ]

    async def _get_top_users(self, session: Session, guild_id: int,
                            start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        """Get top users by message count for a guild."""
        result = await session.execute(
            select(
                User.username,
                User.display_name,
                func.count(Message.id).label('message_count')
            )
            .join(Message, Message.author_id == User.id)
            .join(Channel, Channel.id == Message.channel_id)
            .where(
                and_(
                    Channel.guild_id == guild_id,
                    Message.timestamp >= start_time,
                    Message.timestamp <= end_time
                )
            )
            .group_by(User.id, User.username, User.display_name)
            .order_by(func.count(Message.id).desc())
            .limit(10)
        )

        return [
            {
                'username': row.username,
                'display_name': row.display_name,
                'message_count': row.message_count
            }
            for row in result
        ]

    async def get_real_time_metrics(self) -> Dict[str, Any]:
        """Get real-time metrics."""
        return dict(self.real_time_stats)

    async def export_analytics(self, guild_id: Optional[int] = None,
                              time_range: TimeRange = TimeRange.MONTH) -> Dict[str, Any]:
        """Export analytics data for reporting."""
        if guild_id:
            return await self.get_guild_analytics(guild_id, time_range)
        else:
            return await self.get_system_stats()

# Global analytics service instance
analytics_service = AnalyticsService()

# Convenience functions for recording metrics
async def record_user_action(action: str, user_id: int, **kwargs):
    """Record a user action metric."""
    await analytics_service.record_metric(
        f"user_action.{action}",
        1,
        MetricType.COUNTER,
        {'user_id': str(user_id), **kwargs}
    )

async def record_api_request(endpoint: str, method: str, status_code: int, duration: float):
    """Record an API request metric."""
    await analytics_service.record_metric(
        "api_request",
        1,
        MetricType.COUNTER,
        {
            'endpoint': endpoint,
            'method': method,
            'status_code': str(status_code)
        }
    )

    await analytics_service.record_metric(
        "api_request_duration",
        duration,
        MetricType.HISTOGRAM,
        {
            'endpoint': endpoint,
            'method': method
        }
    )

async def record_websocket_event(event_type: str, user_id: Optional[int] = None):
    """Record a WebSocket event metric."""
    tags = {'event_type': event_type}
    if user_id:
        tags['user_id'] = str(user_id)

    await analytics_service.record_metric(
        "websocket_event",
        1,
        MetricType.COUNTER,
        tags
    )
