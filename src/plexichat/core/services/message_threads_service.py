"""
Message Threads Service
Handles database operations and business logic for message threads.
"""

import asyncio
import logging
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime, timezone
from uuid import uuid4

from plexichat.core.database.manager import database_manager
from plexichat.core.services.core_services import BaseService, ServiceStatus
from plexichat.core.messaging.unified_messaging_system import Thread

logger = logging.getLogger(__name__)


class MessageThreadsService(BaseService):
    """
    Service for managing message threads with database operations and business logic.
    """

    def __init__(self):
        super().__init__("message_threads")
        self.dependencies.add("database")
        self._cache: Dict[str, Thread] = {}
        self._channel_threads_cache: Dict[str, List[str]] = {}

    async def start(self) -> bool:
        """Start the message threads service."""
        try:
            logger.info("Starting Message Threads Service...")

            # Ensure threads table exists
            await self._ensure_threads_table()

            # Load existing threads into cache
            await self._load_threads_cache()

            logger.info("Message Threads Service started successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to start Message Threads Service: {e}")
            return False

    async def stop(self) -> bool:
        """Stop the message threads service."""
        try:
            logger.info("Stopping Message Threads Service...")

            # Clear caches
            self._cache.clear()
            self._channel_threads_cache.clear()

            logger.info("Message Threads Service stopped successfully")
            return True

        except Exception as e:
            logger.error(f"Error stopping Message Threads Service: {e}")
            return False

    async def health_check(self) -> bool:
        """Check service health."""
        try:
            # Check database connectivity
            async with database_manager.get_session() as session:
                result = await session.execute("SELECT COUNT(*) FROM threads")
                count = result.scalar()
                return True
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return False

    async def _ensure_threads_table(self):
        """Ensure the threads table exists."""
        from plexichat.core.database.models import THREAD_SCHEMA
        await database_manager.ensure_table_exists("threads", THREAD_SCHEMA)

    async def _load_threads_cache(self):
        """Load existing threads into memory cache."""
        try:
            async with database_manager.get_session() as session:
                result = await session.execute("SELECT * FROM threads")
                rows = result.fetchall()

                for row in rows:
                    thread = self._row_to_thread(row)
                    self._cache[thread.thread_id] = thread

                    # Update channel threads cache
                    if thread.channel_id not in self._channel_threads_cache:
                        self._channel_threads_cache[thread.channel_id] = []
                    self._channel_threads_cache[thread.channel_id].append(thread.thread_id)

        except Exception as e:
            logger.error(f"Failed to load threads cache: {e}")

    def _row_to_thread(self, row) -> Thread:
        """Convert database row to Thread object."""
        return Thread(
            thread_id=row.id,
            title=row.title,
            channel_id=row.channel_id,
            creator_id=row.creator_id,
            parent_message_id=row.parent_message_id,
            is_resolved=row.is_resolved,
            participant_count=row.participant_count,
            message_count=row.message_count,
            last_message_at=row.last_message_at,
            created_at=row.created_at,
            updated_at=row.updated_at,
            participants=set(row.participants.split(',')) if row.participants else set()
        )

    async def create_thread(self, title: str, channel_id: str, creator_id: str,
                           parent_message_id: Optional[str] = None) -> Tuple[bool, str, Optional[Thread]]:
        """
        Create a new thread.

        Returns:
            Tuple of (success, thread_id_or_error, thread_object)
        """
        try:
            thread_id = str(uuid4())
            now = datetime.now(timezone.utc)

            thread = Thread(
                thread_id=thread_id,
                title=title,
                channel_id=channel_id,
                creator_id=creator_id,
                parent_message_id=parent_message_id,
                participants={creator_id}
            )

            # Insert into database
            async with database_manager.get_session() as session:
                await session.execute("""
                    INSERT INTO threads (
                        id, title, channel_id, creator_id, parent_message_id,
                        is_resolved, participant_count, message_count,
                        last_message_at, created_at, updated_at, participants
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    thread_id, title, channel_id, creator_id, parent_message_id,
                    False, 1, 0, None, now, now, creator_id
                ))
                await session.commit()

            # Update caches
            self._cache[thread_id] = thread
            if channel_id not in self._channel_threads_cache:
                self._channel_threads_cache[channel_id] = []
            self._channel_threads_cache[channel_id].append(thread_id)

            logger.info(f"Created thread {thread_id} in channel {channel_id}")
            return True, thread_id, thread

        except Exception as e:
            logger.error(f"Failed to create thread: {e}")
            return False, f"Database error: {str(e)}", None

    async def get_thread(self, thread_id: str) -> Optional[Thread]:
        """Get a thread by ID."""
        # Check cache first
        if thread_id in self._cache:
            return self._cache[thread_id]

        # Load from database
        try:
            async with database_manager.get_session() as session:
                result = await session.execute("SELECT * FROM threads WHERE id = ?", (thread_id,))
                row = result.fetchone()

                if row:
                    thread = self._row_to_thread(row)
                    self._cache[thread_id] = thread
                    return thread

        except Exception as e:
            logger.error(f"Failed to get thread {thread_id}: {e}")

        return None

    async def get_channel_threads(self, channel_id: str) -> List[Thread]:
        """Get all threads in a channel."""
        try:
            # Check cache first
            if channel_id in self._channel_threads_cache:
                thread_ids = self._channel_threads_cache[channel_id]
                threads = []
                for thread_id in thread_ids:
                    thread = await self.get_thread(thread_id)
                    if thread:
                        threads.append(thread)
                return threads

            # Load from database
            async with database_manager.get_session() as session:
                result = await session.execute("SELECT * FROM threads WHERE channel_id = ?", (channel_id,))
                rows = result.fetchall()

                threads = []
                thread_ids = []
                for row in rows:
                    thread = self._row_to_thread(row)
                    threads.append(thread)
                    thread_ids.append(thread.thread_id)
                    self._cache[thread.thread_id] = thread

                # Update cache
                self._channel_threads_cache[channel_id] = thread_ids

                return threads

        except Exception as e:
            logger.error(f"Failed to get threads for channel {channel_id}: {e}")
            return []

    async def update_thread_participants(self, thread_id: str, participants: Set[str]) -> bool:
        """Update thread participants."""
        try:
            async with database_manager.get_session() as session:
                participants_str = ','.join(participants)
                await session.execute("""
                    UPDATE threads
                    SET participants = ?, participant_count = ?, updated_at = ?
                    WHERE id = ?
                """, (participants_str, len(participants), datetime.now(timezone.utc), thread_id))
                await session.commit()

            # Update cache
            if thread_id in self._cache:
                self._cache[thread_id].participants = participants
                self._cache[thread_id].participant_count = len(participants)
                self._cache[thread_id].updated_at = datetime.now(timezone.utc)

            return True

        except Exception as e:
            logger.error(f"Failed to update thread participants: {e}")
            return False

    async def update_thread_stats(self, thread_id: str, message_count: int,
                                 last_message_at: Optional[datetime]) -> bool:
        """Update thread statistics."""
        try:
            async with database_manager.get_session() as session:
                await session.execute("""
                    UPDATE threads
                    SET message_count = ?, last_message_at = ?, updated_at = ?
                    WHERE id = ?
                """, (message_count, last_message_at, datetime.now(timezone.utc), thread_id))
                await session.commit()

            # Update cache
            if thread_id in self._cache:
                self._cache[thread_id].message_count = message_count
                self._cache[thread_id].last_message_at = last_message_at
                self._cache[thread_id].updated_at = datetime.now(timezone.utc)

            return True

        except Exception as e:
            logger.error(f"Failed to update thread stats: {e}")
            return False

    async def resolve_thread(self, thread_id: str) -> bool:
        """Mark a thread as resolved."""
        try:
            async with database_manager.get_session() as session:
                await session.execute("""
                    UPDATE threads
                    SET is_resolved = ?, updated_at = ?
                    WHERE id = ?
                """, (True, datetime.now(timezone.utc), thread_id))
                await session.commit()

            # Update cache
            if thread_id in self._cache:
                self._cache[thread_id].is_resolved = True
                self._cache[thread_id].updated_at = datetime.now(timezone.utc)

            return True

        except Exception as e:
            logger.error(f"Failed to resolve thread {thread_id}: {e}")
            return False

    async def archive_old_threads(self, days_old: int = 30) -> int:
        """Archive threads older than specified days."""
        try:
            cutoff_date = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
            cutoff_date = cutoff_date.replace(day=cutoff_date.day - days_old)

            async with database_manager.get_session() as session:
                # Mark old resolved threads as archived (you might want to add an archived column)
                result = await session.execute("""
                    UPDATE threads
                    SET updated_at = ?
                    WHERE is_resolved = ? AND updated_at < ?
                """, (datetime.now(timezone.utc), True, cutoff_date))
                await session.commit()

                archived_count = result.rowcount

                # Clean up cache for archived threads
                for thread_id, thread in list(self._cache.items()):
                    if thread.is_resolved and thread.updated_at < cutoff_date:
                        del self._cache[thread_id]
                        # Also remove from channel cache
                        if thread.channel_id in self._channel_threads_cache:
                            self._channel_threads_cache[thread.channel_id] = [
                                tid for tid in self._channel_threads_cache[thread.channel_id]
                                if tid != thread_id
                            ]

                logger.info(f"Archived {archived_count} old threads")
                return archived_count

        except Exception as e:
            logger.error(f"Failed to archive old threads: {e}")
            return 0

    async def get_thread_participants(self, thread_id: str) -> Set[str]:
        """Get thread participants."""
        thread = await self.get_thread(thread_id)
        return thread.participants if thread else set()

    async def search_threads(self, channel_id: str, query: str, limit: int = 20) -> List[Thread]:
        """Search threads by title in a channel."""
        try:
            async with database_manager.get_session() as session:
                result = await session.execute("""
                    SELECT * FROM threads
                    WHERE channel_id = ? AND title LIKE ?
                    ORDER BY updated_at DESC
                    LIMIT ?
                """, (channel_id, f"%{query}%", limit))
                rows = result.fetchall()

                threads = []
                for row in rows:
                    thread = self._row_to_thread(row)
                    threads.append(thread)

                return threads

        except Exception as e:
            logger.error(f"Failed to search threads: {e}")
            return []


# Global service instance
_message_threads_service = MessageThreadsService()


def get_message_threads_service() -> MessageThreadsService:
    """Get the global message threads service instance."""
    return _message_threads_service


__all__ = ["MessageThreadsService", "get_message_threads_service"]