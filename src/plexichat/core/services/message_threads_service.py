

@dataclass
class Thread:
    """Thread structure for organizing message conversations."""

    thread_id: str
    title: str
    channel_id: str
    creator_id: str
    parent_message_id: str | None = None
    is_resolved: bool = False
    participant_count: int = 1
    message_count: int = 0
    last_message_at: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    participants: set[str] = field(default_factory=set)


class MessageThreadsService(BaseService):
    """
    Service for managing message threads with database operations and business logic.
    """

    def __init__(self):
        super().__init__("message_threads")
        self.dependencies.add("database")
        self._cache: dict[str, Thread] = {}
        self._channel_threads_cache: dict[str, list[str]] = {}

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
                result = await session.execute("SELECT COUNT(*) FROM message_threads")
                count = result.scalar()
                return True
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return False

    async def _ensure_threads_table(self):
        """Ensure the threads table exists."""
        from plexichat.core.database.models import MESSAGE_THREADS_SCHEMA

        await database_manager.ensure_table_exists(
            "message_threads", MESSAGE_THREADS_SCHEMA
        )

    async def _load_threads_cache(self):
        """Load existing threads into memory cache."""
        try:
            async with database_manager.get_session() as session:
                result = await session.execute("SELECT * FROM message_threads")
                rows = await result.fetchall()

                for row in rows:
                    thread = self._row_to_thread(row)
                    self._cache[thread.thread_id] = thread

                    # Update channel threads cache
                    if thread.channel_id not in self._channel_threads_cache:
                        self._channel_threads_cache[thread.channel_id] = []
                    self._channel_threads_cache[thread.channel_id].append(
                        thread.thread_id
                    )

        except Exception as e:
            logger.error(f"Failed to load threads cache: {e}")

    def _row_to_thread(self, row) -> Thread:
        """Convert database row to Thread object."""
        return Thread(
            thread_id=row.id,
            title=row.title,
            channel_id="",  # Will be derived from parent_message_id if needed
            creator_id=row.creator_id,
            parent_message_id=row.parent_message_id,
            is_resolved=row.is_archived,
            participant_count=1,  # Default
            message_count=row.reply_count,
            last_message_at=None,  # Not in schema
            created_at=row.created_at,
            updated_at=row.updated_at,
            participants={row.creator_id},  # Default to creator
        )

    async def create_thread(
        self, parent_message_id: str, title: str, creator_id: str
    ) -> tuple[bool, str, Thread | None]:
        """
        Create a new thread.

        Returns:
            Tuple of (success, thread_id_or_error, thread_object)
        """
        try:
            thread_id = str(uuid4())
            now = datetime.now(UTC)

            thread = Thread(
                thread_id=thread_id,
                title=title,
                channel_id="",  # Will be derived from parent_message_id
                creator_id=creator_id,
                parent_message_id=parent_message_id,
                participants={creator_id},
            )

            # Insert into database
            async with database_manager.get_session() as session:
                data = {
                    "id": thread_id,
                    "parent_message_id": parent_message_id,
                    "title": title,
                    "creator_id": creator_id,
                    "created_at": now.isoformat(),
                    "updated_at": now.isoformat(),
                    "reply_count": 0,
                    "is_archived": False,
                }
                await session.insert("message_threads", data)
                await session.commit()

            # Update caches
            self._cache[thread_id] = thread

            logger.info(f"Created thread {thread_id} for message {parent_message_id}")
            return True, thread_id, thread

        except Exception as e:
            logger.error(f"Failed to create thread: {e}")
            return False, f"Database error: {e!s}", None

    async def get_thread(self, thread_id: str) -> Thread | None:
        """Get a thread by ID."""
        # Check cache first
        if thread_id in self._cache:
            return self._cache[thread_id]

        # Load from database
        try:
            async with database_manager.get_session() as session:
                result = await session.fetchone(
                    "SELECT * FROM message_threads WHERE id = ?", (thread_id,)
                )

                if result:
                    thread = self._row_to_thread(result)
                    self._cache[thread_id] = thread
                    return thread

        except Exception as e:
            logger.error(f"Failed to get thread {thread_id}: {e}")

        return None

    async def add_reply(
        self, thread_id: str, message_content: str, user_id: str
    ) -> tuple[bool, str]:
        """
        Add a reply to a thread.

        Returns:
            Tuple of (success, reply_id_or_error)
        """
        try:
            reply_id = str(uuid4())
            now = datetime.now(UTC)

            # Insert into thread_replies table
            async with database_manager.get_session() as session:
                await session.execute(
                    """
                    INSERT INTO thread_replies (
                        id, thread_id, message_content, user_id, created_at, is_edited
                    ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                    (reply_id, thread_id, message_content, user_id, now, False),
                )

                # Update reply_count in message_threads
                await session.execute(
                    """
                    UPDATE message_threads
                    SET reply_count = reply_count + 1, updated_at = ?
                    WHERE id = ?
                """,
                    (now, thread_id),
                )

                await session.commit()

            # Update cache
            if thread_id in self._cache:
                self._cache[thread_id].message_count += 1
                self._cache[thread_id].updated_at = now

            logger.info(f"Added reply {reply_id} to thread {thread_id}")
            return True, reply_id

        except Exception as e:
            logger.error(f"Failed to add reply to thread {thread_id}: {e}")
            return False, f"Database error: {e!s}"

    async def get_thread_replies(
        self, thread_id: str, limit: int = 50, offset: int = 0
    ) -> list[dict[str, Any]]:
        """
        Get replies for a thread.

        Returns:
            List of reply dictionaries
        """
        try:
            async with database_manager.get_session() as session:
                result = await session.execute(
                    """
                    SELECT * FROM thread_replies
                    WHERE thread_id = ?
                    ORDER BY created_at ASC
                    LIMIT ? OFFSET ?
                """,
                    (thread_id, limit, offset),
                )
                rows = await result.fetchall()

                replies = []
                for row in rows:
                    reply = {
                        "id": row.id,
                        "thread_id": row.thread_id,
                        "message_content": row.message_content,
                        "user_id": row.user_id,
                        "created_at": row.created_at,
                        "is_edited": row.is_edited,
                    }
                    replies.append(reply)

                return replies

        except Exception as e:
            logger.error(f"Failed to get replies for thread {thread_id}: {e}")
            return []

    async def update_thread_title(
        self, thread_id: str, new_title: str, user_id: str
    ) -> bool:
        """
        Update thread title.

        Returns:
            Success boolean
        """
        try:
            now = datetime.now(UTC)

            async with database_manager.get_session() as session:
                await session.execute(
                    """
                    UPDATE message_threads
                    SET title = ?, updated_at = ?
                    WHERE id = ? AND creator_id = ?
                """,
                    (new_title, now, thread_id, user_id),
                )
                await session.commit()

            # Update cache
            if thread_id in self._cache:
                self._cache[thread_id].title = new_title
                self._cache[thread_id].updated_at = now

            logger.info(f"Updated title for thread {thread_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to update thread title {thread_id}: {e}")
            return False

    async def delete_thread(self, thread_id: str, user_id: str) -> bool:
        """
        Delete a thread.

        Returns:
            Success boolean
        """
        try:
            async with database_manager.get_session() as session:
                # Check if user is creator
                row = await session.fetchone(
                    """
                    SELECT creator_id FROM message_threads WHERE id = ?
                """,
                    (thread_id,),
                )

                if not row or row["creator_id"] != user_id:
                    return False

                # Delete replies first
                await session.execute(
                    "DELETE FROM thread_replies WHERE thread_id = ?", (thread_id,)
                )

                # Delete thread
                await session.execute(
                    "DELETE FROM message_threads WHERE id = ?", (thread_id,)
                )

                await session.commit()

            # Update cache
            if thread_id in self._cache:
                del self._cache[thread_id]

            logger.info(f"Deleted thread {thread_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete thread {thread_id}: {e}")
            return False

    async def get_channel_threads(self, channel_id: str) -> list[Thread]:
        """Get all threads in a channel."""
        try:
            # For now, return all threads since we don't have a messages table
            # In a full implementation, this would join with messages to filter by channel
            async with database_manager.get_session() as session:
                rows = await session.fetchall("SELECT * FROM message_threads")

                threads = []
                for row in rows:
                    thread = self._row_to_thread(row)
                    # Set channel_id from parameter (since we can't join with messages table)
                    thread.channel_id = channel_id
                    threads.append(thread)
                    self._cache[thread.thread_id] = thread

                return threads

        except Exception as e:
            logger.error(f"Failed to get threads for channel {channel_id}: {e}")
            return []

    # Note: update_thread_participants and update_thread_stats removed as new schema doesn't support these fields

    async def resolve_thread(self, thread_id: str) -> bool:
        """Mark a thread as resolved (archived)."""
        try:
            now = datetime.now(UTC)
            async with database_manager.get_session() as session:
                await session.execute(
                    """
                    UPDATE message_threads
                    SET is_archived = ?, updated_at = ?
                    WHERE id = ?
                """,
                    (True, now, thread_id),
                )
                await session.commit()

            # Update cache
            if thread_id in self._cache:
                self._cache[thread_id].is_resolved = True
                self._cache[thread_id].updated_at = now

            return True

        except Exception as e:
            logger.error(f"Failed to resolve thread {thread_id}: {e}")
            return False

    async def archive_old_threads(self, days_old: int = 30) -> int:
        """Archive threads older than specified days."""
        try:
            cutoff_date = datetime.now(UTC).replace(
                hour=0, minute=0, second=0, microsecond=0
            )
            cutoff_date = cutoff_date.replace(day=cutoff_date.day - days_old)

            async with database_manager.get_session() as session:
                # Mark old archived threads
                now = datetime.now(UTC)
                result = await session.execute(
                    """
                    UPDATE message_threads
                    SET is_archived = ?, updated_at = ?
                    WHERE is_archived = ? AND updated_at < ?
                """,
                    (True, now, False, cutoff_date),
                )  # Note: is_archived = False to find non-archived threads
                await session.commit()

                archived_count = result.rowcount

                # Clean up cache for archived threads
                for thread_id, thread in list(self._cache.items()):
                    if thread.is_resolved and thread.updated_at < cutoff_date:
                        del self._cache[thread_id]

                logger.info(f"Archived {archived_count} old threads")
                return archived_count

        except Exception as e:
            logger.error(f"Failed to archive old threads: {e}")
            return 0

    async def get_thread_participants(self, thread_id: str) -> set[str]:
        """Get thread participants from replies."""
        try:
            async with database_manager.get_session() as session:
                rows = await session.fetchall(
                    """
                    SELECT DISTINCT user_id FROM thread_replies WHERE thread_id = ?
                """,
                    (thread_id,),
                )

                participants = {row.user_id for row in rows}

                # Add creator
                creator_result = await session.execute(
                    """
                    SELECT creator_id FROM message_threads WHERE id = ?
                """,
                    (thread_id,),
                )
                creator_row = await session.fetchone(
                    """
                    SELECT creator_id FROM message_threads WHERE id = ?
                """,
                    (thread_id,),
                )
                if creator_row:
                    participants.add(creator_row.creator_id)

                return participants

        except Exception as e:
            logger.error(f"Failed to get thread participants: {e}")
            return set()

    async def search_threads(
        self, channel_id: str, query: str, limit: int = 20
    ) -> list[Thread]:
        """Search threads by title in a channel."""
        try:
            async with database_manager.get_session() as session:
                # For now, search all threads since we don't have a messages table
                # In a full implementation, this would join with messages to filter by channel
                result = await session.execute(
                    """
                    SELECT * FROM message_threads
                    WHERE title LIKE ?
                    ORDER BY updated_at DESC
                    LIMIT ?
                """,
                    (f"%{query}%", limit),
                )
                rows = await result.fetchall()

                threads = []
                for row in rows:
                    thread = self._row_to_thread(row)
                    thread.channel_id = channel_id
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


__all__ = ["MessageThreadsService", "Thread", "get_message_threads_service"]
