"""
Migration: Add Search Indexes

Adds database indexes to improve search performance for messages, users, and channels.
"""

import logging
from plexichat.core.database.manager import database_manager

logger = logging.getLogger(__name__)


async def up() -> bool:
    """Apply migration: Add search indexes."""
    try:
        logger.info("Adding search indexes...")

        # Add indexes for messages table
        message_indexes = [
            "CREATE INDEX IF NOT EXISTS idx_messages_user_id ON messages(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_messages_channel_id ON messages(channel_id)",
            "CREATE INDEX IF NOT EXISTS idx_messages_created_at ON messages(created_at)",
            "CREATE INDEX IF NOT EXISTS idx_messages_message_type ON messages(message_type)",
            "CREATE INDEX IF NOT EXISTS idx_messages_thread_id ON messages(thread_id)",
            "CREATE INDEX IF NOT EXISTS idx_messages_is_deleted ON messages(is_deleted)",
            # Composite indexes for common search patterns
            "CREATE INDEX IF NOT EXISTS idx_messages_channel_created ON messages(channel_id, created_at)",
            "CREATE INDEX IF NOT EXISTS idx_messages_user_created ON messages(user_id, created_at)",
            "CREATE INDEX IF NOT EXISTS idx_messages_type_created ON messages(message_type, created_at)",
        ]

        # Add indexes for users table
        user_indexes = [
            "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)",
            "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)",
            "CREATE INDEX IF NOT EXISTS idx_users_display_name ON users(display_name)",
            "CREATE INDEX IF NOT EXISTS idx_users_is_active ON users(is_active)",
            "CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at)",
        ]

        # Add indexes for channels table
        channel_indexes = [
            "CREATE INDEX IF NOT EXISTS idx_channels_name ON channels(name)",
            "CREATE INDEX IF NOT EXISTS idx_channels_channel_type ON channels(channel_type)",
            "CREATE INDEX IF NOT EXISTS idx_channels_owner_id ON channels(owner_id)",
            "CREATE INDEX IF NOT EXISTS idx_channels_is_archived ON channels(is_archived)",
            "CREATE INDEX IF NOT EXISTS idx_channels_created_at ON channels(created_at)",
        ]

        # Add indexes for threads table
        thread_indexes = [
            "CREATE INDEX IF NOT EXISTS idx_threads_channel_id ON threads(channel_id)",
            "CREATE INDEX IF NOT EXISTS idx_threads_creator_id ON threads(creator_id)",
            "CREATE INDEX IF NOT EXISTS idx_threads_is_resolved ON threads(is_resolved)",
            "CREATE INDEX IF NOT EXISTS idx_threads_created_at ON threads(created_at)",
            "CREATE INDEX IF NOT EXISTS idx_threads_last_message_at ON threads(last_message_at)",
        ]

        # Execute all index creation statements
        async with database_manager.get_session() as session:
            all_indexes = message_indexes + user_indexes + channel_indexes + thread_indexes

            for index_sql in all_indexes:
                try:
                    await session.execute(index_sql)
                    logger.debug(f"Created index: {index_sql.split(' ON ')[1].split('(')[0]}")
                except Exception as e:
                    logger.warning(f"Failed to create index {index_sql}: {e}")
                    # Continue with other indexes

            await session.commit()

        logger.info("Search indexes added successfully")
        return True

    except Exception as e:
        logger.error(f"Failed to add search indexes: {e}")
        return False


async def down() -> bool:
    """Rollback migration: Remove search indexes."""
    try:
        logger.info("Removing search indexes...")

        # List of indexes to drop
        indexes_to_drop = [
            "idx_messages_user_id",
            "idx_messages_channel_id",
            "idx_messages_created_at",
            "idx_messages_message_type",
            "idx_messages_thread_id",
            "idx_messages_is_deleted",
            "idx_messages_channel_created",
            "idx_messages_user_created",
            "idx_messages_type_created",
            "idx_users_username",
            "idx_users_email",
            "idx_users_display_name",
            "idx_users_is_active",
            "idx_users_created_at",
            "idx_channels_name",
            "idx_channels_channel_type",
            "idx_channels_owner_id",
            "idx_channels_is_archived",
            "idx_channels_created_at",
            "idx_threads_channel_id",
            "idx_threads_creator_id",
            "idx_threads_is_resolved",
            "idx_threads_created_at",
            "idx_threads_last_message_at",
        ]

        async with database_manager.get_session() as session:
            for index_name in indexes_to_drop:
                try:
                    await session.execute(f"DROP INDEX IF EXISTS {index_name}")
                    logger.debug(f"Dropped index: {index_name}")
                except Exception as e:
                    logger.warning(f"Failed to drop index {index_name}: {e}")

            await session.commit()

        logger.info("Search indexes removed successfully")
        return True

    except Exception as e:
        logger.error(f"Failed to remove search indexes: {e}")
        return False


# Migration metadata
migration_version = "add_search_indexes"
migration_description = "Add database indexes for improved search performance"
requires_downtime = False  # Adding indexes doesn't require downtime