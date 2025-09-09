"""
Migration: Add Search Indexes

Adds database indexes to improve search performance for messages, users, and channels.
"""

import logging
from typing import Dict, List, Tuple

from plexichat.core.database.manager import database_manager

from .base import Migration

logger = logging.getLogger(__name__)


class AddSearchIndexesMigration(Migration):
    MIGRATION_VERSION = "add_search_indexes"
    MIGRATION_DESCRIPTION = "Add database indexes for improved search performance"

    def _get_tables(self) -> Dict[str, Dict[str, Any]]:
        return {}

    def _get_indexes(self) -> Dict[str, List[Tuple[str, List[str], bool]]]:
        return {
            "messages": [
                ("idx_messages_user_id", ["user_id"], False),
                ("idx_messages_channel_id", ["channel_id"], False),
                ("idx_messages_created_at", ["created_at"], False),
                ("idx_messages_message_type", ["message_type"], False),
                ("idx_messages_thread_id", ["thread_id"], False),
                ("idx_messages_is_deleted", ["is_deleted"], False),
                ("idx_messages_channel_created", ["channel_id", "created_at"], False),
                ("idx_messages_user_created", ["user_id", "created_at"], False),
                ("idx_messages_type_created", ["message_type", "created_at"], False),
            ],
            "users": [
                ("idx_users_username", ["username"], False),
                ("idx_users_email", ["email"], False),
                ("idx_users_display_name", ["display_name"], False),
                ("idx_users_is_active", ["is_active"], False),
                ("idx_users_created_at", ["created_at"], False),
            ],
            "channels": [
                ("idx_channels_name", ["name"], False),
                ("idx_channels_channel_type", ["channel_type"], False),
                ("idx_channels_owner_id", ["owner_id"], False),
                ("idx_channels_is_archived", ["is_archived"], False),
                ("idx_channels_created_at", ["created_at"], False),
            ],
            "threads": [
                ("idx_threads_channel_id", ["channel_id"], False),
                ("idx_threads_creator_id", ["creator_id"], False),
                ("idx_threads_is_resolved", ["is_resolved"], False),
                ("idx_threads_created_at", ["created_at"], False),
                ("idx_threads_last_message_at", ["last_message_at"], False),
            ],
        }

    def _get_foreign_keys(self) -> Dict[str, List[Tuple[str, str, str, str, str, str]]]:
        return {}

    def _get_check_constraints(self) -> Dict[str, List[Tuple[str, str]]]:
        return {}

    async def up(self):
        await super().up()

    async def down(self):
        await super().down()

    async def verify(self):
        await super().verify()


async def main():
    """CLI entry point for the migration."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python add_search_indexes.py [up|down|verify]")
        sys.exit(1)

    action = sys.argv[1]
    migration = AddSearchIndexesMigration()

    if action == "up":
        await migration.up()
    elif action == "down":
        await migration.down()
    elif action == "verify":
        await migration.verify()
    else:
        print("Invalid action. Use up, down, or verify")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
