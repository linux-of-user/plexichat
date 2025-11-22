"""
Database Optimizations for PlexiChat

Provides optimized database schemas, indexes, and query optimizations
for improved performance and scalability.
"""

from typing import Any

from plexichat.core.logging.logger import get_logger

logger = get_logger(__name__)


# Optimized Keyboard Shortcuts Schema with indexes
OPTIMIZED_KEYBOARD_SHORTCUTS_SCHEMA = {
    "id": "TEXT PRIMARY KEY",
    "user_id": "TEXT NOT NULL",
    "shortcut_key": "TEXT NOT NULL",
    "action": "TEXT NOT NULL",
    "description": "TEXT",
    "is_custom": "BOOLEAN DEFAULT TRUE",
    "created_at": "TEXT NOT NULL",
    "updated_at": "TEXT NOT NULL",
    "metadata": "TEXT DEFAULT '{}'",
}

# Keyboard Shortcuts Indexes for performance optimization
KEYBOARD_SHORTCUTS_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_keyboard_shortcuts_user_id ON keyboard_shortcuts(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_keyboard_shortcuts_user_action ON keyboard_shortcuts(user_id, action)",
    "CREATE INDEX IF NOT EXISTS idx_keyboard_shortcuts_user_key ON keyboard_shortcuts(user_id, shortcut_key)",
    "CREATE INDEX IF NOT EXISTS idx_keyboard_shortcuts_key_only ON keyboard_shortcuts(shortcut_key)",
    "CREATE INDEX IF NOT EXISTS idx_keyboard_shortcuts_action_only ON keyboard_shortcuts(action)",
    "CREATE INDEX IF NOT EXISTS idx_keyboard_shortcuts_custom ON keyboard_shortcuts(is_custom)",
    "CREATE INDEX IF NOT EXISTS idx_keyboard_shortcuts_user_custom ON keyboard_shortcuts(user_id, is_custom)",
]

# Optimized query templates for better performance
OPTIMIZED_KEYBOARD_SHORTCUTS_QUERIES = {
    "get_user_shortcuts": """
        SELECT id, user_id, shortcut_key, action, description, is_custom,
               created_at, updated_at
        FROM keyboard_shortcuts
        WHERE user_id = ?
        ORDER BY action
    """,
    "get_user_shortcut_by_action": """
        SELECT id, user_id, shortcut_key, action, description, is_custom,
               created_at, updated_at
        FROM keyboard_shortcuts
        WHERE user_id = ? AND action = ?
        LIMIT 1
    """,
    "get_user_shortcuts_by_key": """
        SELECT id, user_id, shortcut_key, action, description, is_custom,
               created_at, updated_at
        FROM keyboard_shortcuts
        WHERE user_id = ? AND shortcut_key = ?
    """,
    "get_all_user_custom_shortcuts": """
        SELECT id, user_id, shortcut_key, action, description, is_custom,
               created_at, updated_at
        FROM keyboard_shortcuts
        WHERE user_id = ? AND is_custom = 1
        ORDER BY action
    """,
    "count_user_shortcuts": """
        SELECT COUNT(*) as count
        FROM keyboard_shortcuts
        WHERE user_id = ?
    """,
    "count_user_custom_shortcuts": """
        SELECT COUNT(*) as count
        FROM keyboard_shortcuts
        WHERE user_id = ? AND is_custom = 1
    """,
}


class DatabaseOptimizer:
    """Handles database optimizations and index management."""

    def __init__(self):
        self.logger = get_logger(__name__)

    async def create_optimized_indexes(
        self, table_name: str, indexes: list[str]
    ) -> bool:
        """Create optimized indexes for a table."""
        try:
            from plexichat.core.database import execute_query

            for index_sql in indexes:
                try:
                    await execute_query(index_sql)
                    self.logger.info(
                        f"Created index: {index_sql.split(' ON ')[1].split('(')[0]}"
                    )
                except Exception as e:
                    self.logger.warning(f"Failed to create index {index_sql}: {e}")
                    # Continue with other indexes

            return True

        except Exception as e:
            self.logger.error(
                f"Failed to create optimized indexes for {table_name}: {e}"
            )
            return False

    async def analyze_table_performance(self, table_name: str) -> dict[str, Any]:
        """Analyze table performance and provide optimization recommendations."""
        try:
            from plexichat.core.database import execute_query

            # Get table statistics
            stats = {}

            # Count total rows
            result = await execute_query(f"SELECT COUNT(*) as count FROM {table_name}")
            stats["total_rows"] = result[0]["count"] if result else 0

            # Get index information (SQLite specific)
            try:
                indexes = await execute_query(
                    f"SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='{table_name}'"
                )
                stats["indexes"] = [idx["name"] for idx in indexes] if indexes else []
            except Exception:
                stats["indexes"] = []

            # Performance recommendations
            recommendations = []

            if stats["total_rows"] > 1000 and len(stats["indexes"]) == 0:
                recommendations.append(
                    "Consider adding indexes for frequently queried columns"
                )

            if stats["total_rows"] > 10000:
                recommendations.append(
                    "Table has grown large, consider partitioning or archiving old data"
                )

            stats["recommendations"] = recommendations

            return stats

        except Exception as e:
            self.logger.error(f"Failed to analyze table {table_name}: {e}")
            return {"error": str(e)}

    async def optimize_keyboard_shortcuts_table(self) -> bool:
        """Optimize the keyboard shortcuts table with indexes and performance improvements."""
        try:
            # Create indexes
            success = await self.create_optimized_indexes(
                "keyboard_shortcuts", KEYBOARD_SHORTCUTS_INDEXES
            )

            if success:
                self.logger.info("Successfully optimized keyboard_shortcuts table")

                # Analyze performance
                stats = await self.analyze_table_performance("keyboard_shortcuts")
                self.logger.info(f"Keyboard shortcuts table stats: {stats}")

            return success

        except Exception as e:
            self.logger.error(f"Failed to optimize keyboard_shortcuts table: {e}")
            return False


# Global optimizer instance
database_optimizer = DatabaseOptimizer()


async def optimize_database() -> bool:
    """Optimize database performance with indexes and query improvements."""
    try:
        logger.info("Starting database optimization...")

        # Optimize keyboard shortcuts table
        success = await database_optimizer.optimize_keyboard_shortcuts_table()

        if success:
            logger.info("Database optimization completed successfully")
        else:
            logger.warning("Database optimization completed with some issues")

        return success

    except Exception as e:
        logger.error(f"Database optimization failed: {e}")
        return False


__all__ = [
    "KEYBOARD_SHORTCUTS_INDEXES",
    "OPTIMIZED_KEYBOARD_SHORTCUTS_QUERIES",
    "OPTIMIZED_KEYBOARD_SHORTCUTS_SCHEMA",
    "DatabaseOptimizer",
    "database_optimizer",
    "optimize_database",
]
