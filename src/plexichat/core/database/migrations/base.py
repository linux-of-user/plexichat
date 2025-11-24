from abc import ABC, abstractmethod
import asyncio
from typing import TYPE_CHECKING, Any

from plexichat.core.logging import get_logger

# Import database_manager with proper type checking
if TYPE_CHECKING:
    pass
else:
    from plexichat.core.database.manager import database_manager

# SQLAlchemy imports with fallback
try:
    from sqlalchemy import create_engine, text
    from sqlalchemy.exc import SQLAlchemyError
except ImportError:
    # Fallback for when SQLAlchemy is not available
    def create_engine(*args, **kwargs) -> Any:
        pass

    def text(sql: str) -> str:
        return sql

    class SQLAlchemyError(Exception):
        pass


logger = get_logger(__name__)


class Migration(ABC):
    """
    Base class for database migrations. Subclasses should override abstract methods
    to define specific schema elements.
    """

    MIGRATION_VERSION: str = ""
    MIGRATION_DESCRIPTION: str = ""

    def __init__(self) -> None:
        self.db_manager = database_manager
        self.rollback_sql: list[str] = []

    @abstractmethod
    def get_tables(self) -> dict[str, dict[str, str]]:
        """Returns dictionary of table names to column definitions."""
        pass

    @abstractmethod
    def get_indexes(self) -> dict[str, list[tuple[str, bool]]]:
        """Returns dictionary of table names to list of (index_name, is_unique) tuples."""
        pass

    def get_migration_name(self) -> str:
        """Returns the name of this migration."""
        return f"{self.MIGRATION_VERSION}_{self.MIGRATION_DESCRIPTION}"

    async def is_applied(self, migration_name: str) -> bool:
        """Check if migration has been applied."""
        try:
            async with self.db_manager.get_session() as session:
                result = await session.execute(
                    "SELECT 1 FROM migrations WHERE version = ?",
                    {"version": migration_name},
                )
                row = await result.fetchone()
                return row is not None
        except Exception:
            return False

    async def _get_connection(self) -> Any:
        """Get database connection for SQLAlchemy operations."""
        # Fallback implementation - should be overridden by subclasses
        self.engine = database_manager.get_engine()
        self.db_type = self.engine.dialect.name
        self.session = database_manager.get_session()

        return self.session

    async def _close_connection(self) -> None:
        """Close database connection."""
        if hasattr(self, "session") and self.session:
            await self.session.close()

    async def record_migration(self, migration_name: str) -> None:
        """Record that this migration has been applied."""
        try:
            async with self.db_manager.get_session() as session:
                await session.execute(
                    "INSERT INTO migrations (version, description, applied_at) VALUES (?, ?, ?)",
                    {
                        "version": migration_name,
                        "description": self.MIGRATION_DESCRIPTION,
                        "applied_at": asyncio.get_event_loop().time(),
                    },
                )
                await session.commit()
        except Exception as e:
            logger.error(f"Failed to record migration {migration_name}: {e}")
            raise

    async def remove_migration_record(self, migration_name: str) -> bool:
        """Remove migration record during rollback."""
        try:
            result = await self.session.execute(
                text("DELETE FROM migrations WHERE version = :version"),
                {"version": migration_name},
            )

            if hasattr(result, "rowcount"):
                deleted_count = result.rowcount
            else:
                deleted_count = getattr(result, "scalar", lambda: 0)()

            return deleted_count > 0

        except Exception as e:
            logger.error(f"Failed to remove migration record {migration_name}: {e}")
            return False

    def _get_table_creation_sql(self, table_name: str, columns: dict[str, str]) -> str:
        """Get SQL for creating a table based on database type."""
        # Get existing table structure if it exists
        existing_columns = []
        try:
            result = self.session.execute(text(f"PRAGMA table_info({table_name})"))

            row = result.fetchone()
            if row and hasattr(row, "sql"):
                existing_sql = row.sql.split("(", 1)[1].rsplit(")", 1)[0]
                existing_columns = [
                    col.strip() for col in existing_sql.split(",") if col.strip()
                ]

            if existing_columns:
                logger.debug(
                    f"Table {table_name} exists with columns: {existing_columns}"
                )
                self.rollback_sql.append(f"DROP TABLE IF EXISTS {table_name}")

            elif self.db_type != "sqlite":
                self.rollback_sql.append(f"DROP TABLE IF EXISTS {table_name}")

        except Exception:
            self.rollback_sql.append(f"DROP TABLE IF EXISTS {table_name}")

        column_defs = []
        for column_name, column_type in columns.items():
            if column_name.upper() == "PRIMARY KEY":
                column_defs.append(f"PRIMARY KEY {column_type}")
            else:
                column_defs.append(f"{column_name} {column_type}")

        return f"CREATE TABLE IF NOT EXISTS {table_name} ({', '.join(column_defs)})"

    async def create_table(self, table_name: str, columns: dict[str, str]) -> None:
        """Create a table with the given columns."""
        create_sql = self._get_table_creation_sql(table_name, columns)

        try:
            await self.session.execute(text(create_sql))
            self.rollback_sql.append(f"DROP TABLE IF EXISTS {table_name}")
            await self.session.commit()
            logger.info(f"Created table {table_name}")

        except Exception as e:
            logger.error(f"Failed to create table {table_name}: {e}")
            raise

    async def drop_table(self, table_name: str) -> None:
        """Drop a table."""
        try:
            # Store table creation SQL for rollback
            if self.db_type == "sqlite":
                result = await self.session.execute(
                    text(
                        "SELECT sql FROM sqlite_master WHERE name = :name AND type = 'table'"
                    ),
                    {"name": table_name},
                )

                row = result.fetchone()
                if row:
                    original_sql = row[0]
                    self.rollback_sql.append(original_sql)
                else:
                    self.rollback_sql.append(f"-- Table {table_name} did not exist")

            await self.session.execute(text(f"DROP TABLE IF EXISTS {table_name}"))
            await self.session.commit()

        except Exception as e:
            logger.error(f"Failed to drop table {table_name}: {e}")
            raise

    def _get_index_creation_sql(
        self,
        table_name: str,
        index_name: str,
        columns: list[str],
        is_unique: bool = False,
    ) -> str:
        """Get SQL for creating an index based on database type."""
        if self.db_type == "sqlite" or self.db_type in ["postgresql", "postgres"]:
            unique_clause = "UNIQUE " if is_unique else ""
            columns_clause = ", ".join(columns)
            sql = f"CREATE {unique_clause}INDEX IF NOT EXISTS {index_name} ON {table_name}({columns_clause})"

        elif self.db_type == "mysql":
            unique_clause = "UNIQUE " if is_unique else ""
            columns_clause = ", ".join(columns)
            sql = f"CREATE {unique_clause}INDEX {index_name} ON {table_name}({columns_clause})"

        else:
            # Default fallback
            unique_clause = "UNIQUE " if is_unique else ""
            columns_clause = ", ".join(columns)
            sql = f"CREATE {unique_clause}INDEX {index_name} ON {table_name}({columns_clause})"

        return sql

    def _get_index_drop_sql(self, table_name: str, index_name: str) -> str:
        """Get SQL for dropping an index based on database type."""
        if self.db_type == "sqlite" or self.db_type in ["postgresql", "postgres"]:
            return f"DROP INDEX IF EXISTS {index_name}"
        elif self.db_type == "mysql":
            return f"DROP INDEX {index_name} ON {table_name}"
        else:
            # Default fallback
            return f"DROP INDEX {index_name}"

    async def create_index(
        self,
        table_name: str,
        index_name: str,
        columns: list[str],
        is_unique: bool = False,
    ) -> None:
        """Create an index on the specified table and columns."""
        create_sql = self._get_index_creation_sql(
            table_name, index_name, columns, is_unique
        )
        drop_sql = self._get_index_drop_sql(table_name, index_name)

        try:
            await self.session.execute(text(create_sql))
            self.rollback_sql.append(drop_sql)
            await self.session.commit()
            logger.info(f"Created index {index_name} on table {table_name}")

        except Exception as e:
            logger.error(
                f"Failed to create index {index_name} on table {table_name}: {e}"
            )
            raise

    async def drop_index(self, table_name: str, index_name: str) -> None:
        """Drop an index."""
        try:
            drop_sql = self._get_index_drop_sql(table_name, index_name)
            await self.session.execute(text(drop_sql))
            await self.session.commit()

        except Exception as e:
            logger.error(f"Failed to drop index {index_name}: {e}")
            raise

    def _execute_raw_sql(self, sql: str) -> None:
        """Execute raw SQL with rollback tracking."""
        # Store reverse SQL for more complex operations
        reverse_sql = list(reversed(self.rollback_sql))

        try:
            await self.session.execute(text(sql))
            await self.session.commit()

        except Exception as e:
            logger.error(f"Failed to execute raw SQL: {e}")
            raise

    async def upgrade(self) -> dict[str, Any]:
        """Apply the migration."""
        try:
            await self._get_connection()

            # Get schema definitions
            tables = self.get_tables()
            indexes = self.get_indexes()

            migration_name = self.get_migration_name()

            if await self.is_applied(migration_name):
                return {
                    "success": True,
                    "message": f"Migration {migration_name} already applied",
                    "applied": True,
                }

            # Create tables
            for table_name, columns in tables.items():
                await self.create_table(table_name, columns)

            # Create indexes
            for table_name, table_indexes in indexes.items():
                for idx_name, cols, is_unique in table_indexes:
                    await self.create_index(table_name, idx_name, cols, is_unique)

            # Record migration
            await self.record_migration(migration_name)

            logger.info(f"Successfully applied migration: {migration_name}")

            return {
                "success": True,
                "message": f"Migration {migration_name} applied successfully",
                "applied": True,
            }

        except Exception as e:
            logger.error(f"Migration {migration_name} failed: {e}")
            return {
                "success": False,
                "message": f"Migration {migration_name} failed: {e}",
                "applied": False,
            }
        finally:
            await self._close_connection()

    async def downgrade(self) -> dict[str, Any]:
        """Rollback the migration."""
        migration_name = self.get_migration_name()

        try:
            await self._get_connection()

            if not await self.is_applied(migration_name):
                return {
                    "success": True,
                    "message": f"Migration {migration_name} not applied, nothing to rollback",
                }

            # Execute rollback SQL in reverse order
            for sql in reversed(self.rollback_sql):
                await self.session.execute(text(sql))

            await self.session.commit()

            # Remove migration record
            removed = await self.remove_migration_record(migration_name)
            if not removed:
                logger.warning(
                    f"Could not remove migration record for {migration_name}"
                )

            logger.info(f"Successfully rolled back migration: {migration_name}")

            return {
                "success": True,
                "message": f"Migration {migration_name} rolled back successfully",
            }

        except Exception as e:
            logger.error(f"Rollback of {migration_name} failed: {e}")
            return {
                "success": False,
                "message": f"Rollback of {migration_name} failed: {e}",
            }
        finally:
            await self._close_connection()

    def action(self, action: str) -> None:
        """Placeholder for additional migration actions."""
        pass
