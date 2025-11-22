"""
Database Manager
Provides a unified interface for database operations with security integration.
"""

import asyncio
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool
from sqlalchemy import text

from plexichat.core.auth.permissions import (
    DBOperation,
    ResourceType,
    check_permission,
    format_permission,
)
from plexichat.core.config import config  # Use the singleton instance
from plexichat.core.logging import get_logger

logger = get_logger(__name__)


class DatabaseSession:
    """
    Wrapper around AsyncSession to add security checks and convenience methods.
    """

    def __init__(
        self,
        session: AsyncSession,
        user_permissions: set[str] | None = None,
    ):
        self.session = session
        self.user_permissions = user_permissions or set()

    async def execute(
        self,
        query: str,
        params: dict[str, Any] | None = None,
        check_perms: bool = False,
        resource_type: ResourceType = ResourceType.TABLE,
        resource_name: str = "any",
    ) -> Any:
        """
        Execute a query with optional permission checking.
        """
        if check_perms:
            required_perm = format_permission(
                resource_type, DBOperation.WRITE, resource_name
            )
            check_permission(required_perm, self.user_permissions)

        try:
            result = await self.session.execute(text(query), params)
            return result
        except Exception as e:
            logger.error(f"Database execution error: {e}")
            raise

    async def fetchall(
        self,
        query: str,
        params: dict[str, Any] | None = None,
        check_perms: bool = False,
        resource_type: ResourceType = ResourceType.TABLE,
        resource_name: str = "any",
    ) -> list[dict[str, Any]]:
        """
        Execute a query and return all results as a list of dictionaries.
        """
        if check_perms:
            required_perm = format_permission(
                resource_type, DBOperation.READ, resource_name
            )
            check_permission(required_perm, self.user_permissions)

        try:
            result = await self.session.execute(text(query), params)
            # Convert rows to dicts
            return [dict(row._mapping) for row in result.fetchall()]
        except Exception as e:
            logger.error(f"Database fetchall error: {e}")
            raise

    async def fetchone(
        self,
        query: str,
        params: dict[str, Any] | None = None,
        check_perms: bool = False,
        resource_type: ResourceType = ResourceType.TABLE,
        resource_name: str = "any",
    ) -> dict[str, Any] | None:
        """
        Execute a query and return a single result as a dictionary.
        """
        if check_perms:
            required_perm = format_permission(
                resource_type, DBOperation.READ, resource_name
            )
            check_permission(required_perm, self.user_permissions)

        try:
            result = await self.session.execute(text(query), params)
            row = result.fetchone()
            return dict(row._mapping) if row else None
        except Exception as e:
            logger.error(f"Database fetchone error: {e}")
            raise

    async def commit(self):
        """Commit the transaction."""
        await self.session.commit()

    async def rollback(self):
        """Rollback the transaction."""
        await self.session.rollback()


class DatabaseManager:
    """
    Manages database connections and sessions.
    """

    def __init__(self):
        self.engine: AsyncEngine | None = None
        self.session_maker: async_sessionmaker | None = None
        self._initialized = False

    async def initialize(self):
        """Initialize the database connection."""
        if self._initialized:
            return

        db_url = config.get("database.url", "sqlite+aiosqlite:///plexichat.db")
        
        # Ensure we are using an async driver for SQLite
        if db_url.startswith("sqlite://") and not db_url.startswith("sqlite+aiosqlite://"):
             db_url = db_url.replace("sqlite://", "sqlite+aiosqlite://")

        logger.info(f"Initializing database with URL: {db_url}")

        try:
            self.engine = create_async_engine(
                db_url,
                echo=config.get("database.echo", False),
                poolclass=NullPool if "sqlite" in db_url else None, # SQLite usually doesn't need pooling in this setup
            )

            self.session_maker = async_sessionmaker(
                self.engine, expire_on_commit=False, class_=AsyncSession
            )
            
            # Test connection
            async with self.engine.begin() as conn:
                await conn.execute(text("SELECT 1"))
            
            self._initialized = True
            logger.info("Database initialized successfully")

        except Exception as e:
            logger.critical(f"Failed to initialize database: {e}")
            raise

    async def close(self):
        """Close the database connection."""
        if self.engine:
            await self.engine.dispose()
            self.engine = None
            self._initialized = False
            logger.info("Database connection closed")

    @asynccontextmanager
    async def get_session(
        self, user_permissions: set[str] | None = None
    ) -> AsyncGenerator[DatabaseSession, None]:
        """
        Get a database session context manager.
        """
        if not self._initialized:
            await self.initialize()

        if not self.session_maker:
             raise RuntimeError("Database not initialized")

        async with self.session_maker() as session:
            db_session = DatabaseSession(session, user_permissions)
            try:
                yield db_session
                # Auto-commit is not enabled by default in this wrapper, 
                # user must call commit() explicitly or we can do it here?
                # Usually explicit commit is better for control.
                # But for convenience, we can commit on exit if no exception.
                await session.commit()
            except Exception as e:
                await session.rollback()
                raise
            finally:
                await session.close()

# Global instance
database_manager = DatabaseManager()
