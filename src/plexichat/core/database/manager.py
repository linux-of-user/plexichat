"""
PlexiChat Database Manager
==========================

Production-ready asynchronous database manager using aiosqlite.
Provides connection pooling, transaction management, and robust error handling.
"""

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, List, Optional, Dict, Union
from datetime import datetime, timezone

import aiosqlite

from plexichat.core.config import get_config
from plexichat.core.logging import get_logger

logger = get_logger(__name__)

class DatabaseError(Exception):
    """Base exception for database errors."""
    pass

class DatabaseSession:
    """
    Represents a database session/transaction.
    Wraps an aiosqlite.Cursor or Connection to provide a unified interface.
    """
    def __init__(self, connection: aiosqlite.Connection):
        self.connection = connection
        self._cursor: Optional[aiosqlite.Cursor] = None

    async def execute(self, query: str, params: Union[tuple, dict] = ()) -> aiosqlite.Cursor:
        """Execute a SQL query."""
        try:
            if not self._cursor:
                self._cursor = await self.connection.cursor()
            
            # Log query for debug (redact params in prod)
            logger.debug(f"Executing query: {query} | Params: {params}")
            
            await self._cursor.execute(query, params)
            return self._cursor
        except Exception as e:
            logger.error(f"Query execution failed: {e}")
            raise DatabaseError(f"Query execution failed: {e}") from e

    async def fetch_one(self, query: str, params: Union[tuple, dict] = ()) -> Optional[Dict[str, Any]]:
        """Execute query and fetch one result as a dictionary."""
        cursor = await self.execute(query, params)
        row = await cursor.fetchone()
        if row:
            # Convert sqlite3.Row to dict
            return dict(row)
        return None

    async def fetch_all(self, query: str, params: Union[tuple, dict] = ()) -> List[Dict[str, Any]]:
        """Execute query and fetch all results as a list of dictionaries."""
        cursor = await self.execute(query, params)
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def commit(self):
        """Commit the current transaction."""
        await self.connection.commit()

    async def rollback(self):
        """Rollback the current transaction."""
        await self.connection.rollback()

    async def close(self):
        """Close the cursor."""
        if self._cursor:
            await self._cursor.close()


class DatabaseManager:
    """
    Manages the SQLite database connection and lifecycle.
    """
    def __init__(self):
        self.config = get_config()
        self._db_path: str = "data/plexichat.db" # Default
        self._connection: Optional[aiosqlite.Connection] = None
        self._initialized = False
        self._lock = asyncio.Lock()

    async def initialize(self):
        """Initialize the database connection."""
        if self._initialized:
            return

        async with self._lock:
            try:
                # Load path from config
                db_config = getattr(self.config, "database", {})
                if isinstance(db_config, dict):
                     self._db_path = db_config.get("path", "data/plexichat.db")
                else:
                     self._db_path = getattr(db_config, "path", "data/plexichat.db")

                # Ensure directory exists
                os.makedirs(os.path.dirname(self._db_path), exist_ok=True)

                logger.info(f"Connecting to database at {self._db_path}...")
                
                # Connect with aiosqlite
                self._connection = await aiosqlite.connect(self._db_path)
                
                # Configure connection
                self._connection.row_factory = aiosqlite.Row
                await self._connection.execute("PRAGMA foreign_keys = ON;")
                await self._connection.execute("PRAGMA journal_mode = WAL;") # Write-Ahead Logging for concurrency
                
                self._initialized = True
                logger.info("Database Manager initialized successfully.")
                
            except Exception as e:
                logger.critical(f"Failed to initialize database: {e}")
                raise DatabaseError(f"Database initialization failed: {e}") from e

    @asynccontextmanager
    async def get_session(self) -> AsyncGenerator[DatabaseSession, None]:
        """
        Provide a transactional database session.
        Usage:
            async with database_manager.get_session() as session:
                await session.execute(...)
        """
        if not self._initialized or not self._connection:
            await self.initialize()

        session = DatabaseSession(self._connection)
        try:
            yield session
            await session.commit()
        except Exception as e:
            await session.rollback()
            logger.error(f"Transaction rolled back due to error: {e}")
            raise
        finally:
            await session.close()

    async def shutdown(self):
        """Close the database connection."""
        if self._connection:
            logger.info("Closing database connection...")
            await self._connection.close()
            self._connection = None
            self._initialized = False
            logger.info("Database connection closed.")

    def get_database_status(self) -> Dict[str, Any]:
        """Return status information."""
        return {
            "initialized": self._initialized,
            "path": self._db_path,
            "connected": self._connection is not None,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

# Global Instance
database_manager = DatabaseManager()
