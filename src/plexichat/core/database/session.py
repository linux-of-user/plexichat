"""
Database Session Management

Provides session management and connection handling for the database abstraction layer.
"""

from collections.abc import AsyncGenerator

from plexichat.core.database.manager import DatabaseSession, database_manager

# Re-export for convenience
__all__ = ["DatabaseSession", "get_session"]


async def get_session(
    user_permissions: set[str] | None = None,
) -> AsyncGenerator[DatabaseSession, None]:
    """Get a database session with optional user permissions."""
    async with database_manager.get_session(user_permissions) as session:
        yield session
