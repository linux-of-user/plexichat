"""
Database Session Management

Provides session management and connection handling for the database abstraction layer.
"""

from .manager import DatabaseSession, database_manager

# Re-export for convenience
__all__ = ["DatabaseSession", "get_session"]

async def get_session():
    """Get a database session."""
    return database_manager.get_session()
