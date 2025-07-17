"""
PlexiChat Database Configuration

Provides database configuration and connection management.
"""

from typing import Optional, Any, Dict
import logging

logger = logging.getLogger(__name__)

class MockDatabase:
    """Mock database for development/testing."""
    
    def __init__(self):
        self.connected = False
        self.data = {}
    
    async def connect(self):
        """Connect to database."""
        self.connected = True
        logger.info("Mock database connected")
    
    async def disconnect(self):
        """Disconnect from database."""
        self.connected = False
        logger.info("Mock database disconnected")
    
    async def execute(self, query: str, params: Optional[Dict[str, Any]] = None):
        """Execute a database query."""
        logger.debug(f"Executing query: {query}")
        return {"success": True, "rows": []}
    
    def get_session(self):
        """Get database session."""
        return self

# Global database instance
database = MockDatabase()

__all__ = ["database", "MockDatabase"]
