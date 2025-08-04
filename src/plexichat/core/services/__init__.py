"""
PlexiChat Core Services

Service layer providing clean interfaces between API endpoints and core systems.
"""

from .database_service import DatabaseService, get_database_service

__all__ = [
    "DatabaseService",
    "get_database_service"
]
