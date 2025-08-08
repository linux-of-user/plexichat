"""
PlexiChat Core Services

Service layer providing clean interfaces between API endpoints and core systems.
"""

try:
    # from .database_service import DatabaseService, get_database_service  # type: ignore
    pass  # Temporarily disabled
except ImportError:
    # Fallback implementations
    class DatabaseService:  # type: ignore
        def __init__(self):
            pass

    def get_database_service():  # type: ignore
        return DatabaseService()

# Use fallback implementations to avoid import issues
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)
logger.warning("Using fallback service implementations")

# Fallback service management
class ServiceManager:  # type: ignore
    def __init__(self):
        self._services = {}

    def register(self, name: str, service: Any):
        self._services[name] = service

    def get(self, name: str):
        return self._services.get(name)

    def list(self):
        return list(self._services.keys())

_service_manager = ServiceManager()

def get_service_manager():  # type: ignore
    return _service_manager

def register_service(name: str, service: Any):  # type: ignore
    return _service_manager.register(name, service)

def get_service(name: str):  # type: ignore
    return _service_manager.get(name)

def list_services():  # type: ignore
    return _service_manager.list()

# Import service loader if available
try:
    from .service_loader import ServiceLoader, load_services  # type: ignore
except ImportError:
    class ServiceLoader:  # type: ignore
        def load_all(self):
            pass

    def load_services():
        pass

__all__ = [
    "DatabaseService",
    "get_database_service",
    "ServiceManager",
    "get_service_manager",
    "register_service",
    "get_service",
    "list_services",
    "ServiceLoader",
    "load_services",
]
