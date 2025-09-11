"""
PlexiChat Core Services

Service layer providing clean interfaces between API endpoints and core systems.
"""

import logging
from typing import Any, Dict, Optional

from plexichat.core.services.core_services import DatabaseService, get_database_service

logger = logging.getLogger(__name__)

try:
    from plexichat.core.utils.fallbacks import ServiceManager, get_fallback_instance

    USE_SHARED_FALLBACKS = True
    logger.info("Using shared fallback implementations for services")
except ImportError:
    # Fallback to local definitions if shared fallbacks unavailable
    USE_SHARED_FALLBACKS = False
    logger.warning("Shared fallbacks unavailable, using local implementations")

if USE_SHARED_FALLBACKS:
    _service_manager = get_fallback_instance("ServiceManager")
else:
    # Local fallbacks (preserved for compatibility)
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
from plexichat.core.services.core_services import ServiceLoader, load_services

__all__ = [
    "DatabaseService",
    "ServiceLoader",
    "ServiceManager",
    "get_database_service",
    "get_service",
    "get_service_manager",
    "list_services",
    "load_services",
    "register_service",
]

from plexichat.core.utils.fallbacks import get_module_version

__version__ = get_module_version()
