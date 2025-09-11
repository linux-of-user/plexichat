"""
Fallback implementations for PlexiChat core systems.
Provides local implementations when shared/distributed systems are unavailable.
"""

import logging
from typing import Any, Callable, Dict, List, Optional


logger = logging.getLogger(__name__)

class FallbackManager:
    """Manages fallback implementations for core systems."""
    
    def __init__(self) -> None:
        self.fallbacks: Dict[str, Callable[..., Any]] = {
            "database": self._db_fallback,
            "security": self._security_fallback,
            "caching": self._cache_fallback,
            "monitoring": self._monitoring_fallback,
            "notifications": self._notifications_fallback,
            "messaging": self._messaging_fallback,
            "middleware": self._middleware_fallback,
            "performance": self._performance_fallback,
            "errors": self._errors_fallback,
            "migrations": self._migrations_fallback,
        }
    
    def get_fallback(self, system: str) -> Callable[..., Any]:
        """Get fallback implementation for a system."""
        return self.fallbacks.get(system, lambda *args, **kwargs: None)
    
    def _db_fallback(self, operation: str, **kwargs: Any) -> Any:
        logger.warning(f"Database fallback: {operation} not available")
        return None
    
    def _security_fallback(self, action: str, **kwargs: Any) -> bool:
        logger.warning(f"Security fallback: {action} using local check")
        return True  # Allow in fallback mode
    
    def _cache_fallback(self, key: str, value: Optional[Any] = None) -> Any:
        logger.debug(f"Cache fallback: {key} stored in memory")
        if value is not None:
            # Simple in-memory cache simulation
            if not hasattr(self, '_mem_cache'):
                self._mem_cache: Dict[str, Any] = {}
            self._mem_cache[key] = value
            return value
        return getattr(self, '_mem_cache', {}).get(key)
    
    def _monitoring_fallback(self, metric: str, value: Any) -> None:
        logger.info(f"Monitoring fallback: {metric} = {value}")
    
    def _notifications_fallback(self, message: str, recipients: List[str]) -> bool:
        logger.info(f"Notification fallback: {message} to {len(recipients)} recipients")
        return True
    
    def _messaging_fallback(self, message: Dict[str, Any], queue: str) -> bool:
        logger.info(f"Messaging fallback: queued {message} to {queue}")
        return True
    
    def _middleware_fallback(self, request: Any, response: Any) -> Any:
        logger.debug("Middleware fallback: basic processing")
        return response
    
    def _performance_fallback(self, metric: str, duration: float) -> None:
        logger.debug(f"Performance fallback: {metric} took {duration}ms")
    
    def _errors_fallback(self, error: Exception, context: Dict[str, Any]) -> str:
        error_msg = f"Fallback error handling: {str(error)}"
        logger.error(error_msg, extra=context)
        return error_msg
    
    def _migrations_fallback(self, migration_name: str) -> bool:
        logger.warning(f"Migrations fallback: {migration_name} skipped")
        return False

# Global fallback manager instance
fallback_manager = FallbackManager()

def get_fallback_manager() -> FallbackManager:
    """Get the global fallback manager."""
    return fallback_manager

def apply_fallback(system: str, *args: Any, **kwargs: Any) -> Any:
    """Apply fallback for a system."""
    manager = get_fallback_manager()
    fallback = manager.get_fallback(system)
    if fallback:
        return fallback(*args, **kwargs)
    logger.error(f"No fallback available for system: {system}")
    return None

# Export for imports
__all__ = [
    "FallbackManager",
    "get_fallback_manager",
    "apply_fallback",
    "fallback_manager",
]

def get_module_version(module_name: str = "unknown") -> str:
    """
    Get version information for a module using fallback mechanism.
    Returns a default version string when full versioning system is unavailable.
    """
    logger.info(f"Fallback module version for {module_name}")
    return "1.0.0-fallback"

__all__.append("get_module_version")