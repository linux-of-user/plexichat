"""PlexiChat Middleware"""

import logging

# Typing imports not used

try:
    from plexichat.core.middleware.middleware_manager import (
        AuthenticationMiddleware,
        BaseMiddleware,
        LoggingMiddleware,
        MiddlewareContext,
        MiddlewareManager,
        PerformanceMiddleware,
        RateLimitMiddleware,
        ValidationMiddleware,
        get_middleware_stack,
        middleware_manager,
        process_with_middleware,
        register_middleware,
        unregister_middleware,
    )

    logger = logging.getLogger(__name__)
    logger.info("Middleware modules imported")
except ImportError as e:
    logger = logging.getLogger(__name__)
    logger.warning(f"Could not import middleware modules: {e}")

__all__ = [
    "AuthenticationMiddleware",
    "BaseMiddleware",
    "LoggingMiddleware",
    "MiddlewareContext",
    "MiddlewareManager",
    "PerformanceMiddleware",
    "RateLimitMiddleware",
    "ValidationMiddleware",
    "get_middleware_stack",
    "middleware_manager",
    "process_with_middleware",
    "register_middleware",
    "unregister_middleware",
]

from plexichat.core.utils.fallbacks import get_module_version

__version__ = get_module_version()
