"""PlexiChat Middleware"""

import logging
# Typing imports not used

try:
    from .middleware_manager import (
        MiddlewareManager, BaseMiddleware, MiddlewareContext,
        AuthenticationMiddleware, RateLimitMiddleware, ValidationMiddleware,
        LoggingMiddleware, PerformanceMiddleware,
        middleware_manager, register_middleware, unregister_middleware,
        process_with_middleware, get_middleware_stack
    )
    logger = logging.getLogger(__name__)
    logger.info("Middleware modules imported")
except ImportError as e:
    logger = logging.getLogger(__name__)
    logger.warning(f"Could not import middleware modules: {e}")

__all__ = [
    "MiddlewareManager",
    "BaseMiddleware",
    "MiddlewareContext",
    "AuthenticationMiddleware",
    "RateLimitMiddleware",
    "ValidationMiddleware",
    "LoggingMiddleware",
    "PerformanceMiddleware",
    "middleware_manager",
    "register_middleware",
    "unregister_middleware",
    "process_with_middleware",
    "get_middleware_stack",
]

__version__ = "1.0.0"
