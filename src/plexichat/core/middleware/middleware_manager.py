"""
PlexiChat Middleware Manager

Middleware management with threading and performance optimization.
"""

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Union, Awaitable

try:
    from plexichat.core.threading.thread_manager import async_thread_manager
except ImportError:
    async_thread_manager = None


# Analytics tracking fallback
async def track_event(*args: Any, **kwargs: Any) -> None:
    """Fallback analytics tracking function."""
    pass


# Performance optimization fallback
PerformanceOptimizationEngine = None


def get_performance_logger() -> logging.Logger:
    """Fallback performance logger function."""
    return logging.getLogger("performance")


logger = logging.getLogger(__name__)
performance_logger = get_performance_logger()


@dataclass
class MiddlewareContext:
    """Middleware execution context."""

    request_id: str
    middleware_type: str
    data: Dict[str, Any]
    metadata: Dict[str, Any]
    start_time: float
    user_id: Optional[int] = None
    session_id: Optional[str] = None


class BaseMiddleware(ABC):
    """Base middleware class."""

    def __init__(self, name: str, priority: int = 100) -> None:
        self.name = name
        self.priority = priority
        self.enabled = True

    @abstractmethod
    async def process(
        self, context: MiddlewareContext, next_middleware: Callable[[MiddlewareContext], Awaitable[Any]]
    ) -> Any:
        """Process middleware."""
        pass

    async def before_process(self, context: MiddlewareContext) -> None:
        """Called before processing."""
        pass

    async def after_process(self, context: MiddlewareContext, result: Any) -> None:
        """Called after processing."""
        pass

    async def on_error(self, context: MiddlewareContext, error: Exception) -> None:
        """Called when an error occurs."""
        pass


class AuthenticationMiddleware(BaseMiddleware):
    """Authentication middleware."""

    def __init__(self, priority: int = 10) -> None:
        super().__init__("authentication", priority)

    async def process(
        self, context: MiddlewareContext, next_middleware: Callable[[MiddlewareContext], Awaitable[Any]]
    ) -> Any:
        """Process authentication."""
        try:
            # Extract authentication token
            auth_token = context.data.get("auth_token")
            if not auth_token:
                raise ValueError("Authentication token required")

            # Verify token (placeholder)
            user_id = await self._verify_token(auth_token)
            if not user_id:
                raise ValueError("Invalid authentication token")

            # Add user info to context
            context.user_id = user_id
            context.metadata["authenticated"] = True

            # Continue to next middleware
            return await next_middleware(context)

        except Exception as e:
            logger.error(f"Authentication error: {e}")
            raise

    async def _verify_token(self, token: str) -> Optional[int]:
        """Verify authentication token."""
        try:
            # Placeholder implementation
            if token.startswith("valid_"):
                return int(token.split("_")[1])
            return None
        except Exception:
            return None


class RateLimitMiddleware(BaseMiddleware):
    """Rate limiting middleware."""

    def __init__(self, priority: int = 20) -> None:
        super().__init__("rate_limit", priority)
        self.rate_limits: Dict[str, List[float]] = {}
        self.rate_limit_config = {"requests_per_minute": 60}

    async def process(
        self, context: MiddlewareContext, next_middleware: Callable[[MiddlewareContext], Awaitable[Any]]
    ) -> Any:
        """Process rate limiting."""
        try:
            # Simple rate limiting logic
            current_time = time.time()
            client_id = context.metadata.get("client_id", "unknown")

            if client_id not in self.rate_limits:
                self.rate_limits[client_id] = []

            # Clean old requests
            self.rate_limits[client_id] = [
                t for t in self.rate_limits[client_id] if current_time - t < 60
            ]

            # Check rate limit
            if len(self.rate_limits[client_id]) >= self.rate_limit_config["requests_per_minute"]:
                raise Exception("Rate limit exceeded")

            self.rate_limits[client_id].append(current_time)

            # Continue to next middleware
            return await next_middleware(context)

        except Exception as e:
            logger.error(f"Rate limiting error: {e}")
            raise


class ValidationMiddleware(BaseMiddleware):
    """Data validation middleware."""

    def __init__(self, priority: int = 30) -> None:
        super().__init__("validation", priority)

    async def process(
        self, context: MiddlewareContext, next_middleware: Callable[[MiddlewareContext], Awaitable[Any]]
    ) -> Any:
        """Process data validation."""
        try:
            # Basic validation
            if not isinstance(context.data, dict):
                raise ValueError("Invalid data format")

            # Continue to next middleware
            return await next_middleware(context)

        except Exception as e:
            logger.error(f"Validation error: {e}")
            raise


class LoggingMiddleware(BaseMiddleware):
    """Logging middleware."""

    def __init__(self, priority: int = 40) -> None:
        super().__init__("logging", priority)

    async def process(
        self, context: MiddlewareContext, next_middleware: Callable[[MiddlewareContext], Awaitable[Any]]
    ) -> Any:
        """Process logging."""
        try:
            logger.info(
                f"Processing {context.middleware_type} request {context.request_id}"
            )

            # Continue to next middleware
            result = await next_middleware(context)

            # Log completion
            duration = time.time() - context.start_time
            logger.info(
                f"Completed {context.middleware_type} request {context.request_id} in {duration:.3f}s"
            )

            return result

        except Exception as e:
            duration = time.time() - context.start_time
            logger.error(
                f"Failed {context.middleware_type} request {context.request_id} in {duration:.3f}s: {e}"
            )
            raise


class PerformanceMiddleware(BaseMiddleware):
    """Performance tracking middleware."""

    def __init__(self, performance_logger: Optional[logging.Logger] = None, priority: int = 50) -> None:
        super().__init__("performance", priority)
        self.performance_logger = performance_logger or logger

    async def process(
        self, context: MiddlewareContext, next_middleware: Callable[[MiddlewareContext], Awaitable[Any]]
    ) -> Any:
        """Process performance tracking."""
        try:
            start_time = time.perf_counter()

            # Continue to next middleware
            result = await next_middleware(context)

            # Track performance
            duration = time.perf_counter() - start_time

            try:
                if hasattr(self.performance_logger, 'record_metric'):
                    self.performance_logger.record_metric(
                        f"{context.middleware_type}_duration", duration, "seconds"
                    )

                if hasattr(self.performance_logger, 'increment_counter'):
                    self.performance_logger.increment_counter(
                        f"{context.middleware_type}_requests", 1, "count"
                    )

                # Track event
                await track_event(
                    "middleware_processed",
                    properties={
                        "middleware_type": context.middleware_type,
                        "duration": duration,
                    }
                )

            except Exception as tracking_error:
                logger.warning(f"Performance tracking error: {tracking_error}")

            return result

        except Exception as e:
            duration = time.perf_counter() - context.start_time
            
            try:
                if hasattr(self.performance_logger, 'increment_counter'):
                    self.performance_logger.increment_counter(
                        f"{context.middleware_type}_errors", 1, "count"
                    )

                # Track error event
                await track_event(
                    "middleware_error",
                    properties={
                        "middleware_type": context.middleware_type,
                        "error": str(e),
                    }
                )

            except Exception as tracking_error:
                logger.warning(f"Performance error tracking error: {tracking_error}")

            raise


class MiddlewareManager:
    """Middleware manager with threading support."""

    def __init__(self) -> None:
        # Threading
        self.lock = threading.Lock()

        # Middleware storage
        self.middleware_stacks: Dict[str, List[BaseMiddleware]] = {}

        # Statistics
        self.stats: Dict[str, int] = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
        }

    def register_middleware(self, middleware_type: str, middleware: BaseMiddleware) -> None:
        """Register middleware for a specific type."""
        try:
            if middleware_type not in self.middleware_stacks:
                self.middleware_stacks[middleware_type] = []

            self.middleware_stacks[middleware_type].append(middleware)

            # Sort by priority (lower priority = higher precedence)
            self.middleware_stacks[middleware_type].sort(key=lambda m: m.priority)

            logger.info(
                f"Middleware registered: {middleware.name} for {middleware_type}"
            )

        except Exception as e:
            logger.error(f"Error registering middleware: {e}")

    def unregister_middleware(self, middleware_type: str, middleware_name: str) -> bool:
        """Unregister middleware."""
        try:
            if middleware_type not in self.middleware_stacks:
                return False

            stack = self.middleware_stacks[middleware_type]
            for i, middleware in enumerate(stack):
                if middleware.name == middleware_name:
                    stack.pop(i)
                    logger.info(
                        f"Middleware unregistered: {middleware_name} from {middleware_type}"
                    )
                    return True
            return False

        except Exception as e:
            logger.error(f"Error unregistering middleware: {e}")
            return False

    async def process(
        self,
        middleware_type: str,
        request_id: str,
        data: Dict[str, Any],
        **kwargs: Any
    ) -> Any:
        """Process request through middleware stack."""
        self.stats["total_requests"] += 1

        try:
            # Create context
            context = MiddlewareContext(
                request_id=request_id,
                middleware_type=middleware_type,
                data=data,
                metadata=kwargs,
                start_time=time.time()
            )

            # Get middleware stack
            middleware_stack = self.middleware_stacks.get(middleware_type, [])
            enabled_middleware = [m for m in middleware_stack if m.enabled]

            if not enabled_middleware:
                # No middleware, return data as-is
                return data

            # Process through middleware stack
            result = await self._execute_middleware_stack(
                context, enabled_middleware, 0
            )

            self.stats["successful_requests"] += 1
            return result

        except Exception as e:
            self.stats["failed_requests"] += 1
            logger.error(f"Middleware processing error: {e}")
            raise

    async def _execute_middleware_stack(
        self,
        context: MiddlewareContext,
        middleware_stack: List[BaseMiddleware],
        index: int
    ) -> Any:
        """Execute middleware stack recursively."""
        try:
            if index >= len(middleware_stack):
                # End of stack, return data
                return context.data

            current_middleware = middleware_stack[index]

            # Define next middleware function
            async def next_middleware(ctx: MiddlewareContext) -> Any:
                return await self._execute_middleware_stack(
                    ctx, middleware_stack, index + 1
                )

            # Execute current middleware
            await current_middleware.before_process(context)
            try:
                result = await current_middleware.process(context, next_middleware)
                await current_middleware.after_process(context, result)
                return result
            except Exception as e:
                await current_middleware.on_error(context, e)
                raise

        except Exception as e:
            logger.error(f"Middleware execution error at index {index}: {e}")
            raise

    def get_middleware_stack(self, middleware_type: str) -> List[Dict[str, Any]]:
        """Get middleware stack for a type."""
        try:
            stack = self.middleware_stacks.get(middleware_type, [])
            return [
                {
                    "name": middleware.name,
                    "priority": middleware.priority,
                    "enabled": middleware.enabled,
                    "type": type(middleware).__name__,
                }
                for middleware in stack
            ]
        except Exception as e:
            logger.error(f"Error getting middleware stack: {e}")
            return []

    def enable_middleware(self, middleware_type: str, middleware_name: str) -> bool:
        """Enable middleware."""
        try:
            stack = self.middleware_stacks.get(middleware_type, [])
            for middleware in stack:
                if middleware.name == middleware_name:
                    middleware.enabled = True
                    logger.info(f"Middleware enabled: {middleware_name}")
                    return True
            return False
        except Exception as e:
            logger.error(f"Error enabling middleware: {e}")
            return False

    def disable_middleware(self, middleware_type: str, middleware_name: str) -> bool:
        """Disable middleware."""
        try:
            stack = self.middleware_stacks.get(middleware_type, [])
            for middleware in stack:
                if middleware.name == middleware_name:
                    middleware.enabled = False
                    logger.info(f"Middleware disabled: {middleware_name}")
                    return True
            return False
        except Exception as e:
            logger.error(f"Error disabling middleware: {e}")
            return False

    def get_stats(self) -> Dict[str, Any]:
        """Get middleware manager statistics."""
        try:
            middleware_counts = {
                mtype: len(stack) for mtype, stack in self.middleware_stacks.items()
            }

            return {
                **self.stats,
                "middleware_types": list(self.middleware_stacks.keys()),
                "middleware_counts": middleware_counts,
            }

        except Exception as e:
            logger.error(f"Error getting stats: {e}")
            return {}


# Global middleware manager
middleware_manager = MiddlewareManager()

# Register default middleware
middleware_manager.register_middleware("api", AuthenticationMiddleware())
middleware_manager.register_middleware("api", RateLimitMiddleware())
middleware_manager.register_middleware("api", ValidationMiddleware())
middleware_manager.register_middleware("api", LoggingMiddleware())
middleware_manager.register_middleware("api", PerformanceMiddleware(performance_logger))


# Convenience functions
def register_middleware(middleware_type: str, middleware: BaseMiddleware) -> None:
    """Register middleware using global manager."""
    middleware_manager.register_middleware(middleware_type, middleware)


def unregister_middleware(middleware_type: str, middleware_name: str) -> bool:
    """Unregister middleware using global manager."""
    return middleware_manager.unregister_middleware(middleware_type, middleware_name)


async def process_with_middleware(
    middleware_type: str, request_id: str, data: Dict[str, Any], **kwargs: Any
) -> Any:
    """Process request with middleware using global manager."""
    return await middleware_manager.process(middleware_type, request_id, data, **kwargs)


def get_middleware_stack(middleware_type: str) -> List[Dict[str, Any]]:
    """Get middleware stack using global manager."""
    return middleware_manager.get_middleware_stack(middleware_type)