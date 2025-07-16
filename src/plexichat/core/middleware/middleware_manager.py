"""
PlexiChat Middleware Manager

Middleware management with threading and performance optimization.
"""

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Optional, Union
from dataclasses import dataclass

try:
    from plexichat.core.threading.thread_manager import async_thread_manager
except ImportError:
    async_thread_manager = None

try:
    from plexichat.core.analytics.analytics_manager import track_event
except ImportError:
    track_event = None

try:
    from plexichat.infrastructure.performance.optimization_engine import PerformanceOptimizationEngine
    from plexichat.core_system.logging.performance_logger import get_performance_logger
except ImportError:
    PerformanceOptimizationEngine = None
    get_performance_logger = None

logger = logging.getLogger(__name__)
performance_logger = get_performance_logger() if get_performance_logger else None

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
    
    def __init__(self, name: str, priority: int = 100):
        self.name = name
        self.priority = priority
        self.enabled = True
    
    @abstractmethod
    async def process(self, context: MiddlewareContext, next_middleware: Callable) -> Any:
        """Process middleware."""
        pass
    
    async def before_process(self, context: MiddlewareContext):
        """Called before processing."""
        pass
    
    async def after_process(self, context: MiddlewareContext, result: Any):
        """Called after processing."""
        pass
    
    async def on_error(self, context: MiddlewareContext, error: Exception):
        """Called when an error occurs."""
        pass

class AuthenticationMiddleware(BaseMiddleware):
    """Authentication middleware."""
    
    def __init__(self, priority: int = 10):
        super().__init__("authentication", priority)
    
    async def process(self, context: MiddlewareContext, next_middleware: Callable) -> Any:
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
    
    def __init__(self, requests_per_minute: int = 60, priority: int = 20):
        super().__init__("rate_limit", priority)
        self.requests_per_minute = requests_per_minute
        self.request_counts = {}
    
    async def process(self, context: MiddlewareContext, next_middleware: Callable) -> Any:
        """Process rate limiting."""
        try:
            # Get client identifier
            client_id = context.user_id or context.metadata.get("ip_address", "unknown")
            
            # Check rate limit
            if not await self._check_rate_limit(client_id):
                raise ValueError("Rate limit exceeded")
            
            # Continue to next middleware
            return await next_middleware(context)
            
        except Exception as e:
            logger.error(f"Rate limit error: {e}")
            raise
    
    async def _check_rate_limit(self, client_id: Union[int, str]) -> bool:
        """Check if client is within rate limit."""
        try:
            current_time = time.time()
            minute_window = int(current_time // 60)
            
            key = f"{client_id}_{minute_window}"
            
            if key not in self.request_counts:
                self.request_counts[key] = 0
            
            self.request_counts[key] += 1
            
            # Clean old entries
            old_keys = [k for k in self.request_counts.keys() 
                       if int(k.split("_")[-1]) < minute_window - 1]
            for old_key in old_keys:
                del self.request_counts[old_key]
            
            return self.request_counts[key] <= self.requests_per_minute
            
        except Exception as e:
            logger.error(f"Rate limit check error: {e}")
            return True  # Allow on error

class ValidationMiddleware(BaseMiddleware):
    """Data validation middleware."""
    
    def __init__(self, schema: Optional[Dict[str, Any]] = None, priority: int = 30):
        super().__init__("validation", priority)
        self.schema = schema or {}
    
    async def process(self, context: MiddlewareContext, next_middleware: Callable) -> Any:
        """Process validation."""
        try:
            # Validate data against schema
            if not await self._validate_data(context.data):
                raise ValueError("Data validation failed")
            
            # Continue to next middleware
            return await next_middleware(context)
            
        except Exception as e:
            logger.error(f"Validation error: {e}")
            raise
    
    async def _validate_data(self, data: Dict[str, Any]) -> bool:
        """Validate data against schema."""
        try:
            # Placeholder validation
            if not isinstance(data, dict):
                return False
            
            # Check required fields
            required_fields = self.schema.get("required", [])
            for field in required_fields:
                if field not in data:
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Data validation error: {e}")
            return False

class LoggingMiddleware(BaseMiddleware):
    """Logging middleware."""
    
    def __init__(self, priority: int = 1000):
        super().__init__("logging", priority)
    
    async def process(self, context: MiddlewareContext, next_middleware: Callable) -> Any:
        """Process logging."""
        start_time = time.time()
        
        try:
            logger.info(f"Processing {context.middleware_type} request {context.request_id}")
            
            # Continue to next middleware
            result = await next_middleware(context)
            
            # Log success
            duration = time.time() - start_time
            logger.info(f"Completed {context.middleware_type} request {context.request_id} in {duration:.3f}s")
            
            return result
            
        except Exception as e:
            # Log error
            duration = time.time() - start_time
            logger.error(f"Failed {context.middleware_type} request {context.request_id} in {duration:.3f}s: {e}")
            raise

class PerformanceMiddleware(BaseMiddleware):
    """Performance tracking middleware."""
    
    def __init__(self, priority: int = 1001):
        super().__init__("performance", priority)
    
    async def process(self, context: MiddlewareContext, next_middleware: Callable) -> Any:
        """Process performance tracking."""
        start_time = time.time()
        
        try:
            # Continue to next middleware
            result = await next_middleware(context)
            
            # Track performance
            duration = time.time() - start_time
            
            if self.performance_logger:
                self.performance_logger.record_metric(
                    f"{context.middleware_type}_duration", duration, "seconds"
                )
                self.performance_logger.record_metric(
                    f"{context.middleware_type}_requests", 1, "count"
                )
            
            # Track analytics
            if track_event:
                await track_event(
                    "middleware_processed",
                    user_id=context.user_id,
                    properties={
                        "middleware_type": context.middleware_type,
                        "request_id": context.request_id,
                        "duration": duration,
                        "success": True
                    }
                )
            
            return result
            
        except Exception as e:
            # Track error
            duration = time.time() - start_time
            
            if self.performance_logger:
                self.performance_logger.record_metric(
                    f"{context.middleware_type}_errors", 1, "count"
                )
            
            if track_event:
                await track_event(
                    "middleware_error",
                    user_id=context.user_id,
                    properties={
                        "middleware_type": context.middleware_type,
                        "request_id": context.request_id,
                        "duration": duration,
                        "error": str(e)
                    }
                )
            
            raise

class MiddlewareManager:
    """Middleware manager with threading support."""
    
    def __init__(self):
        self.performance_logger = performance_logger
        self.async_thread_manager = async_thread_manager
        
        # Middleware storage
        self.middleware_stacks: Dict[str, List[BaseMiddleware]] = {}
        
        # Statistics
        self.requests_processed = 0
        self.requests_failed = 0
        self.total_processing_time = 0.0
    
    def register_middleware(self, middleware_type: str, middleware: BaseMiddleware):
        """Register middleware for a specific type."""
        try:
            if middleware_type not in self.middleware_stacks:
                self.middleware_stacks[middleware_type] = []
            
            self.middleware_stacks[middleware_type].append(middleware)
            
            # Sort by priority (lower priority = earlier execution)
            self.middleware_stacks[middleware_type].sort(key=lambda m: m.priority)
            
            logger.info(f"Middleware registered: {middleware.name} for {middleware_type}")
            
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
                    del stack[i]
                    logger.info(f"Middleware unregistered: {middleware_name} from {middleware_type}")
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error unregistering middleware: {e}")
            return False
    
    async def process(self, middleware_type: str, request_id: str, data: Dict[str, Any],
                     metadata: Dict[str, Any] = None) -> Any:
        """Process request through middleware stack."""
        try:
            start_time = time.time()
            
            # Create context
            context = MiddlewareContext(
                request_id=request_id,
                middleware_type=middleware_type,
                data=data,
                metadata=metadata or {},
                start_time=start_time
            )
            
            # Get middleware stack
            middleware_stack = self.middleware_stacks.get(middleware_type, [])
            enabled_middleware = [m for m in middleware_stack if m.enabled]
            
            if not enabled_middleware:
                # No middleware, return data as-is
                return data
            
            # Process through middleware stack
            result = await self._execute_middleware_stack(context, enabled_middleware, 0)
            
            # Update statistics
            processing_time = time.time() - start_time
            self.total_processing_time += processing_time
            self.requests_processed += 1
            
            return result
            
        except Exception as e:
            logger.error(f"Middleware processing error: {e}")
            self.requests_failed += 1
            raise
    
    async def _execute_middleware_stack(self, context: MiddlewareContext, 
                                      middleware_stack: List[BaseMiddleware], 
                                      index: int) -> Any:
        """Execute middleware stack recursively."""
        try:
            if index >= len(middleware_stack):
                # End of stack, return the data
                return context.data
            
            current_middleware = middleware_stack[index]
            
            # Create next function
            async def next_middleware(ctx: MiddlewareContext) -> Any:
                return await self._execute_middleware_stack(ctx, middleware_stack, index + 1)
            
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
                    "type": type(middleware).__name__
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
        avg_processing_time = (
            self.total_processing_time / self.requests_processed 
            if self.requests_processed > 0 else 0
        )
        
        middleware_counts = {
            mtype: len(stack) for mtype, stack in self.middleware_stacks.items()
        }
        
        return {
            "middleware_types": list(self.middleware_stacks.keys()),
            "middleware_counts": middleware_counts,
            "requests_processed": self.requests_processed,
            "requests_failed": self.requests_failed,
            "total_processing_time": self.total_processing_time,
            "average_processing_time": avg_processing_time
        }

# Global middleware manager
middleware_manager = MiddlewareManager()

# Register default middleware
middleware_manager.register_middleware("api", AuthenticationMiddleware())
middleware_manager.register_middleware("api", RateLimitMiddleware())
middleware_manager.register_middleware("api", ValidationMiddleware())
middleware_manager.register_middleware("api", LoggingMiddleware())
middleware_manager.register_middleware("api", PerformanceMiddleware())

# Convenience functions
def register_middleware(middleware_type: str, middleware: BaseMiddleware):
    """Register middleware using global manager."""
    middleware_manager.register_middleware(middleware_type, middleware)

def unregister_middleware(middleware_type: str, middleware_name: str) -> bool:
    """Unregister middleware using global manager."""
    return middleware_manager.unregister_middleware(middleware_type, middleware_name)

async def process_with_middleware(middleware_type: str, request_id: str, data: Dict[str, Any], **kwargs) -> Any:
    """Process request with middleware using global manager."""
    return await middleware_manager.process(middleware_type, request_id, data, **kwargs)

def get_middleware_stack(middleware_type: str) -> List[Dict[str, Any]]:
    """Get middleware stack using global manager."""
    return middleware_manager.get_middleware_stack(middleware_type)
